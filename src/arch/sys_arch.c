/*
 * Copyright (c) 2011, Stefan Lankes, RWTH Aachen University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the University nor the names of its contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <hermit/stddef.h>
#include <hermit/syscall.h>

#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/sys.h"
#include "lwip/stats.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/err.h"

#ifndef TRUE
#define TRUE	1
#endif

#ifndef FALSE
#define FALSE	0
#endif

static HermitSpinlockIrqSave* lwprot_lock = NULL;

/** Returns the current time in milliseconds,
 * may be the same as sys_jiffies or at least based on it. */
u32_t sys_now(void)
{
	struct timeval tv;

	sys_gettimeofday((HermitTimeval*)&tv, NULL);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

#if !NO_SYS

/* sys_init(): init needed system resources
 */
void sys_init(void)
{
	sys_spinlock_irqsave_init(&lwprot_lock);
}

/* sys_thread_new(): Spawns a new thread with given attributes as supported
 * Note: In HermitCore this is realized as kernel tasks
 */
sys_thread_t sys_thread_new(const char *name, lwip_thread_fn thread, void *arg,
		int stacksize, int prio)
{
	static int already_called = FALSE;
	int err;
	sys_thread_t id;

	LWIP_UNUSED_ARG(name);
	LWIP_UNUSED_ARG(stacksize);
	LWIP_ASSERT("lwIP sys_thread_new must only be called once for the TCP/IP thread!", !already_called);

	already_called = TRUE;

	// Spawn a task on core 0, which is guaranteed to be the boot processor.
	err = sys_spawn(&id, (entry_point_t)thread, arg, prio, 0);

	// Register the returned task ID as the TCP/IP task to HermitCore.
	sys_lwip_register_tcpip_task(id);

	return id;
}

/* sys_sem_free(): destroy's given semaphore
 * and releases system resources.
 * This semaphore also gets invalid.
 */
void sys_sem_free(sys_sem_t* s)
{
	s->valid = FALSE;
	SYS_STATS_DEC(sem.used);
	sys_sem_destroy(s->sem);
}

/* sys_sem_valid(): returns if semaphore is valid
 * at the moment
 */
int sys_sem_valid(sys_sem_t* s)
{
	return s->valid;
}

/* sys_sem_new(): creates a new semaphre with given count.
 * This semaphore becomes valid
 */
err_t sys_sem_new(sys_sem_t* s, u8_t count)
{
	int err;

	err = sys_sem_init(&s->sem, count);
	if (err < 0)
		return ERR_VAL;

	SYS_STATS_INC_USED(sem);
	s->valid = TRUE;

	return ERR_OK;
}

/* sys_sem_set_invalid(): this semapohore becomes invalid
 * Note: this does not mean it is destroyed
 */
void sys_sem_set_invalid(sys_sem_t* s)
{
	s->valid = FALSE;
}

/* sys_sem_signal(): this semaphore is signaled
 *
 */
void sys_sem_signal(sys_sem_t* s)
{
	sys_sem_post(s->sem);
}

/* sys_arch_sem_wait): wait for the given semaphore for
 * a given timeout
 * Note: timeout = 0 means wait forever
 */
u32_t sys_arch_sem_wait(sys_sem_t* s, u32_t timeout)
{
	int err = sys_sem_timedwait(s->sem, timeout);

	if (err == 0)
		return 0;

	return SYS_ARCH_TIMEOUT;
}

/* sys_mbox_valid() : returns if the given mailbox
 * is valid
 */
int sys_mbox_valid(sys_mbox_t* mbox)
{
	return mbox->valid;
}

/* sys_arch_mbox_fetch(): wait for the given mailbox for a specified
 * amount of time.
 * Note: timeout = 0 means wait forever
 */
u32_t sys_arch_mbox_fetch(sys_mbox_t* mbox, void** msg, u32_t timeout)
{
	int err;

	err = mailbox_ptr_fetch(&mbox->mailbox, msg, timeout);
	//LWIP_DEBUGF(SYS_DEBUG, ("sys_arch_mbox_fetch: %d\n", err));
	if (!err)
		return 0;

	return SYS_ARCH_TIMEOUT;
}

/* sys_mbox_free() : free the given mailbox, release the system resources
 * and set mbox to invalid
 */
void sys_mbox_free(sys_mbox_t* mbox)
{
	mbox->valid = FALSE;
	SYS_STATS_DEC(mbox.used);
	mailbox_ptr_destroy(&mbox->mailbox);
}

/* sys_arch_mbox_tryfetch(): poll for new data in mailbox
 *
 */
u32_t sys_arch_mbox_tryfetch(sys_mbox_t* mbox, void** msg)
{
	int ret = mailbox_ptr_tryfetch(&mbox->mailbox, msg);
	if (ret)
		return SYS_MBOX_EMPTY;

	return 0;
}

/* sys_mbox_new(): create a new mailbox with a minimum size of "size"
 *
 */
err_t sys_mbox_new(sys_mbox_t* mb, int size)
{
	int err;

	//LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_new: create mailbox with the minimum size: %d\n", size));

	mb->valid = TRUE;
	SYS_STATS_INC_USED(mbox);
	err = mailbox_ptr_init(&mb->mailbox);
	if (err)
		return ERR_MEM;

	return ERR_OK;
}

/* sys_mbox_set_invalid(): set the given mailbox to invald
 * Note: system resources are NOT freed
 */
void sys_mbox_set_invalid(sys_mbox_t* mbox)
{
	mbox->valid = FALSE;
}

/* sys_mbox_trypost(): try to post data to the mailbox
 *
 */
err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg)
{
	int err;

	err = mailbox_ptr_trypost(&mbox->mailbox, msg);
	if (err != 0) {
		LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_trypost: %d\n", err));
		return ERR_MEM;
	}

	return ERR_OK;
}

/* sys_mbox_post(): post new data to the mailbox
 *
 */
void sys_mbox_post(sys_mbox_t* mbox, void* msg)
{
	mailbox_ptr_post(&mbox->mailbox, msg);
}

sys_prot_t sys_arch_protect(void)
{
	sys_spinlock_irqsave_lock(lwprot_lock);
	return ERR_OK;
}

void sys_arch_unprotect(sys_prot_t pval)
{
	LWIP_UNUSED_ARG(pval);
	sys_spinlock_irqsave_unlock(lwprot_lock);
}

int* __getreent(void);

static inline int* libc_errno(void)
{
	return __getreent();
}

#if LWIP_SOCKET

int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	int fd = lwip_accept(s & ~LWIP_FD_BIT, addr, addrlen);

	if (fd < 0)
	{
		*libc_errno() = errno;
		return -1;
	}

	return fd | LWIP_FD_BIT;
}

int bind(int s, const struct sockaddr *name, socklen_t namelen)
{
	int ret = lwip_bind(s & ~LWIP_FD_BIT, name, namelen);


	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}

	return 0;
}

int getpeername(int s, struct sockaddr *name, socklen_t *namelen)
{
	int ret = lwip_getpeername(s & ~LWIP_FD_BIT, name, namelen);

	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}

	return 0;
}

int getsockname(int s, struct sockaddr *name, socklen_t *namelen)
{
	int ret = lwip_getsockname(s & ~LWIP_FD_BIT, name, namelen);

	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}

	return 0;
}

int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
	int ret = lwip_getsockopt(s & ~LWIP_FD_BIT, level, optname, optval, optlen);

	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}

	return 0;
}

int setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
	int ret = lwip_setsockopt(s & ~LWIP_FD_BIT, level, optname, optval, optlen);

	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}

	return 0;
}

int connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	int ret = lwip_connect(s & ~LWIP_FD_BIT, name, namelen);

	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}

	return 0;
}

int listen(int s, int backlog)
{
	int ret = lwip_listen(s & ~LWIP_FD_BIT, backlog);

	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}

	return 0;
}

int recv(int s, void *mem, size_t len, int flags)
{
	int ret = lwip_recv(s & ~LWIP_FD_BIT, mem, len, flags);

	if (ret < 0)
	{
		*libc_errno() = errno;
		return -1;
	}

	return ret;
}

int recvfrom(int s, void *mem, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
	int ret = lwip_recvfrom(s & ~LWIP_FD_BIT, mem, len, flags, from, fromlen);

	if (ret < 0)
	{
		*libc_errno() = errno;
		return -1;
	}

	return ret;
}

int send(int s, const void *dataptr, size_t size, int flags)
{
	int ret = lwip_send(s & ~LWIP_FD_BIT, dataptr, size, flags);

	if (ret < 0)
	{
		*libc_errno() = errno;
		return -1;
	}

	return ret;
}

int sendto(int s, const void *dataptr, size_t size, int flags, const struct sockaddr *to, socklen_t tolen)
{
	int ret = lwip_sendto(s & ~LWIP_FD_BIT, dataptr, size, flags, to, tolen);

	if (ret < 0)
	{
		*libc_errno() = errno;
		return -1;
	}

	return ret;
}

int socket(int domain, int type, int protocol)
{
	int fd = lwip_socket(domain, type, protocol);

	if (fd < 0)
	{
		*libc_errno() = errno;
		return -1;
	}

	return fd | LWIP_FD_BIT;
}

int select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset, struct timeval *timeout)
{
	int ret;

	ret = lwip_select(maxfdp1, readset, writeset, exceptset, timeout);

	if (ret < 0)
	{
		*libc_errno() = errno;
		return -1;
	}

	// check if another task is already ready
	sys_yield();

	return ret;
}

int fcntl(int s, int cmd, int val)
{
	return lwip_fcntl(s & ~LWIP_FD_BIT, cmd, val);
}

int shutdown(int socket, int how)
{
	return lwip_shutdown(socket & ~LWIP_FD_BIT, how);
}

#if LWIP_DNS

// TODO: replace dummy function
int gethostname(char *name, size_t len)
{
	strncpy(name, "hermit", len);

	return 0;
}

struct hostent *gethostbyname(const char* name)
{
	return lwip_gethostbyname(name);
}

int gethostbyname_r(const char *name, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop)
{
	return lwip_gethostbyname_r(name, ret, buf, buflen, result, h_errnop);
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
	return lwip_getaddrinfo(node, service, hints, res);
}

void freeaddrinfo(struct addrinfo *res)
{
	lwip_freeaddrinfo(res);
}

#endif /* LWIP_DNS */

#endif /* LWIP_SOCKET */

#endif /* !NO_SYS */

#define RAND_MAX	0x7fffffff

int lwip_rand(void)
{
	return (int)(sys_rand() & RAND_MAX);
}

#if LWIP_NETCONN_SEM_PER_THREAD
static __thread sem_t netconn_sem;

sys_sem_t* sys_arch_netconn_sem_get(void)
{
	kprintf("netcon %p\n", netconn_sem);
	return netconn_sem;
}

void sys_arch_netconn_sem_alloc(void)
{
	if (netconn_sem != NULL)
		return;

	sys_sem_new(&netconn_sem, 0);
}

void sys_arch_netconn_sem_free(void)
{
	sys_sem_destroy(&netconn_sem);
}
#endif /* LWIP_NETCONN_SEM_PER_THREAD */

static void tcpip_init_done(void* arg)
{
	sys_sem_t* s = (sys_sem_t*)arg;

	sys_sem_signal(s);
}

void init_lwip(void)
{
	sys_sem_t	s;

	if (sys_sem_new(&s, 0) != ERR_OK)
		LWIP_ASSERT("Failed to create semaphore", 0);

	tcpip_init(tcpip_init_done, &s);
	sys_sem_wait(&s);
	kprintf("LwIP intialized\n");
	sys_sem_free(&s);
}
