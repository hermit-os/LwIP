#ifndef __ARCH_SYS_ARCH_H__
#define __ARCH_SYS_ARCH_H__

#include <hermit/errno.h>
#include <hermit/mailbox.h>
#include <hermit/syscall.h>

#define sys_jiffies() sys_now()

#define EWOULDBLOCK	EAGAIN	/* Operation would block */
#define HIGH_PRIO 16

typedef HermitSemaphore* sys_mutex_t;

typedef struct
{
	HermitSemaphore* sem;
	int valid;
} sys_sem_t;

typedef struct 
{	mailbox_ptr_t	mailbox;
	int		valid;
} sys_mbox_t;

typedef tid_t		sys_thread_t;

typedef uint32_t sys_prot_t;
sys_prot_t sys_arch_protect(void);
void sys_arch_unprotect(sys_prot_t pval);

sys_sem_t* sys_arch_netconn_sem_get(void);
void sys_arch_netconn_sem_alloc(void);
void sys_arch_netconn_sem_free(void);
#define LWIP_NETCONN_THREAD_SEM_GET()   sys_arch_netconn_sem_get()
#define LWIP_NETCONN_THREAD_SEM_ALLOC() sys_arch_netconn_sem_alloc()
#define LWIP_NETCONN_THREAD_SEM_FREE()  sys_arch_netconn_sem_free()

#endif /* __ARCH_SYS_ARCH_H__ */
