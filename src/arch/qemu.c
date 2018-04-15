/*
 * Copyright (c) 2018, Stefan Lankes, RWTH Aachen University
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

#include <lwip/sys.h>
#include <lwip/stats.h>
#include <lwip/ip_addr.h>
#include <lwip/udp.h>
#include <lwip/tcp.h>
#include <lwip/tcpip.h>
#include <lwip/dhcp.h>
#include <lwip/netifapi.h>
#include <lwip/ip_addr.h>
#include <lwip/sockets.h>
#include <lwip/err.h>
#include <lwip/stats.h>

#define HERMIT_PORT	0x494E

static const int sobufsize = 131072;

size_t c_strlen(const char* str)
{
	return strlen(str);
}

int get_qemu_socket(void)
{
	struct sockaddr_in6 server, client;
	int s = -1, c = -1;
	int flag, len;
	err_t err;

	s = lwip_socket(AF_INET6, SOCK_STREAM , 0);
	if (s < 0) {
		kprintf("socket failed: %d\n", server);
		return -1;
	}

	// prepare the sockaddr_in structure
	memset((char *) &server, 0x00, sizeof(server));
	server.sin6_family = AF_INET6;
	server.sin6_addr = in6addr_any;
	server.sin6_port = htons(HERMIT_PORT);

	if ((err = lwip_bind(s, (struct sockaddr *) &server, sizeof(server))) < 0)
	{
		kprintf("bind failed: %d\n", errno);
		lwip_close(s);
		return -1;
	}

	if ((err = lwip_listen(s, 2)) < 0)
	{
		kprintf("listen failed: %d\n", errno);
		lwip_close(s);
		return -1;
	}

	len = sizeof(struct sockaddr_in);

	kprintf("TCP server is listening.\n");

	if ((c = lwip_accept(s, (struct sockaddr *)&client, (socklen_t*)&len)) < 0)
	{
		kprintf("accept faild: %d\n", errno);
		lwip_close(s);
		return -1;
	}

	kprintf("Establish IP connection\n");

	lwip_setsockopt(c, SOL_SOCKET, SO_RCVBUF, (char *) &sobufsize, sizeof(sobufsize));
	lwip_setsockopt(c, SOL_SOCKET, SO_SNDBUF, (char *) &sobufsize, sizeof(sobufsize));
	flag = 1;
	lwip_setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(flag));
	flag = 0;
	lwip_setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *) &flag, sizeof(flag));

	return c;
}
