/*
 * Copyright 2020 RWTH Aachen University
 * Author(s): Stefan Lankes <slankes@eonerc.rwth-aachen.de>
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

#ifndef __NET_UHYVE_NET_H__
#define __NET_UHYVE_NET_H__

#include <hermit/stddef.h>

#define MIN(a, b)	(a) < (b) ? (a) : (b)

#define UHYVE_PORT_NETINFO      0x600
#define UHYVE_PORT_NETWRITE     0x640
#define SHAREDQUEUE_START       0x80000
#define UHYVE_NET_MTU           1500
#define UHYVE_QUEUE_SIZE        8

void uhyve_get_ip(uint8_t*);
void uhyve_get_gateway(uint8_t*);
void uhyve_get_mask(uint8_t*);
void sys_yield(void);

#define SHAREDQUEUE_FLOOR(x)	((x) & !0x3f)
#define SHAREDQUEUE_CEIL(x)		(((x) + 0x3f) & ~0x3f)

typedef struct { volatile uint64_t counter; } atomic_uint64_t __attribute__ ((aligned (64)));

inline static uint64_t atomic_uint64_read(atomic_uint64_t *d) {
	return d->counter;
}

inline static int64_t atomic_uint64_inc(atomic_uint64_t* d) {
	uint64_t res = 1;
	__asm__ volatile("lock xaddq %0, %1" : "+r"(res), "+m"(d->counter) : : "memory", "cc");
	return ++res;
}

typedef struct queue_inner {
	uint16_t len;
	uint8_t data[UHYVE_NET_MTU+34];
} queue_inner_t;

typedef struct shared_queue {
	atomic_uint64_t read;
	atomic_uint64_t written;
	uint8_t reserved[64-8];
	queue_inner_t inner[UHYVE_QUEUE_SIZE];
} shared_queue_t;

/*
 * Helper struct to hold private data used to operate your ethernet interface.
 */
typedef struct uhyve_netif {
	struct eth_addr *ethaddr;
	/* Add whatever per-interface state that is needed here. */
} uhyve_netif_t;

#endif
