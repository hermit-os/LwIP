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

/* We used several existing projects as guides
 * kvmtest.c: http://lwn.net/Articles/658512/
 * lkvm: http://github.com/clearlinux/kvmtool
 */


#include <hermit/stddef.h>
#include <hermit/stdio.h>
#include <hermit/errno.h>
#include <lwip/sys.h>
#include <sys/poll.h>
#include <lwip/netif.h>
#include <lwip/tcpip.h>
#include <lwip/snmp.h>
#include <lwip/sockets.h>
#include <lwip/err.h>
#include <lwip/stats.h>
#include <lwip/ethip6.h>
#include <lwip/netifapi.h>
#include <netif/etharp.h>

#include "uhyve-net.h"
#include <arch_io.h>

#define UHYVE_IRQ	11

static struct netif* mynetif = NULL;

//---------------------------- OUTPUT --------------------------------------------

static err_t uhyve_netif_output(struct netif* netif, struct pbuf* p)
{
	uhyve_netif_t* uhyve_netif = netif->state;
	uint32_t i;
	struct pbuf *q;

	if (BUILTIN_EXPECT(p->tot_len > UHYVE_NET_MTU, 0))
		return ERR_IF;

	shared_queue_t* tx_queue = (shared_queue_t*) (SHAREDQUEUE_START + SHAREDQUEUE_CEIL(sizeof(shared_queue_t)));

	uint64_t written = atomic_uint64_read(&tx_queue->written);
	uint64_t read = atomic_uint64_read(&tx_queue->read);
	uint64_t distance = written - read;

	if (distance >= UHYVE_QUEUE_SIZE) {
		LINK_STATS_INC(link.drop);
		kprintf("CCC drop packet\n");
		return ERR_IF;
	}

	uint64_t idx = written % UHYVE_QUEUE_SIZE;

#if ETH_PAD_SIZE
	pbuf_header(p, -ETH_PAD_SIZE); /*drop padding word */
#endif

	/*
	 * q traverses through linked list of pbuf's
	 * This list MUST consist of a single packet ONLY
	 */
	for (q = p, i = 0; q != 0; q = q->next) {
		// send the packet
		memcpy(tx_queue->inner[idx].data, q->payload, q->len);
		i += q->len;
	}
	tx_queue->inner[idx].len = p->tot_len;
	atomic_uint64_inc(&tx_queue->written);
	if (written == atomic_uint64_read(&tx_queue->read)) {
		outportl(UHYVE_PORT_NETWRITE, 0);
	}

#if ETH_PAD_SIZE
	pbuf_header(p, ETH_PAD_SIZE); /* reclaim the padding word */
#endif

	LINK_STATS_INC(link.xmit);

	return ERR_OK;
}

static void consume_packet(void* ctx)
{
	struct pbuf *p = (struct pbuf*) ctx;

	mynetif->input(p, mynetif);
}

//------------------------------- POLLING ----------------------------------------

void uhyve_netif_poll(void)
{
	uhyve_netif_t* uhyve_netif = mynetif->state;
	shared_queue_t* receive_queue = (shared_queue_t*) SHAREDQUEUE_START;
	uint64_t written = atomic_uint64_read(&receive_queue->written);
	uint64_t read = atomic_uint64_read(&receive_queue->read);
	uint64_t distance = written - read;

	while (distance > 0) {
		uint64_t idx = read % UHYVE_QUEUE_SIZE;
		uint16_t len = receive_queue->inner[idx].len;

#if ETH_PAD_SIZE
		len += ETH_PAD_SIZE; /* allow room for Ethernet padding */
#endif

		struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
		if(p) {
#if ETH_PAD_SIZE
			pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */
#endif
			uint8_t pos = 0;
			for (struct pbuf *q=p; q!=NULL; q=q->next) {
				memcpy((uint8_t*) q->payload, receive_queue->inner[idx].data + pos, q->len);
				pos += q->len;
			}

#if ETH_PAD_SIZE
			pbuf_header(p, ETH_PAD_SIZE); /* reclaim the padding word */
#endif

			// forward packet to the IP thread
			if (tcpip_callback_with_block(consume_packet, p, 0) == ERR_OK) {
				LINK_STATS_INC(link.recv);
			} else {
				LINK_STATS_INC(link.drop);
				pbuf_free(p);
			}
		} else {
			LINK_STATS_INC(link.memerr);
			LINK_STATS_INC(link.drop);
		}

		read = atomic_uint64_inc(&receive_queue->read);
		written = atomic_uint64_read(&receive_queue->written);
		distance = written - read;
	}

	eoi();
	sys_yield();
}

#if defined(__x86_64__)
void uhyve_irqhandler(void);

__asm__(".global uhyve_irqhandler\n"
        "uhyve_irqhandler:\n\t"
        "cld\n\t"	/* Set direction flag forward for C functions */
		"push %rax\n\t"
        "push %rcx\n\t"
		"push %rdx\n\t"
		"push %rsi\n\t"
		"push %rdi\n\t"
		"push %r8\n\t"
		"push %r9\n\t"
		"push %r10\n\t"
		"push %r11\n\t"
        "call uhyve_netif_poll\n\t"
        "pop %r11\n\t"
		"pop %r10\n\t"
		"pop %r9\n\t"
		"pop %r8\n\t"
		"pop %rdi\n\t"
		"pop %rsi\n\t"
		"pop %rdx\n\t"
		"pop %rcx\n\t"
		"pop %rax\n\t"
        "iretq");
#elif defined(__aarch64__)
void uhyve_irqhandler(void)
{
	kprintf("TODO: Implement uhyve_irqhandler for AArch64\n");
}
#else
#error Invalid architecture
#endif

//--------------------------------- INIT -----------------------------------------

static uhyve_netif_t static_uhyve_netif;
static uhyve_netif_t* uhyve_netif = NULL;

static err_t uhyve_netif_init (struct netif* netif)
{
	LWIP_ASSERT("netif != NULL", (netif != NULL));

	kprintf("uhyve_netif_init: Found uhyve_net interface\n");

	LWIP_ASSERT("uhyve_netif == NULL", (uhyve_netif == NULL));

	// currently we support only one device => use a static variable uhyve_netif
	uhyve_netif = &static_uhyve_netif;

	netif->state = uhyve_netif;
	mynetif = netif;

	netif->hwaddr_len = ETHARP_HWADDR_LEN;

	outportl(UHYVE_PORT_NETINFO, (unsigned)virt_to_phys((size_t)netif->hwaddr));
	/*kprintf("MAC address: ");
	for(int i=0; i<ETHARP_HWADDR_LEN; i++) {
		if (i < ETHARP_HWADDR_LEN-1)
			kprintf("%02x:", netif->hwaddr[i] & 0xFF);
		else
			kprintf("%02x", netif->hwaddr[i] & 0xFF);
	}
	kprintf("\n");*/

	uhyve_netif->ethaddr = (struct eth_addr *)netif->hwaddr;

	//kprintf("uhye_netif uses irq %d\n", UHYVE_IRQ);
	irq_install_handler(UHYVE_IRQ, uhyve_irqhandler);

	/*
	 * Initialize the snmp variables and counters inside the struct netif.
	 * The last argument should be replaced with your link speed, in units
	 * of bits per second.
	 */
	NETIF_INIT_SNMP(netif, snmp_ifType_ethernet_csmacd, 1000);

	netif->name[0] = 'e';
	netif->name[1] = 'n';
	netif->num = 0;
	/* downward functions */
	netif->output = etharp_output;
	netif->linkoutput = uhyve_netif_output;
	/* maximum transfer unit */
	netif->mtu = UHYVE_NET_MTU;
	/* broadcast capability */
	netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP | NETIF_FLAG_LINK_UP | NETIF_FLAG_MLD6;

#if LWIP_IPV6
	netif->output_ip6 = ethip6_output;
	netif_create_ip6_linklocal_address(netif, 1);
	netif->ip6_autoconfig_enabled = 1;
#endif

	/* check if we already receive an interrupt */
	uhyve_netif_poll();

	return ERR_OK;
}

static struct netif default_netif;

int init_uhyve_netif(void)
{
	uint8_t		hcip[4];
	uint8_t		hcgateway[4];
	uint8_t		hcmask[4];
	ip_addr_t	ipaddr;
	ip_addr_t	netmask;
	ip_addr_t	gw;

	// determine network configuration
	uhyve_get_ip(hcip);
	uhyve_get_gateway(hcgateway);
	uhyve_get_mask(hcmask);

	/*kprintf("IP: %d.%d.%d.%d\n", hcip[0], hcip[1], hcip[2], hcip[3]);
	kprintf("Gateway: %d.%d.%d.%d\n", hcgateway[0], hcgateway[1], hcgateway[2], hcgateway[3]);
	kprintf("Mask: %d.%d.%d.%d\n", hcmask[0], hcmask[1], hcmask[2], hcmask[3]);*/

	/* Set network address variables */
	IP_ADDR4(&gw, hcgateway[0], hcgateway[1], hcgateway[2], hcgateway[3]);
	IP_ADDR4(&ipaddr, hcip[0], hcip[1], hcip[2], hcip[3]);
	IP_ADDR4(&netmask, hcmask[0], hcmask[1], hcmask[2], hcmask[3]);

	if ((netifapi_netif_add(&default_netif, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gw), NULL, uhyve_netif_init, ethernet_input)) != ERR_OK) {
		kprintf("Unable to add the uhyve_net network interface\n");
		return -ENODEV;
	}

	/* tell lwip all initialization is done and we want to set it up */
	netifapi_netif_set_default(&default_netif);
	netifapi_netif_set_up(&default_netif);

	return ERR_OK;
}
