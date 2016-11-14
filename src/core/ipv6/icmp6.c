/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

/* Some ICMP messages should be passed to the transport protocols. This
   is not implemented. */

#include "lwip/opt.h"

#if LWIP_ICMP /* don't build if not configured for use in lwipopts.h */

#include "lwip/icmp6.h"
#include "lwip/prot/icmp6.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/inet_chksum.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/nd6.h"
#include "lwip/mld6.h"
#include "lwip/ip.h"
#include "lwip/stats.h"

void
icmp_input(struct pbuf *p, struct netif *inp)
{
  struct icmp6_hdr *icmp6hdr;
  struct pbuf *r;
  const ip6_addr_t *reply_src;

  ICMP_STATS_INC(icmp.recv);

  /* TODO: check length before accessing payload! */

  type = ((u8_t *)p->payload)[0];

#if CHECKSUM_CHECK_ICMP6
  IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_CHECK_ICMP6) {
    if (ip6_chksum_pseudo(p, IP6_NEXTH_ICMP6, p->tot_len, ip6_current_src_addr(),
                          ip6_current_dest_addr()) != 0) {
      /* Checksum failed */
      pbuf_free(p);
      ICMP6_STATS_INC(icmp6.chkerr);
      ICMP6_STATS_INC(icmp6.drop);
      return;
    }
  }
#endif /* CHECKSUM_CHECK_ICMP6 */

  switch (icmp6hdr->type) {
  case ICMP6_TYPE_NA: /* Neighbor advertisement */
  case ICMP6_TYPE_NS: /* Neighbor solicitation */
  case ICMP6_TYPE_RA: /* Router advertisement */
  case ICMP6_TYPE_RD: /* Redirect */
  case ICMP6_TYPE_PTB: /* Packet too big */
    nd6_input(p, inp);
    return;
    break;
  case ICMP6_TYPE_RS:
#if LWIP_IPV6_FORWARD
    /* @todo implement router functionality */
#endif
    break;
#if LWIP_IPV6_MLD
  case ICMP6_TYPE_MLQ:
  case ICMP6_TYPE_MLR:
  case ICMP6_TYPE_MLD:
    mld6_input(p, inp);
    return;
    break;
#endif
  case ICMP6_TYPE_EREQ:
#if !LWIP_MULTICAST_PING
    /* multicast destination address? */
    if (ip6_addr_ismulticast(ip6_current_dest_addr())) {
      /* drop */
      pbuf_free(p);
      ICMP6_STATS_INC(icmp6.drop);
      return;
    }
#endif /* LWIP_MULTICAST_PING */

      pbuf_free(p);
      ICMP_STATS_INC(icmp.lenerr);
      return;
    }
    iecho = p->payload;
    iphdr = (struct ip_hdr *)((u8_t *)p->payload - IP_HLEN);
    if (inet_chksum_pbuf(p) != 0) {
      LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: checksum failed for received ICMP echo (%"X16_F")\n", inet_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len)));
      ICMP_STATS_INC(icmp.chkerr);
    /*      return;*/
    }

    /* Determine reply source IPv6 address. */
#if LWIP_MULTICAST_PING
    if (ip6_addr_ismulticast(ip6_current_dest_addr())) {
      reply_src = ip_2_ip6(ip6_select_source_address(inp, ip6_current_src_addr()));
      if (reply_src == NULL) {
        /* drop */
        pbuf_free(p);
        pbuf_free(r);
        ICMP6_STATS_INC(icmp6.rterr);
        return;
      }
    }
    else
#endif /* LWIP_MULTICAST_PING */
    {
      reply_src = ip6_current_dest_addr();
    }
    LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: checksum failed for received ICMP echo (%"X16_F")\n", inet_chksum_pseudo(p, &(iphdr->src), &(iphdr->dest), IP_PROTO_ICMP, p->tot_len)));
    ICMP_STATS_INC(icmp.xmit);

    /* Set fields in reply. */
    ((struct icmp6_echo_hdr *)(r->payload))->type = ICMP6_TYPE_EREP;
    ((struct icmp6_echo_hdr *)(r->payload))->chksum = 0;
#if CHECKSUM_GEN_ICMP6
    IF__NETIF_CHECKSUM_ENABLED(inp, NETIF_CHECKSUM_GEN_ICMP6) {
      ((struct icmp6_echo_hdr *)(r->payload))->chksum = ip6_chksum_pseudo(r,
          IP6_NEXTH_ICMP6, r->tot_len, reply_src, ip6_current_src_addr());
    }
#endif /* CHECKSUM_GEN_ICMP6 */

    /* Send reply. */
    ICMP6_STATS_INC(icmp6.xmit);
    ip6_output_if(r, reply_src, ip6_current_src_addr(),
        LWIP_ICMP6_HL, 0, IP6_NEXTH_ICMP6, inp);
    pbuf_free(r);

    break;
  default:
    LWIP_DEBUGF(ICMP_DEBUG, ("icmp_input: ICMP type %"S16_F" not supported.\n", (s16_t)type));
    ICMP_STATS_INC(icmp.proterr);
    ICMP_STATS_INC(icmp.drop);
  }

  pbuf_free(p);
}

void
icmp_dest_unreach(struct pbuf *p, enum icmp_dur_type t)
{
  struct pbuf *q;
  struct ip_hdr *iphdr;
  struct icmp_dur_hdr *idur;

  /* @todo: can this be PBUF_LINK instead of PBUF_IP? */
  q = pbuf_alloc(PBUF_IP, 8 + IP_HLEN + 8, PBUF_RAM);
  /* ICMP header + IP header + 8 bytes of data */
  if (q == NULL) {
    LWIP_DEBUGF(ICMP_DEBUG, ("icmp_dest_unreach: failed to allocate pbuf for ICMP packet.\n"));
    pbuf_free(p);
    return;
  }
  LWIP_ASSERT("check that first pbuf can hold icmp message",
             (q->len >= (8 + IP_HLEN + 8)));

  iphdr = p->payload;

  idur = q->payload;
  idur->type = (u8_t)ICMP6_DUR;
  idur->icode = (u8_t)t;

  SMEMCPY((u8_t *)q->payload + 8, p->payload, IP_HLEN + 8);

  /* calculate checksum */
  idur->chksum = 0;
  idur->chksum = inet_chksum(idur, q->len);
  ICMP_STATS_INC(icmp.xmit);

  ip_output(q, NULL,
      (struct ip_addr *)&(iphdr->src), ICMP_TTL, IP_PROTO_ICMP);
  pbuf_free(q);
}

void
icmp_time_exceeded(struct pbuf *p, enum icmp_te_type t)
{
  struct pbuf *q;
  struct icmp6_hdr *icmp6hdr;
  const ip6_addr_t *reply_src;
  ip6_addr_t *reply_dest;
  ip6_addr_t reply_src_local, reply_dest_local;
  struct ip6_hdr *ip6hdr;
  struct netif *netif;

  /* @todo: can this be PBUF_LINK instead of PBUF_IP? */
  q = pbuf_alloc(PBUF_IP, 8 + IP_HLEN + 8, PBUF_RAM);
  /* ICMP header + IP header + 8 bytes of data */
  if (q == NULL) {
    LWIP_DEBUGF(ICMP_DEBUG, ("icmp_dest_unreach: failed to allocate pbuf for ICMP packet.\n"));
    pbuf_free(p);
    return;
  }
  LWIP_ASSERT("check that first pbuf can hold icmp message",
             (q->len >= (8 + IP_HLEN + 8)));

  iphdr = p->payload;

  tehdr = q->payload;
  tehdr->type = (u8_t)ICMP6_TE;
  tehdr->icode = (u8_t)t;

  /* Get the destination address and netif for this ICMP message. */
  if ((ip_current_netif() == NULL) ||
      ((code == ICMP6_TE_FRAG) && (type == ICMP6_TYPE_TE))) {
    /* Special case, as ip6_current_xxx is either NULL, or points
     * to a different packet than the one that expired.
     * We must use the addresses that are stored in the expired packet. */
    ip6hdr = (struct ip6_hdr *)p->payload;
    /* copy from packed address to aligned address */
    ip6_addr_copy(reply_dest_local, ip6hdr->src);
    ip6_addr_copy(reply_src_local, ip6hdr->dest);
    reply_dest = &reply_dest_local;
    reply_src = &reply_src_local;
    netif = ip6_route(reply_src, reply_dest);
    if (netif == NULL) {
      /* drop */
      pbuf_free(q);
      ICMP6_STATS_INC(icmp6.rterr);
      return;
    }
  }
  else {
    netif = ip_current_netif();
    reply_dest = ip6_current_src_addr();

    /* Select an address to use as source. */
    reply_src = ip_2_ip6(ip6_select_source_address(netif, reply_dest));
    if (reply_src == NULL) {
      /* drop */
      pbuf_free(q);
      ICMP6_STATS_INC(icmp6.rterr);
      return;
    }
  }

  /* calculate checksum */
  icmp6hdr->chksum = 0;
#if CHECKSUM_GEN_ICMP6
  IF__NETIF_CHECKSUM_ENABLED(netif, NETIF_CHECKSUM_GEN_ICMP6) {
    icmp6hdr->chksum = ip6_chksum_pseudo(q, IP6_NEXTH_ICMP6, q->tot_len,
      reply_src, reply_dest);
  }
#endif /* CHECKSUM_GEN_ICMP6 */

  ICMP6_STATS_INC(icmp6.xmit);
  ip6_output_if(q, reply_src, reply_dest, LWIP_ICMP6_HL, 0, IP6_NEXTH_ICMP6, netif);
  pbuf_free(q);
}

#endif /* LWIP_ICMP */
