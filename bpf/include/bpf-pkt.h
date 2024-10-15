#ifndef __F4_BPF_PKT_H__
#define __F4_BPF_PKT_H__
/*
 * Kernel eBPF packet eBPF packet composer/decomposer
 */

#include <linux/if_packet.h>
#include "bpf-dbg.h"
#include "bpf-cdefs.h"
#include "bpf-nat.h"

/* IP flags */
#define IP_CE 0x8000     /* Flag: "Congestion"		*/
#define IP_DF 0x4000     /* Flag: "Don't Fragment"	*/
#define IP_MF 0x2000     /* Flag: "More Fragments"	*/
#define IP_OFFSET 0x1FFF /* "Fragment Offset" part	*/

static __always_inline int is_ip_fragment(const struct iphdr *iph)
{
    return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}

static __always_inline int is_first_ip_fragment(const struct iphdr *iph)
{
    return (iph->frag_off & htons(IP_OFFSET)) == 0;
}

static inline int is_ipv6_addr_multicast(const struct in6_addr *addr)
{
    return (addr->s6_addr32[0] & htonl(0xFF000000)) == htonl(0xFF000000);
}

static int __always_inline xpkt_decode_eth(struct decoder *coder, void *md,
                                        struct xpkt *pkt)
{
    struct ethhdr *eth;
    eth = XPKT_PTR(coder->data_begin);

    if ((void *)(eth + 1) > coder->data_end) {
        return DP_PRET_FAIL;
    }

    if (coder->in_pkt) {
        pkt->il2.valid = 1;
        memcpy(pkt->il2.dl_dst, eth->h_dest, 2 * 6);
        memcpy(pkt->pm.lkup_dmac, eth->h_dest, 6);
        pkt->il2.dl_type = eth->h_proto;
    } else {
        pkt->l2.valid = 1;
        memcpy(pkt->l2.dl_dst, eth->h_dest, 2 * 6);
        memcpy(pkt->pm.lkup_dmac, eth->h_dest, 6);
        pkt->l2.dl_type = eth->h_proto;
    }

    if (!ETH_TYPE_ETH2(eth->h_proto)) {
        return DP_PRET_PASS;
    }

    coder->data_begin = XPKT_PTR_ADD(eth, sizeof(*eth));

    return DP_PRET_OK;
}

static int __always_inline xpkt_decode_vlan(struct decoder *coder, void *md,
                                         struct xpkt *pkt)
{
    struct __sk_buff *b = md;
    if (b->vlan_present) {
        pkt->l2.vlan[0] = htons((__u16)(b->vlan_tci));
    }
    return DP_PRET_OK;
}

static int __always_inline xpkt_decode_arp(struct decoder *coder, void *md,
                                        struct xpkt *pkt)
{
    struct arp_ethhdr *arp = XPKT_PTR(coder->data_begin);

    if ((void *)(arp + 1) > coder->data_end) {
        return DP_PRET_FAIL;
    }

    if (coder->in_pkt) {
        if (arp->ar_pro == htons(ETH_P_IP) && arp->ar_pln == 4) {
            pkt->il34.saddr4 = arp->ar_spa;
            pkt->il34.daddr4 = arp->ar_tpa;
        }
        pkt->il34.nw_proto = ntohs(arp->ar_op) & 0xff;
    } else {
        if (arp->ar_pro == htons(ETH_P_IP) && arp->ar_pln == 4) {
            pkt->l34.saddr4 = arp->ar_spa;
            pkt->l34.daddr4 = arp->ar_tpa;
        }
        pkt->l34.nw_proto = ntohs(arp->ar_op) & 0xff;
    }

    return DP_PRET_TRAP;
}

static int __always_inline xpkt_decode_tcp(struct decoder *coder, void *md,
                                        struct xpkt *pkt)
{
    struct tcphdr *tcp = XPKT_PTR(coder->data_begin);
    __u8 tcp_flags = 0;

    if ((void *)(tcp + 1) > coder->data_end) {
        /* In case of fragmented packets */
        return DP_PRET_OK;
    }

    if (tcp->fin)
        tcp_flags = F4_TCP_FIN;
    if (tcp->rst)
        tcp_flags |= F4_TCP_RST;
    if (tcp->syn)
        tcp_flags |= F4_TCP_SYN;
    if (tcp->psh)
        tcp_flags |= F4_TCP_PSH;
    if (tcp->ack)
        tcp_flags |= F4_TCP_ACK;
    if (tcp->urg)
        tcp_flags |= F4_TCP_URG;

    if (coder->in_pkt) {
        if (tcp_flags & (F4_TCP_FIN | F4_TCP_RST)) {
            pkt->pm.il4fin = 1;
        }

        pkt->il34.source = tcp->source;
        pkt->il34.dest = tcp->dest;
        pkt->il34.seq = tcp->seq;
        pkt->pm.itcp_flags = tcp_flags;
    } else {
        if (tcp_flags & (F4_TCP_FIN | F4_TCP_RST)) {
            pkt->pm.l4fin = 1;
        }

        pkt->l34.source = tcp->source;
        pkt->l34.dest = tcp->dest;
        pkt->l34.seq = tcp->seq;
        pkt->pm.tcp_flags = tcp_flags;
    }

    return DP_PRET_OK;
}

static int __always_inline xpkt_decode_icmp(struct decoder *coder, void *md,
                                         struct xpkt *pkt)
{
    struct icmphdr *icmp = XPKT_PTR(coder->data_begin);

    if ((void *)(icmp + 1) > coder->data_end) {
        return DP_PRET_OK;
    }

    if ((icmp->type == ICMP_ECHOREPLY || icmp->type == ICMP_ECHO)) {
        if (coder->in_pkt) {
            pkt->il34.source = icmp->un.echo.id;
            pkt->il34.dest = icmp->un.echo.id;
        } else {
            pkt->l34.source = icmp->un.echo.id;
            pkt->l34.dest = icmp->un.echo.id;
        }
    }
    return DP_PRET_OK;
}

static int __always_inline xpkt_decode_udp(struct decoder *coder, void *md,
                                        struct xpkt *pkt)
{
    struct udphdr *udp = XPKT_PTR(coder->data_begin);

    if ((void *)(udp + 1) > coder->data_end) {
        return DP_PRET_OK;
    }

    pkt->l34.source = udp->source;
    pkt->l34.dest = udp->dest;

    return DP_PRET_OK;
}

static int __always_inline xpkt_decode_icmp6(struct decoder *coder, void *md,
                                          struct xpkt *pkt)
{
    struct icmp6hdr *icmp6 = XPKT_PTR(coder->data_begin);

    if ((void *)(icmp6 + 1) > coder->data_end) {
        return DP_PRET_OK;
    }

    if ((icmp6->icmp6_type == ICMPV6_ECHO_REPLY ||
         icmp6->icmp6_type == ICMPV6_ECHO_REQUEST)) {
        if (coder->in_pkt) {
            pkt->il34.source = icmp6->icmp6_dataun.u_echo.identifier;
            pkt->il34.dest = icmp6->icmp6_dataun.u_echo.identifier;
        } else {
            pkt->l34.source = icmp6->icmp6_dataun.u_echo.identifier;
            pkt->l34.dest = icmp6->icmp6_dataun.u_echo.identifier;
        }
    } else if (icmp6->icmp6_type >= 133 && icmp6->icmp6_type <= 137) {
        return DP_PRET_PASS;
    }

    return DP_PRET_OK;
}

static int __always_inline xpkt_decode_ipv4(struct decoder *coder, void *md,
                                         struct xpkt *pkt)
{
    struct iphdr *iph = XPKT_PTR(coder->data_begin);
    int iphl = iph->ihl << 2;

    if ((void *)(iph + 1) > coder->data_end) {
        return DP_PRET_FAIL;
    }

    if (XPKT_PTR_ADD(iph, iphl) > coder->data_end) {
        return DP_PRET_FAIL;
    }

    if (pkt->pm.igr) {
        __u8 *hit;
        hit = bpf_map_lookup_elem(&f4gw_igr_ipv4, &iph->daddr);
        if (hit != NULL) {
            bpf_tail_call(md, &fsm_progs, FSM_CNI_PASS_PROG_ID);
        }
    } else if (pkt->pm.egr) {
        __u8 *hit;
        hit = bpf_map_lookup_elem(&f4gw_egr_ipv4, &iph->daddr);
        if (hit != NULL) {
            bpf_tail_call(md, &fsm_progs, FSM_CNI_PASS_PROG_ID);
        }
    }

    pkt->pm.l3_len = ntohs(iph->tot_len);
    pkt->pm.l3_plen = pkt->pm.l3_len - iphl;

    pkt->l34.valid = 1;
    pkt->l34.tos = iph->tos & 0xfc;
    pkt->l34.nw_proto = iph->protocol;
    pkt->l34.saddr4 = iph->saddr;
    pkt->l34.daddr4 = iph->daddr;

    if (is_first_ip_fragment(iph)) {
        pkt->pm.l4_off = XPKT_PTR_SUB(XPKT_PTR_ADD(iph, iphl), coder->start);
        coder->data_begin = XPKT_PTR_ADD(iph, iphl);

        if (is_ip_fragment(iph)) {
            pkt->l2.ssnid = iph->id;
            pkt->pm.goct = 1;
        }

        if (pkt->l34.nw_proto == IPPROTO_TCP) {
            return xpkt_decode_tcp(coder, md, pkt);
        } else if (pkt->l34.nw_proto == IPPROTO_UDP) {
            return xpkt_decode_udp(coder, md, pkt);
        } else if (pkt->l34.nw_proto == IPPROTO_ICMP) {
            return xpkt_decode_icmp(coder, md, pkt);
        }
    } else {
        if (is_ip_fragment(iph)) {
            pkt->l34.source = iph->id;
            pkt->l34.dest = iph->id;
            pkt->l2.ssnid = iph->id;
            pkt->l34.frg = 1;
        }
    }

    return DP_PRET_OK;
}

static int __always_inline xpkt_decode_ipv6(struct decoder *coder, void *md,
                                         struct xpkt *pkt)
{
    struct ipv6hdr *ip6 = XPKT_PTR(coder->data_begin);

    if ((void *)(ip6 + 1) > coder->data_end) {
        return DP_PRET_FAIL;
    }

    if (is_ipv6_addr_multicast(&ip6->daddr) ||
        is_ipv6_addr_multicast(&ip6->saddr)) {
        return DP_PRET_PASS;
    }

    pkt->pm.l3_plen = ntohs(ip6->payload_len);
    pkt->pm.l3_len = pkt->pm.l3_plen + sizeof(*ip6);

    pkt->l34.valid = 1;
    pkt->l34.tos =
        ((ip6->priority << 4) | ((ip6->flow_lbl[0] & 0xf0) >> 4)) & 0xfc;
    pkt->l34.nw_proto = ip6->nexthdr;
    memcpy(&pkt->l34.saddr, &ip6->saddr, sizeof(ip6->saddr));
    memcpy(&pkt->l34.daddr, &ip6->daddr, sizeof(ip6->daddr));

    pkt->pm.l4_off = XPKT_PTR_SUB(XPKT_PTR_ADD(ip6, sizeof(*ip6)), coder->start);
    coder->data_begin = XPKT_PTR_ADD(ip6, sizeof(*ip6));

    if (pkt->l34.nw_proto == IPPROTO_TCP) {
        return xpkt_decode_tcp(coder, md, pkt);
    } else if (pkt->l34.nw_proto == IPPROTO_UDP) {
        return xpkt_decode_udp(coder, md, pkt);
    } else if (pkt->l34.nw_proto == IPPROTO_ICMPV6) {
        return xpkt_decode_icmp6(coder, md, pkt);
    }
    return DP_PRET_OK;
}

static int __always_inline xpkt_decode(void *md, struct xpkt *pkt,
                                          int skip_ipv6)
{
    int ret = 0;
    struct decoder coder;

    coder.in_pkt = 0;
    coder.skip_l2 = 0;
    coder.skip_ipv6 = skip_ipv6;
    coder.start = XPKT_PTR(XPKT_DATA(md));
    coder.data_begin = XPKT_PTR(coder.start);
    coder.data_end = XPKT_PTR(XPKT_DATA_END(md));

    pkt->pm.py_bytes = XPKT_PTR_SUB(coder.data_end, coder.data_begin);

    if ((ret = xpkt_decode_eth(&coder, md, pkt))) {
        goto handle_excp;
    }

    if ((ret = xpkt_decode_vlan(&coder, md, pkt))) {
        goto handle_excp;
    }

    pkt->pm.l3_off = XPKT_PTR_SUB(coder.data_begin, coder.start);

    if (pkt->l2.dl_type == htons(ETH_P_ARP)) {
        ret = xpkt_decode_arp(&coder, md, pkt);
    } else if (pkt->l2.dl_type == htons(ETH_P_IP)) {
        ret = xpkt_decode_ipv4(&coder, md, pkt);
    } else if (pkt->l2.dl_type == htons(ETH_P_IPV6)) {
        if (coder.skip_ipv6 == 1) {
            return 0;
        }
        ret = xpkt_decode_ipv6(&coder, md, pkt);
    }
    // else if (pkt->l2m.dl_type == htons(ETH_P_F4)) {
    //   ret = dp_parse_f4(&coder, md, pkt);
    // }

    if (ret != 0) {
        goto handle_excp;
    }

    return 0;

handle_excp:
    if (ret > DP_PRET_OK) {
        F4_PPLN_PASSC(pkt, F4_PIPE_RC_PARSER);
    } else if (ret < DP_PRET_OK) {
        F4_PPLN_DROPC(pkt, F4_PIPE_RC_PARSER);
    }
    return ret;
}

static int __always_inline xpkt_encode_packet_always(void *ctx, struct xpkt *pkt)
{
    if (pkt->pm.nf & F4_NAT_SRC && pkt->nat.dsr == 0) {
        if (pkt->l2.dl_type == ntohs(ETH_P_IPV6) || pkt->nat.nv6) {
            // dp_sunp_tcall(ctx, xf);
        } else {
            if (dp_do_snat(ctx, pkt) != 0) {
                return TC_ACT_SHOT;
            }
        }
    } else if (pkt->pm.nf & F4_NAT_DST && pkt->nat.dsr == 0) {
        if (pkt->l2.dl_type == ntohs(ETH_P_IPV6)) {
            // dp_sunp_tcall(ctx, xf);
        } else {
            if (dp_do_dnat(ctx, pkt) != 0) {
                return TC_ACT_SHOT;
            }
        }
    }

    return 0;
}

static int __always_inline xpkt_encode_packet(void *ctx, struct xpkt *pkt)
{
    return dp_do_out(ctx, pkt);
}

#endif