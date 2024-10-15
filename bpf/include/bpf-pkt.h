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

static __always_inline int ip_is_fragment(const struct iphdr *iph)
{
    return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}

static __always_inline int ip_is_last_fragment(const struct iphdr *iph)
{
    return (iph->frag_off & htons(IP_MF)) == 0;
}

static __always_inline int ip_is_first_fragment(const struct iphdr *iph)
{
    return (iph->frag_off & htons(IP_OFFSET)) == 0;
}

static __always_inline int proto_is_vlan(__be16 h_proto)
{
    return !!(h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD));
}

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
    __be32 check = iph->check;
    check += htons(0x0100);
    iph->check = (__be16)(check + (check >= 0xFFFF));
    return --iph->ttl;
}

static inline int ipv6_addr_is_multicast(const struct in6_addr *addr)
{
    return (addr->s6_addr32[0] & htonl(0xFF000000)) == htonl(0xFF000000);
}

static int __always_inline dp_pkt_is_l2mcbc(struct xpkt *pkt, void *md)
{
    struct __sk_buff *b = md;

    if (b->pkt_type == PACKET_MULTICAST || b->pkt_type == PACKET_BROADCAST) {
        return 1;
    }
    return 0;
}

static int __always_inline dp_parse_eth(struct decoder *p, void *md,
                                        struct xpkt *pkt)
{
    struct ethhdr *eth;
    eth = TC_PTR(p->data_begin);

    if ((void *)(eth + 1) > p->data_end) {
        return DP_PRET_FAIL;
    }

    if (p->in_pkt) {
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

    p->data_begin = TC_PTR_ADD(eth, sizeof(*eth));

    return DP_PRET_OK;
}

static int __always_inline dp_parse_vlan(struct decoder *p, void *md,
                                         struct xpkt *pkt)
{
    struct __sk_buff *b = md;
    if (b->vlan_present) {
        pkt->l2.vlan[0] = htons((__u16)(b->vlan_tci));
        debug_printf("vlan id %u\n", pkt->l2.vlan[0]);
    }
    return DP_PRET_OK;
}

static int __always_inline dp_parse_arp(struct decoder *p, void *md,
                                        struct xpkt *pkt)
{
    struct arp_ethhdr *arp = TC_PTR(p->data_begin);

    if ((void *)(arp + 1) > p->data_end) {
        return DP_PRET_FAIL;
    }

    if (p->in_pkt) {
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

static int __always_inline dp_parse_tcp(struct decoder *p, void *md,
                                        struct xpkt *pkt)
{
    struct tcphdr *tcp = TC_PTR(p->data_begin);
    __u8 tcp_flags = 0;

    if ((void *)(tcp + 1) > p->data_end) {
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

    if (p->in_pkt) {
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

static int __always_inline dp_parse_icmp(struct decoder *p, void *md,
                                         struct xpkt *pkt)
{
    struct icmphdr *icmp = TC_PTR(p->data_begin);

    if ((void *)(icmp + 1) > p->data_end) {
        return DP_PRET_OK;
    }

    if ((icmp->type == ICMP_ECHOREPLY || icmp->type == ICMP_ECHO)) {
        if (p->in_pkt) {
            pkt->il34.source = icmp->un.echo.id;
            pkt->il34.dest = icmp->un.echo.id;
        } else {
            pkt->l34.source = icmp->un.echo.id;
            pkt->l34.dest = icmp->un.echo.id;
        }
    }
    return DP_PRET_OK;
}

static int __always_inline dp_parse_udp(struct decoder *p, void *md,
                                        struct xpkt *pkt)
{
    struct udphdr *udp = TC_PTR(p->data_begin);

    if ((void *)(udp + 1) > p->data_end) {
        return DP_PRET_OK;
    }

    pkt->l34.source = udp->source;
    pkt->l34.dest = udp->dest;

    return DP_PRET_OK;
}

static int __always_inline dp_parse_icmp6(struct decoder *p, void *md,
                                          struct xpkt *pkt)
{
    struct icmp6hdr *icmp6 = TC_PTR(p->data_begin);

    if ((void *)(icmp6 + 1) > p->data_end) {
        return DP_PRET_OK;
    }

    if ((icmp6->icmp6_type == ICMPV6_ECHO_REPLY ||
         icmp6->icmp6_type == ICMPV6_ECHO_REQUEST)) {
        if (p->in_pkt) {
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

static int __always_inline dp_parse_ipv4(struct decoder *p, void *md,
                                         struct xpkt *pkt)
{
    struct iphdr *iph = TC_PTR(p->data_begin);
    int iphl = iph->ihl << 2;

    if ((void *)(iph + 1) > p->data_end) {
        return DP_PRET_FAIL;
    }

    if (TC_PTR_ADD(iph, iphl) > p->data_end) {
        return DP_PRET_FAIL;
    }

    if (pkt->pm.igr) {
        __u8 *hit;
        hit = bpf_map_lookup_elem(&f4gw_igr_ipv4, &iph->daddr);
        if (hit != NULL) {
            bpf_tail_call(md, &fsm_progs, F4_TC_ACT_OK_PGM_ID);
        }
    } else if (pkt->pm.egr) {
        __u8 *hit;
        hit = bpf_map_lookup_elem(&f4gw_egr_ipv4, &iph->daddr);
        if (hit != NULL) {
            bpf_tail_call(md, &fsm_progs, F4_TC_ACT_OK_PGM_ID);
        }
    }

    pkt->pm.l3_len = ntohs(iph->tot_len);
    pkt->pm.l3_plen = pkt->pm.l3_len - iphl;

    pkt->l34.valid = 1;
    pkt->l34.tos = iph->tos & 0xfc;
    pkt->l34.nw_proto = iph->protocol;
    pkt->l34.saddr4 = iph->saddr;
    pkt->l34.daddr4 = iph->daddr;

    if (ip_is_first_fragment(iph)) {
        pkt->pm.l4_off = TC_PTR_SUB(TC_PTR_ADD(iph, iphl), p->start);
        p->data_begin = TC_PTR_ADD(iph, iphl);

        if (ip_is_fragment(iph)) {
            pkt->l2.ssnid = iph->id;
            pkt->pm.goct = 1;
        }

        if (pkt->l34.nw_proto == IPPROTO_TCP) {
            return dp_parse_tcp(p, md, pkt);
        } else if (pkt->l34.nw_proto == IPPROTO_UDP) {
            return dp_parse_udp(p, md, pkt);
        } else if (pkt->l34.nw_proto == IPPROTO_ICMP) {
            return dp_parse_icmp(p, md, pkt);
        }
    } else {
        if (ip_is_fragment(iph)) {
            pkt->l34.source = iph->id;
            pkt->l34.dest = iph->id;
            pkt->l2.ssnid = iph->id;
            pkt->l34.frg = 1;
        }
    }

    return DP_PRET_OK;
}

static int __always_inline dp_parse_ipv6(struct decoder *p, void *md,
                                         struct xpkt *pkt)
{
    struct ipv6hdr *ip6 = TC_PTR(p->data_begin);

    if ((void *)(ip6 + 1) > p->data_end) {
        return DP_PRET_FAIL;
    }

    if (ipv6_addr_is_multicast(&ip6->daddr) ||
        ipv6_addr_is_multicast(&ip6->saddr)) {
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

    pkt->pm.l4_off = TC_PTR_SUB(TC_PTR_ADD(ip6, sizeof(*ip6)), p->start);
    p->data_begin = TC_PTR_ADD(ip6, sizeof(*ip6));

    if (pkt->l34.nw_proto == IPPROTO_TCP) {
        return dp_parse_tcp(p, md, pkt);
    } else if (pkt->l34.nw_proto == IPPROTO_UDP) {
        return dp_parse_udp(p, md, pkt);
    } else if (pkt->l34.nw_proto == IPPROTO_ICMPV6) {
        return dp_parse_icmp6(p, md, pkt);
    }
    return DP_PRET_OK;
}

static int __always_inline fsm_xpkt_decode(void *md, struct xpkt *pkt,
                                          int skip_v6)
{
    int ret = 0;
    struct decoder coder;

    coder.in_pkt = 0;
    coder.skip_l2 = 0;
    coder.skip_v6 = skip_v6;
    coder.start = TC_PTR(XPKT_DATA(md));
    coder.data_begin = TC_PTR(coder.start);
    coder.data_end = TC_PTR(XPKT_DATA_END(md));

    pkt->pm.py_bytes = TC_PTR_SUB(coder.data_end, coder.data_begin);

    if ((ret = dp_parse_eth(&coder, md, pkt))) {
        goto handle_excp;
    }

    if ((ret = dp_parse_vlan(&coder, md, pkt))) {
        goto handle_excp;
    }

    pkt->pm.l3_off = TC_PTR_SUB(coder.data_begin, coder.start);

    if (pkt->l2.dl_type == htons(ETH_P_ARP)) {
        ret = dp_parse_arp(&coder, md, pkt);
    } else if (pkt->l2.dl_type == htons(ETH_P_IP)) {
        ret = dp_parse_ipv4(&coder, md, pkt);
    } else if (pkt->l2.dl_type == htons(ETH_P_IPV6)) {
        if (coder.skip_v6 == 1) {
            return 0;
        }
        ret = dp_parse_ipv6(&coder, md, pkt);
    }
    // else if (pkt->l2m.dl_type == htons(ETH_P_F4)) {
    //   ret = dp_parse_f4(&p, md, pkt);
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

static int __always_inline dp_unparse_packet_always(void *ctx, struct xpkt *pkt)
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

static int __always_inline dp_unparse_packet(void *ctx, struct xpkt *pkt)
{
    return dp_do_out(ctx, pkt);
}

#endif