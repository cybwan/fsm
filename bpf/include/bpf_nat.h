#ifndef __F4_BPF_NAT_H__
#define __F4_BPF_NAT_H__

#include "bpf_macros.h"

INTERNAL(int)
xpkt_do_dnat(skb_t *skb, xpkt_t *pkt)
{
    void *dend = XPKT_PTR(XPKT_DATA_END(skb));

    if (pkt->l34.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = XPKT_PTR_ADD(XPKT_DATA(skb), pkt->ctx.l4_off);
        if ((void *)(tcp + 1) > dend) {
            F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLERR);
            return -1;
        }

        if (pkt->nat.raddr4 == 0) {
            // /* Hairpin nat to host */
            // xaddr = pkt->l34m.saddr4;
            // xpkt_csum_replace_tcp_src_ip(skb, pkt, pkt->l34m.daddr4);
            // xpkt_csum_replace_tcp_dst_ip(skb, pkt, xaddr);
        } else {
            // xpkt_csum_replace_tcp_src_ip(skb, xf, pkt->nm.xaddr4);
            xpkt_csum_replace_tcp_dst_ip(skb, pkt, pkt->nat.raddr4);
        }
        // xpkt_csum_replace_tcp_src_port(skb, xf, pkt->nm.xport);
        xpkt_csum_replace_tcp_dst_port(skb, pkt, pkt->nat.rport);
    } else if (pkt->l34.proto == IPPROTO_UDP) {
        struct udphdr *udp = XPKT_PTR_ADD(XPKT_DATA(skb), pkt->ctx.l4_off);

        if (udp + 1 > dend) {
            F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLERR);
            return -1;
        }

        if (pkt->nat.raddr4 == 0) {
            // /* Hairpin nat to host */
            // xaddr = pkt->l34m.saddr4;
            // xpkt_csum_replace_udp_src_ip(skb, pkt, pkt->l34m.daddr4);
            // xpkt_csum_replace_udp_dst_ip(skb, pkt, xaddr);
        } else {
            // xpkt_csum_replace_udp_src_ip(skb, pkt, pkt->nm.xaddr4);
            xpkt_csum_replace_udp_dst_ip(skb, pkt, pkt->nat.raddr4);
        }
        // xpkt_csum_replace_udp_src_port(skb, pkt, pkt->nm.xport);
        xpkt_csum_replace_udp_dst_port(skb, pkt, pkt->nat.rport);
    } else if (pkt->l34.proto == IPPROTO_ICMP) {
        // xpkt_csum_replace_icmp_src_ip(skb, pkt, pkt->nm.xaddr4);
        xpkt_csum_replace_icmp_dst_ip(skb, pkt, pkt->nat.raddr4);
    }

    return 0;
}

INTERNAL(int)
xpkt_do_snat(skb_t *skb, xpkt_t *pkt)
{
    void *dend = XPKT_PTR(XPKT_DATA_END(skb));

    if (pkt->l34.proto == IPPROTO_TCP) {
        struct iphdr *iph = XPKT_PTR(XPKT_DATA(skb) + pkt->ctx.l3_off);
        if ((void *)(iph + 1) > dend) {
            F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLRT_ERR);
            return -1;
        }
        struct tcphdr *tcp = XPKT_PTR_ADD(XPKT_DATA(skb), pkt->ctx.l4_off);
        if ((void *)(tcp + 1) > dend) {
            F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLERR);
            return -1;
        }

        if (pkt->nat.raddr4 == 0) {
            /* Hairpin nat to host */
            // xaddr = pkt->l34m.saddr4;
            // xpkt_csum_replace_tcp_src_ip(skb, pkt, pkt->l34m.daddr4);
            // xpkt_csum_replace_tcp_dst_ip(skb, pkt, xaddr);
        } else {
            xpkt_csum_replace_tcp_src_ip(skb, pkt, pkt->nat.xaddr4);
            // xpkt_csum_replace_tcp_dst_ip(skb, pkt, pkt->nm.raddr4);
        }
        xpkt_csum_replace_tcp_src_port(skb, pkt, pkt->nat.xport);
        // xpkt_csum_replace_tcp_dst_port(skb, pkt, pkt->nm.rport);
    } else if (pkt->l34.proto == IPPROTO_UDP) {
        struct udphdr *udp = XPKT_PTR_ADD(XPKT_DATA(skb), pkt->ctx.l4_off);

        if (udp + 1 > dend) {
            F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLERR);
            return -1;
        }

        if (pkt->nat.raddr4 == 0) {
            // /* Hairpin nat to host */
            // xaddr = pkt->l34m.saddr4;
            // xpkt_csum_replace_udp_src_ip(skb, pkt, pkt->l34m.daddr4);
            // xpkt_csum_replace_udp_dst_ip(skb, pkt, xaddr);
        } else {
            xpkt_csum_replace_udp_src_ip(skb, pkt, pkt->nat.xaddr4);
            // xpkt_csum_replace_udp_dst_ip(skb, pkt, pkt->nm.raddr4);
        }
        xpkt_csum_replace_udp_src_port(skb, pkt, pkt->nat.xport);
        // xpkt_csum_replace_udp_dst_port(skb, pkt, pkt->nm.rport);
    } else if (pkt->l34.proto == IPPROTO_ICMP) {
        xpkt_csum_replace_icmp_src_ip(skb, pkt, pkt->nat.xaddr4);
        // xpkt_csum_replace_icmp_dst_ip(skb, pkt, pkt->nm.raddr4);
    }

    return 0;
}

#endif