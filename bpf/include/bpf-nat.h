#ifndef __F4_BPF_NAT_H__
#define __F4_BPF_NAT_H__

__attribute__((__always_inline__)) static inline int
xpkt_do_dnat(void *ctx, struct xpkt *pkt)
{
    void *dend = XPKT_PTR(XPKT_DATA_END(ctx));

    if (pkt->l34.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = XPKT_PTR_ADD(XPKT_DATA(ctx), pkt->pm.l4_off);
        if ((void *)(tcp + 1) > dend) {
            F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLERR);
            return -1;
        }

        if (pkt->nat.nrip4 == 0) {
            // /* Hairpin nat to host */
            // xip = pkt->l34m.saddr4;
            // xpkt_csum_replace_tcp_src_ip(ctx, pkt, pkt->l34m.daddr4);
            // xpkt_csum_replace_tcp_dst_ip(ctx, pkt, xip);
        } else {
            // xpkt_csum_replace_tcp_src_ip(ctx, xf, pkt->nm.nxip4);
            xpkt_csum_replace_tcp_dst_ip(ctx, pkt, pkt->nat.nrip4);
        }
        // xpkt_csum_replace_tcp_src_port(ctx, xf, pkt->nm.nxport);
        xpkt_csum_replace_tcp_dst_port(ctx, pkt, pkt->nat.nrport);
    } else if (pkt->l34.proto == IPPROTO_UDP) {
        struct udphdr *udp = XPKT_PTR_ADD(XPKT_DATA(ctx), pkt->pm.l4_off);

        if (udp + 1 > dend) {
            F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLERR);
            return -1;
        }

        if (pkt->nat.nrip4 == 0) {
            // /* Hairpin nat to host */
            // xip = pkt->l34m.saddr4;
            // xpkt_csum_replace_udp_src_ip(ctx, pkt, pkt->l34m.daddr4);
            // xpkt_csum_replace_udp_dst_ip(ctx, pkt, xip);
        } else {
            // xpkt_csum_replace_udp_src_ip(ctx, pkt, pkt->nm.nxip4);
            xpkt_csum_replace_udp_dst_ip(ctx, pkt, pkt->nat.nrip4);
        }
        // xpkt_csum_replace_udp_src_port(ctx, pkt, pkt->nm.nxport);
        xpkt_csum_replace_udp_dst_port(ctx, pkt, pkt->nat.nrport);
    } else if (pkt->l34.proto == IPPROTO_ICMP) {
        // xpkt_csum_replace_icmp_src_ip(ctx, pkt, pkt->nm.nxip4);
        xpkt_csum_replace_icmp_dst_ip(ctx, pkt, pkt->nat.nrip4);
    }

    return 0;
}

__attribute__((__always_inline__)) static inline int
xpkt_do_snat(void *ctx, struct xpkt *pkt)
{
    void *dend = XPKT_PTR(XPKT_DATA_END(ctx));

    if (pkt->l34.proto == IPPROTO_TCP) {
        struct iphdr *iph = XPKT_PTR(XPKT_DATA(ctx) + pkt->pm.l3_off);
        if ((void *)(iph + 1) > dend) {
            F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLRT_ERR);
            return -1;
        }
        struct tcphdr *tcp = XPKT_PTR_ADD(XPKT_DATA(ctx), pkt->pm.l4_off);
        if ((void *)(tcp + 1) > dend) {
            F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLERR);
            return -1;
        }

        if (pkt->nat.nrip4 == 0) {
            /* Hairpin nat to host */
            // xip = pkt->l34m.saddr4;
            // xpkt_csum_replace_tcp_src_ip(ctx, pkt, pkt->l34m.daddr4);
            // xpkt_csum_replace_tcp_dst_ip(ctx, pkt, xip);
        } else {
            xpkt_csum_replace_tcp_src_ip(ctx, pkt, pkt->nat.nxip4);
            // xpkt_csum_replace_tcp_dst_ip(ctx, pkt, pkt->nm.nrip4);
        }
        xpkt_csum_replace_tcp_src_port(ctx, pkt, pkt->nat.nxport);
        // xpkt_csum_replace_tcp_dst_port(ctx, pkt, pkt->nm.nrport);
    } else if (pkt->l34.proto == IPPROTO_UDP) {
        struct udphdr *udp = XPKT_PTR_ADD(XPKT_DATA(ctx), pkt->pm.l4_off);

        if (udp + 1 > dend) {
            F4_PPLN_DROPC(pkt, F4_PIPE_RC_PLERR);
            return -1;
        }

        if (pkt->nat.nrip4 == 0) {
            // /* Hairpin nat to host */
            // xip = pkt->l34m.saddr4;
            // xpkt_csum_replace_udp_src_ip(ctx, pkt, pkt->l34m.daddr4);
            // xpkt_csum_replace_udp_dst_ip(ctx, pkt, xip);
        } else {
            xpkt_csum_replace_udp_src_ip(ctx, pkt, pkt->nat.nxip4);
            // xpkt_csum_replace_udp_dst_ip(ctx, pkt, pkt->nm.nrip4);
        }
        xpkt_csum_replace_udp_src_port(ctx, pkt, pkt->nat.nxport);
        // xpkt_csum_replace_udp_dst_port(ctx, pkt, pkt->nm.nrport);
    } else if (pkt->l34.proto == IPPROTO_ICMP) {
        xpkt_csum_replace_icmp_src_ip(ctx, pkt, pkt->nat.nxip4);
        // xpkt_csum_replace_icmp_dst_ip(ctx, pkt, pkt->nm.nrip4);
    }

    return 0;
}

#endif