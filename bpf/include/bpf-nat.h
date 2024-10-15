#ifndef __F4_BPF_NAT_H__ 
#define __F4_BPF_NAT_H__

static int __always_inline
dp_do_dnat(void *ctx, struct xfrm *xf)
{
  void *dend = DP_TC_PTR(FSM_PKT_DATA_END(ctx));

  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    struct tcphdr *tcp = DP_ADD_PTR(FSM_PKT_DATA(ctx), xf->pm.l4_off);
    if ((void *)(tcp + 1) > dend) {
      F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
      return -1;
    }

    if (xf->nm.nrip4 == 0) {
      // /* Hairpin nat to host */
      // xip = xf->l34m.saddr4;
      // dp_set_tcp_src_ip(ctx, xf, xf->l34m.daddr4);
      // dp_set_tcp_dst_ip(ctx, xf, xip);
    } else {
      // dp_set_tcp_src_ip(ctx, xf, xf->nm.nxip4);
      dp_set_tcp_dst_ip(ctx, xf, xf->nm.nrip4);
    }
    // dp_set_tcp_sport(ctx, xf, xf->nm.nxport);
    dp_set_tcp_dport(ctx, xf, xf->nm.nrport);
} 
  else if (xf->l34m.nw_proto == IPPROTO_UDP)  {
    struct udphdr *udp = DP_ADD_PTR(FSM_PKT_DATA(ctx), xf->pm.l4_off);

    if (udp + 1 > dend) {
      F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
      return -1;
    }

    if (xf->nm.nrip4 == 0) {
      // /* Hairpin nat to host */
      // xip = xf->l34m.saddr4;
      // dp_set_udp_src_ip(ctx, xf, xf->l34m.daddr4);
      // dp_set_udp_dst_ip(ctx, xf, xip);
    } else {
      // dp_set_udp_src_ip(ctx, xf, xf->nm.nxip4);
      dp_set_udp_dst_ip(ctx, xf, xf->nm.nrip4);
    }
    // dp_set_udp_sport(ctx, xf, xf->nm.nxport);
    dp_set_udp_dport(ctx, xf, xf->nm.nrport);
  } else if (xf->l34m.nw_proto == IPPROTO_ICMP)  {
    // dp_set_icmp_src_ip(ctx, xf, xf->nm.nxip4);
    dp_set_icmp_dst_ip(ctx, xf, xf->nm.nrip4);
  }

  return 0;
}

static int __always_inline
dp_do_snat(void *ctx, struct xfrm *xf)
{
  void *dend = DP_TC_PTR(FSM_PKT_DATA_END(ctx));

  if (xf->l34m.nw_proto == IPPROTO_TCP)  {
    struct iphdr *iph = DP_TC_PTR(FSM_PKT_DATA(ctx) + xf->pm.l3_off);
    if ((void *)(iph + 1) > dend)  {
      F4_PPLN_DROPC(xf, F4_PIPE_RC_PLRT_ERR);
      return -1;
    }
    struct tcphdr *tcp = DP_ADD_PTR(FSM_PKT_DATA(ctx), xf->pm.l4_off);
    if ((void *)(tcp + 1) > dend) {
      F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
      return -1;
    }

    if (xf->nm.nrip4 == 0) {
      /* Hairpin nat to host */
      // xip = xf->l34m.saddr4;
      // dp_set_tcp_src_ip(ctx, xf, xf->l34m.daddr4);
      // dp_set_tcp_dst_ip(ctx, xf, xip);
    } else {
      dp_set_tcp_src_ip(ctx, xf, xf->nm.nxip4);
      // dp_set_tcp_dst_ip(ctx, xf, xf->nm.nrip4);
    }
    dp_set_tcp_sport(ctx, xf, xf->nm.nxport);
    // dp_set_tcp_dport(ctx, xf, xf->nm.nrport);
  } else if (xf->l34m.nw_proto == IPPROTO_UDP)  {
    struct udphdr *udp = DP_ADD_PTR(FSM_PKT_DATA(ctx), xf->pm.l4_off);

    if (udp + 1 > dend) {
      F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
      return -1;
    }

    if (xf->nm.nrip4 == 0) {
      // /* Hairpin nat to host */
      // xip = xf->l34m.saddr4;
      // dp_set_udp_src_ip(ctx, xf, xf->l34m.daddr4);
      // dp_set_udp_dst_ip(ctx, xf, xip);
    } else {
      dp_set_udp_src_ip(ctx, xf, xf->nm.nxip4);
      // dp_set_udp_dst_ip(ctx, xf, xf->nm.nrip4);
    }
    dp_set_udp_sport(ctx, xf, xf->nm.nxport);
    // dp_set_udp_dport(ctx, xf, xf->nm.nrport);
  } else if (xf->l34m.nw_proto == IPPROTO_ICMP)  {
    dp_set_icmp_src_ip(ctx, xf, xf->nm.nxip4);
    // dp_set_icmp_dst_ip(ctx, xf, xf->nm.nrip4);
  }

  return 0;
}

#endif