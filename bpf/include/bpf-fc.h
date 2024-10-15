#ifndef __F4_BPF_FC_H__ 
#define __F4_BPF_FC_H__

#include "bpf-dbg.h"

static int  __always_inline
dp_mk_fcv4_key(struct xpkt *pkt, struct dp_fcv4_key *key)
{
  key->daddr      = pkt->l34.daddr4;
  key->saddr      = pkt->l34.saddr4;
  key->sport      = pkt->l34.source;
  key->dport      = pkt->l34.dest;
  key->l4proto    = pkt->l34.nw_proto;
  key->pad        = 0;
  key->in_port    = 0;
  return 0;
}

static int __always_inline
dp_do_fcv4_lkup(void *ctx, struct xpkt *pkt)
{
  struct dp_fcv4_key key;
  struct dp_fc_tacts *acts;
  struct dp_fc_tact *ta;
  int ret = 1;
  int z = 0;

  dp_mk_fcv4_key(pkt, &key);

  acts = bpf_map_lookup_elem(&f4gw_fc_v4, &key);
  if (!acts) {
    /* xfck - fcache key table is maintained so that 
     * there is no need to make fcv4 key again in
     * tail-call sections
     */
    bpf_map_update_elem(&f4gw_xfck, &z, &key, BPF_ANY);
    return 0; 
  }

  /* Check timeout */ 
  if (bpf_ktime_get_ns() - acts->its > FC_V4_DPTO) {
    bpf_map_update_elem(&f4gw_xfck, &z, &key, BPF_ANY);
    bpf_map_delete_elem(&f4gw_fc_v4, &key);
    pkt->pm.rcode |= F4_PIPE_RC_FCTO;
    return 0; 
  }

  if (acts->ca.ftrap) {
    pkt->pm.rcode |= F4_PIPE_RC_FCBP;
    return 0; 
  }

  pkt->pm.phit |= F4_DP_FC_HIT;
  pkt->pm.zone = acts->zone;
  pkt->pm.pten = acts->pten;

  if (acts->fcta[DP_SET_SNAT].ca.act_type == DP_SET_SNAT) {
    ta = &acts->fcta[DP_SET_SNAT];

    if (ta->nat_act.fr == 1 || ta->nat_act.doct) {
      pkt->pm.rcode |= F4_PIPE_RC_FCBP;
      return 0;
    }

    dp_pipe_set_nat(ctx, pkt, &ta->nat_act, 1);
  } else if (acts->fcta[DP_SET_DNAT].ca.act_type == DP_SET_DNAT) {
    ta = &acts->fcta[DP_SET_DNAT];

    if (ta->nat_act.fr == 1 || ta->nat_act.doct) {
      pkt->pm.rcode |= F4_PIPE_RC_FCBP;
      return 0;
    }

    dp_pipe_set_nat(ctx, pkt, &ta->nat_act, 0);
  }


  /* Catch any conditions which need us to go to cp/ct */
  if (pkt->pm.l4fin) {
    acts->ca.ftrap = 1;
    goto del_out;
  }

  // DP_RUN_CT_HELPER(pkt);

  DP_XMAC_CP(pkt->l2.dl_src, pkt->nat.nxmac);
  DP_XMAC_CP(pkt->l2.dl_dst, pkt->nat.nrmac);
  pkt->pm.oport = pkt->nat.nxifi;
  
  dp_unparse_packet_always(ctx, pkt);
  // dp_unparse_packet(ctx, pkt);

  F4_PPLN_RDR(pkt);

  return ret;

del_out:
  bpf_map_delete_elem(&f4gw_fc_v4, &key);
  pkt->pm.rcode |= F4_PIPE_RC_FCBP;
  return 0;
}

static int __always_inline
dp_ing_fc_main(void *ctx, struct xpkt *pkt)
{
  int z = 0;
  int oif;
  if (pkt->pm.pipe_act == 0 &&
      pkt->l2.dl_type == ntohs(ETH_P_IP)) {
    if (dp_do_fcv4_lkup(ctx, pkt) == 1) {
      if (pkt->pm.pipe_act == F4_PIPE_RDR) {
        // oif = pkt->pm.oport;
        // return bpf_redirect(oif, 0);
        return TC_ACT_OK;
      }
    }
  }

  bpf_map_update_elem(&fsm_xpkts, &z, pkt, BPF_ANY);
  bpf_tail_call(ctx, &fsm_progs, F4_DP_SH_PGM_ID);
  return TC_ACT_SHOT;
}

static int __always_inline
dp_egr_main(void *ctx, struct xpkt *pkt)
{
  if (pkt->l2.dl_type == ntohs(ETH_P_IP) && (pkt->l34.nw_proto == IPPROTO_TCP || pkt->l34.nw_proto == IPPROTO_UDP)) {
    struct dp_snat_opt_key key;
    struct dp_snat_opt_tact *adat = NULL;

    memset(&key, 0, sizeof(key));
    key.v6 = 0;
    key.l4proto = pkt->l34.nw_proto;
    key.saddr = pkt->l34.saddr4;
    key.daddr = pkt->l34.daddr4;
    key.sport = ntohs(pkt->l34.source);
    key.dport = ntohs(pkt->l34.dest);

    adat = bpf_map_lookup_elem(&f4gw_snat_opts, &key);

    if (adat != NULL) {
      if (pkt->pm.igr) {
        if (pkt->l34.nw_proto == IPPROTO_TCP) {
          dp_set_tcp_dst_ip(ctx, pkt, adat->xaddr);
          dp_set_tcp_dport(ctx, pkt, htons(adat->xport));
        } else if (pkt->l34.nw_proto == IPPROTO_UDP) {
          dp_set_udp_dst_ip(ctx, pkt, adat->xaddr);
          dp_set_udp_dport(ctx, pkt, htons(adat->xport));
        }
      } else if (pkt->pm.egr) {
        if (pkt->l34.nw_proto == IPPROTO_TCP) {
          dp_set_tcp_src_ip(ctx, pkt, adat->xaddr);
          dp_set_tcp_sport(ctx, pkt, htons(adat->xport));
        } else if (pkt->l34.nw_proto == IPPROTO_UDP) {
          dp_set_udp_src_ip(ctx, pkt, adat->xaddr);
          dp_set_udp_sport(ctx, pkt, htons(adat->xport));
        }
      }
    }
  }

  return TC_ACT_OK;
}

#endif