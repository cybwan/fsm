#ifndef __F4_BPF_LB_H__ 
#define __F4_BPF_LB_H__

#include "bpf-dbg.h"

static int __always_inline
dp_pipe_set_nat(void *ctx, struct xpkt *pkt, 
                struct dp_nat_act *na, int do_snat)
{
  pkt->pm.nf = do_snat ? F4_NAT_SRC : F4_NAT_DST;
  DP_XADDR_CP(pkt->nat.nxip, na->xip);
  DP_XADDR_CP(pkt->nat.nrip, na->rip);
  DP_XMAC_CP(pkt->nat.nxmac, na->xmac);
  DP_XMAC_CP(pkt->nat.nrmac, na->rmac);
  pkt->nat.nxifi = na->xifi;
  pkt->nat.nxport = na->xport;
  pkt->nat.nrport = na->rport;
  pkt->nat.nv6 = na->nv6 ? 1 : 0;
  pkt->nat.dsr = na->dsr;
  pkt->nat.cdis = na->cdis;
  return 0;
}

static int __always_inline
dp_sel_nat_ep(void *ctx, struct xpkt *pkt, struct dp_nat_tacts *act)
{
  int sel = -1;
  __u8 n = 0;
  __u16 i = 0;
  struct dp_xfrm_inf *nxfrm_act;
  __u16 rule_num = act->ca.cidx;

  if (act->sel_type == NAT_LB_SEL_RR) {
    dp_spin_lock(&act->lock);
    i = act->sel_hint; 

    while (n < F4_MAX_NXFRMS) {
      if (i >= 0 && i < F4_MAX_NXFRMS) {
        nxfrm_act = &act->nxfrms[i];
        if (nxfrm_act->inactive == 0) {
          act->sel_hint = (i + 1) % act->nxfrm;
          sel = i;
          break;
        }
      }
      i++;
      i = i % act->nxfrm;
      n++;
    }
    dp_spin_unlock(&act->lock);
  } else if (act->sel_type == NAT_LB_SEL_HASH) {
    sel = dp_get_pkt_hash(ctx) % act->nxfrm;
    if (sel >= 0 && sel < F4_MAX_NXFRMS) {
      /* Fall back if hash selection gives us a deadend */
      if (act->nxfrms[sel].inactive) {
        for (i = 0; i < F4_MAX_NXFRMS; i++) {
          if (act->nxfrms[i].inactive == 0) {
            sel = i;
            break;
          }
        }
      }
    }
  } else if (act->sel_type == NAT_LB_SEL_RR_PERSIST) {
    __u64 now = bpf_ktime_get_ns();
    __u64 base;
    __u64 tfc = 0;

    dp_spin_lock(&act->lock);
    if (act->base_to == 0 || now - act->lts > act->pto) {
      act->base_to = (now/act->pto) * act->pto;
    }
    base = act->base_to;
    if (act->pto) {
      tfc = base/act->pto;
    } else {
      act->pto = NAT_LB_PERSIST_TIMEOUT;
      tfc = base/NAT_LB_PERSIST_TIMEOUT;
    }
    sel = (pkt->l34.saddr4 & 0xff) ^  ((pkt->l34.saddr4 >> 24) & 0xff) ^ (tfc & 0xff);
    sel %= act->nxfrm;
    act->lts = now;
    dp_spin_unlock(&act->lock);
  } else if (act->sel_type == NAT_LB_SEL_LC) {
    struct dp_nat_epacts *epa;
    __u32 key = rule_num;
    __u32 lc = 0;
    epa = bpf_map_lookup_elem(&f4gw_nat_ep, &key);
    if (epa != NULL) {
      epa->ca.act_type = DP_SET_NACT_SESS;
      dp_spin_lock(&epa->lock);
      for (i = 0; i < F4_MAX_NXFRMS; i++) {
        __u32 as = epa->active_sess[i];
        if (sel < 0) {
          sel = i;
          lc = as;
        } else {
          if (lc > as) {
            sel = i;
            lc = as;
          }
        }
      }
      if (sel >= 0 && sel < F4_MAX_NXFRMS) {
        epa->active_sess[sel]++;
      }
      dp_spin_unlock(&epa->lock);
    }
  }

  return sel;
}

static int __always_inline
dp_do_nat(void *ctx, struct xpkt *pkt)
{
  struct dp_nat_key key;
  struct dp_xfrm_inf *nxfrm_act;
  struct dp_nat_tacts *act;
  int sel;

  memset(&key, 0, sizeof(key));
  DP_XADDR_CP(key.daddr, pkt->l34.daddr);
  if (pkt->l34.nw_proto != IPPROTO_ICMP) {
    key.dport = pkt->l34.dest;
  } else {
    key.dport = 0;
  }
  key.zone = pkt->pm.zone;
  key.l4proto = pkt->l34.nw_proto;
  key.mark = (__u16)(pkt->pm.dp_mark & 0xffff);
  if (pkt->l2.dl_type == ntohs(ETH_P_IPV6)) {
    key.v6 = 1;
  }

  memset(&key, 0, sizeof(key));
  key.l4proto = pkt->l34.nw_proto;
  key.v6 = 0;

  act = bpf_map_lookup_elem(&f4gw_nat, &key);
  if (!act) {
    /* Default action - Nothing to do */
    pkt->pm.nf &= ~F4_NAT_DST;
    return 0;
  }

  if (act->ca.act_type == DP_SET_SNAT || 
      act->ca.act_type == DP_SET_DNAT) {
    sel = dp_sel_nat_ep(ctx, pkt, act);

    pkt->nat.dsr = act->ca.oaux ? 1: 0;
    pkt->nat.cdis = act->cdis ? 1: 0;
    pkt->pm.nf = act->ca.act_type == DP_SET_SNAT ? F4_NAT_SRC : F4_NAT_DST;

    /* FIXME - Do not select inactive end-points 
     * Need multi-passes for selection
     */
    if (sel >= 0 && sel < F4_MAX_NXFRMS) {
      nxfrm_act = &act->nxfrms[sel];

      DP_XADDR_CP(pkt->nat.nxip, nxfrm_act->nat_xip);
      DP_XADDR_CP(pkt->nat.nrip, nxfrm_act->nat_rip);
      DP_XMAC_CP(pkt->nat.nxmac, nxfrm_act->nat_xmac);
      DP_XMAC_CP(pkt->nat.nrmac, nxfrm_act->nat_rmac);
      pkt->nat.nxifi = nxfrm_act->nat_xifi;
      pkt->nat.nrport = nxfrm_act->nat_rport;
      if(nxfrm_act->nat_xport) {
        pkt->nat.nxport = nxfrm_act->nat_xport;
      } else {
        pkt->nat.nxport = pkt->l34.source;
      }

      pkt->nat.nv6 = nxfrm_act->nv6 ? 1: 0;
      pkt->nat.sel_aid = sel;
      pkt->nat.ito = act->ito;
      pkt->pm.rule_id =  act->ca.cidx;

      /* Special case related to host-dnat */
      if (pkt->l34.saddr4 == pkt->nat.nxip4 && pkt->pm.nf == F4_NAT_DST) {
        pkt->nat.nxip4 = 0;
      }
    } else {
      pkt->pm.nf = 0;
    }
  } else { 
    F4_PPLN_DROPC(pkt, F4_PIPE_RC_ACT_UNK);
  }

  if (pkt->l34.nw_proto == IPPROTO_TCP || pkt->l34.nw_proto == IPPROTO_UDP) {
    struct dp_dnat_opt_key okey;
    struct dp_dnat_opt_tact oact;

    memset(&okey, 0, sizeof(okey));
    memset(&oact, 0, sizeof(oact));

    okey.v6 = 0;
    okey.l4proto = pkt->l34.nw_proto;
    okey.xaddr = pkt->l34.saddr4;
    okey.xport = ntohs(pkt->l34.source);

    oact.daddr = pkt->l34.daddr4;
    oact.saddr = pkt->l34.saddr4;
    oact.dport = ntohs(pkt->l34.dest);
    oact.sport = ntohs(pkt->l34.source);
    oact.ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&f4gw_dnat_opts, &okey, &oact, BPF_ANY);
  }

  return 1;
}

#endif