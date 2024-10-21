#ifndef __F4_BPF_LB_H__
#define __F4_BPF_LB_H__

#include "bpf-dbg.h"

__attribute__((__always_inline__)) static inline int
xpkt_nat_set(skb_t *skb, struct xpkt *pkt, struct dp_nat_act *na, int do_snat)
{
    pkt->ctx.nf = do_snat ? F4_NAT_SRC : F4_NAT_DST;
    XADDR_COPY(pkt->nat.nxip, na->xip);
    XADDR_COPY(pkt->nat.nrip, na->rip);
    XMAC_COPY(pkt->nat.nxmac, na->xmac);
    XMAC_COPY(pkt->nat.nrmac, na->rmac);
    pkt->nat.nxifi = na->xifi;
    pkt->nat.nxport = na->xport;
    pkt->nat.nrport = na->rport;
    pkt->nat.nv6 = na->nv6 ? 1 : 0;
    pkt->nat.dsr = na->dsr;
    pkt->nat.cdis = na->cdis;
    return 0;
}

__attribute__((__always_inline__)) static inline int
xpkt_nat_endpoint(skb_t *skb, struct xpkt *pkt, struct xpkt_nat_ops *ops)
{
    int sel = -1;
    __u8 n = 0;
    __u16 i = 0;
    struct xpkt_nat_endpoint *nxfrm_act;

    if (ops->algo == NAT_LB_RDRB) {
        xpkt_spin_lock(&ops->lock);
        i = ops->sel_hint;

        while (n < F4_MAX_NXFRMS) {
            if (i >= 0 && i < F4_MAX_NXFRMS) {
                nxfrm_act = &ops->nxfrms[i];
                if (nxfrm_act->inactive == 0) {
                    ops->sel_hint = (i + 1) % ops->nxfrm;
                    sel = i;
                    break;
                }
            }
            i++;
            i = i % ops->nxfrm;
            n++;
        }
        xpkt_spin_unlock(&ops->lock);
    } else if (ops->algo == NAT_LB_HASH) {
        sel = xpkt_get_pkt_hash(skb) % ops->nxfrm;
        if (sel >= 0 && sel < F4_MAX_NXFRMS) {
            /* Fall back if hash selection gives us a deadend */
            if (ops->nxfrms[sel].inactive) {
                for (i = 0; i < F4_MAX_NXFRMS; i++) {
                    if (ops->nxfrms[i].inactive == 0) {
                        sel = i;
                        break;
                    }
                }
            }
        }
    }

    return sel;
}

__attribute__((__always_inline__)) static inline int
xpkt_nat_proc(skb_t *skb, struct xpkt *pkt)
{
    struct xpkt_nat_key key;
    struct xpkt_nat_endpoint *nxfrm_act;
    struct xpkt_nat_ops *ops;
    int sel;

    memset(&key, 0, sizeof(key));
    XADDR_COPY(key.daddr, pkt->l34.daddr);
    if (pkt->l34.proto != IPPROTO_ICMP) {
        key.dport = pkt->l34.dest;
    } else {
        key.dport = 0;
    }
    key.zone = pkt->ctx.zone;
    key.proto = pkt->l34.proto;
    key.mark = (__u16)(pkt->ctx.dp_mark & 0xffff);
    if (pkt->l2.dl_type == ntohs(ETH_P_IPV6)) {
        key.v6 = 1;
    }

    memset(&key, 0, sizeof(key));
    key.proto = pkt->l34.proto;
    key.v6 = 0;

    ops = bpf_map_lookup_elem(&fsm_nat, &key);
    if (!ops) {
        /* Default action - Nothing to do */
        pkt->ctx.nf &= ~F4_NAT_DST;
        return 0;
    }

    if (ops->nat_type == DP_SET_SNAT || ops->nat_type == DP_SET_DNAT) {
        sel = xpkt_nat_endpoint(skb, pkt, ops);
        pkt->ctx.nf = ops->nat_type == DP_SET_SNAT ? F4_NAT_SRC : F4_NAT_DST;

        /* FIXME - Do not select inactive end-points
         * Need multi-passes for selection
         */
        if (sel >= 0 && sel < F4_MAX_NXFRMS) {
            nxfrm_act = &ops->nxfrms[sel];

            XADDR_COPY(pkt->nat.nxip, nxfrm_act->nat_xip);
            XADDR_COPY(pkt->nat.nrip, nxfrm_act->nat_rip);
            XMAC_COPY(pkt->nat.nxmac, nxfrm_act->nat_xmac);
            XMAC_COPY(pkt->nat.nrmac, nxfrm_act->nat_rmac);
            pkt->nat.nxifi = nxfrm_act->nat_xifi;
            pkt->nat.nrport = nxfrm_act->nat_rport;
            if (nxfrm_act->nat_xport) {
                pkt->nat.nxport = nxfrm_act->nat_xport;
            } else {
                pkt->nat.nxport = pkt->l34.source;
            }

            pkt->nat.nv6 = nxfrm_act->nv6 ? 1 : 0;
            pkt->nat.sel_aid = sel;
            pkt->nat.ito = ops->ito;

            /* Special case related to host-dnat */
            if (pkt->l34.saddr4 == pkt->nat.nxip4 &&
                pkt->ctx.nf == F4_NAT_DST) {
                pkt->nat.nxip4 = 0;
            }
        } else {
            pkt->ctx.nf = 0;
        }
    } else {
        F4_PPLN_DROPC(pkt, F4_PIPE_RC_ACT_UNK);
    }

    if (pkt->l34.proto == IPPROTO_TCP || pkt->l34.proto == IPPROTO_UDP) {
        struct dp_dnat_opt_key okey;
        struct dp_dnat_opt_tact oact;

        memset(&okey, 0, sizeof(okey));
        memset(&oact, 0, sizeof(oact));

        okey.v6 = 0;
        okey.proto = pkt->l34.proto;
        okey.xaddr = pkt->l34.saddr4;
        okey.xport = ntohs(pkt->l34.source);

        oact.daddr = pkt->l34.daddr4;
        oact.saddr = pkt->l34.saddr4;
        oact.dport = ntohs(pkt->l34.dest);
        oact.sport = ntohs(pkt->l34.source);
        oact.ts = bpf_ktime_get_ns();

        bpf_map_update_elem(&fsm_dnat_opt, &okey, &oact, BPF_ANY);
    }

    return 1;
}

#endif