#ifndef __F4_BPF_LB_H__
#define __F4_BPF_LB_H__

#include "bpf-macros.h"
#include "bpf-dbg.h"

INLINE(int)
xpkt_nat_load(skb_t *skb, xpkt_t *pkt, struct dp_nat_act *na, int do_snat)
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
    return 0;
}

INLINE(int)
xpkt_nat_endpoint(skb_t *skb, xpkt_t *pkt, nat_ops_t *ops)
{
    int sel = -1;
    __u8 ep_idx = 0;
    __u8 ep_sel = 0;
    nat_endpoint_t *ep;

    if (ops->lb_algo == NAT_LB_HASH) {
        bpf_set_hash_invalid(skb);
        sel = bpf_get_hash_recalc(skb) % ops->ep_cnt;
        if (sel >= 0 && sel < F4_MAX_ENDPOINTS) {
            if (ops->endpoints[sel].inactive) {
                goto lb_rr;
            }
        }
    }

    if (ops->lb_algo == NAT_LB_RDRB) {
    lb_rr:
        xpkt_spin_lock(&ops->lock);
        ep_sel = ops->ep_sel;
        while (ep_idx < F4_MAX_ENDPOINTS) {
            if (ep_sel < F4_MAX_ENDPOINTS) {
                ep = &ops->endpoints[ep_sel];
                if (ep->inactive == 0) {
                    ops->ep_sel = (ep_sel + 1) % ops->ep_cnt;
                    sel = ep_sel;
                    break;
                }
            }
            ep_sel++;
            ep_sel = ep_sel % ops->ep_cnt;
            ep_idx++;
        }
        xpkt_spin_unlock(&ops->lock);
    }

    return sel;
}

INLINE(int) xpkt_nat_proc(skb_t *skb, xpkt_t *pkt)
{
    nat_key_t key;
    nat_endpoint_t *ep;
    nat_ops_t *ops;
    int ep_sel;

    memset(&key, 0, sizeof(key));
    XADDR_COPY(key.daddr, pkt->l34.daddr);
    if (pkt->l34.proto != IPPROTO_ICMP) {
        key.dport = pkt->l34.dest;
    } else {
        key.dport = 0;
    }
    key.proto = pkt->l34.proto;
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
        ep_sel = xpkt_nat_endpoint(skb, pkt, ops);
        pkt->ctx.nf = ops->nat_type == DP_SET_SNAT ? F4_NAT_SRC : F4_NAT_DST;

        /* FIXME - Do not select inactive end-points
         * Need multi-passes for selection
         */
        if (ep_sel >= 0 && ep_sel < F4_MAX_ENDPOINTS) {
            ep = &ops->endpoints[ep_sel];

            XADDR_COPY(pkt->nat.nxip, ep->nat_xip);
            XADDR_COPY(pkt->nat.nrip, ep->nat_rip);
            XMAC_COPY(pkt->nat.nxmac, ep->nat_xmac);
            XMAC_COPY(pkt->nat.nrmac, ep->nat_rmac);
            pkt->nat.nxifi = ep->nat_xifi;
            pkt->nat.nrport = ep->nat_rport;
            if (ep->nat_xport) {
                pkt->nat.nxport = ep->nat_xport;
            } else {
                pkt->nat.nxport = pkt->l34.source;
            }

            pkt->nat.nv6 = ep->nv6 ? 1 : 0;
            pkt->nat.ep_sel = ep_sel;
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