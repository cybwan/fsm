#ifndef __F4_BPF_CT_H__
#define __F4_BPF_CT_H__

#include "bpf_macros.h"
#include "bpf_dbg.h"
#include "bpf_dp.h"
#include "bpf_mdi.h"
#include "bpf_sm.h"

#define dp_run_ctact_helper(x, a)                                              \
    do {                                                                       \
        switch ((a)->nf) {                                                     \
        case NF_DO_NOOP:                                                       \
        case NF_DO_SNAT:                                                       \
        case NF_DO_DNAT:                                                       \
            (a)->attr.sm.t.dirs[CT_DIR_IN].pseq = (x)->l34.seq;                \
            (a)->attr.sm.t.dirs[CT_DIR_IN].pack = (x)->l34.ack_seq;            \
            break;                                                             \
        default:                                                               \
            break;                                                             \
        }                                                                      \
    } while (0)

INTERNAL(int)
dp_ct_proto_xfk_init(xpkt_t *pkt, ct_key_t *ckey, nat_ep_t *ucep,
                     ct_key_t *rkey, nat_ep_t *urep)
{
    XADDR_COPY(rkey->daddr, ckey->saddr);
    XADDR_COPY(rkey->saddr, ckey->daddr);
    rkey->sport = ckey->dport;
    rkey->dport = ckey->sport;
    rkey->proto = ckey->proto;
    rkey->v6 = ckey->v6;

    /* Apply NAT xfrm if needed */
    if (ucep->nat_flags & F4_NAT_DST) {
        rkey->v6 = (__u8)(ucep->v6);
        XADDR_COPY(rkey->saddr, ucep->raddr);
        // XADDR_COPY(rkey->daddr, ucep->xaddr);
        XADDR_COPY(urep->xaddr, ckey->daddr);
        XADDR_COPY(urep->raddr, ckey->saddr);
        if (ckey->proto != IPPROTO_ICMP) {
            rkey->dport = ucep->xport;
            rkey->sport = ucep->rport;
            urep->xport = ckey->dport;
            urep->rport = ckey->sport;
        }

        urep->nat_flags = F4_NAT_SRC;
        urep->v6 = ckey->v6;
    }
    if (ucep->nat_flags & F4_NAT_SRC) {
        rkey->v6 = ucep->v6;
        // XADDR_COPY(rkey->saddr, ucep->raddr);
        XADDR_COPY(rkey->daddr, ucep->xaddr);
        XADDR_COPY(urep->raddr, pkt->l34.saddr);
        XADDR_COPY(urep->xaddr, pkt->l34.daddr);

        if (ckey->proto != IPPROTO_ICMP) {
            rkey->dport = ucep->xport;
            rkey->sport = ucep->rport;
            urep->xport = ckey->dport;
            urep->rport = ckey->sport;
        }

        urep->nat_flags = F4_NAT_DST;
        urep->v6 = ckey->v6;
    }
    if (ucep->nat_flags & F4_NAT_HDST) {
        XADDR_COPY(rkey->saddr, ckey->saddr);
        XADDR_COPY(rkey->daddr, ckey->daddr);

        if (ckey->proto != IPPROTO_ICMP) {
            if (ucep->xport)
                rkey->sport = ucep->xport;
            else
                ucep->xport = ckey->dport;
        }

        urep->nat_flags = F4_NAT_HSRC;
        urep->v6 = ckey->v6;
        XADDR_SET_ZERO(urep->xaddr);
        XADDR_SET_ZERO(ucep->xaddr);
        if (ckey->proto != IPPROTO_ICMP)
            urep->xport = ckey->dport;
    }
    if (ucep->nat_flags & F4_NAT_HSRC) {
        XADDR_COPY(rkey->saddr, ckey->saddr);
        XADDR_COPY(rkey->daddr, ckey->daddr);

        if (ckey->proto != IPPROTO_ICMP) {
            if (ucep->xport)
                rkey->dport = ucep->xport;
            else
                ucep->xport = ckey->sport;
        }

        urep->nat_flags = F4_NAT_HDST;
        urep->v6 = ckey->v6;
        XADDR_SET_ZERO(urep->xaddr);
        XADDR_SET_ZERO(ucep->xaddr);

        if (ckey->proto != IPPROTO_ICMP)
            urep->xport = ckey->sport;
    }

    return 0;
}

#define CP_CT_NAT_TACTS(dst, src)                                              \
    memcpy(&dst->attr, &src->attr, sizeof(ct_attr_t));                         \
    dst->ito = src->ito;                                                       \
    dst->lts = src->lts;                                                       \
    memcpy(&dst->nfs.nat, &src->nfs.nat, sizeof(nf_nat_t));

INTERNAL(int)
dp_ct_est(xpkt_t *pkt, ct_key_t *ckey, ct_key_t *rkey, ct_op_t *acop,
          ct_op_t *arop)
{
    ct_attr_t *tdat = &acop->attr;
    ct_op_t *ucop, *urop;
    int cidx = 0, ridx = 1;

    ucop = bpf_map_lookup_elem(&fsm_ct_ops, &cidx);
    urop = bpf_map_lookup_elem(&fsm_ct_ops, &ridx);
    if (ucop == NULL || urop == NULL || tdat->ep.v6) {
        return 0;
    }

    CP_CT_NAT_TACTS(ucop, acop);
    CP_CT_NAT_TACTS(urop, arop);

    switch (pkt->l34.proto) {
    case IPPROTO_UDP:
        if (pkt->l2.ssnid) {
            if (pkt->ctx.dir == CT_DIR_IN) {
                ckey->sport = pkt->l2.ssnid;
                ckey->dport = pkt->l2.ssnid;
                bpf_map_update_elem(&fsm_ct, ckey, ucop, BPF_ANY);
            } else {
                rkey->sport = pkt->l2.ssnid;
                rkey->dport = pkt->l2.ssnid;
                bpf_map_update_elem(&fsm_ct, rkey, urop, BPF_ANY);
            }
        }
        break;
    default:
        break;
    }
    return 0;
}

INTERNAL(int) dp_ct_in(skb_t *skb, xpkt_t *pkt)
{
    ct_key_t ckey, rkey;
    ct_op_t *ucop, *urop;
    ct_op_t *acop, *arop;
    nat_ep_t *ucep, *urep;
    int cidx = 0, ridx = 1;
    int smr = CT_SMR_ERR;

    if (F4_DEBUG_PKT(pkt)) {
        FSM_DBG("[DBG] dp_ct_in\n");
    }

    if (pkt->l34.proto != IPPROTO_TCP && pkt->l34.proto != IPPROTO_UDP &&
        pkt->l34.proto != IPPROTO_ICMP && pkt->l34.proto != IPPROTO_ICMPV6) {
        return CT_SMR_INPROG;
    }

    ucop = bpf_map_lookup_elem(&fsm_ct_ops, &cidx);
    urop = bpf_map_lookup_elem(&fsm_ct_ops, &ridx);
    if (ucop == NULL || urop == NULL) {
        return smr;
    }

    ucep = &ucop->attr.ep;
    urep = &urop->attr.ep;

    /* CT Key */
    XADDR_COPY(ckey.daddr, pkt->l34.daddr);
    XADDR_COPY(ckey.saddr, pkt->l34.saddr);
    ckey.sport = pkt->l34.sport;
    ckey.dport = pkt->l34.dport;
    ckey.proto = pkt->l34.proto;
    ckey.v6 = pkt->l2.dl_type == ntohs(ETH_P_IPV6) ? 1 : 0;

    ucep->nat_flags = pkt->ctx.nf;
    XADDR_COPY(ucep->xaddr, pkt->nat.xaddr);
    XADDR_COPY(ucep->raddr, pkt->nat.raddr);
    ucep->xport = pkt->nat.xport;
    ucep->rport = pkt->nat.rport;
    ucep->v6 = pkt->nat.v6;

    urep->nat_flags = 0;
    urep->xport = 0;
    urep->rport = 0;
    XADDR_SET_ZERO(urep->xaddr);
    XADDR_SET_ZERO(urep->raddr);

    if (pkt->ctx.nf & (F4_NAT_DST | F4_NAT_SRC)) {
        if (XADDR_IS_ZERO(ucep->xaddr)) {
            if (pkt->ctx.nf == F4_NAT_DST) {
                ucep->nat_flags = F4_NAT_HDST;
            } else if (pkt->ctx.nf == F4_NAT_SRC) {
                ucep->nat_flags = F4_NAT_HSRC;
            }
        }
    }

    dp_ct_proto_xfk_init(pkt, &ckey, ucep, &rkey, urep);

    acop = bpf_map_lookup_elem(&fsm_ct, &ckey);
    arop = bpf_map_lookup_elem(&fsm_ct, &rkey);
    if (acop == NULL || arop == NULL) {
        memset(&ucop->attr.sm, 0, sizeof(ct_sm_t));
        if (ucep->nat_flags) {
            ucop->nf = ucep->nat_flags & (F4_NAT_DST | F4_NAT_HDST)
                           ? NF_DO_DNAT
                           : NF_DO_SNAT;
            XADDR_COPY(ucop->nfs.nat.xaddr, ucep->xaddr);
            XADDR_COPY(ucop->nfs.nat.raddr, ucep->raddr);
            ucop->nfs.nat.xport = ucep->xport;
            ucop->nfs.nat.rport = ucep->rport;
            ucop->nfs.nat.do_ct = 0;
            ucop->nfs.nat.ep_sel = pkt->nat.ep_sel;
            ucop->nfs.nat.v6 = pkt->nat.v6 ? 1 : 0;
            ucop->ito = pkt->nat.ito;
        } else {
            ucop->ito = 0;
            ucop->nf = NF_DO_CTTK;
        }
        ucop->attr.dir = CT_DIR_IN;
        ucop->attr.smr = CT_SMR_INIT;

        memset(&urop->attr.sm, 0, sizeof(ct_sm_t));
        if (urep->nat_flags) {
            urop->nf = urep->nat_flags & (F4_NAT_DST | F4_NAT_HDST)
                           ? NF_DO_DNAT
                           : NF_DO_SNAT;
            XADDR_COPY(urop->nfs.nat.xaddr, urep->xaddr);
            XADDR_COPY(urop->nfs.nat.raddr, urep->raddr);
            urop->nfs.nat.xport = urep->xport;
            urop->nfs.nat.rport = urep->rport;
            urop->nfs.nat.do_ct = 0;
            urop->nfs.nat.ep_sel = pkt->nat.ep_sel;
            urop->nfs.nat.v6 = ckey.v6 ? 1 : 0;
            urop->ito = pkt->nat.ito;
        } else {
            urop->ito = 0;
            urop->nf = NF_DO_CTTK;
        }
        urop->attr.dir = CT_DIR_OUT;
        urop->attr.smr = CT_SMR_INIT;

        bpf_map_update_elem(&fsm_ct, &rkey, urop, BPF_ANY);
        bpf_map_update_elem(&fsm_ct, &ckey, ucop, BPF_ANY);

        acop = bpf_map_lookup_elem(&fsm_ct, &ckey);
        arop = bpf_map_lookup_elem(&fsm_ct, &rkey);
    }

    if (acop != NULL && arop != NULL) {
        acop->lts = bpf_ktime_get_ns();
        arop->lts = acop->lts;
        pkt->ctx.act = F4_PIPE_RDR;
        if (acop->attr.dir == CT_DIR_IN) {
            pkt->ctx.dir = CT_DIR_IN;
            pkt->ctx.phit |= F4_DP_CTSI_HIT;
            smr = dp_ct_sm(skb, pkt, acop, arop, CT_DIR_IN);
        } else {
            pkt->ctx.dir = CT_DIR_OUT;
            pkt->ctx.phit |= F4_DP_CTSO_HIT;
            smr = dp_ct_sm(skb, pkt, arop, acop, CT_DIR_OUT);
        }

        if (smr == CT_SMR_EST) {
            if (ucep->nat_flags) {
                acop->nfs.nat.do_ct = 0;
                arop->nfs.nat.do_ct = 0;
                if (acop->attr.dir == CT_DIR_IN) {
                    dp_ct_est(pkt, &ckey, &rkey, acop, arop);
                } else {
                    dp_ct_est(pkt, &rkey, &ckey, arop, acop);
                }
            } else {
                acop->nf = NF_DO_NOOP;
                arop->nf = NF_DO_NOOP;
            }
        } else if (smr == CT_SMR_ERR || smr == CT_SMR_CTD) {
            bpf_map_delete_elem(&fsm_ct, &rkey);
            bpf_map_delete_elem(&fsm_ct, &ckey);
            if (F4_DEBUG_PKT(pkt)) {
                FSM_DBG("[DBG] [CTRK] bpf_map_delete_elem by igr\n");
            }
        }
    }

    return smr;
}

#endif