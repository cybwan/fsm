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
        rkey->v6 = (__u8)(ucep->nv6);
        XADDR_COPY(rkey->saddr, ucep->nat_rip);
        // XADDR_COPY(rkey->daddr, ucep->nat_xip);
        XADDR_COPY(urep->nat_xip, ckey->daddr);
        XADDR_COPY(urep->nat_rip, ckey->saddr);
        if (ckey->proto != IPPROTO_ICMP) {
            rkey->dport = ucep->nat_xport;
            rkey->sport = ucep->nat_rport;
            urep->nat_xport = ckey->dport;
            urep->nat_rport = ckey->sport;
        }

        urep->nat_flags = F4_NAT_SRC;
        urep->nv6 = ckey->v6;
    }
    if (ucep->nat_flags & F4_NAT_SRC) {
        rkey->v6 = ucep->nv6;
        // XADDR_COPY(rkey->saddr, ucep->nat_rip);
        XADDR_COPY(rkey->daddr, ucep->nat_xip);
        XADDR_COPY(urep->nat_rip, pkt->l34.saddr);
        XADDR_COPY(urep->nat_xip, pkt->l34.daddr);

        if (ckey->proto != IPPROTO_ICMP) {
            rkey->dport = ucep->nat_xport;
            rkey->sport = ucep->nat_rport;
            urep->nat_xport = ckey->dport;
            urep->nat_rport = ckey->sport;
        }

        urep->nat_flags = F4_NAT_DST;
        urep->nv6 = ckey->v6;
    }
    if (ucep->nat_flags & F4_NAT_HDST) {
        XADDR_COPY(rkey->saddr, ckey->saddr);
        XADDR_COPY(rkey->daddr, ckey->daddr);

        if (ckey->proto != IPPROTO_ICMP) {
            if (ucep->nat_xport)
                rkey->sport = ucep->nat_xport;
            else
                ucep->nat_xport = ckey->dport;
        }

        urep->nat_flags = F4_NAT_HSRC;
        urep->nv6 = ckey->v6;
        XADDR_SET_ZERO(urep->nat_xip);
        XADDR_SET_ZERO(ucep->nat_xip);
        if (ckey->proto != IPPROTO_ICMP)
            urep->nat_xport = ckey->dport;
    }
    if (ucep->nat_flags & F4_NAT_HSRC) {
        XADDR_COPY(rkey->saddr, ckey->saddr);
        XADDR_COPY(rkey->daddr, ckey->daddr);

        if (ckey->proto != IPPROTO_ICMP) {
            if (ucep->nat_xport)
                rkey->dport = ucep->nat_xport;
            else
                ucep->nat_xport = ckey->sport;
        }

        urep->nat_flags = F4_NAT_HDST;
        urep->nv6 = ckey->v6;
        XADDR_SET_ZERO(urep->nat_xip);
        XADDR_SET_ZERO(ucep->nat_xip);

        if (ckey->proto != IPPROTO_ICMP)
            urep->nat_xport = ckey->sport;
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
    int i, j, k;

    k = 0;
    ucop = bpf_map_lookup_elem(&fsm_ct_ops, &k);

    k = 1;
    urop = bpf_map_lookup_elem(&fsm_ct_ops, &k);

    if (ucop == NULL || urop == NULL || tdat->ep.nv6) {
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
    XADDR_COPY(ucep->nat_xip, pkt->nat.nxip);
    XADDR_COPY(ucep->nat_rip, pkt->nat.nrip);
    ucep->nat_xport = pkt->nat.nxport;
    ucep->nat_rport = pkt->nat.nrport;
    ucep->nv6 = pkt->nat.nv6;

    urep->nat_flags = 0;
    urep->nat_xport = 0;
    urep->nat_rport = 0;
    XADDR_SET_ZERO(urep->nat_xip);
    XADDR_SET_ZERO(urep->nat_rip);

    if (pkt->ctx.nf & (F4_NAT_DST | F4_NAT_SRC)) {
        if (XADDR_IS_ZERO(ucep->nat_xip)) {
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
        FSM_DBG("[CTRK] AAAAA 1\n");
        memset(&ucop->attr.sm, 0, sizeof(ct_sm_t));
        if (ucep->nat_flags) {
            ucop->nf = ucep->nat_flags & (F4_NAT_DST | F4_NAT_HDST)
                           ? NF_DO_DNAT
                           : NF_DO_SNAT;
            XADDR_COPY(ucop->nfs.nat.xip, ucep->nat_xip);
            XADDR_COPY(ucop->nfs.nat.rip, ucep->nat_rip);
            ucop->nfs.nat.xport = ucep->nat_xport;
            ucop->nfs.nat.rport = ucep->nat_rport;
            ucop->nfs.nat.doct = 0;
            ucop->nfs.nat.aid = pkt->nat.ep_sel;
            ucop->nfs.nat.nv6 = pkt->nat.nv6 ? 1 : 0;
            ucop->ito = pkt->nat.ito;
        } else {
            ucop->ito = 0;
            ucop->nf = NF_DO_CTTK;
        }
        ucop->attr.dir = CT_DIR_IN;

        /* FIXME This is duplicated data */
        ucop->attr.ep_sel = pkt->nat.ep_sel;
        ucop->attr.smr = CT_SMR_INIT;

        memset(&urop->attr.sm, 0, sizeof(ct_sm_t));
        if (urep->nat_flags) {
            urop->nf = urep->nat_flags & (F4_NAT_DST | F4_NAT_HDST)
                           ? NF_DO_DNAT
                           : NF_DO_SNAT;
            XADDR_COPY(urop->nfs.nat.xip, urep->nat_xip);
            XADDR_COPY(urop->nfs.nat.rip, urep->nat_rip);
            urop->nfs.nat.xport = urep->nat_xport;
            urop->nfs.nat.rport = urep->nat_rport;
            urop->nfs.nat.doct = 0;
            urop->nfs.nat.aid = pkt->nat.ep_sel;
            urop->nfs.nat.nv6 = ckey.v6 ? 1 : 0;
            urop->ito = pkt->nat.ito;
        } else {
            urop->ito = 0;
            urop->nf = NF_DO_CTTK;
        }
        urop->lts = ucop->lts;
        urop->attr.dir = CT_DIR_OUT;
        urop->attr.smr = CT_SMR_INIT;
        urop->attr.ep_sel = ucop->attr.ep_sel;

        bpf_map_update_elem(&fsm_ct, &rkey, urop, BPF_ANY);
        bpf_map_update_elem(&fsm_ct, &ckey, ucop, BPF_ANY);

        acop = bpf_map_lookup_elem(&fsm_ct, &ckey);
        arop = bpf_map_lookup_elem(&fsm_ct, &rkey);
    }

    if (acop != NULL && arop != NULL) {
        FSM_DBG("[CTRK] AAAAA 2\n");
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
                acop->nfs.nat.doct = 0;
                arop->nfs.nat.doct = 0;
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