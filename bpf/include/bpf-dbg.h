#ifndef __F4_BPF_DEBUG_H__
#define __F4_BPF_DEBUG_H__

#define FSM_DBG debug_printf

#ifdef F4_DP_DEBUG
#define F4_DBG_PRINTK debug_printf
#else
#define F4_DBG_PRINTK(fmt, ...)                                                \
    do {                                                                       \
    } while (0)
#endif

// #define F4_DEBUG_INT(x) 0
// #define F4_DEBUG_EXT(x) 0

// 192.168.226.32 551725248
// 3.213.1.197 3305231619
#define F4_DEBUG_INT(x)                                                        \
    (x->pm.igr == 1 && x->l2m.dl_type == ntohs(ETH_P_IP) &&                    \
     x->l34m.proto == IPPROTO_TCP && x->l34m.saddr4 == 551725248 &&            \
     x->l34m.daddr4 == 3305231619 && x->l34m.dest == htons(80))

// 192.168.127.33 562014400
// 192.168.127.32 545237184
#define F4_DEBUG_EXT(x)                                                        \
    (x->pm.egr == 1 && x->l2m.dl_type == ntohs(ETH_P_IP) &&                    \
     x->l34m.proto == IPPROTO_TCP && x->l34m.saddr4 == 562014400 &&            \
     x->l34m.daddr4 == 545237184 && x->l34m.source == htons(80))

#define F4_DEBUG_PKT(x) (F4_DEBUG_INT(x) || F4_DEBUG_EXT(x))

#endif