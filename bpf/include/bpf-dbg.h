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

// #define F4_DEBUG_IGR(x) 0
// #define F4_DEBUG_EGR(x) 0

#define SRC_ADDR 33554442 // 10.0.0.2
#define DST_ADDR 16777226 // 10.0.0.1
#define SRC_PORT 6060
#define DST_PORT 8080

#define F4_DEBUG_IGR(x)                                                        \
    (x->pm.igr == 1 && x->l2.dl_type == ntohs(ETH_P_IP) &&                     \
     x->l34.proto == IPPROTO_TCP && x->l34.saddr4 == DST_ADDR &&               \
     x->l34.daddr4 == SRC_ADDR && x->l34.source == htons(DST_PORT))

#define F4_DEBUG_EGR(x)                                                        \
    (x->pm.egr == 1 && x->l2.dl_type == ntohs(ETH_P_IP) &&                     \
     x->l34.proto == IPPROTO_TCP && x->l34.saddr4 == SRC_ADDR &&               \
     x->l34.daddr4 == DST_ADDR && x->l34.dest == htons(DST_PORT))

#define F4_DEBUG_PKT(x) (F4_DEBUG_IGR(x) || F4_DEBUG_EGR(x))

#endif