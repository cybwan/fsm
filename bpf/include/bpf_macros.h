#ifndef __F4_BPF_MACROS_H__
#define __F4_BPF_MACROS_H__

#define INTERNAL(type) __attribute__((__always_inline__)) static inline type

typedef struct __sk_buff skb_t;

#define xip4 xip[0]
#define rip4 rip[0]
#define nat_xip4 nat_xip[0]
#define nat_rip4 nat_rip[0]

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memset(dest, c, n) __builtin_memset((dest), (c), (n))
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((unsigned long)&((TYPE *)0)->MEMBER)
#endif

#define XPKT_PTR(x) ((void *)((long)x))
#define XPKT_PTR_ADD(x, len) ((void *)(((__u8 *)((long)x)) + (len)))
#define XPKT_PTR_SUB(x, y) (((__u8 *)XPKT_PTR(x)) - ((__u8 *)XPKT_PTR(y)))

#define XADDR_COPY(dst, src) memcpy(dst, src, 16)
#define XADDR_SET_ZERO(v) memset(v, 0, 16)
#define XADDR_IS_ZERO(v) (v[0] == 0 && v[1] == 0 && v[2] == 0 && v[3] == 0)

#endif