#ifndef __F4_BPF_MACROS_H__
#define __F4_BPF_MACROS_H__

#define INTERNAL(type) __attribute__((__always_inline__)) static inline type

typedef struct __sk_buff skb_t;

#endif