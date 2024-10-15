#ifndef __F4_BPF_UTILS_H__
#define __F4_BPF_UTILS_H__
#define INLINE __attribute__((__always_inline__)) static inline

#define debug_printf(fmt, ...)                                                 \
    do {                                                                       \
        char _fmt[] = fmt;                                                     \
        bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                   \
    } while (0)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ntohs(x) __builtin_bswap16(x)
#define htons(x) __builtin_bswap16(x)
#define ntohl(x) __builtin_bswap32(x)
#define htonl(x) __builtin_bswap32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ntohs(x) (x)
#define htons(x) (x)
#define ntohl(x) (x)
#define htonl(x) (x)
#else
#error "Unknown __BYTE_ORDER__"
#endif

/* When utilizing vmlinux.h with BPF CO-RE, user BPF programs can't include
 * any system-level headers (such as stddef.h, linux/version.h, etc), and
 * commonly-used macros like NULL and KERNEL_VERSION aren't available through
 * vmlinux.h. This just adds unnecessary hurdles and forces users to re-define
 * them on their own. So as a convenience, provide such definitions here.
 */
#ifndef NULL
#define NULL ((void *)0)
#endif

#endif