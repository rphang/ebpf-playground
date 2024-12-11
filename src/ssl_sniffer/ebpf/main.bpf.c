#ifndef __VMLINUX_H
#define __VMLINUX_H
#include "vmlinux.h"
#endif
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "ebpf/struct_bpf.h"
#include "ebpf/maps_bpf.h"

#define logprefix "ssl_sniffer: "
#ifdef bpf_printk
#undef bpf_printk
#define bpf_printk(fmt, ...)                       \
    ({                                             \
        char ____fmt[] = logprefix fmt;            \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })
#endif

#define min(x, y)                      \
    ({                                 \
        typeof(x) _min1 = (x);         \
        typeof(y) _min2 = (y);         \
        (void)(&_min1 == &_min2);      \
        _min1 < _min2 ? _min1 : _min2; \
    })

// Internal maps (mostly for ptr tracking, other maps are in headers)
// Lookup maps
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);   // pid
    __type(value, u64); // buffer address
    __uint(max_entries, 1024);
} ptr_ssl_rw_buff SEC(".maps");

static __always_inline int handle_rw_exit(struct pt_regs *ctx, int is_write)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 *buf = bpf_map_lookup_elem(&ptr_ssl_rw_buff, &pid);
    if (!buf)
        return 0;

    int resp = PT_REGS_RC_CORE(ctx);
    if (resp <= 0)
        return 0;
    if (resp > MAX_DATA_LEN)
        bpf_printk("we might lose some data (%d), need some recursive read\n", resp);
    u32 read_len = min((size_t)resp, (size_t)MAX_DATA_LEN);

    // Prepare to send to user space (ring buffer)
    int msg_len = sizeof(struct data_event);
    struct data_event *msg = bpf_ringbuf_reserve(&rb, msg_len, 0);
    if (!msg)
        return 0;

    u64 ts = bpf_ktime_get_ns();

    bpf_core_read(&msg->pid, sizeof(msg->pid), &pid);
    bpf_get_current_comm(&msg->comm, TASK_COMM_LEN);
    bpf_core_read(&msg->ts, sizeof(msg->ts), &ts);
    msg->op = is_write ? SSL_OP_WRITE : SSL_OP_READ;
    msg->len = read_len;

    //if (!is_write)
    //    bpf_probe_write_user((void *)*buf, "HTTP/1.1 200 OK\nContent-Length: 12\n\nHello World\n\00", 50);
    // We can fake the data being sent back to user space but difference in read size will be detected

    bpf_core_read_user(&msg->data, read_len, (void *)*buf);
    // Sending to ring buffer
    bpf_ringbuf_submit(msg, 0);
    return 0;
}

SEC("uprobe/fd_attach_ssl")
int probe_fd_attach_ssl(struct pt_regs *ctx)
{
    bpf_printk("fd_attach_ssl\n");
    return 0;
}

SEC("uprobe/ssl_rw_enter")
int probe_ssl_rw_enter(struct pt_regs *ctx)
{
    u64 buf = PT_REGS_PARM2_CORE(ctx);
    if (!buf)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    bpf_map_update_elem(&ptr_ssl_rw_buff, &pid, &buf, 0);
    return 0;
}

SEC("uprobe/ssl_read_return")
int probe_ssl_read_return(struct pt_regs *ctx)
{
    return (handle_rw_exit(ctx, 0));
}

SEC("uprobe/ssl_write_return")
int probe_ssl_write_return(struct pt_regs *ctx)
{
    return (handle_rw_exit(ctx, 1));
}

char _license[] SEC("license") = "GPL";