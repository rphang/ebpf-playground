#ifndef __VMLINUX_H
#define __VMLINUX_H
#include "vmlinux.h"
#endif

#ifndef __MAPS_BPF_H
#define __MAPS_BPF_H

#include <bpf/bpf_helpers.h>

#define BUFFER_ENTRY_SIZE 256*1024

/*
    This implementation uses BPF_MAP_TYPE_RINGBUF to store the data events.
    The ring buffer is a new feature in Kernel 5.8 and above. (https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
*/
// TODO: (Bug) LINUX_VERSION_CODE seems to be undefined. Need to look into this.
//#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
//#error "Kernel version is less than 5.8
//#endif

// Ring buffer is only available in Kernel 5.8 and above
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, BUFFER_ENTRY_SIZE);
} rb SEC(".maps");

// Lookup maps
// FD <-> SSL CTX (TODO: Look into this)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, void *);
    __uint(max_entries, 1024);
} fd_to_ssl_ctx SEC(".maps");

#endif