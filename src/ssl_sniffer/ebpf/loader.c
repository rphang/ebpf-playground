#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#include "ebpf/loader.h"
#include "ebpf/struct_bpf.h"

#include "sniffer.skel.h"

static volatile bool exiting = false;

#define __ATTACH_UPROBE(program_path, arg_func_name, ebpf_fn, is_retprobe)                              \
    do                                                                                                  \
    {                                                                                                   \
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = arg_func_name, .retprobe = is_retprobe); \
        skel->links.ebpf_fn = bpf_program__attach_uprobe_opts(                                          \
            skel->progs.ebpf_fn,                                                                        \
            -1, program_path, 0, &uprobe_opts);                                                         \
        if (!skel->links.ebpf_fn)                                                                       \
        {                                                                                               \
            fprintf(stderr, "Failed to attach uprobe\n");                                               \
            return 1;                                                                                   \
        }                                                                                               \
    } while (0)

struct sniffer_bpf *skel;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

/**
 * @brief Unload and destroy the BPF program & poller
 * 
 * @return void
 */
void ssl_exit()
{
    if (!skel)
        return;
    exiting = true;
    sniffer_bpf__destroy(skel);
}

/**
 * @brief Set the debug level of the BPF program
 *
 * @param enable 1 to enable debug, 0 to disable
 * @return void
 */
void ssl_set_debug(int enable)
{
    libbpf_set_print(enable ? libbpf_print_fn : NULL);
}

/**
 * @brief Load the BPF program
 *
 * @return int 0 if the BPF program is loaded successfully, 1 otherwise
 */
int ssl_load()
{
    int err;
    skel = sniffer_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = sniffer_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }
    return 0;
}

/**
 * @brief Attach the OpenSSL probes to the specified library/program path
 *
 * @param program_path the path to the program/library to attach the probes to
 * @return int 0 if the probes are attached successfully, 1 otherwise
 */
int ssl_attach_openssl(char *program_path)
{
    __ATTACH_UPROBE(program_path, "SSL_set_fd", probe_fd_attach_ssl, false);
    __ATTACH_UPROBE(program_path, "SSL_write", probe_ssl_rw_enter, false);
    __ATTACH_UPROBE(program_path, "SSL_write", probe_ssl_write_return, true);
    __ATTACH_UPROBE(program_path, "SSL_read", probe_ssl_rw_enter, false);
    __ATTACH_UPROBE(program_path, "SSL_read", probe_ssl_read_return, true);
    return 0;
}

/**
 * @brief Attach the GnuTLS probes to the specified library/program path
 *
 * @param program_path the path to the program/library to attach the probes to
 * @return int 0 if the probes are attached successfully, 1 otherwise
 */
int ssl_attach_gnutls(char *program_path)
{
    __ATTACH_UPROBE(program_path, "gnutls_record_send", probe_ssl_rw_enter, false);
    __ATTACH_UPROBE(program_path, "gnutls_record_send", probe_ssl_write_return, true);
    __ATTACH_UPROBE(program_path, "gnutls_record_recv", probe_ssl_rw_enter, false);
    __ATTACH_UPROBE(program_path, "gnutls_record_recv", probe_ssl_read_return, true);
    return 0;
}

/**
 * @brief Attach the NSS probes to the specified library/program path
 *
 * @param program_path the path to the program/library to attach the probes to
 * @return int 0 if the probes are attached successfully, 1 otherwise
 */
int ssl_attach_nss(char *program_path)
{
    __ATTACH_UPROBE(program_path, "PR_Write" , probe_ssl_rw_enter, false);
    __ATTACH_UPROBE(program_path, "PR_Write" , probe_ssl_write_return, true);
    __ATTACH_UPROBE(program_path, "PR_Read" , probe_ssl_rw_enter, false);
    __ATTACH_UPROBE(program_path, "PR_Read" , probe_ssl_read_return, true);
    __ATTACH_UPROBE(program_path, "PR_Send" , probe_ssl_rw_enter, false);
    __ATTACH_UPROBE(program_path, "PR_Send" , probe_ssl_write_return, true);
    __ATTACH_UPROBE(program_path, "PR_Recv" , probe_ssl_rw_enter, false);
    __ATTACH_UPROBE(program_path, "PR_Recv" , probe_ssl_read_return, true);
    return 0;
}

static void log_event(struct data_event *event)
{
    char *op = event->op == 1 ? "SSL_OP_READ" : "SSL_OP_WRITE";
    fprintf(stdout, "[+] %s(%d), ts: %llu, op: %s, len: %d --> \n", event->comm, event->pid, event->ts, op, event->len);
    for (int i = 0; i < event->len; i++)
    {
        fprintf(stdout, "%c", event->data[i]);
    }
    fprintf(stdout, "\n");
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct data_event *event = (struct data_event *)data;
    log_event(event);
    return 0;
}

/**
 * @brief Listen to the events from the BPF program
 *
 * @return int 0 if the events are listened successfully, 1 otherwise
 */
int ssl_listen_event()
{
    int err = 0;
    struct ring_buffer *rb;

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        return err;
    }

    while (!exiting)
    {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
        {
            err = 0;
            break;
        }
        if (err < 0)
        {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    return err;
}
