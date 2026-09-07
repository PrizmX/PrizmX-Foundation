#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/// One TCP/UDP socket owned by `pid`. Ports are host-endian.
/// IPv4 addresses occupy the first 4 bytes of `*_addr`.
typedef struct prizmx_socket_row {
    int32_t pid;
    uint8_t transport; /* 6 = TCP, 17 = UDP */
    uint8_t is_ipv6;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t local_addr[16];
    uint8_t remote_addr[16];
} prizmx_socket_row;

/// Enumerate TCP/UDP sockets via public `proc_pidinfo` / `proc_pidfdinfo`.
/// Skips `skip_pid` (the tunnel itself). Returns the number of rows written,
/// 0 when none, or a negative `-errno` on failure.
int prizmx_list_sockets(prizmx_socket_row *out, int max_count, pid_t skip_pid);

/// Parse `net.inet.{tcp,udp}.pcblist_n` tagged xinpcb_n + xsocket_n.
/// PID comes from so_e_pid, falling back to so_last_pid.
int prizmx_list_pcblist_n(prizmx_socket_row *out, int max_count, pid_t skip_pid);

/// Look up one local port in pcblist_n. Returns 0 if not found.
pid_t prizmx_find_pid_pcblist_n(uint16_t local_port_host, int is_tcp);

/// Probe a sysctl MIB (`net.inet.tcp.pcblist` / `.n`). Returns 0 on success.
/// `errno_out` / `len_out` are always filled.
int prizmx_sysctl_probe(const char *name, int *errno_out, size_t *len_out);

/// Sandbox diagnostics for the libproc walk (no socket payload).
typedef struct prizmx_libproc_stats {
    int listpids_bytes;
    int pid_count;
    int pids_inspected;
    int pids_denied;
    int socket_fds;
    int inet_sockets;
    int last_errno;
} prizmx_libproc_stats;

int prizmx_libproc_stats_fill(prizmx_libproc_stats *out, pid_t skip_pid);

/// Extra sandbox probes: KERN_PROC, self pidinfo, pcblist row counts.
typedef struct prizmx_sandbox_probe {
    int kernproc_errno;
    int kernproc_count;
    int self_fd_bytes;
    int self_errno;
    int tcp_pcb_rows;
    int udp_pcb_rows;
    int tcp_sample_pgid;
    int tcp_sample_uid;
    int tcp_sample_lport;
    int pidinfo_ok;
    int pidinfo_fail;
    int pidinfo_sample_errno;
} prizmx_sandbox_probe;

int prizmx_sandbox_probe_fill(prizmx_sandbox_probe *out);
