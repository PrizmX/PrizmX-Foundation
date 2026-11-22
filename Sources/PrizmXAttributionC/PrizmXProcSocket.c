#include "PrizmXProcSocket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <libproc.h>
#include <net/if.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stddef.h>
#include <sys/proc_info.h>
#include <sys/socketvar.h>
#include <uuid/uuid.h>

static const struct in_sockinfo *inet_info(const struct socket_info *soi) {
    if (soi->soi_kind == SOCKINFO_TCP) {
        return &soi->soi_proto.pri_tcp.tcpsi_ini;
    }
    if (soi->soi_kind == SOCKINFO_IN) {
        return &soi->soi_proto.pri_in;
    }
    return NULL;
}

static uint8_t transport_of(const struct socket_info *soi) {
    if (soi->soi_kind == SOCKINFO_TCP || soi->soi_protocol == IPPROTO_TCP) {
        return IPPROTO_TCP;
    }
    if (soi->soi_protocol == IPPROTO_UDP) {
        return IPPROTO_UDP;
    }
    return 0;
}

static void copy_addr(uint8_t out[16], uint8_t *is_ipv6, const struct in_sockinfo *info, int local) {
    memset(out, 0, 16);
    if (info->insi_vflag & INI_IPV6) {
        *is_ipv6 = 1;
        const struct in6_addr *addr = local ? &info->insi_laddr.ina_6 : &info->insi_faddr.ina_6;
        memcpy(out, addr, 16);
    } else {
        *is_ipv6 = 0;
        const struct in_addr *addr = local
            ? &info->insi_laddr.ina_46.i46a_addr4
            : &info->insi_faddr.ina_46.i46a_addr4;
        memcpy(out, addr, 4);
    }
}

#ifndef ROUNDUP64
#define ROUNDUP64(x) (((x) + 7u) & ~7u)
#endif

#define XSO_SOCKET  0x001u
#define XSO_INPCB   0x010u

/// Enumerate all pids: proc_listpids first, `kern.proc.all` when listpids is
/// denied (App Sandbox blocks `process-info-listpids` but still allows the
/// KERN_PROC sysctl). Caller frees the returned buffer.
static int enum_all_pids(pid_t **out_pids, int *out_errno) {
    int pid_bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (pid_bytes > 0) {
        pid_t *pids = malloc((size_t)pid_bytes);
        if (pids == NULL) {
            *out_errno = ENOMEM;
            return -1;
        }
        int got = proc_listpids(PROC_ALL_PIDS, 0, pids, pid_bytes);
        if (got > 0) {
            *out_pids = pids;
            return got / (int)sizeof(pid_t);
        }
        free(pids);
    }
    if (out_errno != NULL) {
        *out_errno = errno;
    }

    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    size_t len = 0;
    if (sysctl(mib, 3, NULL, &len, NULL, 0) != 0 || len == 0) {
        return -1;
    }
    struct kinfo_proc *procs = malloc(len);
    if (procs == NULL) {
        *out_errno = ENOMEM;
        return -1;
    }
    if (sysctl(mib, 3, procs, &len, NULL, 0) != 0) {
        free(procs);
        return -1;
    }
    int count = (int)(len / sizeof(struct kinfo_proc));
    pid_t *pids = malloc((size_t)(count + 1) * sizeof(pid_t));
    if (pids == NULL) {
        free(procs);
        *out_errno = ENOMEM;
        return -1;
    }
    int n = 0;
    for (int i = 0; i < count; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        if (pid > 0) {
            pids[n++] = pid;
        }
    }
    free(procs);
    *out_pids = pids;
    return n;
}

static int fill_pcblist_n(
    const char *mib,
    uint8_t transport,
    prizmx_socket_row *out,
    int max_count,
    pid_t skip_pid,
    int *claimed_count
) {
    if (out == NULL || max_count <= 0) {
        return 0;
    }
    char *buf = NULL;
    size_t len = 0;
    // The socket table can grow between the size probe and the read (e.g. a
    // burst of reconnects on wake). Reserve headroom and retry on ENOMEM so a
    // transient growth does not silently drop every TCP row.
    for (int attempt = 0; attempt < 4; attempt++) {
        size_t probe = 0;
        if (sysctlbyname(mib, NULL, &probe, NULL, 0) != 0 || probe < 16) {
            return -1;
        }
        size_t alloc = probe + (probe >> 2) + 4096;
        if (attempt > 0) {
            alloc += (size_t)attempt * (probe >> 1);
        }
        buf = malloc(alloc);
        if (buf == NULL) {
            return -1;
        }
        size_t got = alloc;
        if (sysctlbyname(mib, buf, &got, NULL, 0) == 0) {
            len = got;
            break;
        }
        int err = errno;
        free(buf);
        buf = NULL;
        if (err != ENOMEM) {
            return -1;
        }
    }
    if (buf == NULL || len < 16) {
        free(buf);
        return -1;
    }
    uint32_t hdr_len = *(uint32_t *)(void *)buf;
    if (hdr_len < 8 || hdr_len > len) {
        hdr_len = 24;
    }
    // xinpgen.xig_count: sockets the kernel claims to hold. On macOS 26/27 the
    // records are filtered down to the caller's own sockets while the header
    // still reports the system-wide count — callers compare the two.
    if (claimed_count != NULL && hdr_len >= 8 && len >= 8) {
        *claimed_count = (int)*(uint32_t *)(void *)(buf + 4);
    }
    char *p = buf + hdr_len;
    char *end = buf + len;
    int written = 0;
    uint16_t pending_lport = 0;
    uint16_t pending_fport = 0;
    uint8_t pending_v6 = 0;
    uint8_t pending_laddr[16];
    uint8_t pending_faddr[16];
    int pending = 0;
    while (p + 8 <= end && written < max_count) {
        uint32_t rec_len = *(uint32_t *)(void *)p;
        uint32_t rec_kind = *(uint32_t *)(void *)(p + 4);
        if (rec_len < 8 || p + rec_len > end) {
            break;
        }
        if (rec_kind == XSO_INPCB && rec_len >= 20) {
            pending_fport = ntohs(*(uint16_t *)(void *)(p + 16));
            pending_lport = ntohs(*(uint16_t *)(void *)(p + 18));
            memset(pending_laddr, 0, sizeof(pending_laddr));
            memset(pending_faddr, 0, sizeof(pending_faddr));
            pending_v6 = 0;
            // xinpcb_n (pack 4): inp_vflag @44, inp_dependfaddr @48,
            // inp_dependladdr @64; IPv4 sits in the last 4 bytes of each
            // union (in_addr_4in6). Same offsets mihomo reads.
            if (rec_len >= 80) {
                uint8_t vflag = *(uint8_t *)(p + 44);
                if (vflag & 0x1) {
                    memcpy(pending_faddr, p + 60, 4);
                    memcpy(pending_laddr, p + 76, 4);
                } else if (vflag & 0x2) {
                    pending_v6 = 1;
                    memcpy(pending_faddr, p + 48, 16);
                    memcpy(pending_laddr, p + 64, 16);
                }
            }
            pending = 1;
        } else if (rec_kind == XSO_SOCKET && rec_len >= 76 && pending) {
            pid_t last_pid = *(pid_t *)(void *)(p + 68);
            pid_t e_pid = *(pid_t *)(void *)(p + 72);
            pid_t pid = e_pid != 0 ? e_pid : last_pid;
            pending = 0;
            if (pid > 0 && pid != skip_pid && pending_lport != 0) {
                prizmx_socket_row *row = &out[written];
                memset(row, 0, sizeof(*row));
                row->pid = pid;
                row->transport = transport;
                row->is_ipv6 = pending_v6;
                row->local_port = pending_lport;
                row->remote_port = pending_fport;
                memcpy(row->local_addr, pending_laddr, sizeof(row->local_addr));
                memcpy(row->remote_addr, pending_faddr, sizeof(row->remote_addr));
                written += 1;
            }
        }
        p += ROUNDUP64(rec_len);
    }
    free(buf);
    return written;
}

// Kernel ABI for `kern.skywalk.stats.flow` (XNU `bsd/skywalk/os_stats_private.h`
// and `bsd/skywalk/nexus/os_nexus_private.h`). Network.framework (`NWConnection`
// / modern `URLSession`) connections over utun use Skywalk user-space channels
// (`flowsw` / `libusrtcp`) and do not appear in `net.inet.*.pcblist_n` or
// `PROC_PIDLISTFDS` socket entries.
#define PRIZMX_SFLOWF_DESTROYED 0x40000000u
#define PRIZMX_SFLOWF_LINGERING 0x80000000u

struct prizmx_sk_flow_key {
    uint16_t fk_mask;
    uint8_t fk_ipver;
    uint8_t fk_proto;
    uint16_t fk_sport;
    uint16_t fk_dport;
    uint8_t fk_src[16];
    uint8_t fk_dst[16];
    uint64_t fk_pad[1];
} __attribute__((__aligned__(16)));

struct prizmx_sk_flow_track {
    uint64_t sft_bytes;
    uint64_t sft_packets;
    uint64_t sft_spackets;
    uint32_t sft_state;
    uint32_t sft_rtt;
    uint32_t sft_seq;
    uint16_t sft_max_win;
    uint8_t sft_wscale;
};

struct prizmx_sk_activity_bitmap {
    uint64_t start;
    uint64_t bitmap[2];
};

struct prizmx_sk_stats_flow {
    uuid_t sf_nx_uuid;
    uuid_t sf_uuid;
    char sf_if_name[IFNAMSIZ];
    uint32_t sf_if_index;
    uint32_t sf_bucket_idx;
    pid_t sf_pid;
    pid_t sf_epid;
    char sf_proc_name[32];
    char sf_eproc_name[32];
    uint32_t sf_flags;
    uint16_t sf_nx_port;
    uint8_t sf_protocol;
    uint32_t sf_svc_class;
    uint32_t sf_adv_idx;
    struct prizmx_sk_flow_key sf_key __attribute__((__aligned__(16)));
    struct prizmx_sk_flow_track sf_ltrack;
    struct prizmx_sk_flow_track sf_rtrack;
    struct prizmx_sk_activity_bitmap sf_activity;
};

_Static_assert(sizeof(struct prizmx_sk_flow_key) == 48, "flow_key ABI mismatch");
_Static_assert(offsetof(struct prizmx_sk_stats_flow, sf_key) == 144, "sk_stats_flow.sf_key ABI mismatch");
_Static_assert(sizeof(struct prizmx_sk_stats_flow) == 304, "sk_stats_flow ABI mismatch");

/// Best-effort append of Skywalk user-space flows (`kern.skywalk.stats.flow`,
/// root-only). Returns 0 when unavailable (non-root EPERM, unsupported OS, or
/// ABI size mismatch) so callers keep their BSD `pcblist_n` results intact.
static int fill_skywalk_flows(
    prizmx_socket_row *out,
    int max_count,
    pid_t skip_pid
) {
    if (out == NULL || max_count <= 0) {
        return 0;
    }
    char *buf = NULL;
    size_t len = 0;
    for (int attempt = 0; attempt < 4; attempt++) {
        size_t probe = 0;
        if (sysctlbyname("kern.skywalk.stats.flow", NULL, &probe, NULL, 0) != 0 || probe == 0) {
            return 0;
        }
        size_t alloc = probe + (probe >> 2) + 4096;
        if (attempt > 0) {
            alloc += (size_t)attempt * (probe >> 1);
        }
        buf = malloc(alloc);
        if (buf == NULL) {
            return 0;
        }
        size_t got = alloc;
        if (sysctlbyname("kern.skywalk.stats.flow", buf, &got, NULL, 0) == 0) {
            len = got;
            break;
        }
        int err = errno;
        free(buf);
        buf = NULL;
        if (err != ENOMEM) {
            return 0;
        }
    }
    if (buf == NULL || len < sizeof(struct prizmx_sk_stats_flow)) {
        free(buf);
        return 0;
    }
    // Guard against future macOS struct size changes: only parse exact multiples.
    if ((len % sizeof(struct prizmx_sk_stats_flow)) != 0) {
        free(buf);
        return 0;
    }
    size_t count = len / sizeof(struct prizmx_sk_stats_flow);
    const struct prizmx_sk_stats_flow *flows = (const struct prizmx_sk_stats_flow *)(const void *)buf;
    int written = 0;
    for (size_t i = 0; i < count && written < max_count; i++) {
        const struct prizmx_sk_stats_flow *f = &flows[i];
        if ((f->sf_flags & (PRIZMX_SFLOWF_DESTROYED | PRIZMX_SFLOWF_LINGERING)) != 0) {
            continue;
        }
        pid_t pid = f->sf_epid > 0 ? f->sf_epid : f->sf_pid;
        if (pid <= 0 || pid == skip_pid) {
            continue;
        }
        uint8_t proto = f->sf_key.fk_proto != 0 ? f->sf_key.fk_proto : f->sf_protocol;
        if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
            continue;
        }
        uint16_t lport = ntohs(f->sf_key.fk_sport);
        if (lport == 0) {
            continue;
        }
        uint16_t rport = ntohs(f->sf_key.fk_dport);
        uint8_t ipver = f->sf_key.fk_ipver;
        // XNU `flow_req2key` stores `IPVERSION` (4) for IPv4 and `IPV6_VERSION`
        // (0x60) for IPv6 (accept literal 6 too just in case).
        int is_v6 = (ipver == IPV6_VERSION || ipver == 6);
        if (ipver != IPVERSION && !is_v6) {
            continue;
        }
        prizmx_socket_row *row = &out[written];
        memset(row, 0, sizeof(*row));
        row->pid = pid;
        row->transport = proto;
        row->local_port = lport;
        row->remote_port = rport;
        if (is_v6) {
            row->is_ipv6 = 1;
            memcpy(row->local_addr, f->sf_key.fk_src, 16);
            memcpy(row->remote_addr, f->sf_key.fk_dst, 16);
        } else {
            row->is_ipv6 = 0;
            memcpy(row->local_addr, f->sf_key.fk_src, 4);
            memcpy(row->remote_addr, f->sf_key.fk_dst, 4);
        }
        written += 1;
    }
    free(buf);
    return written;
}

static int list_pcblist_n(prizmx_socket_row *out, int max_count, pid_t skip_pid, int guard_filtered) {
    if (out == NULL || max_count <= 0) {
        errno = EINVAL;
        return -EINVAL;
    }
    int claimed_tcp = 0;
    int claimed_udp = 0;
    int tcp = fill_pcblist_n(
        "net.inet.tcp.pcblist_n",
        IPPROTO_TCP,
        out,
        max_count,
        skip_pid,
        &claimed_tcp
    );
    if (tcp < 0) {
        // Do not mask a failed TCP read with a non-empty UDP table; return 0
        // so callers fall back to libproc instead of caching a TCP-less view.
        return 0;
    }
    int udp = 0;
    if (tcp < max_count) {
        udp = fill_pcblist_n(
            "net.inet.udp.pcblist_n",
            IPPROTO_UDP,
            out + tcp,
            max_count - tcp,
            skip_pid,
            &claimed_udp
        );
        if (udp < 0) {
            return 0;
        }
    }
    int written = tcp + udp;
    if (written >= max_count) {
        // Buffer full: not a filtered table. The caller grows and retries.
        return max_count;
    }
    int claimed = claimed_tcp + claimed_udp;
    // Filtered table (only the caller's own sockets) looks non-empty but is
    // useless for attribution — report failure so callers use libproc instead.
    if (guard_filtered && claimed >= 16 && written < claimed / 4) {
        return 0;
    }
    // Append Skywalk user-space flows (NWConnection / channel-flow, root-only).
    if (written < max_count) {
        int skywalk = fill_skywalk_flows(out + written, max_count - written, skip_pid);
        written += skywalk;
        if (written >= max_count) {
            return max_count;
        }
    }
    return written;
}

int prizmx_list_pcblist_n(prizmx_socket_row *out, int max_count, pid_t skip_pid) {
    return list_pcblist_n(out, max_count, skip_pid, 1);
}

int prizmx_list_pcblist_n_raw(prizmx_socket_row *out, int max_count, pid_t skip_pid) {
    return list_pcblist_n(out, max_count, skip_pid, 0);
}

pid_t prizmx_find_pid_pcblist_n(uint16_t local_port_host, int is_tcp) {
    prizmx_socket_row *rows = calloc(4096, sizeof(prizmx_socket_row));
    if (rows == NULL) {
        return 0;
    }
    int n = prizmx_list_pcblist_n(rows, 4096, 0);
    pid_t found = 0;
    uint8_t transport = is_tcp ? IPPROTO_TCP : IPPROTO_UDP;
    for (int i = 0; i < n; i++) {
        if (rows[i].transport == transport && rows[i].local_port == local_port_host) {
            found = rows[i].pid;
            break;
        }
    }
    free(rows);
    return found;
}

/// Appends `pid`'s TCP/UDP sockets to `out` from index `written`. Returns the
/// new row count (unchanged when the process cannot be inspected).
static int append_pid_sockets(pid_t pid, prizmx_socket_row *out, int max_count, int written) {
    int fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (fd_bytes <= 0) {
        return written;
    }
    struct proc_fdinfo *fds = malloc((size_t)fd_bytes);
    if (fds == NULL) {
        return written;
    }
    int fd_got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, fd_bytes);
    if (fd_got <= 0) {
        free(fds);
        return written;
    }
    int fd_count = fd_got / (int)sizeof(struct proc_fdinfo);
    for (int j = 0; j < fd_count && written < max_count; j++) {
        if (fds[j].proc_fdtype != PROX_FDTYPE_SOCKET) {
            continue;
        }
        struct socket_fdinfo info;
        memset(&info, 0, sizeof(info));
        int n = proc_pidfdinfo(
            pid,
            fds[j].proc_fd,
            PROC_PIDFDSOCKETINFO,
            &info,
            (int)sizeof(info)
        );
        if (n < (int)sizeof(info)) {
            continue;
        }
        uint8_t transport = transport_of(&info.psi);
        if (transport != IPPROTO_TCP && transport != IPPROTO_UDP) {
            continue;
        }
        const struct in_sockinfo *inet = inet_info(&info.psi);
        if (inet == NULL) {
            continue;
        }
        prizmx_socket_row *row = &out[written];
        row->pid = pid;
        row->transport = transport;
        row->local_port = ntohs((uint16_t)inet->insi_lport);
        row->remote_port = ntohs((uint16_t)inet->insi_fport);
        copy_addr(row->local_addr, &row->is_ipv6, inet, 1);
        uint8_t remote_v6 = 0;
        copy_addr(row->remote_addr, &remote_v6, inet, 0);
        (void)remote_v6;
        written += 1;
    }
    free(fds);
    return written;
}

int prizmx_list_sockets(prizmx_socket_row *out, int max_count, pid_t skip_pid) {
    if (out == NULL || max_count <= 0) {
        errno = EINVAL;
        return -EINVAL;
    }

    int enum_errno = 0;
    pid_t *pids = NULL;
    int pid_count = enum_all_pids(&pids, &enum_errno);
    if (pid_count <= 0 || pids == NULL) {
        int err = pid_count == 0 ? 0 : -(enum_errno != 0 ? enum_errno : errno);
        free(pids);
        return err;
    }
    int written = 0;

    for (int i = 0; i < pid_count && written < max_count; i++) {
        pid_t pid = pids[i];
        if (pid <= 0 || pid == skip_pid) {
            continue;
        }
        written = append_pid_sockets(pid, out, max_count, written);
    }

    free(pids);
    return written;
}

int prizmx_list_sockets_of_pid(pid_t pid, prizmx_socket_row *out, int max_count) {
    if (out == NULL || max_count <= 0 || pid <= 0) {
        return 0;
    }
    return append_pid_sockets(pid, out, max_count, 0);
}

int prizmx_sysctl_probe(const char *name, int *errno_out, size_t *len_out) {
    if (name == NULL || errno_out == NULL || len_out == NULL) {
        if (errno_out) *errno_out = EINVAL;
        if (len_out) *len_out = 0;
        return -1;
    }
    size_t len = 0;
    int rc = sysctlbyname(name, NULL, &len, NULL, 0);
    if (rc != 0) {
        *errno_out = errno;
        *len_out = 0;
        return rc;
    }
    void *buf = malloc(len == 0 ? 1 : len);
    if (buf == NULL) {
        *errno_out = ENOMEM;
        *len_out = 0;
        return -1;
    }
    rc = sysctlbyname(name, buf, &len, NULL, 0);
    *errno_out = rc == 0 ? 0 : errno;
    *len_out = rc == 0 ? len : 0;
    free(buf);
    return rc;
}

int prizmx_libproc_stats_fill(prizmx_libproc_stats *out, pid_t skip_pid) {
    if (out == NULL) {
        errno = EINVAL;
        return -EINVAL;
    }
    memset(out, 0, sizeof(*out));

    int enum_errno = 0;
    pid_t *pids = NULL;
    int pid_count = enum_all_pids(&pids, &enum_errno);
    out->last_errno = enum_errno;
    if (pid_count <= 0 || pids == NULL) {
        free(pids);
        return pid_count < 0 && enum_errno != 0 ? -enum_errno : 0;
    }
    out->pid_count = pid_count;

    for (int i = 0; i < pid_count; i++) {
        pid_t pid = pids[i];
        if (pid <= 0 || pid == skip_pid) {
            continue;
        }
        int fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (fd_bytes <= 0) {
            out->pids_denied += 1;
            out->last_errno = errno;
            continue;
        }
        out->pids_inspected += 1;
        struct proc_fdinfo *fds = malloc((size_t)fd_bytes);
        if (fds == NULL) {
            continue;
        }
        int fd_got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, fd_bytes);
        if (fd_got <= 0) {
            out->pids_denied += 1;
            out->last_errno = errno;
            free(fds);
            continue;
        }
        int fd_count = fd_got / (int)sizeof(struct proc_fdinfo);
        for (int j = 0; j < fd_count; j++) {
            if (fds[j].proc_fdtype != PROX_FDTYPE_SOCKET) {
                continue;
            }
            out->socket_fds += 1;
            struct socket_fdinfo info;
            memset(&info, 0, sizeof(info));
            int n = proc_pidfdinfo(
                pid,
                fds[j].proc_fd,
                PROC_PIDFDSOCKETINFO,
                &info,
                (int)sizeof(info)
            );
            if (n < (int)sizeof(info)) {
                continue;
            }
            uint8_t transport = transport_of(&info.psi);
            if (transport == IPPROTO_TCP || transport == IPPROTO_UDP) {
                out->inet_sockets += 1;
            }
        }
        free(fds);
    }

    free(pids);
    return 0;
}

static int walk_pcblist(const char *mib, int is_tcp, int *rows, int *sample_pgid, int *sample_uid, int *sample_lport) {
    size_t len = 0;
    if (sysctlbyname(mib, NULL, &len, NULL, 0) != 0) {
        return errno;
    }
    char *buf = malloc(len == 0 ? 1 : len);
    if (buf == NULL) {
        return ENOMEM;
    }
    if (sysctlbyname(mib, buf, &len, NULL, 0) != 0) {
        int err = errno;
        free(buf);
        return err;
    }
    if (len < sizeof(struct xinpgen)) {
        free(buf);
        return 0;
    }
    struct xinpgen *xig = (struct xinpgen *)(void *)buf;
    char *end = buf + len;
    char *cursor = buf + xig->xig_len;
    int count = 0;
    while (cursor + sizeof(uint32_t) <= end) {
        uint32_t rec_len = *(uint32_t *)(void *)cursor;
        if (rec_len <= sizeof(struct xinpgen) || cursor + rec_len > end) {
            break;
        }
        if (is_tcp) {
            if (rec_len >= 4 + sizeof(struct inpcb) + sizeof(struct xsocket) + sizeof(u_quad_t)) {
                struct inpcb *inp = (struct inpcb *)(void *)(cursor + 4);
                struct xsocket *so = (struct xsocket *)(void *)(
                    cursor + rec_len - (int)sizeof(u_quad_t) - (int)sizeof(struct xsocket)
                );
                if (count == 0) {
                    *sample_lport = (int)ntohs(inp->inp_lport);
                    *sample_pgid = (int)so->so_pgid;
                    *sample_uid = (int)so->so_uid;
                }
            }
        } else if (rec_len >= sizeof(struct xinpcb)) {
            struct xinpcb *xi = (struct xinpcb *)(void *)cursor;
            if (count == 0) {
                *sample_lport = (int)ntohs(xi->xi_inp.inp_lport);
                *sample_pgid = (int)xi->xi_socket.so_pgid;
                *sample_uid = (int)xi->xi_socket.so_uid;
            }
        }
        count += 1;
        cursor += rec_len;
    }
    *rows = count;
    free(buf);
    return 0;
}

int prizmx_sandbox_probe_fill(prizmx_sandbox_probe *out) {
    if (out == NULL) {
        return -EINVAL;
    }
    memset(out, 0, sizeof(*out));

    size_t kern_len = 0;
    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    int rc = sysctl(mib, 3, NULL, &kern_len, NULL, 0);
    out->kernproc_errno = rc == 0 ? 0 : errno;
    if (rc == 0 && kern_len > 0) {
        struct kinfo_proc *procs = malloc(kern_len);
        if (procs != NULL) {
            rc = sysctl(mib, 3, procs, &kern_len, NULL, 0);
            out->kernproc_errno = rc == 0 ? 0 : errno;
            if (rc == 0) {
                int count = (int)(kern_len / sizeof(struct kinfo_proc));
                out->kernproc_count = count;
                int checked = 0;
                for (int i = 0; i < count && checked < 8; i++) {
                    pid_t pid = procs[i].kp_proc.p_pid;
                    if (pid <= 0) {
                        continue;
                    }
                    checked += 1;
                    int fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
                    if (fd_bytes > 0) {
                        out->pidinfo_ok += 1;
                    } else {
                        out->pidinfo_fail += 1;
                        out->pidinfo_sample_errno = errno;
                    }
                }
            }
            free(procs);
        }
    }

    errno = 0;
    int self_bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    out->self_fd_bytes = self_bytes;
    out->self_errno = self_bytes > 0 ? 0 : errno;

    walk_pcblist(
        "net.inet.tcp.pcblist",
        1,
        &out->tcp_pcb_rows,
        &out->tcp_sample_pgid,
        &out->tcp_sample_uid,
        &out->tcp_sample_lport
    );
    int udp_pgid = 0, udp_uid = 0, udp_lport = 0;
    walk_pcblist("net.inet.udp.pcblist", 0, &out->udp_pcb_rows, &udp_pgid, &udp_uid, &udp_lport);
    (void)udp_pgid;
    (void)udp_uid;
    (void)udp_lport;
    return 0;
}
