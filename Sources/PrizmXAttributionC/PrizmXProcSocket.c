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
#include <netinet/in_pcb.h>
#include <sys/proc_info.h>
#include <sys/socketvar.h>

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

static int fill_pcblist_n(
    const char *mib,
    uint8_t transport,
    prizmx_socket_row *out,
    int max_count,
    pid_t skip_pid
) {
    if (out == NULL || max_count <= 0) {
        return 0;
    }
    size_t len = 0;
    if (sysctlbyname(mib, NULL, &len, NULL, 0) != 0 || len < 16) {
        return 0;
    }
    char *buf = malloc(len);
    if (buf == NULL) {
        return 0;
    }
    if (sysctlbyname(mib, buf, &len, NULL, 0) != 0) {
        free(buf);
        return 0;
    }
    uint32_t hdr_len = *(uint32_t *)(void *)buf;
    if (hdr_len < 8 || hdr_len > len) {
        hdr_len = 24;
    }
    char *p = buf + hdr_len;
    char *end = buf + len;
    int written = 0;
    uint16_t pending_lport = 0;
    uint16_t pending_fport = 0;
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
                row->local_port = pending_lport;
                row->remote_port = pending_fport;
                written += 1;
            }
        }
        p += ROUNDUP64(rec_len);
    }
    free(buf);
    return written;
}

int prizmx_list_pcblist_n(prizmx_socket_row *out, int max_count, pid_t skip_pid) {
    if (out == NULL || max_count <= 0) {
        errno = EINVAL;
        return -EINVAL;
    }
    int tcp = fill_pcblist_n("net.inet.tcp.pcblist_n", IPPROTO_TCP, out, max_count, skip_pid);
    int udp = 0;
    if (tcp < max_count) {
        udp = fill_pcblist_n(
            "net.inet.udp.pcblist_n",
            IPPROTO_UDP,
            out + tcp,
            max_count - tcp,
            skip_pid
        );
    }
    return tcp + udp;
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

int prizmx_list_sockets(prizmx_socket_row *out, int max_count, pid_t skip_pid) {
    if (out == NULL || max_count <= 0) {
        errno = EINVAL;
        return -EINVAL;
    }

    int pid_bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (pid_bytes <= 0) {
        return pid_bytes == 0 ? 0 : -errno;
    }

    pid_t *pids = malloc((size_t)pid_bytes);
    if (pids == NULL) {
        return -ENOMEM;
    }
    int got = proc_listpids(PROC_ALL_PIDS, 0, pids, pid_bytes);
    if (got <= 0) {
        int err = got == 0 ? 0 : -errno;
        free(pids);
        return err;
    }
    int pid_count = got / (int)sizeof(pid_t);
    int written = 0;

    for (int i = 0; i < pid_count && written < max_count; i++) {
        pid_t pid = pids[i];
        if (pid <= 0 || pid == skip_pid) {
            continue;
        }

        int fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (fd_bytes <= 0) {
            continue;
        }
        struct proc_fdinfo *fds = malloc((size_t)fd_bytes);
        if (fds == NULL) {
            continue;
        }
        int fd_got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, fd_bytes);
        if (fd_got <= 0) {
            free(fds);
            continue;
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
    }

    free(pids);
    return written;
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

    int pid_bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    out->last_errno = errno;
    out->listpids_bytes = pid_bytes;
    if (pid_bytes <= 0) {
        return pid_bytes <= 0 && errno != 0 ? -errno : 0;
    }

    pid_t *pids = malloc((size_t)pid_bytes);
    if (pids == NULL) {
        out->last_errno = ENOMEM;
        return -ENOMEM;
    }
    int got = proc_listpids(PROC_ALL_PIDS, 0, pids, pid_bytes);
    if (got <= 0) {
        out->last_errno = errno;
        out->listpids_bytes = got;
        free(pids);
        return got == 0 ? 0 : -errno;
    }
    int pid_count = got / (int)sizeof(pid_t);
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
