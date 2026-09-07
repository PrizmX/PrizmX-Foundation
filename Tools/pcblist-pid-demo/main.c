/*
 * CLI demo: resolve a TCP local port to PID via net.inet.tcp.pcblist_n
 * (tagged xinpcb_n + xsocket_n, so_e_pid / so_last_pid).
 *
 *   cc -O2 -o pcblist-pid-demo main.c
 *   ./pcblist-pid-demo
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <libproc.h>

#ifndef ROUNDUP64
#define ROUNDUP64(x) (((x) + 7u) & ~7u)
#endif

#define XSO_SOCKET  0x001
#define XSO_RCVBUF  0x002
#define XSO_SNDBUF  0x004
#define XSO_STATS   0x008
#define XSO_INPCB   0x010
#define XSO_TCPCB   0x020

#pragma pack(push, 4)
struct xinpgen_hdr {
    uint32_t xig_len;
    uint32_t xig_count;
    uint64_t xig_gen;
    uint64_t xig_sogen;
};
#pragma pack(pop)

static pid_t find_pid(uint16_t local_port_host, int is_tcp)
{
    const char *mib = is_tcp ? "net.inet.tcp.pcblist_n" : "net.inet.udp.pcblist_n";
    size_t len = 0;
    if (sysctlbyname(mib, NULL, &len, NULL, 0) != 0) {
        fprintf(stderr, "sysctl size %s: %s\n", mib, strerror(errno));
        return 0;
    }
    char *buf = malloc(len);
    if (buf == NULL) {
        return 0;
    }
    if (sysctlbyname(mib, buf, &len, NULL, 0) != 0) {
        fprintf(stderr, "sysctl read %s: %s\n", mib, strerror(errno));
        free(buf);
        return 0;
    }

    if (len < 16) {
        free(buf);
        return 0;
    }
    uint32_t hdr_len = *(uint32_t *)(void *)buf;
    if (hdr_len < 8 || hdr_len > len) {
        hdr_len = 24;
    }

    char *p = buf + hdr_len;
    char *end = buf + len;
    uint16_t want = htons(local_port_host);
    pid_t found = 0;
    uint16_t pending_lport = 0;
    int pending = 0;
    int records = 0;

    while (p + 8 <= end) {
        uint32_t rec_len = *(uint32_t *)(void *)p;
        uint32_t rec_kind = *(uint32_t *)(void *)(p + 4);
        if (rec_len < 8 || p + rec_len > end) {
            break;
        }
        records += 1;

        if (rec_kind == XSO_INPCB && rec_len >= 20) {
            pending_lport = *(uint16_t *)(void *)(p + 18); /* inp_lport */
            pending = 1;
            if (records < 8) {
                fprintf(stderr, "  inpcb lport=%u fport=%u\n",
                        (unsigned)ntohs(pending_lport),
                        (unsigned)ntohs(*(uint16_t *)(void *)(p + 16)));
            }
        } else if (rec_kind == XSO_SOCKET && rec_len >= 76 && pending) {
            /* Darwin xsocket_n (104 bytes on macOS 26): so_uid@64, so_last_pid@68, so_e_pid@72. */
            pid_t last_pid = *(pid_t *)(void *)(p + 68);
            pid_t e_pid = *(pid_t *)(void *)(p + 72);
            if (pending_lport == want) {
                found = e_pid != 0 ? e_pid : last_pid;
                fprintf(stderr, "match lport=%u last_pid=%d e_pid=%d uid=%d\n",
                        (unsigned)ntohs(pending_lport), (int)last_pid, (int)e_pid,
                        *(int *)(void *)(p + 64));
                break;
            }
            pending = 0;
        }

        size_t step = ROUNDUP64(rec_len);
        if (step < rec_len) {
            break;
        }
        p += step;
    }

    fprintf(stderr, "pcblist_n %s bytes=%zu hdr=%u tagged=%d\n",
            mib, len, hdr_len, records);
    free(buf);
    return found;
}

static int open_tcp_and_get_port(uint16_t *out_port)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 || client < 0) {
        perror("socket");
        return -1;
    }
    int yes = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0
        || listen(listener, 1) != 0) {
        perror("bind/listen");
        return -1;
    }
    socklen_t alen = sizeof(addr);
    if (getsockname(listener, (struct sockaddr *)&addr, &alen) != 0) {
        perror("getsockname listener");
        return -1;
    }
    if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        return -1;
    }
    int accepted = accept(listener, NULL, NULL);
    if (accepted < 0) {
        perror("accept");
        return -1;
    }
    (void)accepted;
    (void)listener; /* keep listener + accepted open for PCB lifetime */

    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    if (getsockname(client, (struct sockaddr *)&local, &local_len) != 0) {
        perror("getsockname client");
        close(client);
        return -1;
    }
    *out_port = ntohs(local.sin_port);
    return client;
}

int main(void)
{
    uint16_t port = 0;
    int fd = open_tcp_and_get_port(&port);
    if (fd < 0) {
        return 1;
    }
    pid_t self = getpid();
    printf("self pid=%d localPort=%u\n", (int)self, (unsigned)port);

    pid_t found = find_pid(port, 1);
    printf("findPID(port=%u, tcp) -> %d\n", (unsigned)port, (int)found);

    if (found == self) {
        char path[4096];
        int n = proc_pidpath(found, path, sizeof(path));
        printf("PASS pid matches self\n");
        if (n > 0) {
            printf("path=%s\n", path);
        }
        close(fd);
        return 0;
    }

    printf("FAIL expected %d\n", (int)self);
    close(fd);
    return 2;
}
