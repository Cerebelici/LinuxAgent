#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "proc_exec.skel.h"

#define TASK_COMM_LEN 16
#define PATH_LEN 256

#define EVENT_TYPE_EXEC 1
#define EVENT_TYPE_CONNECT 2
#define EVENT_TYPE_BASH 3
#define EVENT_TYPE_INJECTION 4

#define TARGET_HOST "sentinel-defence"
#define TARGET_PORT "9999"

/* Custom libbpf print function callback */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

/* Must match the struct layout in proc_exec.bpf.c */
struct event {
    unsigned int type;
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    unsigned int gid;
    char comm[TASK_COMM_LEN];

    union {
        char filename[PATH_LEN]; /* Used for EXEC and BASH */
        
        struct {
            unsigned int daddr;
            unsigned short dport;
            unsigned short family;
        } connect;

        struct {
            unsigned int target_pid;
        } injection;
    } data;
};

static volatile sig_atomic_t stop = 0;
static int sockfd = -1;

static void sig_handler(int sig)
{
    stop = 1;
}

/* Connects/reconnects to sentinel.defence:9999 over raw TCP */
static int init_network_connection(const char *host, const char *port)
{
    struct addrinfo hints, *res, *p;
    int status;

    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     /* IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* TCP */

    if ((status = getaddrinfo(host, port, &hints, &res)) != 0) {
        fprintf(stderr, "[!] DNS resolution failed for %s: %s\n", host, gai_strerror(status));
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0) {
            printf("[+] Connected to %s:%s\n", host, port);
            break;
        }

        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(res);

    if (sockfd < 0) {
        fprintf(stderr, "[!] Could not connect to %s:%s\n", host, port);
        return -1;
    }

    return 0;
}

/* Helper to safely send full buffer over TCP raw socket */
static int send_payload(const char *buf, size_t len)
{
    if (sockfd < 0) {
        if (init_network_connection(TARGET_HOST, TARGET_PORT) < 0) {
            return -1;
        }
    }

    /* MSG_NOSIGNAL prevents process SIGPIPE crash if the receiver disconnects */
    ssize_t sent = send(sockfd, buf, len, MSG_NOSIGNAL);
    if (sent < 0) {
        fprintf(stderr, "[!] Send failed (%s). Retrying connection...\n", strerror(errno));
        close(sockfd);
        sockfd = -1;

        /* Attempt 1 reconnect attempt immediately */
        if (init_network_connection(TARGET_HOST, TARGET_PORT) == 0) {
            send(sockfd, buf, len, MSG_NOSIGNAL);
        }
        return -1;
    }

    return 0;
}

/* Event consumer callback */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    char payload[1024];
    int len = 0;

    if (e->type == EVENT_TYPE_EXEC) {
        printf("[EXEC]      PID: %-6u | PPID: %-6u | UID: %-5u | COMM: %-12s | FILE: %s\n",
               e->pid, e->ppid, e->uid, e->comm, e->data.filename);

        len = snprintf(payload, sizeof(payload),
                       "{\"type\":\"EXEC\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\",\"filename\":\"%s\"}\n",
                       e->pid, e->ppid, e->uid, e->comm, e->data.filename);

    } else if (e->type == EVENT_TYPE_CONNECT) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(e->data.connect.daddr), ip_str, sizeof(ip_str));
        printf("[CONNECT]   PID: %-6u | PPID: %-6u | UID: %-5u | COMM: %-12s | DST: %s:%d\n",
               e->pid, e->ppid, e->uid, e->comm, ip_str, e->data.connect.dport);

        len = snprintf(payload, sizeof(payload),
                       "{\"type\":\"CONNECT\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\",\"dst_ip\":\"%s\",\"dst_port\":%d}\n",
                       e->pid, e->ppid, e->uid, e->comm, ip_str, e->data.connect.dport);

    } else if (e->type == EVENT_TYPE_BASH) {
        printf("[BASH_CMD]  PID: %-6u | PPID: %-6u | UID: %-5u | COMM: %-12s | CMD: %s\n",
               e->pid, e->ppid, e->uid, e->comm, e->data.filename);

        len = snprintf(payload, sizeof(payload),
                       "{\"type\":\"BASH_CMD\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\",\"cmd\":\"%s\"}\n",
                       e->pid, e->ppid, e->uid, e->comm, e->data.filename);

    } else if (e->type == EVENT_TYPE_INJECTION) {
        printf("[INJECTION] PID: %-6u | PPID: %-6u | UID: %-5u | COMM: %-12s | TARGET PID: %u\n",
               e->pid, e->ppid, e->uid, e->comm, e->data.injection.target_pid);

        len = snprintf(payload, sizeof(payload),
                       "{\"type\":\"INJECTION\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\",\"target_pid\":%u}\n",
                       e->pid, e->ppid, e->uid, e->comm, e->data.injection.target_pid);
    }

    /* Send payload out over raw socket */
    if (len > 0) {
        send_payload(payload, len);
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct proc_exec_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    /* Set up libbpf debug output callback */
    libbpf_set_print(libbpf_print_fn);

    /* Initial attempt to open connection to sentinel.defence:9999 */
    init_network_connection(TARGET_HOST, TARGET_PORT);

    /* Open BPF application skeleton */
    skel = proc_exec_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs inside the kernel */
    err = proc_exec_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Automatically attach all SEC() hooks (tracepoints & uprobes) */
    err = proc_exec_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Catch Ctrl+C (SIGINT) and termination (SIGTERM) for graceful exit */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("=================================================================================\n");
    printf("Successfully started eBPF Security Agent! Listening for events...\n");
    printf("=================================================================================\n");

    /* Poll ring buffer continuously */
    while (!stop) {
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err < 0 && err == -EINTR) {
            continue;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    printf("\nCleaning up and shutting down...\n");
    if (sockfd >= 0) {
        close(sockfd);
    }
    ring_buffer__free(rb);
    proc_exec_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}