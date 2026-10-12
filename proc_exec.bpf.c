#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#define TASK_COMM_LEN 16
#define PATH_LEN 256

/* EDR Event Types */
#define EVENT_TYPE_EXEC 1
#define EVENT_TYPE_CONNECT 2
#define EVENT_TYPE_BASH 3
#define EVENT_TYPE_INJECTION 4
#define EVENT_TYPE_FILE_TAMPER 5
#define EVENT_TYPE_PRIV_ESC 6
#define EVENT_TYPE_KERNEL_MOD 7
#define EVENT_TYPE_MEMFD_EXEC 8

struct event {
    u32 type;           /* 1=EXEC, 2=CONNECT, 3=BASH, 4=INJECTION, 5=FILE_TAMPER, 6=PRIV_ESC, 7=KERNEL_MOD, 8=MEMFD_EXEC */
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char comm[TASK_COMM_LEN];

    /* Union for event-specific payloads to optimize ring buffer space */
    union {
        char filename[PATH_LEN]; /* Used for EXEC, BASH, FILE_TAMPER, KERNEL_MOD, MEMFD_EXEC */
        
        struct {
            u32 daddr;
            u16 dport;
            u16 family;
        } connect;

        struct {
            u32 target_pid;
            u32 req;             /* 0 for process_vm_writev, or ptrace request type */
        } injection;

        struct {
            u32 target_uid;
            u32 old_uid;
        } priv_esc;
    } data;
};

/* 512 KB Kernel Ring Buffer for high-throughput event streaming */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} rb SEC(".maps");

/* Noise filtering map: Comms in this map are dropped in kernel to avoid ring buffer noise */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, u8);
} noise_comms SEC(".maps");

/* Blocklist map: Comms in this map are flagged for termination by the Kill Switch */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, u8);
} blocked_comms SEC(".maps");

/* Fast inline check for commonly executed benign Linux utilities (cat, sed, ls, etc.) */
static __always_inline int is_noise_comm(const char *c)
{
    /* ls */
    if (c[0] == 'l' && c[1] == 's' && c[2] == '\0') return 1;
    /* cat */
    if (c[0] == 'c' && c[1] == 'a' && c[2] == 't' && c[3] == '\0') return 1;
    /* sed */
    if (c[0] == 's' && c[1] == 'e' && c[2] == 'd' && c[3] == '\0') return 1;
    /* grep */
    if (c[0] == 'g' && c[1] == 'r' && c[2] == 'e' && c[3] == 'p' && c[4] == '\0') return 1;
    /* awk */
    if (c[0] == 'a' && c[1] == 'w' && c[2] == 'k' && c[3] == '\0') return 1;
    /* sleep */
    if (c[0] == 's' && c[1] == 'l' && c[2] == 'e' && c[3] == 'e' && c[4] == 'p' && c[5] == '\0') return 1;
    /* which */
    if (c[0] == 'w' && c[1] == 'h' && c[2] == 'i' && c[3] == 'c' && c[4] == 'h' && c[5] == '\0') return 1;
    /* head */
    if (c[0] == 'h' && c[1] == 'e' && c[2] == 'a' && c[3] == 'd' && c[4] == '\0') return 1;
    /* tail */
    if (c[0] == 't' && c[1] == 'a' && c[2] == 'i' && c[3] == 'l' && c[4] == '\0') return 1;
    /* cut */
    if (c[0] == 'c' && c[1] == 'u' && c[2] == 't' && c[3] == '\0') return 1;
    /* tr */
    if (c[0] == 't' && c[1] == 'r' && c[2] == '\0') return 1;
    /* wc */
    if (c[0] == 'w' && c[1] == 'c' && c[2] == '\0') return 1;
    /* sort */
    if (c[0] == 's' && c[1] == 'o' && c[2] == 'r' && c[3] == 't' && c[4] == '\0') return 1;
    /* uniq */
    if (c[0] == 'u' && c[1] == 'n' && c[2] == 'i' && c[3] == 'q' && c[4] == '\0') return 1;
    /* date */
    if (c[0] == 'd' && c[1] == 'a' && c[2] == 't' && c[3] == 'e' && c[4] == '\0') return 1;
    /* uname */
    if (c[0] == 'u' && c[1] == 'n' && c[2] == 'a' && c[3] == 'm' && c[4] == 'e' && c[5] == '\0') return 1;
    /* clear */
    if (c[0] == 'c' && c[1] == 'l' && c[2] == 'e' && c[3] == 'a' && c[4] == 'r' && c[5] == '\0') return 1;
    /* reset */
    if (c[0] == 'r' && c[1] == 'e' && c[2] == 's' && c[3] == 'e' && c[4] == 't' && c[5] == '\0') return 1;
    /* basename */
    if (c[0] == 'b' && c[1] == 'a' && c[2] == 's' && c[3] == 'e' && c[4] == 'n' && c[5] == 'a' && c[6] == 'm' && c[7] == 'e' && c[8] == '\0') return 1;
    /* dirname */
    if (c[0] == 'd' && c[1] == 'i' && c[2] == 'r' && c[3] == 'n' && c[4] == 'a' && c[5] == 'm' && c[6] == 'e' && c[7] == '\0') return 1;
    /* true */
    if (c[0] == 't' && c[1] == 'r' && c[2] == 'u' && c[3] == 'e' && c[4] == '\0') return 1;
    /* false */
    if (c[0] == 'f' && c[1] == 'a' && c[2] == 'l' && c[3] == 's' && c[4] == '\0') return 1;

    return 0;
}

/* 1. Capture Process Execution */
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    /* Check if process is explicitly blocked by Kill Switch policy */
    u8 *blocked = bpf_map_lookup_elem(&blocked_comms, comm);
    int is_blocked = (blocked && *blocked == 1);

    if (!is_blocked) {
        /* Drop useless noise executions directly in kernel */
        if (is_noise_comm(comm))
            return 0;

        u8 *noise = bpf_map_lookup_elem(&noise_comms, comm);
        if (noise && *noise == 1)
            return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_TYPE_EXEC;
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    for (int i = 0; i < TASK_COMM_LEN; i++)
        e->comm[i] = comm[i];

    u64 filename_ptr = (u64)ctx + (ctx->__data_loc_filename & 0xffff);
    bpf_probe_read_str(&e->data.filename, sizeof(e->data.filename), (void *)filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 2. Capture Network Connections (Outbound TCP) */
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in addr;
    struct sockaddr *user_addr = (struct sockaddr *)ctx->args[1];
    
    if (!user_addr)
        return 0;

    bpf_probe_read_user(&addr, sizeof(addr), user_addr);

    if (addr.sin_family != AF_INET)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 id = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    e->type = EVENT_TYPE_CONNECT;
    e->pid = id >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->data.connect.family = addr.sin_family;
    e->data.connect.daddr = addr.sin_addr.s_addr;
    e->data.connect.dport = bpf_ntohs(addr.sin_port);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 3. Capture Interactive Bash Commands via readline */
SEC("uretprobe//bin/bash:readline")
int handle_bash_readline(struct pt_regs *ctx)
{
    char *cmd = (char *)PT_REGS_RC(ctx);
    if (!cmd)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_TYPE_BASH;
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->data.filename, sizeof(e->data.filename), cmd);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 4. Capture Process Injection Attempts via process_vm_writev */
SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int handle_process_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 current_pid = id >> 32;
    u32 target_pid = (u32)ctx->args[0];
    if (current_pid == target_pid || target_pid <= 1)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_TYPE_INJECTION;
    e->pid = current_pid;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->data.injection.target_pid = target_pid;
    e->data.injection.req = 0; /* process_vm_writev */

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 5. Capture Process Injection Attempts via ptrace */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 current_pid = id >> 32;
    u32 target_pid = (u32)ctx->args[1];
    long req = (long)ctx->args[0];

    /* Ignore self-tracing or invalid targets */
    if (target_pid <= 1 || current_pid == target_pid)
        return 0;

    /* Filter for injection / hijack requests:
       PTRACE_POKETEXT(4), PTRACE_POKEDATA(5), PTRACE_ATTACH(16), PTRACE_SEIZE(0x4206) */
    if (req != 4 && req != 5 && req != 16 && req != 0x4206)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_TYPE_INJECTION;
    e->pid = current_pid;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->data.injection.target_pid = target_pid;
    e->data.injection.req = (u32)req;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 6. Sensitive File Integrity Monitoring (FIM) / Tampering */
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    int flags = (int)ctx->args[2];

    /* Only inspect write/create/truncate operations (O_WRONLY=1, O_RDWR=2, O_CREAT=64, O_TRUNC=512) */
    if ((flags & 3) == 0 && (flags & 64) == 0 && (flags & 512) == 0)
        return 0;

    const char *user_path = (const char *)ctx->args[1];
    if (!user_path)
        return 0;

    char prefix[8];
    bpf_probe_read_user_str(prefix, sizeof(prefix), user_path);

    /* Quick check: matches sensitive system directories (/etc/ or /root) */
    int sensitive = 0;
    if (prefix[0] == '/' && prefix[1] == 'e' && prefix[2] == 't' && prefix[3] == 'c' && prefix[4] == '/')
        sensitive = 1;
    else if (prefix[0] == '/' && prefix[1] == 'r' && prefix[2] == 'o' && prefix[3] == 'o' && prefix[4] == 't')
        sensitive = 1;

    if (!sensitive)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_TYPE_FILE_TAMPER;
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->data.filename, sizeof(e->data.filename), user_path);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 7. Capture Kernel Module Loading (Rootkit attempts) */
SEC("tracepoint/syscalls/sys_enter_init_module")
int handle_init_module(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_TYPE_KERNEL_MOD;
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *uargs = (const char *)ctx->args[2];
    if (uargs)
        bpf_probe_read_user_str(&e->data.filename, sizeof(e->data.filename), uargs);
    else
        e->data.filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int handle_finit_module(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_TYPE_KERNEL_MOD;
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    int fd = (int)ctx->args[0];
    e->data.filename[0] = 'f';
    e->data.filename[1] = 'd';
    e->data.filename[2] = ':';
    e->data.filename[3] = '0' + (fd % 10);
    e->data.filename[4] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 8. Capture Privilege Escalation (Non-root attempting to become root UID 0) */
SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx)
{
    u32 target_uid = (u32)ctx->args[0];
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 current_uid = (u32)uid_gid;

    /* Detect non-root process escalating to root (uid 0) */
    if (current_uid == 0 || target_uid != 0)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_TYPE_PRIV_ESC;
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid = current_uid;
    e->gid = (u32)(uid_gid >> 32);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->data.priv_esc.target_uid = target_uid;
    e->data.priv_esc.old_uid = current_uid;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 9. Capture Fileless In-Memory Execution via memfd_create */
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_TYPE_MEMFD_EXEC;
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *uname = (const char *)ctx->args[0];
    if (uname)
        bpf_probe_read_user_str(&e->data.filename, sizeof(e->data.filename), uname);
    else
        e->data.filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
