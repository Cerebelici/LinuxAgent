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

#define EVENT_TYPE_EXEC 1
#define EVENT_TYPE_CONNECT 2
#define EVENT_TYPE_BASH 3
#define EVENT_TYPE_INJECTION 4

struct event {
    u32 type;           /* 1 = EXEC, 2 = CONNECT, 3 = BASH, 4 = INJECTION */
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char comm[TASK_COMM_LEN];

    /* Union for event-specific payloads to save ring buffer space */
    union {
        char filename[PATH_LEN]; /* Used for EXEC and BASH */
        
        struct {
            u32 daddr;
            u16 dport;
            u16 family;
        } connect;

        struct {
            u32 target_pid;
        } injection;
    } data;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024); /* 512 KB Ring Buffer */
} rb SEC(".maps");

/* 1. Capture Process Execution */
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
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

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    u64 filename_ptr = (u64)ctx + (ctx->__data_loc_filename & 0xffff);
    bpf_probe_read_str(&e->data.filename, sizeof(e->data.filename), (void *)filename_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 2. Capture Network Connections */
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

/* 3. Capture Typed Bash Commands via uretprobe on readline */
SEC("uretprobe//bin/bash:readline")
int handle_bash_readline(struct pt_regs *ctx)
{
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

    char *cmd = (char *)PT_REGS_RC(ctx);
    if (cmd) {
        bpf_probe_read_user_str(&e->data.filename, sizeof(e->data.filename), cmd);
    } else {
        e->data.filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* 4. Capture Process Injection Attempts */
SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int handle_process_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 current_pid = id >> 32;
    u32 target_pid = (u32)ctx->args[0];
    if (current_pid == target_pid)
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

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
