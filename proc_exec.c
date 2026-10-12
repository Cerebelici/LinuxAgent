#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/types.h>
typedef __u32 u32;
typedef __u64 u64;

#include "proc_exec.skel.h"
#include "identity.h"
#include "exporter.h"

#define TASK_COMM_LEN 16
#define PATH_LEN 256
#define MAX_INVENTORY_PROCS 2048

/* Event types matching proc_exec.bpf.c */
#define EVENT_TYPE_EXEC 1
#define EVENT_TYPE_CONNECT 2
#define EVENT_TYPE_BASH 3
#define EVENT_TYPE_INJECTION 4
#define EVENT_TYPE_FILE_TAMPER 5
#define EVENT_TYPE_PRIV_ESC 6
#define EVENT_TYPE_KERNEL_MOD 7
#define EVENT_TYPE_MEMFD_EXEC 8

/* ANSI Colors for formatted console output */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"
#define COLOR_MAGENTA "\033[1;35m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_BOLD    "\033[1m"

/* Event structure layout matching kernel eBPF */
struct event {
    unsigned long long ts_ns;
    unsigned int type;
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    unsigned int gid;
    char comm[TASK_COMM_LEN];

    union {
        char filename[PATH_LEN]; /* Used for EXEC, BASH, FILE_TAMPER, KERNEL_MOD, MEMFD_EXEC */

        struct {
            unsigned int daddr;
            unsigned char daddr6[16];
            unsigned short dport;
            unsigned short family;
        } connect;

        struct {
            unsigned int target_pid;
            unsigned int req;    /* 0 for process_vm_writev, or ptrace request type */
        } injection;

        struct {
            unsigned int target_uid;
            unsigned int old_uid;
        } priv_esc;
    } data;
};

/* Threat assessment structure */
struct threat_assessment {
    int is_threat;
    const char *severity;        /* INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL */
    const char *rule_name;       /* e.g. POTENTIAL_REVERSE_SHELL */
    const char *mitre_tactic;    /* e.g. Command and Control */
    const char *mitre_technique; /* e.g. T1059.004 */
    char description[512];
};

/* Agent Configuration */
struct agent_config {
    char sentinel_url[512];
    char enroll_token[256];
    char token_file[512];
    char ca_file[512];
    int insecure_http;
    int auto_kill;
    int verbose;
    char hostname[128];
};

static struct agent_config config;
static volatile sig_atomic_t stop = 0;
static unsigned long long total_events_processed = 0;
static unsigned long long total_alerts_detected = 0;
__attribute__((unused)) static time_t agent_start_time = 0;

static struct agent_identity global_identity;
static struct exporter *global_exporter = NULL;
static struct timespec boot_realtime;
static struct timespec boot_boottime;

/* BPF skeleton handle */
__attribute__((unused)) static struct proc_exec_bpf *global_skel = NULL;

/* Default noise binaries to filter out */
static const char *const NOISE_COMM_LIST[] = {
    "ls", "cat", "sed", "grep", "awk", "sleep", "which",
    "head", "tail", "cut", "tr", "wc", "sort", "uniq",
    "date", "uname", "clear", "reset", "basename", "dirname",
    "true", "false", "expr", "touch", "id", "groups",
    "dircolors", "stty", "tput", "uptime", "hostname", "locale",
    NULL
};

/* Helper: Custom libbpf print callback */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !config.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

/* Helper: Signal handler for graceful shutdown */
static void sig_handler(int sig)
{
    (void)sig;
    stop = 1;
}

/* Helper: Escape JSON string safely, escaping \u00XX for all bytes < 0x20 */
static void json_escape(const char *src, char *dst, size_t dst_len)
{
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j < dst_len - 1; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\"') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\'; dst[j++] = '\"';
        } else if (c == '\\') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\'; dst[j++] = '\\';
        } else if (c < 0x20) {
            if (j + 6 >= dst_len) break;
            snprintf(&dst[j], 7, "\\u00%02x", c);
            j += 6;
        } else {
            dst[j++] = c;
        }
    }
    dst[j] = '\0';
}

/* Helper: ISO 8601 UTC timestamp with milliseconds */
static void get_iso8601_time(char *buf, size_t buf_len)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_info;
    gmtime_r(&ts.tv_sec, &tm_info);
    char tmp[32];
    strftime(tmp, sizeof(tmp), "%Y-%m-%dT%H:%M:%S", &tm_info);
    snprintf(buf, buf_len, "%s.%03ldZ", tmp, ts.tv_nsec / 1000000L);
}

/* Helper: Format event boot timestamp to ISO 8601 UTC */
static void format_event_ts(unsigned long long ts_ns, char *buf, size_t buf_len)
{
    if (ts_ns == 0) {
        get_iso8601_time(buf, buf_len);
        return;
    }
    time_t sec = (boot_realtime.tv_sec - boot_boottime.tv_sec) + (time_t)(ts_ns / 1000000000ULL);
    long nsec = (boot_realtime.tv_nsec - boot_boottime.tv_nsec) + (long)(ts_ns % 1000000000ULL);
    if (nsec < 0) {
        sec -= 1;
        nsec += 1000000000L;
    } else if (nsec >= 1000000000L) {
        sec += 1;
        nsec -= 1000000000L;
    }
    struct tm tm_info;
    gmtime_r(&sec, &tm_info);
    char tmp[32];
    strftime(tmp, sizeof(tmp), "%Y-%m-%dT%H:%M:%S", &tm_info);
    snprintf(buf, buf_len, "%s.%03ldZ", tmp, nsec / 1000000L);
}

/* Inline checks for noise filtering */
static int is_noise_comm(const char *comm)
{
    for (int i = 0; NOISE_COMM_LIST[i] != NULL; i++) {
        if (strcmp(comm, NOISE_COMM_LIST[i]) == 0)
            return 1;
    }
    return 0;
}

static int is_noise_bash_cmd(const char *cmd)
{
    if (cmd[0] == '\0') return 1;
    if (strcmp(cmd, "ls") == 0 || strcmp(cmd, "clear") == 0 ||
        strcmp(cmd, "pwd") == 0 || strcmp(cmd, "whoami") == 0)
        return 1;
    return 0;
}

/* Populate noise filter map in kernel BPF */
static void populate_noise_filter_map(struct proc_exec_bpf *skel)
{
    if (!skel || !skel->maps.noise_comms) return;
    int map_fd = bpf_map__fd(skel->maps.noise_comms);
    uint8_t val = 1;

    for (int i = 0; NOISE_COMM_LIST[i] != NULL; i++) {
        char key[TASK_COMM_LEN] = {0};
        snprintf(key, sizeof(key), "%s", NOISE_COMM_LIST[i]);
        bpf_map_update_elem(map_fd, key, &val, BPF_ANY);
    }
}

/* Local EDR Threat Assessment Rules */
static void assess_event(const struct event *e, struct threat_assessment *out)
{
    memset(out, 0, sizeof(*out));
    out->is_threat = 0;
    out->severity = "INFORMATIONAL";
    out->rule_name = "BENIGN_TELEMETRY";
    out->mitre_tactic = "Execution";
    out->mitre_technique = "T1059";
    snprintf(out->description, sizeof(out->description), "Normal observed event");

    switch (e->type) {
        case EVENT_TYPE_INJECTION:
            out->is_threat = 1;
            out->severity = "CRITICAL";
            out->mitre_tactic = "Defense Evasion";
            if (e->data.injection.req == 0) {
                out->rule_name = "PROCESS_VM_WRITEV_INJECTION";
                out->mitre_technique = "T1055";
                snprintf(out->description, sizeof(out->description),
                         "Process memory write detected into target PID %u", e->data.injection.target_pid);
            } else {
                out->rule_name = "PTRACE_PROCESS_INJECTION";
                out->mitre_technique = "T1055.008";
                snprintf(out->description, sizeof(out->description),
                         "Ptrace hijack attempt (req=%u) against target PID %u",
                         e->data.injection.req, e->data.injection.target_pid);
            }
            break;

        case EVENT_TYPE_KERNEL_MOD:
            out->is_threat = 1;
            out->severity = "CRITICAL";
            out->rule_name = "KERNEL_ROOTKIT_ATTEMPT";
            out->mitre_tactic = "Persistence";
            out->mitre_technique = "T1547.006";
            snprintf(out->description, sizeof(out->description),
                     "Kernel module insertion attempt by %.32s (args: %.200s)", e->comm, e->data.filename);
            break;

        case EVENT_TYPE_FILE_TAMPER:
            out->is_threat = 1;
            out->mitre_tactic = "Defense Evasion";
            if (strstr(e->data.filename, "shadow") || strstr(e->data.filename, "passwd")) {
                out->severity = "CRITICAL";
                out->rule_name = "SHADOW_CREDENTIAL_TAMPER";
                out->mitre_technique = "T1003.008";
                snprintf(out->description, sizeof(out->description),
                         "Tampering with sensitive credential file: %.200s", e->data.filename);
            } else if (strstr(e->data.filename, "ld.so.preload")) {
                out->severity = "CRITICAL";
                out->rule_name = "PRELOAD_ROOTKIT_PERSISTENCE";
                out->mitre_technique = "T1574.006";
                snprintf(out->description, sizeof(out->description),
                         "Rootkit persistence attempt modifying /etc/ld.so.preload");
            } else if (strstr(e->data.filename, "sudoers")) {
                out->severity = "HIGH";
                out->rule_name = "SUDOERS_PRIVILEGE_TAMPER";
                out->mitre_technique = "T1548.003";
                snprintf(out->description, sizeof(out->description),
                         "Privilege configuration tampered: %.200s", e->data.filename);
            } else if (strstr(e->data.filename, "cron")) {
                out->severity = "HIGH";
                out->rule_name = "CRON_PERSISTENCE_TAMPER";
                out->mitre_technique = "T1053.003";
                snprintf(out->description, sizeof(out->description),
                         "Scheduled job tampered: %.200s", e->data.filename);
            } else if (strstr(e->data.filename, "authorized_keys")) {
                out->severity = "HIGH";
                out->rule_name = "SSH_BACKDOOR_KEY_MODIFICATION";
                out->mitre_technique = "T1098.004";
                snprintf(out->description, sizeof(out->description),
                         "SSH backdoor key tampering detected: %.200s", e->data.filename);
            } else {
                out->severity = "MEDIUM";
                out->rule_name = "SYSTEM_CONFIG_TAMPER";
                out->mitre_technique = "T1565";
                snprintf(out->description, sizeof(out->description),
                         "System config file write: %.200s", e->data.filename);
            }
            break;

        case EVENT_TYPE_PRIV_ESC:
            out->is_threat = 1;
            out->severity = "HIGH";
            out->rule_name = "UNAUTHORIZED_ROOT_ESCALATION";
            out->mitre_tactic = "Privilege Escalation";
            out->mitre_technique = "T1068";
            snprintf(out->description, sizeof(out->description),
                     "Process %.32s (UID %u) attempted escalation to root UID 0", e->comm, e->data.priv_esc.old_uid);
            break;

        case EVENT_TYPE_MEMFD_EXEC:
            out->is_threat = 1;
            out->severity = "HIGH";
            out->rule_name = "FILELESS_MEMFD_EXECUTION";
            out->mitre_tactic = "Defense Evasion";
            out->mitre_technique = "T1620";
            snprintf(out->description, sizeof(out->description),
                     "Anonymous in-memory execution via memfd_create (%.200s)", e->data.filename);
            break;

        case EVENT_TYPE_CONNECT: {
            static const char *const REVERSE_SHELL_BINARIES[] = {
                "sh", "bash", "dash", "zsh", "nc", "ncat", "netcat", "socat",
                "python", "python3", "perl", "ruby", "lua", NULL
            };
            int is_shell = 0;
            for (int i = 0; REVERSE_SHELL_BINARIES[i] != NULL; i++) {
                if (strcmp(e->comm, REVERSE_SHELL_BINARIES[i]) == 0) {
                    is_shell = 1;
                    break;
                }
            }
            if (is_shell) {
                out->is_threat = 1;
                out->severity = "CRITICAL";
                out->rule_name = "POTENTIAL_REVERSE_SHELL";
                out->mitre_tactic = "Command and Control";
                out->mitre_technique = "T1059.004";
                snprintf(out->description, sizeof(out->description),
                         "Shell/interpreter %.32s spawned outbound network connection to port %d",
                         e->comm, e->data.connect.dport);
            }
            break;
        }

        case EVENT_TYPE_BASH: {
            const char *cmd = e->data.filename;
            if (strstr(cmd, "/dev/tcp/") || strstr(cmd, "bash -i") ||
                strstr(cmd, "nc -e") || strstr(cmd, "ncat -e") ||
                strstr(cmd, "mkfifo /tmp") || strstr(cmd, "socat exec:")) {
                out->is_threat = 1;
                out->severity = "CRITICAL";
                out->rule_name = "INTERACTIVE_REVERSE_SHELL_COMMAND";
                out->mitre_tactic = "Execution";
                out->mitre_technique = "T1059.004";
                snprintf(out->description, sizeof(out->description),
                         "Reverse shell interactive command pattern: %.200s", cmd);
            } else if (strstr(cmd, "curl") && strstr(cmd, "|") && strstr(cmd, "sh")) {
                out->is_threat = 1;
                out->severity = "HIGH";
                out->rule_name = "PIPE_TO_SHELL_DOWNLOAD_EXECUTE";
                out->mitre_tactic = "Execution";
                out->mitre_technique = "T1059.004";
                snprintf(out->description, sizeof(out->description),
                         "Suspicious remote script execution via curl | sh pipe: %.200s", cmd);
            }
            break;
        }

        case EVENT_TYPE_EXEC: {
            const char *f = e->data.filename;
            if (strstr(f, "/tmp/") || strstr(f, "/dev/shm/") || strstr(f, "/var/tmp/")) {
                out->is_threat = 1;
                out->severity = "HIGH";
                out->rule_name = "SUSPICIOUS_TMP_EXECUTION";
                out->mitre_tactic = "Defense Evasion";
                out->mitre_technique = "T1059";
                snprintf(out->description, sizeof(out->description),
                         "Execution of binary dropped in writable directory: %.200s", f);
            }
            break;
        }
    }
}

/* Recursively kill process and child processes (used by local --auto-kill) */
static int kill_process_tree(pid_t target_pid, int sig)
{
    if (target_pid <= 1 || target_pid == getpid()) {
        fprintf(stderr, "%s[!] Safety check: Refusing to kill protected PID %d%s\n",
                COLOR_YELLOW, target_pid, COLOR_RESET);
        return -1;
    }

    DIR *dir = opendir("/proc");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            char *endptr;
            long child_pid = strtol(entry->d_name, &endptr, 10);
            if (*endptr != '\0' || child_pid <= 1 || child_pid == target_pid)
                continue;

            char stat_path[64];
            snprintf(stat_path, sizeof(stat_path), "/proc/%ld/stat", child_pid);
            FILE *f = fopen(stat_path, "r");
            if (f) {
                char buf[512];
                if (fgets(buf, sizeof(buf), f)) {
                    char *close_paren = strrchr(buf, ')');
                    if (close_paren) {
                        char state;
                        long ppid = 0;
                        if (sscanf(close_paren + 1, " %c %ld", &state, &ppid) == 2) {
                            if (ppid == target_pid) {
                                printf("%s[⚡ AUTO-KILL] Terminating child PID %ld of parent %d%s\n",
                                       COLOR_MAGENTA, child_pid, target_pid, COLOR_RESET);
                                kill_process_tree((pid_t)child_pid, sig);
                            }
                        }
                    }
                }
                fclose(f);
            }
        }
        closedir(dir);
    }

    int res = kill(target_pid, sig);
    if (res == 0) {
        printf("%s[⚡ AUTO-KILL] Successfully sent signal %d to PID %d%s\n",
               COLOR_GREEN, sig, target_pid, COLOR_RESET);
        return 0;
    } else {
        fprintf(stderr, "%s[!] Kill failed for PID %d: %s%s\n",
                COLOR_RED, target_pid, strerror(errno), COLOR_RESET);
        return -errno;
    }
}

#ifdef CERBERUS_ENABLE_REMOTE_ACTIONS
static void process_siem_command(const char *cmd_line)
{
    /* Legacy remote control commands handler */
    (void)cmd_line;
}
#endif

/* Format individual raw event according to DEV-01 contract */
static int format_event_json(const struct event *e, const struct threat_assessment *threat, char *buf, size_t buf_len)
{
    char ts_str[64];
    format_event_ts(e->ts_ns, ts_str, sizeof(ts_str));

    char escaped_comm[64] = {0};
    json_escape(e->comm, escaped_comm, sizeof(escaped_comm));

    char data_json[512] = {0};
    const char *type_str = "UNKNOWN";

    switch (e->type) {
        case EVENT_TYPE_EXEC: {
            type_str = "EXEC";
            char escaped_file[256] = {0};
            json_escape(e->data.filename, escaped_file, sizeof(escaped_file));
            snprintf(data_json, sizeof(data_json), "{\"filename\":\"%s\"}", escaped_file);
            break;
        }
        case EVENT_TYPE_CONNECT: {
            type_str = "CONNECT";
            char ip_str[INET6_ADDRSTRLEN] = {0};
            if (e->data.connect.family == AF_INET6) {
                inet_ntop(AF_INET6, e->data.connect.daddr6, ip_str, sizeof(ip_str));
                snprintf(data_json, sizeof(data_json), "{\"family\":\"inet6\",\"dst_ip\":\"%s\",\"dst_port\":%u}",
                         ip_str, (unsigned int)e->data.connect.dport);
            } else {
                inet_ntop(AF_INET, &(e->data.connect.daddr), ip_str, sizeof(ip_str));
                snprintf(data_json, sizeof(data_json), "{\"family\":\"inet\",\"dst_ip\":\"%s\",\"dst_port\":%u}",
                         ip_str, (unsigned int)e->data.connect.dport);
            }
            break;
        }
        case EVENT_TYPE_BASH: {
            type_str = "BASH_READLINE";
            char escaped_cmd[256] = {0};
            json_escape(e->data.filename, escaped_cmd, sizeof(escaped_cmd));
            snprintf(data_json, sizeof(data_json), "{\"command\":\"%s\"}", escaped_cmd);
            break;
        }
        case EVENT_TYPE_INJECTION: {
            type_str = "PROC_INJECTION";
            const char *method = (e->data.injection.req == 0) ? "process_vm_writev" : "ptrace";
            snprintf(data_json, sizeof(data_json),
                     "{\"method\":\"%s\",\"target_pid\":%u,\"ptrace_request\":%u}",
                     method, e->data.injection.target_pid, e->data.injection.req);
            break;
        }
        case EVENT_TYPE_FILE_TAMPER: {
            type_str = "FILE_TAMPER";
            char escaped_path[256] = {0};
            json_escape(e->data.filename, escaped_path, sizeof(escaped_path));
            snprintf(data_json, sizeof(data_json), "{\"path\":\"%s\"}", escaped_path);
            break;
        }
        case EVENT_TYPE_PRIV_ESC: {
            type_str = "PRIV_ESC";
            snprintf(data_json, sizeof(data_json),
                     "{\"old_uid\":%u,\"target_uid\":%u}",
                     e->data.priv_esc.old_uid, e->data.priv_esc.target_uid);
            break;
        }
        case EVENT_TYPE_KERNEL_MOD: {
            type_str = "KERNEL_MODULE";
            char escaped_args[256] = {0};
            json_escape(e->data.filename, escaped_args, sizeof(escaped_args));
            snprintf(data_json, sizeof(data_json), "{\"args\":\"%s\"}", escaped_args);
            break;
        }
        case EVENT_TYPE_MEMFD_EXEC: {
            type_str = "MEMFD_CREATE";
            char escaped_name[256] = {0};
            json_escape(e->data.filename, escaped_name, sizeof(escaped_name));
            snprintf(data_json, sizeof(data_json), "{\"name\":\"%s\"}", escaped_name);
            break;
        }
    }

    if (threat && threat->is_threat) {
        char esc_rule[64] = {0};
        char esc_sev[32] = {0};
        char esc_tech[32] = {0};
        json_escape(threat->rule_name ? threat->rule_name : "", esc_rule, sizeof(esc_rule));
        json_escape(threat->severity ? threat->severity : "", esc_sev, sizeof(esc_sev));
        json_escape(threat->mitre_technique ? threat->mitre_technique : "", esc_tech, sizeof(esc_tech));

        return snprintf(buf, buf_len,
                        "{\"type\":\"%s\",\"ts\":\"%s\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"gid\":%u,\"comm\":\"%s\",\"data\":%s,\"agent_assessment\":{\"rule\":\"%s\",\"severity\":\"%s\",\"mitre_technique\":\"%s\"}}",
                        type_str, ts_str, e->pid, e->ppid, e->uid, e->gid, escaped_comm, data_json,
                        esc_rule, esc_sev, esc_tech);
    } else {
        return snprintf(buf, buf_len,
                        "{\"type\":\"%s\",\"ts\":\"%s\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"gid\":%u,\"comm\":\"%s\",\"data\":%s}",
                        type_str, ts_str, e->pid, e->ppid, e->uid, e->gid, escaped_comm, data_json);
    }
}

/* Ring buffer callback */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    (void)data_sz;
    const struct event *e = data;
    total_events_processed++;

    /* Filter out self-telemetry from the agent itself (defense-in-depth) */
    if (strcmp(e->comm, "proc_exec") == 0 || (e->pid == (uint32_t)getpid())) {
        return 0;
    }

    /* 1. Filter out useless noise executions */
    if (e->type == EVENT_TYPE_EXEC && is_noise_comm(e->comm)) {
        return 0;
    }
    if (e->type == EVENT_TYPE_BASH && is_noise_bash_cmd(e->data.filename)) {
        return 0;
    }

    /* 2. Run EDR threat assessment */
    struct threat_assessment threat;
    assess_event(e, &threat);

    if (threat.is_threat) {
        total_alerts_detected++;
    }

    /* 3. Handle Autonomous Kill Switch if enabled and threat is CRITICAL */
    if (config.auto_kill && threat.is_threat && strcmp(threat.severity, "CRITICAL") == 0) {
        printf("%s[⚡ AUTO-KILL SWITCH] Terminating high-risk threat PID %u (%s) - %s%s\n",
               COLOR_RED, e->pid, e->comm, threat.rule_name, COLOR_RESET);
        kill_process_tree((pid_t)e->pid, SIGKILL);
    }

    /* 4. Console output */
    if (threat.is_threat) {
        printf("%s[🚨 EDR ALERT] [%s] %s | PID: %-6u | COMM: %-12s | MITRE: %s%s\n",
               COLOR_RED, threat.severity, threat.rule_name, e->pid, e->comm, threat.mitre_technique, COLOR_RESET);
        printf("    Details: %s\n", threat.description);
    } else if (config.verbose || e->type != EVENT_TYPE_EXEC) {
        switch (e->type) {
            case EVENT_TYPE_EXEC:
                printf("%s[EXEC]%-6s PID: %-6u | PPID: %-6u | UID: %-5u | COMM: %-12s | FILE: %s%s\n",
                       COLOR_BLUE, "", e->pid, e->ppid, e->uid, e->comm, e->data.filename, COLOR_RESET);
                break;
            case EVENT_TYPE_CONNECT: {
                char ip_str[INET6_ADDRSTRLEN];
                if (e->data.connect.family == AF_INET6) {
                    inet_ntop(AF_INET6, e->data.connect.daddr6, ip_str, sizeof(ip_str));
                } else {
                    inet_ntop(AF_INET, &(e->data.connect.daddr), ip_str, sizeof(ip_str));
                }
                printf("%s[CONNECT]%-3s PID: %-6u | PPID: %-6u | UID: %-5u | COMM: %-12s | DST: %s:%d%s\n",
                       COLOR_CYAN, "", e->pid, e->ppid, e->uid, e->comm, ip_str, e->data.connect.dport, COLOR_RESET);
                break;
            }
            case EVENT_TYPE_BASH:
                printf("%s[BASH_CMD]  PID: %-6u | PPID: %-6u | UID: %-5u | COMM: %-12s | CMD: %s%s\n",
                       COLOR_YELLOW, e->pid, e->ppid, e->uid, e->comm, e->data.filename, COLOR_RESET);
                break;
            case EVENT_TYPE_INJECTION:
                printf("%s[INJECTION] PID: %-6u | COMM: %-12s | TARGET PID: %u%s\n",
                       COLOR_RED, e->pid, e->comm, e->data.injection.target_pid, COLOR_RESET);
                break;
            case EVENT_TYPE_FILE_TAMPER:
                printf("%s[FILE_TAMPER] PID: %-6u | COMM: %-12s | PATH: %s%s\n",
                       COLOR_YELLOW, e->pid, e->comm, e->data.filename, COLOR_RESET);
                break;
            case EVENT_TYPE_PRIV_ESC:
                printf("%s[PRIV_ESC]  PID: %-6u | COMM: %-12s | %u -> %u%s\n",
                       COLOR_MAGENTA, e->pid, e->comm, e->data.priv_esc.old_uid, e->data.priv_esc.target_uid, COLOR_RESET);
                break;
            case EVENT_TYPE_KERNEL_MOD:
                printf("%s[KERNEL_MOD] PID: %-6u | COMM: %-12s | %s%s\n",
                       COLOR_RED, e->pid, e->comm, e->data.filename, COLOR_RESET);
                break;
            case EVENT_TYPE_MEMFD_EXEC:
                printf("%s[MEMFD_EXEC] PID: %-6u | COMM: %-12s | %s%s\n",
                       COLOR_MAGENTA, e->pid, e->comm, e->data.filename, COLOR_RESET);
                break;
        }
    }

    /* 5. Format enriched JSON and enqueue into exporter ring buffer */
    char event_json[EVENT_JSON_MAX];
    int json_len = format_event_json(e, &threat, event_json, sizeof(event_json));
    if (json_len > 0 && global_exporter) {
        exporter_enqueue(global_exporter, event_json, (size_t)json_len, threat.is_threat);
    }

    return 0;
}

/* Resilient BPF Hook Attachment */
static int attach_bpf_programs(struct proc_exec_bpf *skel)
{
    if (proc_exec_bpf__attach(skel) == 0) {
        return 0;
    }

    fprintf(stderr, "%s[!] Skeleton auto-attach encountered an issue, attaching individual hooks...%s\n",
            COLOR_YELLOW, COLOR_RESET);

    int attached = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, skel->obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (link) {
            attached++;
        } else {
            fprintf(stderr, "[!] Warning: Optional hook '%s' could not attach: %s (continuing)\n",
                    bpf_program__name(prog), strerror(errno));
        }
    }

    return (attached > 0) ? 0 : -1;
}

static void print_usage(const char *prog)
{
    printf("\n%sCerberus Endpoint Agent — Userspace eBPF & HTTP Exporter%s\n", COLOR_BOLD, COLOR_RESET);
    printf("---------------------------------------------------------------------------------\n");
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  -u, --sentinel-url <url>      Sentinel ingestion base URL (default: https://127.0.0.1:8080 or $CERBERUS_URL)\n");
    printf("      --enroll-token <token>    Enrollment token (or $CERBERUS_ENROLL_TOKEN)\n");
    printf("      --token-file <path>       Token storage path (default: /var/lib/cerberus-agent/token or $CERBERUS_TOKEN_FILE)\n");
    printf("      --ca-file <path>          Path to CA certificate bundle (or $CERBERUS_CA_FILE)\n");
    printf("      --insecure-http           Allow unencrypted HTTP communication (or $CERBERUS_INSECURE_HTTP)\n");
    printf("  -a, --auto-kill               Autonomous kill switch: terminate critical threats locally\n");
    printf("  -v, --verbose                 Verbose debug logging\n");
    printf("  -h, --help                    Show this usage information\n");
    printf("---------------------------------------------------------------------------------\n\n");
}

int main(int argc, char **argv)
{
    struct proc_exec_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

    agent_start_time = time(NULL);
    clock_gettime(CLOCK_REALTIME, &boot_realtime);
    clock_gettime(CLOCK_BOOTTIME, &boot_boottime);

    /* Initialize configuration with env vars and defaults */
    memset(&config, 0, sizeof(config));
    const char *env_url = getenv("CERBERUS_URL");
    const char *env_tok = getenv("CERBERUS_ENROLL_TOKEN");
    const char *env_tok_file = getenv("CERBERUS_TOKEN_FILE");
    const char *env_ca = getenv("CERBERUS_CA_FILE");
    const char *env_insecure = getenv("CERBERUS_INSECURE_HTTP");
    const char *env_auto_kill = getenv("CERBERUS_AUTO_KILL");
    if (!env_auto_kill) env_auto_kill = getenv("EDR_AUTO_KILL");

    snprintf(config.sentinel_url, sizeof(config.sentinel_url), "%s", env_url ? env_url : "https://127.0.0.1:8080");
    if (env_tok) snprintf(config.enroll_token, sizeof(config.enroll_token), "%s", env_tok);
    if (env_tok_file) snprintf(config.token_file, sizeof(config.token_file), "%s", env_tok_file);
    if (env_ca) snprintf(config.ca_file, sizeof(config.ca_file), "%s", env_ca);
    if (env_insecure && (strcmp(env_insecure, "1") == 0 || strcasecmp(env_insecure, "true") == 0)) {
        config.insecure_http = 1;
    }
    config.auto_kill = (env_auto_kill && atoi(env_auto_kill) == 1) ? 1 : 0;
    config.verbose = 0;

    if (gethostname(config.hostname, sizeof(config.hostname)) != 0) {
        snprintf(config.hostname, sizeof(config.hostname), "linux-agent");
    }

    static struct option long_options[] = {
        {"sentinel-url",   required_argument, 0, 'u'},
        {"enroll-token",   required_argument, 0, 1001},
        {"token-file",     required_argument, 0, 1002},
        {"ca-file",        required_argument, 0, 1003},
        {"insecure-http",  no_argument,       0, 1004},
        {"auto-kill",      no_argument,       0, 'a'},
        {"verbose",        no_argument,       0, 'v'},
        {"help",           no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "u:avh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'u':
                snprintf(config.sentinel_url, sizeof(config.sentinel_url), "%s", optarg);
                break;
            case 1001:
                snprintf(config.enroll_token, sizeof(config.enroll_token), "%s", optarg);
                break;
            case 1002:
                snprintf(config.token_file, sizeof(config.token_file), "%s", optarg);
                break;
            case 1003:
                snprintf(config.ca_file, sizeof(config.ca_file), "%s", optarg);
                break;
            case 1004:
                config.insecure_http = 1;
                break;
            case 'a':
                config.auto_kill = 1;
                break;
            case 'v':
                config.verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Initialize identity */
    if (identity_init(&global_identity, config.token_file) != 0) {
        fprintf(stderr, "[-] Failed to initialize agent identity\n");
    }

    /* Enrollment if token missing */
    if (global_identity.token[0] == '\0') {
        if (config.enroll_token[0] != '\0') {
            printf("[+] Initiating agent enrollment with Sentinel at %s...\n", config.sentinel_url);
            if (identity_enroll(&global_identity, config.sentinel_url, config.enroll_token,
                                config.ca_file, config.insecure_http) != 0) {
                fprintf(stderr, "[!] Warning: Initial enrollment failed, will retry in background\n");
            } else {
                printf("[+] Enrolled successfully as Agent ID: %s\n", global_identity.agent_id);
            }
        } else {
            fprintf(stderr, "[!] Warning: No existing token and --enroll-token not specified\n");
        }
    } else {
        printf("[+] Loaded existing agent token from %s (Agent ID: %s)\n",
               global_identity.token_path, global_identity.agent_id);
    }

    /* Initialize HTTP Exporter */
    struct exporter_config exp_cfg;
    memset(&exp_cfg, 0, sizeof(exp_cfg));
    snprintf(exp_cfg.sentinel_url, sizeof(exp_cfg.sentinel_url), "%s", config.sentinel_url);
    snprintf(exp_cfg.enroll_token, sizeof(exp_cfg.enroll_token), "%s", config.enroll_token);
    snprintf(exp_cfg.ca_file, sizeof(exp_cfg.ca_file), "%s", config.ca_file);
    exp_cfg.insecure_http = config.insecure_http;
    exp_cfg.verbose = config.verbose;

    global_exporter = exporter_create(&exp_cfg, &global_identity);
    if (!global_exporter) {
        fprintf(stderr, "[-] Failed to initialize HTTP exporter\n");
        return 1;
    }
    if (exporter_start(global_exporter) != 0) {
        fprintf(stderr, "[-] Failed to start HTTP exporter background thread\n");
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    /* Open BPF skeleton */
    skel = proc_exec_bpf__open();
    if (!skel) {
        fprintf(stderr, "[-] Failed to open BPF skeleton\n");
        err = 1;
        goto cleanup;
    }
    global_skel = skel;

    /* Set agent_tgid in .rodata to filter out the agent's own traffic (prevents self-loop) */
    skel->rodata->agent_tgid = (uint32_t)getpid();

    /* Disable readline probe if /bin/bash is missing */
    if (access("/bin/bash", F_OK) != 0) {
        if (config.verbose) {
            printf("[!] /bin/bash not found; disabling optional bash readline probe.\n");
        }
        bpf_program__set_autoload(skel->progs.handle_bash_readline, false);
    }

    /* Load and verify BPF programs */
    err = proc_exec_bpf__load(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    populate_noise_filter_map(skel);

    err = attach_bpf_programs(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to attach BPF hooks: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "[-] Failed to initialize ring buffer\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("=================================================================================\n");
    printf("%s[+] Cerberus EDR Agent & HTTP Exporter ACTIVE%s\n", COLOR_GREEN, COLOR_RESET);
    printf("    Sentinel URL     : %s\n", config.sentinel_url);
    printf("    Agent ID         : %s\n", global_identity.agent_id);
    printf("    Host Identifier  : %s\n", global_identity.hostname);
    printf("    Kernel Version   : %s\n", global_identity.kernel);
    printf("    Autonomous Kill  : %s\n", config.auto_kill ? "ENABLED (CRITICAL threats auto-killed)" : "DISABLED");
    printf("    Interfaces       : %d monitored\n", global_identity.interface_count);
    printf("=================================================================================\n");

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err == -EINTR) continue;
        if (err < 0) {
            fprintf(stderr, "[!] Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    printf("\n%s[+] Shutting down Cerberus Agent...%s\n", COLOR_YELLOW, COLOR_RESET);
    stop = 1;

    if (global_exporter) {
        exporter_stop(global_exporter);
        global_exporter = NULL;
    }

    if (rb) {
        ring_buffer__free(rb);
    }
    if (skel) {
        proc_exec_bpf__destroy(skel);
    }

    printf("%s[+] Shutdown complete. Processed: %llu events | Detected: %llu alerts.%s\n",
           COLOR_GREEN, total_events_processed, total_alerts_detected, COLOR_RESET);

    return err < 0 ? -err : 0;
}