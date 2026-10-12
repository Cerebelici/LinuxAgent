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
#include "proc_exec.skel.h"

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

/* Default SIEM Destination */
#define DEFAULT_SIEM_HOST "sentinel-defence"
#define DEFAULT_SIEM_PORT "9999"

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
    char description[256];
};

/* Agent Configuration */
struct agent_config {
    char siem_host[256];
    char siem_port[16];
    int auto_kill;               /* Autonomous kill switch for CRITICAL threats */
    int verbose;
    char hostname[128];
};

/* Process node for full process tree and service inspection */
struct proc_node {
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    char comm[TASK_COMM_LEN];
    char state;
    char exe[PATH_LEN];
    char cmdline[512];
    char version[128];
    int depth;
    int is_service;
    const char *reputation;      /* "GOOD", "SUSPICIOUS", "BAD" */
    char assessment[256];
};

static struct agent_config config;
static volatile sig_atomic_t stop = 0;
static int siem_sockfd = -1;
static pthread_mutex_t socket_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long total_events_processed = 0;
static unsigned long long total_alerts_detected = 0;
static time_t agent_start_time = 0;

/* BPF skeleton handle */
static struct proc_exec_bpf *global_skel = NULL;

/* Thread-safe Circular Event Queue between BPF poller and SIEM sender */
#define QUEUE_CAPACITY 2048
#define MAX_PAYLOAD_SIZE 2048

struct event_queue {
    char payloads[QUEUE_CAPACITY][MAX_PAYLOAD_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
};

static struct event_queue siem_queue;
static pthread_t network_tid;

/* Default noise binaries to filter out */
static const char *const NOISE_COMM_LIST[] = {
    "ls", "cat", "sed", "grep", "awk", "sleep", "which",
    "head", "tail", "cut", "tr", "wc", "sort", "uniq",
    "date", "uname", "clear", "reset", "basename", "dirname",
    "true", "false", "expr", "touch", "id", "groups",
    "dircolors", "stty", "tput", "uptime", "hostname", "locale",
    NULL
};

/* Forward declarations */
static void send_siem_direct(const char *buf);
static void report_process_tree_to_siem(void);
static void report_services_to_siem(void);

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
    stop = 1;
}

/* Helper: Escape JSON string safely */
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
        } else if (c == '\n') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\'; dst[j++] = 'n';
        } else if (c == '\r') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\'; dst[j++] = 'r';
        } else if (c == '\t') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\'; dst[j++] = 't';
        } else if (c < 32) {
            dst[j++] = ' ';
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
    snprintf(buf, buf_len, "%s.%03ldZ", tmp, ts.tv_nsec / 1000000);
}

/* Helper: Extract string value from simple JSON */
static int json_get_string(const char *json, const char *key, char *out, size_t out_len)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p += strlen(search);
    while (*p && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    if (*p != '\"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '\"' && i < out_len - 1) {
        if (*p == '\\' && *(p + 1)) p++;
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 0;
}

/* Helper: Extract integer value from simple JSON */
static int json_get_int(const char *json, const char *key, int *out)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p += strlen(search);
    while (*p && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    if (!*p) return -1;
    *out = atoi(p);
    return 0;
}

/* Check if comm matches useless noise utilities */
static int is_noise_comm(const char *c)
{
    for (int i = 0; NOISE_COMM_LIST[i] != NULL; i++) {
        if (strcmp(c, NOISE_COMM_LIST[i]) == 0)
            return 1;
    }
    return 0;
}

/* Check if typed bash command is benign noise vs sensitive/suspicious */
static int is_noise_bash_cmd(const char *cmd)
{
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    if (!*cmd) return 1;

    /* Suspicious indicators in command line: do NOT filter */
    static const char *const SUSPICIOUS_TOKENS[] = {
        "/dev/tcp", "/dev/udp", "bash -i", "sh -i", "nc ", "ncat ", "netcat ",
        "socat ", "curl ", "wget ", "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        "/etc/ld.so", ".ssh", "history -c", "rm -rf /var/log", "shred ",
        "chmod 777", "chmod +s", "chown root", "memfd", "python -c", "perl -e",
        "pkexec", "sudo", "base64 -d", NULL
    };

    for (int i = 0; SUSPICIOUS_TOKENS[i] != NULL; i++) {
        if (strstr(cmd, SUSPICIOUS_TOKENS[i]) != NULL) {
            return 0; /* Important security context! */
        }
    }

    /* Extract initial binary/command word */
    char word[64];
    size_t i = 0;
    while (cmd[i] && !isspace((unsigned char)cmd[i]) && i < sizeof(word) - 1) {
        word[i] = cmd[i];
        i++;
    }
    word[i] = '\0';

    /* If it is a benign utility without sensitive arguments, drop as noise */
    if (is_noise_comm(word)) return 1;
    if (strcmp(word, "pwd") == 0 || strcmp(word, "cd") == 0 ||
        strcmp(word, "echo") == 0 || strcmp(word, "man") == 0) return 1;

    return 0;
}

/* Populate the in-kernel noise filtering eBPF map */
static void populate_noise_filter_map(struct proc_exec_bpf *skel)
{
    if (!skel || !skel->maps.noise_comms) return;
    int map_fd = bpf_map__fd(skel->maps.noise_comms);
    if (map_fd < 0) return;

    for (int i = 0; NOISE_COMM_LIST[i] != NULL; i++) {
        char key[TASK_COMM_LEN] = {0};
        strncpy(key, NOISE_COMM_LIST[i], sizeof(key) - 1);
        uint8_t val = 1;
        bpf_map_update_elem(map_fd, key, &val, BPF_ANY);
    }
    if (config.verbose) {
        printf("[+] Kernel noise filter populated with standard utility list.\n");
    }
}

/* EDR Threat Detection Engine: Analyzes telemetry in real-time */
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
                out->mitre_technique = "T1055: Process Injection";
                snprintf(out->description, sizeof(out->description),
                         "Process memory write detected into target PID %u", e->data.injection.target_pid);
            } else {
                out->rule_name = "PTRACE_PROCESS_INJECTION";
                out->mitre_technique = "T1055.008: Ptrace Injection";
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
            out->mitre_technique = "T1014: Rootkit / Kernel Module";
            snprintf(out->description, sizeof(out->description),
                     "Kernel module insertion attempt by %s (args: %s)", e->comm, e->data.filename);
            break;

        case EVENT_TYPE_FILE_TAMPER:
            out->is_threat = 1;
            out->mitre_tactic = "Defense Evasion";
            if (strstr(e->data.filename, "shadow") || strstr(e->data.filename, "passwd")) {
                out->severity = "CRITICAL";
                out->rule_name = "SHADOW_CREDENTIAL_TAMPER";
                out->mitre_technique = "T1003.008: /etc/passwd and /etc/shadow";
                snprintf(out->description, sizeof(out->description),
                         "Tampering with sensitive credential file: %s", e->data.filename);
            } else if (strstr(e->data.filename, "ld.so.preload")) {
                out->severity = "CRITICAL";
                out->rule_name = "PRELOAD_ROOTKIT_PERSISTENCE";
                out->mitre_technique = "T1574.006: LD_PRELOAD Hijack";
                snprintf(out->description, sizeof(out->description),
                         "Rootkit persistence attempt modifying /etc/ld.so.preload");
            } else if (strstr(e->data.filename, "sudoers")) {
                out->severity = "HIGH";
                out->rule_name = "SUDOERS_PRIVILEGE_TAMPER";
                out->mitre_technique = "T1548.003: Sudoers Modification";
                snprintf(out->description, sizeof(out->description),
                         "Privilege configuration tampered: %s", e->data.filename);
            } else if (strstr(e->data.filename, "cron")) {
                out->severity = "HIGH";
                out->rule_name = "CRON_PERSISTENCE_TAMPER";
                out->mitre_technique = "T1053.003: Scheduled Task / Cron";
                snprintf(out->description, sizeof(out->description),
                         "Scheduled job tampered: %s", e->data.filename);
            } else if (strstr(e->data.filename, "authorized_keys")) {
                out->severity = "HIGH";
                out->rule_name = "SSH_BACKDOOR_KEY_MODIFICATION";
                out->mitre_technique = "T1098.004: SSH Authorized Keys";
                snprintf(out->description, sizeof(out->description),
                         "SSH backdoor key tampering detected: %s", e->data.filename);
            } else {
                out->severity = "MEDIUM";
                out->rule_name = "SYSTEM_CONFIG_TAMPER";
                out->mitre_technique = "T1565: Data Manipulation";
                snprintf(out->description, sizeof(out->description),
                         "System config file write: %s", e->data.filename);
            }
            break;

        case EVENT_TYPE_PRIV_ESC:
            out->is_threat = 1;
            out->severity = "HIGH";
            out->rule_name = "UNAUTHORIZED_ROOT_ESCALATION";
            out->mitre_tactic = "Privilege Escalation";
            out->mitre_technique = "T1548: Abuse Elevation Control Mechanism";
            snprintf(out->description, sizeof(out->description),
                     "Process %s (UID %u) attempted escalation to root UID 0", e->comm, e->data.priv_esc.old_uid);
            break;

        case EVENT_TYPE_MEMFD_EXEC:
            out->is_threat = 1;
            out->severity = "HIGH";
            out->rule_name = "FILELESS_MEMFD_EXECUTION";
            out->mitre_tactic = "Defense Evasion";
            out->mitre_technique = "T1620: Reflective Code Loading";
            snprintf(out->description, sizeof(out->description),
                     "Anonymous in-memory execution via memfd_create (%s)", e->data.filename);
            break;

        case EVENT_TYPE_CONNECT: {
            /* Check if a shell or scripting language is initiating outbound connections */
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
                out->mitre_technique = "T1059.004: Interactive Shell Network Connection";
                snprintf(out->description, sizeof(out->description),
                         "Shell/interpreter %s spawned outbound network connection to port %d",
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
                out->mitre_technique = "T1059.004: Reverse Shell Command";
                snprintf(out->description, sizeof(out->description), "Reverse shell pattern in typed command");
            } else if (strstr(cmd, "history -c") || strstr(cmd, "rm -rf /var/log") ||
                       strstr(cmd, "shred ") || strstr(cmd, "set +o history")) {
                out->is_threat = 1;
                out->severity = "HIGH";
                out->rule_name = "DEFENSE_EVASION_INDICATOR_REMOVAL";
                out->mitre_tactic = "Defense Evasion";
                out->mitre_technique = "T1070.003: Clear Command History / Logs";
                snprintf(out->description, sizeof(out->description), "Anti-forensics indicator removal detected");
            } else if (strstr(cmd, "/etc/shadow") || strstr(cmd, "/etc/passwd")) {
                out->is_threat = 1;
                out->severity = "HIGH";
                out->rule_name = "CREDENTIAL_RECONNAISSANCE";
                out->mitre_tactic = "Credential Access";
                out->mitre_technique = "T1003.008: Credential Dumping";
                snprintf(out->description, sizeof(out->description), "Direct inspection of credential files");
            }
            break;
        }

        case EVENT_TYPE_EXEC: {
            /* Detect hacking tools or shells spawned under web server */
            static const char *const SUSPICIOUS_TOOLS[] = {
                "mimikatz", "linpeas", "chisel", "nmap", "masscan",
                "socat", "hydra", "john", "sqlmap", "cve", NULL
            };
            for (int i = 0; SUSPICIOUS_TOOLS[i] != NULL; i++) {
                if (strstr(e->comm, SUSPICIOUS_TOOLS[i]) || strstr(e->data.filename, SUSPICIOUS_TOOLS[i])) {
                    out->is_threat = 1;
                    out->severity = "HIGH";
                    out->rule_name = "SUSPICIOUS_SECURITY_TOOL_EXEC";
                    out->mitre_tactic = "Execution";
                    out->mitre_technique = "T1059: Command and Scripting";
                    snprintf(out->description, sizeof(out->description), "Known exploit or scanning tool executed: %s", e->comm);
                    break;
                }
            }
            /* Web server user (www-data / uid 33) spawning shells */
            if (e->uid == 33 && (strcmp(e->comm, "sh") == 0 || strcmp(e->comm, "bash") == 0)) {
                out->is_threat = 1;
                out->severity = "CRITICAL";
                out->rule_name = "WEBSHELL_INTERACTIVE_EXECUTION";
                out->mitre_tactic = "Persistence";
                out->mitre_technique = "T1505.003: Web Shell";
                snprintf(out->description, sizeof(out->description), "Web server daemon spawned interactive shell");
            }
            break;
        }
    }
}

/* ========================================================================= */
/* PROCESS & SERVICE REPUTATION / VERSION DETECTION ENGINE                  */
/* ========================================================================= */

/* Assess process / service safety: classifies into GOOD, SUSPICIOUS, BAD */
static void evaluate_process_reputation(struct proc_node *p)
{
    /* 1. Kernel worker threads */
    if (p->pid == 2 || p->ppid == 2) {
        p->reputation = "GOOD";
        snprintf(p->assessment, sizeof(p->assessment), "Legitimate Linux kernel task");
        return;
    }

    /* 2. Malicious or volatile directories (CRITICAL BAD) */
    if (strncmp(p->exe, "/tmp/", 5) == 0 || strncmp(p->exe, "/var/tmp/", 9) == 0 ||
        strncmp(p->exe, "/dev/shm/", 9) == 0 || strncmp(p->exe, "/dev/", 5) == 0 ||
        strstr(p->exe, "(deleted)") != NULL) {
        p->reputation = "BAD";
        snprintf(p->assessment, sizeof(p->assessment), "CRITICAL: Binary executing from untrusted path or deleted from disk");
        return;
    }

    /* 3. Known malicious or offensive security tool binaries */
    static const char *const MALICIOUS_NAMES[] = {
        "xmrig", "minerd", "stratum", "chisel", "mimikatz", "linpeas",
        "masscan", "sqlmap", "hydra", "john", NULL
    };
    for (int i = 0; MALICIOUS_NAMES[i] != NULL; i++) {
        if (strstr(p->comm, MALICIOUS_NAMES[i]) || strstr(p->cmdline, MALICIOUS_NAMES[i])) {
            p->reputation = "BAD";
            snprintf(p->assessment, sizeof(p->assessment), "CRITICAL: Known malicious or offensive binary detected");
            return;
        }
    }

    /* 4. Masquerading check: kernel thread name in userspace */
    if (strncmp(p->comm, "kworker", 7) == 0 && p->ppid != 2 && strlen(p->exe) > 0) {
        p->reputation = "BAD";
        snprintf(p->assessment, sizeof(p->assessment), "CRITICAL: Userspace process masquerading as kernel thread");
        return;
    }

    /* 5. Suspicious network daemons or shell relays */
    if ((strcmp(p->comm, "nc") == 0 || strcmp(p->comm, "ncat") == 0 || strcmp(p->comm, "socat") == 0) &&
        (strstr(p->cmdline, "-e") || strstr(p->cmdline, "sh"))) {
        p->reputation = "BAD";
        snprintf(p->assessment, sizeof(p->assessment), "CRITICAL: Network relay spawning shell execution");
        return;
    }

    /* 6. Script interpreter running directly under init as service without wrapper */
    if ((strcmp(p->comm, "python") == 0 || strcmp(p->comm, "python3") == 0 ||
         strcmp(p->comm, "perl") == 0 || strcmp(p->comm, "ruby") == 0) && p->ppid == 1) {
        p->reputation = "SUSPICIOUS";
        snprintf(p->assessment, sizeof(p->assessment), "WARNING: Standalone scripting interpreter running directly under init");
        return;
    }

    /* 7. Root service executing from user home directory */
    if (p->uid == 0 && (strncmp(p->exe, "/home/", 6) == 0 || strncmp(p->exe, "/root/", 6) == 0)) {
        p->reputation = "SUSPICIOUS";
        snprintf(p->assessment, sizeof(p->assessment), "WARNING: Root privilege daemon running from user home directory");
        return;
    }

    /* 8. Standard Linux system directories */
    if (strncmp(p->exe, "/usr/sbin/", 10) == 0 || strncmp(p->exe, "/usr/bin/", 9) == 0 ||
        strncmp(p->exe, "/sbin/", 6) == 0 || strncmp(p->exe, "/bin/", 5) == 0 ||
        strncmp(p->exe, "/lib/", 5) == 0 || strncmp(p->exe, "/usr/lib/", 9) == 0) {
        p->reputation = "GOOD";
        snprintf(p->assessment, sizeof(p->assessment), "Standard system binary in verified directory");
        return;
    }

    p->reputation = "SUSPICIOUS";
    snprintf(p->assessment, sizeof(p->assessment), "Non-standard execution path or unverified binary");
}

/* Query version string of running service safely */
static void query_service_version(const char *comm, const char *exe, char *ver_buf, size_t ver_buf_len)
{
    ver_buf[0] = '\0';

    /* Refuse to execute untrusted binaries */
    if (strncmp(exe, "/tmp/", 5) == 0 || strncmp(exe, "/var/tmp/", 9) == 0 ||
        strncmp(exe, "/dev/shm/", 9) == 0 || strstr(exe, "(deleted)") != NULL) {
        snprintf(ver_buf, ver_buf_len, "Untrusted / Unverified");
        return;
    }

    char cmd[512] = {0};
    if (strstr(comm, "sshd") || strstr(exe, "sshd")) {
        snprintf(cmd, sizeof(cmd), "%s -V 2>&1", exe);
    } else if (strstr(comm, "nginx") || strstr(exe, "nginx")) {
        snprintf(cmd, sizeof(cmd), "%s -v 2>&1", exe);
    } else if (strstr(comm, "apache") || strstr(comm, "httpd") || strstr(exe, "apache2")) {
        snprintf(cmd, sizeof(cmd), "%s -v 2>&1", exe);
    } else if (strstr(comm, "systemd") || strstr(exe, "systemd")) {
        snprintf(cmd, sizeof(cmd), "systemctl --version 2>&1");
    } else if (strstr(comm, "docker") || strstr(exe, "dockerd")) {
        snprintf(cmd, sizeof(cmd), "dockerd --version 2>&1");
    } else if (strstr(comm, "containerd") || strstr(exe, "containerd")) {
        snprintf(cmd, sizeof(cmd), "containerd --version 2>&1");
    } else if (strstr(comm, "redis") || strstr(exe, "redis-server")) {
        snprintf(cmd, sizeof(cmd), "%s --version 2>&1", exe);
    } else if (strstr(comm, "postgres") || strstr(exe, "postgres")) {
        snprintf(cmd, sizeof(cmd), "%s --version 2>&1", exe);
    } else if (strstr(comm, "cron") || strstr(exe, "cron")) {
        snprintf(cmd, sizeof(cmd), "%s -V 2>&1", exe);
    } else if (strstr(comm, "rsyslog") || strstr(exe, "rsyslogd")) {
        snprintf(cmd, sizeof(cmd), "%s -v 2>&1", exe);
    } else if (strncmp(exe, "/usr/", 5) == 0 || strncmp(exe, "/bin/", 5) == 0 ||
               strncmp(exe, "/sbin/", 6) == 0) {
        snprintf(cmd, sizeof(cmd), "%s --version 2>&1", exe);
    }

    if (cmd[0] != '\0') {
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char line[256];
            if (fgets(line, sizeof(line), fp)) {
                size_t l = strlen(line);
                while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) {
                    line[--l] = '\0';
                }
                int has_digit = 0;
                for (size_t i = 0; i < l; i++) {
                    if (isdigit((unsigned char)line[i])) {
                        has_digit = 1;
                        break;
                    }
                }
                if (has_digit && l > 0) {
                    strncpy(ver_buf, line, ver_buf_len - 1);
                    ver_buf[ver_buf_len - 1] = '\0';
                }
            }
            pclose(fp);
        }
    }

    if (ver_buf[0] == '\0') {
        snprintf(ver_buf, ver_buf_len, "Installed");
    }
}

/* Collect and audit running processes across /proc */
static int collect_processes(struct proc_node **procs_out, int *count_out)
{
    *procs_out = NULL;
    *count_out = 0;

    DIR *dir = opendir("/proc");
    if (!dir) return -1;

    struct proc_node *procs = calloc(MAX_INVENTORY_PROCS, sizeof(struct proc_node));
    if (!procs) {
        closedir(dir);
        return -1;
    }

    int count = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL && count < MAX_INVENTORY_PROCS) {
        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        struct proc_node *p = &procs[count];
        p->pid = (pid_t)pid;
        p->ppid = 0;
        p->state = '?';
        p->reputation = "UNKNOWN";

        /* Read /proc/<pid>/stat for PPID and State */
        char path_buf[128];
        snprintf(path_buf, sizeof(path_buf), "/proc/%ld/stat", pid);
        FILE *f = fopen(path_buf, "r");
        if (f) {
            char buf[512];
            if (fgets(buf, sizeof(buf), f)) {
                char *close_paren = strrchr(buf, ')');
                if (close_paren) {
                    char st = '?';
                    long ppid = 0;
                    if (sscanf(close_paren + 1, " %c %ld", &st, &ppid) == 2) {
                        p->state = st;
                        p->ppid = (pid_t)ppid;
                    }
                }
            }
            fclose(f);
        }

        /* Read /proc/<pid>/comm */
        snprintf(path_buf, sizeof(path_buf), "/proc/%ld/comm", pid);
        f = fopen(path_buf, "r");
        if (f) {
            if (fgets(p->comm, sizeof(p->comm), f)) {
                size_t l = strlen(p->comm);
                if (l > 0 && p->comm[l - 1] == '\n') p->comm[l - 1] = '\0';
            }
            fclose(f);
        }

        /* Read /proc/<pid>/status for UID */
        snprintf(path_buf, sizeof(path_buf), "/proc/%ld/status", pid);
        f = fopen(path_buf, "r");
        if (f) {
            char line[128];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "Uid:", 4) == 0) {
                    unsigned int ruid = 0;
                    if (sscanf(line + 4, "%u", &ruid) == 1) {
                        p->uid = ruid;
                    }
                    break;
                }
            }
            fclose(f);
        }

        /* Read /proc/<pid>/exe symlink */
        snprintf(path_buf, sizeof(path_buf), "/proc/%ld/exe", pid);
        ssize_t link_len = readlink(path_buf, p->exe, sizeof(p->exe) - 1);
        if (link_len > 0) {
            p->exe[link_len] = '\0';
        } else {
            p->exe[0] = '\0';
        }

        /* Read /proc/<pid>/cmdline */
        snprintf(path_buf, sizeof(path_buf), "/proc/%ld/cmdline", pid);
        int fd = open(path_buf, O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, p->cmdline, sizeof(p->cmdline) - 1);
            if (n > 0) {
                p->cmdline[n] = '\0';
                for (ssize_t i = 0; i < n - 1; i++) {
                    if (p->cmdline[i] == '\0') p->cmdline[i] = ' ';
                }
            } else {
                p->cmdline[0] = '\0';
            }
            close(fd);
        }

        /* Identify if process is a service */
        p->is_service = 0;
        if (p->ppid == 1 && p->pid != 1) {
            p->is_service = 1;
        } else {
            static const char *const DAEMON_NAMES[] = {
                "systemd", "sshd", "cron", "nginx", "apache2", "httpd", "dockerd",
                "containerd", "redis-server", "mysqld", "postgres", "systemd-journald",
                "systemd-resolved", "systemd-networkd", "systemd-udevd", "rsyslogd",
                "dbus-daemon", "polkitd", "chronyd", "auditd", "ufw", "fail2ban",
                "named", "dnsmasq", "smbd", "cupsd", NULL
            };
            for (int k = 0; DAEMON_NAMES[k] != NULL; k++) {
                if (strstr(p->comm, DAEMON_NAMES[k]) != NULL) {
                    p->is_service = 1;
                    break;
                }
            }
        }

        if (p->is_service) {
            query_service_version(p->comm, p->exe, p->version, sizeof(p->version));
        } else {
            p->version[0] = '\0';
        }

        /* Evaluate reputation */
        evaluate_process_reputation(p);

        count++;
    }

    closedir(dir);

    /* Compute tree depth hierarchy */
    for (int i = 0; i < count; i++) {
        int d = 0;
        pid_t curr_ppid = procs[i].ppid;
        int loop_guard = 0;
        while (curr_ppid > 0 && loop_guard < 16) {
            int found_parent = 0;
            for (int j = 0; j < count; j++) {
                if (procs[j].pid == curr_ppid) {
                    d++;
                    curr_ppid = procs[j].ppid;
                    found_parent = 1;
                    break;
                }
            }
            if (!found_parent) break;
            loop_guard++;
        }
        procs[i].depth = d;
    }

    *procs_out = procs;
    *count_out = count;
    return 0;
}

/* Audit and stream full process tree with good/bad evaluations to SIEM */
static void report_process_tree_to_siem(void)
{
    struct proc_node *procs = NULL;
    int count = 0;
    if (collect_processes(&procs, &count) != 0 || count == 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg),
                 "{\"type\":\"ACTION_RESULT\",\"action\":\"process_tree\",\"status\":\"FAILED\","
                 "\"message\":\"Could not inspect /proc\",\"agent_id\":\"%s\"}\n", config.hostname);
        send_siem_direct(err_msg);
        return;
    }

    int good_count = 0, susp_count = 0, bad_count = 0;
    for (int i = 0; i < count; i++) {
        if (strcmp(procs[i].reputation, "GOOD") == 0) good_count++;
        else if (strcmp(procs[i].reputation, "BAD") == 0) bad_count++;
        else susp_count++;
    }

    char now_str[64];
    get_iso8601_time(now_str, sizeof(now_str));

    printf("\n%s=================================================================================%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s[🌳 PROCESS TREE AUDIT] Total: %d | Good: %s%d%s | Suspicious: %s%d%s | Bad: %s%d%s%s\n",
           COLOR_BOLD, count, COLOR_GREEN, good_count, COLOR_BOLD,
           COLOR_YELLOW, susp_count, COLOR_BOLD,
           COLOR_RED, bad_count, COLOR_BOLD, COLOR_RESET);
    printf("%s=================================================================================%s\n", COLOR_CYAN, COLOR_RESET);

    /* 1. Transmit header */
    char header[512];
    snprintf(header, sizeof(header),
             "{\"type\":\"PROCESS_TREE_HEADER\",\"agent_id\":\"%s\",\"total\":%d,\"good\":%d,"
             "\"suspicious\":%d,\"bad\":%d,\"timestamp\":\"%s\"}\n",
             config.hostname, count, good_count, susp_count, bad_count, now_str);
    send_siem_direct(header);

    /* 2. Stream all nodes */
    for (int i = 0; i < count; i++) {
        struct proc_node *p = &procs[i];

        char esc_comm[32], esc_exe[512], esc_cmd[1024], esc_assess[512], esc_ver[128];
        json_escape(p->comm, esc_comm, sizeof(esc_comm));
        json_escape(p->exe, esc_exe, sizeof(esc_exe));
        json_escape(p->cmdline, esc_cmd, sizeof(esc_cmd));
        json_escape(p->assessment, esc_assess, sizeof(esc_assess));
        json_escape(p->version, esc_ver, sizeof(esc_ver));

        char node[2048];
        snprintf(node, sizeof(node),
                 "{\"type\":\"PROCESS_TREE_NODE\",\"depth\":%d,\"pid\":%d,\"ppid\":%d,\"uid\":%u,"
                 "\"comm\":\"%s\",\"state\":\"%c\",\"exe\":\"%s\",\"cmdline\":\"%s\",\"reputation\":\"%s\","
                 "\"assessment\":\"%s\",\"version\":\"%s\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                 p->depth, p->pid, p->ppid, p->uid, esc_comm, p->state, esc_exe, esc_cmd,
                 p->reputation, esc_assess, esc_ver, config.hostname, now_str);
        send_siem_direct(node);

        /* Console visualization */
        const char *rep_color = COLOR_GREEN;
        if (strcmp(p->reputation, "BAD") == 0) rep_color = COLOR_RED;
        else if (strcmp(p->reputation, "SUSPICIOUS") == 0) rep_color = COLOR_YELLOW;

        if (strcmp(p->reputation, "BAD") == 0 || strcmp(p->reputation, "SUSPICIOUS") == 0 || p->depth <= 1) {
            for (int k = 0; k < p->depth; k++) printf("  ");
            printf("%sPID %-5d (PPID %-5d) [%s]: %s%s %s\n",
                   rep_color, p->pid, p->ppid, p->reputation, p->comm,
                   strlen(p->version) > 0 ? p->version : "", COLOR_RESET);
            if (strcmp(p->reputation, "BAD") == 0 || strcmp(p->reputation, "SUSPICIOUS") == 0) {
                for (int k = 0; k < p->depth; k++) printf("  ");
                printf("  %s↳ %s (Exe: %s)%s\n", rep_color, p->assessment, p->exe, COLOR_RESET);
            }
        }
    }

    /* 3. Transmit completion */
    char complete[512];
    snprintf(complete, sizeof(complete),
             "{\"type\":\"PROCESS_TREE_COMPLETE\",\"total\":%d,\"good\":%d,\"suspicious\":%d,\"bad\":%d,"
             "\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
             count, good_count, susp_count, bad_count, config.hostname, now_str);
    send_siem_direct(complete);

    free(procs);
}

/* Audit and stream all running services, versions, and security status to SIEM */
static void report_services_to_siem(void)
{
    struct proc_node *procs = NULL;
    int count = 0;
    if (collect_processes(&procs, &count) != 0 || count == 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg),
                 "{\"type\":\"ACTION_RESULT\",\"action\":\"services\",\"status\":\"FAILED\","
                 "\"message\":\"Could not inspect services in /proc\",\"agent_id\":\"%s\"}\n", config.hostname);
        send_siem_direct(err_msg);
        return;
    }

    int total_services = 0, good_srv = 0, susp_srv = 0, bad_srv = 0;
    for (int i = 0; i < count; i++) {
        if (!procs[i].is_service) continue;
        total_services++;
        if (strcmp(procs[i].reputation, "GOOD") == 0) good_srv++;
        else if (strcmp(procs[i].reputation, "BAD") == 0) bad_srv++;
        else susp_srv++;
    }

    char now_str[64];
    get_iso8601_time(now_str, sizeof(now_str));

    printf("\n%s=================================================================================%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s[⚙️  RUNNING SERVICES INVENTORY] Total: %d | Good: %s%d%s | Suspicious: %s%d%s | Bad: %s%d%s%s\n",
           COLOR_BOLD, total_services, COLOR_GREEN, good_srv, COLOR_BOLD,
           COLOR_YELLOW, susp_srv, COLOR_BOLD,
           COLOR_RED, bad_srv, COLOR_BOLD, COLOR_RESET);
    printf("%s=================================================================================%s\n", COLOR_CYAN, COLOR_RESET);

    /* 1. Transmit header */
    char header[512];
    snprintf(header, sizeof(header),
             "{\"type\":\"SERVICES_INVENTORY_HEADER\",\"agent_id\":\"%s\",\"total_services\":%d,"
             "\"good\":%d,\"suspicious\":%d,\"bad\":%d,\"timestamp\":\"%s\"}\n",
             config.hostname, total_services, good_srv, susp_srv, bad_srv, now_str);
    send_siem_direct(header);

    /* 2. Stream all service entries */
    for (int i = 0; i < count; i++) {
        struct proc_node *p = &procs[i];
        if (!p->is_service) continue;

        char esc_comm[32], esc_exe[512], esc_ver[128], esc_assess[512];
        json_escape(p->comm, esc_comm, sizeof(esc_comm));
        json_escape(p->exe, esc_exe, sizeof(esc_exe));
        json_escape(p->version, esc_ver, sizeof(esc_ver));
        json_escape(p->assessment, esc_assess, sizeof(esc_assess));

        char entry[2048];
        snprintf(entry, sizeof(entry),
                 "{\"type\":\"SERVICE_ENTRY\",\"name\":\"%s\",\"pid\":%d,\"uid\":%u,\"exe\":\"%s\","
                 "\"version\":\"%s\",\"reputation\":\"%s\",\"assessment\":\"%s\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                 esc_comm, p->pid, p->uid, esc_exe, esc_ver, p->reputation, esc_assess,
                 config.hostname, now_str);
        send_siem_direct(entry);

        const char *color = COLOR_GREEN;
        if (strcmp(p->reputation, "BAD") == 0) color = COLOR_RED;
        else if (strcmp(p->reputation, "SUSPICIOUS") == 0) color = COLOR_YELLOW;

        printf("  %s%-16s%s | PID: %-5d | Version: %-25s | Status: %s%-10s%s | %s\n",
               COLOR_BOLD, p->comm, COLOR_RESET, p->pid,
               strlen(p->version) > 0 ? p->version : "Installed",
               color, p->reputation, COLOR_RESET, p->assessment);
    }

    /* 3. Transmit completion */
    char complete[512];
    snprintf(complete, sizeof(complete),
             "{\"type\":\"SERVICES_INVENTORY_COMPLETE\",\"total_services\":%d,\"good\":%d,"
             "\"suspicious\":%d,\"bad\":%d,\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
             total_services, good_srv, susp_srv, bad_srv, config.hostname, now_str);
    send_siem_direct(complete);

    free(procs);
}

/* ========================================================================= */
/* KILL SWITCH ENGINE                                                        */
/* ========================================================================= */

/* Recursively kill process and its child processes */
static int kill_process_tree(pid_t target_pid, int sig)
{
    if (target_pid <= 1 || target_pid == getpid()) {
        fprintf(stderr, "%s[!] Safety check: Refusing to kill protected PID %d%s\n",
                COLOR_YELLOW, target_pid, COLOR_RESET);
        return -1;
    }

    /* Iterate /proc to find and kill all descendant child processes */
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
                                printf("%s[⚡ KILL SWITCH] Terminating child PID %ld of parent %d%s\n",
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

    /* Send signal to target process */
    int res = kill(target_pid, sig);
    if (res == 0) {
        printf("%s[⚡ KILL SWITCH] Successfully sent signal %d to PID %d%s\n",
               COLOR_GREEN, sig, target_pid, COLOR_RESET);
        return 0;
    } else {
        fprintf(stderr, "%s[!] Kill failed for PID %d: %s%s\n",
                COLOR_RED, target_pid, strerror(errno), COLOR_RESET);
        return -errno;
    }
}

/* Terminate all running processes matching binary name */
static int kill_processes_by_comm(const char *target_comm, int sig)
{
    int killed = 0;
    DIR *dir = opendir("/proc");
    if (!dir) return 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 1 || pid == getpid())
            continue;

        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%ld/comm", pid);
        FILE *f = fopen(comm_path, "r");
        if (f) {
            char proc_comm[32] = {0};
            if (fgets(proc_comm, sizeof(proc_comm), f)) {
                size_t len = strlen(proc_comm);
                if (len > 0 && proc_comm[len - 1] == '\n') proc_comm[len - 1] = '\0';
                if (strcmp(proc_comm, target_comm) == 0) {
                    printf("%s[⚡ KILL SWITCH] Terminating blocked instance PID %ld (%s)%s\n",
                           COLOR_MAGENTA, pid, target_comm, COLOR_RESET);
                    kill_process_tree((pid_t)pid, sig);
                    killed++;
                }
            }
            fclose(f);
        }
    }
    closedir(dir);
    return killed;
}

/* Enqueue payload for transmission to SIEM */
static void enqueue_siem_payload(const char *payload)
{
    pthread_mutex_lock(&siem_queue.lock);
    if (siem_queue.count >= QUEUE_CAPACITY) {
        /* Drop oldest non-critical event if queue is saturated */
        siem_queue.head = (siem_queue.head + 1) % QUEUE_CAPACITY;
        siem_queue.count--;
    }
    strncpy(siem_queue.payloads[siem_queue.tail], payload, MAX_PAYLOAD_SIZE - 1);
    siem_queue.payloads[siem_queue.tail][MAX_PAYLOAD_SIZE - 1] = '\0';
    siem_queue.tail = (siem_queue.tail + 1) % QUEUE_CAPACITY;
    siem_queue.count++;
    pthread_cond_signal(&siem_queue.not_empty);
    pthread_mutex_unlock(&siem_queue.lock);
}

/* Send direct high-priority response to SIEM */
static void send_siem_direct(const char *buf)
{
    pthread_mutex_lock(&socket_lock);
    if (siem_sockfd >= 0) {
        size_t len = strlen(buf);
        size_t sent_total = 0;
        while (sent_total < len) {
            ssize_t n = send(siem_sockfd, buf + sent_total, len - sent_total, MSG_NOSIGNAL);
            if (n <= 0) break;
            sent_total += n;
        }
    }
    pthread_mutex_unlock(&socket_lock);
}

/* Execute command instructed by SIEM and report action result */
static void process_siem_command(const char *cmd_line)
{
    char action[64] = {0};
    char comm[64] = {0};
    int target_pid = -1;
    int sig = SIGKILL;
    char response[1024];
    char now_str[64];
    get_iso8601_time(now_str, sizeof(now_str));

    /* Parse JSON action command */
    if (json_get_string(cmd_line, "action", action, sizeof(action)) != 0) {
        /* Support simple text fallback */
        if (sscanf(cmd_line, "KILL %d", &target_pid) == 1) {
            strncpy(action, "kill", sizeof(action) - 1);
        } else if (strcmp(cmd_line, "PING") == 0) {
            strncpy(action, "ping", sizeof(action) - 1);
        } else if (strcmp(cmd_line, "PROCESS_TREE") == 0 || strcmp(cmd_line, "PS_TREE") == 0 || strcmp(cmd_line, "TREE") == 0) {
            strncpy(action, "process_tree", sizeof(action) - 1);
        } else if (strcmp(cmd_line, "SERVICES") == 0) {
            strncpy(action, "services", sizeof(action) - 1);
        } else if (strcmp(cmd_line, "INVENTORY") == 0 || strcmp(cmd_line, "AUDIT") == 0 || strcmp(cmd_line, "SCAN") == 0) {
            strncpy(action, "inventory", sizeof(action) - 1);
        } else {
            fprintf(stderr, "[!] Unrecognized SIEM command: %s\n", cmd_line);
            return;
        }
    }

    json_get_int(cmd_line, "pid", &target_pid);
    json_get_int(cmd_line, "signal", &sig);
    json_get_string(cmd_line, "comm", comm, sizeof(comm));

    printf("%s[⚡ SIEM ACTION RECEIVED] Action='%s' | PID=%d | Comm='%s'%s\n",
           COLOR_MAGENTA, action, target_pid, comm, COLOR_RESET);

    if (strcmp(action, "kill") == 0 || strcmp(action, "terminate") == 0) {
        if (target_pid <= 1) {
            snprintf(response, sizeof(response),
                     "{\"type\":\"ACTION_RESULT\",\"action\":\"kill\",\"target_pid\":%d,\"status\":\"FAILED\","
                     "\"message\":\"Invalid or protected PID\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                     target_pid, config.hostname, now_str);
        } else {
            int ret = kill_process_tree((pid_t)target_pid, sig);
            if (ret == 0) {
                snprintf(response, sizeof(response),
                         "{\"type\":\"ACTION_RESULT\",\"action\":\"kill\",\"target_pid\":%d,\"status\":\"SUCCESS\","
                         "\"signal\":%d,\"message\":\"Process tree terminated successfully\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                         target_pid, sig, config.hostname, now_str);
            } else {
                snprintf(response, sizeof(response),
                         "{\"type\":\"ACTION_RESULT\",\"action\":\"kill\",\"target_pid\":%d,\"status\":\"FAILED\","
                         "\"error\":\"%s\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                         target_pid, strerror(-ret), config.hostname, now_str);
            }
        }
        send_siem_direct(response);

    } else if (strcmp(action, "suspend") == 0) {
        int ret = kill((pid_t)target_pid, SIGSTOP);
        snprintf(response, sizeof(response),
                 "{\"type\":\"ACTION_RESULT\",\"action\":\"suspend\",\"target_pid\":%d,\"status\":\"%s\","
                 "\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                 target_pid, ret == 0 ? "SUCCESS" : "FAILED", config.hostname, now_str);
        send_siem_direct(response);

    } else if (strcmp(action, "resume") == 0) {
        int ret = kill((pid_t)target_pid, SIGCONT);
        snprintf(response, sizeof(response),
                 "{\"type\":\"ACTION_RESULT\",\"action\":\"resume\",\"target_pid\":%d,\"status\":\"%s\","
                 "\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                 target_pid, ret == 0 ? "SUCCESS" : "FAILED", config.hostname, now_str);
        send_siem_direct(response);

    } else if (strcmp(action, "block_comm") == 0) {
        if (strlen(comm) > 0 && global_skel && global_skel->maps.blocked_comms) {
            char key[TASK_COMM_LEN] = {0};
            strncpy(key, comm, sizeof(key) - 1);
            uint8_t val = 1;
            bpf_map_update_elem(bpf_map__fd(global_skel->maps.blocked_comms), key, &val, BPF_ANY);
            int killed = kill_processes_by_comm(comm, SIGKILL);
            snprintf(response, sizeof(response),
                     "{\"type\":\"ACTION_RESULT\",\"action\":\"block_comm\",\"comm\":\"%s\",\"status\":\"SUCCESS\","
                     "\"killed_instances\":%d,\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                     comm, killed, config.hostname, now_str);
        } else {
            snprintf(response, sizeof(response),
                     "{\"type\":\"ACTION_RESULT\",\"action\":\"block_comm\",\"status\":\"FAILED\","
                     "\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                     config.hostname, now_str);
        }
        send_siem_direct(response);

    } else if (strcmp(action, "unblock_comm") == 0) {
        if (strlen(comm) > 0 && global_skel && global_skel->maps.blocked_comms) {
            char key[TASK_COMM_LEN] = {0};
            strncpy(key, comm, sizeof(key) - 1);
            bpf_map_delete_elem(bpf_map__fd(global_skel->maps.blocked_comms), key);
            snprintf(response, sizeof(response),
                     "{\"type\":\"ACTION_RESULT\",\"action\":\"unblock_comm\",\"comm\":\"%s\",\"status\":\"SUCCESS\","
                     "\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                     comm, config.hostname, now_str);
        }
        send_siem_direct(response);

    } else if (strcmp(action, "filter_comm") == 0) {
        if (strlen(comm) > 0 && global_skel && global_skel->maps.noise_comms) {
            char key[TASK_COMM_LEN] = {0};
            strncpy(key, comm, sizeof(key) - 1);
            uint8_t val = 1;
            bpf_map_update_elem(bpf_map__fd(global_skel->maps.noise_comms), key, &val, BPF_ANY);
            snprintf(response, sizeof(response),
                     "{\"type\":\"ACTION_RESULT\",\"action\":\"filter_comm\",\"comm\":\"%s\",\"status\":\"SUCCESS\","
                     "\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                     comm, config.hostname, now_str);
        }
        send_siem_direct(response);

    } else if (strcmp(action, "kill_switch") == 0 || strcmp(action, "stop_agent") == 0) {
        printf("%s[⚡ KILL SWITCH] Agent emergency shutdown instructed by SIEM!%s\n",
               COLOR_RED, COLOR_RESET);
        snprintf(response, sizeof(response),
                 "{\"type\":\"ACTION_RESULT\",\"action\":\"kill_switch\",\"status\":\"SUCCESS\","
                 "\"message\":\"Agent initiating emergency shutdown\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                 config.hostname, now_str);
        send_siem_direct(response);
        stop = 1;

    } else if (strcmp(action, "ping") == 0 || strcmp(action, "status") == 0) {
        time_t uptime = time(NULL) - agent_start_time;
        snprintf(response, sizeof(response),
                 "{\"type\":\"PONG\",\"status\":\"ACTIVE\",\"uptime_sec\":%ld,"
                 "\"events_processed\":%llu,\"alerts_detected\":%llu,\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                 uptime, total_events_processed, total_alerts_detected, config.hostname, now_str);
        send_siem_direct(response);

    } else if (strcmp(action, "process_tree") == 0 || strcmp(action, "ps_tree") == 0 || strcmp(action, "tree") == 0) {
        report_process_tree_to_siem();

    } else if (strcmp(action, "services") == 0 || strcmp(action, "service_list") == 0) {
        report_services_to_siem();

    } else if (strcmp(action, "inventory") == 0 || strcmp(action, "audit") == 0 || strcmp(action, "scan") == 0) {
        report_services_to_siem();
        report_process_tree_to_siem();
    }
}

/* ========================================================================= */
/* SIEM NETWORK WORKER THREAD                                                */
/* ========================================================================= */

static int init_network_connection(const char *host, const char *port)
{
    struct addrinfo hints, *res, *p;
    int status;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(host, port, &hints, &res)) != 0) {
        if (config.verbose) {
            fprintf(stderr, "[!] SIEM DNS lookup failed for %s:%s: %s\n", host, port, gai_strerror(status));
        }
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;

        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd >= 0) {
        pthread_mutex_lock(&socket_lock);
        if (siem_sockfd >= 0) close(siem_sockfd);
        siem_sockfd = fd;
        pthread_mutex_unlock(&socket_lock);
        printf("%s[+] Successfully connected to SIEM (%s:%s)%s\n",
               COLOR_GREEN, host, port, COLOR_RESET);
        return 0;
    }

    return -1;
}

static void close_siem_socket(void)
{
    pthread_mutex_lock(&socket_lock);
    if (siem_sockfd >= 0) {
        close(siem_sockfd);
        siem_sockfd = -1;
    }
    pthread_mutex_unlock(&socket_lock);
}

static void *siem_network_worker(void *arg)
{
    char recv_buf[4096];
    int recv_len = 0;
    time_t last_reconnect = 0;

    while (!stop) {
        int current_fd = -1;
        pthread_mutex_lock(&socket_lock);
        current_fd = siem_sockfd;
        pthread_mutex_unlock(&socket_lock);

        /* 1. Connection check & Auto-reconnect with backoff */
        if (current_fd < 0) {
            time_t now = time(NULL);
            if (now - last_reconnect >= 3) {
                last_reconnect = now;
                init_network_connection(config.siem_host, config.siem_port);
            }
            pthread_mutex_lock(&socket_lock);
            current_fd = siem_sockfd;
            pthread_mutex_unlock(&socket_lock);

            if (current_fd < 0) {
                usleep(200000); /* 200ms sleep when offline */
                continue;
            }
        }

        /* 2. Poll socket for both INCOMING commands and OUTGOING queue */
        struct pollfd pfd;
        pfd.fd = current_fd;
        pfd.events = POLLIN;

        pthread_mutex_lock(&siem_queue.lock);
        int has_queued = (siem_queue.count > 0);
        pthread_mutex_unlock(&siem_queue.lock);

        if (has_queued) {
            pfd.events |= POLLOUT;
        }

        int poll_res = poll(&pfd, 1, 50 /* ms timeout */);
        if (poll_res < 0) {
            if (errno == EINTR) continue;
            close_siem_socket();
            continue;
        }

        /* 3. Read incoming kill switch / action commands from SIEM */
        if (poll_res > 0 && (pfd.revents & POLLIN)) {
            ssize_t n = recv(current_fd, recv_buf + recv_len, sizeof(recv_buf) - 1 - recv_len, 0);
            if (n <= 0) {
                fprintf(stderr, "%s[!] SIEM disconnected. Retrying...%s\n", COLOR_YELLOW, COLOR_RESET);
                close_siem_socket();
                recv_len = 0;
                continue;
            }
            recv_len += n;
            recv_buf[recv_len] = '\0';

            char *line_start = recv_buf;
            char *newline;
            while ((newline = strchr(line_start, '\n')) != NULL) {
                *newline = '\0';
                if (newline > line_start && *(newline - 1) == '\r') {
                    *(newline - 1) = '\0';
                }
                if (strlen(line_start) > 0) {
                    process_siem_command(line_start);
                }
                line_start = newline + 1;
            }
            int remaining = (recv_buf + recv_len) - line_start;
            if (remaining > 0 && line_start != recv_buf) {
                memmove(recv_buf, line_start, remaining);
            }
            recv_len = remaining;
        }

        /* 4. Transmit queued telemetry payload out to SIEM */
        if (poll_res > 0 && (pfd.revents & POLLOUT)) {
            char payload[MAX_PAYLOAD_SIZE];
            int have_payload = 0;

            pthread_mutex_lock(&siem_queue.lock);
            if (siem_queue.count > 0) {
                strncpy(payload, siem_queue.payloads[siem_queue.head], sizeof(payload) - 1);
                payload[sizeof(payload) - 1] = '\0';
                siem_queue.head = (siem_queue.head + 1) % QUEUE_CAPACITY;
                siem_queue.count--;
                have_payload = 1;
            }
            pthread_mutex_unlock(&siem_queue.lock);

            if (have_payload) {
                size_t len = strlen(payload);
                ssize_t sent = send(current_fd, payload, len, MSG_NOSIGNAL);
                if (sent < 0) {
                    fprintf(stderr, "[!] SIEM transmission failure: %s\n", strerror(errno));
                    close_siem_socket();
                }
            }
        }

        if (pfd.revents & (POLLHUP | POLLERR)) {
            close_siem_socket();
            recv_len = 0;
        }
    }

    return NULL;
}

/* ========================================================================= */
/* RING BUFFER EVENT HANDLER                                                 */
/* ========================================================================= */

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    total_events_processed++;

    /* 1. Filter out useless information */
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

    /* 4. Console log output */
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
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(e->data.connect.daddr), ip_str, sizeof(ip_str));
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

    /* 5. Format enriched SIEM JSON telemetry payload */
    char payload[MAX_PAYLOAD_SIZE];
    char now_str[64];
    get_iso8601_time(now_str, sizeof(now_str));

    char escaped_file[512] = {0};
    char escaped_comm[32] = {0};
    json_escape(e->comm, escaped_comm, sizeof(escaped_comm));

    int len = 0;
    const char *category = threat.is_threat ? "SECURITY_ALERT" : "EDR_TELEMETRY";

    switch (e->type) {
        case EVENT_TYPE_EXEC:
            json_escape(e->data.filename, escaped_file, sizeof(escaped_file));
            len = snprintf(payload, sizeof(payload),
                           "{\"type\":\"EXEC\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\",\"filename\":\"%s\","
                           "\"category\":\"%s\",\"severity\":\"%s\",\"alert\":%s,\"rule_name\":\"%s\","
                           "\"mitre_technique\":\"%s\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                           e->pid, e->ppid, e->uid, escaped_comm, escaped_file,
                           category, threat.severity, threat.is_threat ? "true" : "false",
                           threat.rule_name, threat.mitre_technique, config.hostname, now_str);
            break;

        case EVENT_TYPE_CONNECT: {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(e->data.connect.daddr), ip_str, sizeof(ip_str));
            len = snprintf(payload, sizeof(payload),
                           "{\"type\":\"CONNECT\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\","
                           "\"dst_ip\":\"%s\",\"dst_port\":%d,\"category\":\"%s\",\"severity\":\"%s\","
                           "\"alert\":%s,\"rule_name\":\"%s\",\"mitre_technique\":\"%s\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                           e->pid, e->ppid, e->uid, escaped_comm, ip_str, e->data.connect.dport,
                           category, threat.severity, threat.is_threat ? "true" : "false",
                           threat.rule_name, threat.mitre_technique, config.hostname, now_str);
            break;
        }

        case EVENT_TYPE_BASH:
            json_escape(e->data.filename, escaped_file, sizeof(escaped_file));
            len = snprintf(payload, sizeof(payload),
                           "{\"type\":\"BASH_CMD\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\",\"cmd\":\"%s\","
                           "\"category\":\"%s\",\"severity\":\"%s\",\"alert\":%s,\"rule_name\":\"%s\","
                           "\"mitre_technique\":\"%s\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                           e->pid, e->ppid, e->uid, escaped_comm, escaped_file,
                           category, threat.severity, threat.is_threat ? "true" : "false",
                           threat.rule_name, threat.mitre_technique, config.hostname, now_str);
            break;

        case EVENT_TYPE_INJECTION:
            len = snprintf(payload, sizeof(payload),
                           "{\"type\":\"INJECTION\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\","
                           "\"target_pid\":%u,\"req\":%u,\"category\":\"%s\",\"severity\":\"%s\","
                           "\"alert\":true,\"rule_name\":\"%s\",\"mitre_technique\":\"%s\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                           e->pid, e->ppid, e->uid, escaped_comm, e->data.injection.target_pid,
                           e->data.injection.req, category, threat.severity,
                           threat.rule_name, threat.mitre_technique, config.hostname, now_str);
            break;

        case EVENT_TYPE_FILE_TAMPER:
            json_escape(e->data.filename, escaped_file, sizeof(escaped_file));
            len = snprintf(payload, sizeof(payload),
                           "{\"type\":\"FILE_TAMPER\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\",\"filename\":\"%s\","
                           "\"category\":\"%s\",\"severity\":\"%s\",\"alert\":true,\"rule_name\":\"%s\","
                           "\"mitre_technique\":\"%s\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                           e->pid, e->ppid, e->uid, escaped_comm, escaped_file,
                           category, threat.severity, threat.rule_name, threat.mitre_technique, config.hostname, now_str);
            break;

        case EVENT_TYPE_PRIV_ESC:
            len = snprintf(payload, sizeof(payload),
                           "{\"type\":\"PRIV_ESC\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\","
                           "\"old_uid\":%u,\"target_uid\":%u,\"category\":\"%s\",\"severity\":\"%s\","
                           "\"alert\":true,\"rule_name\":\"%s\",\"mitre_technique\":\"%s\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                           e->pid, e->ppid, e->uid, escaped_comm, e->data.priv_esc.old_uid,
                           e->data.priv_esc.target_uid, category, threat.severity,
                           threat.rule_name, threat.mitre_technique, config.hostname, now_str);
            break;

        case EVENT_TYPE_KERNEL_MOD:
            json_escape(e->data.filename, escaped_file, sizeof(escaped_file));
            len = snprintf(payload, sizeof(payload),
                           "{\"type\":\"KERNEL_MOD\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\",\"args\":\"%s\","
                           "\"category\":\"%s\",\"severity\":\"%s\",\"alert\":true,\"rule_name\":\"%s\","
                           "\"mitre_technique\":\"%s\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                           e->pid, e->ppid, e->uid, escaped_comm, escaped_file,
                           category, threat.severity, threat.rule_name, threat.mitre_technique, config.hostname, now_str);
            break;

        case EVENT_TYPE_MEMFD_EXEC:
            json_escape(e->data.filename, escaped_file, sizeof(escaped_file));
            len = snprintf(payload, sizeof(payload),
                           "{\"type\":\"MEMFD_EXEC\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"comm\":\"%s\",\"name\":\"%s\","
                           "\"category\":\"%s\",\"severity\":\"%s\",\"alert\":true,\"rule_name\":\"%s\","
                           "\"mitre_technique\":\"%s\",\"agent_id\":\"%s\",\"timestamp\":\"%s\"}\n",
                           e->pid, e->ppid, e->uid, escaped_comm, escaped_file,
                           category, threat.severity, threat.rule_name, threat.mitre_technique, config.hostname, now_str);
            break;
    }

    if (len > 0) {
        enqueue_siem_payload(payload);
    }

    return 0;
}

/* ========================================================================= */
/* RESILIENT BPF HOOK ATTACHMENT                                             */
/* ========================================================================= */

static int attach_bpf_programs(struct proc_exec_bpf *skel)
{
    /* Try automatic skeleton attach first */
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

/* ========================================================================= */
/* CLI USAGE                                                                 */
/* ========================================================================= */

static void print_usage(const char *prog)
{
    printf("\n%seBPF EDR Security Agent & SIEM Telemetry with Remote Kill Switch%s\n", COLOR_BOLD, COLOR_RESET);
    printf("---------------------------------------------------------------------------------\n");
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  -s, --host <host>     SIEM target host (default: %s or $SIEM_HOST)\n", DEFAULT_SIEM_HOST);
    printf("  -p, --port <port>     SIEM target port (default: %s or $SIEM_PORT)\n", DEFAULT_SIEM_PORT);
    printf("  -a, --auto-kill       Autonomous kill switch: auto-kill critical threats locally\n");
    printf("  -v, --verbose         Verbose debug and telemetry logging\n");
    printf("  -h, --help            Show this usage information\n\n");
    printf("Supported SIEM Remote Control Commands:\n");
    printf("  {\"action\": \"process_tree\"} | PROCESS_TREE   Audit & stream full process tree (Good/Bad)\n");
    printf("  {\"action\": \"services\"}     | SERVICES       Audit running services and versions (Good/Bad)\n");
    printf("  {\"action\": \"inventory\"}    | INVENTORY      Complete endpoint audit (Tree + Services)\n");
    printf("  {\"action\": \"kill\", \"pid\": <PID>, [\"signal\": 9]}   Terminate process tree\n");
    printf("  {\"action\": \"suspend\", \"pid\": <PID>}             Pause process (SIGSTOP)\n");
    printf("  {\"action\": \"resume\", \"pid\": <PID>}              Resume process (SIGCONT)\n");
    printf("  {\"action\": \"block_comm\", \"comm\": \"<binary>\"}    Block binary and kill active instances\n");
    printf("  {\"action\": \"unblock_comm\", \"comm\": \"<binary>\"}  Remove binary from blocklist\n");
    printf("  {\"action\": \"filter_comm\", \"comm\": \"<binary>\"}   Add binary to noise filter\n");
    printf("  {\"action\": \"kill_switch\"}                       Agent emergency shutdown\n");
    printf("  {\"action\": \"ping\"}                              Agent heartbeat / status check\n");
    printf("---------------------------------------------------------------------------------\n\n");
}

/* ========================================================================= */
/* MAIN ENTRY POINT                                                          */
/* ========================================================================= */

int main(int argc, char **argv)
{
    struct proc_exec_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

    agent_start_time = time(NULL);

    /* Initialize default configuration */
    memset(&config, 0, sizeof(config));
    const char *env_host = getenv("SIEM_HOST");
    const char *env_port = getenv("SIEM_PORT");
    const char *env_auto_kill = getenv("EDR_AUTO_KILL");

    strncpy(config.siem_host, env_host ? env_host : DEFAULT_SIEM_HOST, sizeof(config.siem_host) - 1);
    strncpy(config.siem_port, env_port ? env_port : DEFAULT_SIEM_PORT, sizeof(config.siem_port) - 1);
    config.auto_kill = (env_auto_kill && atoi(env_auto_kill) == 1) ? 1 : 0;
    config.verbose = 0;

    if (gethostname(config.hostname, sizeof(config.hostname) - 1) != 0) {
        strncpy(config.hostname, "linux-agent", sizeof(config.hostname) - 1);
    }

    /* Parse CLI arguments */
    static struct option long_options[] = {
        {"host",      required_argument, 0, 's'},
        {"port",      required_argument, 0, 'p'},
        {"auto-kill", no_argument,       0, 'a'},
        {"verbose",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "s:p:avh", long_options, NULL)) != -1) {
        switch (opt) {
            case 's':
                strncpy(config.siem_host, optarg, sizeof(config.siem_host) - 1);
                break;
            case 'p':
                strncpy(config.siem_port, optarg, sizeof(config.siem_port) - 1);
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

    /* Initialize event queue */
    memset(&siem_queue, 0, sizeof(siem_queue));
    pthread_mutex_init(&siem_queue.lock, NULL);
    pthread_cond_init(&siem_queue.not_empty, NULL);

    /* Set up libbpf print callback */
    libbpf_set_print(libbpf_print_fn);

    /* Start background SIEM network thread */
    if (pthread_create(&network_tid, NULL, siem_network_worker, NULL) != 0) {
        fprintf(stderr, "[-] Failed to spawn SIEM network thread\n");
        return 1;
    }

    /* Open BPF skeleton */
    skel = proc_exec_bpf__open();
    if (!skel) {
        fprintf(stderr, "[-] Failed to open BPF skeleton\n");
        err = 1;
        goto cleanup;
    }
    global_skel = skel;

    /* Verify if /bin/bash exists for uprobe; if not, disable readline probe safely */
    if (access("/bin/bash", F_OK) != 0) {
        if (config.verbose) {
            printf("[!] /bin/bash not found; disabling optional bash readline probe.\n");
        }
        bpf_program__set_autoload(skel->progs.handle_bash_readline, false);
    }

    /* Load and verify BPF programs into kernel */
    err = proc_exec_bpf__load(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Populate the kernel-space noise filtering map (cat, sed, ls, etc.) */
    populate_noise_filter_map(skel);

    /* Attach BPF hooks */
    err = attach_bpf_programs(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to attach BPF hooks: %d\n", err);
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "[-] Failed to initialize ring buffer\n");
        goto cleanup;
    }

    /* Register termination signals */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("=================================================================================\n");
    printf("%s[+] eBPF EDR Security Agent & SIEM Telemetry ACTIVE%s\n", COLOR_GREEN, COLOR_RESET);
    printf("    Target SIEM      : %s:%s\n", config.siem_host, config.siem_port);
    printf("    Host Identifier  : %s\n", config.hostname);
    printf("    Autonomous Kill  : %s\n", config.auto_kill ? "ENABLED (CRITICAL threats auto-killed)" : "DISABLED (Remote SIEM trigger only)");
    printf("    Noise Filtering  : ACTIVE (Filtered: cat, sed, ls, grep, awk, sleep, etc.)\n");
    printf("    Process Tree     : READY (Responds to 'process_tree' / 'services' / 'inventory')\n");
    printf("    Kill Switch      : READY (Listening for SIEM instructions over TCP)\n");
    printf("=================================================================================\n");

    /* Main event loop: Poll kernel ring buffer continuously */
    while (!stop) {
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err < 0 && err == -EINTR) {
            continue;
        }
        if (err < 0) {
            fprintf(stderr, "[!] Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    printf("\n%s[+] Shutting down eBPF Security Agent...%s\n", COLOR_YELLOW, COLOR_RESET);
    stop = 1;

    /* Wait for network worker thread */
    pthread_join(network_tid, NULL);

    /* Close SIEM socket */
    close_siem_socket();

    /* Clean up ring buffer and BPF skeleton */
    if (rb) {
        ring_buffer__free(rb);
    }
    if (skel) {
        proc_exec_bpf__destroy(skel);
    }

    pthread_mutex_destroy(&siem_queue.lock);
    pthread_cond_destroy(&siem_queue.not_empty);

    printf("%s[+] Shutdown complete. Processed: %llu events | Detected: %llu alerts.%s\n",
           COLOR_GREEN, total_events_processed, total_alerts_detected, COLOR_RESET);

    return err < 0 ? -err : 0;
}