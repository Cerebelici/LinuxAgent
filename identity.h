#ifndef CERBERUS_IDENTITY_H
#define CERBERUS_IDENTITY_H

#include <stddef.h>
#include <time.h>
#include <netinet/in.h>

#define AGENT_VERSION "0.1.0"
#define DEFAULT_TOKEN_PATH "/var/lib/cerberus-agent/token"
#define MAX_INTERFACES 32
#define MAX_IPS_PER_IFACE 16

struct agent_interface_info {
    char name[32];
    char mac[32];
    char ipv4[MAX_IPS_PER_IFACE][INET_ADDRSTRLEN];
    int ipv4_count;
    char ipv6[MAX_IPS_PER_IFACE][INET6_ADDRSTRLEN];
    int ipv6_count;
};

struct agent_identity {
    char agent_id[37];       /* UUID 36 chars + null */
    char boot_id[37];        /* UUID 36 chars + null */
    char hostname[128];
    char agent_version[32];
    char kernel[128];
    char token[256];
    char token_path[512];
    struct agent_interface_info interfaces[MAX_INTERFACES];
    int interface_count;
    time_t last_iface_refresh;
};

/* Initialize identity (agent_id, boot_id, hostname, kernel, interfaces) */
int identity_init(struct agent_identity *id, const char *token_file_override);

/* Refresh network interfaces list */
int identity_refresh_interfaces(struct agent_identity *id);

/* Load token from token_path */
int identity_load_token(struct agent_identity *id);

/* Save token to token_path (creates directory 0700, file 0600 with O_NOFOLLOW) */
int identity_save_token(struct agent_identity *id, const char *token);

/* Enroll agent with Sentinel endpoint: POST {url}/api/v1/agent/enroll */
int identity_enroll(struct agent_identity *id, const char *sentinel_url, const char *enroll_token, const char *ca_file, int insecure_http);

/* Serialize agent block to JSON string */
int identity_format_agent_json(const struct agent_identity *id, char *dst, size_t dst_len);

#endif /* CERBERUS_IDENTITY_H */
