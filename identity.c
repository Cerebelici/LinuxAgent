#define _GNU_SOURCE
#include "identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ctype.h>

#if defined(__linux__)
#include <netpacket/packet.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <net/if_dl.h>
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <curl/curl.h>

static void trim_whitespace(char *str)
{
    if (!str) return;
    int len = (int)strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r' || isspace((unsigned char)str[len - 1]))) {
        str[len - 1] = '\0';
        len--;
    }
}

static int read_machine_id_raw(unsigned char out[16])
{
    const char *paths[] = {
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
        NULL
    };

    char hex[64] = {0};
    int found = 0;

    for (int i = 0; paths[i] != NULL; i++) {
        FILE *f = fopen(paths[i], "r");
        if (f) {
            if (fgets(hex, sizeof(hex), f)) {
                trim_whitespace(hex);
                if (strlen(hex) >= 32) {
                    found = 1;
                    fclose(f);
                    break;
                }
            }
            fclose(f);
        }
    }

    if (!found) {
        /* Fallback: derive from hostname + random */
        char host[64] = {0};
        gethostname(host, sizeof(host) - 1);
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int dlen = 0;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (ctx) {
            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
            EVP_DigestUpdate(ctx, host, strlen(host));
            EVP_DigestFinal_ex(ctx, digest, &dlen);
            EVP_MD_CTX_free(ctx);
            memcpy(out, digest, 16);
            return 0;
        }
        return -1;
    }

    /* Convert 32 hex chars to 16 bytes */
    for (int i = 0; i < 16; i++) {
        char byte_hex[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        out[i] = (unsigned char)strtoul(byte_hex, NULL, 16);
    }

    return 0;
}

static int generate_agent_id(char *uuid_out, size_t max_len)
{
    unsigned char machine_id[16];
    if (read_machine_id_raw(machine_id) != 0) {
        return -1;
    }

    unsigned char hmac_res[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    const char *data = "cerberus-agent/v1";

    HMAC(EVP_sha256(), machine_id, 16, (const unsigned char *)data, strlen(data), hmac_res, &hmac_len);
    if (hmac_len < 16) {
        return -1;
    }

    /* Version 8 (RFC 9562 custom UUID) */
    hmac_res[6] = (hmac_res[6] & 0x0f) | 0x80;
    /* Variant bits to RFC 9562 (10xx xxxx) */
    hmac_res[8] = (hmac_res[8] & 0x3f) | 0x80;

    snprintf(uuid_out, max_len,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             hmac_res[0], hmac_res[1], hmac_res[2], hmac_res[3],
             hmac_res[4], hmac_res[5], hmac_res[6], hmac_res[7],
             hmac_res[8], hmac_res[9], hmac_res[10], hmac_res[11],
             hmac_res[12], hmac_res[13], hmac_res[14], hmac_res[15]);

    return 0;
}

static int read_boot_id(char *boot_id_out, size_t max_len)
{
    FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (f) {
        if (fgets(boot_id_out, max_len, f)) {
            trim_whitespace(boot_id_out);
            fclose(f);
            return 0;
        }
        fclose(f);
    }

    /* Fallback: pseudo boot-id */
    snprintf(boot_id_out, max_len, "00000000-0000-0000-0000-%012lx", (unsigned long)time(NULL));
    return 0;
}

int identity_refresh_interfaces(struct agent_identity *id)
{
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) == -1) {
        return -1;
    }

    id->interface_count = 0;
    memset(id->interfaces, 0, sizeof(id->interfaces));

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;

        /* Skip loopback and interfaces that are down */
        if (strcmp(ifa->ifa_name, "lo") == 0 || (ifa->ifa_flags & IFF_LOOPBACK)) {
            continue;
        }

        /* Find existing or create new slot */
        int idx = -1;
        for (int i = 0; i < id->interface_count; i++) {
            if (strcmp(id->interfaces[i].name, ifa->ifa_name) == 0) {
                idx = i;
                break;
            }
        }

        if (idx == -1) {
            if (id->interface_count >= MAX_INTERFACES) continue;
            idx = id->interface_count++;
            snprintf(id->interfaces[idx].name, sizeof(id->interfaces[idx].name), "%s", ifa->ifa_name);
        }

        struct agent_interface_info *entry = &id->interfaces[idx];

#if defined(__linux__)
        if (ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;
            if (sll->sll_halen == 6 && strlen(entry->mac) == 0) {
                snprintf(entry->mac, sizeof(entry->mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                         sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2],
                         sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5]);
            }
        }
#elif defined(__APPLE__) || defined(__FreeBSD__)
        if (ifa->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            if (sdl->sdl_alen == 6 && strlen(entry->mac) == 0) {
                unsigned char *m = (unsigned char *)LLADDR(sdl);
                snprintf(entry->mac, sizeof(entry->mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                         m[0], m[1], m[2], m[3], m[4], m[5]);
            }
        }
#endif

        if (ifa->ifa_addr->sa_family == AF_INET) {
            if (entry->ipv4_count < MAX_IPS_PER_IFACE) {
                char ip_buf[INET_ADDRSTRLEN];
                struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                if (inet_ntop(AF_INET, &sin->sin_addr, ip_buf, sizeof(ip_buf))) {
                    snprintf(entry->ipv4[entry->ipv4_count++], INET_ADDRSTRLEN, "%s", ip_buf);
                }
            }
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            if (entry->ipv6_count < MAX_IPS_PER_IFACE) {
                char ip_buf[INET6_ADDRSTRLEN];
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                if (inet_ntop(AF_INET6, &sin6->sin6_addr, ip_buf, sizeof(ip_buf))) {
                    snprintf(entry->ipv6[entry->ipv6_count++], INET6_ADDRSTRLEN, "%s", ip_buf);
                }
            }
        }
    }

    freeifaddrs(ifaddr);
    id->last_iface_refresh = time(NULL);
    return 0;
}

int identity_init(struct agent_identity *id, const char *token_file_override)
{
    memset(id, 0, sizeof(*id));

    if (generate_agent_id(id->agent_id, sizeof(id->agent_id)) != 0) {
        snprintf(id->agent_id, sizeof(id->agent_id), "%s", "00000000-0000-8000-8000-000000000001");
    }

    read_boot_id(id->boot_id, sizeof(id->boot_id));

    if (gethostname(id->hostname, sizeof(id->hostname) - 1) != 0) {
        snprintf(id->hostname, sizeof(id->hostname), "%s", "linux-agent");
    }

    snprintf(id->agent_version, sizeof(id->agent_version), "%s", AGENT_VERSION);

    struct utsname uts;
    if (uname(&uts) == 0) {
        snprintf(id->kernel, sizeof(id->kernel), "%s", uts.release);
    } else {
        snprintf(id->kernel, sizeof(id->kernel), "%s", "unknown");
    }

    if (token_file_override && strlen(token_file_override) > 0) {
        snprintf(id->token_path, sizeof(id->token_path), "%s", token_file_override);
    } else {
        const char *env_tok = getenv("CERBERUS_TOKEN_FILE");
        if (env_tok && strlen(env_tok) > 0) {
            snprintf(id->token_path, sizeof(id->token_path), "%s", env_tok);
        } else {
            snprintf(id->token_path, sizeof(id->token_path), "%s", DEFAULT_TOKEN_PATH);
        }
    }

    identity_refresh_interfaces(id);
    identity_load_token(id);

    return 0;
}

static void ensure_parent_dir(const char *file_path)
{
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", file_path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) {
        *slash = '\0';
        /* Recursive directory creation if needed */
        char tmp[512];
        char *p = NULL;
        snprintf(tmp, sizeof(tmp), "%s", dir);
        for (p = tmp + 1; *p; p++) {
            if (*p == '/') {
                *p = '\0';
                mkdir(tmp, 0700);
                *p = '/';
            }
        }
        mkdir(dir, 0700);
    }
}

int identity_load_token(struct agent_identity *id)
{
    int fd = open(id->token_path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }

    char buf[sizeof(id->token)];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n > 0) {
        buf[n] = '\0';
        trim_whitespace(buf);
        if (strlen(buf) > 0) {
            snprintf(id->token, sizeof(id->token), "%s", buf);
            return 0;
        }
    }

    return -1;
}

int identity_save_token(struct agent_identity *id, const char *token)
{
    ensure_parent_dir(id->token_path);

    int fd = open(id->token_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return -1;
    }

    size_t len = strlen(token);
    ssize_t written = write(fd, token, len);
    close(fd);

    if (written == (ssize_t)len) {
        snprintf(id->token, sizeof(id->token), "%s", token);
        return 0;
    }

    return -1;
}

struct curl_write_ctx {
    char *buf;
    size_t len;
    size_t max;
};

static size_t enroll_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t total = size * nmemb;
    struct curl_write_ctx *ctx = (struct curl_write_ctx *)userp;
    if (ctx->len + total < ctx->max) {
        memcpy(ctx->buf + ctx->len, contents, total);
        ctx->len += total;
        ctx->buf[ctx->len] = '\0';
        return total;
    }
    return 0;
}

static int extract_token_from_json(const char *json, char *token_out, size_t max_len)
{
    const char *key = "\"agent_token\":";
    const char *p = strstr(json, key);
    if (!p) {
        key = "\"agent_token\" :";
        p = strstr(json, key);
    }
    if (!p) return -1;

    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p && (*p == ' ' || *p == '\t')) p++;
    if (*p != '\"') return -1;
    p++;

    const char *end = strchr(p, '\"');
    if (!end) return -1;

    size_t len = end - p;
    if (len >= max_len) len = max_len - 1;
    memcpy(token_out, p, len);
    token_out[len] = '\0';
    return 0;
}

int identity_enroll(struct agent_identity *id, const char *sentinel_url, const char *enroll_token, const char *ca_file, int insecure_http)
{
    if (!sentinel_url || strlen(sentinel_url) == 0) return -1;
    if (!enroll_token || strlen(enroll_token) == 0) return -1;

    if (strncmp(sentinel_url, "http://", 7) == 0 && !insecure_http) {
        fprintf(stderr, "[-] ERROR: Refusing plain HTTP for Sentinel URL without --insecure-http: %s\n", sentinel_url);
        return -1;
    }

    char url[512];
    snprintf(url, sizeof(url), "%s/api/v1/agent/enroll", sentinel_url);

    char post_fields[1024];
    snprintf(post_fields, sizeof(post_fields),
             "{\"agent_id\":\"%s\",\"hostname\":\"%s\",\"enrollment_token\":\"%s\"}",
             id->agent_id, id->hostname, enroll_token);

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char resp_buf[2048] = {0};
    struct curl_write_ctx wctx = { resp_buf, 0, sizeof(resp_buf) };

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, enroll_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &wctx);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 2000L);

    if (ca_file && strlen(ca_file) > 0) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_file);
    }

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || http_code != 201) {
        fprintf(stderr, "[-] Enrollment failed: HTTP %ld, curl status: %s (response: %s)\n",
                http_code, curl_easy_strerror(res), resp_buf);
        return -1;
    }

    char token[256] = {0};
    if (extract_token_from_json(resp_buf, token, sizeof(token)) != 0) {
        fprintf(stderr, "[-] Failed to extract agent_token from response: %s\n", resp_buf);
        return -1;
    }

    if (identity_save_token(id, token) != 0) {
        fprintf(stderr, "[!] Warning: failed to persist token to %s, holding in memory\n", id->token_path);
        snprintf(id->token, sizeof(id->token), "%s", token);
    }

    return 0;
}

int identity_format_agent_json(const struct agent_identity *id, char *dst, size_t dst_len)
{
    char ifaces_json[4096] = {0};
    size_t ioffset = 0;

    for (int i = 0; i < id->interface_count; i++) {
        const struct agent_interface_info *iface = &id->interfaces[i];
        char ipv4_json[1024] = {0};
        char ipv6_json[1024] = {0};

        size_t off4 = 0;
        for (int j = 0; j < iface->ipv4_count; j++) {
            off4 += snprintf(ipv4_json + off4, sizeof(ipv4_json) - off4,
                             "%s\"%s\"", (j == 0 ? "" : ","), iface->ipv4[j]);
        }

        size_t off6 = 0;
        for (int j = 0; j < iface->ipv6_count; j++) {
            off6 += snprintf(ipv6_json + off6, sizeof(ipv6_json) - off6,
                             "%s\"%s\"", (j == 0 ? "" : ","), iface->ipv6[j]);
        }

        ioffset += snprintf(ifaces_json + ioffset, sizeof(ifaces_json) - ioffset,
                            "%s{\"name\":\"%s\",\"mac\":\"%s\",\"ipv4\":[%s],\"ipv6\":[%s]}",
                            (i == 0 ? "" : ","), iface->name, iface->mac, ipv4_json, ipv6_json);
    }

    return snprintf(dst, dst_len,
                    "{\"agent_id\":\"%s\",\"boot_id\":\"%s\",\"hostname\":\"%s\",\"agent_version\":\"%s\",\"kernel\":\"%s\",\"interfaces\":[%s]}",
                    id->agent_id, id->boot_id, id->hostname, id->agent_version, id->kernel, ifaces_json);
}
