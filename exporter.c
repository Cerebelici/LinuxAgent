#define _GNU_SOURCE
#include "exporter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <zlib.h>
#include <curl/curl.h>

struct event_slot {
    char json[EVENT_JSON_MAX];
    size_t len;
};

struct exporter {
    struct exporter_config cfg;
    struct agent_identity *ident;

    /* Alerts Lane (cap 512, no drops) */
    struct event_slot alert_slots[ALERT_RING_CAP];
    int alert_head;
    int alert_tail;
    int alert_count;
    size_t alert_bytes;

    /* Telemetry Lane (cap 2048, drop-oldest) */
    struct event_slot telemetry_slots[TELEMETRY_RING_CAP];
    int telemetry_head;
    int telemetry_tail;
    int telemetry_count;
    size_t telemetry_bytes;

    uint64_t dropped_since_last;
    uint64_t dropped_total;
    uint64_t seq;

    time_t oldest_event_sec;

    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_t thread;
    volatile int running;

    CURL *curl;
};

struct curl_resp_ctx {
    char buf[1024];
    size_t len;
    long retry_after;
};

static size_t curl_header_cb(char *buffer, size_t size, size_t nitems, void *userdata)
{
    size_t total = size * nitems;
    struct curl_resp_ctx *ctx = (struct curl_resp_ctx *)userdata;
    if (total >= 12 && strncasecmp(buffer, "Retry-After:", 12) == 0) {
        char *val = buffer + 12;
        while (*val == ' ' || *val == '\t') val++;
        ctx->retry_after = strtol(val, NULL, 10);
    }
    return total;
}

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t total = size * nmemb;
    struct curl_resp_ctx *ctx = (struct curl_resp_ctx *)userp;
    if (ctx->len + total < sizeof(ctx->buf) - 1) {
        memcpy(ctx->buf + ctx->len, contents, total);
        ctx->len += total;
        ctx->buf[ctx->len] = '\0';
        return total;
    }
    return total;
}

static int gzip_compress(const unsigned char *src, size_t src_len, unsigned char **out, size_t *out_len)
{
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return -1;
    }

    size_t bound = deflateBound(&strm, src_len) + 64;
    unsigned char *dst = malloc(bound);
    if (!dst) {
        deflateEnd(&strm);
        return -1;
    }

    strm.next_in = (Bytef *)src;
    strm.avail_in = src_len;
    strm.next_out = dst;
    strm.avail_out = bound;

    int ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        free(dst);
        deflateEnd(&strm);
        return -1;
    }

    *out_len = strm.total_out;
    *out = dst;
    deflateEnd(&strm);
    return 0;
}

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

static void *sender_loop(void *arg)
{
    struct exporter *exp = (struct exporter *)arg;
    int backoff_step = 0;

    /* Reusable batch building buffer (up to 2 MiB for 1000 events) */
    size_t batch_buf_cap = 2 * 1024 * 1024;
    char *batch_buf = malloc(batch_buf_cap);
    if (!batch_buf) {
        fprintf(stderr, "[-] Fatal: failed to allocate exporter batch buffer\n");
        return NULL;
    }

    while (exp->running) {
        pthread_mutex_lock(&exp->lock);

        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);

        int total_count = exp->alert_count + exp->telemetry_count;
        size_t total_bytes = exp->alert_bytes + exp->telemetry_bytes;
        double age = 0;
        if (total_count > 0 && exp->oldest_event_sec > 0) {
            age = difftime(now.tv_sec, exp->oldest_event_sec);
        }

        int should_flush = (exp->alert_count > 0) ||
                           (total_count >= 256) ||
                           (total_bytes >= 64 * 1024) ||
                           (age >= 1.0);

        if (!should_flush && exp->running) {
            struct timespec wait_time = now;
            wait_time.tv_sec += 1;
            pthread_cond_timedwait(&exp->cond, &exp->lock, &wait_time);

            /* Re-evaluate conditions after wake up */
            total_count = exp->alert_count + exp->telemetry_count;
            total_bytes = exp->alert_bytes + exp->telemetry_bytes;
            clock_gettime(CLOCK_REALTIME, &now);
            if (total_count > 0 && exp->oldest_event_sec > 0) {
                age = difftime(now.tv_sec, exp->oldest_event_sec);
            }
            should_flush = (exp->alert_count > 0) ||
                           (total_count >= 256) ||
                           (total_bytes >= 64 * 1024) ||
                           (age >= 1.0);
        }

        if (total_count == 0 || !should_flush) {
            pthread_mutex_unlock(&exp->lock);
            if (!exp->running) break;
            continue;
        }

        /* 1. Gather up to 1000 events for this batch */
        int take_alerts = exp->alert_count;
        if (take_alerts > 1000) take_alerts = 1000;
        int take_telemetry = exp->telemetry_count;
        if (take_alerts + take_telemetry > 1000) {
            take_telemetry = 1000 - take_alerts;
        }

        uint64_t current_seq = exp->seq;
        uint64_t dropped_reported = exp->dropped_since_last;

        /* Refresh interfaces if stale (>= 60s) */
        time_t cur_sec = time(NULL);
        if (cur_sec - exp->ident->last_iface_refresh >= 60) {
            identity_refresh_interfaces(exp->ident);
        }

        char agent_json[4096];
        identity_format_agent_json(exp->ident, agent_json, sizeof(agent_json));

        char sent_at[64];
        get_iso8601_time(sent_at, sizeof(sent_at));

        /* Assemble JSON payload */
        size_t offset = 0;
        offset += snprintf(batch_buf + offset, batch_buf_cap - offset,
                           "{\"schema_version\":1,\"agent\":%s,"
                           "\"batch\":{\"seq\":%llu,\"sent_at\":\"%s\",\"dropped_since_last\":%llu},"
                           "\"events\":[",
                           agent_json, (unsigned long long)current_seq, sent_at, (unsigned long long)dropped_reported);

        int first = 1;
        /* Add alerts */
        for (int i = 0; i < take_alerts; i++) {
            int slot_idx = (exp->alert_head + i) % ALERT_RING_CAP;
            const struct event_slot *s = &exp->alert_slots[slot_idx];
            if (offset + s->len + 4 >= batch_buf_cap) break;
            if (!first) batch_buf[offset++] = ',';
            memcpy(batch_buf + offset, s->json, s->len);
            offset += s->len;
            first = 0;
        }

        /* Add telemetry */
        for (int i = 0; i < take_telemetry; i++) {
            int slot_idx = (exp->telemetry_head + i) % TELEMETRY_RING_CAP;
            const struct event_slot *s = &exp->telemetry_slots[slot_idx];
            if (offset + s->len + 4 >= batch_buf_cap) break;
            if (!first) batch_buf[offset++] = ',';
            memcpy(batch_buf + offset, s->json, s->len);
            offset += s->len;
            first = 0;
        }

        offset += snprintf(batch_buf + offset, batch_buf_cap - offset, "]}");
        pthread_mutex_unlock(&exp->lock);

        /* 2. Optional gzip compression if payload > 4 KiB */
        unsigned char *send_data = (unsigned char *)batch_buf;
        size_t send_len = offset;
        int is_gzipped = 0;
        unsigned char *gz_buf = NULL;
        size_t gz_len = 0;

        if (offset > 4096) {
            if (gzip_compress((const unsigned char *)batch_buf, offset, &gz_buf, &gz_len) == 0) {
                send_data = gz_buf;
                send_len = gz_len;
                is_gzipped = 1;
            }
        }

        /* 3. HTTP POST via libcurl */
        char url[1024];
        snprintf(url, sizeof(url), "%s/api/v1/agent/telemetry", exp->cfg.sentinel_url);

        char auth_hdr[512];
        snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", exp->ident->token);

        char agent_id_hdr[128];
        snprintf(agent_id_hdr, sizeof(agent_id_hdr), "X-Cerberus-Agent-Id: %s", exp->ident->agent_id);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, auth_hdr);
        headers = curl_slist_append(headers, agent_id_hdr);
        if (is_gzipped) {
            headers = curl_slist_append(headers, "Content-Encoding: gzip");
        }

        struct curl_resp_ctx resp_ctx;
        memset(&resp_ctx, 0, sizeof(resp_ctx));

        curl_easy_setopt(exp->curl, CURLOPT_URL, url);
        curl_easy_setopt(exp->curl, CURLOPT_POST, 1L);
        curl_easy_setopt(exp->curl, CURLOPT_POSTFIELDS, (char *)send_data);
        curl_easy_setopt(exp->curl, CURLOPT_POSTFIELDSIZE, (long)send_len);
        curl_easy_setopt(exp->curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(exp->curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(exp->curl, CURLOPT_WRITEDATA, &resp_ctx);
        curl_easy_setopt(exp->curl, CURLOPT_HEADERFUNCTION, curl_header_cb);
        curl_easy_setopt(exp->curl, CURLOPT_HEADERDATA, &resp_ctx);
        curl_easy_setopt(exp->curl, CURLOPT_TIMEOUT_MS, 5000L);
        curl_easy_setopt(exp->curl, CURLOPT_CONNECTTIMEOUT_MS, 2000L);
        curl_easy_setopt(exp->curl, CURLOPT_TCP_KEEPALIVE, 1L);

        if (exp->cfg.ca_file[0] != '\0') {
            curl_easy_setopt(exp->curl, CURLOPT_CAINFO, exp->cfg.ca_file);
        }

        CURLcode res = curl_easy_perform(exp->curl);
        long http_code = 0;
        if (res == CURLE_OK) {
            curl_easy_getinfo(exp->curl, CURLINFO_RESPONSE_CODE, &http_code);
        }

        curl_slist_free_all(headers);
        if (gz_buf) free(gz_buf);

        /* 4. Handle HTTP Response */
        if (res == CURLE_OK && http_code == 202) {
            /* Success: commit batch, advance seq, free slots */
            pthread_mutex_lock(&exp->lock);
            for (int i = 0; i < take_alerts; i++) {
                int slot_idx = exp->alert_head;
                exp->alert_bytes -= exp->alert_slots[slot_idx].len;
                exp->alert_head = (exp->alert_head + 1) % ALERT_RING_CAP;
                exp->alert_count--;
            }
            for (int i = 0; i < take_telemetry; i++) {
                int slot_idx = exp->telemetry_head;
                exp->telemetry_bytes -= exp->telemetry_slots[slot_idx].len;
                exp->telemetry_head = (exp->telemetry_head + 1) % TELEMETRY_RING_CAP;
                exp->telemetry_count--;
            }
            if (exp->dropped_since_last >= dropped_reported) {
                exp->dropped_since_last -= dropped_reported;
            } else {
                exp->dropped_since_last = 0;
            }
            if (exp->alert_count == 0 && exp->telemetry_count == 0) {
                exp->oldest_event_sec = 0;
            }
            exp->seq++;
            pthread_mutex_unlock(&exp->lock);
            backoff_step = 0;
            if (exp->cfg.verbose) {
                printf("[+] Exporter: Batch %llu accepted (events: %d)\n",
                       (unsigned long long)current_seq, take_alerts + take_telemetry);
            }
        } else if (res == CURLE_OK && http_code == 400) {
            /* Poison batch: drop batch to prevent permanent stall */
            fprintf(stderr, "[-] Exporter: Batch %llu rejected (400 Bad Request): %s\n",
                    (unsigned long long)current_seq, resp_ctx.buf);
            pthread_mutex_lock(&exp->lock);
            for (int i = 0; i < take_alerts; i++) {
                int slot_idx = exp->alert_head;
                exp->alert_bytes -= exp->alert_slots[slot_idx].len;
                exp->alert_head = (exp->alert_head + 1) % ALERT_RING_CAP;
                exp->alert_count--;
            }
            for (int i = 0; i < take_telemetry; i++) {
                int slot_idx = exp->telemetry_head;
                exp->telemetry_bytes -= exp->telemetry_slots[slot_idx].len;
                exp->telemetry_head = (exp->telemetry_head + 1) % TELEMETRY_RING_CAP;
                exp->telemetry_count--;
            }
            if (exp->dropped_since_last >= dropped_reported) {
                exp->dropped_since_last -= dropped_reported;
            } else {
                exp->dropped_since_last = 0;
            }
            if (exp->alert_count == 0 && exp->telemetry_count == 0) {
                exp->oldest_event_sec = 0;
            }
            exp->seq++;
            pthread_mutex_unlock(&exp->lock);
            backoff_step = 0;
        } else if (res == CURLE_OK && http_code == 401) {
            /* Unauthorized: attempt re-enrollment */
            fprintf(stderr, "[!] Exporter: 401 Unauthorized received, re-enrolling agent...\n");
            int enrolled = identity_enroll(exp->ident, exp->cfg.sentinel_url, exp->cfg.enroll_token,
                                           exp->cfg.ca_file, exp->cfg.insecure_http);
            if (enrolled != 0) {
                fprintf(stderr, "[-] Exporter: Re-enrollment failed, backing off\n");
                backoff_step++;
            } else {
                if (exp->cfg.verbose) {
                    printf("[+] Exporter: Re-enrollment successful, will retry batch\n");
                }
            }
        } else {
            /* 5xx, 429, or network error: retain batch and back off */
            if (exp->cfg.verbose) {
                fprintf(stderr, "[!] Exporter: Transmission failed (HTTP %ld / %s), backing off\n",
                        http_code, curl_easy_strerror(res));
            }
            backoff_step++;
            if (backoff_step > 6) backoff_step = 6; /* Cap at ~60s */

            int base_sec = (1 << backoff_step);
            if (base_sec > 60) base_sec = 60;
            double jitter = 0.75 + (0.5 * ((double)rand() / (double)RAND_MAX));
            double wait_sec = (double)base_sec * jitter;
            if (resp_ctx.retry_after > 0 && (double)resp_ctx.retry_after > wait_sec) {
                wait_sec = (double)resp_ctx.retry_after;
            }

            /* Wait while checking running flag in 100ms slices */
            int slices = (int)(wait_sec * 10.0);
            for (int s = 0; s < slices && exp->running; s++) {
                usleep(100000);
            }
        }
    }

    free(batch_buf);
    return NULL;
}

struct exporter *exporter_create(const struct exporter_config *cfg, struct agent_identity *ident)
{
    struct exporter *exp = calloc(1, sizeof(*exp));
    if (!exp) return NULL;

    memcpy(&exp->cfg, cfg, sizeof(exp->cfg));
    exp->ident = ident;
    exp->seq = 1;

    pthread_mutex_init(&exp->lock, NULL);
    pthread_cond_init(&exp->cond, NULL);

    exp->curl = curl_easy_init();
    if (!exp->curl) {
        free(exp);
        return NULL;
    }

    return exp;
}

int exporter_start(struct exporter *exp)
{
    if (!exp) return -1;
    exp->running = 1;
    if (pthread_create(&exp->thread, NULL, sender_loop, exp) != 0) {
        exp->running = 0;
        return -1;
    }
    return 0;
}

void exporter_stop(struct exporter *exp)
{
    if (!exp) return;
    exp->running = 0;
    pthread_cond_broadcast(&exp->cond);
    pthread_join(exp->thread, NULL);

    if (exp->curl) {
        curl_easy_cleanup(exp->curl);
        exp->curl = NULL;
    }

    pthread_mutex_destroy(&exp->lock);
    pthread_cond_destroy(&exp->cond);
    free(exp);
}

int exporter_enqueue(struct exporter *exp, const char *event_json, size_t len, int is_alert)
{
    if (!exp || !event_json || len == 0 || len >= EVENT_JSON_MAX) {
        return -1;
    }

    pthread_mutex_lock(&exp->lock);

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);

    if (is_alert) {
        if (exp->alert_count >= ALERT_RING_CAP) {
            /* Drop oldest alert if completely overflowing (should not occur under normal flush) */
            exp->alert_bytes -= exp->alert_slots[exp->alert_head].len;
            exp->alert_head = (exp->alert_head + 1) % ALERT_RING_CAP;
            exp->alert_count--;
        }
        struct event_slot *s = &exp->alert_slots[exp->alert_tail];
        memcpy(s->json, event_json, len);
        s->json[len] = '\0';
        s->len = len;

        exp->alert_tail = (exp->alert_tail + 1) % ALERT_RING_CAP;
        exp->alert_count++;
        exp->alert_bytes += len;

        if (exp->alert_count == 1 && exp->telemetry_count == 0) {
            exp->oldest_event_sec = now.tv_sec;
        }

        /* Immediate wake-up on alert */
        pthread_cond_signal(&exp->cond);
    } else {
        if (exp->telemetry_count >= TELEMETRY_RING_CAP) {
            /* Drop oldest telemetry slot */
            exp->telemetry_bytes -= exp->telemetry_slots[exp->telemetry_head].len;
            exp->telemetry_head = (exp->telemetry_head + 1) % TELEMETRY_RING_CAP;
            exp->telemetry_count--;
            exp->dropped_since_last++;
            exp->dropped_total++;
        }

        struct event_slot *s = &exp->telemetry_slots[exp->telemetry_tail];
        memcpy(s->json, event_json, len);
        s->json[len] = '\0';
        s->len = len;

        exp->telemetry_tail = (exp->telemetry_tail + 1) % TELEMETRY_RING_CAP;
        exp->telemetry_count++;
        exp->telemetry_bytes += len;

        if (exp->alert_count == 0 && exp->telemetry_count == 1) {
            exp->oldest_event_sec = now.tv_sec;
        }

        int total_count = exp->alert_count + exp->telemetry_count;
        size_t total_bytes = exp->alert_bytes + exp->telemetry_bytes;
        if (total_count >= 256 || total_bytes >= 64 * 1024) {
            pthread_cond_signal(&exp->cond);
        }
    }

    pthread_mutex_unlock(&exp->lock);
    return 0;
}

uint64_t exporter_get_dropped_total(const struct exporter *exp)
{
    if (!exp) return 0;
    return exp->dropped_total;
}
