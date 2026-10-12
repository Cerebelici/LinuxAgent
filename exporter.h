#ifndef CERBERUS_EXPORTER_H
#define CERBERUS_EXPORTER_H

#include <stddef.h>
#include <stdint.h>
#include "identity.h"

#define ALERT_RING_CAP 512
#define TELEMETRY_RING_CAP 2048
#define EVENT_JSON_MAX 1024

struct exporter_config {
    char sentinel_url[512];
    char enroll_token[256];
    char ca_file[512];
    int insecure_http;
    int verbose;
};

struct exporter;

/* Create exporter instance */
struct exporter *exporter_create(const struct exporter_config *cfg, struct agent_identity *ident);

/* Start sender background thread */
int exporter_start(struct exporter *exp);

/* Stop sender thread and free resources */
void exporter_stop(struct exporter *exp);

/* Enqueue an event JSON string into alert or telemetry lane */
int exporter_enqueue(struct exporter *exp, const char *event_json, size_t len, int is_alert);

/* Get total dropped telemetry events count */
uint64_t exporter_get_dropped_total(const struct exporter *exp);

#endif /* CERBERUS_EXPORTER_H */
