// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * test_control_socket.c — unit tests for the control-API command dispatch
 * (src/platform/linux/control_socket.c::dispatch).
 *
 * dispatch()'s command routing, argument validation, error codes, and response
 * JSON shape had no unit-level test — test_control_response_bound.c only checks
 * the worst-case get_status buffer bound and never calls dispatch(). This test
 * drives dispatch() end to end with the server-facing API mocked, covering
 * handler logic (missing-arg handling, failure propagation, JSON shape) without
 * sudo/netns.
 *
 * dispatch() is static, so — following the test_reorder_rx / test_tcp_lane
 * idiom — this file #include's the .c directly and satisfies the mqvpn_server_*
 * / mqvpn_client_* / mqvpn_* symbols the handlers call with configurable stubs
 * (no mqvpn_server.c or mqvpn_client.c linked). Uses an always-active CHECK
 * (not assert()) so a Release build cannot no-op the assertions.
 *
 * Covers both socket modes: the server command set, and the client-mode
 * get_client_status, including the per-row mode gate that keeps a wrong-mode
 * request from reaching a handler that would dereference a NULL handle.
 */

#include "libmqvpn.h"
#include "mqvpn_internal.h" /* mqvpn_internal_fec_stats_t / _entry_t, reorder.h */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── Configurable stub state ──────────────────────────────────────────────── */

static int g_add_user_rc = MQVPN_OK;
static int g_remove_user_rc = MQVPN_OK;

static int g_list_users_n = 0;
static char g_list_users_names[MQVPN_MAX_USERS][64];

static int g_n_clients = 0;
static uint64_t g_uptime = 0;

static int g_client_info_n = 0;
static mqvpn_client_info_t g_client_info_tmpl;

static mqvpn_internal_client_reinject_t g_reinject_tmpl; /* configured per test */

static int g_fec_rc = 1;
static mqvpn_internal_fec_stats_t g_fec_tmpl;

static int g_all_fec_rc = 0;
static int g_all_fec_n = 0;

static int g_reorder_rc = 0;

/* Client-mode stub state. */
static mqvpn_client_state_t g_client_state = MQVPN_STATE_ESTABLISHED;
static int g_client_stats_rc = MQVPN_OK;
static mqvpn_stats_t g_client_stats;
static int g_client_paths_rc = MQVPN_OK;
static int g_client_n_paths = 0;
static mqvpn_path_info_t g_client_paths[MQVPN_MAX_PATHS];

/* ── Stubs for the server-facing API the handlers call ────────────────────── */

int
mqvpn_server_add_user(mqvpn_server_t *s, const char *u, const char *k)
{
    (void)s;
    (void)u;
    (void)k;
    return g_add_user_rc;
}

int
mqvpn_server_remove_user(mqvpn_server_t *s, const char *u)
{
    (void)s;
    (void)u;
    return g_remove_user_rc;
}

int
mqvpn_server_list_users(const mqvpn_server_t *s, char names[][64], int max)
{
    (void)s;
    int n = g_list_users_n < max ? g_list_users_n : max;
    for (int i = 0; i < n; i++) {
        strncpy(names[i], g_list_users_names[i], 63);
        names[i][63] = '\0';
    }
    return n;
}

int
mqvpn_server_get_stats(const mqvpn_server_t *s, mqvpn_stats_t *out)
{
    (void)s;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->bytes_tx = 111;
    out->tcp_flows_total = 7;
    out->udp_tx_sends = 1234;
    out->udp_tx_datagrams = 5678;
    return 0;
}

int
mqvpn_server_get_n_clients(const mqvpn_server_t *s)
{
    (void)s;
    return g_n_clients;
}

uint64_t
mqvpn_server_uptime_seconds(const mqvpn_server_t *s)
{
    (void)s;
    return g_uptime;
}

int
mqvpn_server_get_client_info(const mqvpn_server_t *s, mqvpn_client_info_t *out,
                             int max_clients, int *n_clients)
{
    (void)s;
    int n = g_client_info_n < max_clients ? g_client_info_n : max_clients;
    for (int i = 0; i < n; i++)
        out[i] = g_client_info_tmpl;
    *n_clients = n;
    return 0;
}

const char *
mqvpn_server_scheduler_label(const mqvpn_server_t *s)
{
    (void)s;
    return "wlb";
}

const char *
mqvpn_path_state_label(int state)
{
    return state == 2 ? "active" : "validating";
}

const char *
mqvpn_version_string(void)
{
    return "9.9.9-test";
}

int
mqvpn_server_get_client_reinject(const mqvpn_server_t *s,
                                 mqvpn_internal_client_reinject_t *out, int max)
{
    (void)s;
    if (max > 0) out[0] = g_reinject_tmpl;
    return max > 0 ? 1 : 0;
}

int
mqvpn_server_get_client_fec_stats(const mqvpn_server_t *s, const char *user,
                                  mqvpn_internal_fec_stats_t *out)
{
    (void)s;
    (void)user;
    if (g_fec_rc == 1) *out = g_fec_tmpl;
    return g_fec_rc;
}

int
mqvpn_server_get_all_fec_stats(const mqvpn_server_t *s, mqvpn_internal_fec_entry_t *out,
                               int max)
{
    (void)s;
    if (g_all_fec_rc < 0) return -1;
    int n = g_all_fec_n < max ? g_all_fec_n : max;
    for (int i = 0; i < n; i++) {
        snprintf(out[i].user, sizeof(out[i].user), "user%d", i);
        out[i].stats = g_fec_tmpl;
    }
    return n;
}

int
mqvpn_server_get_reorder_stats(const mqvpn_server_t *s, mqvpn_reorder_stats_t *out)
{
    (void)s;
    memset(out, 0, sizeof(*out));
    out->delivered_count = 55;
    return g_reorder_rc;
}

double
mqvpn_reorder_latency_percentile(const mqvpn_reorder_stats_t *st, double q)
{
    (void)st;
    (void)q;
    return 1.5;
}

double
mqvpn_reorder_latency_buffered_percentile(const mqvpn_reorder_stats_t *st, double q)
{
    (void)st;
    (void)q;
    return 2.5;
}

/* ── Stubs for the client-facing API get_client_status calls ──────────────── */

mqvpn_client_state_t
mqvpn_client_get_state(const mqvpn_client_t *c)
{
    (void)c;
    return g_client_state;
}

int
mqvpn_client_get_stats(const mqvpn_client_t *c, mqvpn_stats_t *out)
{
    (void)c;
    if (g_client_stats_rc != MQVPN_OK) return g_client_stats_rc;
    *out = g_client_stats;
    return MQVPN_OK;
}

int
mqvpn_client_get_paths(const mqvpn_client_t *c, mqvpn_path_info_t *out, int max_paths,
                       int *n_out)
{
    (void)c;
    if (g_client_paths_rc != MQVPN_OK) return g_client_paths_rc;
    int n = g_client_n_paths < max_paths ? g_client_n_paths : max_paths;
    for (int i = 0; i < n; i++)
        out[i] = g_client_paths[i];
    *n_out = n;
    return MQVPN_OK;
}

const char *
mqvpn_path_status_string(mqvpn_path_status_t status)
{
    switch (status) {
    case MQVPN_PATH_PENDING: return "pending";
    case MQVPN_PATH_ACTIVE: return "active";
    case MQVPN_PATH_DEGRADED: return "degraded";
    case MQVPN_PATH_STANDBY: return "standby";
    case MQVPN_PATH_CLOSED: return "closed";
    default: return "unknown";
    }
}

/* Pull in dispatch() + the command handlers (all static). */
#include "control_socket.c"

/* ── Harness ──────────────────────────────────────────────────────────────── */

static int g_failed = 0;
static char g_resp[CTRL_MAX_RESP_BYTES];
static int g_dummy_server; /* opaque sentinel — stubs never dereference it */

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            g_failed++;                                                     \
        }                                                                   \
    } while (0)

/* CHECK a substring is present, printing the actual response on mismatch. */
#define CHECK_HAS(needle)                                                       \
    do {                                                                        \
        if (strstr(g_resp, (needle)) == NULL) {                                 \
            fprintf(stderr, "FAIL %s:%d: response missing \"%s\"\n  got: %s\n", \
                    __FILE__, __LINE__, (needle), g_resp);                      \
            g_failed++;                                                         \
        }                                                                       \
    } while (0)

#define CHECK_EQ_STR(expected)                                                       \
    do {                                                                             \
        if (strcmp(g_resp, (expected)) != 0) {                                       \
            fprintf(stderr, "FAIL %s:%d: response != \"%s\"\n  got: %s\n", __FILE__, \
                    __LINE__, (expected), g_resp);                                   \
            g_failed++;                                                              \
        }                                                                            \
    } while (0)

/* Platform-owned RX offload counters the control socket borrows. Non-zero and
 * unequal so a get_stats regression that hardcodes 0 or swaps the pair cannot
 * pass. */
static uint64_t g_gro_receives = 61;
static uint64_t g_gro_datagrams = 83;

static void
call(const char *req)
{
    memset(g_resp, 0, sizeof(g_resp));
    /* Stack-built context: dispatch and the handlers only read ->server and
     * the borrowed counter pointers, never the libevent members. */
    ctrl_socket_t cs = {
        .server = (mqvpn_server_t *)&g_dummy_server,
        .gro_receives = &g_gro_receives,
        .gro_datagrams = &g_gro_datagrams,
    };
    dispatch(req, g_resp, sizeof(g_resp) - 2, &cs);
}

static int g_dummy_client; /* opaque sentinel — stubs never dereference it */
static char g_last_error[128];
static int g_reconnect_in_sec;

/* Client-mode context: cs.server stays NULL, which is what the dispatch mode
 * gate must protect the server handlers from. */
static void
call_client(const char *req)
{
    memset(g_resp, 0, sizeof(g_resp));
    ctrl_socket_t cs = {
        .client = (mqvpn_client_t *)&g_dummy_client,
        .cli_last_error = g_last_error,
        .cli_reconnect_in_sec = &g_reconnect_in_sec,
    };
    dispatch(req, g_resp, sizeof(g_resp) - 2, &cs);
}

/* ── Envelope / routing ───────────────────────────────────────────────────── */

static void
test_missing_cmd(void)
{
    call("{}");
    CHECK_EQ_STR("{\"ok\":false,\"error\":\"missing cmd\"}");
}

static void
test_unknown_cmd(void)
{
    call("{\"cmd\":\"frobnicate\"}");
    CHECK_EQ_STR("{\"ok\":false,\"error\":\"unknown cmd\"}");
}

/* ── add_user ─────────────────────────────────────────────────────────────── */

static void
test_add_user_success(void)
{
    g_add_user_rc = MQVPN_OK;
    call("{\"cmd\":\"add_user\",\"name\":\"alice\",\"key\":\"secret\"}");
    CHECK_EQ_STR("{\"ok\":true}");
}

static void
test_add_user_missing_name(void)
{
    call("{\"cmd\":\"add_user\",\"key\":\"secret\"}");
    CHECK_HAS("name and key required");
}

static void
test_add_user_missing_key(void)
{
    call("{\"cmd\":\"add_user\",\"name\":\"alice\"}");
    CHECK_HAS("name and key required");
}

static void
test_add_user_server_failure(void)
{
    g_add_user_rc = -5;
    call("{\"cmd\":\"add_user\",\"name\":\"alice\",\"key\":\"secret\"}");
    CHECK_HAS("add_user failed (-5)");
}

/* ── remove_user ──────────────────────────────────────────────────────────── */

static void
test_remove_user_success(void)
{
    g_remove_user_rc = MQVPN_OK;
    call("{\"cmd\":\"remove_user\",\"name\":\"alice\"}");
    CHECK_EQ_STR("{\"ok\":true}");
}

static void
test_remove_user_missing_name(void)
{
    call("{\"cmd\":\"remove_user\"}");
    CHECK_HAS("name required");
}

static void
test_remove_user_not_found(void)
{
    g_remove_user_rc = -1;
    call("{\"cmd\":\"remove_user\",\"name\":\"ghost\"}");
    CHECK_HAS("user not found");
}

/* ── list_users ───────────────────────────────────────────────────────────── */

static void
test_list_users_empty(void)
{
    g_list_users_n = 0;
    call("{\"cmd\":\"list_users\"}");
    CHECK_EQ_STR("{\"ok\":true,\"users\":[]}");
}

static void
test_list_users_two_entries(void)
{
    g_list_users_n = 2;
    strcpy(g_list_users_names[0], "alice");
    strcpy(g_list_users_names[1], "bob");
    call("{\"cmd\":\"list_users\"}");
    CHECK_EQ_STR("{\"ok\":true,\"users\":[\"alice\",\"bob\"]}");
}

/* ── get_stats ────────────────────────────────────────────────────────────── */

static void
test_get_stats(void)
{
    g_n_clients = 3;
    g_uptime = 4242;
    call("{\"cmd\":\"get_stats\"}");
    CHECK_HAS("\"ok\":true");
    CHECK_HAS("\"n_clients\":3");
    CHECK_HAS("\"bytes_tx\":111");
    CHECK_HAS("\"tcp_flows_total\":7");
    CHECK_HAS("\"uptime_sec\":4242");
    /* Offload counters reach the JSON from BOTH sources: udp_tx_* through
     * mqvpn_stats_t (the library issues those sends), udp_rx_* straight from
     * the platform's borrowed counters (GRO never crosses the library ABI).
     * The get_stats body is a hand-written field-by-field snprintf, so a new
     * mqvpn_stats_t field silently reads 0 here unless it is added in both
     * places — that is exactly the failure this pins. */
    CHECK_HAS("\"udp_tx_sends\":1234");
    CHECK_HAS("\"udp_tx_datagrams\":5678");
    CHECK_HAS("\"udp_rx_receives\":61");
    CHECK_HAS("\"udp_rx_datagrams\":83");
}

/* ── get_status ───────────────────────────────────────────────────────────── */

static void
test_get_status_empty(void)
{
    g_client_info_n = 0;
    call("{\"cmd\":\"get_status\"}");
    CHECK_EQ_STR("{\"ok\":true,\"n_clients\":0,\"clients\":[]}");
}

static void
test_get_status_one_client_with_path(void)
{
    memset(&g_client_info_tmpl, 0, sizeof(g_client_info_tmpl));
    strcpy(g_client_info_tmpl.username, "alice");
    strcpy(g_client_info_tmpl.endpoint, "1.2.3.4:443");
    g_client_info_tmpl.n_paths = 1;
    g_client_info_tmpl.paths[0].path_id = 7;
    g_client_info_tmpl.paths[0].state = 2; /* -> "active" */
    g_client_info_n = 1;
    memset(&g_reinject_tmpl, 0, sizeof(g_reinject_tmpl));

    call("{\"cmd\":\"get_status\"}");
    CHECK_HAS("\"n_clients\":1");
    CHECK_HAS("\"user\":\"alice\"");
    CHECK_HAS("\"endpoint\":\"1.2.3.4:443\"");
    CHECK_HAS("\"path_id\":7");
    CHECK_HAS("\"state_label\":\"active\"");
}

/* Alignment semantics (a): a reinject snapshot entry whose path_id matches
 * the client-info path emits its nonzero value. */
static void
test_get_status_reinject_matched_path_id(void)
{
    memset(&g_client_info_tmpl, 0, sizeof(g_client_info_tmpl));
    strcpy(g_client_info_tmpl.username, "alice");
    strcpy(g_client_info_tmpl.endpoint, "1.2.3.4:443");
    g_client_info_tmpl.n_paths = 1;
    g_client_info_tmpl.paths[0].path_id = 7;
    g_client_info_tmpl.paths[0].state = 2;
    g_client_info_n = 1;

    memset(&g_reinject_tmpl, 0, sizeof(g_reinject_tmpl));
    g_reinject_tmpl.n_paths = 1;
    g_reinject_tmpl.paths[0].path_id = 7;
    g_reinject_tmpl.paths[0].reinject_tx_bytes = 99999;

    call("{\"cmd\":\"get_status\"}");
    CHECK_HAS("\"path_id\":7");
    CHECK_HAS("\"reinject_tx_bytes\":99999");
}

/* Alignment semantics (b): a mismatched or wholly absent path_id in the
 * reinject snapshot both emit "reinject_tx_bytes":0 — the field is always
 * present so the JSON shape stays constant regardless of match. Two phases
 * pin the same constant-shape outcome from two different snapshot states. */
static void
test_get_status_reinject_mismatched_path_id(void)
{
    memset(&g_client_info_tmpl, 0, sizeof(g_client_info_tmpl));
    strcpy(g_client_info_tmpl.username, "alice");
    strcpy(g_client_info_tmpl.endpoint, "1.2.3.4:443");
    g_client_info_tmpl.n_paths = 1;
    g_client_info_tmpl.paths[0].path_id = 7;
    g_client_info_tmpl.paths[0].state = 2;
    g_client_info_n = 1;

    /* Phase 1: reinject snapshot has an entry, but its path_id mismatches. */
    memset(&g_reinject_tmpl, 0, sizeof(g_reinject_tmpl));
    g_reinject_tmpl.n_paths = 1;
    g_reinject_tmpl.paths[0].path_id = 42; /* mismatch vs client path_id 7 */
    g_reinject_tmpl.paths[0].reinject_tx_bytes = 99999;

    call("{\"cmd\":\"get_status\"}");
    CHECK_HAS("\"path_id\":7");
    CHECK_HAS("\"reinject_tx_bytes\":0");

    /* Phase 2: reinject snapshot has no entry at all (n_paths == 0). */
    memset(&g_reinject_tmpl, 0, sizeof(g_reinject_tmpl)); /* n_paths = 0 */

    call("{\"cmd\":\"get_status\"}");
    CHECK_HAS("\"path_id\":7");
    CHECK_HAS("\"reinject_tx_bytes\":0");
}

/* ── get_build_info ───────────────────────────────────────────────────────── */

static void
test_get_build_info(void)
{
    call("{\"cmd\":\"get_build_info\"}");
    CHECK_HAS("\"version\":\"9.9.9-test\"");
    CHECK_HAS("\"scheduler\":\"wlb\"");
    CHECK_HAS("\"fec_enabled\":");
}

/* ── get_fec_stats ────────────────────────────────────────────────────────── */

static void
seed_fec_tmpl(void)
{
    memset(&g_fec_tmpl, 0, sizeof(g_fec_tmpl));
    g_fec_tmpl.enable_fec = 1;
    g_fec_tmpl.mp_state = 1;
    g_fec_tmpl.mp_state_label = "active_with_standby";
    g_fec_tmpl.fec_send_cnt = 142;
    g_fec_tmpl.fec_recover_cnt = 17;
}

static void
test_get_fec_stats_missing_user(void)
{
    call("{\"cmd\":\"get_fec_stats\"}");
    CHECK_HAS("user required");
}

static void
test_get_fec_stats_user_not_found(void)
{
    g_fec_rc = 0;
    call("{\"cmd\":\"get_fec_stats\",\"user\":\"ghost\"}");
    CHECK_HAS("user not found");
}

static void
test_get_fec_stats_not_built(void)
{
    g_fec_rc = -1;
    call("{\"cmd\":\"get_fec_stats\",\"user\":\"alice\"}");
    CHECK_HAS("fec not built");
}

static void
test_get_fec_stats_success(void)
{
    seed_fec_tmpl();
    g_fec_rc = 1;
    call("{\"cmd\":\"get_fec_stats\",\"user\":\"alice\"}");
    CHECK_HAS("\"user\":\"alice\"");
    CHECK_HAS("\"mp_state_label\":\"active_with_standby\"");
    CHECK_HAS("\"fec_send_cnt\":142");
    CHECK_HAS("\"fec_recover_cnt\":17");
}

/* ── get_all_fec_stats ────────────────────────────────────────────────────── */

static void
test_get_all_fec_stats(void)
{
    seed_fec_tmpl();
    g_all_fec_rc = 0;
    g_all_fec_n = 2;
    call("{\"cmd\":\"get_all_fec_stats\"}");
    CHECK_HAS("\"n_clients\":2");
    CHECK_HAS("\"user\":\"user0\"");
    CHECK_HAS("\"user\":\"user1\"");
    CHECK_HAS("\"mp_state_label\":\"active_with_standby\"");
}

static void
test_get_all_fec_stats_not_built(void)
{
    g_all_fec_rc = -1;
    call("{\"cmd\":\"get_all_fec_stats\"}");
    CHECK_HAS("fec not built");
}

/* ── get_reorder_stats ────────────────────────────────────────────────────── */

static void
test_get_reorder_stats(void)
{
    g_reorder_rc = 0;
    call("{\"cmd\":\"get_reorder_stats\"}");
    CHECK_HAS("\"reorder\":{");
    CHECK_HAS("\"delivered_count\":55");
    CHECK_HAS("\"added_latency_p99_ms\":");
}

static void
test_get_reorder_stats_internal_error(void)
{
    /* Failure-branch parity with get_fec_stats / get_all_fec_stats: a negative
     * getter return must surface {"error":"internal error"}, not a malformed
     * or half-built reorder object. */
    g_reorder_rc = -1;
    call("{\"cmd\":\"get_reorder_stats\"}");
    CHECK_HAS("\"ok\":false");
    CHECK_HAS("internal error");
}

/* ── get_client_status (client mode) ──────────────────────────────────────── */

static void
reset_client(void)
{
    memset(&g_client_stats, 0, sizeof(g_client_stats));
    memset(g_client_paths, 0, sizeof(g_client_paths));
    memset(g_last_error, 0, sizeof(g_last_error));
    g_client_state = MQVPN_STATE_ESTABLISHED;
    g_client_stats_rc = MQVPN_OK;
    g_client_paths_rc = MQVPN_OK;
    g_client_n_paths = 0;
    g_reconnect_in_sec = 0;
}

static void
set_path(int i, const char *name, mqvpn_path_status_t st, int srtt, uint64_t tx,
         uint64_t rx)
{
    snprintf(g_client_paths[i].name, sizeof(g_client_paths[i].name), "%s", name);
    g_client_paths[i].status = st;
    g_client_paths[i].srtt_ms = srtt;
    g_client_paths[i].bytes_tx = tx;
    g_client_paths[i].bytes_rx = rx;
}

static void
test_client_status_established_two_paths(void)
{
    reset_client();
    g_client_stats.bytes_tx = 1000;
    g_client_stats.bytes_rx = 2000;
    g_client_stats.srtt_ms = 31;
    g_client_stats.dgram_lost = 7;
    g_client_stats.tcp_flows_active = 3;
    g_client_n_paths = 2;
    set_path(0, "eth0", MQVPN_PATH_ACTIVE, 28, 900, 1900);
    set_path(1, "wwan0", MQVPN_PATH_DEGRADED, 144, 100, 100);

    call_client("{\"cmd\":\"get_client_status\"}");
    CHECK_HAS("\"ok\":true");
    CHECK_HAS("\"mode\":\"client\"");
    CHECK_HAS("\"state\":\"established\"");
    CHECK_HAS("\"bytes_tx\":1000");
    CHECK_HAS("\"srtt_ms\":31");
    CHECK_HAS("\"dgram_lost\":7");
    CHECK_HAS("\"tcp_flows_active\":3");
    CHECK_HAS("\"n_paths\":2");
    CHECK_HAS("{\"name\":\"eth0\",\"status\":\"active\",\"srtt_ms\":28,"
              "\"bytes_tx\":900,\"bytes_rx\":1900}");
    CHECK_HAS("{\"name\":\"wwan0\",\"status\":\"degraded\",\"srtt_ms\":144,"
              "\"bytes_tx\":100,\"bytes_rx\":100}");
    /* The client does not expose mqvpn_path_stats_t, so these must be ABSENT
     * rather than zero — a consumer must not mistake "not available on this
     * end" for "measured zero". */
    CHECK(strstr(g_resp, "pkt_lost") == NULL);
    CHECK(strstr(g_resp, "min_rtt") == NULL);
    CHECK(strstr(g_resp, "cwnd") == NULL);
    CHECK(strstr(g_resp, "reinject_tx_bytes") == NULL);
}

static void
test_client_status_no_paths(void)
{
    reset_client();
    g_client_state = MQVPN_STATE_CONNECTING;

    call_client("{\"cmd\":\"get_client_status\"}");
    CHECK_HAS("\"state\":\"connecting\"");
    CHECK_HAS("\"n_paths\":0");
    CHECK_HAS("\"paths\":[]");
}

/* The two fields that distinguish "the server rejected your key" from "the
 * server did not answer". Neither is reachable through a library accessor. */
static void
test_client_status_reports_failure_reason(void)
{
    reset_client();
    g_client_state = MQVPN_STATE_RECONNECTING;
    snprintf(g_last_error, sizeof(g_last_error), "PSK auth failure (403)");
    g_reconnect_in_sec = 5;

    call_client("{\"cmd\":\"get_client_status\"}");
    CHECK_HAS("\"state\":\"reconnecting\"");
    CHECK_HAS("\"last_error\":\"PSK auth failure (403)\"");
    CHECK_HAS("\"reconnect_in_sec\":5");
}

static void
test_client_status_stats_unavailable(void)
{
    reset_client();
    g_client_stats_rc = MQVPN_ERR_INVALID_STATE;

    call_client("{\"cmd\":\"get_client_status\"}");
    CHECK_EQ_STR("{\"ok\":false,\"error\":\"stats unavailable\"}");
}

/* Linux permits almost any byte except '/' and NUL in an interface name, and
 * nothing validates one for JSON safety. A quote must not escape the string. */
static void
test_client_status_sanitizes_iface_name(void)
{
    reset_client();
    g_client_n_paths = 1;
    set_path(0, "e\"th 0", MQVPN_PATH_ACTIVE, 10, 1, 2);

    call_client("{\"cmd\":\"get_client_status\"}");
    CHECK_HAS("\"name\":\"e_th_0\"");
    CHECK_HAS("\"ok\":true");
}

/* Both diagnostic pointers are documented as optional. */
static void
test_client_status_null_diagnostics(void)
{
    reset_client();
    memset(g_resp, 0, sizeof(g_resp));
    ctrl_socket_t cs = {.client = (mqvpn_client_t *)&g_dummy_client};
    dispatch("{\"cmd\":\"get_client_status\"}", g_resp, sizeof(g_resp) - 2, &cs);
    CHECK_HAS("\"last_error\":\"\"");
    CHECK_HAS("\"reconnect_in_sec\":0");
}

/* ── Mode gate ────────────────────────────────────────────────────────────── */

/* Every server handler dereferences cs->server, which is NULL on a client
 * socket. The per-row mode column in ctrl_cmds[] is what stops the request
 * before it gets there — and answering "server-only command" rather than
 * "unknown cmd" lets a consumer tell an old build from a wrong endpoint. */
static void
test_mode_gate_server_only_command(void)
{
    reset_client();
    static const char *server_cmds[] = {
        "add_user",      "remove_user",       "list_users",
        "get_stats",     "get_status",        "get_build_info",
        "get_fec_stats", "get_all_fec_stats", "get_reorder_stats",
    };
    char req[64];
    for (size_t i = 0; i < sizeof(server_cmds) / sizeof(server_cmds[0]); i++) {
        snprintf(req, sizeof(req), "{\"cmd\":\"%s\"}", server_cmds[i]);
        call_client(req);
        CHECK_EQ_STR("{\"ok\":false,\"error\":\"server-only command\"}");
    }
}

static void
test_mode_gate_client_only_command(void)
{
    call("{\"cmd\":\"get_client_status\"}");
    CHECK_EQ_STR("{\"ok\":false,\"error\":\"client-only command\"}");
}

int
main(void)
{
    test_missing_cmd();
    test_unknown_cmd();

    test_add_user_success();
    test_add_user_missing_name();
    test_add_user_missing_key();
    test_add_user_server_failure();

    test_remove_user_success();
    test_remove_user_missing_name();
    test_remove_user_not_found();

    test_list_users_empty();
    test_list_users_two_entries();

    test_get_stats();

    test_get_status_empty();
    test_get_status_one_client_with_path();
    test_get_status_reinject_matched_path_id();
    test_get_status_reinject_mismatched_path_id();

    test_get_build_info();

    test_get_fec_stats_missing_user();
    test_get_fec_stats_user_not_found();
    test_get_fec_stats_not_built();
    test_get_fec_stats_success();

    test_get_all_fec_stats();
    test_get_all_fec_stats_not_built();

    test_get_reorder_stats();
    test_get_reorder_stats_internal_error();

    test_client_status_established_two_paths();
    test_client_status_no_paths();
    test_client_status_reports_failure_reason();
    test_client_status_stats_unavailable();
    test_client_status_sanitizes_iface_name();
    test_client_status_null_diagnostics();

    test_mode_gate_server_only_command();
    test_mode_gate_client_only_command();

    if (g_failed) {
        fprintf(stderr, "test_control_socket: %d CHECK(s) FAILED\n", g_failed);
        return 1;
    }
    printf("test_control_socket: all OK\n");
    return 0;
}
