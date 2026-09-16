// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * buf_limits.h — the [Advanced] receive-buffering limits.
 *
 * Five knobs that bound how much a receiver may hold for ONE peer before it
 * stops reading and lets QUIC flow control do the work (RFC 9000 §4.1).
 * They are grouped in a struct, rather than spelled out five times, because
 * they are needed on BOTH sides and the CLI→library bridge is therefore two
 * call sites (src/platform/client_config_bridge.c and
 * linux_platform_run_server() in src/platform/linux/platform_linux.c).
 * mqvpn_reorder_config_t and mqvpn_hybrid_config_t are bridged the same way
 * for the same reason; see the header comment on client_config_bridge.c for
 * the regression that convention descends from.
 *
 * WHY BOTH SIDES, when RecvRateLimit next door is deliberately client-only:
 * RecvRateLimit is a conn-level RATE cap, and on a server it would throttle
 * every client's uplink. These five are per-stream/per-connection BUFFER
 * bounds, and for an upload the concentrator is the receiver with exactly
 * the same unbounded buffer the box has on a download (both call
 * xqc_h3_request_recv_body — src/mqvpn_server.c and src/hybrid/tcp_egress.c).
 * A bound that only ever binds on the client leaves the upload direction
 * exactly where it was.
 *
 * EVERY FIELD IS 0 BY DEFAULT and 0 means "leave xquic's own default alone",
 * so a config that names none of them is byte-for-byte the behaviour of the
 * release before they existed. Values are a product decision that belongs
 * with measurement, not with this plumbing.
 */
#ifndef MQVPN_BUF_LIMITS_H
#define MQVPN_BUF_LIMITS_H

#include <stdint.h>

/* Upper bound for the four H3 buffer limits.
 *
 * xquic types them size_t; the config surface parses uint64. 2^32-1 is the
 * largest value that cannot silently truncate on a 32-bit build (mips/arm
 * OpenWrt targets), and it is already four orders of magnitude past any
 * sane setting on a 1 GB box, so the clamp costs nothing real. */
#define MQVPN_BUF_LIMIT_MAX 0xffffffffULL

/* Upper bound for MaxRecvWindow: xquic types max_recv_window uint32_t, so
 * this is the field's own range, not a policy choice. For reference the
 * built-in per-stream window xquic uses when this is 0 is XQC_MAX_RECV_WINDOW
 * = 16 MiB; a value ABOVE that raises the window rather than lowering it. */
#define MQVPN_MAX_RECV_WINDOW_MAX 0xffffffffULL

typedef struct mqvpn_buf_limits_s {
    /* xqc_conn_settings_t.max_body_buf_per_stream / _per_conn: buffered
     * HTTP/3 DATA payload a request (resp. a whole connection) may hold
     * before the H3 layer stops reading the transport stream. 0 = unbounded,
     * which is what every release before the field existed did.
     *
     * READ THE ORDERING NOTE ON max_recv_window BELOW BEFORE SETTING THESE. */
    uint64_t h3_body_buf_per_stream;
    uint64_t h3_body_buf_per_conn;

    /* xqc_conn_settings_t.max_blocked_buf_per_stream / _per_conn: the QPACK
     * decode-blocked buffer, which is a SECOND queue on the same request and
     * is NOT covered by the body-buf bound above. The honest peak for one
     * wedged request is the sum:
     *
     *     h3_body_buf_per_stream + blocked_buf_per_stream + one 4 KB chunk
     *
     * mqvpn enables the QPACK dynamic table at both ends
     * (qpack_enc/dec_max_table_capacity = 16 KiB, qpack_blocked_streams = 64
     * in mqvpn_client.c / mqvpn_server.c), so that path is reachable, not
     * theoretical.
     *
     * ASYMMETRIC DEFAULT, and this is the trap: xquic applies its internal
     * 1 MB / 8 MB defaults for these two ONLY inside
     * xqc_server_set_conn_settings(); the client path assigns the whole
     * settings struct with no defaulting. So 0 means 1 MB / 8 MB on the
     * CONCENTRATOR and UNBOUNDED on the BOX. Whoever sets
     * h3_body_buf_per_stream must set blocked_buf_per_stream in the same
     * breath or the box's bound is a bound on one of two queues. */
    uint64_t blocked_buf_per_stream;
    uint64_t blocked_buf_per_conn;

    /* xqc_conn_settings_t.max_recv_window: ceiling on the PER-STREAM receive
     * window (the advertised initial_max_stream_data_bidi_local/_remote and
     * the auto-tune doubling). 0 = xquic's XQC_MAX_RECV_WINDOW, 16 MiB.
     * This is NOT the connection-level window, which stays untouched.
     *
     * ORDERING: the window and xquic's buffered-node reassembly cap have to
     * be read together. A window of W bytes against an average frame of L
     * bytes permits W/L buffered nodes; if that exceeds the cap, the cap
     * trips first and the peer sees whole-packet drops and a silent stall
     * instead of flow-control backpressure. Lowering the window is what buys
     * the body-buf bound its margin — set this one first. */
    uint64_t max_recv_window;
} mqvpn_buf_limits_t;

#endif /* MQVPN_BUF_LIMITS_H */
