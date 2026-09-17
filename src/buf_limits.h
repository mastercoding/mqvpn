// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * buf_limits.h — the [Advanced] receive-buffering limits.
 *
 * Four knobs that bound how much a receiver may hold for ONE peer. Two of
 * them stop it reading and let QUIC flow control do the work (RFC 9000 §4.1);
 * TWO OF THEM CLOSE THE TUNNEL INSTEAD — read blocked_buf_per_stream below
 * before setting anything.
 * They are grouped in a struct, rather than spelled out four times, because
 * they are needed on BOTH sides and the CLI→library bridge is therefore two
 * call sites (src/platform/client_config_bridge.c and
 * linux_platform_run_server() in src/platform/linux/platform_linux.c).
 * mqvpn_reorder_config_t and mqvpn_hybrid_config_t are bridged the same way
 * for the same reason; see the header comment on client_config_bridge.c for
 * the regression that convention descends from.
 *
 * WHY BOTH SIDES, when RecvRateLimit next door is deliberately client-only:
 * RecvRateLimit is a conn-level RATE cap, and on a server it would throttle
 * every client's uplink. These four are per-stream/per-connection BUFFER
 * bounds, and for an upload the SERVER is the receiver with exactly the
 * same unbounded buffer a client has on a download (both call
 * xqc_h3_request_recv_body — src/mqvpn_server.c and src/hybrid/tcp_egress.c).
 * A bound that only ever binds on the client leaves the upload direction
 * exactly where it was.
 *
 * EVERY FIELD IS 0 BY DEFAULT and 0 means "leave xquic's own default alone",
 * so a config that names none of them is byte-for-byte the behaviour of the
 * release before they existed. Values belong with a measurement of the
 * deployment they are for, not with this plumbing.
 */
#ifndef MQVPN_BUF_LIMITS_H
#define MQVPN_BUF_LIMITS_H

#include <stdint.h>

/* Upper bound for the four H3 buffer limits.
 *
 * xquic types them size_t; the config surface parses uint64. 2^32-1 is the
 * largest value that cannot silently truncate on a 32-bit build (mips/arm
 * OpenWrt targets), and it is already four orders of magnitude past any
 * sane setting on a 1 GB device, so the clamp costs nothing real. */
#define MQVPN_BUF_LIMIT_MAX 0xffffffffULL

/* Upper bound for MaxRecvWindow: xquic types max_recv_window uint32_t, so
 * this is the field's own range, not a policy choice. For reference the
 * built-in per-stream window xquic uses when this is 0 is XQC_MAX_RECV_WINDOW
 * = 16 MiB; a value ABOVE that raises the window rather than lowering it. */
#define MQVPN_MAX_RECV_WINDOW_MAX 0xffffffffULL

typedef struct mqvpn_buf_limits_s {
    /* xqc_conn_settings_t.max_body_buf_per_stream: buffered HTTP/3 DATA
     * payload ONE request may hold before the H3 layer stops reading its
     * transport stream. 0 = unbounded, which is what every release before the
     * field existed did. This one is real backpressure: the read point
     * freezes, the window stops advancing, the peer is told to wait, and the
     * request resumes when the application drains. Nothing is dropped and no
     * connection is closed.
     *
     * PER STREAM AND ONLY PER STREAM. There is no companion connection-wide
     * key, and that is deliberate rather than missing: a request can only be
     * suspended on bytes its own application can free. A connection-wide
     * companion would suspend a request holding ZERO bytes because of bytes
     * a different request held; with nothing of its own to drain, that
     * request never resumes, its delivered bytes are never read for the life
     * of the connection, and the tunnel goes on reporting healthy. (We built
     * one while developing this, on our own branch, and that is how it
     * behaved; it is not in any published xquic.) So the aggregate across
     * concurrent
     * requests is NOT bounded here: it is
     * (backlogged requests x h3_body_buf_per_stream), and the lever for it is
     * max_recv_window below, which dominates the sum anyway — a suspended
     * request holds at most this many parsed bytes against up to a full
     * receive window of un-reassembled ones (262,144 against 16,655,150 on
     * the same stream at the same instant, measured on our own two-path
     * test rig — see website/guide/configuration.md).
     *
     * READ THE ORDERING NOTE ON max_recv_window BELOW BEFORE SETTING THIS. */
    uint64_t h3_body_buf_per_stream;

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
     * ================== THESE TWO ARE NOT BACKPRESSURE ==================
     * EXCEEDING EITHER LIMIT CLOSES THE HTTP/3 CONNECTION — the tunnel —
     * with H3_EXCESSIVE_LOAD. Not a pause, not a drop, not a reset of the
     * offending stream: the whole tunnel goes down and every TCP flow on it
     * dies with it. Two sites do it, both unconditional:
     * xqc_h3_stream_process_in() and xqc_h3_stream_process_blocked_data(),
     * via XQC_H3_CONN_ERR(h3c, H3_EXCESSIVE_LOAD, ...). The value you choose
     * is the amount of decode-blocked data that is allowed to arrive before
     * the tunnel is torn down. At 25 MB/s, 1 MiB is about 42 ms of blocked
     * time on one request.
     * ====================================================================
     *
     * ASYMMETRIC DEFAULT, and this is the second trap: xquic applies its
     * internal 1 MiB / 8 MiB defaults for these two ONLY inside
     * xqc_server_set_conn_settings(); the client path assigns the whole
     * settings struct with no defaulting. So 0 means 1 MiB / 8 MiB on a
     * SERVER — where the fatal branch has therefore been armed since before
     * these keys existed — and UNBOUNDED on a CLIENT.
     *
     * The consequence is that there is no safe value, only a choice of
     * failure: a number, and a legitimate peer behind a deep queue can take
     * the tunnel down; or 0 on a client, and one decode-blocked request can
     * grow without bound the way an unbounded body buffer can. Choose it
     * deliberately and say which you chose. What we measured, and on what,
     * is in website/guide/configuration.md under BlockedBufPerStream. */
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

/* ── What this build's xquic can actually honour ──────────────────────
 *
 * Two of the four fields above landed in xqc_conn_settings_t later than the
 * other two, so which of them exist depends on the third_party/xquic pin:
 * max_blocked_buf_per_stream/_per_conn have been there for a while,
 * max_body_buf_per_stream and max_recv_window have not. CMake probes for
 * each (check_struct_has_member) and defines MQVPN_HAVE_XQC_* for the ones
 * it finds; mqvpn_build_conn_settings() assigns only those.
 *
 * That leaves exactly one thing that must not happen: a key an operator has
 * written being accepted, stored and then never applied. H3BodyBufPerStream
 * exists to bound memory, so a build that cannot apply it must say so rather
 * than run unbounded and look configured. Hence this:
 *
 * Returns the [Advanced] key name of the FIRST limit that is set to a
 * non-zero value but whose xquic field is missing from this build, or NULL
 * when every set limit can be applied. All-zero always returns NULL — zero
 * means "leave xquic's own default alone" and needs no field to express.
 *
 * src/main.c calls this once after the config is loaded — below the
 * --status early exit, since reading a running instance's state opens no
 * connection — and refuses to start. There is no public setter for these
 * limits, so the CLI is the only way in and that one call covers every path
 * that brings a tunnel up. */
const char *mqvpn_buf_limits_unsupported(const mqvpn_buf_limits_t *bufs);

#endif /* MQVPN_BUF_LIMITS_H */
