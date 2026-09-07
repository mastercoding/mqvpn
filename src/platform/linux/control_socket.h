// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

/*
 * control_socket.h — TCP control API for mqvpn
 *
 * Listens on a TCP port (default: 127.0.0.1 only) and accepts JSON commands.
 *
 * Two modes. A socket created with ctrl_socket_create() is bound to a server
 * and serves the management + monitoring commands. A socket created with
 * ctrl_socket_create_client() is bound to a client and serves exactly one
 * command, get_client_status, which reports this client's own tunnel state
 * and per-path detail. Server-only commands answer
 * {"ok":false,"error":"server-only command"} on a client socket, and vice
 * versa; the transport, framing, size caps and connection caps are shared.
 * All I/O is driven by the same libevent loop as the VPN — no locking needed.
 *
 * Protocol: one JSON object per connection (newline-terminated or EOF).
 * Response: one JSON object followed by a newline, then connection closes.
 *
 * Example:
 *   echo '{"cmd":"add_user","name":"carol","key":"carol-secret"}' \
 *       | nc 127.0.0.1 9090
 */

#ifndef MQVPN_CONTROL_SOCKET_H
#define MQVPN_CONTROL_SOCKET_H

#include "libmqvpn.h"

/* Forward-decl so consumers that only want CTRL_MAX_RESP_BYTES (e.g.
 * tests/test_control_response_bound.c) don't transitively pull libevent
 * headers. The control_socket.c implementation itself includes
 * <event2/event.h> directly. */
struct event_base;

/* Maximum response size. Worst-case get_status with MQVPN_MAX_USERS=64 and
 * MQVPN_MAX_PATHS=8 produces ~210 KB; round up to 256 KB. The exact bound is
 * verified by tests/test_control_response_bound.c — bump it if either limit
 * grows. */
#define CTRL_MAX_RESP_BYTES (256 * 1024)

typedef struct ctrl_socket_s ctrl_socket_t;

/* addr defaults to "127.0.0.1" when NULL.
 *
 * gro_receives / gro_datagrams point at the platform's live receive-side UDP
 * offload counters, reported by get_stats as udp_rx_*. They are borrowed, not
 * copied: the caller must keep them alive for the socket's lifetime. Both may
 * be NULL (reported as 0).
 *
 * They come in as parameters rather than through mqvpn_stats_t because UDP
 * GRO is enabled and un-coalesced entirely in the platform layer — the
 * library never observes it, so routing these through the library ABI would
 * add fields nothing in the library produces. The transmit-side pair does
 * cross that ABI (mqvpn_stats_t.udp_tx_*) precisely because the library
 * issues those sends itself. Same split as the ABI has for UdpGso vs UdpGro.
 *
 * No synchronization: the platform's read callbacks are the only writers and
 * run on the same libevent loop as this socket's handlers. */
ctrl_socket_t *ctrl_socket_create(struct event_base *eb, const char *addr, int port,
                                  mqvpn_server_t *server, const uint64_t *gro_receives,
                                  const uint64_t *gro_datagrams);

/* Client-mode listener. Same addr defaulting and same non-loopback warning.
 *
 * Serves only get_client_status, which is assembled entirely from the public
 * client accessors (mqvpn_client_get_state / _get_stats / _get_paths), so this
 * adds no library surface and no ABI change. The richer per-path fields the
 * server reports (min_rtt, cwnd, pkt_lost, reinject_tx_bytes) live in
 * mqvpn_path_stats_t, which the client does not expose; they are absent here
 * rather than zero-filled.
 *
 * There is no gro_receives/gro_datagrams pair: those counters exist to feed
 * get_stats's udp_rx_* fields, which are a server-side command.
 *
 * last_error and reconnect_in_sec are borrowed, not copied, exactly like the
 * server's gro counters: the platform ctx outlives this socket, and the
 * platform's callbacks are the only writers, running on the same libevent
 * loop as this socket's handlers. Both may be NULL (reported as "" and 0).
 * They carry what the library's accessors cannot: mqvpn_client_get_state()
 * reports "reconnecting" but not why, and the backoff delay is announced only
 * through mqvpn_reconnect_scheduled_fn. */
ctrl_socket_t *ctrl_socket_create_client(struct event_base *eb, const char *addr,
                                         int port, mqvpn_client_t *client,
                                         const char *last_error,
                                         const int *reconnect_in_sec);

void ctrl_socket_destroy(ctrl_socket_t *cs);

#endif /* MQVPN_CONTROL_SOCKET_H */
