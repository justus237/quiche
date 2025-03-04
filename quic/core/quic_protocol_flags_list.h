// Copyright (c) 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// NOLINT(build/header_guard)
// This file intentionally does not have header guards, it's intended to be
// included multiple times, each time with a different definition of
// QUIC_PROTOCOL_FLAG.

#if defined(QUIC_PROTOCOL_FLAG)

QUIC_PROTOCOL_FLAG(
    bool,
    quic_allow_chlo_buffering,
    true,
    "If true, allows packets to be buffered in anticipation of a "
    "future CHLO, and allow CHLO packets to be buffered until next "
    "iteration of the event loop.")

QUIC_PROTOCOL_FLAG(bool,
                   quic_disable_pacing_for_perf_tests,
                   false,
                   "If true, disable pacing in QUIC")

// Note that single-packet CHLOs are only enforced for Google QUIC versions that
// do not use CRYPTO frames. This currently means only Q043 and Q046. All other
// versions of QUIC (both Google QUIC and IETF) allow multi-packet CHLOs
// regardless of the value of this flag.
QUIC_PROTOCOL_FLAG(bool, quic_enforce_single_packet_chlo, true,
                   "If true, enforce that sent QUIC CHLOs fit in one packet. "
                   "Only applies to Q043 and Q046.")

// Currently, this number is quite conservative.  At a hypothetical 1000 qps,
// this means that the longest time-wait list we should see is:
//   200 seconds * 1000 qps = 200000.
// Of course, there are usually many queries per QUIC connection, so we allow a
// factor of 3 leeway.
QUIC_PROTOCOL_FLAG(int64_t,
                   quic_time_wait_list_max_connections,
                   600000,
                   "Maximum number of connections on the time-wait list.  "
                   "A negative value implies no configured limit.")

QUIC_PROTOCOL_FLAG(int64_t,
                   quic_time_wait_list_seconds,
                   200,
                   "Time period for which a given connection_id should live in "
                   "the time-wait state.")

// This number is relatively conservative. For example, there are at most 1K
// queued stateless resets, which consume 1K * 21B = 21KB.
QUIC_PROTOCOL_FLAG(
    uint64_t, quic_time_wait_list_max_pending_packets, 1024,
    "Upper limit of pending packets in time wait list when writer is blocked.")

// Stop sending a reset if the recorded number of addresses that server has
// recently sent stateless reset to exceeds this limit.
QUIC_PROTOCOL_FLAG(uint64_t, quic_max_recent_stateless_reset_addresses, 1024,
                   "Max number of recorded recent reset addresses.")

// After this timeout, recent reset addresses will be cleared.
// FLAGS_quic_max_recent_stateless_reset_addresses * (1000ms /
// FLAGS_quic_recent_stateless_reset_addresses_lifetime_ms) is roughly the max
// reset per second. For example, 1024 * (1000ms / 1000ms) = 1K reset per
// second.
QUIC_PROTOCOL_FLAG(
    uint64_t, quic_recent_stateless_reset_addresses_lifetime_ms, 1000,
    "Max time that a client address lives in recent reset addresses set.")

QUIC_PROTOCOL_FLAG(double,
                   quic_bbr_cwnd_gain,
                   2.0f,
                   "Congestion window gain for QUIC BBR during PROBE_BW phase.")

QUIC_PROTOCOL_FLAG(
    int32_t,
    quic_buffered_data_threshold,
    8 * 1024,
    "If buffered data in QUIC stream is less than this "
    "threshold, buffers all provided data or asks upper layer for more data")

QUIC_PROTOCOL_FLAG(
    uint64_t,
    quic_send_buffer_max_data_slice_size,
    4 * 1024,
    "Max size of data slice in bytes for QUIC stream send buffer.")

QUIC_PROTOCOL_FLAG(
    int32_t,
    quic_lumpy_pacing_size,
    2,
    "Number of packets that the pacing sender allows in bursts during "
    "pacing. This flag is ignored if a flow's estimated bandwidth is "
    "lower than 1200 kbps.")

QUIC_PROTOCOL_FLAG(
    double,
    quic_lumpy_pacing_cwnd_fraction,
    0.25f,
    "Congestion window fraction that the pacing sender allows in bursts "
    "during pacing.")

QUIC_PROTOCOL_FLAG(
    int32_t, quic_lumpy_pacing_min_bandwidth_kbps, 1200,
    "The minimum estimated client bandwidth below which the pacing sender will "
    "not allow bursts.")

QUIC_PROTOCOL_FLAG(int32_t,
                   quic_max_pace_time_into_future_ms,
                   10,
                   "Max time that QUIC can pace packets into the future in ms.")

QUIC_PROTOCOL_FLAG(
    double,
    quic_pace_time_into_future_srtt_fraction,
    0.125f,  // One-eighth smoothed RTT
    "Smoothed RTT fraction that a connection can pace packets into the future.")

QUIC_PROTOCOL_FLAG(bool,
                   quic_export_write_path_stats_at_server,
                   false,
                   "If true, export detailed write path statistics at server.")

QUIC_PROTOCOL_FLAG(bool,
                   quic_disable_version_negotiation_grease_randomness,
                   false,
                   "If true, use predictable version negotiation versions.")

QUIC_PROTOCOL_FLAG(bool,
                   quic_enable_http3_grease_randomness,
                   true,
                   "If true, use random greased settings and frames.")

QUIC_PROTOCOL_FLAG(
    bool, quic_enable_chaos_protection, true,
    "If true, use chaos protection to randomize client initials.")

QUIC_PROTOCOL_FLAG(int64_t,
                   quic_max_tracked_packet_count,
                   10000,
                   "Maximum number of tracked packets.")

QUIC_PROTOCOL_FLAG(
    bool,
    quic_client_convert_http_header_name_to_lowercase,
    true,
    "If true, HTTP request header names sent from QuicSpdyClientBase(and "
    "descendents) will be automatically converted to lower case.")

QUIC_PROTOCOL_FLAG(
    int32_t,
    quic_bbr2_default_probe_bw_base_duration_ms,
    2000,
    "The default minimum duration for BBRv2-native probes, in milliseconds.")

QUIC_PROTOCOL_FLAG(
    int32_t,
    quic_bbr2_default_probe_bw_max_rand_duration_ms,
    1000,
    "The default upper bound of the random amount of BBRv2-native "
    "probes, in milliseconds.")

QUIC_PROTOCOL_FLAG(
    int32_t,
    quic_bbr2_default_probe_rtt_period_ms,
    10000,
    "The default period for entering PROBE_RTT, in milliseconds.")

QUIC_PROTOCOL_FLAG(
    double,
    quic_bbr2_default_loss_threshold,
    0.02,
    "The default loss threshold for QUIC BBRv2, should be a value "
    "between 0 and 1.")

QUIC_PROTOCOL_FLAG(
    int32_t,
    quic_bbr2_default_startup_full_loss_count,
    8,
    "The default minimum number of loss marking events to exit STARTUP.")

QUIC_PROTOCOL_FLAG(
    int32_t,
    quic_bbr2_default_probe_bw_full_loss_count,
    2,
    "The default minimum number of loss marking events to exit PROBE_UP phase.")

QUIC_PROTOCOL_FLAG(
    double,
    quic_bbr2_default_inflight_hi_headroom,
    0.15,
    "The default fraction of unutilized headroom to try to leave in path "
    "upon high loss.")

QUIC_PROTOCOL_FLAG(
    int32_t,
    quic_bbr2_default_initial_ack_height_filter_window,
    10,
    "The default initial value of the max ack height filter's window length.")

QUIC_PROTOCOL_FLAG(
    double,
    quic_ack_aggregation_bandwidth_threshold,
    1.0,
    "If the bandwidth during ack aggregation is smaller than (estimated "
    "bandwidth * this flag), consider the current aggregation completed "
    "and starts a new one.")

// TODO(b/153892665): Change the default value of
// quic_anti_amplification_factor back to 3 when cert compression is
// supported.
QUIC_PROTOCOL_FLAG(
    int32_t,
    quic_anti_amplification_factor,
    5,
    3,
    "Anti-amplification factor. Before address validation, server will "
    "send no more than factor times bytes received.")

QUIC_PROTOCOL_FLAG(
    int32_t,
    quic_max_buffered_crypto_bytes,
    16 * 1024,  // 16 KB
    "The maximum amount of CRYPTO frame data that can be buffered.")

QUIC_PROTOCOL_FLAG(
    int32_t,
    quic_max_aggressive_retransmittable_on_wire_ping_count,
    5,
    "Maximum number of consecutive pings that can be sent with the "
    "aggressive initial retransmittable on the wire timeout if there is "
    "no new stream data received. After this limit, the timeout will be "
    "doubled each ping until it exceeds the default ping timeout.")

QUIC_PROTOCOL_FLAG(
    int32_t,
    quic_max_retransmittable_on_wire_ping_count,
    1000,
    "Maximum number of pings that can be sent with the retransmittable "
    "on the wire timeout, over the lifetime of a connection. After this "
    "limit, the timeout will be the default ping timeout.")

QUIC_PROTOCOL_FLAG(int32_t,
                   quic_max_congestion_window,
                   2000,
                   "The maximum congestion window in packets.")

QUIC_PROTOCOL_FLAG(
    int32_t,
    quic_max_streams_window_divisor,
    2,
    "The divisor that controls how often MAX_STREAMS frame is sent.")

QUIC_PROTOCOL_FLAG(
    uint64_t,
    quic_key_update_confidentiality_limit,
    0,
    "If non-zero and key update is allowed, the maximum number of "
    "packets sent for each key phase before initiating a key update.")

QUIC_PROTOCOL_FLAG(bool,
                   quic_disable_client_tls_zero_rtt,
                   false,
                   "If true, QUIC client with TLS will not try 0-RTT.")

QUIC_PROTOCOL_FLAG(bool,
                   quic_disable_server_tls_resumption,
                   false,
                   "If true, QUIC server will disable TLS resumption by not "
                   "issuing or processing session tickets.")

QUIC_PROTOCOL_FLAG(bool,
                   quic_defer_send_in_response,
                   true,
                   "If true, QUIC servers will defer sending in response to "
                   "incoming packets by default.")

QUIC_PROTOCOL_FLAG(
    bool,
    quic_header_size_limit_includes_overhead,
    true,
    "If true, QUIC QPACK decoder includes 32-bytes overheader per entry while "
    "comparing request/response header size against its upper limit.")

QUIC_PROTOCOL_FLAG(
    bool,
    quic_reject_retry_token_in_initial_packet,
    false,
    "If true, always reject retry_token received in INITIAL packets")

QUIC_PROTOCOL_FLAG(bool, quic_use_lower_server_response_mtu_for_test, false,
                   "If true, cap server response packet size at 1250.")
#endif
