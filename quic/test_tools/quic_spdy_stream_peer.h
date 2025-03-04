// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_TEST_TOOLS_QUIC_SPDY_STREAM_PEER_H_
#define QUICHE_QUIC_TEST_TOOLS_QUIC_SPDY_STREAM_PEER_H_

#include "quic/core/quic_ack_listener_interface.h"
#include "quic/core/quic_interval_set.h"
#include "quic/platform/api/quic_containers.h"

namespace quic {

class QpackDecodedHeadersAccumulator;
class QuicSpdyStream;

namespace test {

class QuicSpdyStreamPeer {
 public:
  static void set_ack_listener(
      QuicSpdyStream* stream,
      quiche::QuicheReferenceCountedPointer<QuicAckListenerInterface>
          ack_listener);
  static const QuicIntervalSet<QuicStreamOffset>& unacked_frame_headers_offsets(
      QuicSpdyStream* stream);
  static bool use_datagram_contexts(QuicSpdyStream* stream);
  static bool OnHeadersFrameEnd(QuicSpdyStream* stream);
};

}  // namespace test

}  // namespace quic

#endif  // QUICHE_QUIC_TEST_TOOLS_QUIC_SPDY_STREAM_PEER_H_
