// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/core/http/quic_receive_control_stream.h"

#include <utility>

#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "quic/core/http/http_constants.h"
#include "quic/core/http/http_decoder.h"
#include "quic/core/http/quic_spdy_session.h"
#include "quic/core/quic_types.h"
#include "quic/platform/api/quic_flag_utils.h"
#include "quic/platform/api/quic_flags.h"
#include "common/quiche_text_utils.h"

namespace quic {

QuicReceiveControlStream::QuicReceiveControlStream(
    PendingStream* pending,
    QuicSpdySession* spdy_session)
    : QuicStream(pending,
                 spdy_session,
                 /*is_static=*/true),
      settings_frame_received_(false),
      decoder_(this),
      spdy_session_(spdy_session) {
  sequencer()->set_level_triggered(true);
}

QuicReceiveControlStream::~QuicReceiveControlStream() {}

void QuicReceiveControlStream::OnStreamReset(
    const QuicRstStreamFrame& /*frame*/) {
  stream_delegate()->OnStreamError(
      QUIC_HTTP_CLOSED_CRITICAL_STREAM,
      "RESET_STREAM received for receive control stream");
}

void QuicReceiveControlStream::OnDataAvailable() {
  iovec iov;
  while (!reading_stopped() && decoder_.error() == QUIC_NO_ERROR &&
         sequencer()->GetReadableRegion(&iov)) {
    QUICHE_DCHECK(!sequencer()->IsClosed());

    QuicByteCount processed_bytes = decoder_.ProcessInput(
        reinterpret_cast<const char*>(iov.iov_base), iov.iov_len);
    sequencer()->MarkConsumed(processed_bytes);

    if (!session()->connection()->connected()) {
      return;
    }

    // The only reason QuicReceiveControlStream pauses HttpDecoder is an error,
    // in which case the connection would have already been closed.
    QUICHE_DCHECK_EQ(iov.iov_len, processed_bytes);
  }
}

void QuicReceiveControlStream::OnError(HttpDecoder* decoder) {
  stream_delegate()->OnStreamError(decoder->error(), decoder->error_detail());
}

bool QuicReceiveControlStream::OnMaxPushIdFrame(const MaxPushIdFrame& frame) {
  if (GetQuicReloadableFlag(quic_ignore_max_push_id)) {
    QUIC_RELOADABLE_FLAG_COUNT(quic_ignore_max_push_id);
    return ValidateFrameType(HttpFrameType::MAX_PUSH_ID);
  }

  if (spdy_session()->debug_visitor()) {
    spdy_session()->debug_visitor()->OnMaxPushIdFrameReceived(frame);
  }

  if (!ValidateFrameType(HttpFrameType::MAX_PUSH_ID)) {
    return false;
  }

  return spdy_session()->OnMaxPushIdFrame(frame.push_id);
}

bool QuicReceiveControlStream::OnGoAwayFrame(const GoAwayFrame& frame) {
  if (spdy_session()->debug_visitor()) {
    spdy_session()->debug_visitor()->OnGoAwayFrameReceived(frame);
  }

  if (!ValidateFrameType(HttpFrameType::GOAWAY)) {
    return false;
  }

  spdy_session()->OnHttp3GoAway(frame.id);
  return true;
}

bool QuicReceiveControlStream::OnSettingsFrameStart(
    QuicByteCount /*header_length*/) {
  return ValidateFrameType(HttpFrameType::SETTINGS);
}

bool QuicReceiveControlStream::OnSettingsFrame(const SettingsFrame& frame) {
  QUIC_DVLOG(1) << "Control Stream " << id()
                << " received settings frame: " << frame;
  return spdy_session_->OnSettingsFrame(frame);
}

bool QuicReceiveControlStream::OnDataFrameStart(QuicByteCount /*header_length*/,
                                                QuicByteCount
                                                /*payload_length*/) {
  return ValidateFrameType(HttpFrameType::DATA);
}

bool QuicReceiveControlStream::OnDataFramePayload(
    absl::string_view /*payload*/) {
  QUICHE_NOTREACHED();
  return false;
}

bool QuicReceiveControlStream::OnDataFrameEnd() {
  QUICHE_NOTREACHED();
  return false;
}

bool QuicReceiveControlStream::OnHeadersFrameStart(
    QuicByteCount /*header_length*/,
    QuicByteCount
    /*payload_length*/) {
  return ValidateFrameType(HttpFrameType::HEADERS);
}

bool QuicReceiveControlStream::OnHeadersFramePayload(
    absl::string_view /*payload*/) {
  QUICHE_NOTREACHED();
  return false;
}

bool QuicReceiveControlStream::OnHeadersFrameEnd() {
  QUICHE_NOTREACHED();
  return false;
}

bool QuicReceiveControlStream::OnPriorityUpdateFrameStart(
    QuicByteCount /*header_length*/) {
  return ValidateFrameType(HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM);
}

bool QuicReceiveControlStream::OnPriorityUpdateFrame(
    const PriorityUpdateFrame& frame) {
  if (spdy_session()->debug_visitor()) {
    spdy_session()->debug_visitor()->OnPriorityUpdateFrameReceived(frame);
  }

  // TODO(b/147306124): Use a proper structured headers parser instead.
  for (absl::string_view key_value :
       absl::StrSplit(frame.priority_field_value, ',')) {
    std::vector<absl::string_view> key_and_value =
        absl::StrSplit(key_value, '=');
    if (key_and_value.size() != 2) {
      continue;
    }

    absl::string_view key = key_and_value[0];
    quiche::QuicheTextUtils::RemoveLeadingAndTrailingWhitespace(&key);
    if (key != "u") {
      continue;
    }

    absl::string_view value = key_and_value[1];
    int urgency;
    if (!absl::SimpleAtoi(value, &urgency) || urgency < 0 || urgency > 7) {
      stream_delegate()->OnStreamError(
          QUIC_INVALID_PRIORITY_UPDATE,
          "Invalid value for PRIORITY_UPDATE urgency parameter.");
      return false;
    }

    if (frame.prioritized_element_type == REQUEST_STREAM) {
      return spdy_session_->OnPriorityUpdateForRequestStream(
          frame.prioritized_element_id, urgency);
    } else {
      return spdy_session_->OnPriorityUpdateForPushStream(
          frame.prioritized_element_id, urgency);
    }
  }

  // Ignore frame if no urgency parameter can be parsed.
  return true;
}

bool QuicReceiveControlStream::OnAcceptChFrameStart(
    QuicByteCount /* header_length */) {
  return ValidateFrameType(HttpFrameType::ACCEPT_CH);
}

bool QuicReceiveControlStream::OnAcceptChFrame(const AcceptChFrame& frame) {
  QUICHE_DCHECK_EQ(Perspective::IS_CLIENT, spdy_session()->perspective());

  if (spdy_session()->debug_visitor()) {
    spdy_session()->debug_visitor()->OnAcceptChFrameReceived(frame);
  }

  spdy_session()->OnAcceptChFrame(frame);
  return true;
}

void QuicReceiveControlStream::OnWebTransportStreamFrameType(
    QuicByteCount /*header_length*/,
    WebTransportSessionId /*session_id*/) {
  QUIC_BUG(WEBTRANSPORT_STREAM on Control Stream)
      << "Parsed WEBTRANSPORT_STREAM on a control stream.";
}

bool QuicReceiveControlStream::OnUnknownFrameStart(
    uint64_t frame_type,
    QuicByteCount /*header_length*/,
    QuicByteCount payload_length) {
  if (spdy_session()->debug_visitor()) {
    spdy_session()->debug_visitor()->OnUnknownFrameReceived(id(), frame_type,
                                                            payload_length);
  }

  return ValidateFrameType(static_cast<HttpFrameType>(frame_type));
}

bool QuicReceiveControlStream::OnUnknownFramePayload(
    absl::string_view /*payload*/) {
  // Ignore unknown frame types.
  return true;
}

bool QuicReceiveControlStream::OnUnknownFrameEnd() {
  // Ignore unknown frame types.
  return true;
}

bool QuicReceiveControlStream::ValidateFrameType(HttpFrameType frame_type) {
  // Certain frame types are forbidden.
  if (frame_type == HttpFrameType::DATA ||
      frame_type == HttpFrameType::HEADERS ||
      (spdy_session()->perspective() == Perspective::IS_CLIENT &&
       frame_type == HttpFrameType::MAX_PUSH_ID) ||
      (spdy_session()->perspective() == Perspective::IS_SERVER &&
       frame_type == HttpFrameType::ACCEPT_CH)) {
    stream_delegate()->OnStreamError(
        QUIC_HTTP_FRAME_UNEXPECTED_ON_CONTROL_STREAM,
        absl::StrCat("Invalid frame type ", static_cast<int>(frame_type),
                     " received on control stream."));
    return false;
  }

  if (settings_frame_received_) {
    if (frame_type == HttpFrameType::SETTINGS) {
      // SETTINGS frame may only be the first frame on the control stream.
      stream_delegate()->OnStreamError(
          QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_CONTROL_STREAM,
          "SETTINGS frame can only be received once.");
      return false;
    }
    return true;
  }

  if (frame_type == HttpFrameType::SETTINGS) {
    settings_frame_received_ = true;
    return true;
  }
  stream_delegate()->OnStreamError(
      QUIC_HTTP_MISSING_SETTINGS_FRAME,
      absl::StrCat("First frame received on control stream is type ",
                   static_cast<int>(frame_type), ", but it must be SETTINGS."));
  return false;
}

}  // namespace quic
