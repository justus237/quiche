// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/core/http/http_decoder.h"

#include <cstdint>
#include <limits>

#include "absl/base/attributes.h"
#include "absl/strings/string_view.h"
#include "http2/http2_constants.h"
#include "quic/core/http/http_frames.h"
#include "quic/core/quic_data_reader.h"
#include "quic/core/quic_error_codes.h"
#include "quic/core/quic_types.h"
#include "quic/platform/api/quic_bug_tracker.h"
#include "quic/platform/api/quic_flag_utils.h"
#include "quic/platform/api/quic_flags.h"
#include "quic/platform/api/quic_logging.h"

namespace quic {

HttpDecoder::HttpDecoder(Visitor* visitor) : HttpDecoder(visitor, Options()) {}
HttpDecoder::HttpDecoder(Visitor* visitor, Options options)
    : visitor_(visitor),
      allow_web_transport_stream_(options.allow_web_transport_stream),
      state_(STATE_READING_FRAME_TYPE),
      current_frame_type_(0),
      current_length_field_length_(0),
      remaining_length_field_length_(0),
      current_frame_length_(0),
      remaining_frame_length_(0),
      current_type_field_length_(0),
      remaining_type_field_length_(0),
      current_push_id_length_(0),
      remaining_push_id_length_(0),
      error_(QUIC_NO_ERROR),
      error_detail_(""),
      error_on_http3_push_(GetQuicReloadableFlag(quic_error_on_http3_push)) {
  QUICHE_DCHECK(visitor_);
  if (error_on_http3_push_) {
    QUIC_RELOADABLE_FLAG_COUNT(quic_error_on_http3_push);
  }
}

HttpDecoder::~HttpDecoder() {}

// static
bool HttpDecoder::DecodeSettings(const char* data,
                                 QuicByteCount len,
                                 SettingsFrame* frame) {
  QuicDataReader reader(data, len);
  uint64_t frame_type;
  if (!reader.ReadVarInt62(&frame_type)) {
    QUIC_DLOG(ERROR) << "Unable to read frame type.";
    return false;
  }

  if (frame_type != static_cast<uint64_t>(HttpFrameType::SETTINGS)) {
    QUIC_DLOG(ERROR) << "Invalid frame type " << frame_type;
    return false;
  }

  absl::string_view frame_contents;
  if (!reader.ReadStringPieceVarInt62(&frame_contents)) {
    QUIC_DLOG(ERROR) << "Failed to read SETTINGS frame contents";
    return false;
  }

  QuicDataReader frame_reader(frame_contents);

  while (!frame_reader.IsDoneReading()) {
    uint64_t id;
    if (!frame_reader.ReadVarInt62(&id)) {
      QUIC_DLOG(ERROR) << "Unable to read setting identifier.";
      return false;
    }
    uint64_t content;
    if (!frame_reader.ReadVarInt62(&content)) {
      QUIC_DLOG(ERROR) << "Unable to read setting value.";
      return false;
    }
    auto result = frame->values.insert({id, content});
    if (!result.second) {
      QUIC_DLOG(ERROR) << "Duplicate setting identifier.";
      return false;
    }
  }
  return true;
}

QuicByteCount HttpDecoder::ProcessInput(const char* data, QuicByteCount len) {
  QUICHE_DCHECK_EQ(QUIC_NO_ERROR, error_);
  QUICHE_DCHECK_NE(STATE_ERROR, state_);

  QuicDataReader reader(data, len);
  bool continue_processing = true;
  while (continue_processing &&
         (reader.BytesRemaining() != 0 || state_ == STATE_FINISH_PARSING)) {
    // |continue_processing| must have been set to false upon error.
    QUICHE_DCHECK_EQ(QUIC_NO_ERROR, error_);
    QUICHE_DCHECK_NE(STATE_ERROR, state_);

    switch (state_) {
      case STATE_READING_FRAME_TYPE:
        continue_processing = ReadFrameType(&reader);
        break;
      case STATE_READING_FRAME_LENGTH:
        continue_processing = ReadFrameLength(&reader);
        break;
      case STATE_READING_FRAME_PAYLOAD:
        continue_processing = ReadFramePayload(&reader);
        break;
      case STATE_FINISH_PARSING:
        continue_processing = FinishParsing(&reader);
        break;
      case STATE_PARSING_NO_LONGER_POSSIBLE:
        continue_processing = false;
        QUIC_BUG(HttpDecoder PARSING_NO_LONGER_POSSIBLE)
            << "HttpDecoder called after an indefinite-length frame has been "
               "received";
        RaiseError(QUIC_INTERNAL_ERROR,
                   "HttpDecoder called after an indefinite-length frame has "
                   "been received");
        break;
      case STATE_ERROR:
        break;
      default:
        QUIC_BUG(quic_bug_10411_1) << "Invalid state: " << state_;
    }
  }

  return len - reader.BytesRemaining();
}

bool HttpDecoder::ReadFrameType(QuicDataReader* reader) {
  QUICHE_DCHECK_NE(0u, reader->BytesRemaining());
  if (current_type_field_length_ == 0) {
    // A new frame is coming.
    current_type_field_length_ = reader->PeekVarInt62Length();
    QUICHE_DCHECK_NE(0u, current_type_field_length_);
    if (current_type_field_length_ > reader->BytesRemaining()) {
      // Buffer a new type field.
      remaining_type_field_length_ = current_type_field_length_;
      BufferFrameType(reader);
      return true;
    }
    // The reader has all type data needed, so no need to buffer.
    bool success = reader->ReadVarInt62(&current_frame_type_);
    QUICHE_DCHECK(success);
  } else {
    // Buffer the existing type field.
    BufferFrameType(reader);
    // The frame is still not buffered completely.
    if (remaining_type_field_length_ != 0) {
      return true;
    }
    QuicDataReader type_reader(type_buffer_.data(), current_type_field_length_);
    bool success = type_reader.ReadVarInt62(&current_frame_type_);
    QUICHE_DCHECK(success);
  }

  // https://tools.ietf.org/html/draft-ietf-quic-http-31#section-7.2.8
  // specifies that the following frames are treated as errors.
  if (current_frame_type_ ==
          static_cast<uint64_t>(http2::Http2FrameType::PRIORITY) ||
      current_frame_type_ ==
          static_cast<uint64_t>(http2::Http2FrameType::PING) ||
      current_frame_type_ ==
          static_cast<uint64_t>(http2::Http2FrameType::WINDOW_UPDATE) ||
      current_frame_type_ ==
          static_cast<uint64_t>(http2::Http2FrameType::CONTINUATION)) {
    RaiseError(QUIC_HTTP_RECEIVE_SPDY_FRAME,
               absl::StrCat("HTTP/2 frame received in a HTTP/3 connection: ",
                            current_frame_type_));
    return false;
  }

  if (error_on_http3_push_) {
    if (current_frame_type_ ==
        static_cast<uint64_t>(HttpFrameType::CANCEL_PUSH)) {
      RaiseError(QUIC_HTTP_FRAME_ERROR, "CANCEL_PUSH frame received.");
      return false;
    }
    if (current_frame_type_ ==
        static_cast<uint64_t>(HttpFrameType::PUSH_PROMISE)) {
      RaiseError(QUIC_HTTP_FRAME_ERROR, "PUSH_PROMISE frame received.");
      return false;
    }
  }

  state_ = STATE_READING_FRAME_LENGTH;
  return true;
}

bool HttpDecoder::ReadFrameLength(QuicDataReader* reader) {
  QUICHE_DCHECK_NE(0u, reader->BytesRemaining());
  if (current_length_field_length_ == 0) {
    // A new frame is coming.
    current_length_field_length_ = reader->PeekVarInt62Length();
    QUICHE_DCHECK_NE(0u, current_length_field_length_);
    if (current_length_field_length_ > reader->BytesRemaining()) {
      // Buffer a new length field.
      remaining_length_field_length_ = current_length_field_length_;
      BufferFrameLength(reader);
      return true;
    }
    // The reader has all length data needed, so no need to buffer.
    bool success = reader->ReadVarInt62(&current_frame_length_);
    QUICHE_DCHECK(success);
  } else {
    // Buffer the existing length field.
    BufferFrameLength(reader);
    // The frame is still not buffered completely.
    if (remaining_length_field_length_ != 0) {
      return true;
    }
    QuicDataReader length_reader(length_buffer_.data(),
                                 current_length_field_length_);
    bool success = length_reader.ReadVarInt62(&current_frame_length_);
    QUICHE_DCHECK(success);
  }

  // WEBTRANSPORT_STREAM frames are indefinitely long, and thus require
  // special handling; the number after the frame type is actually the
  // WebTransport session ID, and not the length.
  if (allow_web_transport_stream_ &&
      current_frame_type_ ==
          static_cast<uint64_t>(HttpFrameType::WEBTRANSPORT_STREAM)) {
    visitor_->OnWebTransportStreamFrameType(
        current_length_field_length_ + current_type_field_length_,
        current_frame_length_);
    state_ = STATE_PARSING_NO_LONGER_POSSIBLE;
    return false;
  }

  if (current_frame_length_ > MaxFrameLength(current_frame_type_)) {
    RaiseError(QUIC_HTTP_FRAME_TOO_LARGE, "Frame is too large.");
    return false;
  }

  // Calling the following visitor methods does not require parsing of any
  // frame payload.
  bool continue_processing = true;
  const QuicByteCount header_length =
      current_length_field_length_ + current_type_field_length_;

  switch (current_frame_type_) {
    case static_cast<uint64_t>(HttpFrameType::DATA):
      continue_processing =
          visitor_->OnDataFrameStart(header_length, current_frame_length_);
      break;
    case static_cast<uint64_t>(HttpFrameType::HEADERS):
      continue_processing =
          visitor_->OnHeadersFrameStart(header_length, current_frame_length_);
      break;
    case static_cast<uint64_t>(HttpFrameType::CANCEL_PUSH):
      if (error_on_http3_push_) {
        QUICHE_NOTREACHED();
        break;
      }
      break;
    case static_cast<uint64_t>(HttpFrameType::SETTINGS):
      continue_processing = visitor_->OnSettingsFrameStart(header_length);
      break;
    case static_cast<uint64_t>(HttpFrameType::PUSH_PROMISE):
      if (error_on_http3_push_) {
        QUICHE_NOTREACHED();
        break;
      }
      // This edge case needs to be handled here, because ReadFramePayload()
      // does not get called if |current_frame_length_| is zero.
      if (current_frame_length_ == 0) {
        RaiseError(QUIC_HTTP_FRAME_ERROR,
                   "PUSH_PROMISE frame with empty payload.");
        return false;
      }
      continue_processing = visitor_->OnPushPromiseFrameStart(header_length);
      break;
    case static_cast<uint64_t>(HttpFrameType::GOAWAY):
      break;
    case static_cast<uint64_t>(HttpFrameType::MAX_PUSH_ID):
      break;
    case static_cast<uint64_t>(HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM):
      continue_processing = visitor_->OnPriorityUpdateFrameStart(header_length);
      break;
    case static_cast<uint64_t>(HttpFrameType::ACCEPT_CH):
      continue_processing = visitor_->OnAcceptChFrameStart(header_length);
      break;
    default:
      continue_processing = visitor_->OnUnknownFrameStart(
          current_frame_type_, header_length, current_frame_length_);
      break;
  }

  remaining_frame_length_ = current_frame_length_;
  state_ = (remaining_frame_length_ == 0) ? STATE_FINISH_PARSING
                                          : STATE_READING_FRAME_PAYLOAD;
  return continue_processing;
}

bool HttpDecoder::ReadFramePayload(QuicDataReader* reader) {
  QUICHE_DCHECK_NE(0u, reader->BytesRemaining());
  QUICHE_DCHECK_NE(0u, remaining_frame_length_);

  bool continue_processing = true;

  switch (current_frame_type_) {
    case static_cast<uint64_t>(HttpFrameType::DATA): {
      QuicByteCount bytes_to_read = std::min<QuicByteCount>(
          remaining_frame_length_, reader->BytesRemaining());
      absl::string_view payload;
      bool success = reader->ReadStringPiece(&payload, bytes_to_read);
      QUICHE_DCHECK(success);
      QUICHE_DCHECK(!payload.empty());
      continue_processing = visitor_->OnDataFramePayload(payload);
      remaining_frame_length_ -= payload.length();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::HEADERS): {
      QuicByteCount bytes_to_read = std::min<QuicByteCount>(
          remaining_frame_length_, reader->BytesRemaining());
      absl::string_view payload;
      bool success = reader->ReadStringPiece(&payload, bytes_to_read);
      QUICHE_DCHECK(success);
      QUICHE_DCHECK(!payload.empty());
      continue_processing = visitor_->OnHeadersFramePayload(payload);
      remaining_frame_length_ -= payload.length();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::CANCEL_PUSH): {
      if (error_on_http3_push_) {
        QUICHE_NOTREACHED();
      } else {
        continue_processing = BufferOrParsePayload(reader);
      }
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::SETTINGS): {
      continue_processing = BufferOrParsePayload(reader);
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::PUSH_PROMISE): {
      if (error_on_http3_push_) {
        QUICHE_NOTREACHED();
        break;
      }
      PushId push_id;
      if (current_frame_length_ == remaining_frame_length_) {
        // A new Push Promise frame just arrived.
        QUICHE_DCHECK_EQ(0u, current_push_id_length_);
        current_push_id_length_ = reader->PeekVarInt62Length();
        if (current_push_id_length_ > remaining_frame_length_) {
          RaiseError(QUIC_HTTP_FRAME_ERROR,
                     "Unable to read PUSH_PROMISE push_id.");
          return false;
        }
        if (current_push_id_length_ > reader->BytesRemaining()) {
          // Not all bytes of push id is present yet, buffer push id.
          QUICHE_DCHECK_EQ(0u, remaining_push_id_length_);
          remaining_push_id_length_ = current_push_id_length_;
          BufferPushId(reader);
          break;
        }
        bool success = reader->ReadVarInt62(&push_id);
        QUICHE_DCHECK(success);
        remaining_frame_length_ -= current_push_id_length_;
        if (!visitor_->OnPushPromiseFramePushId(
                push_id, current_push_id_length_,
                current_frame_length_ - current_push_id_length_)) {
          continue_processing = false;
          current_push_id_length_ = 0;
          break;
        }
        current_push_id_length_ = 0;
      } else if (remaining_push_id_length_ > 0) {
        // Waiting for more bytes on push id.
        BufferPushId(reader);
        if (remaining_push_id_length_ != 0) {
          break;
        }
        QuicDataReader push_id_reader(push_id_buffer_.data(),
                                      current_push_id_length_);

        bool success = push_id_reader.ReadVarInt62(&push_id);
        QUICHE_DCHECK(success);
        if (!visitor_->OnPushPromiseFramePushId(
                push_id, current_push_id_length_,
                current_frame_length_ - current_push_id_length_)) {
          continue_processing = false;
          current_push_id_length_ = 0;
          break;
        }
        current_push_id_length_ = 0;
      }

      // Read Push Promise headers.
      QUICHE_DCHECK_LT(remaining_frame_length_, current_frame_length_);
      QuicByteCount bytes_to_read = std::min<QuicByteCount>(
          remaining_frame_length_, reader->BytesRemaining());
      if (bytes_to_read == 0) {
        break;
      }
      absl::string_view payload;
      bool success = reader->ReadStringPiece(&payload, bytes_to_read);
      QUICHE_DCHECK(success);
      QUICHE_DCHECK(!payload.empty());
      continue_processing = visitor_->OnPushPromiseFramePayload(payload);
      remaining_frame_length_ -= payload.length();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::GOAWAY): {
      continue_processing = BufferOrParsePayload(reader);
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::MAX_PUSH_ID): {
      continue_processing = BufferOrParsePayload(reader);
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM): {
      continue_processing = BufferOrParsePayload(reader);
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::ACCEPT_CH): {
      continue_processing = BufferOrParsePayload(reader);
      break;
    }
    default: {
      continue_processing = HandleUnknownFramePayload(reader);
      break;
    }
  }

  // BufferOrParsePayload() may have advanced |state_|.
  if (state_ == STATE_READING_FRAME_PAYLOAD && remaining_frame_length_ == 0) {
    state_ = STATE_FINISH_PARSING;
  }

  return continue_processing;
}

bool HttpDecoder::FinishParsing(QuicDataReader* reader) {
  QUICHE_DCHECK_EQ(0u, remaining_frame_length_);

  bool continue_processing = true;

  switch (current_frame_type_) {
    case static_cast<uint64_t>(HttpFrameType::DATA): {
      continue_processing = visitor_->OnDataFrameEnd();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::HEADERS): {
      continue_processing = visitor_->OnHeadersFrameEnd();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::CANCEL_PUSH): {
      if (error_on_http3_push_) {
        QUICHE_NOTREACHED();
      } else {
        // If frame payload is not empty, FinishParsing() is skipped.
        QUICHE_DCHECK_EQ(0u, current_frame_length_);
        continue_processing = BufferOrParsePayload(reader);
      }
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::SETTINGS): {
      // If frame payload is not empty, FinishParsing() is skipped.
      QUICHE_DCHECK_EQ(0u, current_frame_length_);
      continue_processing = BufferOrParsePayload(reader);
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::PUSH_PROMISE): {
      if (error_on_http3_push_) {
        QUICHE_NOTREACHED();
      } else {
        continue_processing = visitor_->OnPushPromiseFrameEnd();
      }
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::GOAWAY): {
      // If frame payload is not empty, FinishParsing() is skipped.
      QUICHE_DCHECK_EQ(0u, current_frame_length_);
      continue_processing = BufferOrParsePayload(reader);
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::MAX_PUSH_ID): {
      // If frame payload is not empty, FinishParsing() is skipped.
      QUICHE_DCHECK_EQ(0u, current_frame_length_);
      continue_processing = BufferOrParsePayload(reader);
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM): {
      // If frame payload is not empty, FinishParsing() is skipped.
      QUICHE_DCHECK_EQ(0u, current_frame_length_);
      continue_processing = BufferOrParsePayload(reader);
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::ACCEPT_CH): {
      // If frame payload is not empty, FinishParsing() is skipped.
      QUICHE_DCHECK_EQ(0u, current_frame_length_);
      continue_processing = BufferOrParsePayload(reader);
      break;
    }
    default:
      continue_processing = visitor_->OnUnknownFrameEnd();
  }

  current_length_field_length_ = 0;
  current_type_field_length_ = 0;
  state_ = STATE_READING_FRAME_TYPE;
  return continue_processing;
}

bool HttpDecoder::HandleUnknownFramePayload(QuicDataReader* reader) {
  QuicByteCount bytes_to_read = std::min<QuicByteCount>(
      remaining_frame_length_, reader->BytesRemaining());
  absl::string_view payload;
  bool success = reader->ReadStringPiece(&payload, bytes_to_read);
  QUICHE_DCHECK(success);
  QUICHE_DCHECK(!payload.empty());
  remaining_frame_length_ -= payload.length();
  return visitor_->OnUnknownFramePayload(payload);
}

void HttpDecoder::DiscardFramePayload(QuicDataReader* reader) {
  QuicByteCount bytes_to_read = std::min<QuicByteCount>(
      remaining_frame_length_, reader->BytesRemaining());
  absl::string_view payload;
  bool success = reader->ReadStringPiece(&payload, bytes_to_read);
  QUICHE_DCHECK(success);
  remaining_frame_length_ -= payload.length();
  if (remaining_frame_length_ == 0) {
    state_ = STATE_READING_FRAME_TYPE;
    current_length_field_length_ = 0;
    current_type_field_length_ = 0;
  }
}

bool HttpDecoder::BufferOrParsePayload(QuicDataReader* reader) {
  QUICHE_DCHECK_EQ(current_frame_length_,
                   buffer_.size() + remaining_frame_length_);

  bool continue_processing = true;

  if (buffer_.empty() && reader->BytesRemaining() >= current_frame_length_) {
    // |*reader| contains entire payload, which might be empty.
    remaining_frame_length_ = 0;
    QuicDataReader current_payload_reader(reader->PeekRemainingPayload().data(),
                                          current_frame_length_);
    continue_processing = ParseEntirePayload(&current_payload_reader);
    reader->Seek(current_frame_length_);
  } else {
    if (buffer_.empty()) {
      buffer_.reserve(current_frame_length_);
    }

    // Buffer as much of the payload as |*reader| contains.
    QuicByteCount bytes_to_read = std::min<QuicByteCount>(
        remaining_frame_length_, reader->BytesRemaining());
    absl::StrAppend(&buffer_, reader->PeekRemainingPayload().substr(
                                  /* pos = */ 0, bytes_to_read));
    reader->Seek(bytes_to_read);
    remaining_frame_length_ -= bytes_to_read;

    QUICHE_DCHECK_EQ(current_frame_length_,
                     buffer_.size() + remaining_frame_length_);

    if (remaining_frame_length_ > 0) {
      QUICHE_DCHECK(reader->IsDoneReading());
      return true;
    }

    QuicDataReader buffer_reader(buffer_);
    continue_processing = ParseEntirePayload(&buffer_reader);
    buffer_.clear();
  }

  current_length_field_length_ = 0;
  current_type_field_length_ = 0;
  state_ = STATE_READING_FRAME_TYPE;
  return continue_processing;
}

bool HttpDecoder::ParseEntirePayload(QuicDataReader* reader) {
  QUICHE_DCHECK_EQ(current_frame_length_, reader->BytesRemaining());
  QUICHE_DCHECK_EQ(0u, remaining_frame_length_);

  switch (current_frame_type_) {
    case static_cast<uint64_t>(HttpFrameType::CANCEL_PUSH): {
      if (error_on_http3_push_) {
        QUICHE_NOTREACHED();
        return false;
      }
      CancelPushFrame frame;
      if (!reader->ReadVarInt62(&frame.push_id)) {
        RaiseError(QUIC_HTTP_FRAME_ERROR,
                   "Unable to read CANCEL_PUSH push_id.");
        return false;
      }
      if (!reader->IsDoneReading()) {
        RaiseError(QUIC_HTTP_FRAME_ERROR,
                   "Superfluous data in CANCEL_PUSH frame.");
        return false;
      }
      return visitor_->OnCancelPushFrame(frame);
    }
    case static_cast<uint64_t>(HttpFrameType::SETTINGS): {
      SettingsFrame frame;
      if (!ParseSettingsFrame(reader, &frame)) {
        return false;
      }
      return visitor_->OnSettingsFrame(frame);
    }
    case static_cast<uint64_t>(HttpFrameType::GOAWAY): {
      GoAwayFrame frame;
      if (!reader->ReadVarInt62(&frame.id)) {
        RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read GOAWAY ID.");
        return false;
      }
      if (!reader->IsDoneReading()) {
        RaiseError(QUIC_HTTP_FRAME_ERROR, "Superfluous data in GOAWAY frame.");
        return false;
      }
      return visitor_->OnGoAwayFrame(frame);
    }
    case static_cast<uint64_t>(HttpFrameType::MAX_PUSH_ID): {
      MaxPushIdFrame frame;
      if (!reader->ReadVarInt62(&frame.push_id)) {
        RaiseError(QUIC_HTTP_FRAME_ERROR,
                   "Unable to read MAX_PUSH_ID push_id.");
        return false;
      }
      if (!reader->IsDoneReading()) {
        RaiseError(QUIC_HTTP_FRAME_ERROR,
                   "Superfluous data in MAX_PUSH_ID frame.");
        return false;
      }
      return visitor_->OnMaxPushIdFrame(frame);
    }
    case static_cast<uint64_t>(HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM): {
      PriorityUpdateFrame frame;
      if (!ParseNewPriorityUpdateFrame(reader, &frame)) {
        return false;
      }
      return visitor_->OnPriorityUpdateFrame(frame);
    }
    case static_cast<uint64_t>(HttpFrameType::ACCEPT_CH): {
      AcceptChFrame frame;
      if (!ParseAcceptChFrame(reader, &frame)) {
        return false;
      }
      return visitor_->OnAcceptChFrame(frame);
    }
    default:
      // Only above frame types are parsed by ParseEntirePayload().
      QUICHE_NOTREACHED();
      return false;
  }
}

void HttpDecoder::BufferFrameLength(QuicDataReader* reader) {
  QuicByteCount bytes_to_read = std::min<QuicByteCount>(
      remaining_length_field_length_, reader->BytesRemaining());
  bool success =
      reader->ReadBytes(length_buffer_.data() + current_length_field_length_ -
                            remaining_length_field_length_,
                        bytes_to_read);
  QUICHE_DCHECK(success);
  remaining_length_field_length_ -= bytes_to_read;
}

void HttpDecoder::BufferFrameType(QuicDataReader* reader) {
  QuicByteCount bytes_to_read = std::min<QuicByteCount>(
      remaining_type_field_length_, reader->BytesRemaining());
  bool success =
      reader->ReadBytes(type_buffer_.data() + current_type_field_length_ -
                            remaining_type_field_length_,
                        bytes_to_read);
  QUICHE_DCHECK(success);
  remaining_type_field_length_ -= bytes_to_read;
}

void HttpDecoder::BufferPushId(QuicDataReader* reader) {
  QUICHE_DCHECK_LE(remaining_push_id_length_, current_frame_length_);
  QuicByteCount bytes_to_read = std::min<QuicByteCount>(
      reader->BytesRemaining(), remaining_push_id_length_);
  bool success =
      reader->ReadBytes(push_id_buffer_.data() + current_push_id_length_ -
                            remaining_push_id_length_,
                        bytes_to_read);
  QUICHE_DCHECK(success);
  remaining_push_id_length_ -= bytes_to_read;
  remaining_frame_length_ -= bytes_to_read;
}

void HttpDecoder::RaiseError(QuicErrorCode error, std::string error_detail) {
  state_ = STATE_ERROR;
  error_ = error;
  error_detail_ = std::move(error_detail);
  visitor_->OnError(this);
}

bool HttpDecoder::ParseSettingsFrame(QuicDataReader* reader,
                                     SettingsFrame* frame) {
  while (!reader->IsDoneReading()) {
    uint64_t id;
    if (!reader->ReadVarInt62(&id)) {
      RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read setting identifier.");
      return false;
    }
    uint64_t content;
    if (!reader->ReadVarInt62(&content)) {
      RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read setting value.");
      return false;
    }
    auto result = frame->values.insert({id, content});
    if (!result.second) {
      RaiseError(QUIC_HTTP_DUPLICATE_SETTING_IDENTIFIER,
                 "Duplicate setting identifier.");
      return false;
    }
  }
  return true;
}

bool HttpDecoder::ParsePriorityUpdateFrame(QuicDataReader* reader,
                                           PriorityUpdateFrame* frame) {
  uint8_t prioritized_element_type;
  if (!reader->ReadUInt8(&prioritized_element_type)) {
    RaiseError(QUIC_HTTP_FRAME_ERROR,
               "Unable to read prioritized element type.");
    return false;
  }

  if (prioritized_element_type != REQUEST_STREAM &&
      prioritized_element_type != PUSH_STREAM) {
    RaiseError(QUIC_HTTP_FRAME_ERROR, "Invalid prioritized element type.");
    return false;
  }

  frame->prioritized_element_type =
      static_cast<PrioritizedElementType>(prioritized_element_type);

  if (!reader->ReadVarInt62(&frame->prioritized_element_id)) {
    RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read prioritized element id.");
    return false;
  }

  absl::string_view priority_field_value = reader->ReadRemainingPayload();
  frame->priority_field_value =
      std::string(priority_field_value.data(), priority_field_value.size());

  return true;
}

bool HttpDecoder::ParseNewPriorityUpdateFrame(QuicDataReader* reader,
                                              PriorityUpdateFrame* frame) {
  frame->prioritized_element_type = REQUEST_STREAM;

  if (!reader->ReadVarInt62(&frame->prioritized_element_id)) {
    RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read prioritized element id.");
    return false;
  }

  absl::string_view priority_field_value = reader->ReadRemainingPayload();
  frame->priority_field_value =
      std::string(priority_field_value.data(), priority_field_value.size());

  return true;
}

bool HttpDecoder::ParseAcceptChFrame(QuicDataReader* reader,
                                     AcceptChFrame* frame) {
  absl::string_view origin;
  absl::string_view value;
  while (!reader->IsDoneReading()) {
    if (!reader->ReadStringPieceVarInt62(&origin)) {
      RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read ACCEPT_CH origin.");
      return false;
    }
    if (!reader->ReadStringPieceVarInt62(&value)) {
      RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read ACCEPT_CH value.");
      return false;
    }
    // Copy data.
    frame->entries.push_back({std::string(origin.data(), origin.size()),
                              std::string(value.data(), value.size())});
  }
  return true;
}

QuicByteCount HttpDecoder::MaxFrameLength(uint64_t frame_type) {
  switch (frame_type) {
    case static_cast<uint64_t>(HttpFrameType::CANCEL_PUSH):
      // TODO(b/171463363): Remove.
      return sizeof(PushId);
    case static_cast<uint64_t>(HttpFrameType::SETTINGS):
      // This limit is arbitrary.
      return 1024 * 1024;
    case static_cast<uint64_t>(HttpFrameType::GOAWAY):
      return VARIABLE_LENGTH_INTEGER_LENGTH_8;
    case static_cast<uint64_t>(HttpFrameType::MAX_PUSH_ID):
      // TODO(b/171463363): Remove.
      return sizeof(PushId);
    case static_cast<uint64_t>(HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM):
      // This limit is arbitrary.
      return 1024 * 1024;
    case static_cast<uint64_t>(HttpFrameType::ACCEPT_CH):
      // This limit is arbitrary.
      return 1024 * 1024;
    default:
      // Other frames require no data buffering, so it's safe to have no limit.
      return std::numeric_limits<QuicByteCount>::max();
  }
}

}  // namespace quic
