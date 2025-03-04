#include "http2/adapter/oghttp2_session.h"

#include "http2/adapter/mock_http2_visitor.h"
#include "http2/adapter/test_frame_sequence.h"
#include "http2/adapter/test_utils.h"
#include "common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

using spdy::SpdyFrameType;
using testing::_;

enum FrameType {
  DATA,
  HEADERS,
  PRIORITY,
  RST_STREAM,
  SETTINGS,
  PUSH_PROMISE,
  PING,
  GOAWAY,
  WINDOW_UPDATE,
};

}  // namespace

TEST(OgHttp2SessionTest, ClientConstruction) {
  testing::StrictMock<MockHttp2Visitor> visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kClient});
  EXPECT_TRUE(session.want_read());
  EXPECT_FALSE(session.want_write());
  EXPECT_EQ(session.GetRemoteWindowSize(), kInitialFlowControlWindowSize);
  EXPECT_FALSE(session.IsServerSession());
  EXPECT_EQ(0, session.GetHighestReceivedStreamId());
}

TEST(OgHttp2SessionTest, ClientHandlesFrames) {
  testing::StrictMock<MockHttp2Visitor> visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kClient});

  const std::string initial_frames = TestFrameSequence()
                                         .ServerPreface()
                                         .Ping(42)
                                         .WindowUpdate(0, 1000)
                                         .Serialize();
  testing::InSequence s;

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor, OnPing(42, false));
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 1000));

  const int64_t initial_result = session.ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  EXPECT_EQ(session.GetRemoteWindowSize(),
            kInitialFlowControlWindowSize + 1000);
  EXPECT_EQ(0, session.GetHighestReceivedStreamId());

  // Connection has not yet received any data.
  EXPECT_EQ(kInitialFlowControlWindowSize, session.GetReceiveWindowSize());

  EXPECT_EQ(0, session.GetHpackDecoderDynamicTableSize());

  // Submit a request to ensure the first stream is created.
  const char* kSentinel1 = "arbitrary pointer 1";
  auto body1 = absl::make_unique<TestDataFrameSource>(visitor, true);
  body1->AppendPayload("This is an example request body.");
  body1->EndData();
  int stream_id =
      session.SubmitRequest(ToHeaders({{":method", "POST"},
                                       {":scheme", "http"},
                                       {":authority", "example.com"},
                                       {":path", "/this/is/request/one"}}),
                            std::move(body1), const_cast<char*>(kSentinel1));
  EXPECT_EQ(stream_id, 1);

  // Submit another request to ensure the next stream is created.
  int stream_id2 =
      session.SubmitRequest(ToHeaders({{":method", "GET"},
                                       {":scheme", "http"},
                                       {":authority", "example.com"},
                                       {":path", "/this/is/request/two"}}),
                            nullptr, nullptr);
  EXPECT_EQ(stream_id2, 3);

  const std::string stream_frames =
      TestFrameSequence()
          .Headers(stream_id,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(stream_id, "This is the response body.")
          .RstStream(stream_id2, Http2ErrorCode::INTERNAL_ERROR)
          .GoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, "calm down!!")
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id, ":status", "200"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(stream_id, "server", "my-fake-server"));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id, "date",
                                         "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, 26, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(stream_id, 26));
  EXPECT_CALL(visitor,
              OnDataForStream(stream_id, "This is the response body."));
  EXPECT_CALL(visitor, OnFrameHeader(stream_id2, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnRstStream(stream_id2, Http2ErrorCode::INTERNAL_ERROR));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id2, Http2ErrorCode::INTERNAL_ERROR));
  EXPECT_CALL(visitor, OnFrameHeader(0, 19, GOAWAY, 0));
  EXPECT_CALL(visitor, OnGoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, ""));
  const int64_t stream_result = session.ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));
  EXPECT_EQ(stream_id2, session.GetHighestReceivedStreamId());

  // The first stream is active and has received some data.
  EXPECT_GT(kInitialFlowControlWindowSize,
            session.GetStreamReceiveWindowSize(stream_id));
  // Connection receive window is equivalent to the first stream's.
  EXPECT_EQ(session.GetReceiveWindowSize(),
            session.GetStreamReceiveWindowSize(stream_id));
  // Receive window upper bound is still the initial value.
  EXPECT_EQ(kInitialFlowControlWindowSize,
            session.GetStreamReceiveWindowLimit(stream_id));

  EXPECT_GT(session.GetHpackDecoderDynamicTableSize(), 0);
}

// Verifies that a client session enqueues initial SETTINGS if Send() is called
// before any frames are explicitly queued.
TEST(OgHttp2SessionTest, ClientEnqueuesSettingsOnSend) {
  DataSavingVisitor visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kClient});
  EXPECT_FALSE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::SETTINGS}));
}

// Verifies that a client session enqueues initial SETTINGS before whatever
// frame type is passed to the first invocation of EnqueueFrame().
TEST(OgHttp2SessionTest, ClientEnqueuesSettingsBeforeOtherFrame) {
  DataSavingVisitor visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kClient});
  EXPECT_FALSE(session.want_write());
  session.EnqueueFrame(absl::make_unique<spdy::SpdyPingIR>(42));
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, 8, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, 8, 0x0, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::PING}));
}

// Verifies that if the first call to EnqueueFrame() passes a SETTINGS frame,
// the client session will not enqueue an additional SETTINGS frame.
TEST(OgHttp2SessionTest, ClientEnqueuesSettingsOnce) {
  DataSavingVisitor visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kClient});
  EXPECT_FALSE(session.want_write());
  session.EnqueueFrame(absl::make_unique<spdy::SpdySettingsIR>());
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2SessionTest, ClientSubmitRequest) {
  DataSavingVisitor visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kClient});

  EXPECT_FALSE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  // Even though the user has not queued any frames for the session, it should
  // still send the connection preface.
  int result = session.Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  // Initial SETTINGS.
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  const std::string initial_frames =
      TestFrameSequence().ServerPreface().Serialize();
  testing::InSequence s;

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = session.ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  // Session will want to write a SETTINGS ack.
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_EQ(0, session.GetHpackEncoderDynamicTableSize());

  const char* kSentinel1 = "arbitrary pointer 1";
  auto body1 = absl::make_unique<TestDataFrameSource>(visitor, true);
  body1->AppendPayload("This is an example request body.");
  body1->EndData();
  int stream_id =
      session.SubmitRequest(ToHeaders({{":method", "POST"},
                                       {":scheme", "http"},
                                       {":authority", "example.com"},
                                       {":path", "/this/is/request/one"}}),
                            std::move(body1), const_cast<char*>(kSentinel1));
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(session.want_write());
  EXPECT_EQ(kSentinel1, session.GetStreamUserData(stream_id));

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::HEADERS,
                                            spdy::SpdyFrameType::DATA}));
  visitor.Clear();
  EXPECT_FALSE(session.want_write());

  // Some data was sent, so the remaining send window size should be less than
  // the default.
  EXPECT_LT(session.GetStreamSendWindowSize(stream_id),
            kInitialFlowControlWindowSize);
  EXPECT_GT(session.GetStreamSendWindowSize(stream_id), 0);
  // Send window for a nonexistent stream is not available.
  EXPECT_EQ(-1, session.GetStreamSendWindowSize(stream_id + 2));

  EXPECT_GT(session.GetHpackEncoderDynamicTableSize(), 0);

  stream_id =
      session.SubmitRequest(ToHeaders({{":method", "POST"},
                                       {":scheme", "http"},
                                       {":authority", "example.com"},
                                       {":path", "/this/is/request/two"}}),
                            nullptr, nullptr);
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(session.want_write());
  const char* kSentinel2 = "arbitrary pointer 2";
  EXPECT_EQ(nullptr, session.GetStreamUserData(stream_id));
  session.SetStreamUserData(stream_id, const_cast<char*>(kSentinel2));
  EXPECT_EQ(kSentinel2, session.GetStreamUserData(stream_id));

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));

  result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::HEADERS}));

  // No data was sent (just HEADERS), so the remaining send window size should
  // still be the default.
  EXPECT_EQ(session.GetStreamSendWindowSize(stream_id),
            kInitialFlowControlWindowSize);
}

// This test exercises the case where the client request body source is read
// blocked.
TEST(OgHttp2SessionTest, ClientSubmitRequestWithReadBlock) {
  DataSavingVisitor visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kClient});
  EXPECT_FALSE(session.want_write());

  const char* kSentinel1 = "arbitrary pointer 1";
  auto body1 = absl::make_unique<TestDataFrameSource>(visitor, true);
  TestDataFrameSource* body_ref = body1.get();
  int stream_id =
      session.SubmitRequest(ToHeaders({{":method", "POST"},
                                       {":scheme", "http"},
                                       {":authority", "example.com"},
                                       {":path", "/this/is/request/one"}}),
                            std::move(body1), const_cast<char*>(kSentinel1));
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(session.want_write());
  EXPECT_EQ(kSentinel1, session.GetStreamUserData(stream_id));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  // No data frame, as body1 was read blocked.
  visitor.Clear();
  EXPECT_FALSE(session.want_write());

  body_ref->AppendPayload("This is an example request body.");
  body_ref->EndData();
  EXPECT_TRUE(session.ResumeStream(stream_id));
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::DATA}));
  EXPECT_FALSE(session.want_write());

  // Stream data is done, so this stream cannot be resumed.
  EXPECT_FALSE(session.ResumeStream(stream_id));
  EXPECT_FALSE(session.want_write());
}

// This test exercises the case where the client request body source is read
// blocked, then ends with an empty DATA frame.
TEST(OgHttp2SessionTest, ClientSubmitRequestEmptyDataWithFin) {
  DataSavingVisitor visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kClient});
  EXPECT_FALSE(session.want_write());

  const char* kSentinel1 = "arbitrary pointer 1";
  auto body1 = absl::make_unique<TestDataFrameSource>(visitor, true);
  TestDataFrameSource* body_ref = body1.get();
  int stream_id =
      session.SubmitRequest(ToHeaders({{":method", "POST"},
                                       {":scheme", "http"},
                                       {":authority", "example.com"},
                                       {":path", "/this/is/request/one"}}),
                            std::move(body1), const_cast<char*>(kSentinel1));
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(session.want_write());
  EXPECT_EQ(kSentinel1, session.GetStreamUserData(stream_id));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS}));
  // No data frame, as body1 was read blocked.
  visitor.Clear();
  EXPECT_FALSE(session.want_write());

  body_ref->EndData();
  EXPECT_TRUE(session.ResumeStream(stream_id));
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, 0, 0x1, 0));

  result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::DATA}));
  EXPECT_FALSE(session.want_write());

  // Stream data is done, so this stream cannot be resumed.
  EXPECT_FALSE(session.ResumeStream(stream_id));
  EXPECT_FALSE(session.want_write());
}

// This test exercises the case where the connection to the peer is write
// blocked.
TEST(OgHttp2SessionTest, ClientSubmitRequestWithWriteBlock) {
  DataSavingVisitor visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kClient});
  EXPECT_FALSE(session.want_write());

  const char* kSentinel1 = "arbitrary pointer 1";
  auto body1 = absl::make_unique<TestDataFrameSource>(visitor, true);
  body1->AppendPayload("This is an example request body.");
  body1->EndData();
  int stream_id =
      session.SubmitRequest(ToHeaders({{":method", "POST"},
                                       {":scheme", "http"},
                                       {":authority", "example.com"},
                                       {":path", "/this/is/request/one"}}),
                            std::move(body1), const_cast<char*>(kSentinel1));
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(session.want_write());
  EXPECT_EQ(kSentinel1, session.GetStreamUserData(stream_id));
  visitor.set_is_write_blocked(true);
  int result = session.Send();
  EXPECT_EQ(0, result);

  EXPECT_THAT(visitor.data(), testing::IsEmpty());
  EXPECT_TRUE(session.want_write());
  visitor.set_is_write_blocked(false);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  result = session.Send();
  EXPECT_EQ(0, result);

  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(serialized,
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::HEADERS,
                            SpdyFrameType::DATA}));
  EXPECT_FALSE(session.want_write());
}

TEST(OgHttp2SessionTest, ServerConstruction) {
  testing::StrictMock<MockHttp2Visitor> visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kServer});
  EXPECT_TRUE(session.want_read());
  EXPECT_FALSE(session.want_write());
  EXPECT_EQ(session.GetRemoteWindowSize(), kInitialFlowControlWindowSize);
  EXPECT_TRUE(session.IsServerSession());
  EXPECT_EQ(0, session.GetHighestReceivedStreamId());
}

TEST(OgHttp2SessionTest, ServerHandlesFrames) {
  DataSavingVisitor visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kServer});

  EXPECT_EQ(0, session.GetHpackDecoderDynamicTableSize());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Ping(42)
                                 .WindowUpdate(0, 1000)
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .WindowUpdate(1, 2000)
                                 .Data(1, "This is the request body.")
                                 .Headers(3,
                                          {{":method", "GET"},
                                           {":scheme", "http"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/two"}},
                                          /*fin=*/true)
                                 .RstStream(3, Http2ErrorCode::CANCEL)
                                 .Ping(47)
                                 .Serialize();
  testing::InSequence s;

  const char* kSentinel1 = "arbitrary pointer 1";

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor, OnPing(42, false));
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 1000));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1))
      .WillOnce(testing::InvokeWithoutArgs([&session, kSentinel1]() {
        session.SetStreamUserData(1, const_cast<char*>(kSentinel1));
        return true;
      }));
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(1, 2000));
  EXPECT_CALL(visitor, OnFrameHeader(1, 25, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 25));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the request body."));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":scheme", "http"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":path", "/this/is/request/two"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnEndStream(3));
  EXPECT_CALL(visitor, OnFrameHeader(3, 4, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnRstStream(3, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor, OnCloseStream(3, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor, OnPing(47, false));

  const int64_t result = session.ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_EQ(kSentinel1, session.GetStreamUserData(1));

  // The first stream is active and has received some data.
  EXPECT_GT(kInitialFlowControlWindowSize,
            session.GetStreamReceiveWindowSize(1));
  // Connection receive window is equivalent to the first stream's.
  EXPECT_EQ(session.GetReceiveWindowSize(),
            session.GetStreamReceiveWindowSize(1));
  // Receive window upper bound is still the initial value.
  EXPECT_EQ(kInitialFlowControlWindowSize,
            session.GetStreamReceiveWindowLimit(1));

  EXPECT_GT(session.GetHpackDecoderDynamicTableSize(), 0);

  // It should no longer be possible to set user data on a closed stream.
  const char* kSentinel3 = "another arbitrary pointer";
  session.SetStreamUserData(3, const_cast<char*>(kSentinel3));
  EXPECT_EQ(nullptr, session.GetStreamUserData(3));

  EXPECT_EQ(session.GetRemoteWindowSize(),
            kInitialFlowControlWindowSize + 1000);
  EXPECT_EQ(3, session.GetHighestReceivedStreamId());

  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, 0x1, 0));

  // Some bytes should have been serialized.
  int send_result = session.Send();
  EXPECT_EQ(0, send_result);
  // Initial SETTINGS, SETTINGS ack, and PING acks (for PING IDs 42 and 47).
  EXPECT_THAT(visitor.data(),
              EqualsFrames(
                  {spdy::SpdyFrameType::SETTINGS, spdy::SpdyFrameType::SETTINGS,
                   spdy::SpdyFrameType::PING, spdy::SpdyFrameType::PING}));
}

// Verifies that a server session enqueues initial SETTINGS before whatever
// frame type is passed to the first invocation of EnqueueFrame().
TEST(OgHttp2SessionTest, ServerEnqueuesSettingsBeforeOtherFrame) {
  DataSavingVisitor visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kServer});
  EXPECT_FALSE(session.want_write());
  session.EnqueueFrame(absl::make_unique<spdy::SpdyPingIR>(42));
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, 0x0, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::PING}));
}

// Verifies that if the first call to EnqueueFrame() passes a SETTINGS frame,
// the server session will not enqueue an additional SETTINGS frame.
TEST(OgHttp2SessionTest, ServerEnqueuesSettingsOnce) {
  DataSavingVisitor visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kServer});
  EXPECT_FALSE(session.want_write());
  session.EnqueueFrame(absl::make_unique<spdy::SpdySettingsIR>());
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  int result = session.Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2SessionTest, ServerSubmitResponse) {
  DataSavingVisitor visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kServer});

  EXPECT_FALSE(session.want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  const char* kSentinel1 = "arbitrary pointer 1";

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1))
      .WillOnce(testing::InvokeWithoutArgs([&session, kSentinel1]() {
        session.SetStreamUserData(1, const_cast<char*>(kSentinel1));
        return true;
      }));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = session.ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_EQ(1, session.GetHighestReceivedStreamId());

  EXPECT_EQ(0, session.GetHpackEncoderDynamicTableSize());

  // Server will want to send initial SETTINGS, and a SETTINGS ack.
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  int send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_FALSE(session.want_write());
  // A data fin is not sent so that the stream remains open, and the flow
  // control state can be verified.
  auto body1 = absl::make_unique<TestDataFrameSource>(visitor, false);
  body1->AppendPayload("This is an example response body.");
  int submit_result = session.SubmitResponse(
      1,
      ToHeaders({{":status", "404"},
                 {"x-comment", "I have no idea what you're talking about."}}),
      std::move(body1));
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(session.want_write());

  // Stream user data should have been set successfully after receiving headers.
  EXPECT_EQ(kSentinel1, session.GetStreamUserData(1));
  session.SetStreamUserData(1, nullptr);
  EXPECT_EQ(nullptr, session.GetStreamUserData(1));

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  EXPECT_FALSE(session.want_write());

  // Some data was sent, so the remaining send window size should be less than
  // the default.
  EXPECT_LT(session.GetStreamSendWindowSize(1), kInitialFlowControlWindowSize);
  EXPECT_GT(session.GetStreamSendWindowSize(1), 0);
  // Send window for a nonexistent stream is not available.
  EXPECT_EQ(session.GetStreamSendWindowSize(3), -1);

  EXPECT_GT(session.GetHpackEncoderDynamicTableSize(), 0);
}

// Tests the case where the server queues trailers after the data stream is
// exhausted.
TEST(OgHttp2SessionTest, ServerSendsTrailers) {
  DataSavingVisitor visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kServer});

  EXPECT_FALSE(session.want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = session.ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  // Server will want to send initial SETTINGS, and a SETTINGS ack.
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  int send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_FALSE(session.want_write());

  // The body source must indicate that the end of the body is not the end of
  // the stream.
  auto body1 = absl::make_unique<TestDataFrameSource>(visitor, false);
  body1->AppendPayload("This is an example response body.");
  body1->EndData();
  int submit_result = session.SubmitResponse(
      1, ToHeaders({{":status", "200"}, {"x-comment", "Sure, sounds good."}}),
      std::move(body1));
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA}));
  visitor.Clear();
  EXPECT_FALSE(session.want_write());

  // The body source has been exhausted by the call to Send() above.
  int trailer_result = session.SubmitTrailer(
      1, ToHeaders({{"final-status", "a-ok"},
                    {"x-comment", "trailers sure are cool"}}));
  ASSERT_EQ(trailer_result, 0);
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::HEADERS}));
}

// Tests the case where the server queues trailers immediately after headers and
// data, and before any writes have taken place.
TEST(OgHttp2SessionTest, ServerQueuesTrailersWithResponse) {
  DataSavingVisitor visitor;
  OgHttp2Session session(
      visitor, OgHttp2Session::Options{.perspective = Perspective::kServer});

  EXPECT_FALSE(session.want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = session.ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  // Server will want to send initial SETTINGS, and a SETTINGS ack.
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  int send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::SETTINGS}));
  visitor.Clear();

  EXPECT_FALSE(session.want_write());

  // The body source must indicate that the end of the body is not the end of
  // the stream.
  auto body1 = absl::make_unique<TestDataFrameSource>(visitor, false);
  body1->AppendPayload("This is an example response body.");
  body1->EndData();
  int submit_result = session.SubmitResponse(
      1, ToHeaders({{":status", "200"}, {"x-comment", "Sure, sounds good."}}),
      std::move(body1));
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(session.want_write());
  // There has not been a call to Send() yet, so neither headers nor body have
  // been written.
  int trailer_result = session.SubmitTrailer(
      1, ToHeaders({{"final-status", "a-ok"},
                    {"x-comment", "trailers sure are cool"}}));
  ASSERT_EQ(trailer_result, 0);
  EXPECT_TRUE(session.want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  send_result = session.Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames({SpdyFrameType::HEADERS, SpdyFrameType::DATA,
                            SpdyFrameType::HEADERS}));
}

}  // namespace test
}  // namespace adapter
}  // namespace http2
