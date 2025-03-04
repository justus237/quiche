// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/core/crypto/crypto_utils.h"

#include <string>

#include "absl/base/macros.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "quic/core/quic_utils.h"
#include "quic/platform/api/quic_test.h"
#include "quic/test_tools/quic_test_utils.h"
#include "common/test_tools/quiche_test_utils.h"

namespace quic {
namespace test {
namespace {

class CryptoUtilsTest : public QuicTest {};

TEST_F(CryptoUtilsTest, HandshakeFailureReasonToString) {
  EXPECT_STREQ("HANDSHAKE_OK",
               CryptoUtils::HandshakeFailureReasonToString(HANDSHAKE_OK));
  EXPECT_STREQ("CLIENT_NONCE_UNKNOWN_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_UNKNOWN_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_INVALID_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_INVALID_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_NOT_UNIQUE_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_NOT_UNIQUE_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_INVALID_ORBIT_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_INVALID_ORBIT_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_INVALID_TIME_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_INVALID_TIME_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_STRIKE_REGISTER_TIMEOUT",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_STRIKE_REGISTER_TIMEOUT));
  EXPECT_STREQ("CLIENT_NONCE_STRIKE_REGISTER_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_STRIKE_REGISTER_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_DECRYPTION_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_DECRYPTION_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_INVALID_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_INVALID_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_NOT_UNIQUE_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_NOT_UNIQUE_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_INVALID_TIME_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_INVALID_TIME_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_REQUIRED_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_REQUIRED_FAILURE));
  EXPECT_STREQ("SERVER_CONFIG_INCHOATE_HELLO_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_CONFIG_INCHOATE_HELLO_FAILURE));
  EXPECT_STREQ("SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_INVALID_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_INVALID_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_PARSE_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_PARSE_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE));
  EXPECT_STREQ("INVALID_EXPECTED_LEAF_CERTIFICATE",
               CryptoUtils::HandshakeFailureReasonToString(
                   INVALID_EXPECTED_LEAF_CERTIFICATE));
  EXPECT_STREQ("MAX_FAILURE_REASON",
               CryptoUtils::HandshakeFailureReasonToString(MAX_FAILURE_REASON));
  EXPECT_STREQ(
      "INVALID_HANDSHAKE_FAILURE_REASON",
      CryptoUtils::HandshakeFailureReasonToString(
          static_cast<HandshakeFailureReason>(MAX_FAILURE_REASON + 1)));
}

TEST_F(CryptoUtilsTest, AuthTagLengths) {
  for (const auto& version : AllSupportedVersions()) {
    for (QuicTag algo : {kAESG, kCC20}) {
      SCOPED_TRACE(version);
      std::unique_ptr<QuicEncrypter> encrypter(
          QuicEncrypter::Create(version, algo));
      size_t auth_tag_size = 12;
      if (version.UsesInitialObfuscators()) {
        auth_tag_size = 16;
      }
      EXPECT_EQ(encrypter->GetCiphertextSize(0), auth_tag_size);
    }
  }
}

TEST_F(CryptoUtilsTest, ValidateChosenVersion) {
  for (const ParsedQuicVersion& v1 : AllSupportedVersions()) {
    for (const ParsedQuicVersion& v2 : AllSupportedVersions()) {
      std::string error_details;
      bool success = CryptoUtils::ValidateChosenVersion(
          CreateQuicVersionLabel(v1), v2, &error_details);
      EXPECT_EQ(success, v1 == v2);
      EXPECT_EQ(success, error_details.empty());
    }
  }
}

TEST_F(CryptoUtilsTest, ValidateServerVersionsNoVersionNegotiation) {
  QuicVersionLabelVector version_information_other_versions;
  ParsedQuicVersionVector client_original_supported_versions;
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    std::string error_details;
    EXPECT_TRUE(CryptoUtils::ValidateServerVersions(
        version_information_other_versions, version,
        client_original_supported_versions, &error_details));
    EXPECT_TRUE(error_details.empty());
  }
}

TEST_F(CryptoUtilsTest, ValidateServerVersionsWithVersionNegotiation) {
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    QuicVersionLabelVector version_information_other_versions{
        CreateQuicVersionLabel(version)};
    ParsedQuicVersionVector client_original_supported_versions{
        ParsedQuicVersion::ReservedForNegotiation(), version};
    std::string error_details;
    EXPECT_TRUE(CryptoUtils::ValidateServerVersions(
        version_information_other_versions, version,
        client_original_supported_versions, &error_details));
    EXPECT_TRUE(error_details.empty());
  }
}

TEST_F(CryptoUtilsTest, ValidateServerVersionsWithDowngrade) {
  if (AllSupportedVersions().size() <= 1) {
    // We are not vulnerable to downgrade if we only support one version.
    return;
  }
  ParsedQuicVersion client_version = AllSupportedVersions().front();
  ParsedQuicVersion server_version = AllSupportedVersions().back();
  ASSERT_NE(client_version, server_version);
  QuicVersionLabelVector version_information_other_versions{
      CreateQuicVersionLabel(client_version)};
  ParsedQuicVersionVector client_original_supported_versions{
      ParsedQuicVersion::ReservedForNegotiation(), server_version};
  std::string error_details;
  EXPECT_FALSE(CryptoUtils::ValidateServerVersions(
      version_information_other_versions, server_version,
      client_original_supported_versions, &error_details));
  EXPECT_FALSE(error_details.empty());
}

// Test that the library is using the correct labels for each version, and
// therefore generating correct obfuscators, using the test vectors in appendix
// A of each RFC or internet-draft.
TEST_F(CryptoUtilsTest, ValidateCryptoLabels) {
  // if the number of HTTP/3 QUIC versions has changed, we need to change the
  // expected_keys hardcoded into this test. Regrettably, this is not a
  // compile-time constant.
  EXPECT_EQ(AllSupportedVersionsWithTls().size(), 3u);
  const char draft_29_key[] = {// test vector from draft-ietf-quic-tls-29, A.1
                               0x14,
                               static_cast<char>(0x9d),
                               0x0b,
                               0x16,
                               0x62,
                               static_cast<char>(0xab),
                               static_cast<char>(0x87),
                               0x1f,
                               static_cast<char>(0xbe),
                               0x63,
                               static_cast<char>(0xc4),
                               static_cast<char>(0x9b),
                               0x5e,
                               0x65,
                               0x5a,
                               0x5d};
  const char v1_key[] = {// test vector from RFC 9001, A.1
                         static_cast<char>(0xcf),
                         0x3a,
                         0x53,
                         0x31,
                         0x65,
                         0x3c,
                         0x36,
                         0x4c,
                         static_cast<char>(0x88),
                         static_cast<char>(0xf0),
                         static_cast<char>(0xf3),
                         0x79,
                         static_cast<char>(0xb6),
                         0x06,
                         0x7e,
                         0x37};
  const char v2_01_key[] = {// test vector from draft-ietf-quic-v2-01
                            0x15,
                            static_cast<char>(0xd5),
                            static_cast<char>(0xb4),
                            static_cast<char>(0xd9),
                            static_cast<char>(0xa2),
                            static_cast<char>(0xb8),
                            static_cast<char>(0x91),
                            0x6a,
                            static_cast<char>(0xa3),
                            static_cast<char>(0x9b),
                            0x1b,
                            static_cast<char>(0xfe),
                            0x57,
                            0x4d,
                            0x2a,
                            static_cast<char>(0xad)};
  const char connection_id[] =  // test vector from both docs
      {static_cast<char>(0x83),
       static_cast<char>(0x94),
       static_cast<char>(0xc8),
       static_cast<char>(0xf0),
       0x3e,
       0x51,
       0x57,
       0x08};
  const QuicConnectionId cid(connection_id, sizeof(connection_id));
  const char* key_str;
  size_t key_size;
  for (const ParsedQuicVersion& version : AllSupportedVersionsWithTls()) {
    if (version == ParsedQuicVersion::Draft29()) {
      key_str = draft_29_key;
      key_size = sizeof(draft_29_key);
    } else if (version == ParsedQuicVersion::RFCv1()) {
      key_str = v1_key;
      key_size = sizeof(v1_key);
    } else {  // draft-ietf-quic-v2-01
      key_str = v2_01_key;
      key_size = sizeof(v2_01_key);
    }
    const absl::string_view expected_key{key_str, key_size};

    CrypterPair crypters;
    CryptoUtils::CreateInitialObfuscators(Perspective::IS_SERVER, version, cid,
                                          &crypters);
    EXPECT_EQ(crypters.encrypter->GetKey(), expected_key);
  }
}

}  // namespace
}  // namespace test
}  // namespace quic
