// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/core/quic_versions.h"

#include "absl/base/macros.h"
#include "quic/platform/api/quic_expect_bug.h"
#include "quic/platform/api/quic_flags.h"
#include "quic/platform/api/quic_logging.h"
#include "quic/platform/api/quic_mock_log.h"
#include "quic/platform/api/quic_test.h"

namespace quic {
namespace test {
namespace {

using ::testing::ElementsAre;
using ::testing::IsEmpty;

TEST(QuicVersionsTest, CreateQuicVersionLabelUnsupported) {
  EXPECT_QUIC_BUG(
      CreateQuicVersionLabel(UnsupportedQuicVersion()),
      "Unsupported version QUIC_VERSION_UNSUPPORTED PROTOCOL_UNSUPPORTED");
}

TEST(QuicVersionsTest, KnownAndValid) {
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_TRUE(version.IsKnown());
    EXPECT_TRUE(ParsedQuicVersionIsValid(version.handshake_protocol,
                                         version.transport_version));
  }
  ParsedQuicVersion unsupported = UnsupportedQuicVersion();
  EXPECT_FALSE(unsupported.IsKnown());
  EXPECT_TRUE(ParsedQuicVersionIsValid(unsupported.handshake_protocol,
                                       unsupported.transport_version));
  ParsedQuicVersion reserved = QuicVersionReservedForNegotiation();
  EXPECT_TRUE(reserved.IsKnown());
  EXPECT_TRUE(ParsedQuicVersionIsValid(reserved.handshake_protocol,
                                       reserved.transport_version));
  // Check that invalid combinations are not valid.
  EXPECT_FALSE(ParsedQuicVersionIsValid(PROTOCOL_TLS1_3, QUIC_VERSION_43));
  EXPECT_FALSE(ParsedQuicVersionIsValid(PROTOCOL_QUIC_CRYPTO,
                                        QUIC_VERSION_IETF_DRAFT_29));
  // Check that deprecated versions are not valid.
  EXPECT_FALSE(ParsedQuicVersionIsValid(PROTOCOL_QUIC_CRYPTO,
                                        static_cast<QuicTransportVersion>(33)));
  EXPECT_FALSE(ParsedQuicVersionIsValid(PROTOCOL_QUIC_CRYPTO,
                                        static_cast<QuicTransportVersion>(99)));
  EXPECT_FALSE(ParsedQuicVersionIsValid(PROTOCOL_TLS1_3,
                                        static_cast<QuicTransportVersion>(99)));
}

TEST(QuicVersionsTest, Features) {
  ParsedQuicVersion parsed_version_q043 = ParsedQuicVersion::Q043();
  ParsedQuicVersion parsed_version_draft_29 = ParsedQuicVersion::Draft29();

  EXPECT_TRUE(parsed_version_q043.IsKnown());
  EXPECT_FALSE(parsed_version_q043.KnowsWhichDecrypterToUse());
  EXPECT_FALSE(parsed_version_q043.UsesInitialObfuscators());
  EXPECT_FALSE(parsed_version_q043.AllowsLowFlowControlLimits());
  EXPECT_FALSE(parsed_version_q043.HasHeaderProtection());
  EXPECT_FALSE(parsed_version_q043.SupportsRetry());
  EXPECT_FALSE(
      parsed_version_q043.SendsVariableLengthPacketNumberInLongHeader());
  EXPECT_FALSE(parsed_version_q043.AllowsVariableLengthConnectionIds());
  EXPECT_FALSE(parsed_version_q043.SupportsClientConnectionIds());
  EXPECT_FALSE(parsed_version_q043.HasLengthPrefixedConnectionIds());
  EXPECT_FALSE(parsed_version_q043.SupportsAntiAmplificationLimit());
  EXPECT_FALSE(parsed_version_q043.CanSendCoalescedPackets());
  EXPECT_TRUE(parsed_version_q043.SupportsGoogleAltSvcFormat());
  EXPECT_FALSE(parsed_version_q043.HasIetfInvariantHeader());
  EXPECT_FALSE(parsed_version_q043.SupportsMessageFrames());
  EXPECT_FALSE(parsed_version_q043.UsesHttp3());
  EXPECT_FALSE(parsed_version_q043.HasLongHeaderLengths());
  EXPECT_FALSE(parsed_version_q043.UsesCryptoFrames());
  EXPECT_FALSE(parsed_version_q043.HasIetfQuicFrames());
  EXPECT_FALSE(parsed_version_q043.UsesTls());
  EXPECT_TRUE(parsed_version_q043.UsesQuicCrypto());

  EXPECT_TRUE(parsed_version_draft_29.IsKnown());
  EXPECT_TRUE(parsed_version_draft_29.KnowsWhichDecrypterToUse());
  EXPECT_TRUE(parsed_version_draft_29.UsesInitialObfuscators());
  EXPECT_TRUE(parsed_version_draft_29.AllowsLowFlowControlLimits());
  EXPECT_TRUE(parsed_version_draft_29.HasHeaderProtection());
  EXPECT_TRUE(parsed_version_draft_29.SupportsRetry());
  EXPECT_TRUE(
      parsed_version_draft_29.SendsVariableLengthPacketNumberInLongHeader());
  EXPECT_TRUE(parsed_version_draft_29.AllowsVariableLengthConnectionIds());
  EXPECT_TRUE(parsed_version_draft_29.SupportsClientConnectionIds());
  EXPECT_TRUE(parsed_version_draft_29.HasLengthPrefixedConnectionIds());
  EXPECT_TRUE(parsed_version_draft_29.SupportsAntiAmplificationLimit());
  EXPECT_TRUE(parsed_version_draft_29.CanSendCoalescedPackets());
  EXPECT_FALSE(parsed_version_draft_29.SupportsGoogleAltSvcFormat());
  EXPECT_TRUE(parsed_version_draft_29.HasIetfInvariantHeader());
  EXPECT_TRUE(parsed_version_draft_29.SupportsMessageFrames());
  EXPECT_TRUE(parsed_version_draft_29.UsesHttp3());
  EXPECT_TRUE(parsed_version_draft_29.HasLongHeaderLengths());
  EXPECT_TRUE(parsed_version_draft_29.UsesCryptoFrames());
  EXPECT_TRUE(parsed_version_draft_29.HasIetfQuicFrames());
  EXPECT_TRUE(parsed_version_draft_29.UsesTls());
  EXPECT_FALSE(parsed_version_draft_29.UsesQuicCrypto());
}

TEST(QuicVersionsTest, ParseQuicVersionLabel) {
  static_assert(SupportedVersions().size() == 6u,
                "Supported versions out of sync");
  EXPECT_EQ(ParsedQuicVersion::Q043(),
            ParseQuicVersionLabel(MakeVersionLabel('Q', '0', '4', '3')));
  EXPECT_EQ(ParsedQuicVersion::Q046(),
            ParseQuicVersionLabel(MakeVersionLabel('Q', '0', '4', '6')));
  EXPECT_EQ(ParsedQuicVersion::Q050(),
            ParseQuicVersionLabel(MakeVersionLabel('Q', '0', '5', '0')));
  EXPECT_EQ(ParsedQuicVersion::Draft29(),
            ParseQuicVersionLabel(MakeVersionLabel(0xff, 0x00, 0x00, 0x1d)));
  EXPECT_EQ(ParsedQuicVersion::RFCv1(),
            ParseQuicVersionLabel(MakeVersionLabel(0x00, 0x00, 0x00, 0x01)));
  EXPECT_EQ(ParsedQuicVersion::V2Draft01(),
            ParseQuicVersionLabel(MakeVersionLabel(0x70, 0x9a, 0x50, 0xc4)));
  EXPECT_EQ((ParsedQuicVersionVector{ParsedQuicVersion::V2Draft01(),
                                     ParsedQuicVersion::RFCv1(),
                                     ParsedQuicVersion::Draft29()}),
            ParseQuicVersionLabelVector(QuicVersionLabelVector{
                MakeVersionLabel(0x70, 0x9a, 0x50, 0xc4),
                MakeVersionLabel(0x00, 0x00, 0x00, 0x01),
                MakeVersionLabel(0xaa, 0xaa, 0xaa, 0xaa),
                MakeVersionLabel(0xff, 0x00, 0x00, 0x1d)}));

  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_EQ(version, ParseQuicVersionLabel(CreateQuicVersionLabel(version)));
  }
}

TEST(QuicVersionsTest, ParseQuicVersionString) {
  static_assert(SupportedVersions().size() == 6u,
                "Supported versions out of sync");
  EXPECT_EQ(ParsedQuicVersion::Q043(), ParseQuicVersionString("Q043"));
  EXPECT_EQ(ParsedQuicVersion::Q046(),
            ParseQuicVersionString("QUIC_VERSION_46"));
  EXPECT_EQ(ParsedQuicVersion::Q046(), ParseQuicVersionString("46"));
  EXPECT_EQ(ParsedQuicVersion::Q046(), ParseQuicVersionString("Q046"));
  EXPECT_EQ(ParsedQuicVersion::Q050(), ParseQuicVersionString("Q050"));
  EXPECT_EQ(ParsedQuicVersion::Q050(), ParseQuicVersionString("50"));
  EXPECT_EQ(ParsedQuicVersion::Q050(), ParseQuicVersionString("h3-Q050"));

  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionString(""));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionString("Q 46"));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionString("Q046 "));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionString("99"));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionString("70"));

  EXPECT_EQ(ParsedQuicVersion::Draft29(), ParseQuicVersionString("ff00001d"));
  EXPECT_EQ(ParsedQuicVersion::Draft29(), ParseQuicVersionString("draft29"));
  EXPECT_EQ(ParsedQuicVersion::Draft29(), ParseQuicVersionString("h3-29"));

  EXPECT_EQ(ParsedQuicVersion::RFCv1(), ParseQuicVersionString("00000001"));
  EXPECT_EQ(ParsedQuicVersion::RFCv1(), ParseQuicVersionString("h3"));

  // QUICv2 will never be the result for "h3".

  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_EQ(version,
              ParseQuicVersionString(ParsedQuicVersionToString(version)));
    EXPECT_EQ(version, ParseQuicVersionString(QuicVersionLabelToString(
                           CreateQuicVersionLabel(version))));
    if (!version.AlpnDeferToRFCv1()) {
      EXPECT_EQ(version, ParseQuicVersionString(AlpnForVersion(version)));
    }
  }
}

TEST(QuicVersionsTest, ParseQuicVersionVectorString) {
  ParsedQuicVersion version_q046 = ParsedQuicVersion::Q046();
  ParsedQuicVersion version_q050 = ParsedQuicVersion::Q050();
  ParsedQuicVersion version_draft_29 = ParsedQuicVersion::Draft29();

  EXPECT_THAT(ParseQuicVersionVectorString(""), IsEmpty());

  EXPECT_THAT(ParseQuicVersionVectorString("QUIC_VERSION_50"),
              ElementsAre(version_q050));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-Q050"),
              ElementsAre(version_q050));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-Q050, h3-29"),
              ElementsAre(version_q050, version_draft_29));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-29,h3-Q050,h3-29"),
              ElementsAre(version_draft_29, version_q050));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-29,h3-Q050, h3-29"),
              ElementsAre(version_draft_29, version_q050));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-29, h3-Q050"),
              ElementsAre(version_draft_29, version_q050));
  EXPECT_THAT(ParseQuicVersionVectorString("QUIC_VERSION_50,h3-29"),
              ElementsAre(version_q050, version_draft_29));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-29,QUIC_VERSION_50"),
              ElementsAre(version_draft_29, version_q050));
  EXPECT_THAT(ParseQuicVersionVectorString("QUIC_VERSION_50, h3-29"),
              ElementsAre(version_q050, version_draft_29));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-29, QUIC_VERSION_50"),
              ElementsAre(version_draft_29, version_q050));
  EXPECT_THAT(ParseQuicVersionVectorString("QUIC_VERSION_50,QUIC_VERSION_46"),
              ElementsAre(version_q050, version_q046));
  EXPECT_THAT(ParseQuicVersionVectorString("QUIC_VERSION_46,QUIC_VERSION_50"),
              ElementsAre(version_q046, version_q050));

  // Regression test for https://crbug.com/1044952.
  EXPECT_THAT(ParseQuicVersionVectorString("QUIC_VERSION_50, QUIC_VERSION_50"),
              ElementsAre(version_q050));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-Q050, h3-Q050"),
              ElementsAre(version_q050));
  EXPECT_THAT(ParseQuicVersionVectorString("h3-Q050, QUIC_VERSION_50"),
              ElementsAre(version_q050));
  EXPECT_THAT(ParseQuicVersionVectorString(
                  "QUIC_VERSION_50, h3-Q050, QUIC_VERSION_50, h3-Q050"),
              ElementsAre(version_q050));
  EXPECT_THAT(ParseQuicVersionVectorString("QUIC_VERSION_50, h3-29, h3-Q050"),
              ElementsAre(version_q050, version_draft_29));

  EXPECT_THAT(ParseQuicVersionVectorString("99"), IsEmpty());
  EXPECT_THAT(ParseQuicVersionVectorString("70"), IsEmpty());
  EXPECT_THAT(ParseQuicVersionVectorString("h3-01"), IsEmpty());
  EXPECT_THAT(ParseQuicVersionVectorString("h3-01,h3-29"),
              ElementsAre(version_draft_29));
}

// Do not use MakeVersionLabel() to generate expectations, because
// CreateQuicVersionLabel() uses MakeVersionLabel() internally,
// in case it has a bug.
TEST(QuicVersionsTest, CreateQuicVersionLabel) {
  static_assert(SupportedVersions().size() == 6u,
                "Supported versions out of sync");
  EXPECT_EQ(0x51303433u, CreateQuicVersionLabel(ParsedQuicVersion::Q043()));
  EXPECT_EQ(0x51303436u, CreateQuicVersionLabel(ParsedQuicVersion::Q046()));
  EXPECT_EQ(0x51303530u, CreateQuicVersionLabel(ParsedQuicVersion::Q050()));
  EXPECT_EQ(0xff00001du, CreateQuicVersionLabel(ParsedQuicVersion::Draft29()));
  EXPECT_EQ(0x00000001u, CreateQuicVersionLabel(ParsedQuicVersion::RFCv1()));
  EXPECT_EQ(0x709a50c4u,
            CreateQuicVersionLabel(ParsedQuicVersion::V2Draft01()));

  // Make sure the negotiation reserved version is in the IETF reserved space.
  EXPECT_EQ(
      0xda5a3a3au & 0x0f0f0f0f,
      CreateQuicVersionLabel(ParsedQuicVersion::ReservedForNegotiation()) &
          0x0f0f0f0f);

  // Make sure that disabling randomness works.
  SetQuicFlag(FLAGS_quic_disable_version_negotiation_grease_randomness, true);
  EXPECT_EQ(0xda5a3a3au, CreateQuicVersionLabel(
                             ParsedQuicVersion::ReservedForNegotiation()));
}

TEST(QuicVersionsTest, QuicVersionLabelToString) {
  static_assert(SupportedVersions().size() == 6u,
                "Supported versions out of sync");
  EXPECT_EQ("Q043", QuicVersionLabelToString(
                        CreateQuicVersionLabel(ParsedQuicVersion::Q043())));
  EXPECT_EQ("Q046", QuicVersionLabelToString(
                        CreateQuicVersionLabel(ParsedQuicVersion::Q046())));
  EXPECT_EQ("Q050", QuicVersionLabelToString(
                        CreateQuicVersionLabel(ParsedQuicVersion::Q050())));
  EXPECT_EQ("ff00001d", QuicVersionLabelToString(CreateQuicVersionLabel(
                            ParsedQuicVersion::Draft29())));
  EXPECT_EQ("00000001", QuicVersionLabelToString(CreateQuicVersionLabel(
                            ParsedQuicVersion::RFCv1())));
  EXPECT_EQ("709a50c4", QuicVersionLabelToString(CreateQuicVersionLabel(
                            ParsedQuicVersion::V2Draft01())));

  QuicVersionLabelVector version_labels = {
      MakeVersionLabel('Q', '0', '3', '5'),
      MakeVersionLabel('T', '0', '3', '8'),
      MakeVersionLabel(0xff, 0, 0, 7),
  };

  EXPECT_EQ("Q035", QuicVersionLabelToString(version_labels[0]));
  EXPECT_EQ("T038", QuicVersionLabelToString(version_labels[1]));
  EXPECT_EQ("ff000007", QuicVersionLabelToString(version_labels[2]));

  EXPECT_EQ("Q035,T038,ff000007",
            QuicVersionLabelVectorToString(version_labels));
  EXPECT_EQ("Q035:T038:ff000007",
            QuicVersionLabelVectorToString(version_labels, ":", 2));
  EXPECT_EQ("Q035|T038|...",
            QuicVersionLabelVectorToString(version_labels, "|", 1));

  std::ostringstream os;
  os << version_labels;
  EXPECT_EQ("Q035,T038,ff000007", os.str());
}

TEST(QuicVersionsTest, ParseQuicVersionLabelString) {
  static_assert(SupportedVersions().size() == 6u,
                "Supported versions out of sync");
  // Explicitly test known QUIC version label strings.
  EXPECT_EQ(ParsedQuicVersion::Q043(), ParseQuicVersionLabelString("Q043"));
  EXPECT_EQ(ParsedQuicVersion::Q046(), ParseQuicVersionLabelString("Q046"));
  EXPECT_EQ(ParsedQuicVersion::Q050(), ParseQuicVersionLabelString("Q050"));
  EXPECT_EQ(ParsedQuicVersion::Draft29(),
            ParseQuicVersionLabelString("ff00001d"));
  EXPECT_EQ(ParsedQuicVersion::RFCv1(),
            ParseQuicVersionLabelString("00000001"));
  EXPECT_EQ(ParsedQuicVersion::V2Draft01(),
            ParseQuicVersionLabelString("709a50c4"));

  // Sanity check that a variety of other serialization formats are ignored.
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionLabelString("1"));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionLabelString("46"));
  EXPECT_EQ(UnsupportedQuicVersion(),
            ParseQuicVersionLabelString("QUIC_VERSION_46"));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionLabelString("h3"));
  EXPECT_EQ(UnsupportedQuicVersion(), ParseQuicVersionLabelString("h3-29"));

  // Test round-trips between QuicVersionLabelToString and
  // ParseQuicVersionLabelString.
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_EQ(version, ParseQuicVersionLabelString(QuicVersionLabelToString(
                           CreateQuicVersionLabel(version))));
  }
}

TEST(QuicVersionsTest, QuicVersionToString) {
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED",
            QuicVersionToString(QUIC_VERSION_UNSUPPORTED));

  QuicTransportVersion single_version[] = {QUIC_VERSION_43};
  QuicTransportVersionVector versions_vector;
  for (size_t i = 0; i < ABSL_ARRAYSIZE(single_version); ++i) {
    versions_vector.push_back(single_version[i]);
  }
  EXPECT_EQ("QUIC_VERSION_43",
            QuicTransportVersionVectorToString(versions_vector));

  QuicTransportVersion multiple_versions[] = {QUIC_VERSION_UNSUPPORTED,
                                              QUIC_VERSION_43};
  versions_vector.clear();
  for (size_t i = 0; i < ABSL_ARRAYSIZE(multiple_versions); ++i) {
    versions_vector.push_back(multiple_versions[i]);
  }
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED,QUIC_VERSION_43",
            QuicTransportVersionVectorToString(versions_vector));

  // Make sure that all supported versions are present in QuicVersionToString.
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_NE("QUIC_VERSION_UNSUPPORTED",
              QuicVersionToString(version.transport_version));
  }

  std::ostringstream os;
  os << versions_vector;
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED,QUIC_VERSION_43", os.str());
}

TEST(QuicVersionsTest, ParsedQuicVersionToString) {
  EXPECT_EQ("0", ParsedQuicVersionToString(ParsedQuicVersion::Unsupported()));
  EXPECT_EQ("Q043", ParsedQuicVersionToString(ParsedQuicVersion::Q043()));
  EXPECT_EQ("Q046", ParsedQuicVersionToString(ParsedQuicVersion::Q046()));
  EXPECT_EQ("Q050", ParsedQuicVersionToString(ParsedQuicVersion::Q050()));
  EXPECT_EQ("draft29", ParsedQuicVersionToString(ParsedQuicVersion::Draft29()));
  EXPECT_EQ("RFCv1", ParsedQuicVersionToString(ParsedQuicVersion::RFCv1()));
  EXPECT_EQ("v2draft01",
            ParsedQuicVersionToString(ParsedQuicVersion::V2Draft01()));

  ParsedQuicVersionVector versions_vector = {ParsedQuicVersion::Q043()};
  EXPECT_EQ("Q043", ParsedQuicVersionVectorToString(versions_vector));

  versions_vector = {ParsedQuicVersion::Unsupported(),
                     ParsedQuicVersion::Q043()};
  EXPECT_EQ("0,Q043", ParsedQuicVersionVectorToString(versions_vector));
  EXPECT_EQ("0:Q043", ParsedQuicVersionVectorToString(versions_vector, ":",
                                                      versions_vector.size()));
  EXPECT_EQ("0|...", ParsedQuicVersionVectorToString(versions_vector, "|", 0));

  // Make sure that all supported versions are present in
  // ParsedQuicVersionToString.
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_NE("0", ParsedQuicVersionToString(version));
  }

  std::ostringstream os;
  os << versions_vector;
  EXPECT_EQ("0,Q043", os.str());
}

TEST(QuicVersionsTest, FilterSupportedVersionsAllVersions) {
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    QuicEnableVersion(version);
  }
  ParsedQuicVersionVector expected_parsed_versions;
  for (const ParsedQuicVersion& version : SupportedVersions()) {
    expected_parsed_versions.push_back(version);
  }
  EXPECT_EQ(expected_parsed_versions,
            FilterSupportedVersions(AllSupportedVersions()));
  EXPECT_EQ(expected_parsed_versions, AllSupportedVersions());
}

TEST(QuicVersionsTest, FilterSupportedVersionsWithoutFirstVersion) {
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    QuicEnableVersion(version);
  }
  QuicDisableVersion(AllSupportedVersions().front());
  ParsedQuicVersionVector expected_parsed_versions;
  for (const ParsedQuicVersion& version : SupportedVersions()) {
    expected_parsed_versions.push_back(version);
  }
  expected_parsed_versions.erase(expected_parsed_versions.begin());
  EXPECT_EQ(expected_parsed_versions,
            FilterSupportedVersions(AllSupportedVersions()));
}

TEST(QuicVersionsTest, LookUpParsedVersionByIndex) {
  ParsedQuicVersionVector all_versions = AllSupportedVersions();
  int version_count = all_versions.size();
  for (int i = -5; i <= version_count + 1; ++i) {
    ParsedQuicVersionVector index = ParsedVersionOfIndex(all_versions, i);
    if (i >= 0 && i < version_count) {
      EXPECT_EQ(all_versions[i], index[0]);
    } else {
      EXPECT_EQ(UnsupportedQuicVersion(), index[0]);
    }
  }
}

// This test may appear to be so simplistic as to be unnecessary,
// yet a typo was made in doing the #defines and it was caught
// only in some test far removed from here... Better safe than sorry.
TEST(QuicVersionsTest, CheckTransportVersionNumbersForTypos) {
  static_assert(SupportedVersions().size() == 6u,
                "Supported versions out of sync");
  EXPECT_EQ(QUIC_VERSION_43, 43);
  EXPECT_EQ(QUIC_VERSION_46, 46);
  EXPECT_EQ(QUIC_VERSION_50, 50);
  EXPECT_EQ(QUIC_VERSION_IETF_DRAFT_29, 73);
  EXPECT_EQ(QUIC_VERSION_IETF_RFC_V1, 80);
  EXPECT_EQ(QUIC_VERSION_IETF_2_DRAFT_01, 81);
}

TEST(QuicVersionsTest, AlpnForVersion) {
  static_assert(SupportedVersions().size() == 6u,
                "Supported versions out of sync");
  EXPECT_EQ("h3-Q043", AlpnForVersion(ParsedQuicVersion::Q043()));
  EXPECT_EQ("h3-Q046", AlpnForVersion(ParsedQuicVersion::Q046()));
  EXPECT_EQ("h3-Q050", AlpnForVersion(ParsedQuicVersion::Q050()));
  EXPECT_EQ("h3-29", AlpnForVersion(ParsedQuicVersion::Draft29()));
  EXPECT_EQ("h3", AlpnForVersion(ParsedQuicVersion::RFCv1()));
  EXPECT_EQ("h3", AlpnForVersion(ParsedQuicVersion::V2Draft01()));
}

TEST(QuicVersionsTest, QuicVersionEnabling) {
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    QuicFlagSaver flag_saver;
    QuicDisableVersion(version);
    EXPECT_FALSE(QuicVersionIsEnabled(version));
    QuicEnableVersion(version);
    EXPECT_TRUE(QuicVersionIsEnabled(version));
  }
}

TEST(QuicVersionsTest, ReservedForNegotiation) {
  EXPECT_EQ(QUIC_VERSION_RESERVED_FOR_NEGOTIATION,
            QuicVersionReservedForNegotiation().transport_version);
  // QUIC_VERSION_RESERVED_FOR_NEGOTIATION MUST NOT be supported.
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    EXPECT_NE(QUIC_VERSION_RESERVED_FOR_NEGOTIATION, version.transport_version);
  }
}

TEST(QuicVersionsTest, SupportedVersionsHasCorrectList) {
  size_t index = 0;
  for (HandshakeProtocol handshake_protocol : SupportedHandshakeProtocols()) {
    for (int trans_vers = 255; trans_vers > 0; trans_vers--) {
      QuicTransportVersion transport_version =
          static_cast<QuicTransportVersion>(trans_vers);
      SCOPED_TRACE(index);
      if (ParsedQuicVersionIsValid(handshake_protocol, transport_version)) {
        ParsedQuicVersion version = SupportedVersions()[index];
        EXPECT_EQ(version,
                  ParsedQuicVersion(handshake_protocol, transport_version));
        index++;
      }
    }
  }
  EXPECT_EQ(SupportedVersions().size(), index);
}

TEST(QuicVersionsTest, SupportedVersionsAllDistinct) {
  for (size_t index1 = 0; index1 < SupportedVersions().size(); ++index1) {
    ParsedQuicVersion version1 = SupportedVersions()[index1];
    for (size_t index2 = index1 + 1; index2 < SupportedVersions().size();
         ++index2) {
      ParsedQuicVersion version2 = SupportedVersions()[index2];
      EXPECT_NE(version1, version2) << version1 << " " << version2;
      EXPECT_NE(CreateQuicVersionLabel(version1),
                CreateQuicVersionLabel(version2))
          << version1 << " " << version2;
      // The one pair where ALPNs are the same.
      if ((version1 != ParsedQuicVersion::V2Draft01()) &&
          (version2 != ParsedQuicVersion::RFCv1())) {
        EXPECT_NE(AlpnForVersion(version1), AlpnForVersion(version2))
            << version1 << " " << version2;
      }
    }
  }
}

TEST(QuicVersionsTest, CurrentSupportedHttp3Versions) {
  ParsedQuicVersionVector h3_versions = CurrentSupportedHttp3Versions();
  ParsedQuicVersionVector all_current_supported_versions =
      CurrentSupportedVersions();
  for (auto& version : all_current_supported_versions) {
    bool version_is_h3 = false;
    for (auto& h3_version : h3_versions) {
      if (version == h3_version) {
        EXPECT_TRUE(version.UsesHttp3());
        version_is_h3 = true;
        break;
      }
    }
    if (!version_is_h3) {
      EXPECT_FALSE(version.UsesHttp3());
    }
  }
}

}  // namespace
}  // namespace test
}  // namespace quic
