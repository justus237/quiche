// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/core/crypto/proof_source_x509.h"

#include <memory>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"
#include "quic/core/crypto/certificate_view.h"
#include "quic/core/crypto/crypto_protocol.h"
#include "quic/core/quic_data_writer.h"
#include "quic/platform/api/quic_bug_tracker.h"
#include "common/quiche_endian.h"

namespace quic {

std::unique_ptr<ProofSourceX509> ProofSourceX509::Create(
    quiche::QuicheReferenceCountedPointer<Chain> default_chain,
    CertificatePrivateKey default_key) {
  std::unique_ptr<ProofSourceX509> result(new ProofSourceX509());
  if (!result->AddCertificateChain(default_chain, std::move(default_key))) {
    return nullptr;
  }
  result->default_certificate_ = &result->certificates_.front();
  return result;
}

void ProofSourceX509::GetProof(
    const QuicSocketAddress& /*server_address*/,
    const QuicSocketAddress& /*client_address*/,
    const std::string& hostname,
    const std::string& server_config,
    QuicTransportVersion /*transport_version*/,
    absl::string_view chlo_hash,
    std::unique_ptr<ProofSource::Callback> callback) {
  QuicCryptoProof proof;

  size_t payload_size = sizeof(kProofSignatureLabel) + sizeof(uint32_t) +
                        chlo_hash.size() + server_config.size();
  auto payload = std::make_unique<char[]>(payload_size);
  QuicDataWriter payload_writer(payload_size, payload.get(),
                                quiche::Endianness::HOST_BYTE_ORDER);
  bool success = payload_writer.WriteBytes(kProofSignatureLabel,
                                           sizeof(kProofSignatureLabel)) &&
                 payload_writer.WriteUInt32(chlo_hash.size()) &&
                 payload_writer.WriteStringPiece(chlo_hash) &&
                 payload_writer.WriteStringPiece(server_config);
  if (!success) {
    callback->Run(/*ok=*/false, nullptr, proof, nullptr);
    return;
  }

  Certificate* certificate = GetCertificate(hostname, &proof.cert_matched_sni);
  proof.signature =
      certificate->key.Sign(absl::string_view(payload.get(), payload_size),
                            SSL_SIGN_RSA_PSS_RSAE_SHA256);
  callback->Run(/*ok=*/!proof.signature.empty(), certificate->chain, proof,
                nullptr);
}

quiche::QuicheReferenceCountedPointer<ProofSource::Chain>
ProofSourceX509::GetCertChain(const QuicSocketAddress& /*server_address*/,
                              const QuicSocketAddress& /*client_address*/,
                              const std::string& hostname,
                              bool* cert_matched_sni) {
  return GetCertificate(hostname, cert_matched_sni)->chain;
}

void ProofSourceX509::ComputeTlsSignature(
    const QuicSocketAddress& /*server_address*/,
    const QuicSocketAddress& /*client_address*/,
    const std::string& hostname,
    uint16_t signature_algorithm,
    absl::string_view in,
    std::unique_ptr<ProofSource::SignatureCallback> callback) {
  bool cert_matched_sni;
  std::string signature = GetCertificate(hostname, &cert_matched_sni)
                              ->key.Sign(in, signature_algorithm);
  callback->Run(/*ok=*/!signature.empty(), signature, nullptr);
}

absl::InlinedVector<uint16_t, 8>
ProofSourceX509::SupportedTlsSignatureAlgorithms() const {
  // Let ComputeTlsSignature() report an error if a bad signature algorithm is
  // requested.
  return {};
}

ProofSource::TicketCrypter* ProofSourceX509::GetTicketCrypter() {
  return nullptr;
}

bool ProofSourceX509::AddCertificateChain(
    quiche::QuicheReferenceCountedPointer<Chain> chain,
    CertificatePrivateKey key) {
  if (chain->certs.empty()) {
    QUIC_BUG(quic_bug_10644_1) << "Empty certificate chain supplied.";
    return false;
  }

  std::unique_ptr<CertificateView> leaf =
      CertificateView::ParseSingleCertificate(chain->certs[0]);
  if (leaf == nullptr) {
    QUIC_BUG(quic_bug_10644_2)
        << "Unable to parse X.509 leaf certificate in the supplied chain.";
    return false;
  }
  if (!key.MatchesPublicKey(*leaf)) {
    QUIC_BUG(quic_bug_10644_3)
        << "Private key does not match the leaf certificate.";
    return false;
  }

  certificates_.push_front(Certificate{
      chain,
      std::move(key),
  });
  Certificate* certificate = &certificates_.front();

  for (absl::string_view host : leaf->subject_alt_name_domains()) {
    certificate_map_[std::string(host)] = certificate;
  }
  return true;
}

ProofSourceX509::Certificate* ProofSourceX509::GetCertificate(
    const std::string& hostname, bool* cert_matched_sni) const {
  auto it = certificate_map_.find(hostname);
  if (it != certificate_map_.end()) {
    *cert_matched_sni = true;
    return it->second;
  }
  auto dot_pos = hostname.find('.');
  if (dot_pos != std::string::npos) {
    std::string wildcard = absl::StrCat("*", hostname.substr(dot_pos));
    it = certificate_map_.find(wildcard);
    if (it != certificate_map_.end()) {
      *cert_matched_sni = true;
      return it->second;
    }
  }
  *cert_matched_sni = false;
  return default_certificate_;
}

}  // namespace quic
