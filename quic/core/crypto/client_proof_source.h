// Copyright (c) 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_CRYPTO_CLIENT_PROOF_SOURCE_H_
#define QUICHE_QUIC_CORE_CRYPTO_CLIENT_PROOF_SOURCE_H_

#include <memory>

#include "absl/container/flat_hash_map.h"
#include "quic/core/crypto/certificate_view.h"
#include "quic/core/crypto/proof_source.h"

namespace quic {

// ClientProofSource is the interface for a QUIC client to provide client certs
// and keys based on server hostname. It is only used by TLS handshakes.
class QUIC_EXPORT_PRIVATE ClientProofSource {
 public:
  using Chain = ProofSource::Chain;

  virtual ~ClientProofSource() {}

  struct QUIC_EXPORT_PRIVATE CertAndKey {
    CertAndKey(quiche::QuicheReferenceCountedPointer<Chain> chain,
               CertificatePrivateKey private_key)
        : chain(std::move(chain)), private_key(std::move(private_key)) {}

    quiche::QuicheReferenceCountedPointer<Chain> chain;
    CertificatePrivateKey private_key;
  };

  // Get the client certificate to be sent to the server with |server_hostname|
  // and its corresponding private key. It returns nullptr if the cert and key
  // can not be found.
  //
  // |server_hostname| is typically a full domain name(www.foo.com), but it
  // could also be a wildcard domain(*.foo.com), or a "*" which will return the
  // default cert.
  virtual const CertAndKey* GetCertAndKey(
      absl::string_view server_hostname) const = 0;
};

// DefaultClientProofSource is an implementation that simply keeps an in memory
// map of server hostnames to certs.
class QUIC_EXPORT_PRIVATE DefaultClientProofSource : public ClientProofSource {
 public:
  ~DefaultClientProofSource() override {}

  // Associate all hostnames in |server_hostnames| with {|chain|,|private_key|}.
  // Elements of |server_hostnames| can be full domain names(www.foo.com),
  // wildcard domains(*.foo.com), or "*" which means the given cert chain is the
  // default one.
  // If any element of |server_hostnames| is already associated with a cert
  // chain, it will be updated to be associated with the new cert chain.
  bool AddCertAndKey(std::vector<std::string> server_hostnames,
                     quiche::QuicheReferenceCountedPointer<Chain> chain,
                     CertificatePrivateKey private_key);

  // ClientProofSource implementation
  const CertAndKey* GetCertAndKey(absl::string_view hostname) const override;

 private:
  const CertAndKey* LookupExact(absl::string_view map_key) const;
  absl::flat_hash_map<std::string, std::shared_ptr<CertAndKey>> cert_and_keys_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_CRYPTO_CLIENT_PROOF_SOURCE_H_
