// Copyright (c) 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/core/crypto/quic_client_session_cache.h"

#include "quic/core/quic_clock.h"

#include "quic/core/crypto/transport_parameters.h"

#include "absl/strings/string_view.h"
#include "absl/strings/str_split.h"
#include <iostream>
#include <fstream>
#include <ios>
#include <string>
#include "common/quiche_text_utils.h"

namespace quic {

namespace {

const size_t kDefaultMaxEntries = 1024;
// Returns false if the SSL |session| doesn't exist or it is expired at |now|.
bool IsValid(SSL_SESSION* session, uint64_t now) {
  if (!session) return false;

  // now_u64 may be slightly behind because of differences in how
  // time is calculated at this layer versus BoringSSL.
  // Add a second of wiggle room to account for this.
  return !(now + 1 < SSL_SESSION_get_time(session) ||
           now >= SSL_SESSION_get_time(session) +
                      SSL_SESSION_get_timeout(session));
}

bool DoApplicationStatesMatch(const ApplicationState* state,
                              ApplicationState* other) {
  if ((state && !other) || (!state && other)) return false;
  if ((!state && !other) || *state == *other) return true;
  return false;
}

}  // namespace

QuicClientSessionCache::QuicClientSessionCache()
    : QuicClientSessionCache(kDefaultMaxEntries) {}

QuicClientSessionCache::QuicClientSessionCache(size_t max_entries)
    : cache_(max_entries),
      session_cache_file("/tmp/chrome_session_cache.txt"),
      first_lookup_from_cold_start(true),
      first_insert_from_cold_start(true)
      {}

QuicClientSessionCache::~QuicClientSessionCache() { Clear(); }

void QuicClientSessionCache::Insert(const QuicServerId& server_id,
                                    bssl::UniquePtr<SSL_SESSION> session,
                                    const TransportParameters& params,
                                    const ApplicationState* application_state) {
  QUICHE_DCHECK(session) << "TLS session is not inserted into client cache.";
  fprintf(stderr, "session cache entry for %s:%u\n", server_id.host().c_str(), server_id.port());
  QUIC_DLOG(ERROR) << "Setting session ticket for " << server_id.host() << ":" << server_id.port();


  std::vector<uint8_t> serialized_param_bytes;
  bool success = SerializeTransportParameters(ParsedQuicVersion::RFCv1(), params, &serialized_param_bytes);
  if (success != false) {
      fprintf(stderr, "param_str = \"%s\";\n", absl::BytesToHexString(absl::string_view(
              reinterpret_cast<const char*>(serialized_param_bytes.data()),
              serialized_param_bytes.size())).c_str());
  }

  size_t encoded_len;
  uint8_t *encoded;
  SSL_SESSION_to_bytes(session.get(), &encoded, &encoded_len);
  fprintf(stderr, "session_str = \"%s\";\n", absl::BytesToHexString(absl::string_view(
          reinterpret_cast<const char*>(encoded),
          encoded_len)).c_str());

  fprintf(stderr, "app_str = \"%s\";\n", absl::BytesToHexString(absl::string_view(
          reinterpret_cast<const char*>(application_state->data()),
          application_state->size())).c_str());


    if (first_insert_from_cold_start) {
        first_insert_from_cold_start = false;
        //if we are inserting for the first time we are likely visiting a test website
        //we kind of cannot prevent google api stuff to also use this cache unless we manually filter
        //TODO: maybe manually filter all the google api stuff out, would probably make life easier down the road
        //we still have to write all tokens though, because we cannot force new token generation from client
        std::ofstream output_file(session_cache_file.c_str(), std::ios::out | std::ios::app);
        if (output_file) {
            fprintf(stderr, "-----Opened %s from Insert for writing\n", session_cache_file.c_str());
            output_file << "session=" <<server_id.host() << ":" << server_id.port() << "|" <<
                    absl::BytesToHexString(absl::string_view(
                    reinterpret_cast<const char*>(encoded),
                    encoded_len)).c_str() << "|" <<
                    absl::BytesToHexString(absl::string_view(
                    reinterpret_cast<const char*>(serialized_param_bytes.data()),
                    serialized_param_bytes.size())).c_str() << "|" <<
                    absl::BytesToHexString(absl::string_view(
                    reinterpret_cast<const char*>(application_state->data()),
                    application_state->size())).c_str() << "" << std::endl;
        } else {
            fprintf(stderr,
                    "-----Could not open %s %s\nthis means we are probably on macos so instead we test serialization and subsequent parsing of transport params\n",
                    session_cache_file.c_str(), strerror(errno));
            fprintf(stderr, "%s\n", params.ToString().c_str());
            TransportParameters params_;
            std::string error_details;
            bool success = ParseTransportParameters(ParsedQuicVersion::RFCv1(),
                                                    Perspective::IS_SERVER,
                                                    serialized_param_bytes.data(),
                                                    serialized_param_bytes.size(),
                                                    &params_, &error_details);
            if (!success) {
                fprintf(stderr, "error when parsing transport parameters: %s\n", error_details.c_str());
            } else {
                fprintf(stderr, "should be equal to this:\n%s\n", params_.ToString().c_str());
            }

        }
        output_file.close();
    }
  
  
  auto iter = cache_.Lookup(server_id);
  if (iter == cache_.end()) {
    CreateAndInsertEntry(server_id, std::move(session), params,
                         application_state);
    return;
  }

  QUICHE_DCHECK(iter->second->params);
  // The states are both the same, so only need to insert sessions.
  if (params == *iter->second->params &&
      DoApplicationStatesMatch(application_state,
                               iter->second->application_state.get())) {
    iter->second->PushSession(std::move(session));
    return;
  }
  // Erase the existing entry because this Insert call must come from a
  // different QUIC session.
  cache_.Erase(iter);
  CreateAndInsertEntry(server_id, std::move(session), params,
                       application_state);
}

std::unique_ptr<QuicResumptionState> QuicClientSessionCache::Lookup(
    const QuicServerId& server_id, QuicWallTime now, const SSL_CTX* /*ctx*/) {
  if (first_lookup_from_cold_start) {
      first_lookup_from_cold_start = false;
      std::ifstream input_file(session_cache_file.c_str());
      if (input_file.is_open()) {
          fprintf(stderr, "-----Opened %s from Lookup for reading\n", session_cache_file.c_str());

          //we might return early without any state being used but unique pointers should just get destroyed
          auto state = std::make_unique<QuicResumptionState>();

          for (std::string line; getline(input_file, line);) {
              fprintf(stderr, "-----%s\n", line.c_str());
              std::vector<std::string> outer_split = absl::StrSplit(line, '=');
              if (strcmp(outer_split[0].c_str(), "session") == 0) {
                  //case session
                  std::vector<std::string> inner_split = absl::StrSplit(outer_split[1], '|');
                  std::vector<std::string> server_id_from_disk = absl::StrSplit(inner_split[0], ':');
                  if (strcmp(server_id.host().c_str(), server_id_from_disk[0].c_str()) != 0 || server_id.port() != server_id_from_disk[1]) {
                      //set our flag again so we can try again
                      first_lookup_from_cold_start = true;
                      return nullptr;
                  }
                  std::string serialized_param_bytes = absl::HexStringToBytes(absl::string_view(inner_split[2]));
                  TransportParameters params_;
                  std::string error_details;
                  bool success = ParseTransportParameters(ParsedQuicVersion::RFCv1(),
                     Perspective::IS_SERVER,
                     reinterpret_cast<const uint8_t*>(&serialized_param_bytes),
                     sizeof(serialized_param_bytes),
                     &params_, &error_details);
                  //copy it because im too stupid to figure out c++
                  auto params = std::make_unique<TransportParameters>(params_);

                  std::string cached_session =
                  absl::HexStringToBytes(absl::string_view(inner_split[1]));
                  SSL_SESSION* session = SSL_SESSION_from_bytes(
                  reinterpret_cast<const uint8_t*>(cached_session.data()),
                  cached_session.size(), ctx);
                  state->tls_session = bssl::UniquePtr<SSL_SESSION>(session);
                  state->application_state = std::make_unique<ApplicationState>(absl::HexStringToBytes(absl::string_view(inner_split[3])));
                  return state;
              }
              //case token

          }
      } else {
          fprintf(stderr, "-----Could not open %s %s\n", session_cache_file.c_str(), strerror(errno));
      }
      input_file.close();
      //clear the file after using it for the first lookup
      std::ofstream output_file(session_cache_file.c_str(), std::ios::out | std::ios::trunc);
      if (output_file) {
          fprintf(stderr, "-----cleared session cache file successfully\n");
      } else {
          fprintf(stderr, "-----failed clearing session cache file: %s\n", strerror(errno));
      }
      output_file.close();
  }

        auto iter = cache_.Lookup(server_id);
        if (iter == cache_.end()) return nullptr;

        if (!IsValid(iter->second->PeekSession(), now.ToUNIXSeconds())) {
            QUIC_DLOG(INFO) << "TLS Session expired for host:" << server_id.host();
            cache_.Erase(iter);
            return nullptr;
        }
        auto state = std::make_unique<QuicResumptionState>();
        state->tls_session = iter->second->PopSession();
        if (iter->second->params != nullptr) {
            state->transport_params =
                    std::make_unique<TransportParameters>(*iter->second->params);
        }
        if (iter->second->application_state != nullptr) {
            state->application_state =
                    std::make_unique<ApplicationState>(*iter->second->application_state);
        }
        if (!iter->second->token.empty()) {
            state->token = iter->second->token;
            // Clear token after use.
            iter->second->token.clear();
        }

        return state;
    }
}

void QuicClientSessionCache::ClearEarlyData(const QuicServerId& server_id) {
  auto iter = cache_.Lookup(server_id);
  if (iter == cache_.end()) return;
  for (auto& session : iter->second->sessions) {
    if (session) {
      QUIC_DLOG(INFO) << "Clear early data for for host: " << server_id.host();
      session.reset(SSL_SESSION_copy_without_early_data(session.get()));
    }
  }
}

void QuicClientSessionCache::OnNewTokenReceived(const QuicServerId& server_id,
                                                absl::string_view token) {
  if (token.empty()) {
    return;
  }
  fprintf(stderr, "token store entry for %s:%u\n", server_id.host().c_str(), server_id.port());
  fprintf(stderr, "token = \"%s\";\n", absl::BytesToHexString(token).c_str());
    std::ofstream output_file(session_cache_file.c_str(), std::ios::out | std::ios::app);
    if (output_file) {
        output_file << "token=" <<server_id.host() << ":" << server_id.port() << "||" <<
        absl::BytesToHexString(token).c_str() << ";" << std::endl;
    }
  auto iter = cache_.Lookup(server_id);
  if (iter == cache_.end()) {
    return;
  }
  iter->second->token = std::string(token);
}

void QuicClientSessionCache::RemoveExpiredEntries(QuicWallTime now) {
  auto iter = cache_.begin();
  while (iter != cache_.end()) {
    if (!IsValid(iter->second->PeekSession(), now.ToUNIXSeconds())) {
      iter = cache_.Erase(iter);
    } else {
      ++iter;
    }
  }
}

void QuicClientSessionCache::Clear() { cache_.Clear(); }

void QuicClientSessionCache::CreateAndInsertEntry(
    const QuicServerId& server_id, bssl::UniquePtr<SSL_SESSION> session,
    const TransportParameters& params,
    const ApplicationState* application_state) {
  auto entry = std::make_unique<Entry>();
  entry->PushSession(std::move(session));
  entry->params = std::make_unique<TransportParameters>(params);
  if (application_state) {
    entry->application_state =
        std::make_unique<ApplicationState>(*application_state);
  }
  cache_.Insert(server_id, std::move(entry));
}

QuicClientSessionCache::Entry::Entry() = default;
QuicClientSessionCache::Entry::Entry(Entry&&) = default;
QuicClientSessionCache::Entry::~Entry() = default;

void QuicClientSessionCache::Entry::PushSession(
    bssl::UniquePtr<SSL_SESSION> session) {
  if (sessions[0] != nullptr) {
    sessions[1] = std::move(sessions[0]);
  }
  sessions[0] = std::move(session);
}

bssl::UniquePtr<SSL_SESSION> QuicClientSessionCache::Entry::PopSession() {
  if (sessions[0] == nullptr) return nullptr;
  bssl::UniquePtr<SSL_SESSION> session = std::move(sessions[0]);
  sessions[0] = std::move(sessions[1]);
  sessions[1] = nullptr;
  return session;
}

SSL_SESSION* QuicClientSessionCache::Entry::PeekSession() {
  return sessions[0].get();
}

}  // namespace quic
