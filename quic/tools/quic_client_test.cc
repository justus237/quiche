// Copyright (c) 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/tools/quic_client.h"

#include <dirent.h>
#include <sys/types.h>

#include <memory>
#include <utility>

#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "quic/platform/api/quic_epoll.h"
#include "quic/platform/api/quic_test.h"
#include "quic/platform/api/quic_test_loopback.h"
#include "quic/test_tools/crypto_test_utils.h"
#include "quic/test_tools/quic_client_peer.h"
#include "common/quiche_text_utils.h"

namespace quic {
namespace test {
namespace {

const char* kPathToFds = "/proc/self/fd";

// Return the value of a symbolic link in |path|, if |path| is not found, return
// an empty string.
std::string ReadLink(const std::string& path) {
  std::string result(PATH_MAX, '\0');
  ssize_t result_size = readlink(path.c_str(), &result[0], result.size());
  if (result_size < 0 && errno == ENOENT) {
    return "";
  }
  QUICHE_CHECK(result_size > 0 &&
               static_cast<size_t>(result_size) < result.size())
      << "result_size:" << result_size << ", errno:" << errno
      << ", path:" << path;
  result.resize(result_size);
  return result;
}

// Counts the number of open sockets for the current process.
size_t NumOpenSocketFDs() {
  size_t socket_count = 0;
  dirent* file;
  std::unique_ptr<DIR, int (*)(DIR*)> fd_directory(opendir(kPathToFds),
                                                   closedir);
  while ((file = readdir(fd_directory.get())) != nullptr) {
    absl::string_view name(file->d_name);
    if (name == "." || name == "..") {
      continue;
    }

    std::string fd_path = ReadLink(absl::StrCat(kPathToFds, "/", name));
    if (absl::StartsWith(fd_path, "socket:")) {
      socket_count++;
    }
  }
  return socket_count;
}

class QuicClientTest : public QuicTest {
 public:
  QuicClientTest() {
    // Creates and destroys a single client first which may open persistent
    // sockets when initializing platform dependencies like certificate
    // verifier. Future creation of addtional clients will deterministically
    // open one socket per client.
    CreateAndInitializeQuicClient();
  }

  // Creates a new QuicClient and Initializes it on an unused port.
  // Caller is responsible for deletion.
  std::unique_ptr<QuicClient> CreateAndInitializeQuicClient() {
    QuicSocketAddress server_address(QuicSocketAddress(TestLoopback(), 0));
    QuicServerId server_id("hostname", server_address.port(), false);
    ParsedQuicVersionVector versions = AllSupportedVersions();
    auto client = std::make_unique<QuicClient>(
        server_address, server_id, versions, &epoll_server_,
        crypto_test_utils::ProofVerifierForTesting());
    EXPECT_TRUE(client->Initialize());
    return client;
  }

 private:
  QuicEpollServer epoll_server_;
};

TEST_F(QuicClientTest, DoNotLeakSocketFDs) {
  // Make sure that the QuicClient doesn't leak socket FDs. Doing so could cause
  // port exhaustion in long running processes which repeatedly create clients.

  // Record the initial number of FDs.
  size_t number_of_open_fds = NumOpenSocketFDs();

  // Create a number of clients, initialize them, and verify this has resulted
  // in additional FDs being opened.
  const int kNumClients = 50;
  for (int i = 0; i < kNumClients; ++i) {
    EXPECT_EQ(number_of_open_fds, NumOpenSocketFDs());
    std::unique_ptr<QuicClient> client(CreateAndInitializeQuicClient());
    // Initializing the client will create a new FD.
    EXPECT_EQ(number_of_open_fds + 1, NumOpenSocketFDs());
  }

  // The FDs created by the QuicClients should now be closed.
  EXPECT_EQ(number_of_open_fds, NumOpenSocketFDs());
}

TEST_F(QuicClientTest, CreateAndCleanUpUDPSockets) {
  size_t number_of_open_fds = NumOpenSocketFDs();

  std::unique_ptr<QuicClient> client(CreateAndInitializeQuicClient());
  // Creating and initializing a client will result in one socket being opened.
  EXPECT_EQ(number_of_open_fds + 1, NumOpenSocketFDs());

  // Create more UDP sockets.
  EXPECT_TRUE(QuicClientPeer::CreateUDPSocketAndBind(client.get()));
  EXPECT_EQ(number_of_open_fds + 2, NumOpenSocketFDs());
  EXPECT_TRUE(QuicClientPeer::CreateUDPSocketAndBind(client.get()));
  EXPECT_EQ(number_of_open_fds + 3, NumOpenSocketFDs());

  // Clean up UDP sockets.
  QuicClientPeer::CleanUpUDPSocket(client.get(), client->GetLatestFD());
  EXPECT_EQ(number_of_open_fds + 2, NumOpenSocketFDs());
  QuicClientPeer::CleanUpUDPSocket(client.get(), client->GetLatestFD());
  EXPECT_EQ(number_of_open_fds + 1, NumOpenSocketFDs());
}

}  // namespace
}  // namespace test
}  // namespace quic
