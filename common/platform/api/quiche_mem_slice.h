// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_PLATFORM_API_QUICHE_MEM_SLICE_H_
#define QUICHE_COMMON_PLATFORM_API_QUICHE_MEM_SLICE_H_

#include <memory>

#include "quiche_platform_impl/quiche_mem_slice_impl.h"
#include "absl/strings/string_view.h"
#include "common/platform/api/quiche_export.h"
#include "common/quiche_buffer_allocator.h"

namespace quiche {

// QuicheMemSlice is a wrapper around a platform-specific I/O buffer type. It
// may be reference counted, though QUICHE itself does not rely on that.
class QUICHE_EXPORT_PRIVATE QuicheMemSlice {
 public:
  // Constructs a empty QuicheMemSlice with no underlying data.
  QuicheMemSlice() = default;

  // Constructs a QuicheMemSlice that takes ownership of |buffer|.  The length
  // of the |buffer| must not be zero.  To construct an empty QuicheMemSlice,
  // use the zero-argument constructor instead.
  explicit QuicheMemSlice(QuicheBuffer buffer) : impl_(std::move(buffer)) {}

  // Constructs a QuicheMemSlice that takes ownership of |buffer| allocated on
  // heap.  |length| must not be zero.
  QuicheMemSlice(std::unique_ptr<char[]> buffer, size_t length)
      : impl_(std::move(buffer), length) {}

  // Constructs QuicheMemSlice from |impl|. It takes the reference away from
  // |impl|.
  explicit QuicheMemSlice(QuicheMemSliceImpl impl) : impl_(std::move(impl)) {}

  QuicheMemSlice(const QuicheMemSlice& other) = delete;
  QuicheMemSlice& operator=(const QuicheMemSlice& other) = delete;

  // Move constructors. |other| will not hold a reference to the data buffer
  // after this call completes.
  QuicheMemSlice(QuicheMemSlice&& other) = default;
  QuicheMemSlice& operator=(QuicheMemSlice&& other) = default;

  ~QuicheMemSlice() = default;

  // Release the underlying reference. Further access the memory will result in
  // undefined behavior.
  void Reset() { impl_.Reset(); }

  // Returns a const char pointer to underlying data buffer.
  const char* data() const { return impl_.data(); }
  // Returns the length of underlying data buffer.
  size_t length() const { return impl_.length(); }
  // Returns the representation of the underlying data as a string view.
  absl::string_view AsStringView() const {
    return absl::string_view(data(), length());
  }

  bool empty() const { return impl_.empty(); }

  QuicheMemSliceImpl* impl() { return &impl_; }

 private:
  QuicheMemSliceImpl impl_;
};

}  // namespace quiche

#endif  // QUICHE_COMMON_PLATFORM_API_QUICHE_MEM_SLICE_H_
