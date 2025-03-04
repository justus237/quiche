// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_PLATFORM_API_QUIC_ERROR_CODE_WRAPPERS_H_
#define QUICHE_QUIC_PLATFORM_API_QUIC_ERROR_CODE_WRAPPERS_H_

#include "common/platform/api/quiche_error_code_wrappers.h"

// TODO(vasilvv): ensure WRITE_STATUS_MSG_TOO_BIG works everywhere and remove
// this.
#define QUIC_EMSGSIZE QUICHE_EMSGSIZE

#endif  // QUICHE_QUIC_PLATFORM_API_QUIC_ERROR_CODE_WRAPPERS_H_
