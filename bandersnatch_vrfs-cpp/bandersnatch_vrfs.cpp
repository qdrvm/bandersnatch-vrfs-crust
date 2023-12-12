/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bandersnatch_vrfs/bandersnatch_vrfs.hpp"

#include "bandersnatch_vrfs_crust.h"

#include <span>

namespace bandersnatch_vrfs {

  SecretKey SecretKey::from_seed(std::span<const uint8_t> seed) {
    SecretKey res;
    res.secret_ = bandersnatch_SecretKey_from_seed(seed.data());
    return res;
  }

  SecretKey::~SecretKey() {
    bandersnatch_SecretKey_destroy(secret_);
  }

  PublicKey SecretKey::publicKey() const {
    PublicKey res;
    bandersnatch_SecretKey_to_public(secret_, res.data());
    return res;
  }

}  // namespace bandersnatch_vrfs
