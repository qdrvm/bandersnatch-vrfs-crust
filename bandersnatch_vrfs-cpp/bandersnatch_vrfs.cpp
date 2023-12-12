/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bandersnatch_vrfs/bandersnatch_vrfs.hpp"

#include "bandersnatch_vrfs_crust.h"

#include <span>

namespace bandersnatch_vrfs {

  SecretKey::SecretKey(const Seed &seed)
      : secret_(bandersnatch_SecretKey_from_seed(seed.data())) {}

  SecretKey::~SecretKey() {
    bandersnatch_SecretKey_destroy(secret_);
  }

  PublicKey SecretKey::publicKey() const {
    if (not public_.has_value()) {
      auto &pk = const_cast<std::optional<PublicKey> &>(public_).emplace();
      bandersnatch_SecretKey_to_public(secret_, pk.data());
    }
    return public_.value();
  }

  VrfPreOut SecretKey::vrfPreOut(const VrfInput &vrf_input) const {
    VrfPreOut vrf_preout;
    bandersnatch_SecretKey_vrf_preout(secret_,
                                      vrf_input.data(),
                                      vrf_input.size(),
                                      vrf_preout.data(),
                                      vrf_preout.size());
    return vrf_preout;
  }

  VrfInOut SecretKey::vrfInOut(const VrfInput &vrf_input) const {
    VrfInOut vrf_inout{};
    bandersnatch_SecretKey_vrf_inout(secret_,
                                     vrf_input.data(),
                                     vrf_input.size(),
                                     reinterpret_cast<uint8_t *>(&vrf_inout),
                                     sizeof(vrf_inout));
    return vrf_inout;
  }

}  // namespace bandersnatch_vrfs
