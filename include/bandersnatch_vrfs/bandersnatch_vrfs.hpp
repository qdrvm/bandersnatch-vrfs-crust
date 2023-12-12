/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <span>
#include <cstdint>
#include <optional>

struct bandersnatch_SecretKey;

namespace bandersnatch_vrfs {

  using Seed = std::array<uint8_t, 32>;
  using Affine = std::array<uint8_t, 33>;
  using PublicKey = Affine;
  using VrfInput = Affine;
  using VrfOutput = Affine;
  using VrfPreOut = Affine;
  struct VrfInOut {
    VrfInput input;
    VrfPreOut preout;
  };

  class SecretKey {
   public:
    explicit SecretKey(const Seed& seed);

    ~SecretKey();

    PublicKey publicKey() const;
    VrfPreOut vrfPreOut(const VrfInput& vrf_input) const;
    VrfInOut vrfInOut(const VrfInput& vrf_input) const;

   private:
    bandersnatch_SecretKey *secret_;
    std::optional<PublicKey> public_;
  };

}  // namespace bandersnatch_vrfs
