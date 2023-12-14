/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>

struct bandersnatch_SecretKey;
struct bandersnatch_VrfInput;
struct bandersnatch_VrfPreOut;
struct bandersnatch_VrfInOut;

namespace bandersnatch_vrfs {

  using Seed = std::array<uint8_t, 32>;
  using Affine = std::array<uint8_t, 33>;
  using PublicKey = Affine;
  using VrfInput = const bandersnatch_VrfInput *;
  using VrfPreOut = const bandersnatch_VrfPreOut *;
  using VrfInOut = const bandersnatch_VrfInOut *;

  class SecretKey {
   public:
    explicit SecretKey(const Seed &seed);

    ~SecretKey();

    PublicKey publicKey() const;
    VrfPreOut vrfPreOut(VrfInput vrf_input) const;
    VrfInOut vrfInOut(VrfInput vrf_input) const;

   private:
    const bandersnatch_SecretKey *secret_;
    std::optional<PublicKey> public_;
  };

}  // namespace bandersnatch_vrfs
