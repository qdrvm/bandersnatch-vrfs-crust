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

  using PublicKey = std::array<uint8_t, 33>;

  class SecretKey {
   public:
    static SecretKey from_seed(std::span<const uint8_t> seed);

    ~SecretKey();

    PublicKey publicKey() const;

   private:
    bandersnatch_SecretKey *secret_;
    std::optional<PublicKey> public_;
  };

}  // namespace bandersnatch_vrfs
