/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <span>
#include <cstdint>

struct bandersnatch_SecretKey;

namespace bandersnatch_vrfs {

  class SecretKey {
   public:
    static SecretKey from_seed(std::span<const uint8_t> seed);

    ~SecretKey();

   private:
    bandersnatch_SecretKey *secret_;
  };

}  // namespace bandersnatch_vrfs
