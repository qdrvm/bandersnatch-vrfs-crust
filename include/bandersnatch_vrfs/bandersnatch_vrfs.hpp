/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>
#include "../../bandersnatch_vrfs-cpp/bandersnatch_vrfs_crust.h"

struct bandersnatch_SecretKey;
struct bandersnatch_PublicKey;
struct bandersnatch_VrfInput;
struct bandersnatch_VrfPreOut;
struct bandersnatch_VrfInOut;
struct bandersnatch_VrfOutput;
struct bandersnatch_Transcript;
struct bandersnatch_ThinVrfSignature;
struct bandersnatch_Proof;

namespace bandersnatch_vrfs {

  using BytesIn = std::span<const uint8_t>;
  using BytesOut = std::span<uint8_t>;

  using Seed = std::array<uint8_t, 32>;
  using Affine = std::array<uint8_t, 33>;
  using VrfInput = const bandersnatch_VrfInput *;
  using VrfPreOut = const bandersnatch_VrfPreOut *;
  using VrfInOut = const bandersnatch_VrfInOut *;
  using VrfOutput = const bandersnatch_VrfOutput *;
  // using ThinVrfSignature = const bandersnatch_ThinVrfSignature *;
  using Proof = const bandersnatch_Proof *;
  // using Transcript = const bandersnatch_Transcript *;

  class Transcript {
   public:
    explicit Transcript();
    Transcript(Transcript &&) noexcept;
    Transcript(const Transcript &);
    Transcript &operator=(Transcript &&) noexcept;
    Transcript &operator=(const Transcript &);

    ~Transcript();

    const bandersnatch_Transcript *ptr() const {
      return ptr_;
    }

   private:
    const bandersnatch_Transcript *ptr_;
  };

  // ===

  class ThinVrfSignature {
   public:
    explicit ThinVrfSignature(const bandersnatch_ThinVrfSignature *ptr,
                              size_t size);

    std::vector<const bandersnatch_VrfPreOut *> preouts() const;
    void proof(BytesOut out) const;

    ~ThinVrfSignature() = default;

    const bandersnatch_ThinVrfSignature *ptr() const {
      return ptr_;
    }

   private:
    const bandersnatch_ThinVrfSignature *ptr_;
    const size_t size_;
  };

  // ===

  class PublicKey : std::array<uint8_t, BANDERSNATCH_PUBLIC_KEY_SIZE>{
   public:
    static std::optional<PublicKey> fromSpan(BytesIn span);

    PublicKey(const bandersnatch_PublicKey *ptr);

    ~PublicKey();

    bool verifyThinVrf(Transcript &transcript,
                       VrfInput *inputs,
                       size_t size,
                       ThinVrfSignature *signature) const;
  };

  // ===

  class SecretKey {
   public:
    explicit SecretKey(const Seed &seed);

    ~SecretKey();

    PublicKey publicKey() const;
    VrfPreOut vrfPreOut(VrfInput vrf_input) const;
    VrfInOut vrfInOut(VrfInput vrf_input) const;

    ThinVrfSignature signThinVrf(Transcript &transcript,
                                 VrfInOut *vrf_inouts,
                                 size_t size) const;

   private:
    const bandersnatch_SecretKey *secret_;
    std::optional<PublicKey> public_;
  };

}  // namespace bandersnatch_vrfs
