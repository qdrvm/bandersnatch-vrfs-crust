/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bandersnatch_vrfs/bandersnatch_vrfs.hpp"

#include "bandersnatch_vrfs_crust.h"

#include <cassert>
#include <span>

//namespace bandersnatch_vrfs {
//
//  Transcript::Transcript() : ptr_(bandersnatch_Transcript_new()) {}
//
//  Transcript::~Transcript() {
//    if (ptr_) {
//      bandersnatch_Transcript_destroy(ptr_);
//    }
//  }
//
//  Transcript::Transcript(Transcript &&other) noexcept : ptr_(other.ptr_) {
//    other.ptr_ = nullptr;
//  }
//
//  Transcript::Transcript(const Transcript &other)
//      : ptr_(bandersnatch_Transcript_clone(other.ptr_)) {}
//
//  Transcript &Transcript::operator=(Transcript &&other) noexcept {
//    ptr_ = other.ptr_;
//    other.ptr_ = nullptr;
//    return *this;
//  }
//
//  Transcript &Transcript::operator=(const Transcript &other) {
//    ptr_ = bandersnatch_Transcript_clone(other.ptr_);
//    return *this;
//  }
//
//  // ===
//
//  ThinVrfSignature::ThinVrfSignature(const bandersnatch_ThinVrfSignature *ptr,
//                                     size_t size)
//      : ptr_(ptr), size_(size) {}
//
//  std::vector<const bandersnatch_VrfPreOut *> ThinVrfSignature::preouts()
//      const {
//    std::vector<const bandersnatch_VrfPreOut *> res;
//    for (auto index = 0; index < size_; ++index) {
//      res.push_back(bandersnatch_ThinVrfSignature_preout(ptr_, size_, index));
//    }
//    return res;
//  }
//
//  void ThinVrfSignature::proof(BytesOut out) const {
//    std::vector<uint8_t> d;
//    return bandersnatch_ThinVrfSignature_proof(
//        ptr_, size_, out.data(), out.size());
//  }
//
//  // ===
//
//  SecretKey::SecretKey(const Seed &seed)
//      : secret_(bandersnatch_SecretKey_from_seed(seed.data())) {}
//
//  SecretKey::~SecretKey() {
//    bandersnatch_SecretKey_destroy(secret_);
//  }
//
//  PublicKey SecretKey::publicKey() const {
//    if (not public_.has_value()) {
//      auto ptr = bandersnatch_SecretKey_to_public(secret_);
//      auto &pk = const_cast<std::optional<PublicKey> &>(public_).emplace(ptr);
//    }
//    return public_.value();
//  }
//
//  VrfPreOut SecretKey::vrfPreOut(VrfInput vrf_input) const {
//    return bandersnatch_SecretKey_vrf_preout(secret_, vrf_input);
//  }
//
//  VrfInOut SecretKey::vrfInOut(VrfInput vrf_input) const {
//    return bandersnatch_SecretKey_vrf_inout(secret_, vrf_input);
//  }
//
//  ThinVrfSignature SecretKey::signThinVrf(Transcript &transcript,
//                                          VrfInOut *vrf_inouts,
//                                          size_t size) const {
//    auto ptr = bandersnatch_SecretKey_sign_thin_vrf(
//        secret_, transcript.ptr(), vrf_inouts, size);
//    return ThinVrfSignature{ptr, size};
//  }
//
//  std::optional<PublicKey> PublicKey::fromSpan(BytesIn in) {
//    if (in.size() == BANDERSNATCH_PUBLIC_KEY_SIZE) {
//      if (auto ptr = bandersnatch_PublicKey_deserialize(in.data(), in.size())) {
//        return std::make_optional<PublicKey>(ptr);
//      }
//    }
//    return std::nullopt;
//  }
//
//  PublicKey::~PublicKey() {
////    bandersnatch_PublicKey_destroy(ptr_);
//  }
//
//  PublicKey::PublicKey(const bandersnatch_PublicKey *ptr)
////  : ptr_(ptr)
//  {}
//
////  void PublicKey::serialize(BytesOut out) const {
////    assert(out.size() == BANDERSNATCH_PUBLIC_KEY_SIZE);
////    bandersnatch_PublicKey_serialize(ptr_, out.data());
////  }
//
//  bool PublicKey::verifyThinVrf(Transcript &transcript,
//                                VrfInput *inputs,
//                                size_t size,
//                                ThinVrfSignature *signature) const {
////    return bandersnatch_PublicKey_verify_thin_vrf(
////        ptr_, transcript.ptr(), inputs, size, signature->ptr());
//  }
//
//}  // namespace bandersnatch_vrfs
