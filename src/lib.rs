// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate bandersnatch_vrfs;
extern crate core;

use bandersnatch_vrfs::{
    deserialize_publickey, CanonicalSerialize, PublicKey, SecretKey, ThinVrfSignature, Transcript,
};
use std::alloc::{alloc, dealloc, Layout};
use std::mem::size_of;
use std::ptr::null;
use std::{ptr, slice};

/*
#[repr(C)]
pub struct BytesVec {
    data: *mut u8,
    size: c_ulong,
}

#[repr(C)]
pub enum Result {
    Ok(BytesVec),
    Err,
}

impl From <std::result::Result<Vec<u8>, ()>> for Result {
    fn from(value: std::result::Result<Vec<u8>, ()>) -> Self {
        match value {
            Ok(mut vec) => {
                let r = BytesVec{
                    data: vec.as_mut_ptr(),
                    size: vec.len() as _,
                };
                std::mem::forget(vec);
                Result::Ok(r)
            },
            Err(_) => Result::Err
        }
    }
}

impl BytesVec {
    unsafe fn as_slice(&self) -> Vec<u8> {
        std::slice::from_raw_parts_mut(self.data, self.size as usize).to_vec()
    }
}


#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn AWCR_deallocate_bytesvec(data: *mut BytesVec) {
    debug_assert!(!data.is_null());
    debug_assert!(!(*data).data.is_null());
    drop(Box::from_raw((*data).data));
}
*/

pub const SIGNING_CTX: &[u8] = b"BandersnatchSigningContext";

pub const BANDERSNATCH_SEED_SIZE: usize = 32;

pub const BANDERSNATCH_SECRET_KEY_SIZE: usize = 33;
pub const BANDERSNATCH_PUBLIC_KEY_SIZE: usize = 33;

pub const BANDERSNATCH_SIGNATURE_SIZE: usize = 65;

pub const BANDERSNATCH_PREOUT_SIZE: usize = 33;

pub const BANDERSNATCH_MAX_IOS_COUNT: usize = 3;

pub struct Signature([u8; BANDERSNATCH_SIGNATURE_SIZE]);

pub struct Public([u8; BANDERSNATCH_PUBLIC_KEY_SIZE]);

//const PREOUT_SERIALIZED_SIZE: c_ulong = 33;

// #[allow(unused_attributes)]
// #[no_mangle]
// pub unsafe extern "C" fn bandersnatch_keypair_from_seed(keypair_out: *mut u8, seed_ptr: *const u8) {
//     let seed = *(seed_ptr as *const [u8; BANDERSNATCH_SEED_SIZE]);
//
//     let secret = SecretKey::from_seed(&seed);
//     let public = secret.to_public();
//
//     // Fake secret key
//     ptr::copy(
//         [0; BANDERSNATCH_SECRET_KEY_SIZE].as_ptr(),
//         keypair_out,
//         BANDERSNATCH_SECRET_KEY_SIZE as usize,
//     );
//
//     // Fake secret key
//     ptr::copy(seed_ptr, keypair_out, BANDERSNATCH_SECRET_KEY_SIZE as usize);
//
//     let x = slice::from_raw_parts_mut(
//         keypair_out.wrapping_add(BANDERSNATCH_SECRET_KEY_SIZE),
//         BANDERSNATCH_PUBLIC_KEY_SIZE as usize,
//     );
//
//     let _ = public.serialize(x);
// }

// #[allow(unused_attributes)]
// #[no_mangle]
// pub unsafe extern "C" fn bandersnatch_sign(
//     signature_out: *mut u8,
//     keypair_ptr: *const u8,
//     message_ptr: *const u8,
//     message_size: c_ulong
// ) {
//
//     let secret_bytes = slice::from_raw_parts(keypair_ptr, BANDERSNATCH_PRIVATE_KEY_SIZE as usize);
//
//     let secret = SecretKey::from_xof(secret_bytes);
//
//     let data = slice::from_raw_parts(message_ptr, message_size as usize);
//
//     let data = vrf::VrfSignData::new_unchecked(SIGNING_CTX, &[data], None);
// 	let signature = secret.vrf_sign(&data);
//
//
//
//     ptr::copy(
//         secret.to_bytes().as_ptr(),
//         keypair_out,
//         BANDERSNATCH_PRIVATE_KEY_SIZE as usize,
//     );
//
// }

pub type P = bandersnatch_vrfs::VrfInput;

pub type VrfInput = bandersnatch_vrfs::VrfInput;
pub type VrfPreOut = bandersnatch_vrfs::VrfPreOut;
pub type VrfInOut = bandersnatch_vrfs::VrfInOut;

#[allow(non_camel_case_types)]
pub enum bandersnatch_SecretKey {}

#[allow(non_camel_case_types)]
pub enum bandersnatch_PublicKey {}

#[allow(non_camel_case_types)]
pub enum bandersnatch_VrfInput {}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bandersnatch_VrfPreOut {
    pub filler: [u8; size_of::<VrfPreOut>()],
}

pub const X: [u8; size_of::<VrfPreOut>()] = [0; size_of::<VrfPreOut>()];

#[allow(non_camel_case_types)]
pub enum bandersnatch_VrfInOut {}

#[allow(non_camel_case_types)]
pub enum bandersnatch_VrfOutput {}

#[allow(non_camel_case_types)]
pub enum bandersnatch_Transcript {}

#[allow(non_camel_case_types)]
pub enum bandersnatch_ThinVrfSignature {}

#[allow(non_camel_case_types)]
pub enum bandersnatch_Proof {}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_SecretKey_from_seed(
    seed_ptr: *const u8,
) -> *const bandersnatch_SecretKey {
    let seed = &*(seed_ptr as *const [u8; BANDERSNATCH_SEED_SIZE]);
    let secret = SecretKey::from_seed(&seed);

    let ptr = alloc(Layout::new::<SecretKey>());
    if ptr.is_null() {
        return null();
    }
    let ptr = ptr as *mut SecretKey;

    std::ptr::write(ptr, secret);

    let _ = X;

    ptr as *mut bandersnatch_SecretKey
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_SecretKey_destroy(secret_ptr: *const bandersnatch_SecretKey) {
    let secret = secret_ptr as *const SecretKey;
    let _ = *secret;
    dealloc(secret_ptr as *mut u8, Layout::new::<SecretKey>())
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_Transcript_new() -> *const bandersnatch_Transcript {
    let transcript = Transcript::default();

    let ptr = alloc(Layout::new::<Transcript>());
    if ptr.is_null() {
        return null();
    }
    let ptr = ptr as *mut Transcript;

    std::ptr::write(ptr, transcript);

    ptr as *const bandersnatch_Transcript
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_Transcript_destroy(
    transcript_ptr: *const bandersnatch_Transcript,
) {
    let transcript = transcript_ptr as *const Transcript;
    let _ = *transcript;
    dealloc(transcript_ptr as *mut u8, Layout::new::<Transcript>())
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_Transcript_clone(
    transcript_ptr: *const bandersnatch_Transcript,
) -> *const bandersnatch_Transcript {
    let transcript = &*(transcript_ptr as *const Transcript);
    let transcript = transcript.clone();

    let ptr = alloc(Layout::new::<Transcript>());
    if ptr.is_null() {
        return null();
    }
    let ptr = ptr as *mut Transcript;

    std::ptr::write(ptr, transcript);

    ptr as *const bandersnatch_Transcript
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ThinVrfSignature_preout(
    thin_sig_ptr: *const bandersnatch_ThinVrfSignature,
    size: usize,
    index: usize,
) -> *const bandersnatch_VrfPreOut {
    let ptr = match size {
        1 => ptr::addr_of!((&*(thin_sig_ptr as *const ThinVrfSignature<1>)).preouts[index]),
        2 => ptr::addr_of!((&*(thin_sig_ptr as *const ThinVrfSignature<2>)).preouts[index]),
        3 => ptr::addr_of!((&*(thin_sig_ptr as *const ThinVrfSignature<3>)).preouts[index]),
        _ => panic!(),
    };

    ptr as *const bandersnatch_VrfPreOut
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_ThinVrfSignature_proof(
    thin_sig_ptr: *const bandersnatch_ThinVrfSignature,
    size: usize,
    proof_ptr: *mut u8,
    proof_size: usize,
) {
    assert!(size <= BANDERSNATCH_MAX_IOS_COUNT);

    let thin_proof = match size {
        0 => &(&*(thin_sig_ptr as *const ThinVrfSignature<0>)).proof,
        1 => &(&*(thin_sig_ptr as *const ThinVrfSignature<1>)).proof,
        2 => &(&*(thin_sig_ptr as *const ThinVrfSignature<2>)).proof,
        3 => &(&*(thin_sig_ptr as *const ThinVrfSignature<3>)).proof,
        _ => panic!(),
    };

    assert_eq!(proof_size, thin_proof.compressed_size());

    let out = slice::from_raw_parts_mut(proof_ptr, thin_proof.compressed_size());

    thin_proof
        .serialize_compressed(out)
        .expect("Calling code must provide enough space");
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_SecretKey_to_public(
    secret_ptr: *const bandersnatch_SecretKey,
    // public_out: *mut u8,
) -> *const bandersnatch_PublicKey {
    let secret = &*(secret_ptr as *const SecretKey);

    let public = secret.to_public();

    let ptr = alloc(Layout::new::<PublicKey>());
    if ptr.is_null() {
        return null();
    }
    let ptr = ptr as *mut PublicKey;

    std::ptr::write(ptr, public);

    ptr as *mut bandersnatch_PublicKey

    // let out = slice::from_raw_parts_mut(public_out, BANDERSNATCH_PUBLIC_KEY_SIZE as usize);
    //
    // let _ = public.serialize(out);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_SecretKey_vrf_preout(
    secret_ptr: *const bandersnatch_SecretKey,
    input_ptr: *const bandersnatch_VrfInput,
) -> *const bandersnatch_VrfPreOut {
    let secret = &*(secret_ptr as *const SecretKey);

    let vrf_input = &*(input_ptr as *const VrfInput);

    let ptr = alloc(Layout::new::<VrfPreOut>());
    if ptr.is_null() {
        return null();
    }
    let ptr = ptr as *mut VrfPreOut;

    let vrf_preout = secret.vrf_preout(vrf_input);

    std::ptr::write(ptr, vrf_preout);

    ptr as *mut bandersnatch_VrfPreOut
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_SecretKey_vrf_inout(
    secret_ptr: *const bandersnatch_SecretKey,
    input_ptr: *const bandersnatch_VrfInput,
) -> *const bandersnatch_VrfInOut {
    let secret = &*(secret_ptr as *const SecretKey);

    let vrf_input = *(input_ptr as *const VrfInput);

    let ptr = alloc(Layout::new::<VrfInOut>());
    if ptr.is_null() {
        return null();
    }
    let ptr = ptr as *mut VrfInOut;

    let vrf_inout = secret.vrf_inout(vrf_input);

    std::ptr::write(ptr, vrf_inout);

    ptr as *mut bandersnatch_VrfInOut
}

#[allow(non_snake_case)]
unsafe fn bandersnatch_SecretKey_sign_thin_vrf_N<const N: usize>(
    secret: &SecretKey,
    transcript: &mut Transcript,
    inouts_ptr: *const *const bandersnatch_VrfInOut,
) -> *const bandersnatch_ThinVrfSignature {
    let vrf_inouts = *(inouts_ptr as *const [VrfInOut; N]);

    let ptr = alloc(Layout::new::<ThinVrfSignature<N>>());
    if ptr.is_null() {
        return null();
    }
    let ptr = ptr as *mut ThinVrfSignature<N>;

    let thin_sign_vrf = secret.sign_thin_vrf(transcript, &vrf_inouts);

    std::ptr::write(ptr, thin_sign_vrf);

    ptr as *mut bandersnatch_ThinVrfSignature
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_SecretKey_sign_thin_vrf(
    secret_ptr: *const bandersnatch_SecretKey,
    transcript_ptr: *const bandersnatch_Transcript,
    inouts_ptr: *const *const bandersnatch_VrfInOut,
    inouts_size: usize,
) -> *const bandersnatch_ThinVrfSignature {
    let secret = &*(secret_ptr as *const SecretKey);
    let transcript = &mut *(transcript_ptr as *mut Transcript);

    match inouts_size {
        0 => bandersnatch_SecretKey_sign_thin_vrf_N::<0>(secret, transcript, inouts_ptr),
        1 => bandersnatch_SecretKey_sign_thin_vrf_N::<1>(secret, transcript, inouts_ptr),
        2 => bandersnatch_SecretKey_sign_thin_vrf_N::<2>(secret, transcript, inouts_ptr),
        3 => bandersnatch_SecretKey_sign_thin_vrf_N::<3>(secret, transcript, inouts_ptr),
        _ => unreachable!(),
    }
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_PublicKey_serialize(
    public_ptr: *const bandersnatch_PublicKey,
    out_ptr: *mut u8,
) {
    let public = &*(public_ptr as *const PublicKey);

    let out = slice::from_raw_parts_mut(out_ptr, public.size_of_serialized());

    let _ = public.serialize(out);
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_PublicKey_deserialize(
    serialized_ptr: *const u8,
    serialized_size: usize,
) -> *const bandersnatch_PublicKey {
    let serialized = slice::from_raw_parts(serialized_ptr, serialized_size);

    let public_key = match deserialize_publickey(serialized) {
        Ok(public_key) => public_key,
        Err(_) => return null(),
    };

    let ptr = alloc(Layout::new::<PublicKey>());
    if ptr.is_null() {
        return null();
    }
    let ptr = ptr as *mut PublicKey;

    std::ptr::write(ptr, public_key);

    ptr as *const bandersnatch_PublicKey
}

// #[allow(unused_attributes)]
// #[no_mangle]
// pub unsafe extern "C" fn bandersnatch_PublicKey_destroy(public_ptr: *const bandersnatch_PublicKey) {
//     let public = public_ptr as *const PublicKey;
//     let _ = *public;
//     dealloc(public_ptr as *mut u8, Layout::new::<PublicKey>());
// }

#[allow(non_snake_case)]
unsafe fn bandersnatch_PublicKey_verify_thin_vrf_N<const N: usize>(
    public: &PublicKey,
    transcript: &mut Transcript,
    inputs: impl IntoIterator<Item = VrfInput>,
    signature_ptr: *const bandersnatch_ThinVrfSignature,
) -> bool {
    let signature = &*(signature_ptr as *const ThinVrfSignature<N>);

    return public
        .verify_thin_vrf::<N>(transcript, inputs, signature)
        .is_ok();
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_PublicKey_verify_thin_vrf(
    public_ptr: *const bandersnatch_PublicKey,
    transcript_ptr: *const bandersnatch_Transcript,
    inputs_ptr: *const *const bandersnatch_VrfInput,
    inputs_size: usize,
    signature_ptr: *const bandersnatch_ThinVrfSignature,
) -> bool {
    let public = &*(public_ptr as *const PublicKey);
    let transcript = &mut *(transcript_ptr as *mut Transcript);

    return match inputs_size {
        0 => {
            let inputs = [];
            bandersnatch_PublicKey_verify_thin_vrf_N::<0>(public, transcript, inputs, signature_ptr)
        }
        1 => {
            let inputs = [
                *(*inputs_ptr.wrapping_add(0) as *const VrfInput), //
            ];
            bandersnatch_PublicKey_verify_thin_vrf_N::<1>(public, transcript, inputs, signature_ptr)
        }
        2 => {
            let inputs = [
                *(*inputs_ptr.wrapping_add(0) as *const VrfInput),
                *(*inputs_ptr.wrapping_add(1) as *const VrfInput),
            ];
            bandersnatch_PublicKey_verify_thin_vrf_N::<2>(public, transcript, inputs, signature_ptr)
        }
        3 => {
            let inputs = [
                *(*inputs_ptr.wrapping_add(0) as *const VrfInput),
                *(*inputs_ptr.wrapping_add(1) as *const VrfInput),
                *(*inputs_ptr.wrapping_add(2) as *const VrfInput),
            ];
            bandersnatch_PublicKey_verify_thin_vrf_N::<3>(public, transcript, inputs, signature_ptr)
        }
        _ => false,
    };
}

// #[allow(unused_attributes)]
// #[no_mangle]
// pub unsafe extern "C" fn bandersnatch_VrfInput(
//     vrfinput_out: *mut u8,
//     domain_ptr: *const u8,
//     domain_size: c_ulong,
//     data_ptr: *const u8,
//     data_size: c_ulong,
// )  {
//     let domain = slice::from_raw_parts(domain_ptr, domain_size as usize);
//     let data = slice::from_raw_parts(data_ptr, data_size as usize);
//
//     let msg = bandersnatch_vrfs::Message {
//         domain: domain.as_ref(),
//         message: data.as_ref(),
//     };
//
//     let vrf_input = msg.into_vrf_input();
//
//     let out = slice::from_raw_parts_mut(vrfinput_out, vrf_input.0.compressed_size() as usize);
//
//     vrf_input
//         .0
//         .serialize_compressed(out)
//         .expect("Calling code must provide enough space");
// }

pub struct Pair {
    secret: SecretKey,
}

pub type VrfIosVec<T> = Vec<T>;

pub struct VrfOutput(pub bandersnatch_vrfs::VrfPreOut);

pub struct VrfSignData {
    /// Associated protocol transcript.
    pub transcript: Transcript,
    /// VRF inputs to be signed.
    pub inputs: VrfIosVec<VrfInput>,
}

pub struct VrfSignature {
    /// Transcript signature.
    pub signature: Signature,
    /// VRF (pre)outputs.
    pub outputs: VrfIosVec<VrfOutput>,
}

fn vrf_sign_gen<const N: usize>(secret: &SecretKey, data: &VrfSignData) -> VrfSignature {
    let ios = core::array::from_fn(|i| secret.vrf_inout(data.inputs[i].0));

    let thin_signature: ThinVrfSignature<N> =
        secret.sign_thin_vrf(data.transcript.clone(), &ios);

    let outputs: Vec<_> = thin_signature.preouts.into_iter().map(VrfOutput).collect();
    let outputs = VrfIosVec::truncate_from(outputs);

    let mut signature =
        VrfSignature { signature: Signature([0; BANDERSNATCH_SIGNATURE_SIZE]), outputs };

    thin_signature
        .proof
        .serialize_compressed(signature.signature.0.as_mut_slice())
        .expect("serialization length is constant and checked by test; qed");

    signature
}

fn vrf_sign(secret: &SecretKey, data: &VrfSignData) -> VrfSignature {
    const _: () = assert!(BANDERSNATCH_MAX_IOS_COUNT == 3, "`BANDERSNATCH_MAX_IOS_COUNT` expected to be 3");
    // Workaround to overcome backend signature generic over the number of IOs.
    match data.inputs.len() {
        0 => vrf_sign_gen::<0>(&secret, data),
        1 => vrf_sign_gen::<1>(&secret, data),
        2 => vrf_sign_gen::<2>(&secret, data),
        3 => vrf_sign_gen::<3>(&secret, data),
        _ => unreachable!(),
    }
}

fn sign(secret: &SecretKey, data: &[u8]) -> Signature {
    let data = VrfSignData::new_unchecked(SIGNING_CTX, &[data], None);
    vrf_sign(&secret, &data).signature
}

pub unsafe extern "C" fn bandersnatch_sign(
    secret_ptr: *const u8,
    message_ptr: *const u8,
    message_size: usize,
    signature_ptr: *mut u8,
    signature_size: usize,
) {
    let secret = &*(secret_ptr as *const [u8; BANDERSNATCH_SEED_SIZE]);
    let secret = SecretKey::from_seed(secret);

    let message = slice::from_raw_parts(message_ptr, message_size);

    let signature = sign(&secret, message);

    let signature_out = slice::from_raw_parts_mut(signature_ptr, signature_size);

    signature_out.copy_from_slice(&signature.0);
}




fn verify<M: AsRef<[u8]>>(signature: &Signature, data: M, public: &Public) -> bool {
    // let data = vrf::VrfSignData::new_unchecked(SIGNING_CTX, &[data.as_ref()], None);
    // let signature = vrf::VrfSignature {
    //     signature: *signature,
    //     outputs: vrf::VrfIosVec::default(),
    // };
    public.vrf_verify(&data, &signature)
}

pub unsafe extern "C" fn bandersnatch_verify(
    secret_ptr: *const u8,
    message_ptr: *const u8,
    message_size: usize,
    signature_ptr: *mut u8,
    signature_size: usize,
) -> bool {
    let secret = &*(secret_ptr as *const [u8; BANDERSNATCH_SEED_SIZE]);
    let secret = SecretKey::from_seed(secret);

    let message = slice::from_raw_parts(message_ptr, message_size);

    let signature = sign(&secret, message);

    let signature_out = slice::from_raw_parts_mut(signature_ptr, signature_size);

    signature_out.copy_from_slice(&signature.0);
}
