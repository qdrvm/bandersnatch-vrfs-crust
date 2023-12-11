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

// mod utils;

use core::ffi::c_ulong;
use core::ffi::c_void;
use std::ops::Deref;
use std::{ptr, slice};
// use std::vec::Vec;
use bandersnatch_vrfs::{
    CanonicalSerialize,
    IntoVrfInput,
    //Message,
    SecretKey,
};
// use utils::*;

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

/// Size of input SEED for derivation, bytes
pub const BANDERSNATCH_SEED_SIZE: usize = 32;

pub const BANDERSNATCH_SECRET_KEY_SIZE: usize = 33;
pub const BANDERSNATCH_PUBLIC_KEY_SIZE: usize = 33;

pub const BANDERSNATCH_SIGNATURE_SIZE: usize = 65;

pub struct Signature([u8; BANDERSNATCH_SIGNATURE_SIZE]);

//const PREOUT_SERIALIZED_SIZE: c_ulong = 33;

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_keypair_from_seed(keypair_out: *mut u8, seed_ptr: *const u8) {
    let seed = *(seed_ptr as *const [u8; BANDERSNATCH_SEED_SIZE]);

    let secret = SecretKey::from_seed(&seed);
    let public = secret.to_public();

    // Fake secret key
    ptr::copy(
        [0; BANDERSNATCH_SECRET_KEY_SIZE].as_ptr(),
        keypair_out,
        BANDERSNATCH_SECRET_KEY_SIZE as usize,
    );

    // Fake secret key
    ptr::copy(seed_ptr, keypair_out, BANDERSNATCH_SECRET_KEY_SIZE as usize);

    let x = slice::from_raw_parts_mut(
        keypair_out.wrapping_add(BANDERSNATCH_SECRET_KEY_SIZE),
        BANDERSNATCH_PUBLIC_KEY_SIZE as usize,
    );

    let _ = public.serialize(x);
}

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

pub type VrfInput = bandersnatch_vrfs::VrfInput;
pub type VrfPreOut = bandersnatch_vrfs::VrfPreOut;
pub type VrfInOut = bandersnatch_vrfs::VrfInOut;

#[allow(non_camel_case_types)]
pub enum bandersnatch_SecretKey {}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_SecretKey_destroy(secret_ptr: *mut bandersnatch_SecretKey) {
    unsafe {
        let secret = secret_ptr as *mut c_void as *mut Box<SecretKey>;
        let _ = (*secret).deref();
    }
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_SecretKey_from_seed(
    seed_ptr: *const u8,
) -> *mut bandersnatch_SecretKey {
    let seed = &*(seed_ptr as *const [u8; BANDERSNATCH_SEED_SIZE]);
    let secret = SecretKey::from_seed(&seed);
    let mut secret = Box::new(secret);
    let ptr = &mut secret as *mut _ as *const c_void;
    ptr as *mut bandersnatch_SecretKey
}

#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn bandersnatch_VrfInput(
    vrfinput_out: *mut u8,
    domain_ptr: *const u8,
    domain_size: c_ulong,
    data_ptr: *const u8,
    data_size: c_ulong,
) {
    let domain = slice::from_raw_parts(domain_ptr, domain_size as usize);
    let data = slice::from_raw_parts(data_ptr, data_size as usize);

    let msg = bandersnatch_vrfs::Message {
        domain: domain.as_ref(),
        message: data.as_ref(),
    };

    let vrf_input = msg.into_vrf_input();

    let out = slice::from_raw_parts_mut(vrfinput_out, vrf_input.0.compressed_size() as usize);

    vrf_input
        .0
        .serialize_compressed(out)
        .expect("Calling code must provide enough space");
}
