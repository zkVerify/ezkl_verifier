// Copyright 2025 zkonduit
// Copyright 2025 Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT

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

use crate::constants::MAX_U32;
use crate::errors::{GroupError, UtilityError};
use crate::{BYTE_FLAG_BITMASK, G2, PROOF_OFFSET, PTR_BITMASK};
use crate::{EVMWord, Fq, Fr, U256, errors::FieldError, types::G1};
use alloc::{format, string::String};
use ark_bn254::Fq2;
use ark_bn254_ext::CurveHooks;
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, PrimeField};

pub(crate) trait IntoFq {
    fn into_fq(self) -> Fq;
}

// impl Sized for U256 {}

impl IntoFq for U256 {
    fn into_fq(self) -> Fq {
        Fq::from(self)
    }
}

impl IntoFq for u64 {
    fn into_fq(self) -> Fq {
        Fq::new(U256::from(self))
    }
}

impl IntoFq for Fr {
    fn into_fq(self) -> Fq {
        let big_int = self.into_bigint();
        Fq::from_bigint(big_int).expect("Fr value is always a valid Fq element")
    }
}

pub(crate) trait IntoFr {
    fn into_fr(self) -> Fr;
}

impl IntoFr for &EVMWord {
    fn into_fr(self) -> Fr {
        self.into_u256().into_fr()
    }
}

impl IntoFr for EVMWord {
    fn into_fr(self) -> Fr {
        (&self).into_fr()
    }
}

impl IntoFr for U256 {
    fn into_fr(self) -> Fr {
        Fr::new(self)
    }
}

impl IntoFr for u64 {
    fn into_fr(self) -> Fr {
        Fr::new(U256::from(self))
    }
}

impl IntoFr for Fq {
    fn into_fr(self) -> Fr {
        Fr::from(self.into_bigint())
    }
}

pub(crate) trait IntoU256 {
    fn into_u256(self) -> U256;
}

impl IntoU256 for u32 {
    fn into_u256(self) -> U256 {
        U256::from(self)
    }
}

impl IntoU256 for usize {
    fn into_u256(self) -> U256 {
        U256::from(self as u64)
    }
}

impl IntoU256 for &EVMWord {
    fn into_u256(self) -> U256 {
        // Convert the byte array to a little-endian byte vector
        let mut bytes = self.to_vec(); // Convert the &[u8; 32] slice to a Vec<u8>
        bytes.reverse(); // Reverse the bytes to ensure little-endian order

        // Create a BigInteger256 from the little-endian byte array
        let mut limbs = [0u64; 4];

        // Populate the limbs from the byte vector (which is little-endian)
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(
                bytes[(i << 3)..((i + 1) << 3)]
                    .try_into()
                    .expect("Invalid byte slice"),
            );
        }

        U256::new(limbs)
    }
}

impl IntoU256 for EVMWord {
    fn into_u256(self) -> U256 {
        (&self).into_u256()
    }
}

/// Trait for returning a big-endian representation of some object as an `EVMWord`.
pub(crate) trait IntoBEBytes32 {
    fn into_be_bytes32(self) -> EVMWord;
}

impl IntoBEBytes32 for U256 {
    fn into_be_bytes32(self) -> EVMWord {
        let mut rev_iter_be = self.0.iter().rev().flat_map(|limb| limb.to_be_bytes());
        core::array::from_fn(|_| rev_iter_be.next().unwrap())
    }
}

impl IntoBEBytes32 for Fr {
    fn into_be_bytes32(self) -> EVMWord {
        self.into_bigint().into_be_bytes32()
    }
}

impl IntoBEBytes32 for Fq {
    fn into_be_bytes32(self) -> EVMWord {
        self.into_bigint().into_be_bytes32()
    }
}

impl IntoBEBytes32 for u64 {
    fn into_be_bytes32(self) -> EVMWord {
        let be = self.to_be_bytes();
        let mut arr = [0u8; 32];
        arr[24..].copy_from_slice(&be);
        arr
    }
}

// Parse point in G1.
pub(crate) fn read_g1<H: CurveHooks>(data: &[u8], start: usize) -> Result<G1<H>, GroupError> {
    if start >= data.len() {
        return Err(GroupError::IndexOutOfBounds {
            index: start,
            source_length: data.len(),
        });
    }
    if data.len() < 64 {
        return Err(GroupError::InvalidSliceLength {
            actual_length: data.len(),
            expected_length: 64,
        });
    }

    let x = read_fq_util(&data[start..(start + 32)])?;
    let y = read_fq_util(&data[(start + 32)..(start + 64)])?;

    // If (0, 0) is given, we interpret this as the point at infinity:
    // https://docs.rs/ark-ec/0.5.0/src/ark_ec/models/short_weierstrass/affine.rs.html#212-218
    if x == Fq::ZERO && y == Fq::ZERO {
        return Ok(G1::zero());
    }

    let point = G1::new_unchecked(x, y);

    // Validate point
    if !point.is_on_curve() {
        return Err(GroupError::NotOnCurve);
    }
    // This is always true for G1 with the BN254 curve.
    debug_assert!(point.is_in_correct_subgroup_assuming_on_curve());

    Ok(point)
}

// Parse point in G2.
pub(crate) fn read_g2<H: CurveHooks>(data: &[u8]) -> Result<G2<H>, GroupError> {
    if data.len() != 128 {
        return Err(GroupError::InvalidSliceLength {
            actual_length: data.len(),
            expected_length: 128,
        });
    }

    // Read in reverse order (i.e., imaginary part before real part) to match
    // Solidity's encoding:
    // https://eips.ethereum.org/EIPS/eip-197#encoding
    let x_c1 = read_fq_util(&data[0..32])?;
    let x_c0 = read_fq_util(&data[32..64])?;
    let y_c1 = read_fq_util(&data[64..96])?;
    let y_c0 = read_fq_util(&data[96..128])?;

    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);

    let point = G2::<H>::new_unchecked(x, y);

    // Unlike G1, BN254's G2 has a non-trivial cofactor, so the subgroup check is required.
    if !point.is_on_curve() {
        return Err(GroupError::NotOnCurve);
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(GroupError::NotInSubgroup);
    }

    Ok(point)
}

// Utility function for parsing points in G2
pub(crate) fn read_fq_util(data: &[u8]) -> Result<Fq, FieldError> {
    if data.len() != 32 {
        return Err(FieldError::InvalidSliceLength {
            expected_length: 32,
            actual_length: data.len(),
        });
    }

    // Convert bytes to limbs manually
    let mut limbs = [0u64; 4];
    for (i, chunk) in data.chunks(8).enumerate() {
        limbs[3 - i] = u64::from_be_bytes(chunk.try_into().unwrap());
    }

    let bigint = U256::new(limbs);

    // Mirrors `lt(x, Q)` in read_ec_point; also required because `into_fq()` panics for >= q.
    if bigint >= Fq::MODULUS {
        return Err(FieldError::NotMember);
    }

    Ok(bigint.into_fq())
}

// Return a `U256`'s the least significant byte.
pub(crate) fn lsb8(num: &U256) -> usize {
    (num.0[0] & BYTE_FLAG_BITMASK) as usize
}

// Return a `U256`'s two least significant bytes.
pub(crate) fn lsb16(num: &U256) -> usize {
    (num.0[0] & PTR_BITMASK) as usize
}

// Return a `U256`'s four least significant bytes.
pub(crate) fn lsb32(num: &U256) -> usize {
    (num.0[0] & 0xffffffff) as usize
}

// TODO: Address edge cases.
pub(crate) fn mload(memory: &[u8], addr: u32) -> Result<EVMWord, UtilityError> {
    memory
        .get(addr as usize..addr as usize + 32)
        .and_then(|s| s.try_into().ok())
        .ok_or(UtilityError::MloadError {
            index: addr as usize,
            memory_length: memory.len(),
        })
}

// Utility function for parsing a u32 from an EVMWord, while also
// checking that it does not exceed u32::MAX.
pub(crate) fn mload_u32(memory: &[u8], addr: u32) -> Result<u32, UtilityError> {
    let bytes = &mload(memory, addr)?;
    // perform validation
    if bytes.into_u256() > MAX_U32 {
        return Err(UtilityError::MloadU32Error {
            value: bytes.into_u256(),
            index: addr as usize,
        });
    }
    Ok(u32_from_be_tail(bytes))
}

pub(crate) fn load_from_proof(raw_proof: &[u8], addr: u32) -> Result<EVMWord, UtilityError> {
    let idx = addr as usize - PROOF_OFFSET;
    let slice = raw_proof
        .get(idx..idx + 0x20)
        .ok_or(UtilityError::CallDataLoadError {
            index: idx,
            raw_proof_length: raw_proof.len(),
        })?;
    let evm_word: EVMWord = slice
        .try_into()
        .expect("Should be able to convert slice into an EVMWord.");
    Ok(evm_word)
}

pub(crate) fn u32_from_be_tail(bytes: &EVMWord) -> u32 {
    u32::from_be_bytes(
        bytes[28..32]
            .try_into()
            .expect("Should be able to parse the 4 LSBs of an EVMWord as an u32."),
    )
}

// Utility for debugging.
pub(crate) fn to_hex_string(data: &[u8]) -> String {
    let hex_string: String = data.iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{hex_string}")
}
