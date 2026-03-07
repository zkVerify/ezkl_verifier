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

#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

mod constants;
pub mod errors;
mod types;
mod utils;

extern crate alloc;
extern crate core;

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use ark_bn254_ext::CurveHooks;
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{AdditiveGroup, BigInteger, Field, One, PrimeField, fields::batch_inversion};
use ark_models_ext::bn::{G1Prepared, G2Prepared};
use core::{iter, ops::BitAnd};
use sha3::{Digest, Keccak256};

use crate::{
    constants::{BYTE_FLAG_BITMASK, DELTA, PTR_BITMASK},
    utils::{
        IntoBEBytes32, IntoFr, IntoU256, load_from_proof, load_proof_key, lsb8, lsb16, lsb32,
        mload, mload_fq, mload_fr, mload_key, mload_u32, read_g1, read_g2, to_hex_string,
        u32_from_be_tail,
    },
};

pub use errors::*;
pub use types::*;

pub const PUBS_SIZE: usize = 32;

// Useful offsets during verification.
const PROOF_OFFSET: usize = 0x84; // Offset of proof inside the calldata
const VKA_OFFSET: usize = 0x0; // Offset inside the VKA file itself
const MEMORY_OFFSET: usize = 5 * 0x20; // Where the VKA starts inside the memory vector

/// A single public input.
pub type PublicInput = [u8; PUBS_SIZE];
pub type Public = [PublicInput];

enum ProcessOutput {
    Index(usize),
    Scalar(Fr),
}

/// Verifies the given `raw_proof` and public inputs `pubs` using the verification key `raw_vka`.
pub fn verify<H: CurveHooks>(
    raw_vka: &[u8],
    raw_proof: &[u8],
    pubs: &Public,
) -> Result<(), VerifyError> {
    let mut memory = vec![0u8; 64];

    if raw_vka.is_empty() || raw_vka.len() & 0x1f != 0 {
        return Err(VerifyError::KeyError {
            message: "vk length must be a positive multiple of 32".to_string(),
        });
    }

    if raw_proof.is_empty() || raw_proof.len() & 0x1f != 0 {
        return Err(VerifyError::InvalidProofError {
            message: "proof length must be a positive multiple of 32".to_string(),
        });
    }

    // Compute and store the vka_end into memory
    memory.extend_from_slice(
        &(raw_vka.len() + MEMORY_OFFSET)
            .into_u256()
            .into_be_bytes32(),
    );

    memory.extend_from_slice(&[0u8; 32]);
    memory.extend_from_slice(&raw_vka.len().into_u256().into_be_bytes32());
    memory.extend_from_slice(raw_vka);

    // Check valid length of instances
    check_public_input_number(&memory, pubs)?;

    verify_proof_inner::<H>(raw_proof, pubs, &mut memory)
}

/// Function performing the core verification.
fn verify_proof_inner<H: CurveHooks>(
    raw_proof: &[u8],
    pubs: &Public,
    memory: &mut Vec<u8>,
) -> Result<(), VerifyError> {
    let mut proof_cptr: usize = PROOF_OFFSET;
    let vka_end = mload_u32(memory, 0x40).map_err(|e| VerifyError::KeyError {
        message: format!("Unable to parse vka_end as u32. Cause: {e}").to_string(),
    })? as usize;
    let mut hash_mptr = vka_end + 0x20;

    // Check valid length of proof
    // success := and(success, eq(sub(instance_cptr, 0xa4), proof.length))

    let (
        theta_mptr,
        mut challenge_mptr,
        challenge_len_ptr,
        num_words,
        num_evals,
        challenge_len_data,
    ) = initialize_memory(memory, vka_end)?;

    (hash_mptr, proof_cptr, challenge_mptr) =
        read_instances_and_witness_commitments_and_generate_challenges::<H>(
            memory,
            raw_proof,
            pubs,
            num_words as u32,
            vka_end,
            hash_mptr,
            proof_cptr,
            challenge_mptr,
            challenge_len_ptr,
            challenge_len_data,
        )?;

    (proof_cptr, hash_mptr) =
        read_evaluations(memory, raw_proof, proof_cptr, hash_mptr, num_evals)?;

    read_bdfg21_batch_opening_proof_and_generate_challenges::<H>(
        memory,
        raw_proof,
        vka_end,
        challenge_mptr,
        hash_mptr,
        proof_cptr,
    )?;

    // Ensure memory is large enough for accumulator operations:
    // - read_accumulator needs theta_mptr + 0x180
    // - random_linear_combine keccak needs 2*vka_end + 0x100
    let required = core::cmp::max(theta_mptr + 0x180, 2 * vka_end + 0x100);
    if memory.len() < required {
        memory.resize(required, 0);
    }
    read_accumulator_from_instances(memory, pubs, theta_mptr)?;

    compute_lagrange_and_instance_evaluation(memory, pubs, theta_mptr)?;
    perform_quotient_evaluation(memory, raw_proof, vka_end, theta_mptr)?;
    compute_quotient_commitment::<H>(memory, raw_proof, vka_end, theta_mptr)?;
    compute_pairing_lhs_and_rhs::<H>(memory, raw_proof, vka_end, theta_mptr)?;
    random_linear_combine_with_accumulator::<H>(memory, vka_end, theta_mptr)?;

    pairing_check::<H>(memory, theta_mptr)
}

// Utility for checking if number of public inputs in the vk matches the actual length of the PI list.
fn check_public_input_number(memory: &[u8], pubs: &Public) -> Result<(), VerifyError> {
    let num_instances = pubs.len();
    let idx = 0x40 + VKA_OFFSET as u32 + MEMORY_OFFSET as u32;
    let num_instances_in_vka = mload_key(memory, idx, "check_public_input_number: load num_instances_in_vka")?
        .into_u256();
    if num_instances.into_u256() != num_instances_in_vka {
        return Err(VerifyError::PublicInputError {
            message: format!(
                "Number of instances provided does not match those in the vka. Given: {num_instances}; Expected: {num_instances_in_vka}",
            ),
        });
    }

    Ok(())
}

// Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20)
// and validate it.
// Then, store it in (hash_mptr, hash_mptr + 0x20).
// Return updated (success, proof_cptr, hash_mptr).
fn write_ec_point_into_memory<H: CurveHooks>(
    proof: &[u8],
    memory: &mut Vec<u8>,
    proof_cptr: usize,
    hash_mptr: usize,
) -> Result<(usize, usize), VerifyError> {
    let point = read_g1::<H>(proof, proof_cptr - PROOF_OFFSET).map_err(|e| {
        VerifyError::InvalidProofError {
            message: format!("Invalid Proof. Unable to read G1 point from proof. Cause: {e}"),
        }
    })?;
    // Ensure hash_mptr + 0x20 is not out of bounds
    while hash_mptr + 0x20 >= memory.len() {
        memory.extend_from_slice(&[0u8; 32]);
    }

    memory[hash_mptr..hash_mptr + 0x20].copy_from_slice(
        &point
            .x()
            .expect("Slices have the same length")
            .into_be_bytes32(),
    );
    memory[(hash_mptr + 0x20)..(hash_mptr + 0x40)].copy_from_slice(
        &point
            .y()
            .expect("Slices have the same length")
            .into_be_bytes32(),
    );

    Ok((proof_cptr + 0x40, hash_mptr + 0x40))
}

// Squeeze challenge by keccak256(memory[vka_end..hash_mptr]),
// and store hash mod r as challenge in challenge_mptr,
// and push back hash in vka_end as the first input for next squeeze.
// Return updated (challenge_mptr, hash_mptr).
fn squeeze_challenge(
    memory: &mut Vec<u8>,
    vka_end: usize,
    challenge_mptr: usize,
    hash_mptr: usize,
) -> Result<(usize, usize), ()> {
    let start = vka_end;
    let end = hash_mptr; // start + hash_mptr - vka_end

    let hash: [u8; 32] = Keccak256::new()
        .chain_update(&memory[start..end])
        .finalize()
        .into();

    // write hash into memory for use for subsequent challenge generation(s).
    memory[vka_end..vka_end + 0x20].copy_from_slice(&hash);
    while challenge_mptr >= memory.len() {
        memory.extend_from_slice(&[0u8; 32]);
    }

    // write hash (mod R) into memory.
    memory[challenge_mptr..challenge_mptr + 0x20]
        .copy_from_slice(&hash.into_fr().into_be_bytes32());

    Ok((challenge_mptr + 0x20, vka_end + 0x20))
}

// Squeeze challenge without absorbing new input from calldata,
// by putting an extra 0x01 in memory[0x21] and squeeze by keccak256(memory[0..21]),
// and store hash mod r as challenge in challenge_mptr,
// and push back hash in 0x220 as the first input for next squeeze.
// Return updated (challenge_mptr).
fn squeeze_challenge_cont(
    memory: &mut Vec<u8>,
    vka_end: usize,
    challenge_mptr: usize,
) -> Result<usize, ()> {
    memory[vka_end + 0x20] = 1u8;
    let hash: [u8; 32] = Keccak256::new()
        .chain_update(&memory[vka_end..vka_end + 0x21])
        .finalize()
        .into();
    memory[vka_end..vka_end + 0x20].copy_from_slice(&hash);
    while challenge_mptr >= memory.len() {
        memory.extend_from_slice(&[0u8; 32]);
    }

    memory[challenge_mptr..challenge_mptr + 0x20]
        .copy_from_slice(&hash.into_fr().into_be_bytes32());

    Ok(challenge_mptr + 0x20)
}

// Returns start of computations ptr and length of SoA layout memory
// encoding for quotient evaluation data (gate, permutation and lookup computations)
fn soa_layout_metadata(memory: &[u8], offset: usize) -> Result<(usize, usize), String> {
    let computations_len_ptr = mload_u32(memory, offset as u32).map_err(|e| {
        format!("soa_layout_metadata failed to parse computations_len_ptr as an u32. Cause: {e}")
    })?;
    Ok((
        computations_len_ptr as usize + 0x20,
        u32_from_be_tail(&mload(memory, computations_len_ptr).map_err(|e| {
        format!("soa_layout_metadata failed to parse value at computations_len_ptr as an u32. Cause: {e}")
    })?) as usize,
    ))
}

fn expression_evals_packed(
    memory: &mut [u8],
    raw_proof: &[u8],
    fsmp: usize,
    code_ptr: usize,
    mut expressions_word: U256,
) -> Result<(usize, U256, ProcessOutput), VerifyError> {
    // Load in the least significant byte of the `expressions_word` word to get the total number of words we will need to load in.
    let num_words_shift_up_one = (0x20 * lsb8(&expressions_word) + 0x20) as u32;
    // start of the expression encodings
    expressions_word >>= 8;

    let mut acc: u32 = 0;
    let mut ret0: usize = 0;
    for i in (0x20..num_words_shift_up_one).step_by(0x20) {
        while !expressions_word.is_zero() {
            let mstore_ptr = fsmp + acc as usize;

            // Load in the least significant byte of the `expression` word to get the operation type
            // Then determine which operation to peform and then store the result in the next available memory slot.
            match lsb8(&expressions_word) {
                // 0x00 => Advice/Fixed expression
                0x00 => {
                    expressions_word >>= 8;
                    // Load the calldata ptr from the expression, which come from the 2nd and 3rd least significant bytes.
                    let idx = lsb16(&expressions_word);
                    memory[mstore_ptr..mstore_ptr + 0x20].copy_from_slice(
                        &load_proof_key(raw_proof, idx as u32, "expr_evals: load advice/fixed")?,
                    );
                    // Move to the next expression
                    expressions_word >>= 16;
                }
                // 0x01 => Negated expression
                0x01 => {
                    expressions_word >>= 8;
                    // Load the memory ptr from the expression, which come from the 2nd and 3rd least significant bytes
                    let idx = lsb16(&expressions_word);
                    let temp = &mload_fr(memory, idx as u32, "expr_evals: load negated")?
                        .neg_in_place()
                        .into_be_bytes32();
                    memory[mstore_ptr..mstore_ptr + 0x20].copy_from_slice(temp);
                    // Move to the next expression
                    expressions_word >>= 16;
                }
                // 0x02 => Sum expression
                0x02 => {
                    expressions_word >>= 8;
                    // Load the lhs operand memory ptr from the expression, which comes from the 2nd and 3rd least significant bytes
                    let lhs = mload_fr(memory, lsb16(&expressions_word) as u32, "expr_evals: load sum lhs")?;
                    // Load the rhs operand memory ptr from the expression, which comes from the 4th and 5th least significant bytes
                    let rhs = mload_fr(memory, lsb16(&(expressions_word >> 16)) as u32, "expr_evals: load sum rhs")?;

                    memory[mstore_ptr..mstore_ptr + 0x20]
                        .copy_from_slice(&(lhs + rhs).into_be_bytes32());
                    // Move to the next expression
                    expressions_word >>= 32;
                }
                // 0x03 => Product/scalar expression
                0x03 => {
                    expressions_word >>= 8;
                    // Load the lhs operand memory ptr from the expression, which comes from the 2nd and 3rd least significant bytes
                    let lhs = mload_fr(memory, lsb16(&expressions_word) as u32, "expr_evals: load product lhs")?;
                    // Load the rhs operand memory ptr from the expression, which comes from the 4th and 5th least significant bytes
                    let rhs = mload_fr(memory, lsb16(&(expressions_word >> 16)) as u32, "expr_evals: load product rhs")?;

                    memory[mstore_ptr..mstore_ptr + 0x20]
                        .copy_from_slice(&(lhs * rhs).into_be_bytes32());
                    // Move to the next expression
                    expressions_word >>= 32;
                }
                // 0x04 => (For lookup expressions) Start accumulator evaluations for the lookup (table or input)
                // Will always occur at the end of the last word of the lookup expression.
                0x04 => {
                    let (res1, res2, res3) =
                        lookup_input_accum(memory, &expressions_word, i as usize, code_ptr)?;
                    return Ok((res1, res2, ProcessOutput::Scalar(res3)));
                }
                other => {
                    // Invalid opcode
                    return Err(VerifyError::KeyError {
                        message: format!(
                            "expression_evals_packed encountered an invalid opcode ({other})"
                        ),
                    });
                }
            }

            acc += 0x20;
        }
        ret0 = code_ptr + i as usize;
        expressions_word = mload_key(memory, ret0 as u32, "expr_evals: load expressions_word")?
            .into_u256();
    }
    let ret1 = expressions_word;
    let ret2 = (acc - 0x20) as usize;

    Ok((ret0, ret1, ProcessOutput::Index(ret2)))
}

fn lookup_input_accum(
    memory: &[u8],
    expressions_word: &U256,
    i: usize,
    code_ptr: usize,
) -> Result<(usize, U256, Fr), VerifyError> {
    let fmp = mload_u32(memory, 0x40).map_err(|e| VerifyError::KeyError {
        message: format!("lookup_input_accum: load fmp. Cause: {e}"),
    })?;
    let mut ret0: usize = 0;
    let mut expressions_word = *expressions_word;
    expressions_word >>= 8;
    // Number of words the mptr vars for the accumulator evaluations shifted up by one
    let num_words_vars = 0x20 * lsb8(&expressions_word);
    expressions_word >>= 8;
    // Initialize the accumulator with the first value in the vars
    let mut a = mload_fr(memory, lsb16(&expressions_word) as u32, "lookup_input_accum: load initial accum")?;
    expressions_word >>= 16;
    let theta = mload_fr(memory, fmp + 0x60, "lookup_input_accum: load theta")?;

    for j in (0..num_words_vars).step_by(0x20) {
        while !expressions_word.is_zero() {
            a = a * theta
                + mload_fr(memory, lsb16(&expressions_word) as u32, "lookup_input_accum: update accum")?;
            expressions_word >>= 16;
        }
        ret0 = code_ptr + i + j;
        expressions_word = mload_key(memory, ret0 as u32, "lookup_input_accum: load expressions_word")?.into_u256();
    }

    Ok((ret0, expressions_word, a))
}

#[allow(clippy::too_many_arguments)]
fn z_evals(
    memory: &mut [u8],
    raw_proof: &[u8],
    mut z: U256,
    num_words_packed: &U256,
    perm_z_last_ptr: usize,
    mut permutation_z_evals_ptr: usize,
    theta_mptr: usize,
    l_0: Fr,
    y: Fr,
    mut quotient_eval_numer: Fr,
) -> Result<Fr, VerifyError> {
    let mut num_words = lsb16(num_words_packed);

    // Initialize the free static memory pointer to store the column evals.
    let ptr = u32_from_be_tail(
        &mload(memory, 0x40).expect("z_evals should be able to load the fmp ptr at this point."),
    );
    let idx = ptr as usize + 0x20;
    let val = ptr + 0x40;
    memory[idx..idx + 0x20].copy_from_slice(&val.into_u256().into_be_bytes32());

    // Iterate through the tuple window length ( permutation_z_evals_len.len() - 1 ) offset by one word.
    while permutation_z_evals_ptr < perm_z_last_ptr {
        let next_z_ptr = permutation_z_evals_ptr + num_words;
        let z_j = mload_key(memory, next_z_ptr as u32, "z_evals: load z_j")?
            .into_u256();
        let lhs = load_proof_key(raw_proof, (lsb16(&z_j)) as u32, "z_evals: load lhs")?
            .into_fr();
        let rhs = load_proof_key(raw_proof, (lsb16(&(z >> 32))) as u32, "z_evals: load rhs")?
            .into_fr();
        quotient_eval_numer = quotient_eval_numer * y + l_0 * (lhs - rhs);

        col_evals(
            memory,
            raw_proof,
            z,
            num_words,
            permutation_z_evals_ptr,
            theta_mptr,
        )?;
        permutation_z_evals_ptr = next_z_ptr;
        z = z_j;
    }

    // Due to the fact that permutation_columns.len() in H2 might not be divisible by permutation_chunk_len, the last column length might be less than permutation_chunk_len
    // We store this length in the last 16 bits of the num_words_packed word.
    num_words = lsb16(&(*num_words_packed >> 16));

    col_evals(
        memory,
        raw_proof,
        z,
        num_words,
        permutation_z_evals_ptr,
        theta_mptr,
    )?;

    // Iterate through col_evals to update the quotient_eval_numer accumulator
    let fmp = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to load fmp from memory at this point."),
    ); // free memory pointer
    let temp = fmp + 0x20;
    let end_ptr = u32_from_be_tail(&mload_key(memory, temp, "z_evals: load end_ptr")?) as usize;
    let start = fmp as usize + 0x40;
    for j in (start..end_ptr).step_by(0x20) {
        quotient_eval_numer = quotient_eval_numer * y + mload_fr(memory, j as u32, "z_evals: update quotient_eval_numer")?;
    }

    Ok(quotient_eval_numer)
}

fn col_evals(
    memory: &mut [u8],
    raw_proof: &[u8],
    mut z: U256,
    num_words: usize,
    permutation_z_evals_ptr: usize,
    theta_mptr: usize,
) -> Result<(), VerifyError> {
    let gamma = mload_fr(memory, theta_mptr as u32 + 0x40, "col_evals: load gamma")?;
    let beta = mload_fr(memory, theta_mptr as u32 + 0x20, "col_evals: load beta")?;
    let l_last = mload_fr(memory, theta_mptr as u32 + 0x1c0, "col_evals: load l_last")?;
    let l_blind = mload_fr(memory, theta_mptr as u32 + 0x1e0, "col_evals: load l_blind")?;
    let i_eval = mload_fr(memory, theta_mptr as u32 + 0x220, "col_evals: load i_eval")?;

    // free memory pointer
    let fmp = u32_from_be_tail(
        &mload(memory, 0x40).expect("At this point, loading the fmp should succeed."),
    );

    // Extract the index 1 and index 0 z evaluations from the z word.
    let mut lhs = load_proof_key(raw_proof, (lsb16(&(z >> 16))) as u32, "col_evals: load lhs")?
        .into_fr();
    let mut rhs = load_proof_key(raw_proof, (lsb16(&z)) as u32, "col_evals: load rhs")?
        .into_fr();

    z >>= 48;
    // loop through the word_len_chunk
    for j in (0..num_words).step_by(0x20) {
        while !z.is_zero() {
            let mut eval = i_eval;

            if lsb8(&z) == 0x00 {
                eval = load_proof_key(raw_proof, (lsb16(&(z >> 8))) as u32, "col_evals: load eval")?
                    .into_fr();
            }

            lhs *= eval
                + beta * load_proof_key(raw_proof, (lsb16(&(z >> 24))) as u32, "col_evals: update lhs")?
                    .into_fr()
                + gamma;
            rhs *= eval
                + mload_fr(memory, fmp, "col_evals: update rhs")?
                + gamma;

            z >>= 40;

            let idx = fmp as usize;
            let val = DELTA
                * mload_fr(memory, fmp, "col_evals: load delta scalar")?;
            memory[idx..idx + 0x20].copy_from_slice(&val.into_be_bytes32());
        }
        z = mload(memory, (permutation_z_evals_ptr + j + 0x20) as u32)
            .map_err(|e| VerifyError::InvalidProofError {
                message: format!("col_evals was unable to load z from memory. Cause: {e}"),
            })?
            .into_u256();
    }
    let left_sub_right = lhs - rhs;

    let fsm_ptr =
        u32_from_be_tail(
            &mload_key(memory, fmp + 0x20, "col_evals: load fsm_ptr")?,
        ) as usize;

    let val = left_sub_right - left_sub_right * (l_last + l_blind);
    memory[fsm_ptr..fsm_ptr + 0x20].copy_from_slice(&val.into_be_bytes32());

    let idx = fmp as usize + 0x20;
    memory[idx..idx + 0x20].copy_from_slice(&(fsm_ptr + 0x20).into_u256().into_be_bytes32());

    Ok(())
}

fn lookup_expr_evals_packed(
    memory: &mut [u8],
    raw_proof: &[u8],
    fsmp: u32,
    code_ptr: u32,
    expressions_word: U256,
    mv: bool,
) -> Result<(usize, U256, Fr), VerifyError> {
    // expression evaluation.
    let (ret0, ret1, ret2) = expression_evals_packed(
        memory,
        raw_proof,
        fsmp as usize,
        code_ptr as usize,
        expressions_word,
    )?;

    match ret2 {
        ProcessOutput::Scalar(s) => {
            let mut ret2: Fr = s;
            if mv {
                let fmp = u32_from_be_tail(&mload_key(memory, 0x40, "lookup_expr_evals: load fmp")?);
                // add the beta accum addmod if mv lookup
                ret2 += mload_fr(memory, fmp + 0x80, "lookup_expr_evals: load beta accum")?;
            }

            Ok((ret0, ret1, ret2))
        }
        _ => Err(VerifyError::OtherError {
            message: "expression_evals_packed should have returned a Scalar variant.".to_string(),
        }),
    }
}

/// Computes the RHS accumulator for multi-input MV lookups (outer_inputs_len > 0x20).
/// Each input set contributes a product of the other sets' values, accumulated into rhs,
/// then multiplied by the table evaluation.
pub(crate) fn compute_multi_input_rhs(
    memory: &mut [u8],
    fmp: u32,
    outer_inputs_len: usize,
    table: Fr,
) -> Result<Fr, VerifyError> {
    let mut rhs = Fr::ZERO;
    let last_idx = outer_inputs_len - 0x20;
    for i in (0..outer_inputs_len).step_by(0x20) {
        let mut tmp = mload_fr(memory, 0xa0 + fmp, "mv_lookup_evals: load outer tmp")?;
        let mut j = 0x20;
        if i == 0 {
            tmp = mload_fr(memory, 0xc0 + fmp, "mv_lookup_evals: load outer tmp i=0")?;
            j = 0x40;
        }
        while j < outer_inputs_len {
            if i != j {
                tmp *= mload_fr(
                    memory,
                    j as u32 + 0xa0 + fmp,
                    "mv_lookup_evals: update outer tmp",
                )?;
            }
            j += 0x20;
        }
        rhs += tmp;
        if i == last_idx {
            rhs *= table;
        }
    }
    Ok(rhs)
}

fn mv_lookup_evals(
    memory: &mut [u8],
    raw_proof: &[u8],
    mut table: Fr,
    mut evals_ptr: usize,
    mut quotient_eval_numer: Fr,
    y: Fr,
) -> Result<(usize, Fr, Fr), VerifyError> {
    // load the free memory pointer
    let fmp = u32_from_be_tail(
        &mload(memory, 0x40).expect("mv_lookup_evals should be able to load fmp at this point."),
    );
    // iterate through the input_tables_len
    let mut evals = mload_key(memory, evals_ptr as u32, "mv_lookup_evals: load evals")?
        .into_u256();
    // We store a boolean flag in the first LSG byte of the evals ptr to determine if we need to load in a new table or reuse the previous table.
    let new_table = lsb8(&evals);
    evals >>= 8;
    let phi = lsb16(&evals);

    let tmp1 = mload_fr(memory, 0x20 + fmp, "mv_lookup_evals: load tmp1")?;
    let tmp2 = load_proof_key(raw_proof, phi as u32, "mv_lookup_evals: load phi")?
        .into_fr();
    quotient_eval_numer = quotient_eval_numer * y + tmp1 * tmp2;

    let tmp1 = mload_fr(memory, fmp, "mv_lookup_evals: load tmp1 fmp")?;
    quotient_eval_numer = quotient_eval_numer * y + tmp1 * tmp2;

    // load in the lookup_table_lines from the evals_ptr
    evals_ptr += 0x20;
    // Due to the fact that lookups can share the previous table, we can cache it for reuse.
    let mut input_expression = mload_key(memory, evals_ptr as u32, "mv_lookup_evals: load input_expression")?
        .into_u256();
    if new_table != 0 {
        (evals_ptr, input_expression, table) = lookup_expr_evals_packed(
            memory,
            raw_proof,
            0xa0 + fmp,
            evals_ptr as u32,
            mload_key(memory, evals_ptr as u32, "mv_lookup_evals: load expressions_word")?.into_u256(),
            true,
        )?;
    }
    // outer inputs len, stored in the first input expression word
    let outer_inputs_len = lsb16(&input_expression);
    input_expression >>= 16;
    // shift up the inputs iterator by the free static memory offset of 0xa0
    for j in
        ((0xa0 + fmp as usize)..(outer_inputs_len as usize + 0xa0 + fmp as usize)).step_by(0x20)
    {
        // call the expression_evals function to evaluate the input_lines
        let ident: Fr;
        (evals_ptr, input_expression, ident) = lookup_expr_evals_packed(
            memory,
            raw_proof,
            j as u32,
            evals_ptr as u32,
            input_expression,
            true,
        )?;
        // store ident in free static memory
        memory[j..j + 0x20].copy_from_slice(&ident.into_be_bytes32());
    }
    let mut rhs = if outer_inputs_len == 0x20 {
        table
    } else {
        compute_multi_input_rhs(memory, fmp, outer_inputs_len, table)?
    };

    let mut tmp = mload_fr(memory, 0xa0 + fmp, "mv_lookup_evals: load tmp product")?;
    for j in (0x20..outer_inputs_len).step_by(0x20) {
        tmp *= mload_fr(memory, j as u32 + 0xa0 + fmp, "mv_lookup_evals: update tmp product")?;
    }
    rhs -= load_proof_key(raw_proof, (lsb16(&(evals >> 32))) as u32, "mv_lookup_evals: update rhs")?
        .into_fr()
        * tmp;
    let lhs = table
        * tmp
        * (load_proof_key(raw_proof, (lsb16(&(evals >> 16))) as u32, "mv_lookup_evals: load lhs eval")?
            .into_fr()
            - load_proof_key(raw_proof, phi as u32, "mv_lookup_evals: load lhs phi")?.into_fr());
    quotient_eval_numer = quotient_eval_numer * y
        + (Fr::ONE
            - (mload_fr(memory, 0x40 + fmp, "mv_lookup_evals: load l_last")?
                + mload_fr(memory, fmp, "mv_lookup_evals: load l_blind")?))
            * (lhs - rhs);

    Ok((evals_ptr, table, quotient_eval_numer))
}

fn lookup_evals(
    memory: &mut [u8],
    raw_proof: &[u8],
    mut table: Fr,
    mut evals_ptr: usize,
    mut quotient_eval_numer: Fr,
    y: Fr,
) -> Result<(usize, Fr, Fr), VerifyError> {
    // load the free memory pointer
    let fmp = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to load fmp from memory at this point."),
    );
    // iterate through the input_tables_len
    let mut evals = mload_key(memory, evals_ptr as u32, "lookup_evals: load evals")?
        .into_u256();
    // We store a boolean flag in the first LSG byte of the evals ptr to determine if we need to load in a new table or reuse the previous table.
    let new_table = lsb8(&evals);
    evals >>= 8;
    let z = lsb16(&evals) as u32;
    evals >>= 16;
    quotient_eval_numer = quotient_eval_numer * y
        + mload_fr(memory, 0x20 + fmp, "lookup_evals: load l_0")?
        + mload_fr(memory, 0x20 + fmp, "lookup_evals: load l_0 neg")?
            * load_proof_key(raw_proof, z, "lookup_evals: load z eval")?
                .into_fr()
                .neg_in_place();

    {
        let l_blind = mload_fr(memory, fmp, "lookup_evals: load l_blind")?;
        let z_eval = load_proof_key(raw_proof, z, "lookup_evals: load z eval")?.into_fr();
        quotient_eval_numer = quotient_eval_numer * y + l_blind * (z_eval * z_eval - z_eval);
    }

    // load in the lookup_table_lines from the evals_ptr
    evals_ptr += 0x20;
    // Due to the fact that lookups can share the previous table, we can cache it for reuse.
    let mut input_expression = mload_key(memory, evals_ptr as u32, "lookup_evals: load input_expression")?
        .into_u256();
    if new_table != 0 {
        (evals_ptr, input_expression, table) = lookup_expr_evals_packed(
            memory,
            raw_proof,
            0xc0 + fmp,
            evals_ptr as u32,
            mload_key(memory, evals_ptr as u32, "lookup_evals: load expressions_word")?.into_u256(),
            false,
        )?;
    }
    // call the expression_evals function to evaluate the input_lines
    let input: Fr;
    (evals_ptr, _, input) = lookup_expr_evals_packed(
        memory,
        raw_proof,
        0xc0 + fmp,
        evals_ptr as u32,
        input_expression,
        false,
    )?;
    let p_input = lsb16(&(evals >> 16));
    let p_table = lsb16(&(evals >> 48));

    quotient_eval_numer = quotient_eval_numer * y
        + (Fr::ONE
            - (mload_fr(memory, 0x40 + fmp, "lookup_evals: load l_last")?
                + mload_fr(memory, fmp, "lookup_evals: load l_blind")?))
            * (load_proof_key(raw_proof, lsb16(&evals) as u32, "lookup_evals: load z_eval")?
                .into_fr()
                * (load_proof_key(raw_proof, p_input as u32, "lookup_evals: load p_input")?
                    .into_fr()
                    + mload_fr(memory, 0x80 + fmp, "lookup_evals: load beta")?)
                * (load_proof_key(raw_proof, p_table as u32, "lookup_evals: load p_table")?
                    .into_fr()
                    + mload_fr(memory, 0xa0 + fmp, "lookup_evals: load gamma")?)
                - load_proof_key(raw_proof, z, "lookup_evals: load z neg")?.into_fr()
                    * (input + mload_fr(memory, 0x80 + fmp, "lookup_evals: load beta2")?)
                    * (table + mload_fr(memory, 0xa0 + fmp, "lookup_evals: load gamma2")?));

    quotient_eval_numer = quotient_eval_numer * y
        + (mload_fr(memory, 0x20 + fmp, "lookup_evals: load l_0 diff")?
            * (load_proof_key(raw_proof, p_input as u32, "lookup_evals: load p_input diff")?.into_fr()
                - load_proof_key(raw_proof, p_table as u32, "lookup_evals: load p_table diff")?.into_fr()));

    quotient_eval_numer = quotient_eval_numer * y
        + (Fr::ONE
            - (mload_fr(memory, 0x40 + fmp, "lookup_evals: load l_last final")?
                + mload_fr(memory, fmp, "lookup_evals: load l_blind final")?))
            * (load_proof_key(raw_proof, p_input as u32, "lookup_evals: load p_input final")?.into_fr()
                - load_proof_key(raw_proof, p_table as u32, "lookup_evals: load p_table final")?.into_fr())
            * (load_proof_key(raw_proof, p_input as u32, "lookup_evals: load p_input sq")?.into_fr()
                - load_proof_key(raw_proof, lsb16(&(evals >> 32)) as u32, "lookup_evals: load prev_input")?.into_fr());

    Ok((evals_ptr, table, quotient_eval_numer))
}

fn point_rots(
    memory: &mut [u8],
    mut pcs_computations: U256,
    mut pcs_ptr: usize,
    mut word_shift: u32,
    mut x_pow_of_omega: Fr,
    omega: Fr,
    vka_end: usize,
) -> Result<(Fr, usize), String> {
    // Extract the 32 LSG bits (4 bytes) from the pcs_computations word to get the max rot
    let values_max_rot = lsb8(&pcs_computations);
    pcs_computations >>= 8;
    for i in 0..values_max_rot {
        let value = lsb16(&pcs_computations);
        if value != 0 {
            let idx = vka_end + value;
            memory[idx..idx + 0x20].copy_from_slice(&x_pow_of_omega.into_be_bytes32());
        }
        if i == values_max_rot - 1 {
            break;
        }
        x_pow_of_omega *= omega;
        word_shift >>= 16;
        pcs_computations >>= 16;
        if word_shift == 256 {
            word_shift = 0;
            pcs_ptr += 0x20;
            pcs_computations = mload(memory, pcs_ptr as u32).map_err(|e| format!("point_rots was unable to initialize pcs_computations using data from memory. Cause: {e}"))?.into_u256();
        }
    }

    Ok((x_pow_of_omega, pcs_ptr))
}

// Load a pair of Fq coordinates from memory at (addr) and (addr + 0x20).
fn load_fq_point(memory: &[u8], addr: u32, context: &str) -> Result<(Fq, Fq), VerifyError> {
    let x = mload_fq(memory, addr, context)?;
    let y = mload_fq(memory, addr + 0x20, context)?;
    Ok((x, y))
}

// Load 32 bytes from src_addr and copy them to memory[dst..dst+0x20].
fn mload_copy(
    memory: &mut [u8],
    src_addr: u32,
    dst: usize,
    context: &str,
) -> Result<(), VerifyError> {
    let bytes = mload_key(memory, src_addr, context)?;
    memory[dst..dst + 0x20].copy_from_slice(&bytes);
    Ok(())
}

// Write an affine G1 point's coordinates to memory at the given offset.
fn store_g1_to_memory(memory: &mut [u8], offset: usize, point: &G1<impl CurveHooks>) {
    memory[offset..offset + 0x20]
        .copy_from_slice(&point.x().expect("Should succeed").into_be_bytes32());
    memory[offset + 0x20..offset + 0x40]
        .copy_from_slice(&point.y().expect("Should succeed").into_be_bytes32());
}

// Scale point at (vka_end + offset) by scalar.
fn ec_mul<H: CurveHooks>(memory: &mut [u8], scalar: &Fr, offset: usize) -> Result<(), String> {
    let vka_end = u32_from_be_tail(
        &mload(memory, 0x40).expect("ec_mul should be able to read vka_end at this point."),
    ) as usize;

    let base = vka_end + offset;
    let point = read_g1::<H>(memory, base)
        .map_err(|e| format!("ec_mul was unable to read G1 point from memory. Cause: {e}"))?
        .into_group();

    let res = (point * scalar).into_affine();
    store_g1_to_memory(memory, base, &res);
    Ok(())
}

// Add (x, y) into point at (vka_end + offset).
fn ec_add<H: CurveHooks>(
    memory: &mut [u8],
    x: &Fq,
    y: &Fq,
    offset: usize,
) -> Result<(), String> {
    let vka_end = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to load vka_end from memory."),
    ) as usize;

    let base = vka_end + offset;
    let point1 = read_g1::<H>(memory, base)
        .map_err(|e| format!("ec_add was unable to read G1 point from memory. Cause: {e}"))?
        .into_group();
    let point2 = if *x == Fq::ZERO && *y == Fq::ZERO {
        G1::zero()
    } else {
        G1::<H>::new_unchecked(*x, *y)
    };

    if !point2.is_on_curve() {
        return Err("ec_add encountered a point not in G1.".to_string());
    }

    let res = (point1 + point2).into_affine();
    store_g1_to_memory(memory, base, &res);
    Ok(())
}

fn coeff_computations(
    memory: &mut [u8],
    coeff_len_data: U256,
    coeff_data: U256,
) -> Result<U256, VerifyError> {
    let coeff_len = lsb8(&coeff_len_data);
    let ret = coeff_len_data >> 8;

    let fmp = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to load vka_end from memory."),
    );
    match coeff_len {
        0x01 => {
            // We only encode the points if the coeff length is greater than 1.
            // Otherwise, we just encode the mu_minus_point and coeff ptr.
            let idx = lsb16(&(coeff_data >> 16)) + fmp as usize;
            let val = mload_fr(memory, lsb16(&coeff_data) as u32 + fmp, "coeff_computations: load val")?;
            memory[idx..idx + 0x20].copy_from_slice(&val.into_be_bytes32());
        }
        _ => {
            let mut coeff = Fr::ONE;
            let offset_aggr = coeff_len * 16;
            for i in 0..coeff_len {
                let mut first: usize = 0x01;
                let mut offset_base = i as u32 * 16;
                let idx = lsb16(&(coeff_data >> offset_base)) as u32 + fmp;
                let point_i = mload_fr(memory, idx, "coeff_computations: load point_i")?;
                for j in 0..coeff_len {
                    if j == i {
                        continue;
                    }
                    if first != 0 {
                        coeff = point_i
                            - mload_fr(memory, lsb16(&(coeff_data >> (16 * j as u32))) as u32 + fmp, "coeff_computations: load point_j")?;
                        first = 0;
                        continue;
                    }
                    coeff *= point_i
                        - mload_fr(memory, lsb16(&(coeff_data >> (16 * j as u32))) as u32 + fmp, "coeff_computations: load point_j mul")?;
                }
                offset_base += offset_aggr as u32;
                coeff *= mload_fr(memory, lsb16(&(coeff_data >> offset_base)) as u32 + fmp, "coeff_computations: load mu_minus_point")?;
                offset_base += offset_aggr as u32;
                let idx = lsb16(&(coeff_data >> offset_base)) + fmp as usize;
                memory[idx..idx + 0x20].copy_from_slice(&coeff.into_be_bytes32());
            }
        }
    }
    Ok(ret)
}

fn r_evals_computation(
    memory: &mut [u8],
    raw_proof: &[u8],
    rot_len: u32,
    r_evals_data_ptr: u32,
    zeta: Fr,
    quotient_eval: Fr,
    coeff_ptr: u32,
) -> Result<(Fr, usize), VerifyError> {
    let mut r_evals_data = mload_key(memory, r_evals_data_ptr, "r_evals_computation: load data")?
        .into_u256();
    // number of words to encode the data needed for this set in the r_evals computation.
    let num_words = lsb8(&r_evals_data) as u32;
    r_evals_data >>= 8;
    match rot_len {
        0x20 => {
            let (ret0, ret1) = single_rot_set(
                memory,
                raw_proof,
                r_evals_data,
                r_evals_data_ptr,
                num_words,
                zeta,
                quotient_eval,
                coeff_ptr,
            )?;
            Ok((ret0, ret1))
        }
        _ => {
            let (ret0, ret1) = multi_rot_set(
                memory,
                raw_proof,
                r_evals_data,
                r_evals_data_ptr,
                num_words,
                rot_len,
                zeta,
                coeff_ptr,
            )?;
            Ok((ret0, ret1))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn single_rot_set(
    memory: &mut [u8],
    raw_proof: &[u8],
    mut r_evals_data: U256,
    mut ptr: u32,
    num_words: u32,
    zeta: Fr,
    quotient_eval: Fr,
    coeff_ptr: u32,
) -> Result<(Fr, usize), VerifyError> {
    let coeff = mload_fr(memory, coeff_ptr, "single_rot_set: load coeff")?;
    let mut r_eval = Fr::ZERO;
    r_eval += coeff
        * load_proof_key(raw_proof, lsb16(&r_evals_data) as u32, "single_rot_set: load first eval")?
            .into_fr();
    r_evals_data >>= 16;
    r_eval *= zeta;
    r_eval += coeff * quotient_eval;
    for _ in 0..num_words {
        while !r_evals_data.is_zero() {
            let eval_group_len = lsb8(&r_evals_data);
            r_evals_data >>= 8;
            if eval_group_len != 0x0 {
                for _ in 0..eval_group_len {
                    r_eval = r_eval * zeta
                        + coeff
                            * load_proof_key(raw_proof, (lsb16(&r_evals_data)) as u32, "single_rot_set: load eval")?
                                .into_fr();
                    r_evals_data >>= 16;
                }
            } else {
                let mut mptr = lsb16(&r_evals_data);
                r_evals_data >>= 16;
                let mptr_end = lsb16(&r_evals_data);
                while mptr_end < mptr {
                    r_eval = r_eval * zeta
                        + coeff
                            * load_proof_key(raw_proof, mptr as u32, "single_rot_set: load eval range")?
                                .into_fr();
                    mptr -= 0x20;
                }
                r_evals_data >>= 16;
            }
        }
        ptr += 0x20;
        r_evals_data = mload_key(memory, ptr, "single_rot_set: reload data")?
            .into_u256();
    }

    Ok((r_eval, ptr as usize))
}

#[allow(clippy::too_many_arguments)]
fn multi_rot_set(
    memory: &mut [u8],
    raw_proof: &[u8],
    mut r_evals_data: U256,
    mut ptr: u32,
    num_words: u32,
    rot_len: u32,
    zeta: Fr,
    coeff_ptr: u32,
) -> Result<(Fr, usize), VerifyError> {
    let mut r_eval = Fr::ZERO;
    for i in 0..num_words {
        while !r_evals_data.is_zero() {
            for j in (0..rot_len).step_by(0x20) {
                r_eval += mload_fr(memory, coeff_ptr + j, "multi_rot_set: load coeff")?
                    * load_proof_key(raw_proof, lsb16(&r_evals_data) as u32, "multi_rot_set: load eval")?
                        .into_fr();
                r_evals_data >>= 16;
            }
            // Only on the last index do we NOT execute this if block.
            if !r_evals_data.is_zero() || i < num_words - 1 {
                r_eval *= zeta;
            }
        }
        ptr += 0x20;
        r_evals_data = mload_key(memory, ptr, "multi_rot_set: reload data")?
            .into_u256();
    }

    Ok((r_eval, ptr as usize))
}

// Initial phase of computations in preparation for the pairing check.
fn pairing_input_computations_first<H: CurveHooks>(
    memory: &mut [u8],
    raw_proof: &[u8],
    len: u32,
    mut pcs_ptr: u32,
    mut data: U256,
    theta_mptr: u32,
) -> Result<(), VerifyError> {
    let fmp = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to read fmp from memory at this point."),
    );

    let idx = fmp as usize;
    let bytes = load_proof_key(raw_proof, lsb16(&data) as u32, "pairing_first: load point.x")?;
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    data >>= 16;

    let idx = 0x20 + fmp as usize;
    let bytes = load_proof_key(raw_proof, lsb16(&data) as u32, "pairing_first: load point.y")?;
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    data >>= 16;
    for _ in (0..len).step_by(0x20) {
        while !data.is_zero() {
            let ptr_loc = lsb8(&data);
            data >>= 8;
            let comm_len = lsb8(&data);
            data >>= 8;

            match comm_len {
                0x0 => {
                    match ptr_loc {
                        0x0 => {
                            let mptr = lsb16(&data);
                            data >>= 16;
                            let mptr_end = lsb16(&data);
                            let num_commitments = (mptr - mptr_end) / 0x40 + 1;
                            let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_first: load nu")?;

                            let scalars: Vec<Fr> =
                                iter::successors(Some(Fr::ONE), |prev| Some(*prev * s))
                                    .take(num_commitments)
                                    .collect();

                            let commitments: Vec<G1<H>> = (0..num_commitments as u32).rev().map(|i| {
                                if i == 0 {
                                    read_g1::<H>(memory, fmp as usize).map_err(|e| VerifyError::KeyError { message: format!("Unable to load G1 point from memory during MSM computation. Cause: {e}") })
                                } else {
                                    read_g1::<H>(memory, mptr - (i as usize - 1) * 0x40).map_err(|e| VerifyError::KeyError { message: format!("Unable to load G1 point from memory during MSM computation. Cause: {e}") })
                                }
                            }).collect::<Result<Vec<_>, _>>()?;

                            let res = H::bn254_msm_g1(&commitments, &scalars).map_err(|_| {
                                VerifyError::OtherError {
                                    message: "MSM computation failed.".into(),
                                }
                            })?;

                            // Write result of MSM computation into memory
                            memory[fmp as usize..fmp as usize + 0x20].copy_from_slice(
                                &res.into_affine()
                                    .x()
                                    .expect("Should succeed")
                                    .into_be_bytes32(),
                            );
                            memory[fmp as usize + 0x20..fmp as usize + 0x40].copy_from_slice(
                                &res.into_affine()
                                    .y()
                                    .expect("Should succeed")
                                    .into_be_bytes32(),
                            );
                        }
                        0x1 => {
                            let mptr = lsb16(&data);
                            data >>= 16;
                            let mptr_end = lsb16(&data);
                            let num_commitments = (mptr - mptr_end) / 0x40 + 1;
                            let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_first: load nu")?;

                            let scalars: Vec<Fr> =
                                iter::successors(Some(Fr::ONE), |prev| Some(*prev * s))
                                    .take(num_commitments)
                                    .collect();

                            let commitments: Vec<G1<H>> = (0..num_commitments as u32).rev().map(|i| {
                                if i == 0 {
                                    read_g1::<H>(memory, fmp as usize).map_err(|e| VerifyError::KeyError { message: format!("Unable to load G1 point from memory during MSM computation. Cause: {e}") })
                                } else {
                                    read_g1::<H>(raw_proof, mptr - (i as usize - 1) * 0x40 - PROOF_OFFSET).map_err(|e| VerifyError::InvalidProofError { message: format!("Unable to load G1 point from proof during MSM computation. Cause: {e}") })
                                }
                            }).collect::<Result<Vec<_>, _>>()?;

                            let res = H::bn254_msm_g1(&commitments, &scalars).map_err(|_| {
                                VerifyError::OtherError {
                                    message: "MSM computation failed.".into(),
                                }
                            })?;

                            // Write result of MSM computation into memory
                            memory[fmp as usize..fmp as usize + 0x20].copy_from_slice(
                                &res.into_affine()
                                    .x()
                                    .expect("Should succeed")
                                    .into_be_bytes32(),
                            );
                            memory[fmp as usize + 0x20..fmp as usize + 0x40].copy_from_slice(
                                &res.into_affine()
                                    .y()
                                    .expect("Should succeed")
                                    .into_be_bytes32(),
                            );
                        }
                        other => {
                            return Err(VerifyError::OtherError {
                                message: format!(
                                    "pairing_input_computations_first encountered an invalid opcode ({other})"
                                ),
                            });
                        }
                    };
                    data >>= 16;
                }
                _ => {
                    match ptr_loc {
                        0x00 => {
                            let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_first: load nu")?;
                            ec_mul::<H>(memory, &s, 0).map_err(|e| VerifyError::KeyError {
                                message: format!(
                                    "pairing_input_computations_first failed. Cause: {e}"
                                ),
                            })?;
                            let x = mload_fq(memory, lsb16(&data) as u32, "pairing_first: load x from memory")?;
                            let y = mload_fq(memory, lsb16(&(data >> 16)) as u32, "pairing_first: load y from memory")?;
                            ec_add::<H>(memory, &x, &y, 0).map_err(|e| VerifyError::KeyError {
                                message: format!(
                                    "pairing_input_computations_first failed. Cause: {e}"
                                ),
                            })?;
                            if comm_len == 0x02 {
                                data >>= 32;
                                let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_first: load nu")?;
                                ec_mul::<H>(memory, &s, 0).map_err(|e| VerifyError::KeyError {
                                    message: format!(
                                        "pairing_input_computations_first failed. Cause: {e}"
                                    ),
                                })?;
                                let x = mload_fq(memory, lsb16(&data) as u32, "pairing_first: load x from memory")?;
                                let y = mload_fq(memory, lsb16(&(data >> 16)) as u32, "pairing_first: load y from memory")?;
                                ec_add::<H>(memory, &x, &y, 0).map_err(|e| {
                                    VerifyError::KeyError {
                                        message: format!(
                                            "pairing_input_computations_first failed. Cause: {e}"
                                        ),
                                    }
                                })?;
                            }
                            data >>= 32;
                        }
                        0x01 => {
                            let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_first: load nu")?;
                            ec_mul::<H>(memory, &s, 0).map_err(|e| VerifyError::KeyError {
                                message: format!(
                                    "pairing_input_computations_first failed. Cause: {e}"
                                ),
                            })?;
                            let x = Fq::from_be_bytes_mod_order(&load_proof_key(raw_proof, lsb16(&data) as u32, "pairing_first: load x from proof")?);
                            let y = Fq::from_be_bytes_mod_order(&load_proof_key(raw_proof, lsb16(&(data >> 16)) as u32, "pairing_first: load y from proof")?);
                            ec_add::<H>(memory, &x, &y, 0).map_err(|e| VerifyError::KeyError {
                                message: format!(
                                    "pairing_input_computations_first failed. Cause: {e}"
                                ),
                            })?;
                            if comm_len == 0x02 {
                                data >>= 32;
                                let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_first: load nu")?;
                                ec_mul::<H>(memory, &s, 0).map_err(|e| VerifyError::KeyError {
                                    message: format!(
                                        "pairing_input_computations_first failed. Cause: {e}"
                                    ),
                                })?;
                                let x = Fq::from_be_bytes_mod_order(
                                    &load_proof_key(raw_proof, lsb16(&data) as u32, "pairing_first: load x from proof")?,
                                );
                                let y = Fq::from_be_bytes_mod_order(
                                    &load_proof_key(raw_proof, lsb16(&(data >> 16)) as u32, "pairing_first: load y from proof")?,
                                );
                                ec_add::<H>(memory, &x, &y, 0).map_err(|e| {
                                    VerifyError::KeyError {
                                        message: format!(
                                            "pairing_input_computations_first failed. Cause: {e}"
                                        ),
                                    }
                                })?;
                            }
                            data >>= 32;
                        }
                        // Quotient eval x and y points
                        0x02 => {
                            let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_first: load nu")?;

                            ec_mul::<H>(memory, &s, 0).map_err(|e| VerifyError::KeyError {
                                message: format!(
                                    "pairing_input_computations_first failed. Cause: {e}"
                                ),
                            })?;

                            let (x, y) = load_fq_point(memory, theta_mptr + 0x260, "pairing_first: load quotient point")?;
                            ec_add::<H>(memory, &x, &y, 0).map_err(|e| VerifyError::KeyError {
                                message: format!(
                                    "pairing_input_computations_first failed. Cause: {e}"
                                ),
                            })?;
                        }
                        other => {
                            return Err(VerifyError::OtherError {
                                message: format!(
                                    "pairing_input_computations_first encountered an invalid opcode ({other})"
                                ),
                            });
                        }
                    }
                }
            }
        }
        pcs_ptr += 0x20;
        data = mload_key(memory, pcs_ptr, "pairing_first: reload data")?
            .into_u256();
    }
    Ok(())
}

// Perform subsequent computations in preparation for the pairing check.
pub(crate) fn pairing_input_computations<H: CurveHooks>(
    memory: &mut [u8],
    raw_proof: &[u8],
    len: u32,
    mut pcs_ptr: u32,
    mut data: U256,
    theta_mptr: u32,
) -> Result<(), VerifyError> {
    let fmp = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to read fmp from memory at this point."),
    );

    let idx = 0x80 + fmp as usize;
    let bytes = load_proof_key(raw_proof, lsb16(&data) as u32, "pairing_input: load point.x")?;
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    data >>= 16;

    let idx = 0xa0 + fmp as usize;
    let bytes = load_proof_key(raw_proof, lsb16(&data) as u32, "pairing_input: load point.y")?;
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    data >>= 16;
    for _ in (0..len).step_by(0x20) {
        while !data.is_zero() {
            let ptr_loc = lsb8(&data);
            data >>= 8;
            let comm_len = lsb8(&data);
            data >>= 8;
            match comm_len {
                0x0 => {
                    match ptr_loc {
                        0x00 => {
                            let mptr = lsb16(&data);
                            data >>= 16;
                            let mptr_end = lsb16(&data);
                            let num_commitments = (mptr - mptr_end) / 0x40 + 1;
                            let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_input: load nu")?;

                            let scalars: Vec<Fr> =
                                iter::successors(Some(Fr::ONE), |prev| Some(*prev * s))
                                    .take(num_commitments)
                                    .collect();

                            let commitments: Vec<G1<H>> = (0..num_commitments as u32).rev().map(|i| {
                                if i == 0 {
                                    read_g1::<H>(memory, fmp as usize + 0x80).map_err(|e| VerifyError::KeyError { message: format!("Unable to load G1 point from memory during MSM computation. Cause: {e}") })
                                } else {
                                    read_g1::<H>(memory, mptr - (i as usize - 1) * 0x40).map_err(|e| VerifyError::KeyError { message: format!("Unable to load G1 point from memory during MSM computation. Cause: {e}") })
                                }
                            }).collect::<Result<Vec<_>, _>>()?;

                            let res = H::bn254_msm_g1(&commitments, &scalars).map_err(|_| {
                                VerifyError::OtherError {
                                    message: "MSM computation failed.".into(),
                                }
                            })?;

                            // Write result of MSM computation into memory
                            memory[fmp as usize + 0x80..fmp as usize + 0xa0].copy_from_slice(
                                &res.into_affine()
                                    .x()
                                    .expect("Should succeed")
                                    .into_be_bytes32(),
                            );
                            memory[fmp as usize + 0xa0..fmp as usize + 0xc0].copy_from_slice(
                                &res.into_affine()
                                    .y()
                                    .expect("Should succeed")
                                    .into_be_bytes32(),
                            );
                        }
                        0x01 => {
                            let mptr = lsb16(&data);
                            data >>= 16;
                            let mptr_end = lsb16(&data);
                            let num_commitments = (mptr - mptr_end) / 0x40 + 1;
                            let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_input: load nu")?;

                            let scalars: Vec<Fr> =
                                iter::successors(Some(Fr::ONE), |prev| Some(*prev * s))
                                    .take(num_commitments)
                                    .collect();

                            let commitments: Vec<G1<H>> = (0..num_commitments as u32).rev().map(|i| {
                                if i == 0 {
                                    read_g1::<H>(memory, fmp as usize + 0x80).map_err(|e| VerifyError::KeyError { message: format!("Unable to load G1 point from memory during MSM computation. Cause: {e}") })
                                } else {
                                    read_g1::<H>(raw_proof, mptr - (i as usize - 1) * 0x40 - PROOF_OFFSET).map_err(|e| VerifyError::InvalidProofError { message: format!("Unable to load G1 point from proof during MSM computation. Cause: {e}") })
                                }
                            }).collect::<Result<Vec<_>, _>>()?;

                            let res = H::bn254_msm_g1(&commitments, &scalars).map_err(|_| {
                                VerifyError::OtherError {
                                    message: "MSM computation failed.".into(),
                                }
                            })?;

                            // Write result of MSM computation into memory
                            memory[fmp as usize + 0x80..fmp as usize + 0xa0].copy_from_slice(
                                &res.into_affine()
                                    .x()
                                    .expect("Should succeed")
                                    .into_be_bytes32(),
                            );
                            memory[fmp as usize + 0xa0..fmp as usize + 0xc0].copy_from_slice(
                                &res.into_affine()
                                    .y()
                                    .expect("Should succeed")
                                    .into_be_bytes32(),
                            );
                        }
                        other => {
                            return Err(VerifyError::OtherError {
                                message: format!(
                                    "pairing_input_computations encountered an invalid opcode ({other})"
                                ),
                            });
                        }
                    }
                    data >>= 16;
                }
                _ => {
                    match ptr_loc {
                        0x00 => {
                            let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_input: load nu")?;
                            ec_mul::<H>(memory, &s, 0x80).map_err(|e| VerifyError::KeyError {
                                message: format!("pairing_input_computations failed. Cause: {e}"),
                            })?;
                            let x = mload_fq(memory, lsb16(&data) as u32, "pairing_input: load x from memory")?;
                            let y = mload_fq(memory, lsb16(&(data >> 16)) as u32, "pairing_input: load y from memory")?;
                            ec_add::<H>(memory, &x, &y, 0x80).map_err(|e| VerifyError::KeyError {
                                message: format!("pairing_input_computations failed. Cause: {e}"),
                            })?;
                            if comm_len == 0x2 {
                                data >>= 32;
                                let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_input: load nu")?;
                                ec_mul::<H>(memory, &s, 0x80).map_err(|e| VerifyError::KeyError {
                                    message: format!(
                                        "pairing_input_computations failed. Cause: {e}"
                                    ),
                                })?;
                                let x = mload_fq(memory, lsb16(&data) as u32, "pairing_input: load x from memory")?;
                                let y = mload_fq(memory, lsb16(&(data >> 16)) as u32, "pairing_input: load y from memory")?;
                                ec_add::<H>(memory, &x, &y, 0x80).map_err(|e| {
                                    VerifyError::KeyError {
                                        message: format!(
                                            "pairing_input_computations failed. Cause: {e}"
                                        ),
                                    }
                                })?;
                            }
                            data >>= 32;
                        }
                        0x01 => {
                            let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_input: load nu")?;
                            ec_mul::<H>(memory, &s, 0x80).map_err(|e| VerifyError::KeyError {
                                message: format!("pairing_input_computations failed. Cause: {e}"),
                            })?;
                            let x = Fq::from_be_bytes_mod_order(&load_proof_key(raw_proof, lsb16(&data) as u32, "pairing_input: load x from proof")?);
                            let y = Fq::from_be_bytes_mod_order(&load_proof_key(raw_proof, lsb16(&(data >> 16)) as u32, "pairing_input: load y from proof")?);
                            ec_add::<H>(memory, &x, &y, 0x80).map_err(|e| VerifyError::KeyError {
                                message: format!("pairing_input_computations failed. Cause: {e}"),
                            })?;
                            if comm_len == 0x2 {
                                data >>= 32;
                                let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_input: load nu")?;
                                ec_mul::<H>(memory, &s, 0x80).map_err(|e| VerifyError::KeyError {
                                    message: format!(
                                        "pairing_input_computations failed. Cause: {e}"
                                    ),
                                })?;
                                let x = Fq::from_be_bytes_mod_order(&load_proof_key(raw_proof, lsb16(&data) as u32, "pairing_input: load x from proof")?);
                                let y = Fq::from_be_bytes_mod_order(&load_proof_key(raw_proof, lsb16(&(data >> 16)) as u32, "pairing_input: load y from proof")?);
                                ec_add::<H>(memory, &x, &y, 0x80).map_err(|e| {
                                    VerifyError::KeyError {
                                        message: format!(
                                            "pairing_input_computations failed. Cause: {e}"
                                        ),
                                    }
                                })?;
                            }
                            data >>= 32;
                        }
                        // Quotient eval x and y points
                        0x02 => {
                            let s = mload_fr(memory, theta_mptr + 0xa0, "pairing_input: load nu")?;
                            ec_mul::<H>(memory, &s, 0x80).map_err(|e| VerifyError::KeyError {
                                message: format!("pairing_input_computations failed. Cause: {e}"),
                            })?;
                            let (x, y) = load_fq_point(memory, theta_mptr + 0x260, "pairing_input: load quotient point")?;
                            ec_add::<H>(memory, &x, &y, 0x80).map_err(|e| VerifyError::KeyError {
                                message: format!("pairing_input_computations failed. Cause: {e}"),
                            })?;
                        }
                        other => {
                            return Err(VerifyError::OtherError {
                                message: format!(
                                    "pairing_input_computations encountered an invalid opcode ({other})"
                                ),
                            });
                        }
                    }
                }
            }
        }
        pcs_ptr += 0x20;
        data = mload_key(memory, pcs_ptr, "pairing_input: reload data")?
            .into_u256();
    }
    Ok(())
}

// Utility function for batch-inverting a chunk of `Fr` elements in memory.
fn batch_invert_in_memory(memory: &mut Vec<u8>, start: u32, end: u32) -> Result<(), String> {
    if end <= start {
        return Err(format!(
            "Unable to batch-invert in-memory. start index (0x{:x?}) >= end index (0x{:x?})",
            start, end
        )
        .to_string());
    } else if (end - start) & 31 != 0 {
        return Err(
            "Unable to batch-invert in-memory. Slice length is not a positive multiple of 32."
                .to_string(),
        );
    }

    let mut inverses = Vec::new();
    for p in (start..end).step_by(0x20) {
        inverses.push(
            mload(memory, p)
                .map_err(|e| {
                    format!("batch_invert_in_memory could not parse scalar from memory. Cause: {e}")
                })?
                .into_fr(),
        );
    }

    batch_inversion(&mut inverses);

    let start = start as usize;

    while start + inverses.len() * 0x20 >= memory.len() {
        memory.extend_from_slice(&[0u8; 32]);
    }

    for i in 0..inverses.len() {
        memory[(start + i * 0x20)..start + (i + 1) * 0x20]
            .copy_from_slice(&inverses[i].into_be_bytes32());
    }

    Ok(())
}

// Compute Lagrange evaluations and instance evaluation.
fn compute_lagrange_and_instance_evaluation(
    memory: &mut Vec<u8>,
    pubs: &Public,
    theta_mptr: usize,
) -> Result<(), VerifyError> {
    // Calculate vanishing polynomial numerator
    let k = mload_u32(memory, (VKA_OFFSET + 0x00a0 + MEMORY_OFFSET) as u32).map_err(|e| {
        VerifyError::KeyError {
            message: format!("Unable to parse k from the VKA as an u32. Cause: {e}"),
        }
    })?;

    let x = mload_fr(memory, theta_mptr as u32 + 0x80, "lagrange: load x")?;

    let mut x_n = x;
    for _ in 0..k {
        x_n = x_n.square();
    }

    // Prepare denominators for Lagrange evaluation
    let omega = mload_fr(memory, (VKA_OFFSET + 0x00e0 + MEMORY_OFFSET) as u32, "lagrange: load omega")?;

    let x_n_mptr = theta_mptr + 0x180;
    let mut mptr = x_n_mptr;

    let num_instances = mload_u32(memory, 0xe0).map_err(|e| VerifyError::KeyError {
        message: format!("Unable to parse num_instances from VKA as an u32. Cause: {e}"),
    })?;

    let num_neg_lagranges = mload_u32(memory, 0x0480).map_err(|e| VerifyError::KeyError {
        message: format!("Unable to parse num_neg_lagranges from VKA as an u32. Cause: {e}"),
    })?;

    let mut mptr_end = mptr + 32 * (num_instances + num_neg_lagranges) as usize;
    if num_instances == 0 {
        mptr_end += 0x20;
    }

    let mut pow_of_omega = mload_fr(memory, (VKA_OFFSET + 0x0120 + MEMORY_OFFSET) as u32, "lagrange: load omega_inv_to_l")?;

    while mptr_end >= memory.len() {
        memory.extend_from_slice(&[0u8; 32]);
    }

    while mptr < mptr_end {
        memory[mptr..mptr + 32].copy_from_slice(&(x - pow_of_omega).into_be_bytes32());
        pow_of_omega *= omega;
        mptr += 0x20;
    }

    let x_n_minus_1 = x_n - Fr::ONE;
    memory[mptr_end..mptr_end + 32].copy_from_slice(&x_n_minus_1.into_be_bytes32());

    batch_invert_in_memory(memory, x_n_mptr as u32, mptr_end as u32 + 0x20).map_err(|e| {
        VerifyError::KeyError {
            message: format!("Batch inversion failed. Cause: {e}"),
        }
    })?;

    let l_i_common = x_n_minus_1
        * mload_fr(memory, 0x0160, "lagrange: load n_inv")?;
    let mut pow_of_omega = mload_fr(memory, 0x01c0, "lagrange: load pow_of_omega")?;
    for mptr in (x_n_mptr..mptr_end).step_by(0x20) {
        let zeta_minus_omega_i_inv = mload_fr(memory, mptr as u32, "lagrange: load zeta_minus_omega_i_inv")?;
        memory[mptr..mptr + 0x20].copy_from_slice(
            &(l_i_common * zeta_minus_omega_i_inv * pow_of_omega).into_be_bytes32(),
        );

        pow_of_omega *= omega;
    }

    let mut l_blind = mload_fr(memory, x_n_mptr as u32 + 0x20, "lagrange: load l_blind")?;
    let l_i_cptr_end = x_n_mptr + 0x20 * num_neg_lagranges as usize;
    let mut l_i_cptr = x_n_mptr + 0x40;

    while l_i_cptr < l_i_cptr_end {
        l_blind += mload_fr(memory, l_i_cptr as u32, "lagrange: update l_blind")?;
        l_i_cptr += 0x20;
    }

    let mut instance_eval = Fr::ZERO;
    for instance in pubs {
        instance_eval += mload_fr(memory, l_i_cptr as u32, "lagrange: load l_i for instance")?
            * instance.into_fr();
        l_i_cptr += 0x20;
    }

    let x_n_minus_1_inv = mload_fr(memory, mptr_end as u32, "lagrange: load x_n_minus_1_inv")?;
    let l_last = mload_fr(memory, x_n_mptr as u32, "lagrange: load l_last")?;
    let l_0 = mload_fr(memory, x_n_mptr as u32 + 0x20 * num_neg_lagranges, "lagrange: load l_0")?;

    memory[x_n_mptr..x_n_mptr + 0x20].copy_from_slice(&x_n.into_be_bytes32());

    let mut start = theta_mptr + 0x1a0;
    memory[start..start + 0x20].copy_from_slice(&x_n_minus_1_inv.into_be_bytes32());

    start += 0x20;
    memory[start..start + 0x20].copy_from_slice(&l_last.into_be_bytes32());

    start += 0x20;
    memory[start..start + 0x20].copy_from_slice(&l_blind.into_be_bytes32());

    start += 0x20;
    memory[start..start + 0x20].copy_from_slice(&l_0.into_be_bytes32());

    start += 0x20;
    memory[start..start + 0x20].copy_from_slice(&instance_eval.into_be_bytes32());

    Ok(())
}

// Gate computations/expression evaluations. Returns updated quotient_eval_numer.
fn perform_gate_computations(
    memory: &mut [u8],
    raw_proof: &[u8],
    vka_end: usize,
    mut quotient_eval_numer: Fr,
    y: Fr,
) -> Result<Fr, VerifyError> {
    let gate_computations_len_offset = VKA_OFFSET + 0x0340 + MEMORY_OFFSET;
    let (mut computations_ptr, computations_len) =
        soa_layout_metadata(memory, gate_computations_len_offset).map_err(|e| {
            VerifyError::KeyError {
                message: format!("Failed to perform gate computations. Cause: {e}"),
            }
        })?;

    let mut expressions_word = mload_key(memory, computations_ptr as u32, "gate_computations: load expressions_word")?
        .into_u256();
    let mut last_idx: usize;

    // Load in the total number of code blocks from the vk constants, right after the number of= challenges
    for code_block in (0..computations_len).step_by(0x20) {
        // call expression_evals to evaluate the expressions in the code block
        let po: ProcessOutput;
        (computations_ptr, expressions_word, po) = expression_evals_packed(
            memory,
            raw_proof,
            vka_end,
            computations_ptr,
            expressions_word,
        )
        .map_err(|e| VerifyError::KeyError {
            message: format!("expression_evals_packed failed. Cause: {e:?}"),
        })?;
        match po {
            ProcessOutput::Index(ind) => {
                last_idx = ind;
            }
            _ => {
                return Err(VerifyError::OtherError {
                    message: "po should always be an Index variant at this point".to_string(),
                });
            }
        }

        // At the end of each code block we update `quotient_eval_numer`
        // If this is the first code block, we set `quotient_eval_numer` to the last var in the code block
        match code_block == 0 {
            true => {
                quotient_eval_numer = mload_fr(memory, (vka_end + last_idx) as u32, "gate_computations: load quotient_eval_numer")?
            }
            false => {
                // Otherwise we add the last var in the code block to `quotient_eval_numer` mod r
                quotient_eval_numer = quotient_eval_numer * y
                    + mload_fr(memory, (vka_end + last_idx) as u32, "gate_computations: update quotient_eval_numer")?;
            }
        }
    }

    Ok(quotient_eval_numer)
}

// Perform permutation computations. Returns updated quotient_eval_numer.
fn perform_permutation_computations(
    memory: &mut [u8],
    raw_proof: &[u8],
    vka_end: usize,
    theta_mptr: usize,
    mut quotient_eval_numer: Fr,
    y: Fr,
) -> Result<Fr, VerifyError> {
    let mut permutation_z_evals_ptr =
        mload_u32(memory, 0x0360 + VKA_OFFSET as u32 + MEMORY_OFFSET as u32).map_err(|e| {
            VerifyError::KeyError {
                message: format!(
                    "Unable to read permutation_computations_len_offset as an u32. Cause: {e}"
                ),
            }
        })?;

    let mut permutation_z_evals = mload_key(memory, permutation_z_evals_ptr, "perm: load permutation_z_evals")?
        .into_u256();
    // Last idx of permutation evals == permutation_evals.len() - 1
    let last_idx = lsb8(&permutation_z_evals);

    permutation_z_evals >>= 8;
    // Num of words scaled by 0x20 that take up each permutation eval (permutation_z_eval + column evals)
    // first and second LSG bytes contain the number of words for all of the permutation evals except the last.
    // The third and fourth LSG bytes contain the number of words for the last permutation eval
    let num_words = lsb32(&permutation_z_evals);
    permutation_z_evals >>= 32;
    permutation_z_evals_ptr += 0x20;
    permutation_z_evals = mload_key(memory, permutation_z_evals_ptr, "perm: reload permutation_z_evals")?
        .into_u256();
    let l_0 = mload_fr(memory, theta_mptr as u32 + 0x200, "perm: load l_0")?;

    {
        // Get the first and second LSG bytes from the first permutation_z_evals word to load in (z, _, _)
        let idx = lsb16(&permutation_z_evals) as u32;
        let eval = l_0
            - l_0
                * load_proof_key(raw_proof, idx, "perm: load z eval")?
                    .into_fr();
        quotient_eval_numer = quotient_eval_numer * y + eval;
    }

    {
        // Load in the last permutation_z_evals word
        let perm_z_last_ptr =
            last_idx * (num_words & PTR_BITMASK as usize) + permutation_z_evals_ptr as usize;

        let idx = lsb16(
            &mload_key(memory, perm_z_last_ptr as u32, "perm: load perm_z_last addr")?
                .into_u256(),
        ) as u32;
        let perm_z_last = load_proof_key(raw_proof, idx, "perm: load perm_z_last")?
            .into_fr();

        quotient_eval_numer = quotient_eval_numer * y
            + mload_fr(memory, theta_mptr as u32 + 0x1C0, "perm: load l_last")?
                * (perm_z_last * perm_z_last - perm_z_last);

        let lhs = mload_fr(memory, theta_mptr as u32 + 0x20, "perm: load beta")?;
        let rhs = mload_fr(memory, theta_mptr as u32 + 0x80, "perm: load zeta")?;
        memory[vka_end..vka_end + 0x20].copy_from_slice(&(lhs * rhs).into_be_bytes32());

        quotient_eval_numer = z_evals(
            memory,
            raw_proof,
            permutation_z_evals,
            &num_words.into_u256(),
            perm_z_last_ptr,
            permutation_z_evals_ptr as usize,
            theta_mptr,
            l_0,
            y,
            quotient_eval_numer,
        )?;
    }

    Ok(quotient_eval_numer)
}

// Lookup computations. Returns updated quotient_eval_numer.
fn perform_lookup_computations(
    memory: &mut [u8],
    raw_proof: &[u8],
    vka_end: usize,
    theta_mptr: usize,
    mut quotient_eval_numer: Fr,
    y: Fr,
) -> Result<Fr, VerifyError> {
    let value = &mload_key(memory, theta_mptr as u32 + 0x1c0, "lookup: load l_last")?;
    memory[vka_end..vka_end + 0x20].copy_from_slice(value); // l_last

    let value = &mload_key(memory, theta_mptr as u32 + 0x200, "lookup: load l_0")?;
    memory[(vka_end + 0x20)..(vka_end + 0x40)].copy_from_slice(value); // l_0

    let value = &mload_key(memory, theta_mptr as u32 + 0x1e0, "lookup: load l_blind")?;
    memory[(vka_end + 0x40)..(vka_end + 0x60)].copy_from_slice(value); // l_blind

    let value = &mload_key(memory, theta_mptr as u32, "lookup: load theta")?;
    memory[(vka_end + 0x60)..(vka_end + 0x80)].copy_from_slice(value); // theta

    let value = &mload_key(memory, theta_mptr as u32 + 0x20, "lookup: load beta")?;
    memory[(vka_end + 0x80)..(vka_end + 0xa0)].copy_from_slice(value); // beta

    let (mut evals_ptr, meta_data) =
        soa_layout_metadata(memory, 0x380 + VKA_OFFSET + MEMORY_OFFSET).map_err(|e| {
            VerifyError::KeyError {
                message: e.to_string(),
            }
        })?;

    // lookup meta data contains 32 byte flags for indicating if we need to do a lookup table lines
    // expression evaluation or we can use the previous one cached in the table var.
    if meta_data != 0 {
        let mut table = Fr::ZERO;
        let end_ptr = u32::try_from(meta_data as u64 & PTR_BITMASK)
            .expect("Conversion should succeed because this is just 2 bytes long");
        let mv = (meta_data >> 16) as u64 & BYTE_FLAG_BITMASK;
        match mv {
            0x0 => {
                while evals_ptr < end_ptr as usize {
                    (evals_ptr, table, quotient_eval_numer) = mv_lookup_evals(
                        memory,
                        raw_proof,
                        table,
                        evals_ptr,
                        quotient_eval_numer,
                        y,
                    )?;
                }
            }
            0x1 => {
                let bytes = mload_key(memory, theta_mptr as u32 + 0x40, "lookup: load gamma")?;
                memory[vka_end + 0xa0..vka_end + 0xa0 + 0x20].copy_from_slice(&bytes); // gamma

                while evals_ptr < end_ptr as usize {
                    (evals_ptr, table, quotient_eval_numer) =
                        lookup_evals(memory, raw_proof, table, evals_ptr, quotient_eval_numer, y)?;
                }
            }
            _ => {
                return Err(VerifyError::KeyError {
                    message: format!("Unsupported value for mv. Got: {mv}"),
                });
            }
        }
    }

    Ok(quotient_eval_numer)
}

// Compute quotient evaluation.
fn perform_quotient_evaluation(
    memory: &mut [u8],
    raw_proof: &[u8],
    vka_end: usize,
    theta_mptr: usize,
) -> Result<(), VerifyError> {
    let mut quotient_eval_numer = Fr::ONE;
    let y = mload_fr(memory, theta_mptr as u32 + 0x60, "quotient_eval: load y")?;

    quotient_eval_numer =
        perform_gate_computations(memory, raw_proof, vka_end, quotient_eval_numer, y)?;

    quotient_eval_numer = perform_permutation_computations(
        memory,
        raw_proof,
        vka_end,
        theta_mptr,
        quotient_eval_numer,
        y,
    )?;

    quotient_eval_numer = perform_lookup_computations(
        memory,
        raw_proof,
        vka_end,
        theta_mptr,
        quotient_eval_numer,
        y,
    )?;

    let idx = theta_mptr + 0x240;
    let val = quotient_eval_numer * mload_fr(memory, theta_mptr as u32 + 0x1a0, "quotient_eval: load x_n_minus_1_inv")?;
    memory[idx..(idx + 0x20)].copy_from_slice(&val.into_be_bytes32());

    Ok(())
}

// Compute quotient commitment
fn compute_quotient_commitment<H: CurveHooks>(
    memory: &mut Vec<u8>,
    raw_proof: &[u8],
    vka_end: usize,
    theta_mptr: usize,
) -> Result<(), VerifyError> {
    let first_quotient_x_cptr = 0x0320 + VKA_OFFSET + MEMORY_OFFSET;
    let last_quotient_x_cptr = 0x0300 + VKA_OFFSET + MEMORY_OFFSET;
    let bytes = load_from_proof(
        raw_proof,
        mload_u32(memory, last_quotient_x_cptr as u32).map_err(|e| VerifyError::KeyError {
            message: format!(
                "Unable to load pointer at last_quotient_x_cptr from memory. Cause: {e}"
            ),
        })?,
    )
    .map_err(|e| VerifyError::InvalidProofError {
        message: format!("Unable to load last_quotient_x from proof. Cause: {e}"),
    })?;

    memory[vka_end..(vka_end + 0x20)].copy_from_slice(&bytes);

    let bytes = load_from_proof(
        raw_proof,
        mload_u32(memory, last_quotient_x_cptr as u32).map_err(|e| VerifyError::KeyError {
            message: format!(
                "Unable to load pointer at last_quotient_x_cptr from memory. Cause: {e}"
            ),
        })? + 0x20,
    )
    .map_err(|e| VerifyError::InvalidProofError {
        message: format!("Unable to load last_quotient_y from proof. Cause: {e}"),
    })?;
    memory[(vka_end + 0x20)..(vka_end + 0x40)].copy_from_slice(&bytes);

    let x_n = mload_fr(memory, theta_mptr as u32 + 0x180, "quotient_commit: load x_n")?;

    let mut cptr =
        mload_u32(memory, last_quotient_x_cptr as u32).map_err(|e| VerifyError::KeyError {
            message: format!(
                "Failed to initialize cptr during quotient commitment computation phase. Cause: {e}"
            ),
        })? - 0x40;
    let cptr_end =  mload_u32(memory, first_quotient_x_cptr as u32).map_err(|e| VerifyError::KeyError {
                message: format!("Failed to initialize cptr_end during quotient commitment computation phase. Cause: {e}"),
            })? - 0x40;

    while cptr_end < cptr {
        ec_mul::<H>(memory, &x_n, 0).map_err(|e| VerifyError::KeyError {
            message: format!("compute_quotient_commitment failed. Cause: {e}"),
        })?;

        let x = Fq::from_be_bytes_mod_order(&load_proof_key(raw_proof, cptr, "quotient_commit: load x from proof")?);
        let y = Fq::from_be_bytes_mod_order(&load_proof_key(raw_proof, cptr + 0x20, "quotient_commit: load y from proof")?);
        ec_add::<H>(memory, &x, &y, 0).map_err(|e| VerifyError::KeyError {
            message: format!("compute_quotient_commitment failed. Cause: {e}"),
        })?;
        cptr -= 0x40;
    }

    while theta_mptr + 0x280 >= memory.len() {
        memory.extend_from_slice(&[0u8; 32]);
    }

    let bytes = mload(memory, vka_end as u32).map_err(|e| VerifyError::InvalidProofError { message: format!("Unable to read from memory at index vka_end during the quotient commitment computation phase. Cause: {e}") })?;
    memory[(theta_mptr + 0x260)..(theta_mptr + 0x260 + 0x20)].copy_from_slice(&bytes);

    let bytes = mload(memory, vka_end as u32 + 0x20).map_err(|e| VerifyError::InvalidProofError { message: format!("Unable to read from memory at index vka_end + 0x20 during the quotient commitment computation phase. Cause: {e}") })?;
    memory[(theta_mptr + 0x280)..(theta_mptr + 0x280 + 0x20)].copy_from_slice(&bytes);

    Ok(())
}

// Performs point_computations. Returns updated pcs_ptr.
fn perform_point_computations(
    memory: &mut [u8],
    vka_end: usize,
    theta_mptr: usize,
    mut pcs_ptr: usize,
) -> Result<usize, VerifyError> {
    let mut point_computations = mload_key(memory, pcs_ptr as u32, "point_comp: load point_computations")?.into_u256();
    let x = mload_fr(memory, theta_mptr as u32 + 0x80, "point_comp: load x")?;
    let omega = mload_fr(memory, 0x0180, "point_comp: load omega")?;
    let omega_inv = mload_fr(memory, 0x01a0, "point_comp: load omega_inv")?;
    let mut x_pow_of_omega = x * omega;
    (_, pcs_ptr) = point_rots(
        memory,
        point_computations,
        pcs_ptr,
        8,
        x_pow_of_omega,
        omega,
        vka_end,
    )
    .map_err(|e| VerifyError::KeyError {
        message: format!("perform_point_computations failed. Cause: {e}"),
    })?;
    pcs_ptr += 0x20;
    point_computations = mload_key(memory, pcs_ptr as u32, "point_comp: reload point_computations")?.into_u256();
    // Store interm point
    let idx = vka_end + lsb16(&point_computations);
    memory[idx..idx + 0x20].copy_from_slice(&x.into_be_bytes32());

    x_pow_of_omega = x * omega_inv;
    point_computations >>= 16;
    (_, pcs_ptr) = point_rots(
        memory,
        point_computations,
        pcs_ptr,
        24,
        x_pow_of_omega,
        omega_inv,
        vka_end,
    )
    .map_err(|e| VerifyError::KeyError {
        message: format!("perform_point_computations failed. Cause: {e}"),
    })?;
    pcs_ptr += 0x20;

    Ok(pcs_ptr)
}

// Performs vanishing computations. Returns updated pcs_ptr.
fn perform_vanishing_computations(
    memory: &mut [u8],
    vka_end: usize,
    theta_mptr: usize,
    mut pcs_ptr: usize,
) -> Result<usize, VerifyError> {
    let mu = mload_fr(memory, theta_mptr as u32 + 0xE0, "vanishing_comp: load mu")?;

    let mut vanishing_computations = mload_key(memory, pcs_ptr as u32, "vanishing_comp: load vanishing_computations")?.into_u256();

    memory[(vka_end + 0x20)..(vka_end + 0x40)].copy_from_slice(&U256::one().into_be_bytes32());

    let mut mptr = lsb16(&vanishing_computations);
    vanishing_computations >>= 16;
    let mptr_end = lsb16(&vanishing_computations);
    vanishing_computations >>= 16;
    let mut point_mptr = lsb16(&vanishing_computations);
    while mptr < mptr_end {
        let idx = vka_end + mptr;
        let val = mu - mload_fr(memory, (point_mptr + vka_end) as u32, "vanishing_comp: load scalar")?;
        memory[idx..idx + 0x20].copy_from_slice(&val.into_be_bytes32());

        mptr += 0x20;
        point_mptr += 0x20;
    }

    vanishing_computations >>= 16;
    let num_words = lsb8(&vanishing_computations);
    vanishing_computations >>= 8;
    let mut s = mload_fr(memory, (vka_end + lsb16(&vanishing_computations)) as u32, "vanishing_comp: init s")?;
    vanishing_computations >>= 16;
    for _ in 0..num_words {
        while !vanishing_computations.is_zero() {
            s *= mload_fr(memory, (vka_end + lsb16(&vanishing_computations)) as u32, "vanishing_comp: update s")?;
            vanishing_computations >>= 16;
        }
        pcs_ptr += 0x20;
        vanishing_computations = mload_key(memory, pcs_ptr as u32, "vanishing_comp: reload vanishing_computations")?.into_u256();
    }
    let mut diff_ptr = vka_end + lsb16(&vanishing_computations);
    memory[diff_ptr..diff_ptr + 0x20].copy_from_slice(&s.into_be_bytes32());

    vanishing_computations >>= 16;
    let mut diff: Fr;
    let sets_len = lsb16(&vanishing_computations);
    pcs_ptr += 0x20;
    vanishing_computations = mload_key(memory, pcs_ptr as u32, "vanishing_comp: reload vanishing_computations")?.into_u256();
    for i in 0..sets_len {
        diff = mload_fr(memory, (lsb16(&vanishing_computations) + vka_end) as u32, "vanishing_comp: load diff")?;
        vanishing_computations >>= 16;
        while !vanishing_computations.is_zero() {
            diff *= mload_fr(memory, (lsb16(&vanishing_computations) + vka_end) as u32, "vanishing_comp: update diff")?;
            vanishing_computations >>= 16;
        }
        diff_ptr += 0x20;
        memory[diff_ptr..diff_ptr + 0x20].copy_from_slice(&diff.into_be_bytes32());

        if i == 0 {
            memory[vka_end..vka_end + 0x20].copy_from_slice(&diff.into_be_bytes32());
        }
        pcs_ptr += 0x20;
        vanishing_computations = mload_key(memory, pcs_ptr as u32, "vanishing_comp: reload vanishing_computations")?.into_u256();
    }

    Ok(pcs_ptr)
}

// Performs coefficient computations. Returns updated pcs_ptr.
fn perform_coeff_computations(memory: &mut [u8], mut pcs_ptr: usize) -> Result<usize, VerifyError> {
    let mut coeff_len_data = mload_key(memory, pcs_ptr as u32, "coeff_comp: load coeff_len_data")?.into_u256();

    // Load in the least significant byte of the `coeff_len_data` word to get the total number
    // of words we will need to load in that contains the packed Vec<set.rots().len()>.
    let end_ptr_packed_lens = pcs_ptr + 0x20 * lsb8(&coeff_len_data);

    coeff_len_data >>= 8;

    let mut i = pcs_ptr;
    pcs_ptr = end_ptr_packed_lens;
    while i < end_ptr_packed_lens {
        while !coeff_len_data.is_zero() {
            let coeff_data = mload_key(memory, pcs_ptr as u32, "coeff_comp: load coeff_data")?.into_u256();
            coeff_len_data = coeff_computations(memory, coeff_len_data, coeff_data)?;
            pcs_ptr += 0x20;
        }
        coeff_len_data = mload_key(memory, i as u32 + 0x20, "coeff_comp: reload coeff_len_data")?.into_u256();
        i += 0x20;
    }

    Ok(pcs_ptr)
}

// Performs normalized coefficient computations.
fn perform_normalized_coeff_computations(
    memory: &mut Vec<u8>,
    vka_end: usize,
    mut pcs_ptr: usize,
) -> Result<usize, VerifyError> {
    let mut norm_coeff_data = mload_key(memory, pcs_ptr as u32, "norm_coeff: load norm_coeff_data")?.into_u256();

    batch_invert_in_memory(
        memory,
        vka_end as u32,
        (vka_end + lsb16(&norm_coeff_data)) as u32,
    )
    .map_err(|e| VerifyError::KeyError {
        message: format!("Batch inversion failed. Cause: {e}"),
    })?;

    norm_coeff_data >>= 16;

    let diff_0_inv = mload_fr(memory, vka_end as u32, "norm_coeff: load diff_0_inv")?;
    let mptr0 = lsb16(&norm_coeff_data) + vka_end;
    norm_coeff_data >>= 16;

    memory[mptr0..mptr0 + 0x20].copy_from_slice(&diff_0_inv.into_be_bytes32());

    let mptr_end = mptr0 + lsb16(&norm_coeff_data);
    for mptr in ((mptr0 + 0x20)..mptr_end).step_by(0x20) {
        let val = mload_fr(memory, mptr as u32, "norm_coeff: load scalar")? * diff_0_inv;
        memory[mptr..mptr + 0x20].copy_from_slice(&val.into_be_bytes32());
    }
    pcs_ptr += 0x20;

    Ok(pcs_ptr)
}

// Performs r_evals_computations. Returns updated pcs_ptr.
fn perform_r_evals_computations(
    memory: &mut [u8],
    raw_proof: &[u8],
    vka_end: usize,
    theta_mptr: usize,
    mut pcs_ptr: usize,
    mut coeff_ptr: usize,
) -> Result<usize, VerifyError> {
    let mut r_evals_meta_data = mload_key(memory, pcs_ptr as u32, "r_evals_comp: load meta_data")?.into_u256();

    let end_ptr_packed_lens = pcs_ptr + 0x20 * lsb8(&r_evals_meta_data);
    r_evals_meta_data >>= 8;
    let mut set_coeff = lsb16(&r_evals_meta_data) + vka_end;
    r_evals_meta_data >>= 16;
    let mut r_eval_mptr = lsb16(&r_evals_meta_data) + vka_end;
    r_evals_meta_data >>= 16;
    let mut i = pcs_ptr;
    pcs_ptr = end_ptr_packed_lens;
    let zeta = mload_fr(memory, theta_mptr as u32 + 0xA0, "r_evals_comp: load zeta")?;
    let quotient_eval = mload_fr(memory, theta_mptr as u32 + 0x240, "r_evals_comp: load quotient_eval")?;
    let mut not_first = false;
    let mut r_eval: Fr;
    while i < end_ptr_packed_lens {
        while !r_evals_meta_data.is_zero() {
            (r_eval, pcs_ptr) = r_evals_computation(
                memory,
                raw_proof,
                lsb8(&r_evals_meta_data) as u32,
                pcs_ptr as u32,
                zeta,
                quotient_eval,
                coeff_ptr as u32,
            )?;
            coeff_ptr += lsb8(&r_evals_meta_data);
            r_evals_meta_data >>= 8;
            if not_first {
                r_eval *= mload_fr(memory, set_coeff as u32, "r_evals_comp: load set_coeff")?;
                set_coeff += 0x20;
            }
            not_first = true;
            memory[r_eval_mptr..r_eval_mptr + 0x20].copy_from_slice(&r_eval.into_be_bytes32());
            r_eval_mptr += 0x20;
        }
        r_evals_meta_data = mload_key(memory, i as u32 + 0x20, "r_evals_comp: reload meta_data")?.into_u256();
        i += 0x20;
    }

    Ok(pcs_ptr)
}

// Performs coeff_sums_computation. Returns updated pcs_ptr.
fn perform_coeff_sums_computation(
    memory: &mut [u8],
    vka_end: usize,
    mut pcs_ptr: usize,
) -> Result<usize, VerifyError> {
    let mut coeff_sums_data = mload_key(memory, pcs_ptr as u32, "coeff_sums: load coeff_sums_data")?.into_u256();

    let end_ptr_packed_lens = pcs_ptr + 0x20 * lsb8(&coeff_sums_data);
    coeff_sums_data >>= 8;
    let mut coeff_ptr = vka_end + 0x20;

    let mut i = pcs_ptr;
    pcs_ptr = end_ptr_packed_lens;
    while i < end_ptr_packed_lens {
        while !coeff_sums_data.is_zero() {
            let mut sum = mload_fr(memory, coeff_ptr as u32, "coeff_sums: init sum")?;
            let len = lsb8(&coeff_sums_data);
            coeff_sums_data >>= 8;
            for j in (0x20..len).step_by(0x20) {
                sum += mload_fr(memory, (coeff_ptr + j) as u32, "coeff_sums: update sum")?; // TODO: ensure (coeff_ptr + j) as u32 fits into a `u32`
            }
            coeff_ptr += len;
            let idx = lsb16(&coeff_sums_data) + vka_end;
            memory[idx..idx + 0x20].copy_from_slice(&sum.into_be_bytes32());
            coeff_sums_data >>= 16;
        }
        coeff_sums_data = mload_key(memory, i as u32 + 0x20, "coeff_sums: reload coeff_sums_data")?.into_u256();
        i += 0x20;
    }

    Ok(pcs_ptr)
}

// Performs r_eval_computation. Returns updated value of pcs_ptr.
fn perform_r_eval_computation(
    memory: &mut Vec<u8>,
    vka_end: usize,
    theta_mptr: usize,
    mut pcs_ptr: usize,
) -> Result<usize, VerifyError> {
    let mut r_eval_data = mload_key(memory, pcs_ptr as u32, "r_eval_comp: load r_eval_data")?.into_u256();

    let mptr_end = lsb16(&r_eval_data) + vka_end;

    let mut mptr = vka_end;
    r_eval_data >>= 16;
    let mut sum_mptr = lsb16(&r_eval_data) + vka_end;
    while mptr < mptr_end {
        let bytes = mload_key(memory, sum_mptr as u32, "r_eval_computation: load sum")?;
        memory[mptr..mptr + 0x20].copy_from_slice(&bytes);
        mptr += 0x20;
        sum_mptr += 0x20;
    }
    r_eval_data >>= 16;

    batch_invert_in_memory(memory, vka_end as u32, mptr_end as u32).map_err(|e| {
        VerifyError::KeyError {
            message: format!("Batch inversion failed. Cause: {e}"),
        }
    })?;

    let r_eval_ptr = lsb16(&r_eval_data) + vka_end;
    let mut r_eval = mload_fr(memory, mptr_end as u32 - 0x20, "r_eval_comp: init r_eval lhs")?
        * mload_fr(memory, r_eval_ptr as u32, "r_eval_comp: init r_eval rhs")?;
    r_eval_data >>= 16;

    let mut sum_inv_mptr = mptr_end - 0x40;
    let sum_inv_mptr_end = vka_end - 0x20;
    let mut r_eval_mptr = r_eval_ptr - 0x20;

    while sum_inv_mptr > sum_inv_mptr_end {
        r_eval *= mload_fr(memory, theta_mptr as u32 + 0xc0, "r_eval_comp: load nu")?;
        r_eval += mload_fr(memory, sum_inv_mptr as u32, "r_eval_comp: load sum_inv")?
            * mload_fr(memory, r_eval_mptr as u32, "r_eval_comp: load r_eval_mptr")?;

        sum_inv_mptr -= 0x20;
        r_eval_mptr -= 0x20;
    }
    let idx = theta_mptr + 0x2a0;

    while idx >= memory.len() {
        memory.extend_from_slice(&[0u8; 32]);
    }
    memory[idx..idx + 0x20].copy_from_slice(&r_eval.into_be_bytes32());
    pcs_ptr += 0x20;

    Ok(pcs_ptr)
}

// pairing_input_computations
fn perform_pairing_input_computations<H: CurveHooks>(
    memory: &mut Vec<u8>,
    raw_proof: &[u8],
    vka_end: usize,
    theta_mptr: usize,
    mut pcs_ptr: usize,
) -> Result<(), VerifyError> {
    let mut nu = mload_fr(memory, theta_mptr as u32 + 0xC0, "perform_pairing_input: load nu")?;

    let mut pairing_input_meta_data = mload_key(memory, pcs_ptr as u32, "perform_pairing_input: load meta_data")?.into_u256();

    let end_ptr_packed_lens = pcs_ptr + 0x20 * lsb8(&pairing_input_meta_data);
    pairing_input_meta_data >>= 8;
    let mut set_coeff = lsb16(&pairing_input_meta_data) + vka_end;
    pairing_input_meta_data >>= 16;

    let mut ec_points_cptr_packed =
        pairing_input_meta_data.bitand(U256::new([0xffffffffffffffffu64, 0xffffu64, 0, 0]));

    pairing_input_meta_data >>= 80;
    let mut i = pcs_ptr;
    pcs_ptr = end_ptr_packed_lens;
    let mut first = true;

    while i < end_ptr_packed_lens {
        while !pairing_input_meta_data.is_zero() {
            let len = lsb8(&pairing_input_meta_data);
            pairing_input_meta_data >>= 8;
            if first {
                first = false;
                let data = mload_key(memory, pcs_ptr as u32, "perform_pairing_input: load data first")?.into_u256();
                pairing_input_computations_first::<H>(
                    memory,
                    raw_proof,
                    len as u32,
                    pcs_ptr as u32,
                    data,
                    theta_mptr as u32,
                )?;
                pcs_ptr += len;
                continue;
            }
            let data = mload_key(memory, pcs_ptr as u32, "perform_pairing_input: load data")?.into_u256();
            pairing_input_computations::<H>(
                memory,
                raw_proof,
                len as u32,
                pcs_ptr as u32,
                data,
                theta_mptr as u32,
            )?;
            pcs_ptr += len;
            let s = mload_fr(memory, set_coeff as u32, "perform_pairing_input: load set_coeff")?;
            ec_mul::<H>(memory, &(nu * s), 0x80).map_err(|e| VerifyError::KeyError {
                message: format!("perform_pairing_input_computations failed. Cause: {e}"),
            })?;
            set_coeff += 0x20;
            let (x, y) = load_fq_point(memory, 0x80 + vka_end as u32, "perform_pairing_input: load point")?;
            ec_add::<H>(memory, &x, &y, 0).map_err(|e| VerifyError::KeyError {
                message: format!("perform_pairing_input_computations failed. Cause: {e}"),
            })?;
            // Always executes: original Solidity used or(0x1, lt(i, sub(end_ptr_packed_lens, 0x20)))
            nu *= mload_fr(memory, theta_mptr as u32 + 0xc0, "perform_pairing_input: update nu")?;
        }
        pairing_input_meta_data = mload_key(memory, i as u32 + 0x20, "perform_pairing_input: reload meta_data")?
            .into_u256();
        i += 0x20;
    }

    // Load G1's SRS generator from the VKA into memory
    let idx1 = 0x01c0 + VKA_OFFSET + MEMORY_OFFSET; // g1_x index
    let idx2 = vka_end + 0x80;
    let g1_x_bytes = mload_key(memory, idx1 as u32, "perform_pairing_input: load g1_x")?;
    memory[idx2..idx2 + 0x20].copy_from_slice(&g1_x_bytes);

    let idx1 = 0x01e0 + VKA_OFFSET + MEMORY_OFFSET; // g1_y index
    let idx2 = vka_end + 0xa0;
    let g1_y_bytes = mload_key(memory, idx1 as u32, "perform_pairing_input: load g1_y")?;
    memory[idx2..idx2 + 0x20].copy_from_slice(&g1_y_bytes);

    let s = -mload_fr(memory, theta_mptr as u32 + 0x2a0, "perform_pairing_input: load r_eval")?;
    ec_mul::<H>(memory, &s, 0x80).map_err(|e| VerifyError::KeyError {
        message: format!("perform_pairing_input_computations failed. Cause: {e}"),
    })?;
    let (x, y) = load_fq_point(memory, 0x80 + vka_end as u32, "perform_pairing_input: load point")?;
    ec_add::<H>(memory, &x, &y, 0).map_err(|e| VerifyError::KeyError {
        message: format!("perform_pairing_input_computations failed. Cause: {e}"),
    })?;

    let idx = 0x80 + vka_end;
    let bytes = load_proof_key(raw_proof, lsb16(&ec_points_cptr_packed) as u32, "perform_pairing_input: load W.x")?;
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    ec_points_cptr_packed >>= 16;

    let idx = 0xa0 + vka_end;
    let bytes = load_proof_key(raw_proof, lsb16(&ec_points_cptr_packed) as u32, "perform_pairing_input: load W.y")?;
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    ec_points_cptr_packed >>= 16;

    let s = -mload_fr(
        memory,
        lsb16(&ec_points_cptr_packed) as u32 + vka_end as u32,
        "perform_pairing_input: load mu",
    )?;
    ec_mul::<H>(memory, &s, 0x80).map_err(|e| VerifyError::KeyError {
        message: format!("perform_pairing_input_computations failed. Cause: {e}"),
    })?;
    ec_points_cptr_packed >>= 16;

    let (x, y) = load_fq_point(memory, 0x80 + vka_end as u32, "perform_pairing_input: load point after mu")?;
    ec_add::<H>(memory, &x, &y, 0).map_err(|e| VerifyError::KeyError {
        message: format!("perform_pairing_input_computations failed. Cause: {e}"),
    })?;

    let w_prime_x =
        load_proof_key(raw_proof, lsb16(&ec_points_cptr_packed) as u32, "perform_pairing_input: load w_prime_x")?;
    ec_points_cptr_packed >>= 16;
    let w_prime_y =
        load_proof_key(raw_proof, lsb16(&ec_points_cptr_packed) as u32, "perform_pairing_input: load w_prime_y")?;

    let idx = 0x80 + vka_end;
    memory[idx..idx + 0x20].copy_from_slice(&w_prime_x);

    let idx = 0xa0 + vka_end;
    memory[idx..idx + 0x20].copy_from_slice(&w_prime_y);

    let s = mload_fr(memory, theta_mptr as u32 + 0xe0, "perform_pairing_input: load mu")?;
    ec_mul::<H>(memory, &s, 0x80).map_err(|e| VerifyError::KeyError {
        message: format!("perform_pairing_input_computations failed. Cause: {e}"),
    })?;
    let (x, y) = load_fq_point(memory, 0x80 + vka_end as u32, "perform_pairing_input: load point after w_prime")?;
    ec_add::<H>(memory, &x, &y, 0).map_err(|e| VerifyError::KeyError {
        message: format!("perform_pairing_input_computations failed. Cause: {e}"),
    })?;

    while theta_mptr + 0x320 >= memory.len() {
        memory.extend_from_slice(&[0u8; 32]);
    }

    let idx = theta_mptr + 0x2c0;
    let bytes = mload_key(memory, vka_end as u32, "perform_pairing_input: load LHS.x")?;
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    let idx = theta_mptr + 0x2e0;
    let bytes = mload_key(memory, 0x20 + vka_end as u32, "perform_pairing_input: load LHS.y")?;
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    let idx = theta_mptr + 0x300;
    memory[idx..idx + 0x20].copy_from_slice(&w_prime_x);

    let idx = theta_mptr + 0x320;
    memory[idx..idx + 0x20].copy_from_slice(&w_prime_y);

    Ok(())
}

// Compute pairing lhs and rhs
fn compute_pairing_lhs_and_rhs<H: CurveHooks>(
    memory: &mut Vec<u8>,
    raw_proof: &[u8],
    vka_end: usize,
    theta_mptr: usize,
) -> Result<(), VerifyError> {
    let mut pcs_ptr =
        mload_u32(memory, 0x03a0 + VKA_OFFSET as u32 + MEMORY_OFFSET as u32).map_err(|e| {
            VerifyError::KeyError {
                message: format!("Unable to read pcs_ptr from memory. Cause: {e}"),
            }
        })? as usize;
    let coeff_ptr = vka_end + 0x20;

    pcs_ptr = perform_point_computations(memory, vka_end, theta_mptr, pcs_ptr)?;
    pcs_ptr = perform_vanishing_computations(memory, vka_end, theta_mptr, pcs_ptr)?;
    pcs_ptr = perform_coeff_computations(memory, pcs_ptr)?;
    pcs_ptr = perform_normalized_coeff_computations(memory, vka_end, pcs_ptr)?;
    pcs_ptr =
        perform_r_evals_computations(memory, raw_proof, vka_end, theta_mptr, pcs_ptr, coeff_ptr)?;
    pcs_ptr = perform_coeff_sums_computation(memory, vka_end, pcs_ptr)?;
    pcs_ptr = perform_r_eval_computation(memory, vka_end, theta_mptr, pcs_ptr)?;

    perform_pairing_input_computations::<H>(memory, raw_proof, vka_end, theta_mptr, pcs_ptr)?;

    Ok(())
}

// Random linear combine with accumulator.
fn random_linear_combine_with_accumulator<H: CurveHooks>(
    memory: &mut [u8],
    vka_end: usize,
    theta_mptr: usize,
) -> Result<(), VerifyError> {
    let has_accumulator = !mload_key(memory, 0x0140 + VKA_OFFSET as u32 + MEMORY_OFFSET as u32, "verify: load has_accumulator")?
        .into_u256()
        .is_zero();

    if has_accumulator {
        let copy_map: &[(u32, usize)] = &[
            (0x100, 0x00), (0x120, 0x20), (0x140, 0x40), (0x160, 0x60),
            (0x2c0, 0x80), (0x2e0, 0xa0), (0x300, 0xc0), (0x320, 0xe0),
        ];
        for &(src_off, dst_off) in copy_map {
            mload_copy(memory, theta_mptr as u32 + src_off, vka_end + dst_off, "rlc: copy accumulator data")?;
        }

        // let challenge := mod(keccak256(vka_end, add(0x100, vka_end)), R)
        let challenge = {
            let start = vka_end;
            let end = vka_end + 0x100 + vka_end;
            let hash: [u8; 32] = Keccak256::new()
                .chain_update(&memory[start..end])
                .finalize()
                .into();
            hash.into_fr()
        };

        // [pairing_lhs] += challenge * [acc_lhs]
        ec_mul::<H>(memory, &challenge, 0).map_err(|e| VerifyError::KeyError {
            message: format!("random_linear_combine_with_accumulator failed. Cause: {e}"),
        })?;
        let (x, y) = load_fq_point(memory, theta_mptr as u32 + 0x2c0, "rlc: load pairing_lhs")?;
        ec_add::<H>(memory, &x, &y, 0).map_err(|e| VerifyError::KeyError {
            message: format!("random_linear_combine_with_accumulator failed. Cause: {e}"),
        })?;

        let idx = theta_mptr + 0x2c0;
        let bytes = mload_key(memory, vka_end as u32, "rlc: store updated lhs.x")?;
        memory[idx..idx + 0x20].copy_from_slice(&bytes);

        let idx = theta_mptr + 0x2e0;
        let bytes = mload_key(memory, vka_end as u32 + 0x20, "rlc: store updated lhs.y")?;
        memory[idx..idx + 0x20].copy_from_slice(&bytes);

        // [pairing_rhs] += challenge * [acc_rhs]
        let idx = vka_end;
        let bytes =
            mload_key(memory, theta_mptr as u32 + 0x140, "rlc: load acc_rhs.x")?;
        memory[idx..idx + 0x20].copy_from_slice(&bytes);

        let idx = vka_end + 0x20;
        let bytes =
            mload_key(memory, theta_mptr as u32 + 0x160, "rlc: load acc_rhs.y")?;
        memory[idx..idx + 0x20].copy_from_slice(&bytes);

        ec_mul::<H>(memory, &challenge, 0).map_err(|e| VerifyError::KeyError {
            message: format!("random_linear_combine_with_accumulator failed. Cause: {e}"),
        })?;
        let (x, y) = load_fq_point(memory, theta_mptr as u32 + 0x300, "rlc: load pairing_rhs")?;
        ec_add::<H>(memory, &x, &y, 0).map_err(|e| VerifyError::KeyError {
            message: format!("random_linear_combine_with_accumulator failed. Cause: {e}"),
        })?;

        let idx = theta_mptr + 0x300;
        let bytes = mload_key(memory, vka_end as u32, "rlc: store updated rhs.x")?;
        memory[idx..idx + 0x20].copy_from_slice(&bytes);

        let idx = theta_mptr + 0x320;
        let bytes = mload_key(memory, vka_end as u32 + 0x20, "rlc: store updated rhs.y")?;
        memory[idx..idx + 0x20].copy_from_slice(&bytes);
    }

    Ok(())
}

// Performs the final pairing check.
fn pairing_check<H: CurveHooks>(memory: &mut [u8], theta_mptr: usize) -> Result<(), VerifyError> {
    // LHS
    let (x, y) = load_fq_point(memory, theta_mptr as u32 + 0x2c0, "pairing_check: load LHS")?;
    let p_0 = G1::<H>::new(x, y);
    // RHS
    let (x, y) = load_fq_point(memory, theta_mptr as u32 + 0x300, "pairing_check: load RHS")?;
    let p_1 = G1::new(x, y);

    let g1_points = [G1Prepared::from(p_0), G1Prepared::from(p_1)];

    let g2_x_1_index = 0x0200 + VKA_OFFSET + MEMORY_OFFSET;
    let data = &memory[g2_x_1_index..g2_x_1_index + 4 * 0x20];
    let h1 = read_g2::<H>(data).expect("Parsing the SRS point should always work");
    // TODO: VALIDATION REQUIRED!
    // mstore(add(0x40, vka_end), mload( {{ vk_const_offsets["g2_x_1"]|hex() }}))
    // mstore(add(0x60, vka_end), mload( {{ vk_const_offsets["g2_x_2"]|hex() }}))
    // mstore(add(0x80, vka_end), mload( {{ vk_const_offsets["g2_y_1"]|hex() }}))
    // mstore(add(0xa0, vka_end), mload( {{ vk_const_offsets["g2_y_2"]|hex() }}))

    let neg_s_g2_x_1_index = 0x0280 + VKA_OFFSET + MEMORY_OFFSET;
    let data = &memory[neg_s_g2_x_1_index..neg_s_g2_x_1_index + 4 * 0x20];
    let h2 = read_g2::<H>(data).expect("Parsing the SRS point should always work");
    // TODO: VALIDATION REQUIRED!
    // mstore(add(0x100, vka_end), mload( {{ vk_const_offsets["neg_s_g2_x_1"]|hex() }}))
    // mstore(add(0x120, vka_end), mload( {{ vk_const_offsets["neg_s_g2_x_2"]|hex() }}))
    // mstore(add(0x140, vka_end), mload( {{ vk_const_offsets["neg_s_g2_y_1"]|hex() }}))
    // mstore(add(0x160, vka_end), mload( {{ vk_const_offsets["neg_s_g2_y_2"]|hex() }}))

    let g2_points = [G2Prepared::from(h1), G2Prepared::from(h2)];

    let product = Bn254::<H>::multi_pairing(g1_points, g2_points);

    if product.0.is_one() {
        Ok(())
    } else {
        Err(VerifyError::VerificationError)
    }
}

// Initializes memory before challenge generation.
// Returns initial values for: (theta_mptr, challenge_mptr, challenge_len_ptr, num_words, num_evals, challenge_len_data)
fn initialize_memory(
    memory: &mut Vec<u8>,
    vka_end: usize,
) -> Result<(usize, usize, usize, usize, u64, U256), VerifyError> {
    // copy the vka_digest to the vka_end location
    memory.extend_from_slice(
        &mload(memory, (VKA_OFFSET + 0xa0) as u32).expect("Should be able to extend memory."),
    );

    // let proof_cptr := proof.offset
    let challenge_mptr = vka_end
        + mload_u32(memory, (VKA_OFFSET + 0xc0) as u32).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to parse fsm as u32. Cause: {e}").to_string(),
        })? as usize;
    // Set the theta_mptr (vk_mptr + vk_len + challenges_length)
    let theta_mptr = challenge_mptr
        + mload_u32(memory, (VKA_OFFSET + 0x0120) as u32).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to compute theta_mptr as u32. Cause: {e}").to_string(),
        })? as usize;

    let challenge_len_ptr = VKA_OFFSET + MEMORY_OFFSET + 0x420;
    let mut challenge_len_data = mload_key(memory, challenge_len_ptr as u32, "init_memory: load challenge_len_data")?.into_u256();
    let num_words = lsb8(&challenge_len_data);

    challenge_len_data >>= 8;
    // num_evals is defined as u64 in order to be able to fit all possible u32 values
    let num_evals = u64::from(
        0x20 * mload_u32(memory, 0x60 + (VKA_OFFSET + MEMORY_OFFSET) as u32).map_err(|e| {
            VerifyError::KeyError {
                message: format!("Unable to read num_evals as u32. Cause: {e}").to_string(),
            }
        })?,
    );

    Ok((
        theta_mptr,
        challenge_mptr,
        challenge_len_ptr,
        num_words,
        num_evals,
        challenge_len_data,
    ))
}

// Read evaluations. Returns updated (proof_cptr, hash_mptr).
fn read_evaluations(
    memory: &mut [u8],
    raw_proof: &[u8],
    mut proof_cptr: usize,
    mut hash_mptr: usize,
    num_evals: u64,
) -> Result<(usize, usize), VerifyError> {
    let proof_cptr_end = proof_cptr + num_evals as usize; // num_evals
    while proof_cptr < proof_cptr_end {
        let eval: EVMWord = load_proof_key(raw_proof, proof_cptr as u32, "read_evaluations: load eval")?;
        if eval.into_u256() >= Fr::MODULUS {
            return Err(VerifyError::InvalidProofError {
                message: format!("Evaluation {} exceeds field modulus.", to_hex_string(&eval)),
            });
        }

        memory[hash_mptr..hash_mptr + 32].copy_from_slice(&eval);

        proof_cptr += 0x20;
        hash_mptr += 0x20;
    }

    Ok((proof_cptr, hash_mptr))
}

// Read instances and witness commitments and generate challenges.
// Returns updated: (hash_mptr, proof_cptr, challenge_mptr)
#[allow(clippy::too_many_arguments)]
fn read_instances_and_witness_commitments_and_generate_challenges<H: CurveHooks>(
    memory: &mut Vec<u8>,
    raw_proof: &[u8],
    pubs: &Public,
    num_words: u32,
    vka_end: usize,
    mut hash_mptr: usize,
    mut proof_cptr: usize,
    mut challenge_mptr: usize,
    mut challenge_len_ptr: usize,
    mut challenge_len_data: U256,
) -> Result<(usize, usize, usize), VerifyError> {
    for instance in pubs {
        if instance.into_u256() >= Fr::MODULUS {
            return Err(VerifyError::PublicInputError {
                message: format!(
                    "Instance {} exceeds scalar field modulus.",
                    to_hex_string(instance)
                ),
            });
        }
        memory.extend_from_slice(instance);
        hash_mptr += 0x20;
    }

    for _ in 0..num_words {
        challenge_len_ptr += 0x20;
        while !challenge_len_data.is_zero() {
            // add proof_cptr to num advices len
            let proof_cptr_end = proof_cptr + lsb16(&challenge_len_data);
            challenge_len_data >>= 16;
            // Phase loop
            while proof_cptr < proof_cptr_end {
                (proof_cptr, hash_mptr) =
                    write_ec_point_into_memory::<H>(raw_proof, memory, proof_cptr, hash_mptr)?;
            }

            // Generate challenges
            (challenge_mptr, hash_mptr) =
                squeeze_challenge(memory, vka_end, challenge_mptr, hash_mptr).map_err(|_| {
                    VerifyError::OtherError {
                        message: "Failed to squeeze challenge".into(),
                    }
                })?;

            // Continue squeezing challenges based on num_challenges
            let num_challenges = lsb8(&challenge_len_data);
            challenge_len_data >>= 8;
            for _ in 1..num_challenges {
                challenge_mptr =
                    squeeze_challenge_cont(memory, vka_end, challenge_mptr).map_err(|_| {
                        VerifyError::OtherError {
                            message: "Failed to squeeze subsequent challenge".into(),
                        }
                    })?;
            }
        }
        challenge_len_data = mload_key(memory, challenge_len_ptr as u32, "read_instances: reload challenge_len_data")?.into_u256();
    }

    Ok((hash_mptr, proof_cptr, challenge_mptr))
}

// Read Bdfg21 batch opening proof and generate challenges.
fn read_bdfg21_batch_opening_proof_and_generate_challenges<H: CurveHooks>(
    memory: &mut Vec<u8>,
    raw_proof: &[u8],
    vka_end: usize,
    mut challenge_mptr: usize,
    mut hash_mptr: usize,
    mut proof_cptr: usize,
) -> Result<(), VerifyError> {
    // zeta
    (challenge_mptr, hash_mptr) = squeeze_challenge(memory, vka_end, challenge_mptr, hash_mptr)
        .map_err(|_| VerifyError::OtherError {
            message: "Failed to squeeze challenge".into(),
        })?;

    // nu
    challenge_mptr = squeeze_challenge_cont(memory, vka_end, challenge_mptr).map_err(|_| {
        VerifyError::OtherError {
            message: "Failed to squeeze subsequent challenge".into(),
        }
    })?;

    // W
    (proof_cptr, hash_mptr) =
        write_ec_point_into_memory::<H>(raw_proof, memory, proof_cptr, hash_mptr)?;

    // mu
    (_, hash_mptr) =
        squeeze_challenge(memory, vka_end, challenge_mptr, hash_mptr).map_err(|_| {
            VerifyError::OtherError {
                message: "Failed to squeeze challenge".into(),
            }
        })?;

    // W'
    _ = write_ec_point_into_memory::<H>(raw_proof, memory, proof_cptr, hash_mptr)?;

    Ok(())
}

// Read accumulator from instances.
// Reconstructs two G1 points (lhs, rhs) from limb-encoded public inputs
// and stores their coordinates at theta_mptr + {0x100, 0x120, 0x140, 0x160}.
fn read_accumulator_from_instances(
    memory: &mut [u8],
    pubs: &Public,
    theta_mptr: usize,
) -> Result<(), VerifyError> {
    let has_accumulator = !mload_key(memory, 0x0140 + VKA_OFFSET as u32 + MEMORY_OFFSET as u32, "verify: load has_accumulator")?
        .into_u256()
        .is_zero();

    if has_accumulator {
        let acc_offset = mload_u32(memory, 0x0160 + VKA_OFFSET as u32 + MEMORY_OFFSET as u32)
            .map_err(|e| VerifyError::KeyError {
                message: format!("read_accumulator: load acc_offset failed. Cause: {e}"),
            })? as usize;
        let num_limbs = mload_u32(memory, 0x0180 + VKA_OFFSET as u32 + MEMORY_OFFSET as u32)
            .map_err(|e| VerifyError::KeyError {
                message: format!("read_accumulator: load num_limbs failed. Cause: {e}"),
            })? as usize;
        let num_limb_bits = mload_u32(memory, 0x01a0 + VKA_OFFSET as u32 + MEMORY_OFFSET as u32)
            .map_err(|e| VerifyError::KeyError {
                message: format!("read_accumulator: load num_limb_bits failed. Cause: {e}"),
            })? as usize;

        // Reconstruct 4 coordinates from instance limbs
        // Instance layout: [lhs_x limbs | lhs_y limbs | rhs_x limbs | rhs_y limbs]
        let coords = reconstruct_accumulator_coords(pubs, acc_offset, num_limbs, num_limb_bits)?;

        // Validate both points are on the BN254 curve: y² = x³ + 3
        let three = Fq::from(3u64);
        for (label, x, y) in [("lhs", coords[0], coords[1]), ("rhs", coords[2], coords[3])] {
            if y * y != x * x * x + three {
                return Err(VerifyError::OtherError {
                    message: format!("Accumulator {label} point is not on the BN254 curve"),
                });
            }
        }

        // Store at theta_mptr + {0x100, 0x120, 0x140, 0x160}
        for (coord, off) in coords.iter().zip([0x100, 0x120, 0x140, 0x160]) {
            let idx = theta_mptr + off;
            memory[idx..idx + 0x20].copy_from_slice(&coord.into_be_bytes32());
        }
    }

    Ok(())
}

// Reconstruct 4 Fq coordinates (lhs_x, lhs_y, rhs_x, rhs_y) from limb-encoded instances.
fn reconstruct_accumulator_coords(
    pubs: &Public,
    acc_offset: usize,
    num_limbs: usize,
    num_limb_bits: usize,
) -> Result<[Fq; 4], VerifyError> {
    let mut coords = [Fq::ZERO; 4];

    for (coord_idx, coord) in coords.iter_mut().enumerate() {
        let base = acc_offset + coord_idx * num_limbs;
        let mut value = U256::from(0u64);

        for limb_idx in 0..num_limbs {
            let inst_idx = base + limb_idx;
            if inst_idx >= pubs.len() {
                return Err(VerifyError::PublicInputError {
                    message: format!(
                        "Accumulator requires instance index {inst_idx} but only {} instances provided",
                        pubs.len()
                    ),
                });
            }
            let limb = pubs[inst_idx].into_u256() << (limb_idx * num_limb_bits) as u32;
            value |= limb;
        }

        *coord = Fq::from_bigint(value).ok_or_else(|| VerifyError::OtherError {
            message: format!(
                "Accumulator coordinate {coord_idx} exceeds the BN254 base field modulus"
            ),
        })?;
    }

    Ok(coords)
}

#[cfg(test)]
mod should;
