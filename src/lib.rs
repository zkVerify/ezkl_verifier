#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

mod constants;
pub mod errors;
// mod proof;
mod types;
mod utils;
// mod vk;

extern crate alloc;
extern crate core;

use alloc::{format, string::ToString, vec::Vec};
use ark_bn254_ext::CurveHooks;
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{AdditiveGroup, BigInteger, Field, One, PrimeField, fields::batch_inversion};
use ark_models_ext::bn::{G1Prepared, G2Prepared};
use core::ops::BitAnd;
use sha3::{Digest, Keccak256};

use crate::{
    constants::{BYTE_FLAG_BITMASK, DELTA, PTR_BITMASK},
    utils::{
        IntoBEBytes32, IntoFr, IntoU256, load_from_proof, lsb8, lsb16, lsb32, mload, mload_u32,
        read_g1, read_g2, to_hex_string, u32_from_be_tail,
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

pub fn verify<H: CurveHooks>(
    raw_vka: &[u8],
    raw_proof: &[u8],
    pubs: &Public,
) -> Result<(), VerifyError> {
    let mut memory = Vec::<u8>::from(&mut [0u8; 64]);

    if raw_vka.len() == 0 || raw_vka.len() & 0x1f != 0 {
        return Err(VerifyError::KeyError {
            message: "vk length must be a positive multiple of 32".to_string(),
        });
    }

    memory.extend_from_slice(
        &(raw_vka.len() + MEMORY_OFFSET)
            .into_u256()
            .into_be_bytes32(),
    );
    memory.extend_from_slice(&[0u8; 32]);
    memory.extend_from_slice(&raw_vka.len().into_u256().into_be_bytes32());
    memory.extend_from_slice(&raw_vka);

    // Check valid length of instances
    check_public_input_number(&memory, pubs)?;

    verify_proof_inner::<H>(&raw_proof, &pubs, &mut memory)

    // TODO: Rescaling Phase (if needed)
}

/// Function performing the core verification.
fn verify_proof_inner<H: CurveHooks>(
    raw_proof: &[u8],
    pubs: &Public,
    memory: &mut Vec<u8>,
) -> Result<(), VerifyError> {
    let mut proof_cptr: usize = PROOF_OFFSET;
    let vka_end = mload_u32(memory, 0x40).map_err(|e| VerifyError::KeyError {
        message: format!("Unable to parse vka_end as u32. Cause: {}", e).to_string(),
    })? as usize;
    let mut hash_mptr = vka_end + 0x20;

    // let instance_cptr := instances.offset

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

    // TODO: Restore when implemented.
    // read_accumulator_from_instances();

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
    let num_instances_in_vka = mload(memory, idx)
        .map_err(|_| VerifyError::KeyError {
            message: format!(
                "Unable to access memory at index 0x{:x?} (num_instances).",
                idx
            )
            .to_string(),
        })?
        .into_u256();
    if num_instances.into_u256() != num_instances_in_vka {
        return Err(VerifyError::PublicInputError {
            message: format!(
                "Number of instances provided does not match those in the vka. Given: {}; Expected: {}",
                num_instances, num_instances_in_vka
            ),
        });
    }

    Ok(())
}

// Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20)
// and validate it.
// Then, store it in (hash_mptr, hash_mptr + 0x20).
// Return updated (success, proof_cptr, hash_mptr).
pub(crate) fn write_ec_point_into_memory<H: CurveHooks>(
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
    // let hash := keccak256(vka_end, sub(hash_mptr, vka_end))
    let start = vka_end;
    let end = hash_mptr; // start + hash_mptr - vka_end

    let hash: [u8; 32] = Keccak256::new()
        .chain_update(&memory[start..end])
        .finalize()
        .into();

    // write hash into memory for use for subsequent challenge generation(s).
    memory[vka_end..vka_end + 0x20].copy_from_slice(&hash); // mstore(vka_end, hash)
    while challenge_mptr >= memory.len() {
        memory.extend_from_slice(&[0u8; 32]);
    }

    // write hash (mod R) into memory.
    memory[challenge_mptr..challenge_mptr + 0x20]
        .copy_from_slice(&hash.into_fr().into_be_bytes32()); // mstore(challenge_mptr, mod(hash, R))

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
    memory[vka_end + 0x20] = 1u8; // mstore8(add(vka_end, 0x20), 0x01)
    // let hash := keccak256(vka_end, 0x21)
    let hash: [u8; 32] = Keccak256::new()
        .chain_update(&memory[vka_end..vka_end + 0x21])
        .finalize()
        .into();

    memory[vka_end..vka_end + 0x20].copy_from_slice(&hash); // mstore(vka_end, hash)
    while challenge_mptr >= memory.len() {
        memory.extend_from_slice(&[0u8; 32]);
    }
    memory[challenge_mptr..challenge_mptr + 0x20]
        .copy_from_slice(&hash.into_fr().into_be_bytes32()); // mstore(challenge_mptr, mod(hash, R))

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
) -> Result<(usize, U256, ProcessOutput), ()> {
    // Load in the least significant byte of the `expressions_word` word to get the total number of words we will need to load in.
    let num_words_shift_up_one = (0x20 * lsb8(&expressions_word) + 0x20) as u32;

    // let mut expressions_word = *expressions_word;

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
                    let idx = lsb16(&expressions_word) - PROOF_OFFSET;
                    memory[mstore_ptr..mstore_ptr + 0x20]
                        .copy_from_slice(&raw_proof.get(idx..idx + 0x20).unwrap());

                    // Move to the next expression
                    expressions_word >>= 16;
                }
                // 0x01 => Negated expression
                0x01 => {
                    expressions_word >>= 8;
                    // Load the memory ptr from the expression, which come from the 2nd and 3rd least significant bytes
                    let idx = lsb16(&expressions_word) - PROOF_OFFSET;
                    let temp = &mload(memory, idx as u32)
                        .unwrap()
                        .into_fr()
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
                    let lhs = mload(memory, lsb16(&expressions_word) as u32)
                        .unwrap()
                        .into_fr();
                    // Load the rhs operand memory ptr from the expression, which comes from the 4th and 5th least significant bytes
                    let rhs = mload(memory, lsb16(&(expressions_word >> 16)) as u32)
                        .unwrap()
                        .into_fr();

                    memory[mstore_ptr..mstore_ptr + 0x20]
                        .copy_from_slice(&(lhs + rhs).into_be_bytes32());
                    // Move to the next expression
                    expressions_word >>= 32;
                }
                // 0x03 => Product/scalar expression
                0x03 => {
                    expressions_word >>= 8;
                    // Load the lhs operand memory ptr from the expression, which comes from the 2nd and 3rd least significant bytes
                    let lhs = mload(memory, lsb16(&expressions_word) as u32)
                        .unwrap()
                        .into_fr();
                    // Load the rhs operand memory ptr from the expression, which comes from the 4th and 5th least significant bytes
                    let rhs = mload(memory, lsb16(&(expressions_word >> 16)) as u32)
                        .unwrap()
                        .into_fr();

                    memory[mstore_ptr..mstore_ptr + 0x20]
                        .copy_from_slice(&(lhs * rhs).into_be_bytes32());
                    // Move to the next expression
                    expressions_word >>= 32;
                }
                // 0x04 => (For lookup expressions) Start accumulator evaluations for the lookup (table or input)
                // Will always occur at the end of the last word of the lookup expression.
                0x04 => {
                    let (res1, res2, res3) = lookup_input_accum(
                        memory,
                        &expressions_word,
                        // fsmp,
                        i as usize,
                        code_ptr,
                    )?;
                    return Ok((res1, res2, ProcessOutput::Scalar(res3)));
                }
                _ => {
                    // Invalid opcode
                    return Err(()); // TODO: define proper error
                }
            }

            acc += 0x20;
        }
        ret0 = code_ptr + i as usize;
        expressions_word = mload(memory, ret0 as u32).unwrap().into_u256();
    }
    let ret1 = expressions_word;
    let ret2 = (acc - 0x20) as usize;

    Ok((ret0, ret1, ProcessOutput::Index(ret2)))
}

fn lookup_input_accum(
    memory: &[u8],
    expressions_word: &U256,
    // fsmp: usize,
    i: usize,
    code_ptr: usize,
) -> Result<(usize, U256, Fr), ()> {
    let mut ret0: usize = 0;
    let ret1: U256;
    let ret2: Fr;
    let mut expressions_word = *expressions_word;
    expressions_word >>= 8;
    // Number of words the mptr vars for the accumulator evaluations shifted up by one
    let num_words_vars = 0x20 * lsb8(&expressions_word);
    expressions_word >>= 8;
    // initialize the accumulator with the first value in the vars
    let mut a = mload(memory, lsb16(&expressions_word) as u32)
        .unwrap()
        .into_fr();
    expressions_word >>= 16;
    let theta = mload(
        memory,
        u32_from_be_tail(&mload(memory, 0x40).unwrap()) + 0x60,
    )
    .unwrap()
    .into_fr();
    for j in (0..num_words_vars).step_by(0x20) {
        while !expressions_word.is_zero() {
            a = a * theta
                + mload(memory, lsb16(&expressions_word) as u32)
                    .unwrap()
                    .into_fr();
            expressions_word >>= 16;
        }
        ret0 = code_ptr + i + j;
        expressions_word = mload(memory, ret0 as u32).unwrap().into_u256();
    }
    ret1 = expressions_word;
    ret2 = a;

    Ok((ret0, ret1, ret2))
}

fn z_evals(
    memory: &mut [u8],
    raw_proof: &[u8],
    z: U256,
    num_words_packed: &U256,
    perm_z_last_ptr: usize,
    permutation_z_evals_ptr: usize,
    theta_mptr: usize,
    l_0: Fr,
    y: Fr,
    quotient_eval_numer: Fr,
) -> Fr {
    let mut num_words = lsb16(&num_words_packed);

    let mut quotient_eval_numer = quotient_eval_numer;
    let mut z = z.clone();
    let mut permutation_z_evals_ptr = permutation_z_evals_ptr;

    // Initialize the free static memory pointer to store the column evals.
    let ptr = u32_from_be_tail(&mload(memory, 0x40).unwrap());
    let idx = ptr as usize + 0x20;
    let val = ptr + 0x40;
    memory[idx..idx + 0x20].copy_from_slice(&val.into_u256().into_be_bytes32());

    // Iterate through the tuple window length ( permutation_z_evals_len.len() - 1 ) offset by one word.
    while permutation_z_evals_ptr < perm_z_last_ptr {
        let next_z_ptr = permutation_z_evals_ptr + num_words;
        let z_j = mload(memory, next_z_ptr as u32).unwrap().into_u256();
        let lhs = load_from_proof(raw_proof, (lsb16(&z_j)) as u32)
            .unwrap()
            .into_fr();
        let rhs = load_from_proof(raw_proof, (lsb16(&(z >> 32))) as u32)
            .unwrap()
            .into_fr();
        quotient_eval_numer = quotient_eval_numer * y + l_0 * (lhs - rhs);

        col_evals(
            memory,
            raw_proof,
            z,
            num_words,
            permutation_z_evals_ptr,
            theta_mptr,
        );
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
    );

    // iterate through col_evals to update the quotient_eval_numer accumulator
    let fmp = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to load fmp from memory at this point."),
    ); // free memory pointer
    let temp = fmp + 0x20;
    let end_ptr = u32_from_be_tail(&mload(memory, temp).unwrap()) as usize;
    let start = fmp as usize + 0x40;
    for j in (start..end_ptr).step_by(0x20) {
        quotient_eval_numer = quotient_eval_numer * y + mload(memory, j as u32).unwrap().into_fr();
    }

    quotient_eval_numer
}

fn col_evals(
    memory: &mut [u8],
    raw_proof: &[u8],
    mut z: U256,
    num_words: usize,
    permutation_z_evals_ptr: usize,
    theta_mptr: usize,
) -> Result<(), VerifyError> {
    let gamma = mload(memory, theta_mptr as u32 + 0x40)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load gamma from memory. Cause: {e}"),
        })?
        .into_fr();
    let beta = mload(memory, theta_mptr as u32 + 0x20)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load beta from memory. Cause: {e}"),
        })?
        .into_fr();
    let l_last = mload(memory, theta_mptr as u32 + 0x1c0)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load l_last from memory. Cause: {e}"),
        })?
        .into_fr();
    let l_blind = mload(memory, theta_mptr as u32 + 0x1e0)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load l_blind from memory. Cause: {e}"),
        })?
        .into_fr();
    let i_eval = mload(memory, theta_mptr as u32 + 0x220)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load i_eval from memory. Cause: {e}"),
        })?
        .into_fr();

    // free memory pointer
    let fmp = u32_from_be_tail(
        &mload(memory, 0x40).expect("At this point, loading the fmp should succeed."),
    );

    // Extract the index 1 and index 0 z evaluations from the z word.
    let mut lhs = load_from_proof(raw_proof, (lsb16(&(z >> 16))) as u32)
        .map_err(|e| VerifyError::InvalidProofError {
            message: format!("Unable to load lhs from proof. Cause: {e}"),
        })?
        .into_fr();
    let mut rhs = load_from_proof(raw_proof, (lsb16(&z)) as u32)
        .map_err(|e| VerifyError::InvalidProofError {
            message: format!("Unable to load rhs from proof. Cause: {e}"),
        })?
        .into_fr();

    z >>= 48;
    // loop through the word_len_chunk
    for j in (0..num_words).step_by(0x20) {
        while !z.is_zero() {
            let mut eval = i_eval;

            if lsb8(&z) == 0x00 {
                eval = load_from_proof(raw_proof, (lsb16(&(z >> 8))) as u32)
                    .map_err(|e| VerifyError::InvalidProofError {
                        message: format!("Unable to load scalar from proof, in order to initialize eval. Cause: {e}"),
                    })?
                    .into_fr();
            }

            lhs *= eval
                + beta
                    * load_from_proof(raw_proof, (lsb16(&(z >> 24))) as u32)
                        .unwrap()
                        .into_fr()
                + gamma;
            rhs *= eval + mload(memory, fmp).unwrap().into_fr() + gamma;

            z >>= 40;

            // mstore(mload(0x40), mulmod(mload(mload(0x40)), DELTA, R))
            let idx = fmp as usize;
            let val = DELTA * mload(memory, fmp).unwrap().into_fr();
            memory[idx..idx + 0x20].copy_from_slice(&val.into_be_bytes32());
        }
        z = mload(memory, (permutation_z_evals_ptr + j + 0x20) as u32)
            .map_err(|e| VerifyError::InvalidProofError {
                message: format!("Unable to load z from memory. Cause: {e}"),
            })?
            .into_u256();
    }
    let left_sub_right = lhs - rhs;

    let fsm_ptr = u32_from_be_tail(&mload(memory, fmp + 0x20).unwrap()) as usize;

    let val = left_sub_right - left_sub_right * (l_last + l_blind);
    memory[fsm_ptr..fsm_ptr + 0x20].copy_from_slice(&val.into_be_bytes32());

    let idx = fmp as usize + 0x20;
    memory[idx..idx + 0x20].copy_from_slice(&(fsm_ptr + 0x20).into_u256().into_be_bytes32());

    Ok(())
}

// TODO: Re-assess types of ret0, ret1, ret2; also for expression_evals_packed
fn lookup_expr_evals_packed(
    memory: &mut [u8],
    raw_proof: &[u8],
    fsmp: u32,
    code_ptr: u32,
    expressions_word: U256,
    mv: bool,
) -> Result<(usize, U256, Fr), ()> {
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
                let fmp = u32_from_be_tail(&mload(memory, 0x40).unwrap());
                // add the beta accum addmod if mv lookup
                ret2 += mload(memory, fmp + 0x80).unwrap().into_fr();
            }

            Ok((ret0, ret1, ret2))
        }
        _ => Err(()), // TODO: PROPER ERROR HANDLING...
    }
}

fn mv_lookup_evals(
    memory: &mut [u8],
    raw_proof: &[u8],
    mut table: Fr,
    mut evals_ptr: usize,
    mut quotient_eval_numer: Fr,
    y: Fr,
) -> Result<(usize, Fr, Fr), ()> {
    // load the free memory pointer
    let fmp =
        u32_from_be_tail(&mload(memory, 0x40).expect("Should be able to load fmp at this point."));
    // iterate through the input_tables_len
    let mut evals = mload(memory, evals_ptr as u32).unwrap().into_u256();
    // We store a boolean flag in the first LSG byte of the evals ptr to determine if we need to load in a new table or reuse the previous table.
    let new_table = lsb8(&evals);
    evals >>= 8;
    let phi = lsb16(&evals);

    let tmp1 = mload(memory, 0x20 + fmp).unwrap().into_fr();
    let tmp2 = load_from_proof(raw_proof, phi as u32).unwrap().into_fr();
    quotient_eval_numer = quotient_eval_numer * y + tmp1 * tmp2;

    let tmp1 = mload(memory, fmp).unwrap().into_fr();
    quotient_eval_numer = quotient_eval_numer * y + tmp1 * tmp2;

    // load in the lookup_table_lines from the evals_ptr
    evals_ptr += 0x20;
    // Due to the fact that lookups can share the previous table, we can cache it for reuse.
    let mut input_expression = mload(memory, evals_ptr as u32).unwrap().into_u256();
    if new_table != 0 {
        (evals_ptr, input_expression, table) = lookup_expr_evals_packed(
            memory,
            raw_proof,
            0xa0 + fmp,
            evals_ptr as u32,
            mload(memory, evals_ptr as u32).unwrap().into_u256(),
            true,
        )?; // TODO: Error handling...
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
        )?; // TODO: Error handling...
        // store ident in free static memory
        // mstore(j, ident)
        memory[j..j + 0x20].copy_from_slice(&ident.into_be_bytes32());
    }
    let lhs;
    let mut rhs = Fr::ZERO;

    if outer_inputs_len == 0x20 {
        rhs = table;
    } else {
        // iterate through the outer_inputs_len
        let last_idx = outer_inputs_len - 0x20;
        for i in (0..outer_inputs_len).step_by(0x20) {
            let mut tmp = mload(memory, 0xa0 + fmp).unwrap().into_fr();
            let mut j = 0x20;
            if i == 0 {
                tmp = mload(memory, 0xc0 + fmp).unwrap().into_fr();
                j = 0x40;
            }
            while j < outer_inputs_len {
                if i == j {
                    continue;
                }
                tmp *= mload(memory, j as u32 + 0xa0 + fmp).unwrap().into_fr();
                j += 0x20;
            }
            rhs += tmp;
            if i == last_idx {
                rhs *= table;
            }
        }
    }

    let mut tmp = mload(memory, 0xa0 + fmp).unwrap().into_fr();
    for j in (0x20..outer_inputs_len).step_by(0x20) {
        tmp *= mload(memory, j as u32 + 0xa0 + fmp).unwrap().into_fr();
    }
    rhs = rhs
        - load_from_proof(raw_proof, (lsb16(&(evals >> 32))) as u32)
            .unwrap()
            .into_fr()
            * tmp;
    lhs = table
        * tmp
        * (load_from_proof(raw_proof, (lsb16(&(evals >> 16))) as u32)
            .unwrap()
            .into_fr()
            - load_from_proof(raw_proof, phi as u32).unwrap().into_fr());
    quotient_eval_numer = quotient_eval_numer * y
        + (Fr::ONE
            - (mload(memory, 0x40 + fmp).unwrap().into_fr()
                + mload(memory, fmp).unwrap().into_fr()))
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
) -> Result<(usize, Fr, Fr), ()> {
    // load the free memory pointer
    let fmp = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to load fmp from memory at this point."),
    );
    // iterate through the input_tables_len
    let mut evals = mload(memory, evals_ptr as u32).unwrap().into_u256();
    // We store a boolean flag in the first LSG byte of the evals ptr to determine if we need to load in a new table or reuse the previous table.
    let new_table = lsb8(&evals);
    evals >>= 8;
    let z = lsb16(&evals) as u32;
    evals >>= 16;
    quotient_eval_numer = quotient_eval_numer * y
        + mload(memory, 0x20 + fmp).unwrap().into_fr()
        + mload(memory, 0x20 + fmp).unwrap().into_fr()
            * load_from_proof(raw_proof, z)
                .unwrap()
                .into_fr()
                .neg_in_place();

    quotient_eval_numer = quotient_eval_numer * y
        + mload(memory, fmp).unwrap().into_fr()
            * load_from_proof(raw_proof, z).unwrap().into_fr()
            * load_from_proof(raw_proof, z).unwrap().into_fr()
        + load_from_proof(raw_proof, z)
            .unwrap()
            .into_fr()
            .neg_in_place();

    // load in the lookup_table_lines from the evals_ptr
    evals_ptr += 0x20;
    // Due to the fact that lookups can share the previous table, we can cache it for reuse.
    let mut input_expression = mload(memory, evals_ptr as u32).unwrap().into_u256();
    if new_table != 0 {
        (evals_ptr, input_expression, table) = lookup_expr_evals_packed(
            memory,
            raw_proof,
            0xc0 + fmp,
            evals_ptr as u32,
            mload(memory, evals_ptr as u32).unwrap().into_u256(),
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
            - (mload(memory, 0x40 + fmp).unwrap().into_fr()
                + mload(memory, fmp).unwrap().into_fr()))
            * (load_from_proof(raw_proof, lsb16(&evals) as u32)
                .unwrap()
                .into_fr()
                * (load_from_proof(raw_proof, p_input as u32)
                    .unwrap()
                    .into_fr()
                    + mload(memory, 0x80 + fmp).unwrap().into_fr())
                * (load_from_proof(raw_proof, p_table as u32)
                    .unwrap()
                    .into_fr()
                    + mload(memory, 0xa0 + fmp).unwrap().into_fr())
                - load_from_proof(raw_proof, z).unwrap().into_fr()
                    * (input + mload(memory, 0x80 + fmp).unwrap().into_fr())
                    * (table + mload(memory, 0xa0 + fmp).unwrap().into_fr()));

    quotient_eval_numer = quotient_eval_numer * y
        + (mload(memory, 0x20 + fmp).unwrap().into_fr()
            * (load_from_proof(raw_proof, p_input as u32)
                .unwrap()
                .into_fr()
                - load_from_proof(raw_proof, p_table as u32)
                    .unwrap()
                    .into_fr()));

    quotient_eval_numer = quotient_eval_numer * y
        + (Fr::ONE
            - (mload(memory, 0x40 + fmp).unwrap().into_fr()
                + mload(memory, fmp).unwrap().into_fr()))
            * (load_from_proof(raw_proof, p_input as u32)
                .unwrap()
                .into_fr()
                - load_from_proof(raw_proof, p_table as u32)
                    .unwrap()
                    .into_fr())
            * (load_from_proof(raw_proof, p_input as u32)
                .unwrap()
                .into_fr()
                - load_from_proof(raw_proof, lsb16(&(evals >> 32)) as u32)
                    .unwrap()
                    .into_fr());

    Ok((evals_ptr, table, quotient_eval_numer))
}

// TODO: DO PROPER ERROR HANDLING...
fn point_rots(
    memory: &mut [u8],
    mut pcs_computations: U256,
    mut pcs_ptr: usize,
    mut word_shift: u32,
    mut x_pow_of_omega: Fr,
    omega: Fr,
    vka_end: usize,
) -> Result<(Fr, usize), ()> {
    // Extract the 32 LSG bits (4 bytes) from the pcs_computations word to get the max rot
    let values_max_rot = lsb8(&pcs_computations);
    pcs_computations >>= 8;
    for i in 0..values_max_rot {
        let value = lsb16(&pcs_computations);
        if value != 0 {
            // mstore(add(vka_end, value), x_pow_of_omega)
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
            pcs_computations = mload(memory, pcs_ptr as u32).unwrap().into_u256();
        }
    }

    Ok((x_pow_of_omega, pcs_ptr))
}

// Scale point at (0x00, 0x20) by scalar.
fn ec_mul_acc<H: CurveHooks>(memory: &mut [u8], scalar: &Fr) -> Result<(), ()> {
    let vka_end = u32_from_be_tail(&mload(memory, 0x40).unwrap());

    let point = read_g1::<H>(&memory, vka_end as usize)
        .unwrap()
        .into_group();

    let res = (point * scalar).into_affine();

    let vka_end = vka_end as usize;
    memory[vka_end..vka_end + 0x20]
        .copy_from_slice(&res.x().expect("Should succeed").into_be_bytes32());
    memory[(vka_end + 0x20)..(vka_end + 0x40)]
        .copy_from_slice(&res.y().expect("Should succeed").into_be_bytes32());

    Ok(())
}

// Add (x, y) into point at (0x00, 0x20).
// Return updated (success).
fn ec_add_acc<H: CurveHooks>(memory: &mut [u8], x: &Fq, y: &Fq) -> Result<(), ()> {
    let vka_end = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to load vka_end from memory."),
    );

    let point1 = read_g1::<H>(&memory, vka_end as usize)
        .unwrap()
        .into_group();
    let point2 = G1::<H>::new_unchecked(*x, *y);

    // Validate point2
    if !point2.is_on_curve() {
        return Err(());
    }

    let res = (point1 + point2).into_affine();

    let vka_end = vka_end as usize;
    memory[vka_end..vka_end + 0x20]
        .copy_from_slice(&res.x().expect("Should succeed").into_be_bytes32());
    memory[(vka_end + 0x20)..(vka_end + 0x40)]
        .copy_from_slice(&res.y().expect("Should succeed").into_be_bytes32());

    Ok(())
}

// Add (x, y) into point at (0x80, 0xa0).
// Return updated (success).
fn ec_add_tmp<H: CurveHooks>(memory: &mut [u8], x: &Fq, y: &Fq) -> Result<(), ()> {
    let vka_end = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to load vka_end from memory."),
    );

    let point1 = read_g1::<H>(&memory, vka_end as usize + 0x80)
        .unwrap()
        .into_group();
    let point2 = G1::<H>::new_unchecked(*x, *y);

    // Validate point2
    if !point2.is_on_curve() {
        return Err(());
    }

    let res = (point1 + point2).into_affine();

    let vka_end = vka_end as usize;
    memory[(vka_end + 0x80)..(vka_end + 0xa0)]
        .copy_from_slice(&res.x().expect("Should succeed").into_be_bytes32());
    memory[(vka_end + 0xa0)..(vka_end + 0xc0)]
        .copy_from_slice(&res.y().expect("Should succeed").into_be_bytes32());

    Ok(())
}

// Scale point at (0x80, 0xa0) by scalar.
// Return updated (success).
fn ec_mul_tmp<H: CurveHooks>(memory: &mut [u8], scalar: &Fr) -> Result<(), ()> {
    let vka_end = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to load vka_end from memory."),
    );

    let point = read_g1::<H>(&memory, (vka_end + 0x80) as usize)
        .unwrap()
        .into_group();

    let res = (point * scalar).into_affine();
    let vka_end = vka_end as usize;
    memory[(vka_end + 0x80)..(vka_end + 0xa0)]
        .copy_from_slice(&res.x().expect("Should succeed").into_be_bytes32());
    memory[(vka_end + 0xa0)..(vka_end + 0xc0)]
        .copy_from_slice(&res.y().expect("Should succeed").into_be_bytes32());

    Ok(())
}

fn coeff_computations(memory: &mut [u8], coeff_len_data: U256, coeff_data: U256) -> U256 {
    let coeff_len = lsb8(&coeff_len_data);
    let ret = coeff_len_data >> 8;

    let fmp = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to load vka_end from memory."),
    );
    match coeff_len {
        0x01 => {
            // We only encode the points if the coeff length is greater than 1.
            // Otherwise, we just encode the mu_minus_point and coeff ptr.
            // mstore(add(and(shr(16, coeff_data), PTR_BITMASK), mload(0x40)), mod(mload(add(and(coeff_data, PTR_BITMASK), mload(0x40))), R))
            let idx = lsb16(&(coeff_data >> 16)) + fmp as usize;
            let val = mload(memory, lsb16(&coeff_data) as u32 + fmp)
                .unwrap()
                .into_fr();
            memory[idx..idx + 0x20].copy_from_slice(&val.into_be_bytes32());
        }
        _ => {
            let mut coeff = Fr::ONE;
            let offset_aggr = coeff_len * 16;
            for i in 0..coeff_len {
                let mut first: usize = 0x01;
                let mut offset_base = i as u32 * 16;
                let idx = lsb16(&(coeff_data >> offset_base)) as u32 + fmp;
                let point_i = mload(memory, idx).unwrap().into_fr();
                for j in 0..coeff_len {
                    if j == i {
                        continue;
                    }
                    if first != 0 {
                        coeff = point_i
                            - mload(memory, lsb16(&(coeff_data >> (16 * j as u32))) as u32 + fmp)
                                .unwrap()
                                .into_fr();
                        first = 0;
                        continue;
                    }
                    coeff *= point_i
                        - mload(memory, lsb16(&(coeff_data >> (16 * j as u32))) as u32 + fmp)
                            .unwrap()
                            .into_fr();
                }
                offset_base += offset_aggr as u32;
                coeff *= mload(memory, lsb16(&(coeff_data >> offset_base)) as u32 + fmp)
                    .unwrap()
                    .into_fr();
                offset_base += offset_aggr as u32;
                let idx = lsb16(&(coeff_data >> offset_base)) + fmp as usize;
                memory[idx..idx + 0x20].copy_from_slice(&coeff.into_be_bytes32());
            }
        }
    }
    ret
}

// TODO: DO PROPER ERROR HANDLING...
fn r_evals_computation(
    memory: &mut [u8],
    raw_proof: &[u8],
    rot_len: u32,
    r_evals_data_ptr: u32,
    zeta: Fr,
    quotient_eval: Fr,
    coeff_ptr: u32,
) -> Result<(Fr, usize), String> {
    let mut r_evals_data = mload(memory, r_evals_data_ptr)
        .map_err(|e| format!("r_evals_computation failed. Cause: {}", e))?
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
            )
            .map_err(|e| format!("r_evals_computation failed. Cause: {}", e))?;
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
            )
            .map_err(|e| format!("r_evals_computation failed. Cause: {}", e))?;
            Ok((ret0, ret1))
        }
    }
}

fn single_rot_set(
    memory: &mut [u8],
    raw_proof: &[u8],
    mut r_evals_data: U256,
    mut ptr: u32,
    num_words: u32,
    zeta: Fr,
    quotient_eval: Fr,
    coeff_ptr: u32,
) -> Result<(Fr, usize), String> {
    let coeff = mload(memory, coeff_ptr)
        .map_err(|e| format!("single_rot_set failed. Cause: {}", e))?
        .into_fr();
    let mut r_eval = Fr::ZERO;
    r_eval += coeff
        * load_from_proof(raw_proof, lsb16(&r_evals_data) as u32)
            .map_err(|e| format!("single_rot_set failed. Cause: {}", e))?
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
                            * load_from_proof(raw_proof, (lsb16(&r_evals_data)) as u32)
                                .map_err(|e| format!("single_rot_set failed. Cause: {}", e))?
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
                            * load_from_proof(raw_proof, mptr as u32)
                                .map_err(|e| format!("single_rot_set failed. Cause: {}", e))?
                                .into_fr();
                    mptr -= 0x20;
                }
                r_evals_data >>= 16;
            }
        }
        ptr += 0x20;
        r_evals_data = mload(memory, ptr)
            .map_err(|e| format!("single_rot_set failed. Cause: {}", e))?
            .into_u256();
    }

    Ok((r_eval, ptr as usize))
}

fn multi_rot_set(
    memory: &mut [u8],
    raw_proof: &[u8],
    mut r_evals_data: U256,
    mut ptr: u32,
    num_words: u32,
    rot_len: u32,
    zeta: Fr,
    coeff_ptr: u32,
) -> Result<(Fr, usize), String> {
    let mut r_eval = Fr::ZERO;
    for i in 0..num_words {
        while !r_evals_data.is_zero() {
            for j in (0..rot_len).step_by(0x20) {
                r_eval += mload(memory, coeff_ptr + j)
                    .map_err(|e| format!("multi_rot_set failed. Cause: {}", e))?
                    .into_fr()
                    * load_from_proof(raw_proof, lsb16(&r_evals_data) as u32)
                        .map_err(|e| format!("multi_rot_set failed. Cause: {}", e))?
                        .into_fr();
                r_evals_data >>= 16;
            }
            // Only on the last index do we NOT execute this if block.
            if !r_evals_data.is_zero() || i < num_words - 1 {
                r_eval *= zeta;
            }
        }
        ptr += 0x20;
        r_evals_data = mload(memory, ptr)
            .map_err(|e| format!("multi_rot_set failed. Cause: {}", e))?
            .into_u256();
    }

    Ok((r_eval, ptr as usize))
}

fn pairing_input_computations_first<H: CurveHooks>(
    memory: &mut [u8],
    raw_proof: &[u8],
    len: u32,
    mut pcs_ptr: u32,
    mut data: U256,
    theta_mptr: u32,
) -> Result<(), ()> {
    let fmp = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to read fmp from memory at this point."),
    );
    // mstore(mload(0x40), calldataload(and(data, PTR_BITMASK)))
    let idx = fmp as usize;
    let bytes = load_from_proof(raw_proof, lsb16(&data) as u32).unwrap();
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    data >>= 16;
    // mstore(add(0x20, mload(0x40)), calldataload(and(data, PTR_BITMASK)))
    let idx = 0x20 + fmp as usize;
    let bytes = load_from_proof(raw_proof, lsb16(&data) as u32).unwrap();
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
                            let mut mptr = lsb16(&data);
                            data >>= 16;
                            let mptr_end = lsb16(&data);
                            while mptr_end < mptr {
                                let s = mload(memory, theta_mptr + 0xa0).unwrap().into_fr();
                                ec_mul_acc::<H>(memory, &s)?;
                                let x = Fq::from_be_bytes_mod_order(
                                    &mload(memory, mptr as u32).unwrap(),
                                );
                                let y = Fq::from_be_bytes_mod_order(
                                    &mload(memory, mptr as u32 + 0x20).unwrap(),
                                );
                                ec_add_acc::<H>(memory, &x, &y)?;
                                mptr -= 0x40;
                            }
                        }
                        0x1 => {
                            let mut mptr = lsb16(&data);
                            data >>= 16;
                            let mptr_end = lsb16(&data);
                            while mptr_end < mptr {
                                let s = mload(memory, theta_mptr + 0xa0).unwrap().into_fr();
                                ec_mul_acc::<H>(memory, &s)?;
                                let x = Fq::from_be_bytes_mod_order(
                                    &load_from_proof(raw_proof, mptr as u32).unwrap(),
                                );
                                let y = Fq::from_be_bytes_mod_order(
                                    &load_from_proof(raw_proof, (mptr + 0x20) as u32).unwrap(),
                                );
                                ec_add_acc::<H>(memory, &x, &y)?;
                                mptr -= 0x40;
                            }
                        }
                        _ => {
                            return Err(());
                        } // TODO: Proper error handling
                    };
                    data >>= 16;
                }
                _ => {
                    match ptr_loc {
                        0x00 => {
                            let s = mload(memory, theta_mptr + 0xa0).unwrap().into_fr();
                            ec_mul_acc::<H>(memory, &s)?;
                            let x = Fq::from_be_bytes_mod_order(
                                &mload(memory, lsb16(&data) as u32).unwrap(),
                            );
                            let y = Fq::from_be_bytes_mod_order(
                                &mload(memory, lsb16(&(data >> 16)) as u32).unwrap(),
                            );
                            ec_add_acc::<H>(memory, &x, &y)?;
                            if comm_len == 0x02 {
                                data >>= 32;
                                let s = mload(memory, theta_mptr + 0xa0).unwrap().into_fr();
                                ec_mul_acc::<H>(memory, &s)?;
                                let x = Fq::from_be_bytes_mod_order(
                                    &mload(memory, lsb16(&data) as u32).unwrap(),
                                );
                                let y = Fq::from_be_bytes_mod_order(
                                    &mload(memory, lsb16(&(data >> 16)) as u32).unwrap(),
                                );
                                ec_add_acc::<H>(memory, &x, &y)?;
                            }
                            data >>= 32;
                        }
                        0x01 => {
                            let s = mload(memory, theta_mptr + 0xa0).unwrap().into_fr();
                            ec_mul_acc::<H>(memory, &s)?;
                            let x = Fq::from_be_bytes_mod_order(
                                &load_from_proof(raw_proof, lsb16(&data) as u32).unwrap(),
                            );
                            let y = Fq::from_be_bytes_mod_order(
                                &load_from_proof(raw_proof, lsb16(&(data >> 16)) as u32).unwrap(),
                            );
                            ec_add_acc::<H>(memory, &x, &y)?;
                            if comm_len == 0x02 {
                                data >>= 32;
                                let s = mload(memory, theta_mptr + 0xa0).unwrap().into_fr();
                                ec_mul_acc::<H>(memory, &s)?;
                                let x = Fq::from_be_bytes_mod_order(
                                    &load_from_proof(raw_proof, lsb16(&data) as u32).unwrap(),
                                );
                                let y = Fq::from_be_bytes_mod_order(
                                    &load_from_proof(raw_proof, lsb16(&(data >> 16)) as u32)
                                        .unwrap(),
                                );
                                ec_add_acc::<H>(memory, &x, &y)?;
                            }
                            data >>= 32;
                        }
                        // Quotient eval x and y points
                        0x02 => {
                            let s = mload(memory, theta_mptr + 0xa0).unwrap().into_fr();

                            ec_mul_acc::<H>(memory, &s)?;

                            let x = Fq::from_be_bytes_mod_order(
                                &mload(memory, theta_mptr + 0x260).unwrap(),
                            );
                            let y = Fq::from_be_bytes_mod_order(
                                &mload(memory, theta_mptr + 0x280).unwrap(),
                            );
                            ec_add_acc::<H>(memory, &x, &y)?;
                        }
                        _ => {
                            return Err(());
                        } // TODO: Proper error handling
                    }
                }
            }
        }
        pcs_ptr += 0x20;
        data = mload(memory, pcs_ptr).unwrap().into_u256();
    }
    Ok(())
}

fn pairing_input_computations<H: CurveHooks>(
    memory: &mut [u8],
    raw_proof: &[u8],
    len: u32,
    mut pcs_ptr: u32,
    mut data: U256,
    theta_mptr: u32,
) -> Result<(), ()> {
    let fmp = u32_from_be_tail(
        &mload(memory, 0x40).expect("Should be able to read fmp from memory at this point."),
    );
    // mstore(add(0x80, mload(0x40)), calldataload(and(data, PTR_BITMASK)))
    let idx = 0x80 + fmp as usize;
    let bytes = load_from_proof(raw_proof, lsb16(&data) as u32).unwrap();
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    data >>= 16;
    // mstore(add(0xa0, mload(0x40)), calldataload(and(data, PTR_BITMASK)))
    let idx = 0xa0 + fmp as usize;
    let bytes = load_from_proof(raw_proof, lsb16(&data) as u32).unwrap();
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
                            let mut mptr = lsb16(&data);
                            data >>= 16;
                            let mptr_end = lsb16(&data);
                            while mptr_end < mptr {
                                let s = mload(memory, theta_mptr + 0xA0).unwrap().into_fr();
                                ec_mul_tmp::<H>(memory, &s);
                                let x = Fq::from_be_bytes_mod_order(
                                    &mload(memory, mptr as u32).unwrap(),
                                );
                                let y = Fq::from_be_bytes_mod_order(
                                    &mload(memory, mptr as u32 + 0x20).unwrap(),
                                );
                                ec_add_tmp::<H>(memory, &x, &y);
                                mptr -= 0x40;
                            }
                        }
                        0x01 => {
                            let mut mptr = lsb16(&data);
                            data >>= 16;
                            let mptr_end = lsb16(&data);
                            while mptr_end < mptr {
                                let s = mload(memory, theta_mptr + 0xa0).unwrap().into_fr();
                                ec_mul_tmp::<H>(memory, &s);
                                let x = Fq::from_be_bytes_mod_order(
                                    &load_from_proof(raw_proof, mptr as u32).unwrap(),
                                );
                                let y = Fq::from_be_bytes_mod_order(
                                    &load_from_proof(raw_proof, mptr as u32 + 0x20).unwrap(),
                                );
                                ec_add_tmp::<H>(memory, &x, &y);
                                mptr -= 0x40;
                            }
                        }
                        _ => {
                            return Err(());
                        } // TODO: Proper error handling
                    }
                    data >>= 16;
                }
                _ => {
                    match ptr_loc {
                        0x00 => {
                            let s = mload(memory, theta_mptr + 0xa0).unwrap().into_fr();
                            ec_mul_tmp::<H>(memory, &s);
                            let x = Fq::from_be_bytes_mod_order(
                                &mload(memory, lsb16(&data) as u32).unwrap(),
                            );
                            let y = Fq::from_be_bytes_mod_order(
                                &mload(memory, lsb16(&(data >> 16)) as u32).unwrap(),
                            );
                            ec_add_tmp::<H>(memory, &x, &y);
                            if comm_len == 0x2 {
                                data >>= 32;
                                let s = mload(memory, theta_mptr + 0xa0).unwrap().into_fr();
                                ec_mul_tmp::<H>(memory, &s);
                                let x = Fq::from_be_bytes_mod_order(
                                    &mload(memory, lsb16(&data) as u32).unwrap(),
                                );
                                let y = Fq::from_be_bytes_mod_order(
                                    &mload(memory, lsb16(&(data >> 16)) as u32).unwrap(),
                                );
                                ec_add_tmp::<H>(memory, &x, &y);
                            }
                            data >>= 32;
                        }
                        0x01 => {
                            let s = mload(memory, theta_mptr + 0xa0).unwrap().into_fr();
                            ec_mul_tmp::<H>(memory, &s);
                            let x = Fq::from_be_bytes_mod_order(
                                &load_from_proof(raw_proof, lsb16(&data) as u32).unwrap(),
                            );
                            let y = Fq::from_be_bytes_mod_order(
                                &load_from_proof(raw_proof, lsb16(&(data >> 16)) as u32).unwrap(),
                            );
                            ec_add_tmp::<H>(memory, &x, &y);
                            if comm_len == 0x2 {
                                data >>= 32;
                                let s = mload(memory, theta_mptr + 0xa0).unwrap().into_fr();
                                ec_mul_tmp::<H>(memory, &s);
                                let x = Fq::from_be_bytes_mod_order(
                                    &load_from_proof(raw_proof, lsb16(&data) as u32).unwrap(),
                                );
                                let y = Fq::from_be_bytes_mod_order(
                                    &load_from_proof(raw_proof, lsb16(&(data >> 16)) as u32)
                                        .unwrap(),
                                );
                                ec_add_tmp::<H>(memory, &x, &y);
                            }
                            data >>= 32;
                        }
                        // Quotient eval x and y points
                        0x02 => {
                            let s = mload(memory, theta_mptr + 0xa0).unwrap().into_fr();
                            ec_mul_tmp::<H>(memory, &s);
                            let x = Fq::from_be_bytes_mod_order(
                                &mload(memory, theta_mptr + 0x260).unwrap(),
                            );
                            let y = Fq::from_be_bytes_mod_order(
                                &mload(memory, theta_mptr + 0x280).unwrap(),
                            );
                            ec_add_tmp::<H>(memory, &x, &y);
                        }
                        _ => {
                            return Err(());
                        } // TODO: Proper error handling
                    }
                }
            }
        }
        pcs_ptr += 0x20;
        data = mload(memory, pcs_ptr).unwrap().into_u256();
    }
    Ok(())
}

// Utility function for batch-inverting a chunk of `Fr` elements in memory.
fn batch_invert_in_memory(memory: &mut [u8], start: u32, end: u32) -> Result<(), String> {
    // TODO: Error handling...
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

    let mut inverses = (start..end)
        .step_by(0x20)
        .map(|p| {
            mload(memory, p as u32)
                .unwrap()
                // .map_err(|e| {
                //     format!("batch_invert_in_memory could not parse scalar from memory. Cause: {e}")
                // })?
                .into_fr()
        })
        .collect::<Vec<_>>();
    batch_inversion(&mut inverses);

    let start = start as usize;
    for i in 0..inverses.len() {
        memory[(start + i * 0x20)..start + (i + 1) * 0x20]
            .copy_from_slice(&inverses[i].into_be_bytes32()); // TODO: THIS CAN FAIL... (IndexOutOfBounds)
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

    let x = mload(memory, theta_mptr as u32 + 0x80)
        .map_err(|e| VerifyError::KeyError {
            message: format!(
                "Failed reading x from memory at address 0x{:x?}. Cause: {e}",
                theta_mptr as u32 + 0x80
            ),
        })?
        .into_fr();

    let mut x_n = x;
    for _ in 0..k {
        x_n = x_n.square();
    }

    // Prepare denominators for Lagrange evaluation
    let omega = mload(memory, (VKA_OFFSET + 0x00e0 + MEMORY_OFFSET) as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!(
                "Failed reading omega from memory at address 0x{:x?}. Cause: {e}",
                (VKA_OFFSET + 0x00e0 + MEMORY_OFFSET) as u32
            ),
        })?
        .into_fr();

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

    let mut pow_of_omega = mload(memory, (VKA_OFFSET + 0x0120 + MEMORY_OFFSET) as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Failed reading omega_inv_to_l from memory. Cause: {e}"),
        })?
        .into_fr();

    while mptr_end >= memory.len() {
        memory.extend_from_slice(&[0u8; 32]);
    }

    while mptr < mptr_end {
        memory[mptr..mptr + 32].copy_from_slice(&(x - pow_of_omega).into_be_bytes32()); // mstore(mptr, addmod(x, sub(R, pow_of_omega),R))
        pow_of_omega = pow_of_omega * omega;
        mptr += 0x20;
    }

    let x_n_minus_1 = x_n - Fr::ONE;
    memory[mptr_end..mptr_end + 32].copy_from_slice(&x_n_minus_1.into_be_bytes32()); // mstore(mptr_end, x_n_minus_1)

    batch_invert_in_memory(memory, x_n_mptr as u32, mptr_end as u32 + 0x20);

    let l_i_common = x_n_minus_1
        * mload(memory, 0x0160)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Unable to compute l_i_common. Cause: {e}"),
            })?
            .into_fr();
    let mut pow_of_omega = mload(memory, 0x01c0)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read pow_of_omega from VKA. Cause: {e}"),
        })?
        .into_fr();
    for mptr in (x_n_mptr..mptr_end).step_by(0x20) {
        // mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega,R),R))
        let zeta_minus_omega_i_inv = mload(memory, mptr as u32)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Unable to read zeta_minus_omega_i_inv from memory. Cause: {e}"),
            })?
            .into_fr();
        memory[mptr..mptr + 0x20].copy_from_slice(
            &(l_i_common * zeta_minus_omega_i_inv * pow_of_omega).into_be_bytes32(),
        );
        pow_of_omega *= omega;
    }

    let mut l_blind = mload(memory, x_n_mptr as u32 + 0x20)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to initialize l_blind from memory. Cause: {e}"),
        })?
        .into_fr();
    let l_i_cptr_end = x_n_mptr + 0x20 * num_neg_lagranges as usize;
    let mut l_i_cptr = x_n_mptr + 0x40;

    while l_i_cptr < l_i_cptr_end {
        l_blind += mload(memory, l_i_cptr as u32)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Failed to read from memory while updating l_blind. Cause: {e}"),
            })?
            .into_fr();
        l_i_cptr += 0x20;
    }

    let mut instance_eval = Fr::ZERO;
    for instance in pubs {
        instance_eval += mload(memory, l_i_cptr as u32)
            .map_err(|e| VerifyError::KeyError {
                message: format!(
                    "Failed to read from memory while updating instance_eval. Cause: {e}"
                ),
            })?
            .into_fr()
            * instance.into_fr();
        l_i_cptr += 0x20;
    }

    let x_n_minus_1_inv = mload(memory, mptr_end as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Failed to read x_n_minus_1_inv from memory. Cause: {e}"),
        })?
        .into_fr();
    let l_last = mload(memory, x_n_mptr as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Failed to read l_last from memory. Cause: {e}"),
        })?
        .into_fr();
    let l_0 = mload(memory, x_n_mptr as u32 + 0x20 * num_neg_lagranges)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Failed to read l_0 from memory. Cause: {e}"),
        })?
        .into_fr();

    // mstore(x_n_mptr, x_n)
    memory[x_n_mptr..x_n_mptr + 0x20].copy_from_slice(&x_n.into_be_bytes32());
    // mstore(add(theta_mptr, 0x1a0), x_n_minus_1_inv)
    let mut start = theta_mptr + 0x1a0;
    memory[start..start + 0x20].copy_from_slice(&x_n_minus_1_inv.into_be_bytes32());
    // mstore(add(theta_mptr, 0x1c0), l_last)
    start += 0x20;
    memory[start..start + 0x20].copy_from_slice(&l_last.into_be_bytes32());
    // mstore(add(theta_mptr, 0x1e0), l_blind)
    start += 0x20;
    memory[start..start + 0x20].copy_from_slice(&l_blind.into_be_bytes32());
    // mstore(add(theta_mptr, 0x200), l_0)
    start += 0x20;
    memory[start..start + 0x20].copy_from_slice(&l_0.into_be_bytes32());
    // mstore(add(theta_mptr, 0x220), instance_eval)
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

    let mut expressions_word = mload(memory, computations_ptr as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Failed to read expressions_word from memory. Cause: {e}"),
        })?
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
        match code_block {
            0 => {
                quotient_eval_numer = mload(memory, (vka_end + last_idx) as u32)
                    .map_err(|e| VerifyError::KeyError {
                        message: format!(
                            "Unable to read quotient_eval_numer from memory. Cause: {e:?}"
                        ),
                    })?
                    .into_fr()
            }
            1 => {
                // Otherwise we add the last var in the code block to `quotient_eval_numer` mod r
                quotient_eval_numer = quotient_eval_numer * y
                    + mload(memory, (vka_end + last_idx) as u32)
                        .map_err(|e| VerifyError::KeyError {
                            message: format!("Failed to compute quotient_eval_numer. Cause: {e:?}"),
                        })?
                        .into_fr();
            }
            _ => {
                // Invalid code_block value
                return Err(VerifyError::InvalidProofError {
                    message: format!("Invalid code_block value {code_block}"),
                });
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

    let mut permutation_z_evals = mload(memory, permutation_z_evals_ptr)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read permutation_z_evals from memory. Cause: {e}"),
        })?
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
    permutation_z_evals = mload(memory, permutation_z_evals_ptr)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read permutation_z_evals from memory. Cause: {e}"),
        })?
        .into_u256();
    let l_0 = mload(memory, theta_mptr as u32 + 0x200)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read l_0 from memory. Cause: {e}"),
        })?
        .into_fr();

    {
        // Get the first and second LSG bytes from the first permutation_z_evals word to load in (z, _, _)
        let idx = lsb16(&permutation_z_evals) as u32;
        let eval = l_0
            - l_0
                * load_from_proof(raw_proof, idx)
                    .map_err(|e| VerifyError::InvalidProofError {
                        message: format!(
                            "Unable to update eval during permutation computations. Cause: {e}"
                        ),
                    })?
                    .into_fr();
        quotient_eval_numer = quotient_eval_numer * y + eval;
    }

    {
        // Load in the last permutation_z_evals word
        let perm_z_last_ptr =
            last_idx * (num_words & PTR_BITMASK as usize) + permutation_z_evals_ptr as usize;

        let idx = lsb16(
            &mload(memory, perm_z_last_ptr as u32)
                .map_err(|e| VerifyError::KeyError {
                    message: format!(
                        "Unable to read perm_z_last's address from memory. Cause: {e}"
                    ),
                })?
                .into_u256(),
        ) as u32;
        let perm_z_last = load_from_proof(raw_proof, idx)
            .map_err(|e| VerifyError::InvalidProofError {
                message: format!("Unable to load perm_z_last from proof. Cause: {e}"),
            })?
            .into_fr();

        quotient_eval_numer = quotient_eval_numer * y
            + mload(memory, theta_mptr as u32 + 0x1C0).map_err(|e| VerifyError::KeyError {
                    message: format!(
                        "Unable to update quotient_eval_numer during permutation computations. Cause: {e}"
                    ),
                })?.into_fr()
                * (perm_z_last * perm_z_last - perm_z_last);

        let lhs = mload(memory, theta_mptr as u32 + 0x20).map_err(|e| VerifyError::KeyError {
                    message: format!(
                        "Unable to load lhs when loading in the last permutation_z_evals word. Cause: {e}"
                    ),
                })?.into_fr();
        let rhs = mload(memory, theta_mptr as u32 + 0x80).map_err(|e| VerifyError::KeyError {
                    message: format!(
                        "Unable to load rhs when loading in the last permutation_z_evals word. Cause: {e}"
                    ),
                })?.into_fr();
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
        );
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
    // mstore(vka_end, mload(add(theta_mptr, 0x1C0)))
    let value = &mload(&memory, theta_mptr as u32 + 0x1c0).map_err(|e| VerifyError::KeyError {
        message: format!("Failed to read l_last from memory. Cause: {e}"),
    })?;
    memory[vka_end..vka_end + 0x20].copy_from_slice(value); // l_last
    // mstore(add(0x20, vka_end), mload(add(theta_mptr, 0x200)))
    let value = &mload(memory, theta_mptr as u32 + 0x200).map_err(|e| VerifyError::KeyError {
        message: format!("Failed to read l_0 from memory. Cause: {e}"),
    })?;
    memory[(vka_end + 0x20)..(vka_end + 0x40)].copy_from_slice(value); // l_0
    // mstore(add(0x40, vka_end), mload(add(theta_mptr, 0x1E0)))
    let value = &mload(memory, 0x1e0).map_err(|e| VerifyError::KeyError {
        message: format!("Failed to read l_blind from memory. Cause: {e}"),
    })?;
    memory[(vka_end + 0x40)..(vka_end + 0x60)].copy_from_slice(value); // l_blind
    // mstore(add(0x60, vka_end), mload(theta_mptr))
    let value = &mload(memory, theta_mptr as u32).map_err(|e| VerifyError::KeyError {
        message: format!("Failed to read theta from memory. Cause: {e}"),
    })?;
    memory[(vka_end + 0x60)..(vka_end + 0x80)].copy_from_slice(value); // theta
    // mstore(add(0x80, vka_end), mload(add(theta_mptr, 0x20)))
    let value = &mload(memory, theta_mptr as u32 + 0x20).map_err(|e| VerifyError::KeyError {
        message: format!("Failed to read beta from memory. Cause: {e}"),
    })?;
    memory[(vka_end + 0x80)..(vka_end + 0xa0)].copy_from_slice(value); // beta
    let (mut evals_ptr, meta_data) =
        soa_layout_metadata(memory, 0x380 + VKA_OFFSET + MEMORY_OFFSET).map_err(|e| {
            VerifyError::KeyError {
                message: format!("{e}"),
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
                    )
                    .unwrap();
                }
            }
            0x1 => {
                // mstore(add(0xA0, vka_end), mload(add(theta_mptr, 0x40)))
                let bytes = mload(memory, theta_mptr as u32 + 0x40).unwrap();
                memory[vka_end..vka_end + 0xa0].copy_from_slice(&bytes); // gamma
                while evals_ptr < end_ptr as usize {
                    (evals_ptr, table, quotient_eval_numer) =
                        lookup_evals(memory, raw_proof, table, evals_ptr, quotient_eval_numer, y)
                            .unwrap();
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
    let y = mload(memory, theta_mptr as u32 + 0x60)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Failed to read evaluation point y from memory. Cause: {e}"),
        })?
        .into_fr();

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

    // mstore(add(theta_mptr, 0x240), mulmod(quotient_eval_numer, mload(add(theta_mptr, 0x1a0)), R))
    let idx = theta_mptr + 0x240;
    let val = quotient_eval_numer * mload(memory, theta_mptr as u32 + 0x1a0).map_err(|e| VerifyError::KeyError { message: format!("Failed to read scalar from memory at the end of permutation computations phase. Cause: {e}" )})?.into_fr();
    memory[idx..(idx + 0x20)].copy_from_slice(&val.into_be_bytes32());

    Ok(())
}

// Compute quotient commitment
fn compute_quotient_commitment<H: CurveHooks>(
    memory: &mut [u8],
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
    // mstore(vka_end, calldataload(mload(0x03a0)))
    memory[vka_end..(vka_end + 0x20)].copy_from_slice(&bytes);

    // mstore(add(0x20, vka_end), calldataload(add(mload(0x03a0), 0x20)))
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

    let x_n = mload(memory, theta_mptr as u32 + 0x180)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Failed to read x_n from memory. Cause: {e}"),
        })?
        .into_fr();

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
        ec_mul_acc::<H>(memory, &x_n).map_err(|_| VerifyError::OtherError {
            message: "".to_string(),
        })?; // TODO: Replace with better Error variant

        let x = Fq::from_be_bytes_mod_order(&load_from_proof(raw_proof, cptr).map_err(|e| VerifyError::InvalidProofError { message: format!("Unable to read x coordinate from proof during the quotient commitment computation phase. Cause: {e}") })?);
        let y = Fq::from_be_bytes_mod_order(&load_from_proof(raw_proof, cptr + 0x20).map_err(|e| VerifyError::InvalidProofError { message: format!("Unable to read y coordinate from proof during the quotient commitment computation phase. Cause: {e}") })?);
        ec_add_acc::<H>(memory, &x, &y).map_err(|_| VerifyError::OtherError {
            message: "".to_string(),
        })?; // TODO: Replace with better Error variant
        cptr -= 0x40;
    }
    // mstore(add(theta_mptr, 0x260), mload(vka_end))
    let bytes = mload(memory, vka_end as u32).map_err(|e| VerifyError::InvalidProofError { message: format!("Unable to read from memory at index vka_end during the quotient commitment computation phase. Cause: {e}") })?;
    memory[(theta_mptr + 0x260)..(theta_mptr + 0x260 + 0x20)].copy_from_slice(&bytes);

    // mstore(add(theta_mptr, 0x280), mload(add(0x20, vka_end)))
    let bytes = mload(&memory, vka_end as u32 + 0x20).map_err(|e| VerifyError::InvalidProofError { message: format!("Unable to read from memory at index vka_end + 0x20 during the quotient commitment computation phase. Cause: {e}") })?;
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
    let mut point_computations = mload(memory, pcs_ptr as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load point_computations from memory. Cause: {e}"),
        })?
        .into_u256();
    let x = mload(memory, theta_mptr as u32 + 0x80)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load x from memory. Cause: {e}"),
        })?
        .into_fr(); // Is this a point or a scalar?
    let omega = mload(memory, 0x0180)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load omega from memory. Cause: {e}"),
        })?
        .into_fr();
    let omega_inv = mload(memory, 0x01a0)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load omega_inv from memory. Cause: {e}"),
        })?
        .into_fr();
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
    .unwrap();
    pcs_ptr += 0x20;
    point_computations = mload(memory, pcs_ptr as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load point_computations from memory. Cause: {e}"),
        })?
        .into_u256();
    // Store interm point
    // mstore(add(and(point_computations, PTR_BITMASK), vka_end), x)
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
    .unwrap();
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
    let mu = mload(memory, theta_mptr as u32 + 0xE0)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load mu from memory. Cause: {e}"),
        })?
        .into_fr();

    let mut vanishing_computations = mload(memory, pcs_ptr as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load vanishing_computations from memory. Cause: {e}"),
        })?
        .into_u256();

    // mstore(add(0x20, vka_end), 1)
    memory[(vka_end + 0x20)..(vka_end + 0x40)].copy_from_slice(&U256::one().into_be_bytes32());

    let mut mptr = lsb16(&vanishing_computations);
    vanishing_computations >>= 16;
    let mptr_end = lsb16(&vanishing_computations);
    vanishing_computations >>= 16;
    let mut point_mptr = lsb16(&vanishing_computations);
    while mptr < mptr_end {
        let idx = vka_end + mptr;
        let val = mu - mload(memory, (point_mptr + vka_end) as u32)
            .map_err(|e| VerifyError::KeyError {
                message: format!(
                    "Unable to load scalar from memory during vanishing_computations. Cause: {e}"
                ),
            })?
            .into_fr();
        // mstore(add(vka_end, mptr), val);
        memory[idx..idx + 0x20].copy_from_slice(&val.into_be_bytes32());

        mptr += 0x20;
        point_mptr += 0x20;
    }

    vanishing_computations >>= 16;
    let num_words = lsb8(&vanishing_computations);
    vanishing_computations >>= 8;
    let mut s = mload(memory, (vka_end + lsb16(&vanishing_computations)) as u32)
                .map_err(|e| VerifyError::KeyError { message: format!("Unable to initialize s with scalar from memory during vanishing_computations. Cause: {e}") })?
                .into_fr();
    vanishing_computations >>= 16;
    for _ in 0..num_words {
        while !vanishing_computations.is_zero() {
            s = s * mload(memory, (vka_end + lsb16(&vanishing_computations)) as u32)
                .map_err(|e| VerifyError::KeyError {
                    message: format!(
                        "Unable to update s during vanishing_computations. Cause: {e}"
                    ),
                })?
                .into_fr();
            vanishing_computations >>= 16;
        }
        pcs_ptr += 0x20;
        vanishing_computations = mload(memory, pcs_ptr as u32)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Unable to load vanishing_computations from memory. Cause: {e}"),
            })?
            .into_u256();
    }
    let mut diff_ptr = vka_end + lsb16(&vanishing_computations);
    // mstore(diff_ptr, s)
    memory[diff_ptr..diff_ptr + 0x20].copy_from_slice(&s.into_be_bytes32());

    vanishing_computations >>= 16;
    let mut diff: Fr;
    let sets_len = lsb16(&vanishing_computations);
    pcs_ptr += 0x20;
    vanishing_computations = mload(memory, pcs_ptr as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load vanishing_computations from memory. Cause: {e}"),
        })?
        .into_u256();
    for i in 0..sets_len {
        diff = mload(memory, (lsb16(&vanishing_computations) + vka_end) as u32)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Unable to load diff from memory. Cause: {e}"),
            })?
            .into_fr();
        vanishing_computations >>= 16;
        while !vanishing_computations.is_zero() {
            diff = diff
                * mload(memory, (lsb16(&vanishing_computations) + vka_end) as u32)
                    .map_err(|e| VerifyError::KeyError {
                        message: format!(
                            "Unable to read scalar from memory in order to update diff. Cause: {e}"
                        ),
                    })?
                    .into_fr();
            vanishing_computations >>= 16;
        }
        diff_ptr += 0x20;
        // mstore(diff_ptr, diff)
        memory[diff_ptr..diff_ptr + 0x20].copy_from_slice(&diff.into_be_bytes32());

        if i == 0 {
            // mstore(vka_end, diff)
            memory[vka_end..vka_end + 0x20].copy_from_slice(&diff.into_be_bytes32());
        }
        pcs_ptr += 0x20;
        vanishing_computations = mload(memory, pcs_ptr as u32)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Unable to load vanishing_computations from memory. Cause: {e}"),
            })?
            .into_u256();
    }

    Ok(pcs_ptr)
}

// Performs coefficient computations. Returns updated pcs_ptr.
fn perform_coeff_computations(memory: &mut [u8], mut pcs_ptr: usize) -> Result<usize, VerifyError> {
    let mut coeff_len_data = mload(memory, pcs_ptr as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load coeff_len_data from memory. Cause: {e}"),
        })?
        .into_u256();

    // Load in the least significant byte of the `coeff_len_data` word to get the total number
    // of words we will need to load in that contains the packed Vec<set.rots().len()>.
    let end_ptr_packed_lens = pcs_ptr + 0x20 * lsb8(&coeff_len_data);

    coeff_len_data >>= 8;

    let mut i = pcs_ptr;
    pcs_ptr = end_ptr_packed_lens;
    while i < end_ptr_packed_lens {
        while !coeff_len_data.is_zero() {
            let coeff_data = mload(memory, pcs_ptr as u32)
                .map_err(|e| VerifyError::KeyError {
                    message: format!("Unable to load coeff_data from memory. Cause: {e}"),
                })?
                .into_u256();
            coeff_len_data = coeff_computations(memory, coeff_len_data, coeff_data);
            pcs_ptr += 0x20;
        }
        coeff_len_data = mload(memory, i as u32 + 0x20)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Unable to load coeff_len_data from memory. Cause: {e}"),
            })?
            .into_u256();
        i += 0x20;
    }

    Ok(pcs_ptr)
}

// Performs normalized coefficient computations.
fn perform_normalized_coeff_computations(
    memory: &mut [u8],
    vka_end: usize,
    mut pcs_ptr: usize,
) -> Result<usize, VerifyError> {
    let mut norm_coeff_data = mload(memory, pcs_ptr as u32)
                .map_err(|e| VerifyError::KeyError {
                    message: format!("Unable to load norm_coeff_data from memory during normalized_coeff_computations. Cause: {e}"),
                })?
                .into_u256();

    batch_invert_in_memory(
        memory,
        vka_end as u32,
        (vka_end + lsb16(&norm_coeff_data)) as u32,
    );

    norm_coeff_data >>= 16;

    let diff_0_inv = mload(memory, vka_end as u32)
                .map_err(|e| VerifyError::KeyError {
                    message: format!("Unable to load diff_0_inv from memory during normalized_coeff_computations. Cause: {e}"),
                })?
                .into_fr();
    let mptr0 = lsb16(&norm_coeff_data) + vka_end;
    norm_coeff_data >>= 16;

    // mstore(mptr0, diff_0_inv)
    memory[mptr0..mptr0 + 0x20].copy_from_slice(&diff_0_inv.into_be_bytes32());

    let mptr_end = mptr0 + lsb16(&norm_coeff_data);
    for mptr in ((mptr0 + 0x20)..mptr_end).step_by(0x20) {
        // mstore(mptr, mulmod(mload(mptr), diff_0_inv, R))
        let val = mload(memory, mptr as u32).map_err(|e| VerifyError::KeyError {
                    message: format!("Unable to load scalar from memory during normalized_coeff_computations. Cause: {e}"),
                })?.into_fr() * diff_0_inv;
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
    let mut r_evals_meta_data = mload(memory, pcs_ptr as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load r_evals_meta_data from memory. Cause: {e}"),
        })?
        .into_u256();

    let end_ptr_packed_lens = pcs_ptr + 0x20 * lsb8(&r_evals_meta_data);
    r_evals_meta_data >>= 8;
    let mut set_coeff = lsb16(&r_evals_meta_data) + vka_end;
    r_evals_meta_data >>= 16;
    let mut r_eval_mptr = lsb16(&r_evals_meta_data) + vka_end;
    r_evals_meta_data >>= 16;
    let mut i = pcs_ptr;
    pcs_ptr = end_ptr_packed_lens;
    let zeta = mload(memory, theta_mptr as u32 + 0xA0)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load zeta from memory. Cause: {e}"),
        })?
        .into_fr();
    let quotient_eval = mload(memory, theta_mptr as u32 + 0x240)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load quotient_eval from memory. Cause: {e}"),
        })?
        .into_fr();
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
            )
            .map_err(|_| VerifyError::OtherError {
                message: "".to_string(),
            })?; // TODO: REVISIT WHEN DOING ERROR HANDLING...
            coeff_ptr = coeff_ptr + lsb8(&r_evals_meta_data);
            r_evals_meta_data >>= 8;
            if not_first {
                r_eval *= mload(memory, set_coeff as u32)
                    .map_err(|e| VerifyError::KeyError {
                        message: format!("Unable to load set_coeff from memory. Cause: {e}"),
                    })?
                    .into_fr();
                set_coeff += 0x20;
            }
            not_first = true;
            // mstore(r_eval_mptr, r_eval)
            memory[r_eval_mptr..r_eval_mptr + 0x20].copy_from_slice(&r_eval.into_be_bytes32());

            r_eval_mptr += 0x20;
        }
        r_evals_meta_data = mload(memory, i as u32 + 0x20)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Unable to load r_evals_meta_data from memory. Cause: {e}"),
            })?
            .into_u256();
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
    let mut coeff_sums_data = mload(memory, pcs_ptr as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load coeff_sums_data from memory. Cause: {e}"),
        })?
        .into_u256();

    let end_ptr_packed_lens = pcs_ptr + 0x20 * lsb8(&coeff_sums_data);
    coeff_sums_data >>= 8;
    let mut coeff_ptr = vka_end + 0x20;

    let mut i = pcs_ptr;
    pcs_ptr = end_ptr_packed_lens;
    while i < end_ptr_packed_lens {
        while !coeff_sums_data.is_zero() {
            let mut sum = mload(memory, coeff_ptr as u32)
                .map_err(|e| VerifyError::KeyError {
                    message: format!(
                        "Unable to load initial value for sum from memory. Cause: {e}"
                    ),
                })?
                .into_fr();
            let len = lsb8(&coeff_sums_data);
            coeff_sums_data >>= 8;
            for j in (0x20..len).step_by(0x20) {
                sum += mload(memory, (coeff_ptr + j) as u32)
                    .map_err(|e| VerifyError::KeyError {
                        message: format!(
                            "Unable to update sum during coeff_sums_computation. Cause: {e}"
                        ),
                    })?
                    .into_fr(); // TODO: DOUBLE-CHECK: (coeff_ptr + j) as u32 fits into a `u32`
            }
            coeff_ptr += len;
            let idx = lsb16(&coeff_sums_data) + vka_end;
            // mstore(idx, sum)
            memory[idx..idx + 0x20].copy_from_slice(&sum.into_be_bytes32());

            coeff_sums_data >>= 16;
        }
        coeff_sums_data = mload(memory, i as u32 + 0x20)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Unable to load coeff_sums_data from memory. Cause: {e}"),
            })?
            .into_u256();
        i += 0x20;
    }

    Ok(pcs_ptr)
}

// Performs r_eval_computation. Returns updated value of pcs_ptr.
fn perform_r_eval_computation(
    memory: &mut [u8],
    vka_end: usize,
    theta_mptr: usize,
    mut pcs_ptr: usize,
) -> Result<usize, VerifyError> {
    let mut r_eval_data = mload(memory, pcs_ptr as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load r_eval_data from memory. Cause: {e}"),
        })?
        .into_u256();

    let mptr_end = lsb16(&r_eval_data) + vka_end;

    let mut mptr = vka_end;
    r_eval_data >>= 16;
    let mut sum_mptr = lsb16(&r_eval_data) + vka_end;
    while mptr < mptr_end {
        // mstore(mptr, mload(sum_mptr))
        let bytes = mload(memory, sum_mptr as u32).map_err(|e| VerifyError::KeyError {
            message: format!(
                "Unable to load scalar from memory during r_eval_computation. Cause: {e}"
            ),
        })?;
        memory[mptr..mptr + 0x20].copy_from_slice(&bytes);

        mptr += 0x20;
        sum_mptr += 0x20;
    }
    r_eval_data >>= 16;

    batch_invert_in_memory(memory, vka_end as u32, mptr_end as u32);

    let r_eval_ptr = lsb16(&r_eval_data) + vka_end;
    let mut r_eval = mload(memory, mptr_end as u32 - 0x20)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to initialize r_eval. Cause: {e}"),
        })?
        .into_fr()
        * mload(memory, r_eval_ptr as u32)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Unable to initialize r_eval. Cause: {e}"),
            })?
            .into_fr();
    r_eval_data >>= 16;

    let mut sum_inv_mptr = mptr_end - 0x40;
    let sum_inv_mptr_end = vka_end - 0x20;
    let mut r_eval_mptr = r_eval_ptr - 0x20;

    while sum_inv_mptr > sum_inv_mptr_end {
        r_eval *= mload(memory, theta_mptr as u32 + 0xc0)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Unable to update r_eval during r_eval computation. Cause: {e}"),
            })?
            .into_fr();
        r_eval += mload(memory, sum_inv_mptr as u32)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Unable to update r_eval during r_eval computation. Cause: {e}"),
            })?
            .into_fr()
            * mload(memory, r_eval_mptr as u32)
                .map_err(|e| VerifyError::KeyError {
                    message: format!(
                        "Unable to update r_eval during r_eval computation. Cause: {e}"
                    ),
                })?
                .into_fr();

        sum_inv_mptr -= 0x20;
        r_eval_mptr -= 0x20;
    }
    // mstore(add(theta_mptr, 0x2A0), r_eval)
    let idx = theta_mptr + 0x2a0;
    memory[idx..idx + 0x20].copy_from_slice(&r_eval.into_be_bytes32());

    pcs_ptr += 0x20;

    Ok(pcs_ptr)
}

// pairing_input_computations
fn perform_pairing_input_computations<H: CurveHooks>(
    memory: &mut [u8],
    raw_proof: &[u8],
    vka_end: usize,
    theta_mptr: usize,
    mut pcs_ptr: usize,
) -> Result<(), VerifyError> {
    let mut nu = mload(memory, theta_mptr as u32 + 0xC0)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load nu from memory. Cause: {e}"),
        })?
        .into_fr();

    let mut pairing_input_meta_data = mload(memory, pcs_ptr as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to load pairing_input_meta_data from memory. Cause: {e}"),
        })?
        .into_u256();

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
                let data = mload(memory, pcs_ptr as u32).map_err(|e| VerifyError::KeyError {
                message: format!("Unable to load data from memory during pairing_input_computations. Cause: {e}"),
            })?.into_u256();
                pairing_input_computations_first::<H>(
                    memory,
                    raw_proof,
                    len as u32,
                    pcs_ptr as u32,
                    data,
                    theta_mptr as u32,
                );
                pcs_ptr += len;
                continue;
            }
            let data = mload(memory, pcs_ptr as u32).map_err(|e| VerifyError::KeyError {
                message: format!("Unable to load data from memory during pairing_input_computations. Cause: {e}"),
            })?.into_u256();
            pairing_input_computations::<H>(
                memory,
                raw_proof,
                len as u32,
                pcs_ptr as u32,
                data,
                theta_mptr as u32,
            );
            pcs_ptr += len;
            let s = mload(memory, set_coeff as u32).map_err(|e| VerifyError::KeyError {
                message: format!("Unable to initilize s with scalar from memory during pairing_input_computations. Cause: {e}"),
            })?.into_fr();
            ec_mul_tmp::<H>(memory, &(nu * s));
            set_coeff += 0x20;
            let x = Fq::from_be_bytes_mod_order(&mload(memory, 0x80 + vka_end as u32).map_err(
                |e| VerifyError::KeyError {
                    message: format!(
                        "Unable to load x from memory during pairing_input_computations. Cause: {e}"
                    ),
                },
            )?);
            let y = Fq::from_be_bytes_mod_order(&mload(memory, 0xa0 + vka_end as u32).map_err(
                |e| VerifyError::KeyError {
                    message: format!(
                        "Unable to load y from memory during pairing_input_computations. Cause: {e}"
                    ),
                },
            )?);
            ec_add_acc::<H>(memory, &x, &y);
            // execute this if statement if not the last set
            if true || i < end_ptr_packed_lens - 0x20 {
                // if or(0x1, lt(i, sub(end_ptr_packed_lens, 0x20))) {
                nu *= mload(memory, theta_mptr as u32 + 0xc0).map_err(|e| VerifyError::KeyError {
                message: format!("Unable to update nu using scalar from memory during pairing_input_computations. Cause: {e}"),
            })?.into_fr();
            }
        }
        pairing_input_meta_data = mload(memory, i as u32 + 0x20)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Unable to load pairing_input_meta_data from memory. Cause: {e}"),
            })?
            .into_u256();
        i += 0x20;
    }
    // Load G1's SRS generator from the VKA into memory

    // mstore(add(0x80, vka_end), mload(0x0260))
    let idx1 = 0x01c0 + VKA_OFFSET + MEMORY_OFFSET; // g1_x index
    let idx2 = vka_end + 0x80;
    let g1_x_bytes = mload(&memory, idx1 as u32).map_err(|e| VerifyError::KeyError {
        message: format!("Unable to load g1_x_bytes from memory. Cause: {e}"),
    })?;
    memory[idx2..idx2 + 0x20].copy_from_slice(&g1_x_bytes);

    // mstore(add(0xa0, vka_end), mload(0x0280))
    let idx1 = 0x01e0 + VKA_OFFSET + MEMORY_OFFSET; // g1_y index
    let idx2 = vka_end + 0xa0;
    let g1_y_bytes = mload(&memory, idx1 as u32).map_err(|e| VerifyError::KeyError {
        message: format!("Unable to load g1_y_bytes from memory. Cause: {e}"),
    })?;
    memory[idx2..idx2 + 0x20].copy_from_slice(&g1_y_bytes);

    let s = -mload(memory, theta_mptr as u32 + 0x2a0)
        .map_err(|e| VerifyError::KeyError {
            message: format!(
                "Unable to load scalar from memory during pairing_input_computations. Cause: {e}"
            ),
        })?
        .into_fr();
    ec_mul_tmp::<H>(memory, &s);
    let x = Fq::from_be_bytes_mod_order(&mload(memory, 0x80 + vka_end as u32).map_err(|e| {
        VerifyError::KeyError {
            message: format!(
                "Unable to load x from memory during pairing_input_computations. Cause: {e}"
            ),
        }
    })?);
    let y = Fq::from_be_bytes_mod_order(&mload(memory, 0xa0 + vka_end as u32).map_err(|e| {
        VerifyError::KeyError {
            message: format!(
                "Unable to load y from memory during pairing_input_computations. Cause: {e}"
            ),
        }
    })?);
    ec_add_acc::<H>(memory, &x, &y);

    // mstore(add(0x80, vka_end), calldataload(and(ec_points_cptr_packed, PTR_BITMASK)))
    let idx = 0x80 + vka_end;
    let bytes = load_from_proof(raw_proof, lsb16(&ec_points_cptr_packed) as u32).map_err(|e| {
        VerifyError::InvalidProofError {
            message: format!(
                "Unable to load from proof during pairing_input_computations. Cause: {e}"
            ),
        }
    })?;
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    ec_points_cptr_packed >>= 16;

    // mstore(add(0xa0, vka_end), calldataload(and(ec_points_cptr_packed, PTR_BITMASK)))
    let idx = 0xa0 + vka_end;
    let bytes = load_from_proof(raw_proof, lsb16(&ec_points_cptr_packed) as u32).map_err(|e| {
        VerifyError::InvalidProofError {
            message: format!(
                "Unable to load from proof during pairing_input_computations. Cause: {e}"
            ),
        }
    })?;
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    ec_points_cptr_packed >>= 16;

    let s = -mload(
        memory,
        lsb16(&ec_points_cptr_packed) as u32 + vka_end as u32,
    )
    .map_err(|e| VerifyError::KeyError {
        message: format!(
            "Unable to load scalar from memory during pairing_input_computations. Cause: {e}"
        ),
    })?
    .into_fr();
    ec_mul_tmp::<H>(memory, &s);
    ec_points_cptr_packed >>= 16;

    let x = Fq::from_be_bytes_mod_order(&mload(memory, 0x80 + vka_end as u32).map_err(|e| {
        VerifyError::KeyError {
            message: format!(
                "Unable to load x from memory during pairing_input_computations. Cause: {e}"
            ),
        }
    })?);
    let y = Fq::from_be_bytes_mod_order(&mload(memory, 0xa0 + vka_end as u32).map_err(|e| {
        VerifyError::KeyError {
            message: format!(
                "Unable to load y from memory during pairing_input_computations. Cause: {e}"
            ),
        }
    })?);
    ec_add_acc::<H>(memory, &x, &y);

    let w_prime_x =
        load_from_proof(raw_proof, lsb16(&ec_points_cptr_packed) as u32).map_err(|e| {
            VerifyError::InvalidProofError {
                message: format!("Unable to load w_prime_x from proof. Cause: {e}"),
            }
        })?;
    ec_points_cptr_packed >>= 16;
    let w_prime_y =
        load_from_proof(raw_proof, lsb16(&ec_points_cptr_packed) as u32).map_err(|e| {
            VerifyError::InvalidProofError {
                message: format!("Unable to load w_prime_y from proof. Cause: {e}"),
            }
        })?;
    // mstore(add(0x80, vka_end), w_prime_x)
    let idx = 0x80 + vka_end;
    memory[idx..idx + 0x20].copy_from_slice(&w_prime_x);

    // mstore(add(0xa0, vka_end), w_prime_y)
    let idx = 0xa0 + vka_end;
    memory[idx..idx + 0x20].copy_from_slice(&w_prime_y);

    let s = mload(memory, theta_mptr as u32 + 0xe0)
        .map_err(|e| VerifyError::KeyError {
            message: format!(
                "Unable to load scalar from memory during pairing_input_computations. Cause: {e}"
            ),
        })?
        .into_fr();
    ec_mul_tmp::<H>(memory, &s);
    let x = Fq::from_be_bytes_mod_order(&mload(memory, 0x80 + vka_end as u32).map_err(|e| {
        VerifyError::KeyError {
            message: format!(
                "Unable to load x from memory during pairing_input_computations. Cause: {e}"
            ),
        }
    })?);
    let y = Fq::from_be_bytes_mod_order(&mload(memory, 0xa0 + vka_end as u32).map_err(|e| {
        VerifyError::KeyError {
            message: format!(
                "Unable to load y from memory during pairing_input_computations. Cause: {e}"
            ),
        }
    })?);
    ec_add_acc::<H>(memory, &x, &y);

    // mstore(add(theta_mptr, 0x2C0), mload(vka_end))
    let idx = theta_mptr + 0x2c0;
    let bytes = mload(memory, vka_end as u32).map_err(|e| VerifyError::KeyError {
        message: format!(
            "Unable to load scalar from memory during pairing_input_computations. Cause: {e}"
        ),
    })?;
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    // mstore(add(theta_mptr, 0x2E0), mload(add(0x20, vka_end)))
    let idx = theta_mptr + 0x2e0;
    let bytes = mload(memory, 0x20 + vka_end as u32).map_err(|e| VerifyError::KeyError {
        message: format!(
            "Unable to load scalar from memory during pairing_input_computations. Cause: {e}"
        ),
    })?;
    memory[idx..idx + 0x20].copy_from_slice(&bytes);

    // mstore(add(theta_mptr, 0x300), w_prime_x)
    let idx = theta_mptr + 0x300;
    memory[idx..idx + 0x20].copy_from_slice(&w_prime_x);

    // mstore(add(theta_mptr, 0x320), w_prime_y)
    let idx = theta_mptr + 0x320;
    memory[idx..idx + 0x20].copy_from_slice(&w_prime_y);

    Ok(())
}

// Compute pairing lhs and rhs
fn compute_pairing_lhs_and_rhs<H: CurveHooks>(
    memory: &mut [u8],
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
    let has_accumulator = !mload(memory, 0x0140 + VKA_OFFSET as u32 + MEMORY_OFFSET as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read has_accumulator field from VKA. Cause: {e}"),
        })?
        .into_u256()
        .is_zero();
    if has_accumulator {
        //     mstore(add(0x00, vka_end), mload(add(theta_mptr, 0x100)))
        let mut bytes =
            mload(memory, theta_mptr as u32 + 0x100).map_err(|e| VerifyError::KeyError {
                message: format!(
                    "Unable to read from memory during random linear combine. Cause: {e}"
                ),
            })?;
        memory[vka_end..(vka_end + 0x20)].copy_from_slice(&bytes);
        //     mstore(add(0x20, vka_end), mload(add(theta_mptr, 0x120)))
        bytes = mload(memory, theta_mptr as u32 + 0x120).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read from memory during random linear combine. Cause: {e}"),
        })?;
        memory[(vka_end + 0x20)..(vka_end + 0x40)].copy_from_slice(&bytes);
        //     mstore(add(0x40, vka_end), mload(add(theta_mptr, 0x140)))
        bytes = mload(memory, theta_mptr as u32 + 0x140).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read from memory during random linear combine. Cause: {e}"),
        })?;
        memory[(vka_end + 0x40)..(vka_end + 0x60)].copy_from_slice(&bytes);
        //     mstore(add(0x60, vka_end), mload(add(theta_mptr, 0x160)))
        bytes = mload(memory, theta_mptr as u32 + 0x160).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read from memory during random linear combine. Cause: {e}"),
        })?;
        memory[(vka_end + 0x60)..(vka_end + 0x80)].copy_from_slice(&bytes);
        //     mstore(add(0x80, vka_end), mload(add(theta_mptr, 0x2c0)))
        bytes = mload(memory, theta_mptr as u32 + 0x2c0).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read from memory during random linear combine. Cause: {e}"),
        })?;
        memory[(vka_end + 0x80)..(vka_end + 0xa0)].copy_from_slice(&bytes);
        //     mstore(add(0xa0, vka_end), mload(add(theta_mptr, 0x2e0)))
        bytes = mload(memory, theta_mptr as u32 + 0x2e0).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read from memory during random linear combine. Cause: {e}"),
        })?;
        memory[(vka_end + 0xa0)..(vka_end + 0xc0)].copy_from_slice(&bytes);
        //     mstore(add(0xc0, vka_end), mload(add(theta_mptr, 0x300)))
        bytes = mload(memory, theta_mptr as u32 + 0x300).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read from memory during random linear combine. Cause: {e}"),
        })?;
        memory[(vka_end + 0xc0)..(vka_end + 0xe0)].copy_from_slice(&bytes);
        //     mstore(add(0xe0, vka_end), mload(add(theta_mptr, 0x320)))
        bytes = mload(memory, theta_mptr as u32 + 0x320).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read from memory during random linear combine. Cause: {e}"),
        })?;
        memory[(vka_end + 0xe0)..(vka_end + 0x100)].copy_from_slice(&bytes);

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
        ec_mul_acc::<H>(memory, &challenge);
        let x = Fq::from_be_bytes_mod_order(&mload(memory, theta_mptr as u32 + 0x2c0).map_err(
            |e| VerifyError::KeyError {
                message: format!(
                    "Unable to load x from memory during random linear combine phase. Cause: {e}"
                ),
            },
        )?);
        let y = Fq::from_be_bytes_mod_order(&mload(memory, theta_mptr as u32 + 0x2e0).map_err(
            |e| VerifyError::KeyError {
                message: format!(
                    "Unable to load y from memory during random linear combine phase. Cause: {e}"
                ),
            },
        )?);
        ec_add_acc::<H>(memory, &x, &y);
        // mstore(add(theta_mptr, 0x2c0), mload(vka_end))
        let idx = theta_mptr + 0x2c0;
        let bytes = mload(memory, vka_end as u32).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read from memory during random linear combine. Cause: {e}"),
        })?;
        memory[idx..idx + 0x20].copy_from_slice(&bytes);

        // mstore(add(theta_mptr, 0x2e0), mload(add(0x20, vka_end)))
        let idx = theta_mptr + 0x2e0;
        let bytes = mload(memory, vka_end as u32 + 0x20).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read from memory during random linear combine. Cause: {e}"),
        })?;
        memory[idx..idx + 0x20].copy_from_slice(&bytes);

        // [pairing_rhs] += challenge * [acc_rhs]
        // mstore(vka_end, mload(add(theta_mptr, 0x140)))
        let idx = vka_end;
        let bytes =
            mload(memory, theta_mptr as u32 + 0x140).map_err(|e| VerifyError::KeyError {
                message: format!(
                    "Unable to read from memory during random linear combine. Cause: {e}"
                ),
            })?;
        memory[idx..idx + 0x20].copy_from_slice(&bytes);

        // mstore(add(0x20, vka_end), mload(add(theta_mptr, 0x160)))
        let idx = vka_end + 0x20;
        let bytes =
            mload(memory, theta_mptr as u32 + 0x160).map_err(|e| VerifyError::KeyError {
                message: format!(
                    "Unable to read from memory during random linear combine. Cause: {e}"
                ),
            })?;
        memory[idx..idx + 0x20].copy_from_slice(&bytes);

        ec_mul_acc::<H>(memory, &challenge);
        let x = Fq::from_be_bytes_mod_order(&mload(memory, theta_mptr as u32 + 0x300).map_err(
            |e| VerifyError::KeyError {
                message: format!(
                    "Unable to load x from memory during random linear combine phase. Cause: {e}"
                ),
            },
        )?);
        let y = Fq::from_be_bytes_mod_order(&mload(memory, theta_mptr as u32 + 0x320).map_err(
            |e| VerifyError::KeyError {
                message: format!(
                    "Unable to load y from memory during random linear combine phase. Cause: {e}"
                ),
            },
        )?);
        ec_add_acc::<H>(memory, &x, &y);
        // mstore(add(theta_mptr, 0x300), mload(vka_end))
        let idx = theta_mptr + 0x300;
        let bytes = mload(memory, vka_end as u32).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read from memory during random linear combine. Cause: {e}"),
        })?;
        memory[idx..idx + 0x20].copy_from_slice(&bytes);

        // mstore(add(theta_mptr, 0x320), mload(add(0x20, vka_end)))
        let idx = theta_mptr + 0x320;
        let bytes = mload(memory, vka_end as u32 + 0x20).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read from memory during random linear combine. Cause: {e}"),
        })?;
        memory[idx..idx + 0x20].copy_from_slice(&bytes);
    }

    Ok(())
}

// Performs the final pairing check.
fn pairing_check<H: CurveHooks>(memory: &mut [u8], theta_mptr: usize) -> Result<(), VerifyError> {
    // LHS
    let x =
        Fq::from_be_bytes_mod_order(&mload(memory, theta_mptr as u32 + 0x2c0).map_err(|e| {
            VerifyError::KeyError {
                message: format!(
                    "Unable to read LHS.x from memory during pairing computation phase. Cause: {e}"
                ),
            }
        })?);
    let y =
        Fq::from_be_bytes_mod_order(&mload(memory, theta_mptr as u32 + 0x2e0).map_err(|e| {
            VerifyError::KeyError {
                message: format!(
                    "Unable to read LHS.y from memory during pairing computation phase. Cause: {e}"
                ),
            }
        })?);
    let p_0 = G1::<H>::new(x, y);
    // RHS
    let x =
        Fq::from_be_bytes_mod_order(&mload(memory, theta_mptr as u32 + 0x300).map_err(|e| {
            VerifyError::KeyError {
                message: format!(
                    "Unable to read RHS.x from memory during pairing computation phase. Cause: {e}"
                ),
            }
        })?);
    let y =
        Fq::from_be_bytes_mod_order(&mload(memory, theta_mptr as u32 + 0x320).map_err(|e| {
            VerifyError::KeyError {
                message: format!(
                    "Unable to read RHS.y from memory during pairing computation phase. Cause: {e}"
                ),
            }
        })?);
    let p_1 = G1::new(x, y);

    let g1_points = [G1Prepared::from(p_0), G1Prepared::from(p_1)];

    let g2_x_1_index = 0x0200 + VKA_OFFSET + MEMORY_OFFSET;
    let data = &memory[g2_x_1_index..g2_x_1_index + 4 * 0x20];
    let h1 = read_g2::<H>(&data).expect("Parsing the SRS point should always work");
    // TODO: VALIDATION REQUIRED!
    // mstore(add(0x40, vka_end), mload( {{ vk_const_offsets["g2_x_1"]|hex() }}))
    // mstore(add(0x60, vka_end), mload( {{ vk_const_offsets["g2_x_2"]|hex() }}))
    // mstore(add(0x80, vka_end), mload( {{ vk_const_offsets["g2_y_1"]|hex() }}))
    // mstore(add(0xa0, vka_end), mload( {{ vk_const_offsets["g2_y_2"]|hex() }}))

    let neg_s_g2_x_1_index = 0x0280 + VKA_OFFSET + MEMORY_OFFSET;
    let data = &memory[neg_s_g2_x_1_index..neg_s_g2_x_1_index + 4 * 0x20];
    let h2 = read_g2::<H>(&data).expect("Parsing the SRS point should always work");
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
        &mload(&memory, (VKA_OFFSET + 0xa0) as u32).expect("Should be able to extend memory."),
    );

    // let proof_cptr := proof.offset
    let challenge_mptr = vka_end
        + mload_u32(memory, (VKA_OFFSET + 0xc0) as u32).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to parse fsm as u32. Cause: {}", e).to_string(),
        })? as usize;
    // Set the theta_mptr (vk_mptr + vk_len + challenges_length)
    let theta_mptr = challenge_mptr
        + mload_u32(memory, (VKA_OFFSET + 0x0120) as u32).map_err(|e| VerifyError::KeyError {
            message: format!("Unable to compute theta_mptr as u32. Cause: {}", e).to_string(),
        })? as usize;

    let challenge_len_ptr = VKA_OFFSET + MEMORY_OFFSET + 0x420;
    let mut challenge_len_data = mload(&memory, challenge_len_ptr as u32)
        .map_err(|e| VerifyError::KeyError {
            message: format!("Unable to read challenge_len_data. Cause: {e}"),
        })?
        .into_u256();
    let num_words = lsb8(&challenge_len_data);

    challenge_len_data >>= 8;
    // num_evals is defined as u64 in order to be able to fit all possible u32 values
    let num_evals = u64::from(
        0x20 * mload_u32(memory, 0x60 + (VKA_OFFSET + MEMORY_OFFSET) as u32).map_err(|e| {
            VerifyError::KeyError {
                message: format!("Unable to read num_evals as u32. Cause: {}", e).to_string(),
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
        let eval: EVMWord = load_from_proof(raw_proof, proof_cptr as u32).map_err(|e| {
            VerifyError::InvalidProofError {
                message: format!("Unable to read evaluation from proof. Cause: {e}"),
            }
        })?;
        if eval.into_u256() >= Fr::MODULUS {
            return Err(VerifyError::InvalidProofError {
                message: format!("Evaluation {} exceeds field modulus.", to_hex_string(&eval)),
            });
        }

        memory[hash_mptr..hash_mptr + 32].copy_from_slice(&eval); // mstore(hash_mptr, eval)
        proof_cptr += 0x20;
        hash_mptr += 0x20;
    }

    Ok((proof_cptr, hash_mptr))
}

// Read instances and witness commitments and generate challenges.
// Returns updated: (hash_mptr, proof_cptr, challenge_mptr)
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
            let proof_cptr_end = proof_cptr + lsb16(&challenge_len_data) as usize;
            challenge_len_data >>= 16;
            // Phase loop
            while proof_cptr < proof_cptr_end {
                match write_ec_point_into_memory::<H>(raw_proof, memory, proof_cptr, hash_mptr) {
                    Ok((new_proof_cptr, new_hash_mptr)) => {
                        proof_cptr = new_proof_cptr;
                        hash_mptr = new_hash_mptr;
                    }
                    Err(e) => {
                        return Err(e); // TODO: Rework to use better error propagation
                    }
                };
            }

            // Generate challenges
            match squeeze_challenge(memory, vka_end, challenge_mptr, hash_mptr) {
                Ok((new_challenge_mptr, new_hash_mptr)) => {
                    challenge_mptr = new_challenge_mptr;
                    hash_mptr = new_hash_mptr;
                }
                Err(_) => {
                    return Err(VerifyError::OtherError {
                        message: "Failed to squeeze challenge.".to_string(),
                    }); // TODO: Rework to use better error propagation
                }
            };

            // Continue squeezing challenges based on num_challenges
            let num_challenges = lsb8(&challenge_len_data) as usize;
            challenge_len_data >>= 8;
            for _ in 1..num_challenges {
                match squeeze_challenge_cont(memory, vka_end, challenge_mptr) {
                    Ok(new_challenge_mptr) => {
                        challenge_mptr = new_challenge_mptr;
                    }
                    Err(_) => {
                        return Err(VerifyError::OtherError {
                            message: "Failed to squeeze subsequent challenge.".to_string(),
                        }); // TODO: Rework to use better error propagation
                    }
                };
            }
        }
        challenge_len_data = mload(&memory, challenge_len_ptr as u32)
            .map_err(|e| VerifyError::KeyError {
                message: format!("Unable to read challenge_len_data from memory. Cause: {e}"),
            })?
            .into_u256();
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
    match squeeze_challenge(memory, vka_end, challenge_mptr, hash_mptr) {
        Ok((new_challenge_mptr, new_hash_mptr)) => {
            challenge_mptr = new_challenge_mptr;
            hash_mptr = new_hash_mptr;
        }
        Err(_) => {
            return Err(VerifyError::OtherError {
                message: "Failed to squeeze challenge.".to_string(),
            });
        }
    };

    // nu
    match squeeze_challenge_cont(memory, vka_end, challenge_mptr) {
        Ok(new_challenge_mptr) => {
            challenge_mptr = new_challenge_mptr;
        }
        Err(_) => {
            return Err(VerifyError::OtherError {
                message: "Failed to squeeze subsequent challenge.".to_string(),
            });
        }
    };

    // W
    match write_ec_point_into_memory::<H>(raw_proof, memory, proof_cptr, hash_mptr) {
        Ok((new_proof_cptr, new_hash_mptr)) => {
            proof_cptr = new_proof_cptr;
            hash_mptr = new_hash_mptr;
        }
        Err(e) => {
            return Err(e);
        }
    };

    // mu
    match squeeze_challenge(memory, vka_end, challenge_mptr, hash_mptr) {
        Ok((new_challenge_mptr, new_hash_mptr)) => {
            _ = new_challenge_mptr;
            hash_mptr = new_hash_mptr;
        }
        Err(_) => {
            return Err(VerifyError::OtherError {
                message: "Failed to squeeze challenge.".to_string(),
            });
        }
    };

    // W'
    match write_ec_point_into_memory::<H>(raw_proof, memory, proof_cptr, hash_mptr) {
        Ok((new_proof_cptr, new_hash_mptr)) => {
            _ = new_proof_cptr;
            _ = new_hash_mptr;
        }
        Err(e) => {
            return Err(e);
        }
    };

    Ok(())
}

// TODO:
// Read accumulator from instances
// fn read_accumulator_from_instances() {
// if !mload(memory, 0x0140 + VKA_OFFSET as u32 + 5*0x20).unwrap().into_u256().is_zero() { // Validation needed
//     let num_limbs = mload_u32(memory, 0x0180 + VKA_OFFSET as u32 + 5 * 0x20).unwrap();
//     let num_limb_bits = mload_u32(memory, 0x01a0 + VKA_OFFSET as u32 + 5 * 0x20).unwrap();

//     let cptr = add(instances.offset, mul(mload(0x0200), 0x20));
//     let lhs_y_off = num_limbs * 0x20;
//     let rhs_x_off = lhs_y_off * 2;
//     let rhs_y_off = lhs_y_off * 3;
//     let lhs_x = load_from_proof(raw_proof, cptr).unwrap();
//     let lhs_y = load_from_proof(raw_proof, cptr + lhs_y_off).unwrap();
//     let rhs_x = load_from_proof(raw_proof, cptr + rhs_x_off).unwrap();
//     let rhs_y = load_from_proof(raw_proof, cptr + rhs_y_off).unwrap();
//     for
//         {
//             let cptr_end := add(cptr, mul(0x20, num_limbs))
//             let shift := num_limb_bits
//         }
//         lt(cptr, cptr_end)
//         {}
//     {
//         cptr := add(cptr, 0x20)
//         lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
//         lhs_y := add(lhs_y, shl(shift, calldataload(add(cptr, lhs_y_off))))
//         rhs_x := add(rhs_x, shl(shift, calldataload(add(cptr, rhs_x_off))))
//         rhs_y := add(rhs_y, shl(shift, calldataload(add(cptr, rhs_y_off))))
//         shift := add(shift, num_limb_bits)
//     }

//     success := and(success, eq(mulmod(lhs_y, lhs_y, Q), addmod(mulmod(lhs_x, mulmod(lhs_x, lhs_x, Q), Q), 3, Q)))
//     success := and(success, eq(mulmod(rhs_y, rhs_y, Q), addmod(mulmod(rhs_x, mulmod(rhs_x, rhs_x, Q), Q), 3, Q)))

//     mstore(add(theta_mptr, 0x100), lhs_x)
//     mstore(add(theta_mptr, 0x120), lhs_y)
//     mstore(add(theta_mptr, 0x140), rhs_x)
//     mstore(add(theta_mptr, 0x160), rhs_y)
// }
// }

#[cfg(test)]
mod should;
