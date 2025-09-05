// #![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

mod constants;
mod errors;
// mod proof;
mod types;
mod utils;
// mod vk;

use core::num;

use ark_bn254_ext::{CurveHooks, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use sha3::{Digest, Keccak256};

pub use types::*;

extern crate alloc;
extern crate core;
use alloc::{format, string::ToString, vec::Vec};

use crate::{
    constants::{BYTE_FLAG_BITMASK, DELTA, PTR_BITMASK},
    errors::VerifyError,
    utils::{
        IntoBEBytes32, IntoFr, IntoU256, calldataload, lsb8, lsb16, lsb32, mload, read_g1,
        to_hex_string, u32_from_be_tail,
    },
};

pub const PUBS_SIZE: usize = 32;

const PROOF_OFFSET: usize = 0x84; // Offset of proof inside the calldata

/// A single public input.
pub type PublicInput = [u8; PUBS_SIZE];
pub type Public = [PublicInput];

pub fn verify<H: CurveHooks>(
    raw_vka: &[u8],
    raw_proof: &[u8],
    pubs: &Public,
) -> Result<(), VerifyError> {
    // let vk = ...; // Parse VK

    let mut memory = Vec::<u8>::from(&mut [0u8; 64]);

    if raw_vka.len() == 0 || raw_vka.len() & 0x1f != 0 {
        return Err(VerifyError::KeyError {
            message: "vk length must be a positive multiple of 32".to_string(),
        });
    }

    memory.extend_from_slice(&(raw_vka.len() + 5 * 0x20).into_u256().into_be_bytes32());
    memory.extend_from_slice(&[0u8; 32]);
    memory.extend_from_slice(&raw_vka.len().into_u256().into_be_bytes32());
    memory.extend_from_slice(&raw_vka);

    dbg!(memory.len());

    // let public_inputs = &pubs.into_iter().try_fold(Vec::new(), |mut acc, pi_bytes| {
    //     let pi = pi_bytes.into_u256();
    //     if pi < Fr::MODULUS {
    //         acc.push(pi);
    //         Ok(acc)
    //     } else {
    //         Err(format!("Public Input {} exceeds base field modulus", pi))
    //     }
    // })?;

    // // Check valid length of instances
    // if public_inputs.len() != vk.num_instances {
    //     return Err(VerifyError::PublicInputError {
    //         message: format!(
    //             "Number of instances given does not match those in the vk. Got: {}; Expected: {}",
    //             public_inputs.len(),
    //             vk.num_instances
    //         ),
    //     });
    // }

    //
    let success = verify_proof_inner::<H>(&raw_proof, &pubs, &mut memory);

    // TODO: Rescaling Phase

    Ok(())
}

fn verify_proof_inner<H: CurveHooks>(
    raw_proof: &[u8],
    pubs: &Public,
    memory: &mut Vec<u8>,
) -> Result<(), VerifyError> {
    const VKA_OFFSET: usize = 0x0; // Offset inside the VKA file itself
    let mut theta_mptr: usize = 0x0;
    let mut proof_cptr: usize = PROOF_OFFSET;
    let mut num_evals: u32;
    let mut vka_end: usize = 0x0;

    // dbg!(memory);

    {
        // let instance_cptr := instances.offset

        // // Check valid length of proof
        // success := and(success, eq(sub(instance_cptr, 0xa4), proof.length))

        let num_instances = pubs.len();
        let num_instances_in_vka = mload(memory, 0xe0).unwrap().into_u256();
        if num_instances.into_u256() != num_instances_in_vka {
            return Err(VerifyError::PublicInputError {
                message: format!(
                    "Number of instances provided does not match those in the vka. Given: {}; Expected: {}",
                    num_instances, num_instances_in_vka
                ),
            }); // TODO: Replace with Err
        }

        vka_end = u32_from_be_tail(&mload(&memory, 0x40).unwrap()) as usize;
        // println!("0x{:x}", vka_end); // 0xac0

        // copy the vka_digest to the vka_end location
        memory.extend_from_slice(&mload(&memory, (VKA_OFFSET + 0xa0) as u32).unwrap());

        // println!("{:x?}", &memory[0xa0..0xa0 + 32]);

        // Read instances and witness commitments and generate challenges
        let mut hash_mptr = vka_end + 0x20;

        // let proof_cptr := proof.offset
        let mut challenge_mptr = vka_end
            + u32_from_be_tail(&mload(&memory, (VKA_OFFSET + 0xc0) as u32).unwrap()) as usize;
        // Set the theta_mptr (vk_mptr + vk_len + challenges_length)
        theta_mptr = challenge_mptr
            + u32_from_be_tail(&mload(&memory, (VKA_OFFSET + 0x0120) as u32).unwrap()) as usize;

        let mut challenge_len_ptr = VKA_OFFSET + 0xa0 + 0x420;
        let mut challenge_len_data = mload(&memory, challenge_len_ptr as u32)
            .unwrap()
            .into_u256();
        let num_words = challenge_len_data.0[0] & BYTE_FLAG_BITMASK;
        // dbg!(num_words); // 1
        challenge_len_data >>= 8;
        // num_evals is defined as u64 in order to be able to fit all possible u32 values
        let num_evals = u64::from(
            0x20 * u32_from_be_tail(&mload(&memory, (VKA_OFFSET + 0x100) as u32).unwrap()),
        );
        // dbg!(num_evals);

        // let mut instance_cptr_end = instance_cptr + num_instances * 32;
        // while instance_cptr < instance_cptr_end {
        //
        // }
        for instance in pubs {
            if instance.into_u256() >= Fr::MODULUS {
                return Err(VerifyError::PublicInputError {
                    message: format!(
                        "Instance {} exceeds field modulus.",
                        to_hex_string(instance)
                    ),
                });
                // TODO: return Err();
            }
            memory.extend_from_slice(instance);
            hash_mptr += 0x20;
        }

        for _ in 0..num_words {
            //
            challenge_len_ptr += 0x20;
            while !challenge_len_data.is_zero() {
                // add proof_cptr to num advices len
                let proof_cptr_end = proof_cptr + (challenge_len_data.0[0] & PTR_BITMASK) as usize;
                challenge_len_data >>= 16;
                // Phase loop
                while proof_cptr < proof_cptr_end {
                    println!("proof_cptr = 0x{:x?}", proof_cptr);
                    println!("proof_cptr_end = 0x{:x?}", proof_cptr_end);
                    match write_ec_point_into_memory::<H>(raw_proof, memory, proof_cptr, hash_mptr)
                    {
                        Ok((new_proof_cptr, new_hash_mptr)) => {
                            proof_cptr = new_proof_cptr;
                            hash_mptr = new_hash_mptr;
                        }
                        Err(_) => {
                            return Err(VerifyError::OtherError); // TODO: Rework to use better error propagation
                        }
                    };
                }
                println!("Generating challenges...");

                // Generate challenges
                match squeeze_challenge(memory, vka_end, challenge_mptr, hash_mptr) {
                    Ok((new_challenge_mptr, new_hash_mptr)) => {
                        challenge_mptr = new_challenge_mptr;
                        hash_mptr = new_hash_mptr;
                    }
                    Err(_) => {
                        return Err(VerifyError::OtherError); // TODO: Rework to use better error propagation
                    }
                };

                // Continue squeezing challenges based on num_challenges
                let num_challenges = (challenge_len_data.0[0] & BYTE_FLAG_BITMASK) as usize;
                challenge_len_data >>= 8;
                for _ in 1..num_challenges {
                    match squeeze_challenge_cont(memory, vka_end, challenge_mptr) {
                        Ok(new_challenge_mptr) => {
                            challenge_mptr = new_challenge_mptr;
                        }
                        Err(_) => {
                            return Err(VerifyError::OtherError); // TODO: Rework to use better error propagation
                        }
                    };
                }
            }
            challenge_len_data = mload(&memory, challenge_len_ptr as u32)
                .unwrap()
                .into_u256();
        }

        println!("proof_cptr = 0x{:x?}", proof_cptr);

        // Read evaluations
        let proof_cptr_end = proof_cptr + num_evals as usize; // num_evals
        while proof_cptr < proof_cptr_end {
            let start = proof_cptr - PROOF_OFFSET;
            let eval: EVMWord = raw_proof
                .get(start..start + 32)
                .and_then(|s| s.try_into().ok())
                .ok_or(())
                .unwrap(); // TODO: Replace unwrap()
            if eval.into_u256() >= Fr::MODULUS {
                return Err(VerifyError::InvalidProofError {
                    message: format!("Evaluation {} exceeds field modulus.", to_hex_string(&eval)),
                });
            }

            println!("Writing: {} into 0x{:x?}", to_hex_string(&eval), hash_mptr);

            memory[hash_mptr..hash_mptr + 32].copy_from_slice(&eval); // mstore(hash_mptr, eval)
            proof_cptr += 0x20;
            hash_mptr += 0x20;
        }

        // Read batch opening proof and generate challenges
        // Bdfg21
        // zeta
        match squeeze_challenge(memory, vka_end, challenge_mptr, hash_mptr) {
            Ok((new_challenge_mptr, new_hash_mptr)) => {
                challenge_mptr = new_challenge_mptr;
                hash_mptr = new_hash_mptr;
            }
            Err(_) => {
                return Err(VerifyError::OtherError); // TODO: Rework to use better error propagation
            }
        };
        // nu
        match squeeze_challenge_cont(memory, vka_end, challenge_mptr) {
            Ok(new_challenge_mptr) => {
                challenge_mptr = new_challenge_mptr;
            }
            Err(_) => {
                return Err(VerifyError::OtherError); // TODO: Rework to use better error propagation
            }
        };

        // W
        match write_ec_point_into_memory::<H>(raw_proof, memory, proof_cptr, hash_mptr) {
            Ok((new_proof_cptr, new_hash_mptr)) => {
                proof_cptr = new_proof_cptr;
                hash_mptr = new_hash_mptr;
            }
            Err(_) => {
                return Err(VerifyError::OtherError); // TODO: Rework to use better error propagation
            }
        };

        // mu
        match squeeze_challenge(memory, vka_end, challenge_mptr, hash_mptr) {
            Ok((new_challenge_mptr, new_hash_mptr)) => {
                challenge_mptr = new_challenge_mptr;
                hash_mptr = new_hash_mptr;
            }
            Err(_) => {
                return Err(VerifyError::OtherError); // TODO: Rework to use better error propagation
            }
        };

        // W'
        match write_ec_point_into_memory::<H>(raw_proof, memory, proof_cptr, hash_mptr) {
            Ok((new_proof_cptr, new_hash_mptr)) => {
                proof_cptr = new_proof_cptr;
                hash_mptr = new_hash_mptr;
            }
            Err(_) => {
                return Err(VerifyError::OtherError); // TODO: Rework to use better error propagation
            }
        };

        // Read accumulator from instances
        // TODO
    }

    // Compute Lagrange evaluations and instance evaluation
    {
        // Calculate vanishing polynomial numerator
        let k = u32_from_be_tail(&mload(&memory, (VKA_OFFSET + 0x00a0 + 5 * 0x20) as u32).unwrap());

        dbg!(k);

        let x = mload(memory, theta_mptr as u32 + 0x80)
            .map_err(|_| VerifyError::KeyError {
                message: format!(
                    "Failed reading x from memory at address 0x{:x?}",
                    theta_mptr as u32 + 0x80
                ),
            })?
            .into_fr();

        dbg!(x);

        let mut x_n = x;

        dbg!(x_n);

        for _ in 0..k {
            x_n = x_n.square();
        }

        dbg!(x_n);

        // Prepare denominators for Lagrange evaluation
        let omega = mload(memory, (VKA_OFFSET + 0x00e0 + 5 * 0x20) as u32)
            .map_err(|_| VerifyError::KeyError {
                message: format!(
                    "Failed reading omega from memory at address 0x{:x?}",
                    (VKA_OFFSET + 0x00e0 + 5 * 0x20) as u32
                ),
            })?
            .into_fr();
        dbg!(to_hex_string(&omega.into_be_bytes32()));

        let x_n_mptr = theta_mptr + 0x180;
        println!("x_n_mptr = 0x{:x?}", x_n_mptr);
        let mut mptr = x_n_mptr;
        let num_instances =
            u32_from_be_tail(&mload(memory, 0xe0).map_err(|_| VerifyError::KeyError {
                message: format!(
                    "Failed reading num_instances from memory at address 0x{:x?}",
                    0xe0
                ),
            })?);
        let num_neg_lagranges =
            u32_from_be_tail(&mload(memory, 0x0480).map_err(|_| VerifyError::KeyError {
                message: format!(
                    "Failed reading num_neg_lagranges from memory at address 0x{:x?}",
                    0x0480
                ),
            })?);
        let mut mptr_end = mptr + 32 * (num_instances + num_neg_lagranges) as usize;
        println!("mptr_end = 0x{:x?}", mptr_end);
        if num_instances == 0 {
            mptr_end += 0x20;
        }

        let mut pow_of_omega = mload(memory, (VKA_OFFSET + 0x0120 + 5 * 0x20) as u32)
            .map_err(|_| VerifyError::KeyError {
                message: format!(
                    "Failed reading omega_inv_to_l from memory at address 0x{:x?}",
                    (VKA_OFFSET + 0x0120 + 5 * 0x20) as u32
                ),
            })?
            .into_fr();

        dbg!(to_hex_string(&pow_of_omega.into_be_bytes32()));

        while mptr_end >= memory.len() {
            memory.extend_from_slice(&[0u8; 32]);
        }

        while mptr < mptr_end {
            memory[mptr..mptr + 32].copy_from_slice(&(x - pow_of_omega).into_be_bytes32()); // mstore(mptr, addmod(x, sub(R, pow_of_omega),R))

            println!(
                "Wrote: {:x?} at mptr = 0x{:x?}",
                to_hex_string(&(x - pow_of_omega).into_be_bytes32()),
                mptr
            );

            pow_of_omega = pow_of_omega * omega;
            mptr += 0x20;
        }

        let x_n_minus_1 = x_n - Fr::ONE;
        memory[mptr_end..mptr_end + 32].copy_from_slice(&x_n_minus_1.into_be_bytes32()); // mstore(mptr_end, x_n_minus_1)

        dbg!(to_hex_string(&x_n_minus_1.into_be_bytes32()));

        // success := batch_invert(success, x_n_mptr, add(mptr_end, 0x20))
        let mut inverses = (x_n_mptr..mptr_end + 0x20)
            .step_by(0x20)
            .map(|p| mload(memory, p as u32).unwrap().into_fr())
            .collect::<Vec<_>>();

        // println!("x_n_mptr = 0x{:x?}", x_n_mptr);
        // println!("mptr_end + 0x20 = 0x{:x?}", mptr_end + 0x20);
        ark_ff::fields::batch_inversion(&mut inverses);
        for i in 0..inverses.len() {
            memory[(x_n_mptr + i * 0x20)..x_n_mptr + (i + 1) * 0x20]
                .copy_from_slice(&inverses[i].into_be_bytes32());
            println!(
                "Copying: {} into 0x{:x?}",
                to_hex_string(&inverses[i].into_be_bytes32()),
                x_n_mptr + i * 0x20
            );
        }

        println!(
            "=========================================================================================="
        );

        // let mut mptr = x_n_mptr;
        let l_i_common = x_n_minus_1 * mload(memory, 0x0160).unwrap().into_fr();
        println!(
            "l_i_common = {}",
            to_hex_string(&l_i_common.into_be_bytes32())
        );
        let mut pow_of_omega = mload(memory, 0x01c0).unwrap().into_fr();
        for mptr in (x_n_mptr..mptr_end).step_by(0x20) {
            // mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega,R),R))
            let zeta_minus_omega_i_inv = mload(memory, mptr as u32).unwrap().into_fr();
            memory[mptr..mptr + 0x20].copy_from_slice(
                &(l_i_common * zeta_minus_omega_i_inv * pow_of_omega).into_be_bytes32(),
            );
            println!(
                "Storing: {} at 0x{:x?}",
                to_hex_string(
                    &(l_i_common * zeta_minus_omega_i_inv * pow_of_omega).into_be_bytes32()
                ),
                mptr
            );
            pow_of_omega *= omega;
        }

        println!(
            "=========================================================================================="
        );

        let mut l_blind = mload(memory, x_n_mptr as u32 + 0x20).unwrap().into_fr();
        let l_i_cptr_end = x_n_mptr + 0x20 * num_neg_lagranges as usize;
        let mut l_i_cptr = x_n_mptr + 0x40;

        while l_i_cptr < l_i_cptr_end {
            l_blind += mload(memory, l_i_cptr as u32).unwrap().into_fr();
            l_i_cptr += 0x20;
        }

        // println!("0x{:x?}", l_i_cptr);

        println!(
            "=========================================================================================="
        );

        let mut instance_eval = Fr::ZERO;
        for instance in pubs {
            instance_eval += mload(memory, l_i_cptr as u32).unwrap().into_fr() * instance.into_fr();
            l_i_cptr += 0x20;
        }
        // for
        //     {
        //         let instance_cptr := instances.offset
        //         let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances))
        //     }
        //     lt(instance_cptr, instance_cptr_end)
        //     {
        //         instance_cptr := add(instance_cptr, 0x20)
        //         l_i_cptr := add(l_i_cptr, 0x20)
        //     }
        // {
        //     instance_eval := addmod(instance_eval, mulmod(mload(l_i_cptr), calldataload(instance_cptr),R),R)
        // }

        println!(
            "=========================================================================================="
        );

        let x_n_minus_1_inv = mload(memory, mptr_end as u32).unwrap().into_fr();
        let l_last = mload(memory, x_n_mptr as u32).unwrap().into_fr();
        let l_0 = mload(memory, x_n_mptr as u32 + 0x20 * num_neg_lagranges)
            .unwrap()
            .into_fr();

        // mstore(x_n_mptr, x_n)
        memory[x_n_mptr..x_n_mptr + 0x20].copy_from_slice(&x_n.into_be_bytes32());
        println!(
            "Storing x_n = {} into 0x{:x?}",
            to_hex_string(&x_n.into_be_bytes32()),
            x_n_mptr
        );
        // mstore(add(theta_mptr, 0x1a0), x_n_minus_1_inv)
        let mut start = theta_mptr + 0x1a0;
        memory[start..start + 0x20].copy_from_slice(&x_n_minus_1_inv.into_be_bytes32());
        println!(
            "Storing x_n_minus_1_inv = {} into 0x{:x?}",
            to_hex_string(&x_n_minus_1_inv.into_be_bytes32()),
            start
        );
        // mstore(add(theta_mptr, 0x1c0), l_last)
        start += 0x20;
        memory[start..start + 0x20].copy_from_slice(&l_last.into_be_bytes32());
        println!(
            "Storing l_last = {} into 0x{:x?}",
            to_hex_string(&l_last.into_be_bytes32()),
            start
        );
        // mstore(add(theta_mptr, 0x1e0), l_blind)
        start += 0x20;
        memory[start..start + 0x20].copy_from_slice(&l_blind.into_be_bytes32());
        println!(
            "Storing l_blind = {} into 0x{:x?}",
            to_hex_string(&l_blind.into_be_bytes32()),
            start
        );
        // mstore(add(theta_mptr, 0x200), l_0)
        start += 0x20;
        memory[start..start + 0x20].copy_from_slice(&l_0.into_be_bytes32());
        println!(
            "Storing l_0 = {} into 0x{:x?}",
            to_hex_string(&l_0.into_be_bytes32()),
            start
        );
        // mstore(add(theta_mptr, 0x220), instance_eval)
        start += 0x20;
        memory[start..start + 0x20].copy_from_slice(&instance_eval.into_be_bytes32());
        println!(
            "Storing instance_eval = {} into 0x{:x?}",
            to_hex_string(&instance_eval.into_be_bytes32()),
            start
        );
    }

    // println!(
    //     "{:?}",
    //     to_hex_string(
    //         raw_proof
    //             .get(0x0324 - PROOF_OFFSET..0x0324 - PROOF_OFFSET + 0x20)
    //             .unwrap()
    //     )
    // );

    // Compute quotient evaluation
    {
        let mut quotient_eval_numer = Fr::ONE;
        let y = mload(memory, theta_mptr as u32 + 0x60).unwrap().into_fr();

        // println!("y = {}", to_hex_string(&y.into_be_bytes32()));
        {
            // Gate computations/expression evaluations.
            let gate_computations_len_offset = VKA_OFFSET + 0x0340 + 5 * 0x20;
            let (mut computations_ptr, computations_len) =
                soa_layout_metadata(memory, gate_computations_len_offset);

            println!("computations_ptr = 0x{:x?}", computations_ptr);
            println!("computations_len = 0x{:x?}", computations_len);
            let mut expressions_word = mload(memory, computations_ptr as u32).unwrap().into_u256();
            let mut last_idx: usize;

            println!(
                "expressions_word = {}",
                to_hex_string(&expressions_word.into_be_bytes32())
            );

            // Load in the total number of code blocks from the vk constants, right after the number of= challenges
            // for { let code_block := 0 } lt(code_block, computations_len) { code_block := add(code_block, 0x20) } {
            for code_block in (0..computations_len).step_by(0x20) {
                dbg!(code_block);

                // call expression_evals to evaluate the expressions in the code block
                (computations_ptr, expressions_word, last_idx) = expression_evals_packed(
                    memory,
                    raw_proof,
                    vka_end,
                    computations_ptr,
                    &mut expressions_word,
                )
                .unwrap();

                // At the end of each code block we update `quotient_eval_numer`
                // If this is the first code block, we set `quotient_eval_numer` to the last var in the code block
                match code_block {
                    0 => {
                        quotient_eval_numer = mload(memory, (vka_end + last_idx) as u32)
                            .unwrap()
                            .into_fr()
                    }
                    1 => {
                        // Otherwise we add the last var in the code block to `quotient_eval_numer` mod r
                        quotient_eval_numer = quotient_eval_numer * y
                            + mload(memory, (vka_end + last_idx) as u32)
                                .unwrap()
                                .into_fr();
                    }
                    _ => {
                        // Invalid code_block value
                        return Err(VerifyError::InvalidProofError {
                            message: format!("Invalid code_block value {code_block}"),
                        });
                    }
                }

                println!(
                    "quotient_eval_numer = {}",
                    to_hex_string(&quotient_eval_numer.into_be_bytes32())
                );
            }
        }
        {
            println!(
                "=========================================================================================="
            );

            // Permutation computations
            let mut permutation_z_evals_ptr =
                u32_from_be_tail(&mload(memory, 0x0360 + VKA_OFFSET as u32 + 5 * 0x20).unwrap());
            let mut permutation_z_evals =
                mload(memory, permutation_z_evals_ptr).unwrap().into_u256(); // TODO: REVISIT TYPE!!!
            // Last idx of permutation evals == permutation_evals.len() - 1
            let last_idx = lsb8(&permutation_z_evals);

            println!("permutation_z_evals_ptr = 0x{:x?}", permutation_z_evals_ptr);
            println!(
                "permutation_z_evals = {}",
                to_hex_string(&permutation_z_evals.into_be_bytes32())
            );
            println!("last_idx = 0x{:x?}", last_idx);

            permutation_z_evals >>= 8;
            // Num of words scaled by 0x20 that take up each permutation eval (permutation_z_eval + column evals)
            // first and second LSG bytes contain the number of words for all of the permutation evals except the last.
            // The third and fourth LSG bytes contain the number of words for the last permutation eval
            let num_words = lsb32(&permutation_z_evals);
            permutation_z_evals >>= 32;
            permutation_z_evals_ptr += 0x20;
            permutation_z_evals = mload(memory, permutation_z_evals_ptr).unwrap().into_u256();
            let l_0 = mload(memory, theta_mptr as u32 + 0x200).unwrap().into_fr();

            println!(
                "permutation_z_evals = {}",
                to_hex_string(&permutation_z_evals.into_be_bytes32())
            );
            println!("l_0 = {}", to_hex_string(&l_0.into_be_bytes32()));
            {
                // Get the first and second LSG bytes from the first permutation_z_evals word to load in (z, _, _)
                let idx = lsb16(&permutation_z_evals) as u32;
                let eval = l_0
                    - l_0
                        * calldataload(raw_proof, idx - PROOF_OFFSET as u32)
                            .unwrap()
                            .into_fr();
                quotient_eval_numer = quotient_eval_numer * y + eval;

                println!("eval = {}", to_hex_string(&eval.into_be_bytes32()));
                println!(
                    "quotient_eval_numer = {}",
                    to_hex_string(&quotient_eval_numer.into_be_bytes32())
                );
            }

            {
                // Load in the last permutation_z_evals word
                let perm_z_last_ptr = last_idx * (num_words & PTR_BITMASK as usize)
                    + permutation_z_evals_ptr as usize;

                println!("perm_z_last_ptr = 0x{:x?}", perm_z_last_ptr);

                let idx = lsb16(&mload(memory, perm_z_last_ptr as u32).unwrap().into_u256()) as u32;
                // let slice = raw_proof.get(idx..idx + 0x20).unwrap();
                // let eval_bytes: [u8; 32] = slice.try_into().unwrap();
                // let perm_z_last = eval_bytes.into_fr(); // calldataload(lsb16(&mload(memory, perm_z_last_ptr as u32).unwrap().into_u256()));

                // TODO: Maybe it's a good idea to move the "- PROOF_OFFSET" part inside the calldataload function?
                let perm_z_last = calldataload(raw_proof, idx - PROOF_OFFSET as u32)
                    .unwrap()
                    .into_fr();

                println!(
                    "perm_z_last = {}",
                    to_hex_string(&perm_z_last.into_be_bytes32())
                );

                quotient_eval_numer = quotient_eval_numer * y
                    + mload(memory, theta_mptr as u32 + 0x1C0).unwrap().into_fr()
                        * (perm_z_last * perm_z_last - perm_z_last);

                println!(
                    "quotient_eval_numer = {}",
                    to_hex_string(&quotient_eval_numer.into_be_bytes32())
                );

                let lhs = mload(memory, theta_mptr as u32 + 0x20).unwrap().into_fr();
                let rhs = mload(memory, theta_mptr as u32 + 0x80).unwrap().into_fr();
                memory[vka_end..vka_end + 0x20].copy_from_slice(&(lhs * rhs).into_be_bytes32());

                println!(
                    "Storing: {} at 0x{:x?}",
                    to_hex_string(&(lhs * rhs).into_be_bytes32()),
                    vka_end
                );

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
        }
        {
            // lookup computations
            // mstore(vka_end, mload(add(theta_mptr, 0x1C0)))
            let value = &mload(&memory, theta_mptr as u32 + 0x1c0).unwrap();
            memory[vka_end..vka_end + 0x20].copy_from_slice(value); // l_last
            // mstore(add(0x20, vka_end), mload(add(theta_mptr, 0x200)))
            let value = &mload(memory, theta_mptr as u32 + 0x200).unwrap();
            memory[(vka_end + 0x20)..(vka_end + 0x40)].copy_from_slice(value); // l_0
            // mstore(add(0x40, vka_end), mload(add(theta_mptr, 0x1E0)))
            let value = &mload(memory, 0x1e0).unwrap();
            memory[(vka_end + 0x40)..(vka_end + 0x60)].copy_from_slice(value); // l_blind
            // mstore(add(0x60, vka_end), mload(theta_mptr))
            let value = &mload(memory, theta_mptr as u32).unwrap();
            memory[(vka_end + 0x60)..(vka_end + 0x80)].copy_from_slice(value); // theta
            // mstore(add(0x80, vka_end), mload(add(theta_mptr, 0x20)))
            let value = &mload(memory, theta_mptr as u32 + 0x20).unwrap();
            memory[(vka_end + 0x80)..(vka_end + 0xa0)].copy_from_slice(value); // beta
            let (mut evals_ptr, meta_data) =
                soa_layout_metadata(memory, 0x380 + VKA_OFFSET + 5 * 0x20);

            // lookup meta data contains 32 byte flags for indicating if we need to do a lookup table lines
            // expression evaluation or we can use the previous one cached in the table var.
            if meta_data != 0 {
                todo!("Restore this code on the second pass")
                // let mut table: U256;
                // let end_ptr = meta_data as u64 & PTR_BITMASK;
                // let mv = (meta_data >> 16) as u64 & BYTE_FLAG_BITMASK;
                // match mv {
                //     0x0 => {
                //         while evals_ptr < end_ptr {
                //             evals_ptr, table, quotient_eval_numer = mv_lookup_evals(table, evals_ptr, quotient_eval_numer, y);
                //         }
                //     },
                //     0x1 => {
                //         // mstore(add(0xA0, vka_end), mload(add(theta_mptr, 0x40)))
                //         memory[vka_end..vka_end + 0xa0].copy_from_slice(mload(memory, theta_mptr + 0x40)); // gamma
                //         while evals_ptr < end_ptr {
                //             evals_ptr, table, quotient_eval_numer = lookup_evals(table, evals_ptr, quotient_eval_numer, y);
                //         }
                //     },
                //     _ => { return Err(VerifyError::KeyError { message: format!("Unsupported value for mv. Got: {mv}") }); }
                // }
            }
        }

        // mstore(add(theta_mptr, 0x240), mulmod(quotient_eval_numer, mload(add(theta_mptr, 0x1a0)), R))
        let idx = theta_mptr + 0x240;
        let val = quotient_eval_numer * mload(memory, theta_mptr as u32 + 0x1a0).unwrap().into_fr();
        memory[idx..(idx + 0x20)].copy_from_slice(&val.into_be_bytes32());

        println!(
            "Writing: {} at 0x{:x?}",
            to_hex_string(&val.into_be_bytes32()),
            idx
        );
    }

    // Compute quotient commitment
    {
        println!("=================================================================");
        println!("\t\t Compute Quotient Commitment \t\t");
        println!("=================================================================");

        let first_quotient_x_cptr = 0x0320 + VKA_OFFSET + 5 * 0x20; // 0x3c0
        let last_quotient_x_cptr = 0x0300 + VKA_OFFSET + 5 * 0x20; // 0x03a0
        let bytes = calldataload(
            raw_proof,
            u32_from_be_tail(&mload(memory, last_quotient_x_cptr as u32).unwrap())
                - PROOF_OFFSET as u32,
        )
        .unwrap();
        // mstore(vka_end, calldataload(mload(0x03a0)))
        memory[vka_end..(vka_end + 0x20)].copy_from_slice(&bytes);

        println!("Just wrote: {} at 0x{:x?}", to_hex_string(&bytes), vka_end);

        // mstore(add(0x20, vka_end), calldataload(add(mload(0x03a0), 0x20)))
        let bytes = calldataload(
            raw_proof,
            u32_from_be_tail(&mload(memory, last_quotient_x_cptr as u32).unwrap()) + 0x20
                - PROOF_OFFSET as u32,
        )
        .unwrap();
        memory[(vka_end + 0x20)..(vka_end + 0x40)].copy_from_slice(&bytes);

        println!("Just wrote: {} at 0x{:x?}", to_hex_string(&bytes), vka_end);

        let x_n = mload(memory, theta_mptr as u32 + 0x180).unwrap().into_fr();

        println!("x_n = {}", to_hex_string(&x_n.into_be_bytes32()));

        // CORRECT UP TO THIS POINT...

        // for
        //     {
        //         let cptr := sub(mload(0x03a0), 0x40)
        //         let cptr_end := sub(mload(0x03c0), 0x40)
        //     }
        //     lt(cptr_end, cptr)
        //     {}
        // {
        let mut cptr =
            u32_from_be_tail(&mload(memory, last_quotient_x_cptr as u32).unwrap()) - 0x40;
        let cptr_end =
            u32_from_be_tail(&mload(memory, first_quotient_x_cptr as u32).unwrap()) - 0x40;
        while cptr_end < cptr {
            ec_mul_acc::<H>(memory, &x_n).map_err(|_| VerifyError::OtherError)?; // TODO: Replace with better Error variant

            println!("Now reading point at 0x{:x?}...", cptr);

            let x = Fq::from_be_bytes_mod_order(
                // TODO: DOUBLE-CHECK FOR CORRECTNESS
                &calldataload(raw_proof, cptr - PROOF_OFFSET as u32).unwrap(),
            );
            let y = Fq::from_be_bytes_mod_order(
                // TODO: DOUBLE-CHECK FOR CORRECTNESS
                &calldataload(raw_proof, cptr + 0x20 - PROOF_OFFSET as u32).unwrap(),
            );
            ec_add_acc::<H>(memory, &x, &y).map_err(|_| VerifyError::OtherError)?; // TODO: Replace with better Error variant
            cptr -= 0x40;
        }
        // mstore(add(theta_mptr, 0x260), mload(vka_end))
        let bytes = mload(memory, vka_end as u32).unwrap();
        memory[(theta_mptr + 0x260)..(theta_mptr + 0x260 + 0x20)].copy_from_slice(&bytes);

        println!(
            "Wrote: {} at 0x{:x?}",
            to_hex_string(&bytes),
            theta_mptr + 0x260
        );

        // mstore(add(theta_mptr, 0x280), mload(add(0x20, vka_end)))
        let bytes = mload(&memory, vka_end as u32 + 0x20).unwrap();
        memory[(theta_mptr + 0x280)..(theta_mptr + 0x280 + 0x20)].copy_from_slice(&bytes);

        println!(
            "Wrote: {} at 0x{:x?}",
            to_hex_string(&bytes),
            theta_mptr + 0x280
        );
    }

    // Compute pairing lhs and rhs
    // {
    //     // point_computations
    //     let pcs_ptr := u32_from_be_tail(&mload(memory, 0x03a0 + VKA_OFFSET + 5 * 0x20).unwrap()); // 0x0440
    //     {
    //         let point_computations := mload(pcs_ptr)
    //         let x := mload(add(theta_mptr, 0x80))
    //         let omega := mload(0x0180)
    //         let omega_inv := mload(0x01a0)
    //         let x_pow_of_omega := mulmod(x, omega, R)
    //         x_pow_of_omega, pcs_ptr := point_rots(point_computations, pcs_ptr, 8, x_pow_of_omega, omega, vka_end)
    //         pcs_ptr := add(pcs_ptr, 0x20)
    //         point_computations := mload(pcs_ptr)
    //         // Store interm point
    //         mstore(add(and(point_computations, PTR_BITMASK), vka_end), x)
    //         x_pow_of_omega := mulmod(x, omega_inv, R)
    //         point_computations := shr(16, point_computations)
    //         x_pow_of_omega, pcs_ptr := point_rots(point_computations, pcs_ptr, 24, x_pow_of_omega, omega_inv, vka_end)
    //         pcs_ptr := add(pcs_ptr, 0x20)
    //         pop(x_pow_of_omega)
    //     }
    // }

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
) -> Result<(usize, usize), ()> {
    // ret0, ret1, ret2 {
    let point = read_g1::<H>(proof, proof_cptr - PROOF_OFFSET)?;
    // Ensure hash_mptr + 0x20 is not out of bounds
    while hash_mptr + 0x20 >= memory.len() {
        println!("Extend");
        memory.extend_from_slice(&[0u8; 32]);
    }

    println!(
        "Copying: {:x?} into 0x{:x}",
        to_hex_string(&point.x().expect("Should succeed").into_be_bytes32()),
        hash_mptr
    );
    println!(
        "Copying: {:x?} into 0x{:x}",
        to_hex_string(&point.y().expect("Should succeed").into_be_bytes32()),
        hash_mptr + 0x20
    );

    memory[hash_mptr..hash_mptr + 0x20]
        .copy_from_slice(&point.x().expect("Should succeed").into_be_bytes32());
    memory[(hash_mptr + 0x20)..(hash_mptr + 0x40)]
        .copy_from_slice(&point.y().expect("Should succeed").into_be_bytes32());

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

    // println!("Hashing: {:x?}", to_hex_string(&memory[start..end]));
    println!("length = {}", &memory[start..end].len());

    let hash: [u8; 32] = Keccak256::new()
        .chain_update(&memory[start..end])
        .finalize()
        .into();

    println!("hash = {:x?}", to_hex_string(&hash));

    memory[vka_end..vka_end + 0x20].copy_from_slice(&hash); // mstore(vka_end, hash)
    while challenge_mptr >= memory.len() {
        println!("Extend");
        memory.extend_from_slice(&[0u8; 32]);
    }

    println!(
        "hash (mod r) = {:x?}",
        to_hex_string(&hash.into_fr().into_be_bytes32())
    );

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
        println!("sub-Extend");
        memory.extend_from_slice(&[0u8; 32]);
    }
    memory[challenge_mptr..challenge_mptr + 0x20]
        .copy_from_slice(&hash.into_fr().into_be_bytes32()); // mstore(challenge_mptr, mod(hash, R))

    Ok(challenge_mptr + 0x20)
}

// Returns start of computations ptr and length of SoA layout memory
// encoding for quotient evaluation data (gate, permutation and lookup computations)
fn soa_layout_metadata(memory: &[u8], offset: usize) -> (usize, usize) {
    let computations_len_ptr = u32_from_be_tail(&mload(memory, offset as u32).unwrap());
    (
        computations_len_ptr as usize + 0x20,
        u32_from_be_tail(&mload(memory, computations_len_ptr).unwrap()) as usize,
    )
}

fn expression_evals_packed(
    memory: &mut [u8],
    raw_proof: &[u8],
    fsmp: usize,
    code_ptr: usize,
    expressions_word: &U256,
) -> Result<(usize, U256, usize), ()> {
    // Load in the least significant byte of the `expressions_word` word to get the total number of words we will need to load in.
    let num_words_shift_up_one = (0x20 * lsb8(expressions_word) + 0x20) as u32;

    println!("num_words_shift_up_one = 0x{:x?}", num_words_shift_up_one);

    let mut expressions_word = *expressions_word;

    println!("fsmp = 0x{:x?}", fsmp);

    println!(
        "expressions_word = {}",
        to_hex_string(&expressions_word.into_be_bytes32())
    );

    // start of the expression encodings
    expressions_word >>= 8;

    let mut acc: u32 = 0;
    let mut ret0: usize = 0;
    for i in (0x20..num_words_shift_up_one).step_by(0x20) {
        while !expressions_word.is_zero() {
            println!(
                "expressions_word = {}",
                to_hex_string(&expressions_word.into_be_bytes32())
            );

            let mstore_ptr = fsmp + acc as usize;

            println!("mstore_ptr = 0x{:x?}", mstore_ptr);

            // Load in the least significant byte of the `expression` word to get the operation type
            // Then determine which operation to peform and then store the result in the next available memory slot.
            match lsb8(&expressions_word) {
                // 0x00 => Advice/Fixed expression
                0x00 => {
                    expressions_word >>= 8;
                    // Load the calldata ptr from the expression, which come from the 2nd and 3rd least significant bytes.
                    let idx = lsb16(&expressions_word) - PROOF_OFFSET; // (expressions_word.0[0] & PTR_BITMASK) as usize - PROOF_OFFSET;
                    memory[mstore_ptr..mstore_ptr + 0x20]
                        .copy_from_slice(&raw_proof.get(idx..idx + 0x20).unwrap());

                    println!("Opcode: 0x00");
                    println!(
                        "\nWriting: {} to 0x{:x?}\n",
                        to_hex_string(&raw_proof.get(idx..idx + 0x20).unwrap()),
                        mstore_ptr
                    );

                    // Move to the next expression
                    expressions_word >>= 16;
                }
                // 0x01 => Negated expression
                0x01 => {
                    expressions_word >>= 8;
                    // Load the memory ptr from the expression, which come from the 2nd and 3rd least significant bytes
                    let idx = lsb16(&expressions_word) - PROOF_OFFSET; // (expressions_word.0[0] & PTR_BITMASK) as usize - PROOF_OFFSET;
                    let temp = &mload(memory, idx as u32)
                        .unwrap()
                        .into_fr()
                        .neg_in_place()
                        .into_be_bytes32();

                    println!("Opcode: 0x01");
                    println!(
                        "\nWriting: {} to 0x{:x?}\n",
                        to_hex_string(temp),
                        mstore_ptr
                    );

                    memory[mstore_ptr..mstore_ptr + 0x20].copy_from_slice(temp);
                    // mstore(mstore_ptr, sub(R, mload(expressions_word.0[0] & PTR_BITMASK)))
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
                    let rhs = mload(
                        memory,
                        lsb16(&(expressions_word >> 16)) as u32, // ((*expressions_word >> 16).0[0] & PTR_BITMASK) as u32,
                    )
                    .unwrap()
                    .into_fr();

                    println!("Opcode: 0x02");
                    println!(
                        "\nWriting sum: {} to 0x{:x?}\n",
                        to_hex_string(&(lhs + rhs).into_be_bytes32()),
                        mstore_ptr
                    );

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

                    println!("Opcode: 0x03");
                    println!(
                        "\nWriting product: {} to 0x{:x?}\n",
                        to_hex_string(&(lhs * rhs).into_be_bytes32()),
                        mstore_ptr
                    );

                    memory[mstore_ptr..mstore_ptr + 0x20]
                        .copy_from_slice(&(lhs * rhs).into_be_bytes32());
                    // Move to the next expression
                    expressions_word >>= 32;
                }
                // TODO: RESTORE!
                // 0x04 => (For lookup expressions) Start accumulator evaluations for the lookup (table or input)
                // Will always occur at the end of the last word of the lookup expression.
                // 0x04 => {
                //     return Ok(lookup_input_accum(
                //         memory,
                //         expressions_word,
                //         // fsmp,
                //         i as usize,
                //         code_ptr,
                //     ));
                // }
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

    println!("{}", to_hex_string(&expressions_word.into_be_bytes32()));
    println!("0x{:x?}", ret2);

    Ok((ret0, ret1, ret2))
}

fn lookup_input_accum(
    memory: &[u8],
    expressions_word: &U256,
    // fsmp: usize,
    i: usize,
    code_ptr: usize,
) -> (usize, U256, Fr) {
    let mut ret0: usize = 0;
    let ret1: U256;
    let ret2: Fr;
    let mut expressions_word = *expressions_word;
    expressions_word >>= 8;
    // Number of words the mptr vars for the accumulator evaluations shifted up by one
    let num_words_vars = 0x20 * lsb8(&expressions_word); // 0x20 * expressions_word.0[0] & BYTE_FLAG_BITMASK;
    expressions_word >>= 8;
    // initlaize the accumulator with the first value in the vars
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
    // for { let j } lt(j, num_words_vars) { j := add(j, 0x20) } {
    for j in (0..num_words_vars).step_by(0x20) {
        // for {  } expressions_word { } {
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

    (ret0, ret1, ret2)
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

    println!(
        "======================================== z_evals ========================================"
    );
    println!(
        "num_words_packed = {}",
        to_hex_string(&num_words_packed.into_be_bytes32())
    );
    println!("num_words = 0x{:x?}", num_words);

    let mut quotient_eval_numer = quotient_eval_numer;
    let mut z = z.clone();
    let mut permutation_z_evals_ptr = permutation_z_evals_ptr;

    println!(
        "quotient_eval_numer = {}",
        to_hex_string(&quotient_eval_numer.into_be_bytes32())
    );
    println!("z = {}", to_hex_string(&z.into_be_bytes32()));
    println!("permutation_z_evals_ptr = 0x{:x?}", permutation_z_evals_ptr);

    // Initialize the free static memory pointer to store the column evals.
    let ptr = u32_from_be_tail(&mload(memory, 0x40).unwrap());
    let idx = ptr as usize + 0x20;
    let val = ptr + 0x40;
    memory[idx..idx + 0x20].copy_from_slice(&val.into_u256().into_be_bytes32());

    println!(
        "Writing {} at 0x{:x?}",
        to_hex_string(&val.into_u256().into_be_bytes32()),
        idx
    );

    // Iterate through the tuple window length ( permutation_z_evals_len.len() - 1 ) offset by one word.
    // for { } lt(permutation_z_evals_ptr, perm_z_last_ptr) { } {
    while permutation_z_evals_ptr < perm_z_last_ptr {
        let next_z_ptr = permutation_z_evals_ptr + num_words;

        println!("next_z_ptr = 0x{:x?}", next_z_ptr);

        let z_j = mload(memory, next_z_ptr as u32).unwrap().into_u256();

        println!("z_j = {}", to_hex_string(&z_j.into_be_bytes32()));

        // let idx1 = lsb16(&z_j);
        // let slice1 = raw_proof.get(idx1..idx1 + 0x20).unwrap();
        // let lhs_bytes: [u8; 32] = slice1.try_into().unwrap();

        let lhs = calldataload(raw_proof, (lsb16(&z_j) - PROOF_OFFSET) as u32)
            .unwrap()
            .into_fr();

        println!("lhs = {}", to_hex_string(&lhs.into_be_bytes32()));

        // let idx2 = lsb16(&(z >> 32));
        // let slice2 = raw_proof.get(idx2..idx2 + 0x20).unwrap();
        // let rhs_bytes: [u8; 32] = slice2.try_into().unwrap();

        let rhs = calldataload(raw_proof, (lsb16(&(z >> 32)) - PROOF_OFFSET) as u32)
            .unwrap()
            .into_fr();

        println!("rhs = {}", to_hex_string(&rhs.into_be_bytes32()));

        // let temp = lhs - rhs;
        quotient_eval_numer = quotient_eval_numer * y + l_0 * (lhs - rhs);

        println!(
            "quotient_eval_numer = {}",
            to_hex_string(&quotient_eval_numer.into_be_bytes32())
        );

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

        println!("permutation_z_evals_ptr = 0x{:x?}", permutation_z_evals_ptr);
        println!("z = {}", to_hex_string(&z.into_be_bytes32()));
    }

    println!("===============================================================================");
    println!("EXIT LOOP!!!");
    println!("===============================================================================");

    // Due to the fact that permutation_columns.len() in H2 might not be divisible by permutation_chunk_len, the last column length might be less than permutation_chunk_len
    // We store this length in the last 16 bits of the num_words_packed word.
    num_words = lsb16(&(*num_words_packed >> 16));

    println!("num_words = 0x{:x?}", num_words);

    col_evals(
        memory,
        raw_proof,
        z,
        num_words,
        permutation_z_evals_ptr,
        theta_mptr,
    );

    // iterate through col_evals to update the quotient_eval_numer accumulator
    let temp = u32_from_be_tail(&mload(memory, 0x40).unwrap()) + 0x20;
    let end_ptr = u32_from_be_tail(&mload(memory, temp).unwrap()) as usize;
    let start = u32_from_be_tail(&mload(memory, 0x40).unwrap()) as usize + 0x40;
    for j in (start..end_ptr).step_by(0x20) {
        quotient_eval_numer = quotient_eval_numer * y + mload(memory, j as u32).unwrap().into_fr();
    }

    println!(
        "Return quotient_eval_numer = {}",
        to_hex_string(&quotient_eval_numer.into_be_bytes32())
    );

    quotient_eval_numer
}

fn col_evals(
    memory: &mut [u8],
    raw_proof: &[u8],
    z: U256,
    num_words: usize,
    permutation_z_evals_ptr: usize,
    theta_mptr: usize,
) {
    println!(
        "======================================== col_evals ========================================"
    );

    let mut z = z;
    let gamma = mload(memory, theta_mptr as u32 + 0x40).unwrap().into_fr();
    let beta = mload(memory, theta_mptr as u32 + 0x20).unwrap().into_fr();
    // let x = mload(memory, theta_mptr as u32 + 0x80).unwrap().into_fr();
    let l_last = mload(memory, theta_mptr as u32 + 0x1c0).unwrap().into_fr();
    let l_blind = mload(memory, theta_mptr as u32 + 0x1e0).unwrap().into_fr();
    let i_eval = mload(memory, theta_mptr as u32 + 0x220).unwrap().into_fr();

    println!("gamma = {}", to_hex_string(&gamma.into_be_bytes32()));
    println!("beta = {}", to_hex_string(&beta.into_be_bytes32()));
    // println!("x = {}", to_hex_string(&x.into_be_bytes32()));
    println!("l_last = {}", to_hex_string(&l_last.into_be_bytes32()));
    println!("l_blind = {}", to_hex_string(&l_blind.into_be_bytes32()));
    println!("i_eval = {}", to_hex_string(&i_eval.into_be_bytes32()));

    // Extract the index 1 and index 0 z evaluations from the z word.
    // let idx1 = lsb16(&(z >> 16));
    // let lhs_slice = raw_proof.get(idx1..idx1 + 0x20).unwrap();
    // let lhs_bytes: [u8; 32] = lhs_slice.try_into().unwrap();
    // let mut lhs = lhs_bytes.into_fr();
    let mut lhs = calldataload(raw_proof, (lsb16(&(z >> 16)) - PROOF_OFFSET) as u32)
        .unwrap()
        .into_fr();

    // let idx2 = lsb16(&z);
    // let rhs_slice = raw_proof.get(idx2..idx2 + 0x20).unwrap();
    // let rhs_bytes: [u8; 32] = rhs_slice.try_into().unwrap();
    // let mut rhs = rhs_bytes.into_fr();
    let mut rhs = calldataload(raw_proof, (lsb16(&z) - PROOF_OFFSET) as u32)
        .unwrap()
        .into_fr();

    println!("lhs = {}", to_hex_string(&lhs.into_be_bytes32()));
    println!("rhs = {}", to_hex_string(&rhs.into_be_bytes32()));

    z >>= 48;
    // loop through the word_len_chunk
    // for { let j := 0 } lt(j, num_words) { j := add(j, 0x20) } {
    for j in (0..num_words).step_by(0x20) {
        // for { } z { } {
        while !z.is_zero() {
            let mut eval = i_eval;

            if lsb8(&z) == 0x00 {
                // let idx = lsb16(&(z >> 8));
                // let slice = raw_proof.get(idx..idx + 0x20).unwrap();
                // let eval_bytes: [u8; 32] = slice.try_into().unwrap();
                // eval = eval_bytes.into_fr();
                eval = calldataload(raw_proof, (lsb16(&(z >> 8)) - PROOF_OFFSET) as u32)
                    .unwrap()
                    .into_fr();
                println!("[IF] eval = {}", to_hex_string(&eval.into_be_bytes32()));
            }

            println!("z is now: {}", to_hex_string(&z.into_be_bytes32()),);
            println!("eval is now: {}", to_hex_string(&eval.into_be_bytes32()));

            // lhs := mulmod(lhs, addmod(addmod(eval, mulmod(beta, calldataload(and(shr(24, z), PTR_BITMASK)), R), R), gamma, R), R)
            lhs = lhs
                * (eval
                    + beta
                        * calldataload(raw_proof, (lsb16(&(z >> 24)) - PROOF_OFFSET) as u32)
                            .unwrap()
                            .into_fr()
                    + gamma);

            println!("LHS = {}", to_hex_string(&lhs.into_be_bytes32()));

            // rhs := mulmod(rhs, addmod(addmod(eval, mload(mload(0x40)), R), gamma, R), R)
            rhs = rhs
                * (eval
                    + mload(memory, u32_from_be_tail(&mload(memory, 0x40).unwrap()))
                        .unwrap()
                        .into_fr()
                    + gamma);

            println!("RHS = {}", to_hex_string(&rhs.into_be_bytes32()));

            z >>= 40;

            println!("Right shifting z...");
            println!("z is now: {}", to_hex_string(&z.into_be_bytes32()));

            // mstore(mload(0x40), mulmod(mload(mload(0x40)), DELTA, R))
            let idx = u32_from_be_tail(&mload(memory, 0x40).unwrap()) as usize;
            let val = DELTA
                * mload(memory, u32_from_be_tail(&mload(memory, 0x40).unwrap()))
                    .unwrap()
                    .into_fr();
            memory[idx..idx + 0x20].copy_from_slice(&val.into_be_bytes32());

            println!(
                "Storing {} at 0x{:x?}",
                to_hex_string(&val.into_be_bytes32()),
                idx
            );
        }
        z = mload(memory, (permutation_z_evals_ptr + j + 0x20) as u32)
            .unwrap()
            .into_u256();

        println!("Loaded {} into z", to_hex_string(&z.into_be_bytes32()));
    }
    let left_sub_right = lhs - rhs;

    println!(
        "left_sub_right = {}",
        to_hex_string(&left_sub_right.into_be_bytes32())
    );

    let fsm_ptr = u32_from_be_tail(
        &mload(
            memory,
            u32_from_be_tail(&mload(memory, 0x40 as u32).unwrap()) + 0x20,
        )
        .unwrap(),
    ) as usize;

    println!("fsm_ptr = 0x{:x?}", fsm_ptr);

    let val = left_sub_right - left_sub_right * (l_last + l_blind);
    memory[fsm_ptr..fsm_ptr + 0x20].copy_from_slice(&val.into_be_bytes32());

    println!(
        "Storing: {} at 0x{:x?}",
        to_hex_string(&val.into_be_bytes32()),
        fsm_ptr
    );

    let idx = u32_from_be_tail(&mload(memory, 0x40).unwrap()) as usize + 0x20;
    memory[idx..idx + 0x20].copy_from_slice(&(fsm_ptr + 0x20).into_u256().into_be_bytes32());

    println!(
        "Storing: {} at 0x{:x?}",
        to_hex_string(&(fsm_ptr + 0x20).into_u256().into_be_bytes32()),
        idx
    );
}

// TODO: Re-assess types of ret0, ret1, ret2; also for expression_evals_packed
// fn lookup_expr_evals_packed(fsmp, code_ptr, expressions_word, mv) -> Result<(usize, U256, Fr), ()> {
//     // expression evaluation.
//     let (ret0, ret1, ret2: Fr) = expression_evals_packed(memory, raw_proof, fsmp, code_ptr, expressions_word)?;
//     if mv != 0 {
//         // add the beta accum addmod if mv lookup
//         ret2 = addmod(ret2, mload(memory, (u32_from_be_tail(mload(memory, 0x40).unwrap()) + 0x80)), R)
//     }
// }

// fn mv_lookup_evals(memory: &mut [u8], raw_proof: &[u8], table: U256, mut evals_ptr: usize, quotient_eval_numer: Fr, y: Fr) -> ret0, ret1, ret2 {
//     // iterate through the input_tables_len
//     let evals = mload(memory, evals_ptr as u32).unwrap().into_be_bytes32();
//     // We store a boolean flag in the first LSG byte of the evals ptr to determine if we need to load in a new table or reuse the previous table.
//     let new_table = lsb8(&evals);
//     evals >>= 8;
//     let phi = lsb16(evals);
//     let tmp = calldataload(raw_proof, phi as u32 - PROOF_OFFSET);
//     // quotient_eval_numer := addmod(
//     //     mulmod(quotient_eval_numer * y, R),
//     //     mulmod(mload(add(0x20, mload(0x40))), calldataload(phi), R),
//     //     R
//     // )
//     quotient_eval_numer = quotient_eval_numer * y
//         + mload(memory, 0x20 + u32_from_be_tail(mload(memory, 0x40).unwrap())).unwrap().into_fr() * tmp;
//     // quotient_eval_numer := addmod(
//     //     mulmod(quotient_eval_numer, y, R),
//     //     mulmod(mload(mload(memory, 0x40).unwrap), tmp, R),
//     //     R
//     // )
//     quotient_eval_numer = quotient_eval_numer * y
//         + mload(memory, u32_from_be_tail(mload(memory, 0x40).unwrap())).unwrap().into_fr() * tmp;
//     // load in the lookup_table_lines from the evals_ptr
//     evals_ptr += 0x20;
//     // Due to the fact that lookups can share the previous table, we can cache it for reuse.
//     let input_expression = mload(memory, evals_ptr as u32).unwrap();
//     if new_table != 0 {
//         evals_ptr, input_expression, table = lookup_expr_evals_packed(add(0xa0, mload(0x40)), evals_ptr, mload(evals_ptr), 0x1)
//     }
//     // outer inputs len, stored in the first input expression word
//     let outer_inputs_len := and(input_expression, PTR_BITMASK)
//     input_expression := shr(16, input_expression)
//     // shift up the inputs iterator by the free static memory offset of 0xa0
//     for { let j := add(0xa0, mload(0x40)) } lt(j, add(outer_inputs_len, add(0xa0, mload(0x40)))) { j := add(j, 0x20) } {
//         // call the expression_evals function to evaluate the input_lines
//         let ident
//         evals_ptr, input_expression, ident := lookup_expr_evals_packed(j, evals_ptr, input_expression, 0x1)
//         // store ident in free static memory
//         mstore(j, ident)
//     }
//     let lhs
//     let rhs
//     switch eq(outer_inputs_len, 0x20)
//     case 1 {
//         rhs := table
//     } default {
//         // iterate through the outer_inputs_len
//         let last_idx := sub(outer_inputs_len, 0x20)
//         for { let i := 0 } lt(i, outer_inputs_len) { i := add(i, 0x20) } {
//             let tmp := mload(add(0xa0, mload(0x40)))
//             let j := 0x20
//             if eq(i, 0){
//                 tmp := mload(add(0xc0, mload(0x40)))
//                 j := 0x40
//             }
//             for { } lt(j, outer_inputs_len) { j := add(j, 0x20) } {
//                 if eq(i, j) {
//                     continue
//                 }
//                 tmp := mulmod(tmp, mload(add(j, add(0xa0, mload(0x40)))), R)

//             }
//             rhs := addmod(rhs, tmp, R)
//             if eq(i, last_idx) {
//                 rhs := mulmod(rhs, table, R)
//             }
//         }
//     }
//     let tmp := mload(add(0xa0, mload(0x40)))
//     for { let j := 0x20 } lt(j, outer_inputs_len) { j := add(j, 0x20) } {
//         tmp := mulmod(tmp, mload(add(j, add(0xa0, mload(0x40)))), R)
//     }
//     rhs := addmod(
//         rhs,
//         sub(R, mulmod(calldataload(and(shr(32, evals), PTR_BITMASK)), tmp, R)),
//         R
//     )
//     lhs := mulmod(
//         mulmod(table, tmp, R),
//         addmod(calldataload(and(shr(16, evals), PTR_BITMASK)), sub(R, calldataload(phi)), R),
//         R
//     )
//     quotient_eval_numer := addmod(
//         mulmod(quotient_eval_numer, y, R),
//         mulmod(
//             addmod(
//                 1,
//                 sub(R, addmod(mload(add(0x40, mload(0x40))), mload(mload(0x40)), R)),
//                 R
//             ),
//             addmod(lhs, sub(R, rhs), R),
//             R
//         ),
//         R
//     )
//     ret0 := evals_ptr
//     ret1 := table
//     ret2 := quotient_eval_numer
// }

// function lookup_evals(table, evals_ptr, quotient_eval_numer, y) -> ret0, ret1, ret2 {
//     // iterate through the input_tables_len
//     let evals := mload(evals_ptr)
//     // We store a boolean flag in the first LSG byte of the evals ptr to determine if we need to load in a new table or reuse the previous table.
//     let new_table := and(evals, BYTE_FLAG_BITMASK)
//     evals := shr(8, evals)
//     let z := and(evals, PTR_BITMASK)
//     evals := shr(16, evals)
//     quotient_eval_numer := addmod(
//         mulmod(quotient_eval_numer, y, R),
//         addmod(
//             mload(add(0x20, mload(0x40))),
//             mulmod(
//                 mload(add(0x20, mload(0x40))),
//                 sub(R, calldataload(z)),
//                 R
//             ),
//             R
//         ),
//         R
//     )
//     quotient_eval_numer := addmod(
//         mulmod(quotient_eval_numer, y, R),
//         mulmod(
//             mload(mload(0x40)),
//             addmod(
//                 mulmod(calldataload(z), calldataload(z), R),
//                 sub(R, calldataload(z)),
//                 R
//             ),
//             R
//         ),
//         R
//     )
//     // load in the lookup_table_lines from the evals_ptr
//     evals_ptr := add(evals_ptr, 0x20)
//     // Due to the fact that lookups can share the previous table, we can cache it for reuse.
//     let input_expression := mload(evals_ptr)
//     if new_table {
//         evals_ptr, input_expression, table := lookup_expr_evals_packed(add(0xc0, mload(0x40)), evals_ptr, mload(evals_ptr), 0x0)
//     }
//     // call the expression_evals function to evaluate the input_lines
//     let input
//     evals_ptr, input_expression, input := lookup_expr_evals_packed(add(0xc0, mload(0x40)), evals_ptr, input_expression, 0x0)
//     let p_input := and(shr(16, evals), PTR_BITMASK)
//     let p_table := and(shr(48, evals), PTR_BITMASK)
//     quotient_eval_numer := addmod(
//         mulmod(quotient_eval_numer, y, R),
//         mulmod(
//             addmod(
//                 1,
//                 sub(R, addmod(mload(add(0x40, mload(0x40))), mload(mload(0x40)), R)),
//                 R
//             ),
//             addmod(
//                 mulmod(
//                     calldataload(and(evals, PTR_BITMASK)),
//                     mulmod(
//                         addmod(calldataload(p_input), mload(add(0x80, mload(0x40))), R),
//                         addmod(calldataload(p_table), mload(add(0xa0, mload(0x40))), R),
//                         R
//                     ),
//                     R
//                 ),
//                 sub(
//                     R,
//                     mulmod(
//                         calldataload(z),
//                         mulmod(addmod(input, mload(add(0x80, mload(0x40))), R), addmod(table, mload(add(0xa0, mload(0x40))), R), R),
//                         R
//                     )
//                 ),
//                 R
//             ),
//             R
//         ),
//         R
//     )
//     quotient_eval_numer := addmod(
//         mulmod(quotient_eval_numer, y, R),
//         mulmod(mload(add(0x20, mload(0x40))), addmod(calldataload(p_input), sub(R, calldataload(p_table)), R), R),
//         R
//     )
//     quotient_eval_numer := addmod(
//         mulmod(quotient_eval_numer, y, R),
//         mulmod(
//             addmod(
//                 1,
//                 sub(R, addmod(mload(add(0x40, mload(0x40))), mload(mload(0x40)), R)), R),
//                 mulmod(
//                     addmod(calldataload(p_input), sub(R, calldataload(p_table)), R),
//                     addmod(calldataload(p_input), sub(R, calldataload(and(shr(32, evals), PTR_BITMASK))), R),
//                     R
//                 ),
//             R
//         ),
//         R
//     )
//     ret0 := evals_ptr
//     ret1 := table
//     ret2 := quotient_eval_numer
// }

// Scale point at (0x00, 0x20) by scalar.
fn ec_mul_acc<H: CurveHooks>(memory: &mut [u8], scalar: &Fr) -> Result<(), ()> {
    println!("\nec_mul_acc invoked:");

    let vka_end = u32_from_be_tail(&mload(memory, 0x40).unwrap());
    let point = read_g1::<H>(&memory, vka_end as usize)
        .unwrap()
        .into_group(); // This might be incorrect...

    println!("Scalar = {}", to_hex_string(&scalar.into_be_bytes32()));

    println!("point.x = {}", to_hex_string(&point.x.into_be_bytes32()));
    println!("point.y = {}", to_hex_string(&point.y.into_be_bytes32()));

    let res = (point * scalar).into_affine();
    // mstore(add(0x40, vka_end), scalar)
    // ret := and(success, staticcall(gas(), 0x07, vka_end, 0x60, vka_end, 0x40))
    let vka_end = vka_end as usize;
    memory[vka_end..vka_end + 0x20]
        .copy_from_slice(&res.x().expect("Should succeed").into_be_bytes32());
    memory[(vka_end + 0x20)..(vka_end + 0x40)]
        .copy_from_slice(&res.y().expect("Should succeed").into_be_bytes32());

    println!("Scalar Product:");
    println!(
        "res.x = {} written at 0x{:x?}",
        to_hex_string(&res.x.into_be_bytes32()),
        vka_end
    );
    println!(
        "res.y = {} written at 0x{:x?}",
        to_hex_string(&res.y.into_be_bytes32()),
        vka_end + 0x20
    );

    Ok(())
}

// Add (x, y) into point at (0x00, 0x20).
// Return updated (success).
fn ec_add_acc<H: CurveHooks>(memory: &mut [u8], x: &Fq, y: &Fq) -> Result<(), ()> {
    println!("\nec_add_acc invoked:");

    let vka_end = u32_from_be_tail(&mload(memory, 0x40).unwrap());
    // mstore(add(0x40, vka_end), x)
    // mstore(add(0x60, vka_end), y)
    // ret := and(success, staticcall(gas(), 0x06, vka_end, 0x80, vka_end, 0x40))

    println!("G1 Point at vka_end = 0x{:x?}", vka_end);
    let point1 = read_g1::<H>(&memory, vka_end as usize)
        .unwrap()
        .into_group(); // This might be incorrect...

    println!("point1.x = {}", to_hex_string(&point1.x.into_be_bytes32()));
    println!("point1.y = {}", to_hex_string(&point1.y.into_be_bytes32()));

    let point2 = G1::<H>::new_unchecked(*x, *y);

    println!("Other G1 point:");
    println!("point2.x = {}", to_hex_string(&point2.x.into_be_bytes32()));
    println!("point2.y = {}", to_hex_string(&point2.y.into_be_bytes32()));

    // Validate point
    if !point2.is_on_curve() {
        return Err(());
    }

    let res = (point1 + point2).into_affine();

    let vka_end = vka_end as usize;
    memory[vka_end..vka_end + 0x20]
        .copy_from_slice(&res.x().expect("Should succeed").into_be_bytes32());
    memory[(vka_end + 0x20)..(vka_end + 0x40)]
        .copy_from_slice(&res.y().expect("Should succeed").into_be_bytes32());

    println!("Sum of points:");
    println!(
        "res.x = {} written at 0x{:x?}",
        to_hex_string(&res.x.into_be_bytes32()),
        vka_end
    );
    println!(
        "res.y = {} written at 0x{:x?}",
        to_hex_string(&res.y.into_be_bytes32()),
        vka_end + 0x20
    );

    Ok(())
}

#[cfg(test)]
mod should;
