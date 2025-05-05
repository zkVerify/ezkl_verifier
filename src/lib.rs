#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

pub mod errors;
pub mod key;
pub mod proof;
mod srs;
mod types;
mod utils;

use ark_bn254_ext::{Config, CurveHooks};
use errors::VerifyError;

pub use types::*;

pub const PROOF_SIZE: usize = 4768;
pub const PUBS_SIZE: usize = 32;
pub const VK_SIZE: usize = 2016; // TODO: REVISE, ALTHOUGH THIS SEEMS TO BE DYNAMIC...

/// A single public input.
pub type PublicInput = [u8; PUBS_SIZE];
pub type Public = [PublicInput];

pub fn verify<H: CurveHooks + Default>(
    raw_vk: &[u8],
    raw_proof: &[u8],
    pubs: &Public,
) -> Result<(), VerifyError> {
    let num_instances = pubs.len();

    Ok(()) // REMOVE
}

#[cfg(test)]
mod should;
