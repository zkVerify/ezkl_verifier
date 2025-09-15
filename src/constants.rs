use crate::{Fr, U256};
use ark_ff::MontFp;

pub(crate) const PTR_BITMASK: u64 = 0xFFFF;
pub(crate) const BYTE_FLAG_BITMASK: u64 = 0xFF;
pub(crate) const DELTA: Fr =
    MontFp!("4131629893567559867359510883348571134090853742863529169391034518566172092834");
pub(crate) const MAX_U32: U256 = U256::new([u32::MAX as u64, 0, 0, 0]);
