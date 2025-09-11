use ark_ff::MontFp;

use crate::Fr;

pub(crate) const PTR_BITMASK: u64 = 0xFFFF;
pub(crate) const BYTE_FLAG_BITMASK: u64 = 0xFF;
pub(crate) const DELTA: Fr =
    MontFp!("4131629893567559867359510883348571134090853742863529169391034518566172092834");
