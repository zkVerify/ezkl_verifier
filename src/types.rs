pub use ark_bn254_ext::{Fq, Fq2, Fr, FrConfig};
use ark_bn254_ext::{G1Affine, G2Affine};

pub type U256 = ark_ff::BigInteger256;
pub type G1<H> = G1Affine<H>;
pub type G2<H> = G2Affine<H>;
pub type Bn254<H> = ark_bn254_ext::Bn254<H>;
