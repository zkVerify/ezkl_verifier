use crate::{BYTE_FLAG_BITMASK, G2, PTR_BITMASK};
use crate::{EVMWord, Fq, Fr, U256, errors::FieldError, types::G1};
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

/// Trait for returning a big-endian representation of some object as a `[u8; 32]`.
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

pub(crate) fn read_u256(bytes: &[u8]) -> Result<U256, ()> {
    <&[u8; 32]>::try_from(bytes)
        .map_err(|_| ())
        .map(IntoU256::into_u256)
}

// Parse point in G1.
pub(crate) fn read_g1<H: CurveHooks>(data: &[u8], start: usize) -> Result<G1<H>, ()> {
    if start >= data.len() {
        println!("error1");
        return Err(());
    }
    if data.len() < 64 {
        println!("error2");
        return Err(());
    }

    println!("reading coordinates...");

    println!("start = 0x{:x?}", start);

    let x = Fq::from_be_bytes_mod_order(&data[start..(start + 32)]);
    let y = Fq::from_be_bytes_mod_order(&data[(start + 32)..(start + 64)]);

    println!("x = {}", to_hex_string(&x.into_be_bytes32()));
    println!("y = {}", to_hex_string(&y.into_be_bytes32()));

    // let x = Fq::from_bigint(read_u256(&data[start..(start + 32)])?).ok_or(())?;
    // let y = Fq::from_bigint(read_u256(&data[(start + 32)..(start + 64)])?).ok_or(())?;

    println!("successfully read coordinates!");

    // If (0, 0) is given, we interpret this as the point at infinity:
    // https://docs.rs/ark-ec/0.5.0/src/ark_ec/models/short_weierstrass/affine.rs.html#212-218
    if x == Fq::ZERO && y == Fq::ZERO {
        println!("error3");
        return Ok(G1::zero());
    }

    let point = G1::new_unchecked(x, y);

    // Validate point
    if !point.is_on_curve() {
        println!("error4");
        return Err(());
    }
    // This is always true for G1 with the BN254 curve.
    debug_assert!(point.is_in_correct_subgroup_assuming_on_curve());

    Ok(point)
}

// Parse point in G2.
pub(crate) fn read_g2<H: CurveHooks>(data: &[u8]) -> Result<G2<H>, ()> {
    if data.len() != 128 {
        return Err(());
    }

    // Read in reverse order (i.e., imaginary part before real part) to match
    // Solidity's encoding:
    // https://eips.ethereum.org/EIPS/eip-197#encoding
    let x_c1 = read_fq_util(&data[0..32]).expect("Parsing the SRS should always succeed!");
    let x_c0 = read_fq_util(&data[32..64]).expect("Parsing the SRS should always succeed!");
    let y_c1 = read_fq_util(&data[64..96]).expect("Parsing the SRS should always succeed!");
    let y_c0 = read_fq_util(&data[96..128]).expect("Parsing the SRS should always succeed!");

    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);

    Ok(G2::<H>::new(x, y))
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
pub(crate) fn mload(memory: &[u8], addr: u32) -> Result<EVMWord, ()> {
    memory
        .get(addr as usize..addr as usize + 32)
        .and_then(|s| s.try_into().ok())
        .ok_or(())
}

// TODO: Address edge cases.
// TODO: Also, better name.
pub(crate) fn calldataload(raw_proof: &[u8], addr: u32) -> Result<EVMWord, ()> {
    let idx = addr as usize;
    let slice = raw_proof.get(idx..idx + 0x20).unwrap();
    let evm_word: EVMWord = slice.try_into().unwrap();
    Ok(evm_word)
}

pub(crate) fn u32_from_be_tail(bytes: &EVMWord) -> u32 {
    u32::from_be_bytes(bytes[28..32].try_into().unwrap())
}

// Utility for debugging.
pub(crate) fn to_hex_string(data: &[u8]) -> String {
    let hex_string: String = data.iter().map(|b| format!("{:02x}", b)).collect();
    format!("0x{}", hex_string)
}
