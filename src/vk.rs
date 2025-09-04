use ark_bn254_ext::CurveHooks;
use ark_bn254_ext::Fr;
use snafu::Snafu;

use crate::U256;
use crate::utils::IntoU256;
use crate::{G1, G2};
use alloc::vec::Vec;

#[derive(Debug, PartialEq, Snafu)]
pub enum VerificationKeyError {
    #[snafu(display("Buffer too short"))]
    BufferTooShort,

    #[snafu(display(
        "Slice length is too short. Expected: >= {min_expected_length:?}; Got: {actual_length:?}",
    ))]
    SliceTooShort {
        min_expected_length: usize,
        actual_length: usize,
    },

    #[snafu(display("Point for field '{field:?}' is not on curve"))]
    PointNotOnCurve { field: &'static str },

    // #[snafu(display("Point for field '{}' is not in the correct subgroup", field))]
    // PointNotInCorrectSubgroup { field: &'static str },
    #[snafu(display("Invalid circuit type. Expected: 2"))]
    InvalidCircuitType,

    #[snafu(display("Invalid circuit size"))]
    InvalidCircuitSize,

    #[snafu(display("Invalid number of public inputs"))]
    InvalidNumberOfPublicInputs,

    #[snafu(display("Invalid commitment field: {value:?}"))]
    InvalidCommitmentField { value: String },

    #[snafu(display("Invalid commitments number. Expected: 23"))]
    InvalidCommitmentsNumber,

    #[snafu(display("Invalid commitment key encountered"))]
    InvalidCommitmentKey,

    #[snafu(display("Unexpected commitment key: {key:?}. Expected: {expected:?}"))]
    UnexpectedCommitmentKey { key: String, expected: String },

    #[snafu(display("Recursion is not supported"))]
    RecursionNotSupported,

    #[snafu(display("TBD"))]
    TBD,
}

#[derive(PartialEq, Eq, Debug)]
pub struct VerificationKey<H: CurveHooks> {
    pub vk_digest: [u8; 32],
    pub fsm: [u8; 32], // Is this needed though?
    pub num_instances: u32,
    pub num_evals: u32,
    pub challenges_offset: [u8; 32],
    pub k: u32,
    pub omega: Fr,
    pub omega_inv: Fr,
    pub omega_inv_to_l: Fr,
    pub has_accumulator: bool,
    pub acc_offset: usize,
    pub num_acc_limbs: u32,
    pub num_acc_limb_bits: u32,
    pub g1: G1<H>, // SRS
                   // pub g2: G2<H>, // also SRS
                   // pub neg_s_g2: G2<H>,
                   // pub last_quotient_x_cptr: usize,
                   // pub first_quotient_x_cptr: usize,
                   // pub gate_computations_len_offset: usize,
                   // pub permutation_computations_len_offset: usize,
                   // pub lookup_computations_len_offset: usize,
                   // pub pcs_computations_len_offset: usize,
                   // pub rescaling_computations_len_offset: usize,
                   // pub num_neg_lagranges: u32,
                   // pub num_advices_user_challenges: Vec<U256>,
                   // pub fixed_comms: Vec<G1<H>>,
                   // pub permutation_comms: Vec<G1<H>>,
                   // // Quotient Evaluation
                   // pub gate_computations_length: u32,
                   // pub packed_expression_words: Vec<U256>,
                   // pub permutation_meta_data: U256, // ???
                   // pub permutation_data: Vec<U256>,
                   // pub meta_data_of_lookup_computations: U256, // ???
                   // // PCS Computations
                   // pub point_computations: Vec<U256>,         // ???
                   // pub vanishing_computations: Vec<U256>,     // ???
                   // pub coeff_computations: Vec<U256>,         // ???
                   // pub normalized_coeff_computations: U256,   // ???
                   // pub r_evals_computations: Vec<U256>,       // ???
                   // pub coeff_sums_computations: Vec<U256>,    // ???
                   // pub r_eval_computations: U256,             // ???
                   // pub pairing_input_computations: Vec<U256>, // ???
                   // pub rescaling_computations: Vec<U256>,     // ???
}

impl<H: CurveHooks> TryFrom<&[u8]> for VerificationKey<H> {
    type Error = VerificationKeyError;

    fn try_from(raw_vk: &[u8]) -> Result<Self, Self::Error> {
        let (vk_digest, raw_vk) =
            get_bytes32(raw_vk).map_err(|_| VerificationKeyError::SliceTooShort {
                min_expected_length: 32,
                actual_length: raw_vk.len(),
            })?;
        let (fsm, raw_vk) =
            get_bytes32(raw_vk).map_err(|_| VerificationKeyError::SliceTooShort {
                min_expected_length: 32,
                actual_length: raw_vk.len(),
            })?;

        let (num_instances, raw_vk) =
            get_u32(raw_vk).map_err(|_| VerificationKeyError::SliceTooShort {
                min_expected_length: 32,
                actual_length: raw_vk.len(),
            })?;

        let (num_evals, raw_vk) =
            get_u32(raw_vk).map_err(|_| VerificationKeyError::SliceTooShort {
                min_expected_length: 32,
                actual_length: raw_vk.len(),
            })?;

        let (challenges_offset, raw_vk) =
            get_bytes32(raw_vk).map_err(|_| VerificationKeyError::SliceTooShort {
                min_expected_length: 32,
                actual_length: raw_vk.len(),
            })?;

        let (k, raw_vk) = get_u32(raw_vk).map_err(|_| VerificationKeyError::SliceTooShort {
            min_expected_length: 32,
            actual_length: raw_vk.len(),
        })?;

        // const OFFSET_AFTER_COMMITMENTS: usize = 1713;
        // if raw_vk.len() < OFFSET_AFTER_COMMITMENTS + 2 {
        //     return Err(VerificationKeyError::BufferTooShort);
        // }

        // let (circuit_type, raw_vk) = match read_u32(raw_vk) {
        //     Ok((2, raw_vk)) => (2, raw_vk),
        //     _ => Err(VerificationKeyError::InvalidCircuitType)?,
        // };

        // // Q: Given that we do post-processing of the circuit size when forming a PreparedVerificationKey,
        // // does that enable us to drop the condition of circuit_size it being a power of 2???
        // let (circuit_size, raw_vk) = match read_u32(raw_vk) {
        //     Ok((circuit_size, raw_vk)) => {
        //         if !circuit_size.is_power_of_two() || circuit_size > 2u32.pow(MAX_LOG2_CIRCUIT_SIZE)
        //         {
        //             Err(VerificationKeyError::InvalidCircuitSize)?
        //         } else {
        //             (circuit_size, raw_vk)
        //         }
        //     }
        //     _ => Err(VerificationKeyError::InvalidCircuitSize)?,
        // };

        // let (num_public_inputs, raw_vk) =
        //     read_u32(raw_vk).map_err(|_| VerificationKeyError::InvalidNumberOfPublicInputs)?; // TODO

        // let (_num_commitments, raw_vk) = match read_u32(raw_vk) {
        //     Ok((23u32, raw_vk)) => (23u32, raw_vk),
        //     _ => Err(VerificationKeyError::InvalidCommitmentsNumber)?,
        // };

        // let (id_1, raw_vk) = read_commitment(&CommitmentField::ID_1, raw_vk)?;
        // let (id_2, raw_vk) = read_commitment(&CommitmentField::ID_2, raw_vk)?;
        // let (id_3, raw_vk) = read_commitment(&CommitmentField::ID_3, raw_vk)?;
        // let (id_4, raw_vk) = read_commitment(&CommitmentField::ID_4, raw_vk)?;
        // let (q_1, raw_vk) = read_commitment(&CommitmentField::Q_1, raw_vk)?;
        // let (q_2, raw_vk) = read_commitment(&CommitmentField::Q_2, raw_vk)?;
        // let (q_3, raw_vk) = read_commitment(&CommitmentField::Q_3, raw_vk)?;
        // let (q_4, raw_vk) = read_commitment(&CommitmentField::Q_4, raw_vk)?;
        // let (q_arithmetic, raw_vk) = read_commitment(&CommitmentField::Q_ARITHMETIC, raw_vk)?;
        // let (q_aux, raw_vk) = read_commitment(&CommitmentField::Q_AUX, raw_vk)?;
        // let (q_c, raw_vk) = read_commitment(&CommitmentField::Q_C, raw_vk)?;
        // let (q_elliptic, raw_vk) = read_commitment(&CommitmentField::Q_ELLIPTIC, raw_vk)?;
        // let (q_m, raw_vk) = read_commitment(&CommitmentField::Q_M, raw_vk)?;
        // let (q_sort, raw_vk) = read_commitment(&CommitmentField::Q_SORT, raw_vk)?;
        // let (sigma_1, raw_vk) = read_commitment(&CommitmentField::SIGMA_1, raw_vk)?;
        // let (sigma_2, raw_vk) = read_commitment(&CommitmentField::SIGMA_2, raw_vk)?;
        // let (sigma_3, raw_vk) = read_commitment(&CommitmentField::SIGMA_3, raw_vk)?;
        // let (sigma_4, raw_vk) = read_commitment(&CommitmentField::SIGMA_4, raw_vk)?;
        // let (table_1, raw_vk) = read_commitment(&CommitmentField::TABLE_1, raw_vk)?;
        // let (table_2, raw_vk) = read_commitment(&CommitmentField::TABLE_2, raw_vk)?;
        // let (table_3, raw_vk) = read_commitment(&CommitmentField::TABLE_3, raw_vk)?;
        // let (table_4, raw_vk) = read_commitment(&CommitmentField::TABLE_4, raw_vk)?;
        // let (table_type, raw_vk) = read_commitment(&CommitmentField::TABLE_TYPE, raw_vk)?;

        // // debug_assert_eq!(offset, OFFSET_AFTER_COMMITMENTS);

        // let (contains_recursive_proof, _raw_vk) = match read_bool(raw_vk) {
        //     Ok((false, raw_vk)) => (false, raw_vk),
        //     _ => Err(VerificationKeyError::RecursionNotSupported)?,
        // };

        // let recursive_proof_indices = 0;

        // // Note: Since we originally went back by one, I think we can skip the following:

        // // offset = raw_vk.len() - 1;
        // // let _is_recursive_circuit = read_bool_and_check(
        // //     raw_vk,
        // //     &mut offset,
        // //     false,
        // //     VerificationKeyError::RecursionNotSupported,
        // // )?;

        // Ok(VerificationKey::<H> {
        //     circuit_type,
        //     circuit_size,
        //     num_public_inputs,
        //     q_1,
        //     q_2,
        //     q_3,
        //     q_4,
        //     q_m,
        //     q_c,
        //     q_arithmetic,
        //     q_aux,
        //     q_elliptic,
        //     q_sort,
        //     sigma_1,
        //     sigma_2,
        //     sigma_3,
        //     sigma_4,
        //     table_1,
        //     table_2,
        //     table_3,
        //     table_4,
        //     table_type,
        //     id_1,
        //     id_2,
        //     id_3,
        //     id_4,
        //     contains_recursive_proof,
        //     recursive_proof_indices,
        // })
    }
}

fn get_u256(bytes: &[u8]) -> Result<U256, ()> {
    <&[u8; 32]>::try_from(bytes)
        .map_err(|_| ())
        .map(IntoU256::into_u256)
}

fn get_u32(bytes: &[u8]) -> Result<(u32, &[u8]), ()> {
    let out = get_u256(&bytes[..32])?;
    if out < U256::from(u32::MAX) {
        let mut data = [0u8; 4];
        data.copy_from_slice(&bytes[28..32]);
        Ok((u32::from_be_bytes(data), &bytes[32..]))
    } else {
        Err(())
    }
}

fn get_bytes32(bytes: &[u8]) -> Result<(&[u8], &[u8]), ()> {
    if bytes.len() < 32 {
        return Err(());
    }

    Ok(bytes.split_at(32))
}
