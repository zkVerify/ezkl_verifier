use ark_bn254_ext::CurveHooks;
use snafu::Snafu;

#[derive(Debug, PartialEq, Snafu)]
pub enum ProofError {
    #[snafu(display(
        "Incorrect buffer size. Expected: {}; Got: {}",
        expected_size,
        actual_size
    ))]
    IncorrectBufferSize {
        expected_size: usize,
        actual_size: usize,
    },

    #[snafu(display(
        "Invalid slice size. Expected: {}; Got: {}",
        expected_length,
        actual_length
    ))]
    InvalidSliceLength {
        expected_length: usize,
        actual_length: usize,
    },

    #[snafu(display("Point for field is not on curve"))]
    PointNotOnCurve,

    // #[snafu(display("Point is not in the correct subgroup"))]
    // PointNotInCorrectSubgroup,
    #[snafu(display("Value is not a member of Fq"))]
    NotMember,

    #[snafu(display("Other error"))]
    OtherError,
}

#[derive(Debug)]
pub struct Proof<H: CurveHooks> {}

impl<H: CurveHooks> TryFrom<&[u8]> for Proof<H> {
    type Error = ProofError;

    fn try_from(proof: &[u8]) -> Result<Self, ProofError> {
        // if proof.len() != PROOF_SIZE {
        //     return Err(ProofError::IncorrectBufferSize {
        //         expected_size: PROOF_SIZE,
        //         actual_size: proof.len(),
        //     });
        // }

        let mut offset = 0;

        let w1 = read_proof_g1::<H>(proof, &mut offset)?;
        let w2 = read_proof_g1::<H>(proof, &mut offset)?;
        let w3 = read_proof_g1::<H>(proof, &mut offset)?;
        let w4 = read_proof_g1::<H>(proof, &mut offset)?;

        let s = read_proof_g1::<H>(proof, &mut offset)?;
        let z = read_proof_g1::<H>(proof, &mut offset)?;
        let z_lookup = read_proof_g1::<H>(proof, &mut offset)?;

        let t1 = read_proof_g1::<H>(proof, &mut offset)?;
        let t2 = read_proof_g1::<H>(proof, &mut offset)?;
        let t3 = read_proof_g1::<H>(proof, &mut offset)?;
        let t4 = read_proof_g1::<H>(proof, &mut offset)?;

        let w1_eval = read_proof_fq(proof, &mut offset)?;
        let w2_eval = read_proof_fq(proof, &mut offset)?;
        let w3_eval = read_proof_fq(proof, &mut offset)?;
        let w4_eval = read_proof_fq(proof, &mut offset)?;

        let s_eval = read_proof_fq(proof, &mut offset)?;
        let z_eval = read_proof_fq(proof, &mut offset)?;
        let z_lookup_eval = read_proof_fq(proof, &mut offset)?;

        let q1_eval = read_proof_fq(proof, &mut offset)?;
        let q2_eval = read_proof_fq(proof, &mut offset)?;
        let q3_eval = read_proof_fq(proof, &mut offset)?;
        let q4_eval = read_proof_fq(proof, &mut offset)?;
        let qm_eval = read_proof_fq(proof, &mut offset)?;
        let qc_eval = read_proof_fq(proof, &mut offset)?;
        let q_arith_eval = read_proof_fq(proof, &mut offset)?;
        let q_sort_eval = read_proof_fq(proof, &mut offset)?;
        let q_elliptic_eval = read_proof_fq(proof, &mut offset)?;
        let q_aux_eval = read_proof_fq(proof, &mut offset)?;

        let sigma1_eval = read_proof_fq(proof, &mut offset)?;
        let sigma2_eval = read_proof_fq(proof, &mut offset)?;
        let sigma3_eval = read_proof_fq(proof, &mut offset)?;
        let sigma4_eval = read_proof_fq(proof, &mut offset)?;

        let table1_eval = read_proof_fq(proof, &mut offset)?;
        let table2_eval = read_proof_fq(proof, &mut offset)?;
        let table3_eval = read_proof_fq(proof, &mut offset)?;
        let table4_eval = read_proof_fq(proof, &mut offset)?;
        let table_type_eval = read_proof_fq(proof, &mut offset)?;

        let id1_eval = read_proof_fq(proof, &mut offset)?;
        let id2_eval = read_proof_fq(proof, &mut offset)?;
        let id3_eval = read_proof_fq(proof, &mut offset)?;
        let id4_eval = read_proof_fq(proof, &mut offset)?;

        let w1_omega_eval = read_proof_fq(proof, &mut offset)?;
        let w2_omega_eval = read_proof_fq(proof, &mut offset)?;
        let w3_omega_eval = read_proof_fq(proof, &mut offset)?;
        let w4_omega_eval = read_proof_fq(proof, &mut offset)?;

        let s_omega_eval = read_proof_fq(proof, &mut offset)?;
        let z_omega_eval = read_proof_fq(proof, &mut offset)?;
        let z_lookup_omega_eval = read_proof_fq(proof, &mut offset)?;

        let table1_omega_eval = read_proof_fq(proof, &mut offset)?;
        let table2_omega_eval = read_proof_fq(proof, &mut offset)?;
        let table3_omega_eval = read_proof_fq(proof, &mut offset)?;
        let table4_omega_eval = read_proof_fq(proof, &mut offset)?;

        let pi_z = read_proof_g1::<H>(proof, &mut offset)?;
        let pi_z_omega = read_proof_g1::<H>(proof, &mut offset)?;

        Ok(Proof::<H> {})
    }
}
