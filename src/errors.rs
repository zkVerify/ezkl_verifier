use alloc::string::String;
use snafu::Snafu;

/// The verification error type
#[derive(Debug, PartialEq, Snafu)]
pub enum VerifyError {
    /// Failure due to another reason.
    #[snafu(display("Other Error"))]
    OtherError,
    /// Provided data has not valid public inputs.
    #[snafu(display("Invalid public input: {}", message))]
    PublicInputError { message: String },
    /// Provided data has not valid proof.
    #[snafu(display("Invalid Proof"))]
    InvalidProofError { message: String },
    /// Verify proof failed.
    #[snafu(display("Verification Failed"))]
    VerificationError,
    /// Provided an invalid verification key.
    #[snafu(display("Key Error: {}", message))]
    KeyError { message: String },
}

#[derive(Debug, PartialEq)]
pub enum GroupError {
    InvalidSliceLength {
        actual_length: usize,
        expected_length: usize,
    },
    NotOnCurve,
}

#[derive(Debug, PartialEq)]
pub enum FieldError {
    InvalidSliceLength {
        actual_length: usize,
        expected_length: usize,
    },
    NotMember,
}
