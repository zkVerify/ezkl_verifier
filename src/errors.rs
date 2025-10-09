use alloc::string::String;
use snafu::Snafu;

use crate::{
    U256,
    utils::{IntoBEBytes32, to_hex_string},
};

/// The verification error type
#[derive(Debug, PartialEq, Snafu)]
pub enum VerifyError {
    /// Failure due to another reason.
    #[snafu(display("Other Error: {}", message))]
    OtherError { message: String },
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

#[derive(Debug, PartialEq, Snafu)]
pub enum UtilityError {
    /// Index out of Bounds when trying to read from memory.
    #[snafu(display(
        "mload failed. Attempted to access index: {}, while memory length is: {}",
        index,
        memory_length
    ))]
    MloadError { index: usize, memory_length: usize },
    /// Value in memory exceeds u32::MAX.
    #[snafu(display(
        "mload_u32 failed. Value {} (found at memory index: 0x{:x?}) exceeds u32::MAX",
        to_hex_string(&value.into_be_bytes32()),
        index,
    ))]
    MloadU32Error { value: U256, index: usize },
    /// Index out of Bounds when trying to read from raw proof.
    #[snafu(display(
        "calldataload failed. Attempted to access index: {}, while array length is: {}",
        index,
        raw_proof_length
    ))]
    CallDataLoadError {
        index: usize,
        raw_proof_length: usize,
    },
}

#[derive(Debug, PartialEq, Snafu)]
pub enum GroupError {
    /// Index out of Bounds.
    #[snafu(display(
        "Index Out Of Bounds. Attempted to index: {}, while source length is: {}",
        index,
        source_length
    ))]
    IndexOutOfBounds { index: usize, source_length: usize },
    /// Provided slice is too short.
    InvalidSliceLength {
        actual_length: usize,
        expected_length: usize,
    },
    /// Provided slice is too short.
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
