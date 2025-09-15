// use snafu::Snafu;

// /// Unified enum for handling errors of all flavors.
// #[derive(Debug, PartialEq, Snafu)]
// pub enum ProofError {
//     #[snafu(display(
//         "Incorrect buffer size. Expected: {}; Got: {}",
//         expected_size,
//         actual_size
//     ))]
//     IncorrectBufferSize {
//         expected_size: usize,
//         actual_size: usize,
//     },
//     #[snafu(display(
//         "Invalid slice size. Expected: >= {}; Got: {}",
//         expected_length,
//         actual_length
//     ))]
//     InvalidSliceLength {
//         expected_length: usize,
//         actual_length: usize,
//     },
//     #[snafu(display("Point not on curve"))]
//     PointNotOnCurve,
//     #[snafu(display("Other error: {message:?}"))]
//     OtherError { message: String },
// }
