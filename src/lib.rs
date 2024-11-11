// #![deny(warnings)]

//! # Aqua Verifier Rs
//! To get started  check aqua_verifier .
//! All sining, witnessing, verification function are implemented under  AquaVerifier struct .
//! To absract cmplexity AquaVerifier implementation are implmented in veirifier.rs which is visible only to this crate

pub mod util;
pub mod model;
pub mod verifier;
pub mod  check_etherscan;
pub mod  aqua_verifier;
pub mod tests;