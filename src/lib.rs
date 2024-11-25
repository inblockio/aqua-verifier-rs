//! # Aqua Verifier Rs
//! A Rust implementation for verifying, signing, and managing Aqua chains.
//! 
//! This crate provides functionality for aqua protocol.
//! Focused on handling revisions, signatures, and witnesses.

//! To get started  check aqua_verifier .
//! All sining, witnessing, verification function are implemented under  AquaVerifier struct .
//! To absract cmplexity AquaVerifier implementation are implmented in veirifier.rs which is visible only to this crate

/// Module containing utility functions for the Aqua verifier
pub mod util;

/// Module containing core data models and types
pub mod model;

/// Module implementing core verification logic
pub mod verifier;

/// Module handling blockchain lookup operations
pub mod look_up;

/// Main module containing the AquaVerifier implementation
pub mod aqua_verifier;

/// Module containing test suites
pub mod tests;

// Documentation for AquaVerifier and related types

