# AquaChain Verifier Documentation

## Overview
This Rust library implements verification, signing, and management functionality for an AquaChain, the library follows the specification in Aqua Protocol data, https://aqua-protocol.org/ . It provides utilities for handling revisions, signatures, witnesses, and chain management.

## Core Functions

### `verify_revision`
```rust
pub(crate) fn verify_revision(
    revision: Revision,
    verification_platform: String,
    chain: String,
    api_key: String,
) -> RevisionVerificationResult
```
Verifies a single revision in the AquaChain system by performing multiple validation checks:
- File verification
- Content verification
- Metadata verification
- Signature verification (if present)
- Witness verification (if present)

Returns a `RevisionVerificationResult` containing the status of each verification step.

### `verify_signature`
```rust
pub(crate) fn verify_signature(
    signature: RevisionSignature,
    previous_verification_hash: Hash,
) -> ResultStatus
```
Validates a revision signature against a previous verification hash. Returns a `ResultStatus` indicating success or failure.

### `verify_witness`
```rust
pub(crate) fn verify_witness(
    witness: RevisionWitness,
    verification_hash: String,
    do_verify_merkle_proof: bool,
    verification_platform: String,
    chain: String,
    api_key: String,
) -> ResultStatus
```
Verifies a witness record in the chain, including optional Merkle proof verification. Returns a `ResultStatus` with verification details and logs.

### `verify_aqua_chain`
```rust
pub(crate) fn verify_aqua_chain(
    aqua_chain: HashChain,
    verification_platform: String,
    chain: String,
    api_key: String,
) -> RevisionAquaChainResult
```
Performs verification of an entire AquaChain by validating each revision. Returns a comprehensive `RevisionAquaChainResult`.

### `sign_aqua_chain`
```rust
pub(crate) fn sign_aqua_chain(
    mut aqua_chain: PageData,
    revision_content: RevisionContentSignature,
) -> Result<(PageData, Vec<String>), Vec<String>>
```
Signs a revision in the AquaChain using provided signature data. Updates chain state and returns modified chain data with logs.

### `witness_aqua_chain`
```rust
pub(crate) fn witness_aqua_chain(
    mut aqua_chain: PageData,
    witness_input: RevisionWitnessInput,
) -> Result<(PageData, Vec<String>), Vec<String>>
```
Adds witness information to a revision in the chain. Creates Merkle proofs and updates chain state.

### `generate_aqua_chain`
```rust
pub(crate) fn generate_aqua_chain(
    body_bytes: Vec<u8>,
    file_name: String,
    domain_id: String,
) -> Result<PageDataWithLog, Vec<String>>
```
Creates a new AquaChain instance with an initial revision. Handles:
- File size validation (max 20MB)
- Hash generation
- Metadata creation
- Initial chain structure setup

### `delete_revision_in_aqua_chain`
```rust
pub(crate) fn delete_revision_in_aqua_chain(
    aqua_chain: PageData,
    revision_count_for_deletion: i32,
) -> Result<(PageData, Vec<String>), Vec<String>>
```
Removes specified number of revisions from the chain while preserving chain integrity and genesis revision.

## Constants

```rust
const MAX_FILE_SIZE: u32 = 20 * 1024 * 1024; // 20 MB in bytes
```

## Data Types

### Core Types
- `RevisionVerificationResult`: Contains verification results for all aspects of a revision
- `ResultStatus`: Represents the status of a verification operation
- `PageData`: Contains the complete chain data structure
- `HashChain`: Represents a sequence of related revisions
- `Revision`: Individual revision entry in the chain
- `RevisionContent`: Content data for a revision
- `RevisionWitness`: Witness data for blockchain verification
- `RevisionSignature`: Signature data for revision authentication

## Error Handling
The library uses Rust's `Result` type for error handling, with error messages collected in `Vec<String>` for detailed logging and debugging.

## Dependencies
- `sha3`: For cryptographic hash functions
- `chrono`: For timestamp handling
- `ethaddr`: For Ethereum address parsing and validation

## Usage Notes

1. File size limits are enforced (20MB maximum)
2. Genesis revisions cannot be deleted
3. All operations maintain chain integrity through proper hash linking
4. Each operation provides detailed logging for debugging and audit purposes
5. Witness and signature operations require proper cryptographic inputs

## Security Considerations

1. All cryptographic operations use SHA3-512 for hashing
2. Chain integrity is maintained through hash linking
3. Signature verification includes wallet address validation
4. Merkle proofs are used for witness verification
5. All modifications preserve the chain's immutable history

## Best Practices

1. Always verify chain integrity after modifications
2. Maintain proper error handling for all operations
3. Log all operations for audit purposes
4. Validate inputs before chain operations
5. Preserve genesis revision integrity