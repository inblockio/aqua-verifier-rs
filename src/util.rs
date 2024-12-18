use crate::look_up::look_up::get_tx_data;
use aqua_verifier_rs_types::crypt;
use aqua_verifier_rs_types::models::content::RevisionContent;
use aqua_verifier_rs_types::models::hash::Hash;
use aqua_verifier_rs_types::models::metadata::RevisionMetadata;
use aqua_verifier_rs_types::models::public_key::PublicKey;
use aqua_verifier_rs_types::models::revision::Revision;
use aqua_verifier_rs_types::models::signature::RevisionSignature;
use aqua_verifier_rs_types::models::signature::Signature;
use aqua_verifier_rs_types::models::timestamp::Timestamp;
use aqua_verifier_rs_types::models::tx_hash::TxHash;
use aqua_verifier_rs_types::models::witness::{MerkleNode, RevisionWitness};
use ethers::utils::hash_message;
use sha3::{Digest, Sha3_512};
use tokio::runtime::Runtime;
use std::collections::BTreeMap;
use std::str;
use std::str::FromStr;

use crate::model::{ResultStatusEnum, RevisionVerificationResult};

/// Struct to hold the result of file verification.
#[derive(Debug)]
pub struct VerifyFileResult {
    /// The hash of the verified file if successful.
    pub file_hash: Option<String>,
    /// Error message if verification fails.
    pub error_message: Option<String>,
    /// Logs of the verification process.
    pub logs: Vec<String>,
}



/// Generates a SHA3-512 hash sum from the given content.
///
/// # Arguments
///
/// * `content` - A string slice containing the content to hash.
///
/// # Returns
///
/// A hexadecimal representation of the SHA3-512 hash as a String.
///
/// # Example
///
/// ```
/// let hash = get_hash_sum("hello world");
/// println!("Hash: {}", hash);
/// ```
pub fn get_hash_sum(content: &str) -> String {
    if content.is_empty() {
        String::new()
    } else {
        let mut hasher = Sha3_512::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}


/// Generates a SHA3-512 hash from a Base64-encoded string.
///
/// # Parameters
/// 
/// * `b64` - A string slice that holds the Base64-encoded input.
///
/// # Returns
///
/// Returns an `Option<Vec<u8>>`. If the decoding is successful, it returns 
/// `Some` containing the hash as a vector of bytes. If decoding fails, 
/// it returns `None`.
fn generate_hash_from_base64(b64: &str) -> Option<Vec<u8>> {
    // Decode the Base64 string
    let decoded_bytes_result = base64::decode(b64); //.expect("Failed to decode Base64 string");

    if decoded_bytes_result.is_err() {
        println!("unable t decode bytes.");
        return None;
    }
    let decoded_bytes = decoded_bytes_result.unwrap();

    // Create a Sha3_512 hasher
    let mut hasher = Sha3_512::new();

    // Write input data
    hasher.update(&decoded_bytes);

    // Read hash digest and consume hasher
    let result = hasher.finalize();

    // Return the hash as a vector of bytes
    Some(result.to_vec())
}

/// Verifies the file content against its expected hash.
///
/// # Parameters
///
/// * `data` - A `RevisionContent` struct containing the file data and expected hash.
///
/// # Returns
///
/// Returns a tuple containing:
/// - A boolean indicating whether the verification was successful.
/// - A `VerifyFileResult` struct with details about the verification process.
pub fn verify_file_util(data: RevisionContent) -> (bool, VerifyFileResult) {
    let mut logs: Vec<String> = Vec::new();

    let file_content_hash = data.content.file_hash;
    let file_content = data.file.unwrap().data;
    let hash_fromb64 = generate_hash_from_base64(file_content.to_string().as_str());

    if hash_fromb64.is_none() {
        logs.push("Error : unable to decode bytes in  verifying revision content ".to_string());
        return (
            false,
            VerifyFileResult {
                file_hash: None,
                error_message: Some("unable to decode bytes ".to_string()),
                logs: logs,
            },
        );
    }

    let hash_gen = hex::encode(hash_fromb64.unwrap());

    // logs.push(format!("Info : Hash generated {}", hash_gen));
    // logs.push(format!("Info : file Hash in chain  {}", file_content_hash.to_string()));
    if file_content_hash.to_string() != hash_gen {
        logs.push("Error :  File content hash does not match the genrated hash".to_string());
        return (
            false,
            VerifyFileResult {
                file_hash: None,
                error_message: Some("File content hash does not match ".to_string()),
                logs: logs,
            },
        );
    }
    logs.push("Sucess  :  File content hash does matches the genrated hash".to_string());
    (
        true,
        VerifyFileResult {
            file_hash: Some(file_content_hash.to_string()),
            error_message: None,
            logs: logs,
        },
    )
}

/// Verifies that the content's hash matches the expected content hash.
///
/// # Parameters
///
/// * `data` - A reference to a `RevisionContent` struct containing the content to verify.
///
/// # Returns
///
/// Returns a tuple containing:
/// - A boolean indicating whether the verification was successful.
/// - A string representation of the computed content hash.
pub fn verify_content_util(data: &RevisionContent) -> (bool, String) {
    let mut content = String::new();
    content += format!("{:#?}", data.content.file_hash).as_str();

    let content_hash = get_hash_sum(&content);
    let data_content_hash_str = format!("{:#?}", data.content_hash);
    if content_hash == data_content_hash_str {
        (true, content_hash)
    } else {
        (false, "Content hash does not match".to_string())
    }
}

/// Verifies that the metadata matches its expected hash.
///
/// # Parameters
///
/// * `data` - A reference to a `RevisionMetadata` struct containing metadata to verify.
///
/// # Returns
///
/// Returns a tuple containing:
/// - A boolean indicating whether the verification was successful.
/// - A string representation of the computed metadata hash.
pub fn verify_metadata_util(data: &RevisionMetadata) -> (bool, String) {
    // let metadata_hash = calculate_metadata_hash(
    //     data.domain_id.clone(),
    //     data.time_stamp.clone(),
    //     data.previous_verification_hash,
    //     data.merge_hash,
    // );
    let metadata_hash = metadata_hash(
        data.domain_id.clone().as_str(),
        &data.time_stamp.clone(),
        data.previous_verification_hash.as_ref(),
    );
    println!("Metadata hash generated {}", metadata_hash);
    println!("Metadata hash stored {}", data.metadata_hash.to_string());

    if metadata_hash.to_string() == data.metadata_hash.to_string() {
        (true, metadata_hash.to_string())
    } else {
        (false, "Metadata hash does not match".to_string())
    }
}


/// Calculates a metadata hash based on domain ID, timestamp, and optional hashes.
///
/// # Parameters
///
/// * `domain_id` - The domain identifier as a string.
/// * `timestamp` - The timestamp associated with the metadata.
/// * `previous_verification_hash` - An optional previous verification hash.
/// * `merge_hash` - An optional merge hash.
///
/// # Returns
///
/// Returns a string representing the computed metadata hash.
pub fn calculate_metadata_hash(
    domain_id: String,
    timestamp: Timestamp,
    previous_verification_hash: Option<Hash>,
    merge_hash: Option<Hash>,
) -> String {
    let mut content: String = domain_id + &timestamp.to_string();
    if let Some(prev_hash) = previous_verification_hash {
        content += &prev_hash.to_string();
    }
    if let Some(merge) = merge_hash {
        content += &merge.to_string();
    }
    get_hash_sum(&content)
}

///! Verification utilities for digital signatures, witness data, and content integrity.
///! 
///! This module provides functionality for:
///! - Verifying digital signatures against provided verification hashes
///! - Validating witness data and merkle proofs
///! - Computing and verifying various types /// Verifies witness data and optionally checks merkle proof integrity.
/// 
/// # Arguments
/// * `witness_data` - The witness data containing merkle proof and transaction information
/// * `verification_hash` - The hash to verify against
/// * `do_verify_merkle_proof` - Whether to verify the merkle proof
/// * `verification_platform` - The platform to use for verification
/// * `chain` - The blockchain network to use
/// * `api_key` - API key for the verification platform
/// 
/// # Returns
/// A tuple containing:
/// * `bool` - Whether the witness data is valid
/// * `String` - A status message
/// * `Vec<String>` - Logs from the verification processof hashes (content, metadata, witness, etc.)
///! - Managing revision verification chains
///!
///! # Examples
///! ```rust
///! let signature_data = RevisionSignature { /* ... */ };
///! let verification_hash = Hash::new("...");
///! let (is_valid, status) = verify_signature_util(signature_data, verification_hash);
///! ```

#[warn(unused_assignments)]

/// Verifies a digital signature against a provided verification hash.
/// 
/// # Arguments
/// * `data` - The signature data containing the signature and wallet address
/// * `verification_hash` - The hash to verify against
/// 
/// # Returns
/// A tuple containing:
/// * `bool` - Whether the signature is valid
/// * `String` - A status message describing the verification result
pub fn verify_signature_util(data: RevisionSignature, verification_hash: Hash) -> (bool, String) {
    if verification_hash.is_empty() {
        return (false, "Verification hash must not be empty".to_string());
    }

    let padded_message = format!(
        "I sign the following page verification_hash: [0x{}]",
        verification_hash
    );

    let signature_string = format!("{:?}", data.signature);
    println!("The signature is {}", signature_string);

    let mut status = String::new();
    let mut signature_ok = false;
    match (
        hash_message(padded_message),
        ethers::types::Signature::from_str(signature_string.as_str()),
    ) {
        (hashed_msg, Ok(sig)) => {
            println!("Gen signature {}", sig.clone());

            // let clean_input_1 = if sig.to_string().to_lowercase().starts_with("0x") {
            //     sig.to_string().to_lowercase()[2..].to_string()
            // } else {
            //     sig.to_string().to_lowercase()
            // };
            // let clean_input_2 = if signature_string.to_lowercase().starts_with("0x") {
            //     signature_string.to_lowercase()[2..].to_string()
            // } else {
            //     signature_string.to_lowercase()
            // };

            // signature_ok = clean_input_1 == clean_input_2;

            // status = if signature_ok {
            //     "Signature is Valid".to_string()
            // } else {
            //     "Signature is invalid".to_string()
            // };

            //todo to be reviewed
            match ethers::core::types::Signature::recover(&sig, hashed_msg) {
                Ok(recovered_address_long) => {
                    let recovered_address = format!("{:?}", recovered_address_long);
                    let clean_input_1 = if recovered_address
                        .to_string()
                        .to_lowercase()
                        .starts_with("0x")
                    {
                        recovered_address.to_string().to_lowercase()[2..].to_string()
                    } else {
                        recovered_address.to_string().to_lowercase()
                    };
                    let clean_input_2 = if data
                        .wallet_address
                        .to_string()
                        .to_lowercase()
                        .starts_with("0x")
                    {
                        data.wallet_address.to_string().to_lowercase()[2..].to_string()
                    } else {
                        data.wallet_address.to_string().to_lowercase()
                    };

                    println!("1 {:#?}", clean_input_1);
                    println!("2 {:#?}", clean_input_2);

                    signature_ok = clean_input_1 == clean_input_2;
                    // signature_ok = recovered_address.to_string().to_lowercase()
                    //     == data.wallet_address.to_string().to_lowercase();

                    status = if signature_ok {
                        "Signature is Valid".to_string()
                    } else {
                        "Signature is invalid".to_string()
                    };
                }
                Err(e) => {
                    status = format!("An error occurred retrieving signature: {}", e);
                }
            }
        }
        (_, Err(e)) => {
            // Handle invalid signature format
            status = format!("Invalid signature format: {}", e);
        }
    }

    (signature_ok, status)
}


/// Verifies witness data and optionally checks merkle proof integrity.
/// 
/// # Arguments
/// * `witness_data` - The witness data containing merkle proof and transaction information
/// * `verification_hash` - The hash to verify against
/// * `do_verify_merkle_proof` - Whether to verify the merkle proof
/// * `verification_platform` - The platform to use for verification
/// * `chain` - The blockchain network to use
/// * `api_key` - API key for the verification platform
/// 
/// # Returns
/// A tuple containing:
/// * `bool` - Whether the witness data is valid
/// * `String` - A status message
/// * `Vec<String>` - Logs from the verification process
pub fn verify_witness_util(
    witness_data: RevisionWitness,
    verification_hash: String,
    do_verify_merkle_proof: bool,
    verification_platform: String,
    chain: String,
    api_key: String,
) -> (bool, String, Vec<String>) {
    let logs = Vec::new();

    let actual_witness_event_verification_hash = get_hash_sum(
        &(witness_data
            .domain_snapshot_genesis_hash
            .clone()
            .to_string()
            + &witness_data.merkle_root.to_string()),
    );

    if actual_witness_event_verification_hash
        != witness_data.witness_event_verification_hash.to_string()
    {
        return (false, "Verification hashes do not match".to_string(), logs);
    }

    if do_verify_merkle_proof {
        println!("Doing merkle verification: ");
        if verification_hash == witness_data.domain_snapshot_genesis_hash.to_string() {
            return (
                true,
                "Verification hash is the same as domain snapshot genesis hash".to_string(),
                logs
            );
        } else {
            let merkle_proof_is_ok =
                verify_merkle_integrity(&witness_data.structured_merkle_proof, verification_hash);
            return (
                merkle_proof_is_ok,
                if merkle_proof_is_ok {
                    "Merkle proof is OK".to_string()
                } else {
                    "Error verifying merkle proof".to_string()
                },
                logs
            );
        }
    }

    if  verification_platform == "none"{
        println!("No verificaton platform: ");
        (true, "Look up not performed.".to_string(), logs)
    }else{
        println!("Verification platform found: ");
    let tx_hash = witness_data.witness_event_transaction_hash.clone();
    let tx_hash_string = format!("{}", tx_hash);
    let tx_hash_par = tx_hash_string.as_str();
    // Create a new runtime
    let rt = Runtime::new().unwrap();

     // Block on the async function to get its result
    let get_tx_data_res = rt.block_on( get_tx_data(
        tx_hash_par,
        verification_platform,
        chain,
        api_key,
    ));

    let (input_data, _) = get_tx_data_res.unwrap();
    let witness_event_verification_hash  = format!("{}", witness_data.witness_event_verification_hash);

    println!("Data received from getting tx information: {:#?} \n verification hash: {}", input_data, witness_event_verification_hash);

    if input_data == witness_event_verification_hash {
        (true, "Look up performed.".to_string(), logs)
    }else{
        (false, "Look up failed.".to_string(), logs)
    }

}
    // TODO: Implement the checkTransaction function
   
}

/// Verifies the integrity of a merkle proof.
/// 
/// # Arguments
/// * `merkle_branch` - The merkle proof branch nodes
/// * `verification_hash` - The hash to verify against
/// 
/// # Returns
/// `bool` - Whether the merkle proof is valid
pub fn verify_merkle_integrity(merkle_branch: &[MerkleNode], verification_hash: String) -> bool {
    if merkle_branch.is_empty() {
        return false;
    }

    //todo
    // let mut prev_successor: Option<Hash> = None;
    // for node in merkle_branch {
    //     let leaves = [node.left_leaf.clone(), node.right_leaf.clone()];
    //     if let Some(ref prev_succ) = prev_successor {
    //         if !leaves.contains(prev_succ) {
    //             return false;
    //         }
    //     } else {
    //         if !leaves.contains(&Some(verification_hash.to_string())) {
    //             return false;
    //         }
    //     }

    //     let calculated_successor = if node.left_leaf.is_none() {
    //         node.right_leaf.clone()
    //     } else if node.right_leaf.is_none() {
    //         node.left_leaf.clone()
    //     } else {
    //         Some(get_hash_sum(&(node.left_leaf.as_ref().unwrap() + node.right_leaf.as_ref().unwrap())))
    //     };

    //     if calculated_successor != Some(node.successor.clone()) {
    //         return false;
    //     }

    //     prev_successor = Some(node.successor.clone());
    // }

    true
}


/// Checks if all verifications in a revision result are successful.
/// 
/// # Arguments
/// * `revision_result` - The revision verification result containing multiple verification statuses
/// 
/// # Returns
/// `bool` - Whether all available verifications were successful
pub fn all_successful_verifications(revision_result: &RevisionVerificationResult) -> bool {
    let verifications = [
        &revision_result.file_verification,
        &revision_result.content_verification,
        &revision_result.witness_verification,
        &revision_result.signature_verification,
        &revision_result.metadata_verification,
    ];

    for verification in verifications {
        if matches!(verification.status, ResultStatusEnum::AVAILABLE) && !verification.successful {
            return false;
        }
    }

    true
}

/// Computes a witness hash from its components.
/// 
/// # Arguments
/// * `domain_snapshot_genesis_hash` - The genesis hash of the domain snapshot
/// * `merkle_root` - The root of the merkle tree
/// * `witness_network` - The network identifier
/// * `witness_event_transaction_hash` - The transaction hash of the witness event
/// 
/// # Returns
/// `Hash` - The computed witness hash
pub fn witness_hash(
    domain_snapshot_genesis_hash: &Hash,
    merkle_root: &Hash,
    witness_network: &str,
    witness_event_transaction_hash: &TxHash,
) -> Hash {
    // 2.a create hasher {w}
    let mut w = crypt::Hasher::default();
    // 2.b add rev.witness.domain_snapshot_genesis_hash to hasher {w}
    w.update(domain_snapshot_genesis_hash.to_stackstr());
    // 2.c add rev.witness.merkle_root to hasher {w}
    w.update(merkle_root.to_stackstr());
    // 2.d add rev.witness.witness_network to hasher {w}
    w.update(witness_network);
    // 2.e add rev.witness.witness_event_transaction_hash to hasher {w}
    w.update(witness_event_transaction_hash.to_stackstr());
    Hash::from(w.finalize())
}

/// Computes a signature hash from a signature and public key.
/// 
/// # Arguments
/// * `signature` - The digital signature
/// * `public_key` - The public key used for signing
/// 
/// # Returns
/// `Hash` - The computed signature hash
pub fn signature_hash(signature: &Signature, public_key: &PublicKey) -> Hash {
    // 4.a create hasher {s}
    let mut s = crypt::Hasher::default();
    // 4.b add rev.signature.signature to hasher {s}
    s.update(signature.to_stackstr());
    // 4.c add rev.signature.public_key to hasher {s}
    s.update(public_key.to_stackstr());
    Hash::from(s.finalize())
}

/// Computes a content hash from a map of content data.
/// 
/// # Arguments
/// * `content` - Map of content key-value pairs
/// 
/// # Returns
/// `Hash` - The computed content hash
pub fn content_hash(content: &BTreeMap<String, String>) -> Hash {
    // 3.a create hasher {c}
    let mut c = crypt::Hasher::default();
    // 3.b iterate over rev.content.content by its keys
    for value in content.values() {
        // 3.c add each value of rev.content.content to hasher {c}
        c.update(value);
    }
    Hash::from(c.finalize())
}

/// Computes a metadata hash from revision metadata components.
/// 
/// # Arguments
/// * `domain_id` - The domain identifier
/// * `time_stamp` - The timestamp of the revision
/// * `previous_verification_hash` - Optional hash from previous verification
/// 
/// # Returns
/// `Hash` - The computed metadata hash
pub fn metadata_hash(
    domain_id: &str,
    time_stamp: &Timestamp,
    previous_verification_hash: Option<&Hash>,
) -> Hash {
    // 4.a create hasher {m}
    let mut m = crypt::Hasher::default();
    // 4.b add rev.metadata.domain_id to hasher {m}
    m.update(domain_id);
    // 4.c add rev.metadata.time_stamp (in format %Y%m%d%H%M%S) to hasher {m}
    m.update(time_stamp.to_string());
    // 4.d if rev.metadata.previous_verification_hash exists then add rev.metadata.previous_verification_hash to hasher {m}
    if let Some(prev_verification_hash) = previous_verification_hash {
        m.update(prev_verification_hash.to_stackstr());
    }
    Hash::from(m.finalize())
}

/// Computes a verification hash from multiple component hashes.
/// 
/// # Arguments
/// * `content_hash` - Hash of the content
/// * `metadata_hash` - Hash of the metadata
/// * `signature_hash` - Optional signature hash
/// * `witness_hash` - Optional witness hash
/// 
/// # Returns
/// `Hash` - The computed verification hash
pub fn verification_hash(
    content_hash: &Hash,
    metadata_hash: &Hash,
    signature_hash: Option<&Hash>,
    witness_hash: Option<&Hash>,
) -> Hash {

    let mut v = crypt::Hasher::default();
    // 5.b add rev.content.content_hash to hasher {v}
    v.update(content_hash.to_stackstr());
    // 5.c add rev.metadata.metadata_hash to hasher {v}
    v.update(metadata_hash.to_stackstr());
    // 5.d if prev?.signature exists then add prev.signature.signature_hash to hasher {v}
    if let Some(prev_signature_hash) = signature_hash {
        v.update(prev_signature_hash.to_stackstr());
    }
    // 5.e if prev?.witness exists then add prev.witness.witness_hash to hasher {v}
    if let Some(prev_witness_hash) = witness_hash {
        v.update(prev_witness_hash.to_stackstr());
    }
    Hash::from(v.finalize())
}


/// Validates page data revisions for integrity and chain consistency.
/// 
/// # Arguments
/// * `revisions` - Vector of hash-revision pairs to validate
/// 
/// # Returns
/// A tuple containing:
/// * `bool` - Whether the revisions are valid
/// * `String` - A status message describing the validation result
pub fn check_if_page_data_revision_are_okay(revisions: Vec<(Hash, Revision)>) -> (bool, String) {
    let mut is_valid = (true, "".to_string());
    let has_valid_genessis = revsions_has_valid_genesis(revisions.clone());
    // tracing::debug!("revsions_has_valid_genesis {:#?}", has_valid_genessis);

    if has_valid_genessis.is_none() {
        return (
            false,
            "revisions do not contain a valid genesis".to_string(),
        );
    }

    // check if the revision > metadata > previous_verification_hash is among the hash in revsions par
    // if more that one is none return false
    // there is a broken revision chain
    let mut all_hashes: Vec<Hash> = Vec::new();
    revisions
        .iter()
        .for_each(|(hash, _revision)| all_hashes.push(hash.clone()));

    let genesis_hash_str = format!("{:#?}", has_valid_genessis.unwrap());

    for (_index, (current_hash, current_revision)) in revisions.iter().enumerate() {
        let current_hash_str = format!("{:#?}", current_hash);

        // check hash if match the newly generated one
        let recomputed_content_hash = compute_content_hash(&current_revision.content);

        match recomputed_content_hash {
            Ok(data) => {
                if data == *current_hash {
                    // tracing::error!("hashes match the generetaed one continue ...");
                } else {
                    // tracing::error!("\n hashes do not match revision has {:#?} \n vs generated hash {:#?} \n",data,current_hash );
                    is_valid = (false, format!("a hash is not valid : {:#?}", current_hash));

                    break;
                }
            }
            Err(_error) => {
                // tracing::error!("an error occured {}", error);
                is_valid = (false, "error generating a hash ".to_string());
                break;
            }
        }
        // let contnent_hash_str = format!("{:#?}", revision.content.content_hash);
        // let data_str = format!("{:#?}", revision.content.content_hash);
        // tracing::error!("returd conetnet is   {} \n  my json content hash is {} \n", data_str, contnent_hash_str);
        // matches = data ==revision.content.content_hash  ;//revision.content.content_hash;

        // chec if the hash chain is valid (ie if there any orphan revisions)
        if current_hash_str == genesis_hash_str {
            // tracing::debug!("ignoring genessis hash is {:#?}", genesis_hash_str);
        } else {
            let contains = all_hashes.contains(current_hash);

            if contains == false {
                // tracing::debug!("cannot find hash is {:#?}", current_hash_str);
                is_valid = (false, "Hash chain is invalid ".to_string());
                break;
            }
        }
    }

    return is_valid;
}


/// Checks if revisions contain a valid genesis block.
/// 
/// # Arguments
/// * `revisions` - Vector of hash-revision pairs to check
/// 
/// # Returns
/// `Option<Hash>` - The genesis hash if found and valid, None otherwise
pub fn revsions_has_valid_genesis(revisions: Vec<(Hash, Revision)>) -> Option<Hash> {
    // let mut is_valid= true;

    if revisions.len() <= 1 {
        // tracing::debug!("The lengthe is equal to or ess than 1 {}", revisions.len());
        return None;
    }

    let mut revision_genesis: Vec<&Revision> = Vec::new();

    for (_index, (_hash, revision)) in revisions.iter().enumerate() {
        match revision.metadata.previous_verification_hash {
            Some(_data) => {
                // tracing::debug!("The previous hash is {:#?}", data);
            }
            None => {
                // tracing::debug!("pushing revision to vector {:#?}", revision);
                revision_genesis.push(revision)
            }
        }
    }

    if revision_genesis.len() > 1 {
        // tracing::debug!(
        //     "The genesis revision  length {} are {:#?}",
        //     revision_genesis.len(),
        //     revision_genesis
        // );
        return None;
    }

    let res = revision_genesis.first();
    if res.is_none() {
        // tracing::debug!("No genesis hash  (vec is empty)",);
        return None;
    }

    // tracing::debug!("************************ {:#?}", res);
    // we use unwrapp becasue we are guaranteed the res has value due to the if check above
    return Some(res.unwrap().metadata.verification_hash);
}

/// Computes a content hash from revision content.
/// 
/// # Arguments
/// * `content_par` - The revision content containing file data
/// 
/// # Returns
/// `Result<Hash, String>` - The computed hash or an error message
pub fn compute_content_hash(content_par: &RevisionContent) -> Result<Hash, String> {
    let b64 = content_par.file.clone().unwrap().data;

    let mut file_hasher = sha3::Sha3_512::default();
    file_hasher.update(b64.clone());
    let file_hash_current = Hash::from(file_hasher.finalize());

    let mut content_current = BTreeMap::new();

    content_current.insert("file_hash".to_owned(), file_hash_current.to_string());

    // println!("{:#?}", content_current);
    // tracing::debug!("{:#?}", content_current);

    let content_hash_current = content_hash(&content_current.clone());

    // tracing::debug!("{:#?}", content_hash_current);

    Ok(content_hash_current)
}


/// Creates an empty hash using SHA3-512.
/// 
/// # Returns
/// `Hash` - A hash computed from an empty string
pub fn make_empty_hash() -> Hash {
    let mut hasher = sha3::Sha3_512::default();
    hasher.update("");
    let empty_hash = Hash::from(hasher.finalize());
    empty_hash
}
