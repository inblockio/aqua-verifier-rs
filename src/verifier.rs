use crate::model::{
    PageDataWithLog, ResultStatus, ResultStatusEnum, RevisionAquaChainResult,
    RevisionVerificationResult,
};
use aqua_verifier_rs_types::models::base64::Base64;
use aqua_verifier_rs_types::models::content::{FileContent, RevisionContent};
use aqua_verifier_rs_types::models::content::{
    RevisionContentContent, RevisionContentSignature, RevisionWitnessInput,
};
use aqua_verifier_rs_types::models::hash::Hash;
use aqua_verifier_rs_types::models::metadata::RevisionMetadata;
use aqua_verifier_rs_types::models::page_data::PageData;
use aqua_verifier_rs_types::models::page_data::{HashChain, SiteInfo};
use aqua_verifier_rs_types::models::public_key::PublicKey;
use aqua_verifier_rs_types::models::revision::Revision;
use aqua_verifier_rs_types::models::signature::{RevisionSignature, Signature};
use aqua_verifier_rs_types::models::timestamp::Timestamp;
use aqua_verifier_rs_types::models::tx_hash::TxHash;
use aqua_verifier_rs_types::models::witness::{MerkleNode, RevisionWitness};
use sha3::Digest;
use std::collections::BTreeMap;
use std::fmt::format;
use std::str::FromStr;

use crate::util::{
    all_successful_verifications, content_hash, make_empty_hash, metadata_hash, signature_hash,
    verification_hash, verify_content_util, verify_file_util, verify_metadata_util,
    verify_signature_util, verify_witness_util, witness_hash,
};

///! # AquaChain Verifier
///! 
///! This crate provides functionality for verifying, signing, and managing AquaChain data structures.
///! AquaChain is a blockchain-based data verification system that maintains integrity through
///! cryptographic proofs and signatures.
///!
///! ## Key Features
///!
///! - Revision verification and management
///! - Cryptographic signing of chain data
///! - Witness verification and Merkle proof validation
///! - Chain generation and modification utilities
///!
///! ## Core Components
///!
///! The main components include verification utilities, chain management functions, and
///! cryptographic operations for maintaining data integrity.

/// Maximum allowed file size for chain data (20 MB)
/// 
const MAX_FILE_SIZE: u32 = 20 * 1024 * 1024; // 20 MB in bytes


/// Verifies a single revision in the AquaChain system.
///
/// Performs comprehensive verification including file content, metadata,
/// signatures, and witness data if present.
///
/// # Arguments
///
/// * `revision` - The revision to verify
/// * `verification_platform` - Platform identifier for verification
/// * `chain` - Chain identifier
/// * `api_key` - API key for verification service
///
/// # Returns
///
/// Returns a `RevisionVerificationResult` containing the status of each verification step
///
/// # Examples
///
/// ```
/// let result = verify_revision(
///     revision,
///     "platform".to_string(),
///     "chain".to_string(),
///     "api_key".to_string()
/// );
/// if result.successful {
///     println!("Revision verified successfully");
/// }
/// ```
pub(crate) fn verify_revision(
    revision: Revision,
    verification_platform: String,
    chain: String,
    api_key: String,
) -> RevisionVerificationResult {
    let mut logs: Vec<String> = Vec::new();
    let default_result_status: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
        logs: logs.clone(),
    };

    let mut revision_result: RevisionVerificationResult = RevisionVerificationResult {
        successful: false,
        file_verification: default_result_status.clone(),
        content_verification: default_result_status.clone(),
        witness_verification: default_result_status.clone(),
        signature_verification: default_result_status.clone(),
        metadata_verification: default_result_status.clone(),
    };

    logs.push("Info : Verifying  the file".to_string());
    let (file_is_correct, file_out) = verify_file_util(revision.content.clone());
    revision_result.file_verification.status = ResultStatusEnum::AVAILABLE;
    revision_result.file_verification.successful = file_is_correct;
    revision_result.file_verification.message = match file_out.error_message.clone() {
        Some(data) => data,
        None => String::from("No message"),
    };

    file_out
        .logs
        .iter()
        .map(|item| format!("\t {}", item))
        .for_each(|log| logs.push(log));

    if file_is_correct {
        logs.push("Success : successfully  verified file".to_string());
    } else {
        logs.push(format!(
            "Error :  failed to verify file {}",
            file_out
                .error_message
                .unwrap_or(String::from("Unable to parse error"))
        ));
    }

    // Verify Content
    logs.push("Info : Verifying  the content".to_string());
    let (verify_content_is_okay, result_message) = verify_content_util(&revision.content);
    revision_result.content_verification.status = ResultStatusEnum::AVAILABLE;
    revision_result.content_verification.successful = verify_content_is_okay;
    revision_result.content_verification.message = result_message.clone();

    if verify_content_is_okay {
        logs.push("Success : successfully  verified the content".to_string());
    } else {
        logs.push(format!(
            "Error :  failed to verify the content {}",
            result_message
        ));
    }

    // Verify Metadata
    logs.push("Info : Verifying  the metadata".to_string());
    let (metadata_ok, metadata_hash_message) = verify_metadata_util(&revision.metadata);
    revision_result.metadata_verification.status = ResultStatusEnum::AVAILABLE;
    revision_result.metadata_verification.successful = metadata_ok;
    revision_result.metadata_verification.message = metadata_hash_message.clone();

    if metadata_ok {
        logs.push("Success : successfully  verified the metadata".to_string());
    } else {
        logs.push(format!(
            "Error :  failed to verify the metadata {}",
            metadata_hash_message
        ));
    }

    // Verify Signature
    if (revision.signature).is_some() {
        logs.push("Info : Verifying  the signature".to_string());

        let (signature_ok, signature_message) = verify_signature_util(
            revision.signature.unwrap(),
            revision.metadata.previous_verification_hash.unwrap(),
        );
        revision_result.signature_verification.status = ResultStatusEnum::AVAILABLE;
        revision_result.signature_verification.successful = signature_ok;
        revision_result.signature_verification.message = signature_message.clone();

        if signature_ok {
            logs.push("Success : successfully  verified a signature".to_string());
        } else {
            logs.push(format!(
                "Error :  failed to verify the signature {}",
                signature_message
            ));
        }
    }

    // Verify Witness (asynchronous)
    if revision.witness.is_some() {
        logs.push("Info : Verifying  a witness".to_string());
        
        println!("Verification options in revision verificaton 1: {}: {}: {}", verification_platform,
        chain,
        api_key);

        let (success, message, logs_data) = verify_witness_util(
            revision.witness.clone().unwrap(),
            revision
                .metadata
                .previous_verification_hash
                .unwrap()
                .to_string(),
            revision.witness.unwrap().structured_merkle_proof.len() > 1,
            verification_platform,
            chain,
            api_key,
        );
        logs_data
            .iter()
            .for_each(|item| logs.push(format!("\t\t {}", item)));

        revision_result.witness_verification.status = ResultStatusEnum::AVAILABLE;
        revision_result.witness_verification.successful = success;
        revision_result.witness_verification.message = message.clone();

        if success {
            logs.push("Success : successfully  verified a witness".to_string());
        } else {
            logs.push(format!("Error :  failed to verify a witness {}", message));
        }

        revision_result.witness_verification.logs = logs;
    }

    // Update the overall successful status
    revision_result.successful = all_successful_verifications(&revision_result);

    return revision_result;
}

/// Verifies a signature against a previous verification hash.
///
/// # Arguments
///
/// * `signature` - The signature to verify
/// * `previous_verification_hash` - Hash from previous verification
///
/// # Returns
///
/// Returns a `ResultStatus` indicating success or failure of verification
///
/// # Examples
///
/// ```
/// let status = verify_signature(signature, previous_hash);
/// if status.successful {
///     println!("Signature verified");
/// }
/// ```
pub(crate) fn verify_signature(
    signature: RevisionSignature,
    previous_verification_hash: Hash,
) -> ResultStatus {
    let logs: Vec<String> = Vec::new();

    let mut default_result_status: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
        logs: logs,
    };

    let (signature_ok, signature_message) =
        verify_signature_util(signature, previous_verification_hash);

    default_result_status.status = ResultStatusEnum::AVAILABLE;
    default_result_status.successful = signature_ok;
    default_result_status.message = signature_message;

    return default_result_status;
}

/// Verifies a witness record including optional Merkle proof validation.
///
/// # Arguments
///
/// * `witness` - The witness data to verify
/// * `verification_hash` - Hash for verification
/// * `do_verify_merkle_proof` - Whether to verify Merkle proof
/// * `verification_platform` - Platform for verification
/// * `chain` - Chain identifier
/// * `api_key` - API key for verification service
///
/// # Returns
///
/// Returns a `ResultStatus` containing verification results and logs
///
/// # Examples
///
/// ```
/// let status = verify_witness(
///     witness,
///     "hash".to_string(),
///     true,
///     "platform".to_string(),
///     "chain".to_string(),
///     "api_key".to_string()
/// );
/// ```
pub(crate) fn verify_witness(
    witness: RevisionWitness,
    verification_hash: String,
    do_verify_merkle_proof: bool,
    verification_platform: String,
    chain: String,
    api_key: String,
) -> ResultStatus {
    let mut logs: Vec<String> = Vec::new();
    let mut default_result_status: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
        logs: logs.clone(),
    };

    logs.push(format!("Info : Logging here:  verification_platform  {} :  chain {}:  api_key {}", verification_platform, chain,api_key));

    let (success, message, logs_data) = verify_witness_util(
        witness.clone(),
        verification_hash,
        do_verify_merkle_proof,
        verification_platform,
        chain,
        api_key,
    );
    logs_data
        .iter()
        .for_each(|item| logs.push(format!("\t\t {}", item)));

    default_result_status.status = ResultStatusEnum::AVAILABLE;
    default_result_status.successful = success;
    default_result_status.message = message.clone();

    if success {
        logs.push("Success : successfully  verified a witness".to_string());
    } else {
        logs.push(format!("Error :  failed to verify a witness {}", message));
    }

    default_result_status.logs = logs;

    return default_result_status;
}


/// Verifies an entire AquaChain by validating all revisions.
///
/// # Arguments
///
/// * `aqua_chain` - The chain to verify
/// * `verification_platform` - Platform identifier
/// * `chain` - Chain identifier
/// * `api_key` - API key for verification
///
/// # Returns
///
/// Returns a `RevisionAquaChainResult` containing verification results for all revisions
///
/// # Examples
///
/// ```
/// let result = verify_aqua_chain(
///     chain,
///     "platform".to_string(),
///     "chain".to_string(),
///     "api_key".to_string()
/// );
/// ```
pub(crate) fn verify_aqua_chain(
    aqua_chain: HashChain,
    verification_platform: String,
    chain: String,
    api_key: String,
) -> RevisionAquaChainResult {
    let mut hash_chain_result: RevisionAquaChainResult = RevisionAquaChainResult {
        successful: true,
        revision_results: Vec::new(),
    };

    let mut hash_chain_revisions_status: Vec<bool> = Vec::new();

    for (_hash, revision) in aqua_chain.revisions {
        let revision_result: RevisionVerificationResult = verify_revision(
            revision,
            verification_platform.clone(),
            chain.clone(),
            api_key.clone(),
        );
        hash_chain_result
            .revision_results
            .push(revision_result.clone());
        let revision_status_result = all_successful_verifications(&revision_result);
        hash_chain_revisions_status.push(revision_status_result);
    }

    hash_chain_result.successful = !hash_chain_revisions_status.contains(&false);

    return hash_chain_result;
}


/// Signs a revision in the AquaChain using provided signature data.
///
/// # Arguments
///
/// * `aqua_chain` - The chain containing the revision to sign
/// * `revision_content` - Signature content and metadata
///
/// # Returns
///
/// Returns a Result containing the updated chain and logs, or error messages
///
/// # Examples
///
/// ```
/// let (updated_chain, logs) = sign_aqua_chain(chain, signature_content)?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Signature parsing fails
/// - Public key is invalid
/// - Wallet address is invalid
pub(crate) fn sign_aqua_chain(
    mut aqua_chain: PageData,
    revision_content: RevisionContentSignature,
) -> Result<(PageData, Vec<String>), Vec<String>> {
    
    let mut log_data: Vec<String> = Vec::new();
    let len = aqua_chain.pages[0].revisions.len();

    let (ver1, rev1) = &aqua_chain.pages[0].revisions[len - 1].clone();

    let mut rev2 = rev1.clone();
    rev2.witness = None;
    rev2.metadata.previous_verification_hash = Some(*ver1);

    // Parse input data with proper error handling
    let sig = match revision_content.signature.parse::<Signature>() {
        Ok(s) => {
            log_data.push("Success :  signature  parse successfully".to_string());
            s
        }
        Err(e) => {
            log_data.push(format!("error : Failed to parse  signature: {:?}", e));

            return Err(log_data);
        }
    };
    let pubk = match revision_content.publickey.parse::<PublicKey>() {
        Ok(p) => {
            log_data.push("Success : public  key  parsed successfully".to_string());

            p
        }
        Err(e) => {
            log_data.push(format!("error : Failed to parse  public key: {:?}", e));

            return Err(log_data);
        }
    };
    // let address_ = ethaddr::Address::from_str(&revision_content.wallet_address);
    // let addr = match ethaddr::Address::from_str_checksum(&revision_content.wallet_address) {
    //     Ok(a) => {
    //         log_data.push("wallet address parsed successfully".to_string());

    //         a
    //     }
    //     Err(e) => {
    //         log_data.push(format!("Failed to parse wallet address: {:?}", e));

    //         return Err(log_data);
    //     }
    // };

    let mut add: Option<ethaddr::Address> = None;

    let address_result = ethaddr::Address::from_str_checksum(&revision_content.wallet_address);
    if address_result.is_err() {
        let address_result_2 = ethaddr::Address::from_str(&revision_content.wallet_address);
        if address_result_2.is_err() {
            log_data.push(format!(
                "Error : Error Failed to parse wallet address from str: {}",
                revision_content.wallet_address
            ));

            return Err(log_data);
        }
        add = Some(address_result_2.unwrap());
    } else {
        add = Some(address_result.unwrap());
    }

    if add.is_none() {
        log_data.push(format!(
            "Failed to parse wallet address from checksum: {}",
            revision_content.wallet_address
        ));

        return Err(log_data);
    }

    let addr = add.unwrap();

    let sig_hash = signature_hash(&sig, &pubk);

    rev2.signature = Some(RevisionSignature {
        signature: sig,
        public_key: pubk,
        signature_hash: sig_hash.clone(),
        wallet_address: addr,
    });

    let timestamp_current = Timestamp::from(chrono::Utc::now().naive_utc());
    rev2.metadata.time_stamp = timestamp_current.clone();

    let metadata_hash_current = metadata_hash(
        &aqua_chain.pages[0].domain_id,
        &timestamp_current,
        Some(ver1),
    );

    let verification_hash_current = verification_hash(
        &rev2.content.content_hash,
        &metadata_hash_current,
        Some(&sig_hash),
        None,
    );

    rev2.metadata.metadata_hash = metadata_hash_current;
    rev2.metadata.verification_hash = verification_hash_current;

    aqua_chain.pages[0]
        .revisions
        .push((verification_hash_current, rev2));

    return Ok((aqua_chain, log_data));
}

/// Adds witness information to a revision in the chain.
///
/// Creates Merkle proofs and updates chain state with witness data.
///
/// # Arguments
///
/// * `aqua_chain` - The chain to update
/// * `witness_input` - Witness data to add
///
/// # Returns
///
/// Returns a Result containing the updated chain and logs, or error messages
///
/// # Examples
///
/// ```
/// let (updated_chain, logs) = witness_aqua_chain(chain, witness_data)?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Transaction hash parsing fails
/// - Wallet address is invalid
pub(crate) fn witness_aqua_chain(
    mut aqua_chain: PageData,
    witness_input: RevisionWitnessInput,
) -> Result<(PageData, Vec<String>), Vec<String>> {
    let mut log_data: Vec<String> = Vec::new();

    // let mut doc = deserialized.clone();
    let len = aqua_chain.pages[0].revisions.len();

    let (ver1, rev1) = &aqua_chain.pages[0].revisions[len - 1].clone();

    let mut rev2 = rev1.clone();
    rev2.metadata.previous_verification_hash = Some(*ver1);

    let tx_hash = match witness_input.tx_hash.parse::<TxHash>() {
        Ok(s) => s,
        Err(e) => {
            log_data.push(format!("Error :  Failed to to parse tx hash: {:?}", e));
            return Err(log_data);
        }
    };

    log_data.push(format!("Success :  Parsed tx hash: {:?}", tx_hash));

    let wallet_address = match ethaddr::Address::from_str_checksum(&witness_input.wallet_address) {
        Ok(a) => a,
        Err(e) => {
            log_data.push(format!("Error :  Failed to parse wallet address: {:?}", e));
            return Err(log_data);
        }
    };
    log_data.push(format!(
        "Success  :  parsed wallet address: {:?}",
        wallet_address
    ));

    let domain_snapshot_genesis_string = &aqua_chain.pages.get(0).unwrap().genesis_hash;

    let mut hasher = sha3::Sha3_512::default();
    hasher.update("");

    let domain_snapshot_genesis_hash = Hash::from(hasher.finalize());

    let witness_hash_data = witness_hash(
        &domain_snapshot_genesis_hash,
        &rev1.metadata.verification_hash,
        witness_input.network.as_str(),
        &tx_hash,
    );

    let mut merkle_tree_successor_hasher = sha3::Sha3_512::default();
    merkle_tree_successor_hasher.update(format!(
        "{}{}",
        &rev1.metadata.verification_hash.to_string(),
        make_empty_hash().to_string()
    ));

    let merkle_tree_successor = Hash::from(merkle_tree_successor_hasher.finalize());

    let mut merkle_tree = Vec::new();
    merkle_tree.push(MerkleNode {
        left_leaf: rev1.metadata.verification_hash,
        right_leaf: make_empty_hash(),
        successor: merkle_tree_successor,
    });

    let mut hasher_verification = sha3::Sha3_512::default();
    hasher_verification.update(format!(
        "{}{}",
        domain_snapshot_genesis_hash.to_string(),
        &rev1.metadata.verification_hash.to_string()
    ));

    let witness_event_verification_hash = Hash::from(hasher_verification.finalize());

    rev2.witness = Some(RevisionWitness {
        domain_snapshot_genesis_hash: domain_snapshot_genesis_hash,
        merkle_root: rev1.metadata.verification_hash,
        witness_network: witness_input.network,
        witness_event_transaction_hash: tx_hash,
        witness_event_verification_hash: witness_event_verification_hash,
        witness_hash: witness_hash_data,
        structured_merkle_proof: merkle_tree,
    });

    rev2.signature = None;

    let timestamp_current = Timestamp::from(chrono::Utc::now().naive_utc());
    rev2.metadata.time_stamp = timestamp_current.clone();

    let metadata_hash_current = metadata_hash(
        &aqua_chain.pages[0].domain_id,
        &timestamp_current,
        Some(ver1),
    );

    let verification_hash_current = verification_hash(
        &rev2.content.content_hash,
        &metadata_hash_current,
        None,
        Some(&witness_hash_data),
    );

    rev2.metadata.metadata_hash = metadata_hash_current;
    rev2.metadata.verification_hash = verification_hash_current;

    aqua_chain.pages[0]
        .revisions
        .push((verification_hash_current, rev2));

    return Ok((aqua_chain, log_data));
}


/// Creates a new AquaChain instance with initial revision.
///
/// # Arguments
///
/// * `body_bytes` - File content as bytes
/// * `file_name` - Name of the file
/// * `domain_id` - Domain identifier
///
/// # Returns
///
/// Returns a Result containing the new chain and logs, or error messages
///
/// # Examples
///
/// ```
/// let result = generate_aqua_chain(
///     file_bytes,
///     "document.pdf".to_string(),
///     "domain123".to_string()
/// )?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - File size exceeds MAX_FILE_SIZE (20MB)
/// - File processing fails
pub(crate) fn generate_aqua_chain(
    body_bytes: Vec<u8>,
    file_name: String,
    domain_id: String,
) -> Result<PageDataWithLog, Vec<String>> {
    let mut logs: Vec<String> = Vec::new();

    let file_size: u32 = match body_bytes.len().try_into() {
        Ok(size) => size,
        Err(_) => {
            logs.push("Error : File size exceeds u32::MAX".to_string());
            return Err(logs);
        }
    };

    if file_size > MAX_FILE_SIZE {
        logs.push(format!(
            "File size {} exceeds maximum allowed size (20 MB)",
            file_size
        ));
        return Err(logs);
    }
    let mut logs: Vec<String> = Vec::new();

    let b64 = Base64::from(body_bytes);
    let mut file_hasher = sha3::Sha3_512::default();
    file_hasher.update(b64.clone());
    let file_hash_current = Hash::from(file_hasher.finalize());

    let mut content_current = BTreeMap::new();
    content_current.insert("file_hash".to_owned(), file_hash_current.to_string());

    let content_hash_current = content_hash(&content_current);

    let timestamp_current = Timestamp::from(chrono::Utc::now().naive_utc());

    logs.push(format!(
        "Info : Domain ID: {}, Current timestamp: {:#?}",
        domain_id.clone(),
        timestamp_current
    ));

    let metadata_hash_current = metadata_hash(&domain_id.clone(), &timestamp_current, None);
    logs.push(format!("Meta data HASH: {}", metadata_hash_current));

    let verification_hash_current =
        verification_hash(&content_hash_current, &metadata_hash_current, None, None);

    let revision_content_content = RevisionContentContent {
        file_hash: file_hash_current,
    };

    let pagedata_current = PageData {
        site_info: SiteInfo {},
        pages: vec![HashChain {
            genesis_hash: verification_hash_current.clone().to_string(),
            domain_id: domain_id.clone(),
            title: file_name.clone(),
            namespace: 0,
            chain_height: 0,
            revisions: vec![(
                verification_hash_current,
                Revision {
                    content: RevisionContent {
                        file: Some(FileContent {
                            data: b64,
                            filename: file_name.clone(),
                            size: file_size,
                            comment: String::new(),
                        }),
                        content: revision_content_content,
                        content_hash: content_hash_current,
                    },
                    metadata: RevisionMetadata {
                        domain_id: domain_id.clone(),
                        time_stamp: timestamp_current,
                        previous_verification_hash: None,
                        metadata_hash: metadata_hash_current,
                        verification_hash: verification_hash_current,
                        // merge_hash: Some(verification_hash_current), // Todo! Fix me
                    },
                    signature: None,
                    witness: None,
                },
            )],
        }],
    };

    let rs = PageDataWithLog {
        page_data: pagedata_current,
        logs: logs,
    };

    Ok(rs)
}


/// Removes specified number of revisions from the chain.
///
/// Maintains chain integrity and preserves genesis revision.
///
/// # Arguments
///
/// * `aqua_chain` - The chain to modify
/// * `revision_count_for_deletion` - Number of revisions to delete
///
/// # Returns
///
/// Returns a Result containing the modified chain and logs, or error messages
///
/// # Examples
///
/// ```
/// let (updated_chain, logs) = delete_revision_in_aqua_chain(chain, 2)?;
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - Deletion count exceeds available revisions
/// - Attempt to delete genesis revision
pub(crate) fn delete_revision_in_aqua_chain(
    aqua_chain: PageData,
    revision_count_for_deletion: i32,
) -> Result<(PageData, Vec<String>), Vec<String>> {
    let mut log_data: Vec<String> = Vec::new();

    let len = aqua_chain.pages[0].revisions.len() as i32;

    log_data.push(format!(
        "Revisions in chain {} the count provided {}",
        len, revision_count_for_deletion
    ));

    if revision_count_for_deletion > len {
        log_data.push(
            "Info : revisions count for deletin is greater than the number of revision".to_string(),
        );

        return Err(log_data);
    }
    if revision_count_for_deletion == len {
        log_data.push("Info : you cannot delete the genesis revision".to_string());
        return Err(log_data);
    }

    let mut chain: Vec<HashChain> = Vec::new();
    let mut copy_chain_par = aqua_chain.pages[0].clone();

    copy_chain_par
        .revisions
        .truncate(copy_chain_par.revisions.len() - revision_count_for_deletion as usize);
    let chain_0 = HashChain {
        genesis_hash: copy_chain_par.genesis_hash,
        domain_id: copy_chain_par.domain_id,
        title: copy_chain_par.title,
        namespace: copy_chain_par.namespace,
        chain_height: copy_chain_par.chain_height,
        revisions: copy_chain_par.revisions,
    };

    chain.push(chain_0);
    let new_aqua_chain: PageData = PageData {
        pages: chain,
        site_info: aqua_chain.site_info.clone(),
    };
    return Ok((new_aqua_chain, log_data));
}
