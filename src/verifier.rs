use std::collections::BTreeMap;

use crate::model::{
    HashChainWithLog, PageDataWithLog, ResultStatus, ResultStatusEnum, RevisionAquaChainResult,
    RevisionVerificationResult,
};
use aqua_verifier_rs_types::models::base64::Base64;
use aqua_verifier_rs_types::models::content::RevisionContentContent;
use aqua_verifier_rs_types::models::content::{FileContent, RevisionContent};
use aqua_verifier_rs_types::models::hash::Hash;
use aqua_verifier_rs_types::models::metadata::RevisionMetadata;
use aqua_verifier_rs_types::models::page_data::PageData;
use aqua_verifier_rs_types::models::page_data::{HashChain, SiteInfo};
use aqua_verifier_rs_types::models::revision::Revision;
use aqua_verifier_rs_types::models::signature::RevisionSignature;
use aqua_verifier_rs_types::models::timestamp::Timestamp;
use aqua_verifier_rs_types::models::witness::RevisionWitness;
use sha3::Digest;

use crate::util::{all_successful_verifications, verify_content_util, verify_file_util, verify_metadata_util, verify_signature_util, verify_witness_util};
use crate::verification_::{content_hash, metadata_hash, verification_hash};

const MAX_FILE_SIZE: u32 = 20 * 1024 * 1024; // 20 MB in bytes

pub fn verify_revision(revision: Revision, alchemy_key: String, do_alchemy_key_look_up: bool) -> RevisionVerificationResult {
    let mut logs: Vec<String> = Vec::new();
    let default_result_status: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
        logs: logs,
    };

    let mut revision_result: RevisionVerificationResult = RevisionVerificationResult {
        successful: false,
        file_verification: default_result_status.clone(),
        content_verification: default_result_status.clone(), 
        witness_verification: default_result_status.clone(),
        signature_verification: default_result_status.clone(),
        metadata_verification: default_result_status.clone(),
    };

    let (file_is_correct, file_out) = verify_file_util(&revision.content);
    revision_result.file_verification.status = ResultStatusEnum::AVAILABLE;
    revision_result.file_verification.successful = file_is_correct;
    revision_result.file_verification.message = match file_out.error_message{
        Some(data) => data,
        None => String::from("No message")
    };

    // Verify Content
    let (verify_content_is_okay, result_message) = verify_content_util(&revision.content);
    revision_result.content_verification.status = ResultStatusEnum::AVAILABLE;
    revision_result.content_verification.successful = verify_content_is_okay;
    revision_result.content_verification.message = result_message;

    // Verify Metadata 
    let (metadata_ok, metadata_hash_message) = verify_metadata_util(&revision.metadata);
    revision_result.metadata_verification.status = ResultStatusEnum::AVAILABLE;
    revision_result.metadata_verification.successful = metadata_ok;
    revision_result.metadata_verification.message = metadata_hash_message;

    // Verify Signature
    if (revision.signature).is_some() {
        let (signature_ok, signature_message) = verify_signature_util(revision.signature.unwrap(), revision.metadata.previous_verification_hash.unwrap());
        revision_result.signature_verification.status = ResultStatusEnum::AVAILABLE;
        revision_result.signature_verification.successful = signature_ok;
        revision_result.signature_verification.message = signature_message;
    }

    // Verify Witness (asynchronous)
    if revision.witness.is_some() {
            // TODO! Fix me
            let (success, message) = verify_witness_util(
                revision.witness.clone().unwrap(),
                revision.metadata.previous_verification_hash.unwrap().to_string(),
                revision.witness.unwrap().structured_merkle_proof.len() > 1,
                alchemy_key,
                do_alchemy_key_look_up

            );
            revision_result.witness_verification.status = ResultStatusEnum::AVAILABLE;
            revision_result.witness_verification.successful = success;
            revision_result.witness_verification.message = message // message if needed
    }

    // Check the overall status
    // let all_successful = true;
    // for (let verification of Object.values(revision_result)) {
    //     if (verification.status == ResultStatusEnum::AVAILABLE && !verification.successful) {
    //         all_successful = false;
    //         break;
    //     }
    // }

    // for (let verification revision_result) {
    //     if (verification.status == ResultStatusEnum::AVAILABLE && !verification.successful) {
    //         all_successful = false;
    //         break;
    //     }
    // }
    
    // Update the overall successful status
    revision_result.successful = all_successful_verifications(&revision_result);

    return revision_result;
}

pub fn verify_signature(
    signature: RevisionSignature,
    previous_verification_hash: Hash,
) -> ResultStatus {
    let mut logs: Vec<String> = Vec::new();

    let mut default_result_status: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
        logs: logs,
    };

    let (signatureOk, signatureMessage) =
        verify_signature_util(signature, previous_verification_hash);

    default_result_status.status = ResultStatusEnum::AVAILABLE;
    default_result_status.successful = signatureOk;
    default_result_status.message = signatureMessage;

    return default_result_status;
}

pub fn verify_witness(
    witness: RevisionWitness,
    verification_hash: String,
    do_verify_merkle_proof: bool,
    alchemy_key: String,
    do_alchemy_key_look_up: bool,
) -> ResultStatus {
    let mut logs: Vec<String> = Vec::new();
    let mut default_result_status: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
        logs: logs,
    };

    let (witnessOk, witnessMessage) = verify_witness_util(
        witness,
        verification_hash,
        do_verify_merkle_proof,
        alchemy_key,
        do_alchemy_key_look_up,
    );

    default_result_status.status = ResultStatusEnum::AVAILABLE;
    default_result_status.successful = witnessOk;
    default_result_status.message = witnessMessage;

    return default_result_status;
}

pub fn verify_aqua_chain(
    aqua_chain: HashChain,
    alchemy_key: String,
    do_alchemy_key_look_up: bool,
) -> RevisionAquaChainResult {

    let mut hash_chain_result: RevisionAquaChainResult = RevisionAquaChainResult {
        successful: true,
        revisionResults: Vec::new(),
    };

    let mut hash_chain_revisions_status: Vec<bool> = Vec::new();

    for (_hash, revision) in aqua_chain.revisions {
        let revision_result : RevisionVerificationResult = verify_revision(revision, alchemy_key.clone(), do_alchemy_key_look_up);
        hash_chain_result.revisionResults.push(revision_result.clone());
        let revision_status_result = all_successful_verifications(&revision_result);
        hash_chain_revisions_status.push(revision_status_result);
    }

    hash_chain_result.successful = !hash_chain_revisions_status.contains(&false);

    return hash_chain_result;
}
 
// TODO: Fix
pub fn sign_aqua_chain(aqua_chain: HashChain) -> Result<HashChainWithLog, Vec<String>> {
    println!(" sign aqua file ....");
    let mut logs: Vec<String> = Vec::new();
    let rs = HashChainWithLog {
        chain: aqua_chain,
        logs: logs,
    };

    Ok(rs)
}

// TODO: Fix
pub fn witness_aqua_chain(aqua_chain: HashChain) -> Result<HashChainWithLog, Vec<String>> {
    println!(" witness aqua file ....");
    let mut logs: Vec<String> = Vec::new();
    let rs = HashChainWithLog {
        chain: aqua_chain,
        logs: logs,
    };

    Ok(rs)
}

pub fn generate_aqua_chain(
    body_bytes: Vec<u8>,
    file_name: String,
    domain_id: String,
) -> Result<PageDataWithLog, Vec<String>> {
    println!(" sign aqua file ....");

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
                        merge_hash: Some(verification_hash_current), // Todo! Fix me
                    },
                    signature: None,
                    witness: None,
                },
            )],
        }],
    };

    let mut logs: Vec<String> = Vec::new();
    let rs = PageDataWithLog {
        page_data: pagedata_current,
        logs: logs,
    };

    Ok(rs)
}
