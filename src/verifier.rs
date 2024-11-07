use std::collections::BTreeMap;

use crate::model::{
    HashChainWithLog, PageDataWithLog, ResultStatus, ResultStatusEnum, RevisionAquaChainResult,
    RevisionVerificationResult,
};
use aqua_verifier_rs_types::models::base64::Base64;
use aqua_verifier_rs_types::models::content::{FileContent, RevisionContent};
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
use sha3::{Digest, Sha3_512};

use crate::util::{verify_signature_util, verify_witness_util};
use crate::verification::{content_hash, metadata_hash, verification_hash};

const MAX_FILE_SIZE: u32 = 20 * 1024 * 1024; // 20 MB in bytes

pub fn verify_revision(revision: Revision) -> RevisionVerificationResult {
    let mut logs: Vec<String> = Vec::new();
    let default_result_status: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
        logs: logs,
    };

    let revision_result: RevisionVerificationResult = RevisionVerificationResult {
        successful: false,
        file_verification: default_result_status.clone(),
        content_verification: default_result_status.clone(),
        witness_verification: default_result_status.clone(),
        signature_verification: default_result_status.clone(),
        metadata_verification: default_result_status.clone(),
    };

    return revision_result;
}

pub fn verify_signature(
    signature: RevisionSignature,
    previous_verification_hash: String,
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
    let mut revisionResultsData: Vec<RevisionVerificationResult> = Vec::new();

    let mut hashChainResult: RevisionAquaChainResult = RevisionAquaChainResult {
        successful: true,
        revisionResults: revisionResultsData,
    };

    return hashChainResult;
}

pub fn sign_aqua_chain(aqua_chain: HashChain) -> Result<HashChainWithLog, Vec<String>> {
    println!(" sign aqua file ....");
    let mut logs: Vec<String> = Vec::new();
    let rs = HashChainWithLog {
        chain: aqua_chain,
        logs: logs,
    };

    Ok(rs)
}

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
        domain_id.clone(), timestamp_current
    ));

    let metadata_hash_current = metadata_hash(&domain_id.clone(), &timestamp_current, None);
    logs.push(format!("Meta data HASH: {}", metadata_hash_current));
    let verification_hash_current =
        verification_hash(&content_hash_current, &metadata_hash_current, None, None);

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
                        content: content_current,
                        content_hash: content_hash_current,
                        file_hash: content_hash_current, //todo fix me
                    },
                    metadata: RevisionMetadata {
                        domain_id: domain_id.clone(),
                        time_stamp: timestamp_current,
                        previous_verification_hash: None,
                        metadata_hash: metadata_hash_current,
                        verification_hash: verification_hash_current,
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
