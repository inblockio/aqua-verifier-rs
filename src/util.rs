use aqua_verifier_rs_types::models::base64::Base64;
use aqua_verifier_rs_types::models::content::RevisionContent;
use aqua_verifier_rs_types::models::hash::Hash;
use aqua_verifier_rs_types::models::metadata::RevisionMetadata;
use aqua_verifier_rs_types::models::page_data::PageData;
use aqua_verifier_rs_types::models::signature::RevisionSignature;
use aqua_verifier_rs_types::models::timestamp::Timestamp;
use aqua_verifier_rs_types::models::witness::{MerkleNode, RevisionWitness};
use base64::decode;
use ethers::types::H512;
use ethers::utils::hash_message;
use libsecp256k1::recover;
use sha3::{Digest, Sha3_512};
use std::fmt::format;
use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, str};

use crate::model::{ResultStatusEnum, RevisionVerificationResult};

#[derive(Debug)]
pub struct VerifyFileResult {
    pub file_hash: Option<String>,
    pub error_message: Option<String>,
    pub logs : Vec<String>
}

pub fn get_hash_sum(content: &str) -> String {
    if content.is_empty() {
        String::new()
    } else {
        let mut hasher = Sha3_512::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

// pub fn generate_hash_from_base64(b64: Base64) -> String {
// let mut hasher = Sha3_512::new();
// hasher.update(base64::decode(b64).unwrap());
// format!("{:x}", hasher.finalize())
// }

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

pub fn verify_file_util(data: RevisionContent) -> (bool, VerifyFileResult) {
    let mut logs : Vec<String>= Vec::new();

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
                logs:logs
            },
        );
    }

    let hash_gen = hex::encode(hash_fromb64.unwrap());

    logs.push(format!("Info : Hash generated {}", hash_gen));
    logs.push(format!("Info : file Hash in chain  {}", file_content_hash.to_string()));
    if file_content_hash.to_string() != hash_gen {
        logs.push("Error :  File content hash does not match the genrated hash".to_string());
        return (
            false,
            VerifyFileResult {
                file_hash: None,
                error_message: Some("File content hash does not match ".to_string()),
                logs:logs
            },
        );
    }
    logs.push("Sucess  :  File content hash does matches the genrated hash".to_string());
    (
        true,
        VerifyFileResult {
            file_hash: Some(file_content_hash.to_string()),
            error_message: None,
            logs:logs
        },
    )
}

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

pub fn verify_metadata_util(data: &RevisionMetadata) -> (bool, String) {
    let metadata_hash = calculate_metadata_hash(
        data.domain_id.clone(),
        data.time_stamp.clone(),
        data.previous_verification_hash,
        data.merge_hash,
    );
    if metadata_hash == data.metadata_hash.to_string() {
        (true, metadata_hash)
    } else {
        (false, "Metadata hash does not match".to_string())
    }
}

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
        (_hashed_msg, Ok(sig)) => {
            println!("Gen signature {}", sig.clone());

            let clean_input_1 = if sig.to_string().to_lowercase().starts_with("0x") {
                sig.to_string().to_lowercase()[2..].to_string()
            } else {
                sig.to_string().to_lowercase()
            };
            let clean_input_2 = if signature_string.to_lowercase().starts_with("0x") {
                signature_string.to_lowercase()[2..].to_string()
            } else {
                signature_string.to_lowercase()
            };

            signature_ok = clean_input_1 == clean_input_2;

            status = if signature_ok {
                "Signature is Valid".to_string()
            } else {
                "Signature is invalid".to_string()
            };

            //todo to be reviewed
            // match ethers::core::types::Signature::recover(&sig, hashed_msg) {
            //     Ok(recovered_address) => {

            // let clean_input_1 = if recovered_address.to_string().to_lowercase().starts_with("0x") {
            //     recovered_address.to_string().to_lowercase()[2..].to_string()
            // } else {
            //     recovered_address.to_string().to_lowercase()
            // };
            // let clean_input_2 = if data.wallet_address.to_string().to_lowercase().starts_with("0x") {
            //     data.wallet_address.to_string().to_lowercase()[2..].to_string()
            // }else{
            //     data.wallet_address.to_string().to_lowercase()
            // };

            //         println!("1 {:#?}",clean_input_1 );
            //         println!("2 {:#?}",clean_input_2 );

            // signature_ok =  clean_input_1==clean_input_2;
            // // signature_ok = recovered_address.to_string().to_lowercase()
            // //     == data.wallet_address.to_string().to_lowercase();

            // status = if signature_ok {
            //     "Signature is Valid".to_string()
            // } else {
            //     "Signature is invalid".to_string()
            // };
            //     }
            //     Err(e) => {
            //         status = format!("An error occurred retrieving signature: {}", e);
            //     }
            // }
        }
        (_, Err(e)) => {
            // Handle invalid signature format
            status = format!("Invalid signature format: {}", e);
        }
    }

    (signature_ok, status)
}

pub fn verify_witness_util(
    witness_data: RevisionWitness,
    verification_hash: String,
    do_verify_merkle_proof: bool,
    alchemy_key: String,
    do_alchemy_key_look_up: bool,
) -> (bool, String) {
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
        return (false, "Verification hashes do not match".to_string());
    }

    if do_verify_merkle_proof {
        if verification_hash == witness_data.domain_snapshot_genesis_hash.to_string() {
            return (
                true,
                "Verification hash is the same as domain snapshot genesis hash".to_string(),
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
            );
        }
    }

    // TODO: Implement the checkTransaction function
    (true, "Look up not performed.".to_string())
}

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

//test function

