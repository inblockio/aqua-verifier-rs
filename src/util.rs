use aqua_verifier_rs_types::models::base64;
use aqua_verifier_rs_types::models::content::RevisionContent;
use aqua_verifier_rs_types::models::metadata::RevisionMetadata;
use aqua_verifier_rs_types::models::signature::RevisionSignature;
use aqua_verifier_rs_types::models::hash::Hash;
use aqua_verifier_rs_types::models::timestamp::Timestamp;
use aqua_verifier_rs_types::models::witness::{RevisionWitness, MerkleNode};
use sha3::{Digest, Sha3_512};
use std::str;



#[derive(Debug)]
struct VerifyFileResult {
    file_hash: Option<String>,
    error_message: Option<String>,
}

fn get_hash_sum(content: &str) -> String {
    if content.is_empty() {
        String::new()
    } else {
        let mut hasher = Sha3_512::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

fn generate_hash_from_base64(b64: &str) -> String {
    let mut hasher = Sha3_512::new();
    //todo fix me
    // hasher.update(base64::decode(b64).unwrap());
    format!("{:x}", hasher.finalize())
}

fn verify_file_util(data: &RevisionContent) -> (bool, VerifyFileResult) {
    if let Some(file_content_hash) = &data.file_hash {
        if let Some(file_content) = &data.file {
            let hash_from_b64 = generate_hash_from_base64(file_content);
            if file_content_hash.clone() == hash_from_b64 {
                return (true, VerifyFileResult {
                    file_hash: Some(file_content_hash.clone()),
                    error_message: None,
                });
            } else {
                return (
                    false,
                    VerifyFileResult {
                        file_hash: None,
                        error_message: Some("File content hash does not match".to_string()),
                    },
                );
            }
        }
    }
    (
        false,
        VerifyFileResult {
            file_hash: None,
            error_message: Some("Revision contains a file, but no file content hash".to_string()),
        },
    )
}

fn verify_content_util(data: &RevisionContent) -> (bool, String) {
    let mut content = String::new();
    for slotcontent in data.content.values() {
        content += slotcontent;
    }
    let content_hash = get_hash_sum(&content);
    let  data_content_hash_str=  format!("{:#?}", data.content_hash);
    if content_hash ==  data_content_hash_str{
        (true, content_hash)
    } else {
        (false, "Content hash does not match".to_string())
    }
}

fn verify_metadata_util(data: &RevisionMetadata) -> (bool, String) {
    let metadata_hash = calculate_metadata_hash(
        &data.domain_id,
        &data.time_stamp,
        data.previous_verification_hash.as_deref(),
        data.merge_hash.as_deref(),
    );
    if metadata_hash == data.metadata_hash.to_string() {
        (true, metadata_hash)
    } else {
        (false, "Metadata hash does not match".to_string())
    }
}

fn calculate_metadata_hash(
    domain_id:String,
    timestamp:Timestamp,
    previous_verification_hash: Option<Hash>,
    merge_hash: Option<Hash>,
) -> String {
    let mut content : String= domain_id + &timestamp.to_string();
    if let Some(prev_hash) = previous_verification_hash {
        content += &prev_hash.to_string();
    }
    if let Some(merge) = merge_hash {
        content += &merge.to_string();
    }
    get_hash_sum(&content)
}

fn verify_signature_util(
    data: &RevisionSignature,
    verification_hash: &str,
) -> (bool, String) {
    if verification_hash.is_empty() {
        return (false, "Verification hash must not be empty".to_string());
    }

    let padded_message = format!(
        "I sign the following page verification_hash: [0x{}]",
        verification_hash
    );

    (true, "todo".to_string())
    //todo
    // match ethers::utils::recover_address(&ethers::utils::keccak256(padded_message.as_bytes()), &data.signature) {
    //     Ok(recovered_address) => {
    //         let signature_ok = recovered_address.to_lowercase() == data.wallet_address.to_lowercase();
    //         (
    //             signature_ok,
    //             if signature_ok {
    //                 "Signature is Valid".to_string()
    //             } else {
    //                 "Signature is invalid".to_string()
    //             },
    //         )
    //     }
    //     Err(e) => (false, format!("An error occurred retrieving signature: {}", e)),
    // }
}

async fn verify_witness_util(
    witness_data: &RevisionWitness,
    verification_hash: String,
    do_verify_merkle_proof: bool,
    alchemy_key: &str,
) -> (bool, String) {
    let actual_witness_event_verification_hash =
        get_hash_sum(&(witness_data.domain_snapshot_genesis_hash.clone().to_string() + &witness_data.merkle_root.to_string()));

    if actual_witness_event_verification_hash != witness_data.witness_event_verification_hash.to_string() {
        return (false, "Verification hashes do not match".to_string());
    }

    if do_verify_merkle_proof {
        if verification_hash == witness_data.domain_snapshot_genesis_hash.to_string() {
            return (true, "Verification hash is the same as domain snapshot genesis hash".to_string());
        } else {
            let merkle_proof_is_ok = verify_merkle_integrity(&witness_data.structured_merkle_proof, verification_hash);
            return  (
                merkle_proof_is_ok,
                if merkle_proof_is_ok {
                    "Merkle proof is OK".to_string()
                } else {
                    "Error verifying merkle proof".to_string()
                }
            );
        }
    }

    // TODO: Implement the checkTransaction function
    (true, "Look up not performed.".to_string())
}

fn verify_merkle_integrity(merkle_branch: &[MerkleNode], verification_hash: String) -> bool {
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