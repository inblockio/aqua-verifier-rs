use std::collections::BTreeMap;

use aqua_verifier_rs_types::{
    crypt,
    models::{content::RevisionContent, hash::Hash, revision::Revision, timestamp::Timestamp},
};

use sha3::Digest;

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

