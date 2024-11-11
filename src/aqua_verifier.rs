use aqua_verifier_rs_types::models::content::RevisionContentSignature;
use aqua_verifier_rs_types::models::hash::Hash;
use aqua_verifier_rs_types::models::page_data::PageData;
use aqua_verifier_rs_types::models::public_key::PublicKey;
use aqua_verifier_rs_types::models::signature::Signature;
use aqua_verifier_rs_types::models::timestamp::Timestamp;
use std::error::Error;

use aqua_verifier_rs_types::models::{
    page_data::HashChain, revision::Revision, signature::RevisionSignature,
    witness::RevisionWitness,
};
use crate::model::PageDataWithLog;
use crate::util::{metadata_hash, verification_hash, signature_hash};
use crate::verifier::generate_aqua_chain;
use crate::{
    model::{ResultStatus, RevisionAquaChainResult, RevisionVerificationResult},
    verifier::{verify_aqua_chain, verify_revision, verify_signature, verify_witness},
};

const UNSUPPORTED_VERSION: &str = "UNSUPPORTED VERSION";

#[derive(Debug)]
pub struct VerificationOptions {
    pub version: f32,
    pub strict: bool,
    pub allow_null: bool,
    pub alchemy_key: String,
    pub do_alchemy_key_lookup: bool,
}

impl Default for VerificationOptions {
    fn default() -> Self {
        VerificationOptions {
            version: 1.2,
            strict: false,
            allow_null: false,
            alchemy_key: String::new(),
            do_alchemy_key_lookup: false,
        }
    }
}

#[derive(Debug)]
pub struct AquaVerifier {
    options: VerificationOptions,
}

impl AquaVerifier {
    pub fn new(options: Option<VerificationOptions>) -> Self {
        let mut options = options.unwrap_or_default();
        options.strict = false;
        options.allow_null = false;

        AquaVerifier { options }
    }

    pub fn fetch_verification_options(&self) -> &VerificationOptions {
        &self.options
    }

    pub fn verify_revision(
        &self,
        revision: &Revision,
    ) -> Result<RevisionVerificationResult, Box<dyn Error>> {
        if self.options.do_alchemy_key_lookup && self.options.alchemy_key.is_empty() {
            return Err("ALCHEMY KEY NOT SET".into());
        }
        // Call the actual verification function (needs to be defined)
        Ok(verify_revision(
            revision.clone(),
            self.options.alchemy_key.clone(),
            self.options.do_alchemy_key_lookup,
        ))
    }

    pub fn verify_signature(
        &self,
        signature: &RevisionSignature,
        previous_hash: Hash,
    ) -> Result<ResultStatus, Box<dyn Error>> {
        if self.options.version == 1.2 {
            // Call the actual signature verification function (needs to be defined)
            return Ok(verify_signature(signature.clone(), previous_hash));
        }
        Err(UNSUPPORTED_VERSION.into())
    }

    pub fn verify_witness(
        &self,
        witness: &RevisionWitness,
        verification_hash: &str,
        do_verify_merkle_proof: bool,
    ) -> Result<ResultStatus, Box<dyn Error>> {
        if self.options.version != 1.2 {
            return Err(UNSUPPORTED_VERSION.into());
        }
        if self.options.do_alchemy_key_lookup && self.options.alchemy_key.is_empty() {
            return Err("ALCHEMY KEY NOT SET".into());
        }
        // Call the actual witness verification function (needs to be defined)
        Ok(verify_witness(
            witness.clone(),
            verification_hash.to_string(),
            do_verify_merkle_proof,
            self.options.alchemy_key.clone(),
            self.options.do_alchemy_key_lookup,
        ))
    }

    pub fn verify_aqua_chain(
        &self,
        hash_chain: &HashChain,
    ) -> Result<RevisionAquaChainResult, Box<dyn Error>> {
        if self.options.version != 1.2 {
            return Err(UNSUPPORTED_VERSION.into());
        }
        if self.options.do_alchemy_key_lookup && self.options.alchemy_key.is_empty() {
            return Err("ALCHEMY KEY NOT SET".into());
        }
        // Call the actual Aqua chain verification function (needs to be defined)
        Ok(verify_aqua_chain(
            hash_chain.clone(),
            self.options.alchemy_key.clone(),
            self.options.do_alchemy_key_lookup,
        ))
    }

    pub fn verify_merkle_tree(&self) -> Result<(), Box<dyn Error>> {
        Err("Unimplemented error .... ".into())
    }

    pub fn generate_aqua_chain(
        &self,
        body_bytes: Vec<u8>,
        file_name: String,
        domain_id: String,
    ) -> Result<PageDataWithLog, Vec<String>> {
        if self.options.version != 1.2 {
            let mut tmp = Vec::new();
            tmp.push(UNSUPPORTED_VERSION.to_string());
            return Err(tmp);
        }
        return generate_aqua_chain(body_bytes, file_name, domain_id);
    }

    pub fn sign_aqua_chain(&self, mut aqua_chain  :  PageData, revision_content : RevisionContentSignature) -> Result<(PageData,Vec<String> ), Vec<String>  > {
        // Err("Unimplemented error .... ".into())
let mut log_data : Vec<String> = Vec::new();
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
                
                return Err( log_data);
            }
        };
        let pubk = match revision_content.publickey.parse::<PublicKey>() {
            Ok(p) => {
                log_data.push("Success : public  key  parsed successfully".to_string());

                p
            }
            Err(e) => {
               

                log_data.push(format!("error : Failed to parse  public key: {:?}", e));
               

                return Err(  log_data);
            }
        };
        let addr = match ethaddr::Address::from_str_checksum(&revision_content.wallet_address) {
            Ok(a) => {
                log_data.push("wallet address parsed successfully".to_string());

                a
            }
            Err(e) => {
                log_data.push(format!("Failed to parse wallet address: {:?}", e));

                return Err( log_data);
            }
        };

        let sig_hash = signature_hash(&sig, &pubk);

        rev2.signature = Some(RevisionSignature {
            signature: sig,
            public_key: pubk,
            signature_hash: sig_hash.clone(),
            wallet_address: addr,
        });

        let timestamp_current = Timestamp::from(chrono::Utc::now().naive_utc());
        rev2.metadata.time_stamp = timestamp_current.clone();

        let metadata_hash_current =
            metadata_hash(&aqua_chain.pages[0].domain_id, &timestamp_current, Some(ver1));

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

    pub fn witness_aqua_chain(&self) -> Result<(), Box<dyn Error>> {
        Err("Unimplemented error .... ".into())
    }
}
