use aqua_verifier_rs_types::models::hash::Hash;
use std::error::Error;

use aqua_verifier_rs_types::models::{
    page_data::HashChain, revision::Revision, signature::RevisionSignature,
    witness::RevisionWitness,
};

use crate::model::PageDataWithLog;
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
    ) -> Result<PageDataWithLog, Box<dyn Error>> {
        if self.options.version != 1.2 {
            return Err(UNSUPPORTED_VERSION.into());
        }

        let res = generate_aqua_chain(body_bytes,file_name,domain_id);

        if res.is_err(){
            return  Err(format!("{:#?}",res.err()).into());
        }
        return Ok(res.unwrap());
    }

    pub fn sign_aqua_chain(&self) -> Result<(), Box<dyn Error>> {
        Err("Unimplemented error .... ".into())
    }

    pub fn witness_aqua_chain(&self) -> Result<(), Box<dyn Error>> {
        Err("Unimplemented error .... ".into())
    }
}
