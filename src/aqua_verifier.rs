use aqua_verifier_rs_types::models::content::{RevisionContentSignature, RevisionWitnessInput};
use aqua_verifier_rs_types::models::hash::Hash;
use aqua_verifier_rs_types::models::page_data::PageData;
use std::error::Error;

use crate::model::PageDataWithLog;
use crate::verifier::{delete_revision_in_aqua_chain, generate_aqua_chain, sign_aqua_chain, witness_aqua_chain};
use crate::{
    model::{ResultStatus, RevisionAquaChainResult, RevisionVerificationResult},
    verifier::{verify_aqua_chain, verify_revision, verify_signature, verify_witness},
};
use aqua_verifier_rs_types::models::{
    page_data::HashChain, revision::Revision, signature::RevisionSignature,
    witness::RevisionWitness,
};

const UNSUPPORTED_VERSION: &str = "UNSUPPORTED VERSION";
const KEY_NOT_SET : &str  ="ALCHEMY/INFURA KEY NOT SET";

#[derive(Debug)]
pub struct VerificationOptions {
    pub version: f32,
    pub strict: bool,
    pub allow_null: bool,
    pub verification_platform: String,
    pub chain: String,
    pub api_key: String,
}

impl Default for VerificationOptions {
    fn default() -> Self {
        VerificationOptions {
            version: 1.2,
            strict: false,
            allow_null: false,
            verification_platform: "none".to_string(),
            chain: "sepolia".to_string(),
            api_key: "".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct AquaVerifier {
    options: VerificationOptions,
}

impl AquaVerifier {
    pub fn default(options: Option<VerificationOptions>) -> Self {
        let mut options = options.unwrap_or_default();
        options.strict = false;
        options.allow_null = false;
        options.verification_platform = "none".to_string();
        options.chain = "sepolia".to_string();
        options.api_key = "".to_string();

        AquaVerifier { options }
    }

    pub fn new(options: Option<VerificationOptions>) -> Self {
        // let mut options = options.unwrap_or_default();
        // options.strict = false;
        // options.allow_null = false;
        // options.verification_platform = options// "none".to_string();
        // options.chain = "sepolia".to_string();
        // options.api_key = "".to_string();

        let _options = match options {
            Some(x) => x,
            None => panic!("PASS IN OPTIONS")
        };

        AquaVerifier { options: _options }
    }

    pub fn fetch_verification_options(&self) -> &VerificationOptions {
        &self.options
    }

    pub fn verify_revision(
        &self,
        revision: &Revision,
    ) -> Result<RevisionVerificationResult, Box<dyn Error>> {
        if self.options.verification_platform != "none" && self.options.api_key.is_empty() {
            return Err(KEY_NOT_SET.into());
        }
        // Call the actual verification function (needs to be defined)
        println!("Verification options in verify revision func 1: {}: {}: {}", self.options.verification_platform.clone(),
        self.options.chain.clone(),
        self.options.api_key.clone());
        Ok(verify_revision(
            revision.clone(),
            self.options.verification_platform.clone(),
            self.options.chain.clone(),
            self.options.api_key.clone(),
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
        if self.options.verification_platform != "none" && self.options.api_key.is_empty() {
            return Err(KEY_NOT_SET.into());
        }
        // Call the actual witness verification function (needs to be defined)
        Ok(verify_witness(
            witness.clone(),
            verification_hash.to_string(),
            do_verify_merkle_proof,
            self.options.verification_platform.clone(),
            self.options.chain.clone(),
            self.options.api_key.clone(),
        ))
    }

    pub fn verify_aqua_chain(
        &self,
        hash_chain: &HashChain,
    ) -> Result<RevisionAquaChainResult, Box<dyn Error>> {
        if self.options.version != 1.2 {
            return Err(UNSUPPORTED_VERSION.into());
        }
        if self.options.verification_platform != "none" && self.options.api_key.is_empty() {

            return Err(KEY_NOT_SET.into());
        }
        // Call the actual Aqua chain verification function (needs to be defined)
        Ok(verify_aqua_chain(
            hash_chain.clone(),
            self.options.verification_platform.clone(),
            self.options.chain.clone(),
            self.options.api_key.clone(),
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

    pub fn sign_aqua_chain(
        &self,
        mut aqua_chain: PageData,
        revision_content: RevisionContentSignature,
    ) -> Result<(PageData, Vec<String>), Vec<String>> {
        if self.options.version != 1.2 {
            let mut tmp = Vec::new();
            tmp.push(UNSUPPORTED_VERSION.to_string());
            return Err(tmp);
        }
        return sign_aqua_chain(aqua_chain, revision_content);
    }

    pub fn witness_aqua_chain(&self, mut aqua_chain : PageData,  witness_content : RevisionWitnessInput) -> Result<(PageData, Vec<String>), Vec<String>> {
        if self.options.version != 1.2 {
            let mut tmp = Vec::new();
            tmp.push(UNSUPPORTED_VERSION.to_string());
            return Err(tmp);
        }
        return witness_aqua_chain(aqua_chain, witness_content);
    }

    pub fn delete_revision_in_aqua_chain(&self, aqua_chain: PageData, revision_count_for_deletion : i32) ->  Result<(PageData, Vec<String>), Vec<String>> {
        if self.options.version != 1.2 {
            let mut tmp = Vec::new();
            tmp.push(UNSUPPORTED_VERSION.to_string());
            return Err(tmp);
        }
        return delete_revision_in_aqua_chain(aqua_chain, revision_count_for_deletion);

    }
}
