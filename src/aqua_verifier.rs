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


/// Configuration options for the AquaVerifier
#[derive(Debug)]
pub struct VerificationOptions {
    /// Version of the verification protocol (currently supports 1.2)
    pub version: f32,
    /// Whether to enforce strict verification rules
    pub strict: bool,
    /// Whether to allow null values in verification
    pub allow_null: bool,
    /// Platform used for verification (e.g., "infura", "alchemy")
    pub verification_platform: String,
    /// Blockchain network to use (e.g., "sepolia")
    pub chain: String,
    /// API key for the verification platform
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

/// Main verifier struct implementing Aqua chain operations
#[derive(Debug)]
pub struct AquaVerifier {
    options: VerificationOptions,
}

impl AquaVerifier {
     /// Creates a new AquaVerifier instance with default settings
    /// 
    /// # Arguments
    /// * `options` - Optional verification options. If None, uses default values
    /// 
    /// # Returns
    /// Returns an AquaVerifier instance with specified or default options
    pub fn default(options: Option<VerificationOptions>) -> Self {
        let mut options = options.unwrap_or_default();
        options.strict = false;
        options.allow_null = false;
        options.verification_platform = "none".to_string();
        options.chain = "sepolia".to_string();
        options.api_key = "".to_string();

        AquaVerifier { options }
    }

    /// Creates a new AquaVerifier instance with required options
    /// 
    /// # Arguments
    /// * `options` - Required verification options
    /// 
    /// # Panics
    /// Panics if options are not provided
    pub fn new(options: Option<VerificationOptions>) -> Self {
        

        let _options = match options {
            Some(x) => x,
            None => panic!("PASS IN OPTIONS")
        };

        AquaVerifier { options: _options }
    }

    /// Returns the current verification options
    pub fn fetch_verification_options(&self) -> &VerificationOptions {
        &self.options
    }

     /// Verifies a revision in the Aqua chain
    /// 
    /// # Arguments
    /// * `revision` - The revision to verify
    /// 
    /// # Returns
    /// Returns a Result containing RevisionVerificationResult or an error
    /// 
    /// # Errors
    /// Returns an error if:
    /// - API key is not set when using infura/alchemy
    /// - Verification fails
    /// -if the hashes are not the same(metadat hash, content hash, witness hash and revision hash )
    pub fn verify_revision(
        &self,
        revision: &Revision,
    ) -> Result<RevisionVerificationResult, Box<dyn Error>> {
        if self.options.verification_platform == "infura" || self.options.verification_platform == "alchemy" {
            if self.options.api_key.is_empty() {
            return Err(KEY_NOT_SET.into());
            }
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

    /// Verifies a signature against a previous hash
    /// 
    /// # Arguments
    /// * `signature` - The signature to verify
    /// * `previous_hash` - Hash of the previous revision
    /// 
    /// # Returns
    /// Returns a Result containing ResultStatus or an error
    /// 
    /// # Errors
    /// Returns an error if version is not supported (must be 1.2)
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

    /// Verifies a witness against a verification hash
    /// 
    /// # Arguments
    /// * `witness` - The witness to verify
    /// * `verification_hash` - Hash to verify against
    /// * `do_verify_merkle_proof` - Whether to verify the Merkle proof
    /// 
    /// # Returns
    /// Returns a Result containing ResultStatus or an error
    /// 
    /// # Errors
    /// Returns an error if:
    /// - Version is not 1.2
    /// - API key is not set when using infura/alchemy
    pub fn verify_witness(
        &self,
        witness: &RevisionWitness,
        verification_hash: &str,
        do_verify_merkle_proof: bool,
    ) -> Result<ResultStatus, Box<dyn Error>> {
        if self.options.version != 1.2 {
            return Err(UNSUPPORTED_VERSION.into());
        }
        if self.options.verification_platform == "infura" || self.options.verification_platform == "alchemy" {
            if self.options.api_key.is_empty() {
            return Err(KEY_NOT_SET.into());
            }
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


     /// Verifies an entire Aqua chain
    /// 
    /// # Arguments
    /// * `hash_chain` - The hash chain to verify
    /// 
    /// # Returns
    /// Returns a Result containing RevisionAquaChainResult or an error
    /// 
    /// # Errors
    /// Returns an error if:
    /// - Version is not 1.2
    /// - API key is not set when using infura/alchemy
    pub fn verify_aqua_chain(
        &self,
        hash_chain: &HashChain,
    ) -> Result<RevisionAquaChainResult, Box<dyn Error>> {
        if self.options.version != 1.2 {
            return Err(UNSUPPORTED_VERSION.into());
        }
        if self.options.verification_platform == "infura" || self.options.verification_platform == "alchemy" {
            if self.options.api_key.is_empty() {
            return Err(KEY_NOT_SET.into());
            }
        }
        // Call the actual Aqua chain verification function (needs to be defined)
        Ok(verify_aqua_chain(
            hash_chain.clone(),
            self.options.verification_platform.clone(),
            self.options.chain.clone(),
            self.options.api_key.clone(),
        ))
    }

    /// Verifies a Merkle tree (Currently unimplemented)
    /// 
    /// # Returns
    /// Currently returns an unimplemented error
    pub fn verify_merkle_tree(&self) -> Result<(), Box<dyn Error>> {
        Err("Unimplemented error .... ".into())
    }

    /// Generates a new Aqua chain
    /// 
    /// # Arguments
    /// * `body_bytes` - Content bytes for the chain
    /// * `file_name` - Name of the file
    /// * `domain_id` - Domain identifier
    /// 
    /// # Returns
    /// Returns a Result containing PageDataWithLog or a vector of error strings
    /// 
    /// # Errors
    /// Returns an error if version is not 1.2
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

    /// Signs an Aqua chain
    /// 
    /// # Arguments
    /// * `aqua_chain` - The chain to sign
    /// * `revision_content` - Content signature for the revision
    /// 
    /// # Returns
    /// Returns a Result containing (PageData, Vec<String>) or a vector of error strings
    /// 
    /// # Errors
    /// Returns an error if version is not 1.2
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

    /// Adds a witness to an Aqua chain
    /// 
    /// # Arguments
    /// * `aqua_chain` - The chain to witness
    /// * `witness_content` - Witness input data
    /// 
    /// # Returns
    /// Returns a Result containing (PageData, Vec<String>) or a vector of error strings
    /// 
    /// # Errors
    /// Returns an error if version is not 1.2
    pub fn witness_aqua_chain(&self, mut aqua_chain : PageData,  witness_content : RevisionWitnessInput) -> Result<(PageData, Vec<String>), Vec<String>> {
        if self.options.version != 1.2 {
            let mut tmp = Vec::new();
            tmp.push(UNSUPPORTED_VERSION.to_string());
            return Err(tmp);
        }
        return witness_aqua_chain(aqua_chain, witness_content);
    }

      /// Deletes a revision from an Aqua chain
    /// 
    /// # Arguments
    /// * `aqua_chain` - The chain to modify
    /// * `revision_count_for_deletion` - Index of revision to delete
    /// 
    /// # Returns
    /// Returns a Result containing (PageData, Vec<String>) or a vector of error strings
    /// 
    /// # Errors
    /// Returns an error if version is not 1.2
    pub fn delete_revision_in_aqua_chain(&self, aqua_chain: PageData, revision_count_for_deletion : i32) ->  Result<(PageData, Vec<String>), Vec<String>> {
        if self.options.version != 1.2 {
            let mut tmp = Vec::new();
            tmp.push(UNSUPPORTED_VERSION.to_string());
            return Err(tmp);
        }
        return delete_revision_in_aqua_chain(aqua_chain, revision_count_for_deletion);

    }
}
