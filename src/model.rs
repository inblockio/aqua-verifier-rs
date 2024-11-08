use aqua_verifier_rs_types::models::page_data::HashChain;
use aqua_verifier_rs_types::models::page_data::PageData;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct RevisionAquaChainResult {
    pub successful: bool,
    pub revisionResults : Vec<RevisionVerificationResult>
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RevisionVerificationResult {
    pub successful: bool,
    pub file_verification: ResultStatus,
    pub content_verification: ResultStatus,
    pub witness_verification: ResultStatus,
    pub signature_verification: ResultStatus,
    pub metadata_verification: ResultStatus,
}


#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub enum ResultStatusEnum {
    MISSING,
    AVAILABLE
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ResultStatus {
   pub status: ResultStatusEnum,
   pub successful: bool,
   pub message: String,
   pub logs : Vec<String>
}


#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct HashChainWithLog{
   pub chain : HashChain,
    pub logs : Vec<String>
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PageDataWithLog{
   pub page_data : PageData,
    pub logs : Vec<String>
}



#[derive(Deserialize, Serialize, Debug)]
pub struct VerifyFileResult {
    pub error_message: Option<String>,
    pub file_hash: Option<String>,
}



#[derive(Debug, Serialize, Deserialize)]
pub struct CheckEtherScanResult {
    pub verification_hash_matches: bool,
    pub message: String,
    pub successful: bool,
}