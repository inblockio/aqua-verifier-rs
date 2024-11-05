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


#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum ResultStatusEnum {
    MISSING,
    AVAILABLE
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ResultStatus {
   pub status: ResultStatusEnum,
   pub successful: bool,
   pub message: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct VerifyFileResult {
    pub error_message: Option<String>,
    pub file_hash: Option<String>,
}
