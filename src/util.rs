use aqua_verifier_rs_types::models::{
    page_data::HashChain, revision::Revision, signature::RevisionSignature,
    witness::RevisionWitness,
};

use crate::model::{
    ResultStatus, ResultStatusEnum, RevisionAquaChainResult, RevisionVerificationResult,
};

pub fn verifyRevision(revision: Revision) -> RevisionVerificationResult {

    let default_result_status: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string()
    };

    let revisionResult: RevisionVerificationResult = RevisionVerificationResult {
        successful: false,
        file_verification: default_result_status.clone(),
        content_verification: default_result_status.clone(),
        witness_verification: default_result_status.clone(),
        signature_verification: default_result_status.clone(),
        metadata_verification: default_result_status.clone()

    };


  return revisionResult;   
}

pub fn verifySignature(
    signature: RevisionSignature,
    previous_verification_hash: String,
) -> ResultStatus {
    let mut defaultResultStatus: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
    };

    return defaultResultStatus;
}

pub fn verifyWitness(
    witness: RevisionWitness,
    verification_hash: String,
    doVerifyMerkleProof: bool,
    alchemyKey: String,
    doAlchemyKeyLookUp: bool,
) -> ResultStatus {
    let mut defaultResultStatus: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
    };

    return defaultResultStatus;
}

pub fn verifyAquaChain(
    aquaChain: HashChain,
    alchemyKey: String,
    doAlchemyKeyLookUp: bool,
) -> RevisionAquaChainResult {
    let mut revisionResultsData: Vec<RevisionVerificationResult> = Vec::new();

    let mut hashChainResult: RevisionAquaChainResult = RevisionAquaChainResult {
        successful: true,
        revisionResults: revisionResultsData,
    };

    return hashChainResult;
}

pub fn signFile() {}

pub fn witnessFile() {}
