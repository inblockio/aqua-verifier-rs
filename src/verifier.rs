use aqua_verifier_rs_types::models::{
    page_data::HashChain, revision::Revision, signature::RevisionSignature,
    witness::RevisionWitness,
};

use crate::model::{
    ResultStatus, ResultStatusEnum, RevisionAquaChainResult, RevisionVerificationResult,
};

pub fn verify_revision(revision: Revision) -> RevisionVerificationResult {

    let mut logs : Vec<String> =  Vec::new();
    let default_result_status: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
        logs: logs
    };

    let revision_result: RevisionVerificationResult = RevisionVerificationResult {
        successful: false,
        file_verification: default_result_status.clone(),
        content_verification: default_result_status.clone(),
        witness_verification: default_result_status.clone(),
        signature_verification: default_result_status.clone(),
        metadata_verification: default_result_status.clone()

    };


  return revision_result;   
}

pub fn verify_signature(
    signature: RevisionSignature,
    previous_verification_hash: String,
) -> ResultStatus {
    let mut default_result_status: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
    };

    let (signatureOk, signatureMessage) = verify_signature_util(signature, previous_verification_hash) ;

    defaultResultStatus.status = ResultStatusEnum.AVAILABLE ;
    defaultResultStatus.successful = signatureOk ; 
    defaultResultStatus.message = signatureMessage ;

    return default_result_status;
}

pub fn verify_witness(
    witness: RevisionWitness,
    verification_hash: String,
    do_verify_merkle_proof: bool,
    alchemy_key: String,
    do_alchemy_key_look_up: bool,
) -> ResultStatus {
    let mut default_result_status: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
    };


    let (witnessOk, witnessMessage) =  verify_witness_util(witness, verification_hash, doVerifyMerkleProof, alchemyKey, doAlchemyKeyLookUp) ; 

    defaultResultStatus.status = ResultStatusEnum.AVAILABLE ;
    defaultResultStatus.successful = witnessOk ; 
    defaultResultStatus.message = witnessMessage ;

    return default_result_status;
}

pub fn verifyAquaChain(
    aqua_chain: HashChain,
    alchemy_key: String,
    do_alchemy_key_look_up: bool,
) -> RevisionAquaChainResult {
    let mut revisionResultsData: Vec<RevisionVerificationResult> = Vec::new();

    let mut hashChainResult: RevisionAquaChainResult = RevisionAquaChainResult {
        successful: true,
        revisionResults: revisionResultsData,
    };

    return hashChainResult;
}

pub fn sign_aqua_chain() {
    println!(" sign aqua file ....");
}

pub fn witness_aqua_chain() {

    println!(" witness aqua file ....");
}
