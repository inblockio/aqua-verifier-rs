use aqua_verifier_rs_types::models::{
    page_data::HashChain, revision::Revision, signature::RevisionSignature,
    witness::RevisionWitness,
};

use crate::model::{
    ResultStatus, ResultStatusEnum, RevisionAquaChainResult, RevisionVerificationResult, HashChainWithLog,
};

use crate::util::{verify_signature_util, verify_witness_util};

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
    let mut logs: Vec<String> = Vec::new();

    let mut default_result_status: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
        logs : logs
    };

    let (signatureOk, signatureMessage) = verify_signature_util(signature, previous_verification_hash) ;

    default_result_status.status = ResultStatusEnum::AVAILABLE ;
    default_result_status.successful = signatureOk ; 
    default_result_status.message = signatureMessage ;

    return default_result_status;
}

pub fn verify_witness(
    witness: RevisionWitness,
    verification_hash: String,
    do_verify_merkle_proof: bool,
    alchemy_key: String,
    do_alchemy_key_look_up: bool,
) -> ResultStatus {
    let mut logs: Vec<String> = Vec::new();
    let mut default_result_status: ResultStatus = ResultStatus {
        status: ResultStatusEnum::MISSING,
        successful: false,
        message: "default".to_string(),
        logs : logs
    };


    let (witnessOk, witnessMessage) =  verify_witness_util(
        witness,
         verification_hash,
          do_verify_merkle_proof
         , alchemy_key,
          do_alchemy_key_look_up) ; 

    default_result_status.status = ResultStatusEnum::AVAILABLE ;
    default_result_status.successful = witnessOk ; 
    default_result_status.message = witnessMessage ;

    return default_result_status;
}

pub fn verify_aqua_chain(
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

pub fn sign_aqua_chain(aqua_chain: HashChain) -> Result<HashChainWithLog, Vec<String>> {
    println!(" sign aqua file ....");
    let mut logs : Vec<String> = Vec::new();
    let rs = HashChainWithLog{
        chain: aqua_chain,
        logs: logs
    };

    Ok(rs)
}

pub fn witness_aqua_chain(aqua_chain: HashChain) -> Result<HashChainWithLog, Vec<String>> {

    println!(" witness aqua file ....");
    let mut logs : Vec<String> = Vec::new();
    let rs = HashChainWithLog{
        chain: aqua_chain,
        logs: logs
    };

    Ok(rs)
}
