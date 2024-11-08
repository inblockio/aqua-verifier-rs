
use ::core::str;
use std::collections::HashMap;
use ethers::prelude::*;
use async_trait::async_trait;
use ethers::providers::{Provider, Http};

use crate::model::CheckEtherScanResult;


pub fn network_list () -> HashMap<String, String> { 
        // NETWORK_RPC_MAP: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("mainnet".to_string(), "https://eth-mainnet.g.alchemy.com/v2/".to_string());
        m.insert("holesky".to_string(), "https://eth-holesky.g.alchemy.com/v2/".to_string());
        m.insert("sepolia".to_string(), "https://eth-sepolia.g.alchemy.com/v2/".to_string());
        m
}



#[async_trait]
pub trait TransactionVerifier {
    async fn check_transaction(
        network: &str,
        tx_hash: &str,
        expected_verification_hash: &str,
        alchemy_key: &str,
    ) -> Result<CheckEtherScanResult, String>;
}

pub struct EtherTransactionVerifier;

#[async_trait]
impl TransactionVerifier for EtherTransactionVerifier {
    async fn check_transaction(
        network: &str,
        tx_hash: &str,
        expected_verification_hash: &str,
        alchemy_key: &str,
    ) -> Result<CheckEtherScanResult, String> {
        let mut result = CheckEtherScanResult {
            verification_hash_matches: false,
            message: String::new(),
            successful: false,
        };

        let rpc_url = match network_list().get(network) {
            Some(url) => format!("{}{}", url, alchemy_key),
            None => return Err(format!("Unsupported network: {}", network)),
        };

        let provider = match Provider::<Http>::try_from(rpc_url.as_str()) {
            Ok(provider) => provider,
            Err(_) => return Err("Failed to create provider".to_string()),
        };

        let tx_hash = match tx_hash.parse() {
            Ok(hash) => hash,
            Err(_) => return Err("Invalid transaction hash format".to_string()),
        };

        match provider.get_transaction(tx_hash).await {
            Ok(Some(tx)) => {
                let input_data = tx.input.clone();

                // Convert input data to a string
                let input_data_str = match str::from_utf8(&input_data) {
                    Ok(s) => s,
                    Err(_) => {
                        result.message = "Failed to interpret transaction input as UTF-8 string".to_string();
                        return Ok(result);
                    }
                };

                let function_selector = "0x9cef4ea1";

                if input_data_str.starts_with(function_selector) {
                    // Extract the verification hash directly from the input data string
                    let actual_verification_hash = &input_data_str[10..138];
                    let hash_matches = actual_verification_hash.eq_ignore_ascii_case(expected_verification_hash);

                    result.verification_hash_matches = hash_matches;
                    result.successful = hash_matches;
                    result.message = if hash_matches {
                        "Verification hash matches".to_string()
                    } else {
                        "Verification hash does not match".to_string()
                    };
                } else {
                    result.message = "Transaction data does not contain expected function selector".to_string();
                }
                Ok(result)
            }
            Ok(None) => {
                result.message = "Transaction not found".to_string();
                Ok(result)
            }
            Err(e) => {
                result.message = format!("An error occurred: {}", e);
                Err(result.message.clone())
            }
        }
    }
}
