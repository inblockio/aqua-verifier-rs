use ethers::{
    middleware::SignerMiddleware,
    prelude::*,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
};
use eyre::{Report, Result, WrapErr};
use regex::Regex;
use serde::Deserialize;
use serde_json::from_value;
use std::convert::TryFrom;
use crate::look_up::look_up_utils::extract_etherscan_tx_details;
use crate::look_up::constants::{
    UrlProvider, ALCHEMY_API_KEY_MUST_BE_SET, FAILED_TO_CREATE_PROVIDER,
    FAILED_TO_DESERIALIZE_BLOCK_TIME, FAILED_TO_DESERIALIZE_TRANSACTION, FAILED_TO_GET_BLOCK,
    FAILED_TO_GET_CHAIN_ID, FAILED_TO_GET_TRANSACTION, FAILED_TO_PARSE_BLOCK_NUMBER,
    FAILED_TO_PARSE_INPUT, FAILED_TO_PARSE_TIMESTAMP, FAILED_TO_PARSE_TRANSACTION_HASH,
    FAILED_TO_PARSE_WALLET_KEY, INFURA_KEY_MUST_BE_SET, SELF_HOSTED_API_KEY_MUST_BE_SET,
    SIGNER_PRIVATE_KEY_MUST_BE_SET,
};

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct CustomTransaction {
    blockNumber: String,
    input: String,
}

#[derive(Deserialize, Debug)]
struct Blocktime {
    timestamp: String,
}

impl UrlProvider {
    fn to_url(self, chain_id: u32) -> Option<&'static str> {
        match self {
            UrlProvider::Infura => chain_id_to_infura_url(chain_id),
            UrlProvider::SelfHosted => chain_id_to_self_hosted_url(chain_id),
            UrlProvider::Alchemy => chain_id_to_alchemy_url(chain_id),
        }
    }
}

fn chain_id_to_infura_url(chain_id: u32) -> Option<&'static str> {
    match chain_id {
        0x1 => Some("https://mainnet.infura.io/v3/"),
        0x4268 => Some("https://holesky.infura.io/v3/"),
        0xaa36a7 => Some("https://sepolia.infura.io/v3/"),
        _ => None,
    }
}

fn chain_id_to_self_hosted_url(chain_id: u32) -> Option<&'static str> {
    match chain_id {
        0x1 => Some("http://localhost:8545"), // Example local Ethereum node
        0x4268 => Some("http://localhost:8546"), // Example Holesky local node
        0xaa36a7 => Some("http://localhost:8547"), // Example Sepolia local node
        _ => None,
    }
}

fn chain_id_to_alchemy_url(chain_id: u32) -> Option<&'static str> {
    match chain_id {
        0x1 => Some("https://eth-mainnet.alchemyapi.io/v2/"),
        0x4268 => Some("https://eth-holesky.alchemyapi.io/v2/"),
        0xaa36a7 => Some("https://eth-sepolia.alchemyapi.io/v2/"),
        _ => None,
    }
}

fn validate_transaction_status(input: &str) -> bool {
    let success_pattern = Regex::new(r"^(0x)?[0-9a-fA-F]{64}$").unwrap();
    success_pattern.is_match(input)
}

// fn extract_input_data(tx_input: &str) -> Result<String, String> {
//     // Validate the input: must start with "0x" and be long enough to include the method ID
//     if !tx_input.starts_with("0x") || tx_input.len() <= 10 {
//         return Err("Invalid input data: must start with '0x' and be longer than the method ID".to_string());
//     }

//     // Extract the remaining input after the method ID (first 10 characters, including "0x")
//     // let input_data = format!("0x{}", &tx_input[10..]);
//     let input_data = &tx_input[8..];

//     // Return the extracted input data with the "0x" prefix
//     Ok(input_data.to_owned())
// }

pub(crate) async fn get_tx_data(
    tx_hash: &str,
    verification_provider: String,
    verification_provider_chain: String,
    api_key: String,
) -> Result<(String, u64), Report> {

    println!("get_tx_data function verification_provider {} verification_provider_chain {} api_key {}  ", verification_provider , verification_provider_chain, api_key);
    // Validate input parameters
    if !["infura", "alchemy", "self"].contains(&verification_provider.as_str()) {
        return Err(eyre::eyre!("Invalid verification provider"));
    }

    println!("Starting validation");

    if verification_provider == "self" {
        println!("Self provider");

        return extract_etherscan_tx_details(tx_hash).await;
    } else {
        let url_prefix = match verification_provider.as_str() {
            "infura" => match verification_provider_chain.as_str() {
                "mainnet" => "https://mainnet.infura.io/v3/",
                "sepolia" => "https://sepolia.infura.io/v3/",
                "holesky" => "https://holesky.infura.io/v3/",
                _ => return Err(eyre::eyre!("Invalid Infura chain")),
            },
            "alchemy" => match verification_provider_chain.as_str() {
                "mainnet" => "https://eth-mainnet.g.alchemy.com/v2/",
                "sepolia" => "https://eth-sepolia.g.alchemy.com/v2/",
                "holesky" => "https://eth-holesky.g.alchemy.com/v2/",
                _ => return Err(eyre::eyre!("Invalid Alchemy chain")),
            },

            _ => return Err(eyre::eyre!("Unsupported provider")),
        };

        println!("We have a url prefix: {}", url_prefix);

        // Build the full URL
        let url = format!("{}{}", url_prefix, api_key);

        // Connect to the network
        let provider = Provider::<Http>::try_from(url).wrap_err(FAILED_TO_CREATE_PROVIDER)?;

        println!("Provider set successfully");

        // Parse the transaction hash
        let transaction_hash: H256 = tx_hash.parse().wrap_err(FAILED_TO_PARSE_TRANSACTION_HASH)?;

        // Get the transaction
        let tx = provider
            .get_transaction(transaction_hash)
            .await
            .wrap_err(FAILED_TO_GET_TRANSACTION)?
            .ok_or_else(|| eyre::eyre!("Transaction not found"))?;

        // Deserialize the transaction
        let tx: CustomTransaction =
            from_value(serde_json::to_value(&tx)?).wrap_err(FAILED_TO_DESERIALIZE_TRANSACTION)?;

        println!("Found Transaction input: {:#?}", &tx.input);

        // Validate transaction input
        if !validate_transaction_status(&tx.input) {
            return Err(eyre::eyre!("Invalid transaction input"));
        }

        // Parse the block number
        let blocknumber = u64::from_str_radix(tx.blockNumber.trim_start_matches("0x"), 16)
            .wrap_err(FAILED_TO_PARSE_BLOCK_NUMBER)?;

        // Parse the input
        let input = &tx.input[8..];
            // .parse::<H512>()
            // .wrap_err(FAILED_TO_PARSE_INPUT)?;

        // Ok((input, blocktime_u64))
        Ok((input.to_string(), 0))
    }
}
