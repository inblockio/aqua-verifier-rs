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
use crate::look_up_utils::extract_etherscan_tx_details;
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

pub(crate) async fn get_tx_data(
    tx_hash: &str,
    verification_provider: String,
    verification_provider_chain: String,
    api_key: String,
) -> Result<(H512, u64), Report> {
    // Validate input parameters
    if !["infura", "alchemy", "self"].contains(&verification_provider.as_str()) {
        return Err(eyre::eyre!("Invalid verification provider"));
    }

    if verification_provider == "self" {

        return extract_etherscan_tx_details(tx_hash);
    } else {
        let url_prefix = match verification_provider.as_str() {
            "infura" => match verification_provider_chain.as_str() {
                "mainnet" => "https://mainnet.infura.io/v3/",
                "sepolia" => "https://sepolia.infura.io/v3/",
                "holesky" => "https://holesky.infura.io/v3/",
                _ => return Err(eyre::eyre!("Invalid Infura chain")),
            },
            "alchemy" => match verification_provider_chain.as_str() {
                "mainnet" => "https://eth-mainnet.alchemyapi.io/v2/",
                "sepolia" => "https://eth-sepolia.alchemyapi.io/v2/",
                "holesky" => "https://eth-holesky.alchemyapi.io/v2/",
                _ => return Err(eyre::eyre!("Invalid Alchemy chain")),
            },

            _ => return Err(eyre::eyre!("Unsupported provider")),
        };

        // Build the full URL
        let url = format!("{}{}", url_prefix, api_key);

        // Connect to the network
        let provider = Provider::<Http>::try_from(url).wrap_err(FAILED_TO_CREATE_PROVIDER)?;

        // Get the chain ID
        let chain_id = provider
            .get_chainid()
            .await
            .wrap_err(FAILED_TO_GET_CHAIN_ID)?;

        // Load the signer private key from the .env file
        let wallet_key =
            std::env::var("SIGNER_PRIVATE_KEY").wrap_err(SIGNER_PRIVATE_KEY_MUST_BE_SET)?;

        // Parse the wallet key
        let wallet: LocalWallet = wallet_key
            .parse::<LocalWallet>()
            .wrap_err(FAILED_TO_PARSE_WALLET_KEY)?
            .with_chain_id(chain_id.as_u64());

        // Connect the wallet to the provider
        let client = SignerMiddleware::new(provider, wallet);

        // Parse the transaction hash
        let transaction_hash: H256 = tx_hash.parse().wrap_err(FAILED_TO_PARSE_TRANSACTION_HASH)?;

        // Get the transaction
        let tx = client
            .get_transaction(transaction_hash)
            .await
            .wrap_err(FAILED_TO_GET_TRANSACTION)?
            .ok_or_else(|| eyre::eyre!("Transaction not found"))?;

        // Deserialize the transaction
        let tx: CustomTransaction =
            from_value(serde_json::to_value(&tx)?).wrap_err(FAILED_TO_DESERIALIZE_TRANSACTION)?;

        // Validate transaction input
        if !validate_transaction_status(&tx.input) {
            return Err(eyre::eyre!("Invalid transaction input"));
        }

        // Parse the block number
        let blocknumber = u64::from_str_radix(tx.blockNumber.trim_start_matches("0x"), 16)
            .wrap_err(FAILED_TO_PARSE_BLOCK_NUMBER)?;

        // Get the block
        let block = client
            .get_block(blocknumber)
            .await
            .wrap_err(FAILED_TO_GET_BLOCK)?;

        // Deserialize the block time
        let blocktime: Blocktime =
            from_value(serde_json::to_value(&block)?).wrap_err(FAILED_TO_DESERIALIZE_BLOCK_TIME)?;

        // Parse the block timestamp
        let blocktime_u64 = u64::from_str_radix(blocktime.timestamp.trim_start_matches("0x"), 16)
            .wrap_err(FAILED_TO_PARSE_TIMESTAMP)?;

        // Parse the input
        let input = tx.input[10..]
            .parse::<H512>()
            .wrap_err(FAILED_TO_PARSE_INPUT)?;

        Ok((input, blocktime_u64))
    }
}
