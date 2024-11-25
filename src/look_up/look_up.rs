use ethers::{
    prelude::*,
    providers::{Middleware, Provider},
};
use eyre::{Report, Result, WrapErr};
use regex::Regex;
use serde::Deserialize;
use serde_json::from_value;
use std::convert::TryFrom;
use crate::look_up::look_up_utils::extract_etherscan_tx_details;
use crate::look_up::constants::{
    FAILED_TO_CREATE_PROVIDER,
    FAILED_TO_DESERIALIZE_TRANSACTION, FAILED_TO_GET_TRANSACTION, FAILED_TO_PARSE_TRANSACTION_HASH,
};

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct CustomTransaction {
    blockNumber: String,
    input: String,
}




/// Retrieves transaction data from an Ethereum network.
///
/// # Arguments
///
/// * `tx_hash` - The transaction hash to look up
/// * `verification_provider` - The provider to use ("infura", "alchemy", or "self")
/// * `verification_provider_chain` - The Ethereum network to use ("mainnet", "sepolia", or "holesky")
/// * `api_key` - API key for the chosen provider
///
/// # Returns
///
/// * `Ok((String, u64))` - A tuple containing the transaction input data and block timestamp
/// * `Err(Report)` - An error if the transaction lookup fails
///
/// # Errors
///
/// Returns an error in the following cases:
/// * Invalid verification provider
/// * Invalid chain selection
/// * Failed to create provider
/// * Failed to parse transaction hash
/// * Failed to get transaction
/// * Failed to deserialize transaction
///
/// # Examples
///
/// ```rust
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let (input_data, timestamp) = get_tx_data(
///     "0x123...",
///     "infura".to_string(),
///     "mainnet".to_string(),
///     "your-api-key".to_string()
/// ).await?;
/// # Ok(())
/// # }
/// ```
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

        return extract_etherscan_tx_details(tx_hash, verification_provider_chain).await;
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

        
        // Parse the input
        let input = &tx.input[8..];
            // .parse::<H512>()
            // .wrap_err(FAILED_TO_PARSE_INPUT)?;

        // Ok((input, blocktime_u64))
        Ok((input.to_string(), 0))
    }
}
