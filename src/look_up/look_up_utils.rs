use ethers::{
    types::{H256, H512},
    prelude::*,
};
use eyre::{Report, Result};
use reqwest;
use scraper::{Html, Selector};

pub(crate) async fn extract_etherscan_tx_details(tx_hash: &str) -> Result<(H512, u64)> {
    let url = format!("https://etherscan.io/tx/{}", tx_hash);
    
    // Fetch Etherscan page
    let client = reqwest::Client::new();
    let response = client.get(&url)
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await
        .map_err(|e| eyre::eyre!("Failed to fetch Etherscan page: {}", e))?;

    let body = response.text().await
        .map_err(|e| eyre::eyre!("Failed to read response body: {}", e))?;

    // Parse HTML
    let document = Html::parse_document(&body);
    
    // Selector for transaction timestamp
    let timestamp_selector = Selector::parse("div.mr-3 > span[title]").unwrap();
    let timestamp_elem = document.select(&timestamp_selector).next()
        .ok_or_else(|| eyre::eyre!("Could not find timestamp"))?;
    
    let timestamp_str = timestamp_elem.value().attr("title")
        .ok_or_else(|| eyre::eyre!("Could not extract timestamp"))?;
    
    // Parse timestamp (assuming format like "May-23-2023 10:30:45 AM +UTC")
    let timestamp = parse_etherscan_timestamp(timestamp_str)?;

    // Selector for transaction input data
    let input_selector = Selector::parse("#inputdata").unwrap();
    let input_elem = document.select(&input_selector).next()
        .ok_or_else(|| eyre::eyre!("Could not find input data"))?;
    
    let input_text = input_elem.text().collect::<String>();
    
    // Clean and parse input (remove '0x' if present)
    let input_hex = input_text.trim().trim_start_matches("0x");
    
    // Parse input as H512
    let input = input_hex.parse::<H512>()
        .map_err(|e| eyre::eyre!("Failed to parse input: {}", e))?;

    Ok((input, timestamp))
}

pub(crate) fn parse_etherscan_timestamp(timestamp_str: &str) -> Result<u64> {
    use chrono::{NaiveDateTime, TimeZone, Utc};

    // Parse the timestamp string
    let naive_dt = NaiveDateTime::parse_from_str(
        timestamp_str, 
        "%b-%d-%Y %I:%M:%S %p +%Z"
    ).map_err(|e| eyre::eyre!("Failed to parse timestamp: {}", e))?;

    // Convert to Unix timestamp
    let timestamp = Utc.from_utc_datetime(&naive_dt).timestamp() as u64;

    Ok(timestamp)
}