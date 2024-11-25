use eyre::Result;
use reqwest;
use scraper::{Html, Selector};


/// Extracts transaction details from Etherscan given a transaction hash and blockchain chain.
///
/// This asynchronous function constructs a URL for the specified blockchain's Etherscan
/// and fetches the transaction details. It parses the HTML response to extract the input data
/// related to the transaction.
///
/// # Parameters
///
/// - `tx_hash`: A string slice that holds the transaction hash.
/// - `chain`: A string that specifies the blockchain (e.g., "eth" for Ethereum).
///
/// # Returns
///
/// Returns a `Result` containing a tuple with:
/// - A `String` representing the input data from the transaction.
/// - A `u64` representing the timestamp of the transaction (currently hardcoded to 0).
///
/// # Errors
///
/// This function will return an error if:
/// - The HTTP request to Etherscan fails.
/// - The response body cannot be read.
/// - The expected input data element cannot be found in the parsed HTML.
///
/// # Examples
///
/// ```
/// use eyre::Result;
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     let (input_data, timestamp) = extract_etherscan_tx_details("0x1234567890abcdef", "eth").await?;
///     println!("Input Data: {}, Timestamp: {}", input_data, timestamp);
///     Ok(())
/// }
/// ```
///
/// # Panics
///
/// This function may panic if the CSS selector for input data is malformed or if there are issues
/// with parsing the HTML document.
pub(crate) async fn extract_etherscan_tx_details(tx_hash: &str,chain : String ) -> Result<(String, u64)> {
    let url = format!("https://{}.etherscan.io/tx/{}", chain, tx_hash);
    
    println!("The url : {}", url);
    // Fetch Etherscan page
    let client = reqwest::Client::new();
    let response = client.get(&url)
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await
        .map_err(|e| eyre::eyre!("Failed to fetch Etherscan page: {}", e))?;

         // Debug: print status code
     println!("Response status: {}", response.status());

    let body = response.text().await
        .map_err(|e| eyre::eyre!("Failed to read response body: {}", e))?;

    // Parse HTML
    let document = Html::parse_document(&body);
    
  
    let timestamp = 0;

    // Selector for transaction input data
    let input_selector = Selector::parse("#inputdata").unwrap();
    let input_elem = document.select(&input_selector).next()
        .ok_or_else(|| eyre::eyre!("Could not find input data"))?;
    
    let input_text = input_elem.text().collect::<String>();
    
    println!("Found Transaction input: {:#?}", &input_text);
    // Clean and parse input (remove '0x' if present)
    // let input_hex = input_text.trim().trim_start_matches("0x");
    
    // Parse input as H512
    // let input = input_hex.parse::<H512>()
    //     .map_err(|e| eyre::eyre!("Failed to parse input: {}", e))?;

    let input = &input_text[8..];

    Ok((input.to_string(), timestamp))
}
