use citadel_networking::{NetworkConfig, Resource};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Create a default network configuration
    let config = NetworkConfig::default();
    
    println!("Creating resource fetcher with privacy-preserving networking...");
    // Create a new resource fetcher
    let resource = Resource::new(config).await?;
    
    // Fetch a secure web page
    println!("Fetching https://example.com...");
    let response = resource.fetch_html("https://example.com").await?;
    
    // Print response info
    println!("\nResponse Status: {}", response.status());
    println!("Content Type: {:?}", response.content_type());
    
    // Check for security header warnings
    let warnings = response.security_header_warnings();
    if !warnings.is_empty() {
        println!("\nSecurity Warnings:");
        for warning in warnings {
            println!("- {}", warning);
        }
    }
    
    // Check for tracking blocks
    if response.had_tracking_blocked() {
        println!("\nBlocked Tracking Attempts:");
        for tracking in response.tracking_blocked() {
            println!("- {}", tracking);
        }
    }
    
    // Print a portion of the HTML content
    let body = response.body_text()?;
    let preview = if body.len() > 500 {
        format!("{}...", &body[0..500])
    } else {
        body
    };
    
    println!("\nContent Preview:");
    println!("{}", preview);
    
    Ok(())
} 