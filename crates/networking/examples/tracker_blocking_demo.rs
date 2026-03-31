use std::time::Duration;

use citadel_networking::{
    CitadelPrivacyEngine, NetworkConfig, PrivacyLevel, DnsMode,
    BlocklistConfig, BlockingLevel,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("🛡️ Citadel Browser - Comprehensive Tracker Blocking Demo");
    println!("=========================================================\n");

    // Create a privacy engine with maximum protection
    let mut network_config = NetworkConfig::default();
    network_config.privacy_level = PrivacyLevel::Maximum;
    network_config.dns_mode = DnsMode::LocalCache;
    
    // Configure aggressive tracker blocking
    let mut tracker_config = BlocklistConfig::default();
    tracker_config.blocking_level = BlockingLevel::Aggressive;
    tracker_config.block_fingerprinting = true;
    tracker_config.block_cryptomining = true;
    tracker_config.block_malware = true;

    println!("Creating privacy engine with aggressive blocking...");
    let privacy_engine = CitadelPrivacyEngine::with_config(network_config).await?;
    
    // Update tracker blocking configuration
    privacy_engine.update_tracker_config(tracker_config).await?;
    
    println!("✅ Privacy engine initialized\n");

    // Test various domains and URLs for blocking
    let test_domains = [
        // Known trackers (should be blocked)
        "doubleclick.net",
        "google-analytics.com",
        "facebook.com",
        "connect.facebook.net",
        "ads.twitter.com",
        "scorecardresearch.com",
        "quantserve.com",
        "outbrain.com",
        "taboola.com",
        
        // Legitimate domains (should not be blocked)
        "example.com",
        "github.com",
        "stackoverflow.com",
        "mozilla.org",
        "rust-lang.org",
        
        // Pattern-based blocking tests
        "analytics.example.com",
        "ads.somesite.com",
        "pixel.tracking.com",
    ];

    println!("🔍 Testing domain blocking:");
    println!("----------------------------");
    
    for domain in &test_domains {
        let would_block = privacy_engine.would_block_domain(domain).await;
        let status = if would_block { "🚫 BLOCKED" } else { "✅ ALLOWED" };
        println!("{:<25} -> {}", domain, status);
    }

    println!("\n🔗 Testing URL blocking:");
    println!("-------------------------");
    
    let test_urls = [
        "https://doubleclick.net/tracker.js",
        "https://google-analytics.com/collect",
        "https://example.com/script.js",
        "https://cdn.example.com/library.js",
        "https://fingerprint.example.com/detect.js",
        "https://coinhive.com/miner.js",
    ];
    
    for url in &test_urls {
        let would_block = privacy_engine.would_block_url(url).await;
        let status = if would_block { "🚫 BLOCKED" } else { "✅ ALLOWED" };
        println!("{:<40} -> {}", url, status);
    }

    // Simulate some DNS resolutions and resource loads
    println!("\n📡 Simulating DNS resolutions:");
    println!("-------------------------------");
    
    let dns_resolver = privacy_engine.get_dns_resolver();
    
    for domain in ["example.com", "doubleclick.net", "github.com"].iter() {
        print!("Resolving {}... ", domain);
        
        match dns_resolver.resolve(domain).await {
            Ok(addresses) => {
                println!("✅ Resolved to {} addresses", addresses.len());
            }
            Err(e) => {
                if e.to_string().contains("blocked") {
                    println!("🚫 Blocked for privacy");
                } else {
                    println!("❌ Failed: {}", e);
                }
            }
        }
    }

    // Simulate some resource loading
    println!("\n📦 Simulating resource loading:");
    println!("--------------------------------");
    
    let resource_manager = privacy_engine.get_resource_manager();
    
    let test_resources = [
        ("https://example.com/", "HTML page"),
        ("https://doubleclick.net/ads.js", "Tracking script"),
        ("https://cdn.example.com/app.js", "Legitimate script"),
    ];
    
    for (url, description) in &test_resources {
        print!("Loading {} ({})... ", description, url);
        
        match resource_manager.fetch(url, None).await {
            Ok(_response) => {
                println!("✅ Loaded successfully");
            }
            Err(e) => {
                if e.to_string().contains("Privacy violation") || e.to_string().contains("blocked") {
                    println!("🚫 Blocked by privacy protection");
                } else {
                    println!("❌ Failed: {}", e);
                }
            }
        }
    }

    // Wait a moment for any async operations to complete
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Show comprehensive statistics
    println!("\n📊 Privacy Protection Statistics:");
    println!("==================================");
    
    let stats = privacy_engine.get_privacy_stats().await;
    println!("{}", stats.get_summary());
    
    println!("\n🛡️ Detailed Tracker Blocking Stats:");
    println!("------------------------------------");
    println!("Blocking level: {:?}", stats.tracker_blocking.blocked_by_category);
    println!("Total blocklist entries: {}", stats.tracker_blocking.total_blocklist_entries);
    
    if let Some(last_update_secs) = stats.tracker_blocking.last_blocklist_update {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age_secs = now_secs.saturating_sub(last_update_secs);
        println!("Last blocklist update: {} seconds ago", age_secs);
    }

    // Show recent blocks
    let recent_blocks = privacy_engine.get_recent_blocks().await;
    if !recent_blocks.is_empty() {
        println!("\n🚫 Recent Blocked Requests:");
        println!("---------------------------");
        for (i, block) in recent_blocks.iter().take(10).enumerate() {
            println!("{}. {} - {} ({})", 
                    i + 1, 
                    block.url, 
                    block.reason, 
                    block.category.to_string());
        }
    }

    println!("\n✨ Demo completed successfully!");
    println!("The Citadel Browser's tracker blocking system is working to protect your privacy.");
    
    Ok(())
}