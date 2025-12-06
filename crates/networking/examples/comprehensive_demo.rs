use std::time::Duration;

use citadel_networking::{
    NetworkConfig, PrivacyLevel,
    advanced_loader::{AdvancedResourceLoader, LoadingStrategy},
    integrity::{IntegrityValidator, HashAlgorithm},
    resource_manager::{ResourceManager, ResourceManagerConfig, ResourcePolicy, CachePolicy},
    resource_loader::{ResourceLoader, LoadOptions},
    cache::CacheConfig,
};
use tokio::sync::mpsc;
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("🚀 Citadel Browser - Comprehensive Resource Loading Demo");
    println!("========================================================");

    // Demo 1: Basic Resource Loading with Privacy
    println!("\n📦 Demo 1: Basic Resource Loading with Privacy Settings");
    demo_basic_resource_loading().await?;

    // Demo 2: Advanced Resource Loading with Strategies
    println!("\n🧠 Demo 2: Advanced Resource Loading Strategies");
    demo_advanced_loading_strategies().await?;

    // Demo 3: Content Security and Integrity Verification
    println!("\n🔐 Demo 3: Content Security and Integrity Verification");
    demo_content_security_and_integrity().await?;

    // Demo 4: Resource Manager with Privacy Policies
    println!("\n🛡️ Demo 4: Resource Manager with Privacy Policies");
    demo_resource_manager_privacy().await?;

    // Demo 5: Cache Management and Privacy Compliance
    println!("\n💾 Demo 5: Cache Management and Privacy Compliance");
    demo_cache_management().await?;

    println!("\n✅ All demos completed successfully!");
    println!("🎉 Citadel Browser's privacy-first resource loading pipeline is ready!");

    Ok(())
}

async fn demo_basic_resource_loading() -> Result<(), Box<dyn std::error::Error>> {
    // Create privacy-first configuration
    let config = NetworkConfig {
        privacy_level: PrivacyLevel::High,
        enforce_https: true,
        randomize_user_agent: true,
        strip_tracking_params: true,
        ..Default::default()
    };

    let loader = ResourceLoader::new(config).await?;

    // Example HTML with various resource types
    let test_html = r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Privacy Test Page</title>
        <link rel="stylesheet" href="styles/main.css">
        <link rel="preload" href="fonts/roboto.woff2" as="font" type="font/woff2">
        <script src="js/app.js" defer></script>
    </head>
    <body>
        <h1>Welcome to Citadel Browser</h1>
        <img src="images/logo.png" alt="Citadel Logo">
        <p>Privacy-first browsing experience</p>
    </body>
    </html>
    "#;

    let base_url = Url::parse("https://citadel-browser.com/")?;

    // Load with progress tracking
    let loader_with_progress = loader.with_progress_callback(|progress| {
        println!("  📈 Progress: {:.1}% ({} loaded, {} failed, {} cached)", 
                progress.completion_percentage() * 100.0,
                progress.loaded,
                progress.failed, 
                progress.cached);
    });

    let result = loader_with_progress.load_from_html(test_html, base_url).await;

    match result {
        Ok(load_result) => {
            println!("  ✅ Loaded {} resources in {:?}", 
                    load_result.responses.len(), 
                    load_result.total_time);
            println!("  📊 Success rate: {:.1}%", 
                    load_result.progress.success_rate() * 100.0);
        }
        Err(e) => {
            println!("  ⚠️ Loading completed with errors: {}", e);
        }
    }

    Ok(())
}

async fn demo_advanced_loading_strategies() -> Result<(), Box<dyn std::error::Error>> {
    let config = NetworkConfig::default();
    
    let strategies = [
        ("Sequential", LoadingStrategy::Sequential),
        ("Parallel", LoadingStrategy::Parallel), 
        ("Critical First", LoadingStrategy::CriticalFirst),
        ("Adaptive", LoadingStrategy::Adaptive),
    ];

    for (name, strategy) in &strategies {
        println!("  🔄 Testing {} strategy...", name);
        
        let loader = AdvancedResourceLoader::new(config.clone(), *strategy).await?;
        
        // Set up progress tracking
        let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
        let loader = loader.with_progress_channel(progress_tx);

        // Spawn progress monitor
        let progress_monitor = tokio::spawn(async move {
            let mut updates = 0;
            while let Some(progress) = progress_rx.recv().await {
                updates += 1;
                if updates <= 3 { // Limit output for demo
                    println!("    📊 {:.1}% complete, {} Bps, {:?} network", 
                            progress.basic.completion_percentage() * 100.0,
                            progress.bandwidth,
                            progress.network_condition);
                }
            }
        });

        let test_html = r#"
        <!DOCTYPE html>
        <html>
        <head>
            <link rel="stylesheet" href="critical.css">
            <link rel="stylesheet" href="non-critical.css">
            <script src="important.js"></script>
            <link rel="preload" href="font.woff2" as="font">
        </head>
        <body>
            <img src="hero.jpg" alt="Hero">
            <img src="thumbnail.jpg" alt="Thumb">
        </body>
        </html>
        "#;

        let base_url = Url::parse("https://example.com/")?;
        let options = LoadOptions {
            max_concurrent: 4,
            request_timeout: Duration::from_secs(10),
            total_timeout: Duration::from_secs(30),
            load_non_critical: true,
            use_cache: true,
            validate_cache: false,
            max_retries: 1,
            allowed_types: None,
        };

        let start_time = std::time::Instant::now();
        let result = loader.load_with_strategy(test_html, base_url, options).await;
        let elapsed = start_time.elapsed();

        progress_monitor.abort();

        match result {
            Ok(_) => {
                println!("    ✅ {} completed in {:?}", name, elapsed);
                println!("    📈 Bandwidth: {} bytes/s, Condition: {:?}", 
                        loader.current_bandwidth(),
                        loader.network_condition());
            }
            Err(e) => {
                println!("    ⚠️ {} completed with errors: {}", name, e);
            }
        }
    }

    Ok(())
}

async fn demo_content_security_and_integrity() -> Result<(), Box<dyn std::error::Error>> {
    let validator = IntegrityValidator::strict();

    // Demo content integrity verification
    println!("  🔐 Testing content integrity verification...");
    
    let test_script = b"console.log('Citadel Browser is secure!');";
    
    // Generate integrity hash
    let integrity = validator.generate_integrity(test_script, HashAlgorithm::Sha384);
    println!("    📝 Generated integrity: {}", integrity);
    
    // Verify integrity
    let result = validator.verify_integrity(test_script, &integrity);
    println!("    ✅ Integrity verification: {:?}", result);
    
    // Test with tampered content
    let tampered_script = b"console.log('Malicious code injected!');";
    let tampered_result = validator.verify_integrity(tampered_script, &integrity);
    println!("    🚫 Tampered content verification: {:?}", tampered_result);

    // Demo CSP policy enforcement
    println!("  🛡️ Testing CSP policy enforcement...");
    
    let mut csp_validator = IntegrityValidator::new();
    csp_validator.set_csp_from_header(
        "default-src 'self'; script-src 'self' https://trusted.com; img-src 'self' data: https:"
    );
    
    // Test allowed URLs
    let self_script = Url::parse("https://citadel-browser.com/app.js")?;
    let violation = csp_validator.check_csp_violation(&self_script, "script");
    println!("    ✅ Self script allowed: {:?}", violation.is_none());
    
    let trusted_script = Url::parse("https://trusted.com/lib.js")?;
    let violation = csp_validator.check_csp_violation(&trusted_script, "script");
    println!("    ✅ Trusted script allowed: {:?}", violation.is_none());
    
    // Test blocked URLs
    let evil_script = Url::parse("https://malicious.com/evil.js")?;
    let violation = csp_validator.check_csp_violation(&evil_script, "script");
    println!("    🚫 Malicious script blocked: {:?}", violation.is_some());

    Ok(())
}

async fn demo_resource_manager_privacy() -> Result<(), Box<dyn std::error::Error>> {
    // Create strict privacy configuration
    let config = ResourceManagerConfig {
        network_config: NetworkConfig {
            privacy_level: PrivacyLevel::Maximum,
            enforce_https: true,
            randomize_user_agent: true,
            strip_tracking_params: true,
            ..Default::default()
        },
        resource_policy: ResourcePolicy::BlockTracking,
        cache_policy: CachePolicy::AlwaysValidate,
        max_cache_size_mb: 50,
        default_cache_ttl: Duration::from_secs(1800),
    };

    let manager = ResourceManager::with_config(config).await?;

    println!("  🔍 Testing privacy policy enforcement...");

    // Test tracking domains
    let tracking_domains = [
        "https://google-analytics.com/analytics.js",
        "https://facebook.com/tr/pixel.gif",
        "https://doubleclick.net/ads.js",
    ];

    for domain in &tracking_domains {
        match manager.fetch(domain, None).await {
            Ok(_) => println!("    ⚠️ Tracking domain not blocked: {}", domain),
            Err(e) => {
                if e.to_string().contains("Privacy violation") {
                    println!("    ✅ Tracking domain blocked: {}", domain);
                } else {
                    println!("    🌐 Network error for {}: {}", domain, e);
                }
            }
        }
    }

    // Get statistics
    let stats = manager.get_stats().await;
    println!("  📊 Resource Manager Statistics:");
    println!("    Total requests: {}", stats.total_requests);
    println!("    Successful: {}", stats.successful_requests);
    println!("    Failed: {}", stats.failed_requests);
    println!("    Blocked: {:?}", stats.blocked);

    Ok(())
}

async fn demo_cache_management() -> Result<(), Box<dyn std::error::Error>> {
    // Create privacy-focused cache configuration
    let cache_config = CacheConfig {
        max_size_bytes: 10 * 1024 * 1024, // 10MB
        max_entries: 100,
        default_ttl: Duration::from_secs(1800), // 30 minutes
        max_ttl: Duration::from_secs(3600),     // 1 hour max for privacy
        respect_cache_control: true,
        enable_validation: true,
    };

    let cache = citadel_networking::ResourceCache::new(cache_config);

    println!("  💾 Testing privacy-compliant caching...");

    // Create test resources
    let urls = [
        "https://citadel-browser.com/styles/main.css",
        "https://citadel-browser.com/js/app.js",
        "https://citadel-browser.com/images/logo.png",
    ];

    for (i, url_str) in urls.iter().enumerate() {
        let url = Url::parse(url_str)?;
        let mut headers = std::collections::HashMap::new();
        headers.insert("content-type".to_string(), 
                      match i {
                          0 => "text/css",
                          1 => "application/javascript", 
                          2 => "image/png",
                          _ => "text/plain",
                      }.to_string());
        headers.insert("cache-control".to_string(), "max-age=1800".to_string());

        let content = format!("/* Test content for resource {} */", i);
        let response = citadel_networking::Response::new(
            200,
            headers,
            bytes::Bytes::from(content),
            url.clone(),
            citadel_networking::request::Method::GET,
        );

        // Cache the resource
        cache.put(&url, response)?;
        println!("    📝 Cached: {}", url_str);
    }

    // Display cache statistics
    let stats = cache.stats();
    println!("  📊 Cache Statistics:");
    println!("    Entries: {}/{}", stats.entry_count, stats.max_entries);
    println!("    Size: {} bytes / {} bytes ({:.1}%)", 
            stats.total_size_bytes, 
            stats.max_size_bytes,
            stats.size_utilization());
    println!("    Entry utilization: {:.1}%", stats.entry_utilization());

    // Test cache retrieval
    let test_url = Url::parse(urls[0])?;
    if let Some(cached) = cache.get(&test_url) {
        println!("    ✅ Cache hit for: {}", urls[0]);
        println!("    📄 Content length: {} bytes", cached.body().len());
    }

    // Demonstrate privacy feature: cache clearing
    println!("  🧹 Clearing cache for privacy...");
    cache.clear();
    
    let cleared_stats = cache.stats();
    println!("    ✅ Cache cleared - Entries: {}, Size: {} bytes", 
            cleared_stats.entry_count, 
            cleared_stats.total_size_bytes);

    Ok(())
}
