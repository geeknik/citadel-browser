use std::sync::Arc;
use std::time::Duration;

use citadel_networking::{
    NetworkConfig, ResourceLoader, ResourceDiscovery, ResourceContext,
    LoadOptions, LoadProgress, CacheConfig, 
};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();
    
    println!("🚀 Citadel Browser Resource Loading Pipeline Demo");
    println!("==================================================");
    
    // Configure networking with privacy-first settings
    let network_config = NetworkConfig {
        privacy_level: citadel_networking::PrivacyLevel::High,
        dns_mode: citadel_networking::DnsMode::LocalCache,
        enforce_https: true,
        randomize_user_agent: true,
        strip_tracking_params: true,
        tracker_blocking: citadel_networking::BlocklistConfig::default(),
    };
    
    // Configure resource loading with reasonable limits
    let load_options = LoadOptions {
        max_concurrent: 4,
        request_timeout: Duration::from_secs(10),
        total_timeout: Duration::from_secs(60),
        load_non_critical: true,
        use_cache: true,
        validate_cache: true,
        max_retries: 2,
        allowed_types: None, // Load all resource types
    };
    
    // Configure cache with privacy-preserving settings
    let cache_config = CacheConfig {
        max_size_bytes: 10 * 1024 * 1024, // 10MB cache
        max_entries: 100,
        default_ttl: Duration::from_secs(1800), // 30 minutes
        max_ttl: Duration::from_secs(3600),     // 1 hour max for privacy
        respect_cache_control: true,
        enable_validation: true,
    };
    
    // Create resource loader with progress tracking
    let progress_callback = Arc::new(|progress: &LoadProgress| {
        println!(
            "📊 Progress: {:.1}% ({}/{}) - Phase: {:?}",
            progress.completion_percentage() * 100.0,
            progress.loaded + progress.failed + progress.cached,
            progress.total,
            progress.phase
        );
        
        if progress.bytes_loaded > 0 {
            println!("   📦 Bytes loaded: {} KB", progress.bytes_loaded / 1024);
        }
        
        if progress.cached > 0 {
            println!("   💾 Cache hits: {}", progress.cached);
        }
        
        if progress.failed > 0 {
            println!("   ❌ Failed loads: {}", progress.failed);
        }
    });
    
    let loader = ResourceLoader::with_cache_config(network_config, cache_config)
        .await?
        .with_options(load_options)
        .with_progress_callback(move |progress| progress_callback(progress));
    
    // Demo HTML content with various resource types
    let html_content = r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Resource Loading Demo</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css">
        <link rel="preload" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" as="font">
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400&display=swap');
            
            body {
                font-family: 'Inter', sans-serif;
                background-image: url('https://images.unsplash.com/photo-1557804506-669a67965ba0?w=200');
            }
            
            @font-face {
                font-family: 'CustomFont';
                src: url('https://fonts.gstatic.com/s/inter/v12/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuLyfAZ9hiA.woff2') format('woff2');
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to Citadel Browser</h1>
            <img src="https://picsum.photos/300/200" alt="Demo image" />
            <img src="https://via.placeholder.com/150x150/FF0000/FFFFFF?text=Logo" alt="Logo" />
        </div>
        
        <script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>
        <script>
            // This inline script will be discovered through the embedded CSS extraction
            console.log('Demo loaded');
        </script>
    </body>
    </html>
    "#;
    
    let base_url = Url::parse("https://demo.citadelbrowser.com/")?;
    
    println!("🔍 Discovering resources from HTML...");
    
    // Demonstrate resource discovery
    let discovery = ResourceDiscovery::new()?;
    let context = ResourceContext::new(base_url.clone())
        .include_non_critical(true)
        .max_resources(Some(20));
    
    let discovered_resources = discovery.discover_all(html_content, &context)?;
    
    println!("📋 Discovered {} resources:", discovered_resources.len());
    for (i, resource) in discovered_resources.iter().enumerate() {
        println!(
            "   {}. {} [{}] (Priority: {}, Critical: {})",
            i + 1,
            resource.url,
            format!("{:?}", resource.resource_type),
            resource.priority,
            resource.is_critical
        );
    }
    
    println!("\n🌐 Starting resource loading...");
    
    // Load resources
    let start_time = std::time::Instant::now();
    let result = loader.load_from_html(html_content, base_url).await;
    let total_time = start_time.elapsed();
    
    match result {
        Ok(load_result) => {
            println!("\n✅ Resource loading completed!");
            println!("⏱️  Total time: {:.2}s", total_time.as_secs_f64());
            println!("📊 Final statistics:");
            println!("   • Total resources: {}", load_result.progress.total);
            println!("   • Successfully loaded: {}", load_result.progress.loaded);
            println!("   • Served from cache: {}", load_result.progress.cached);
            println!("   • Failed to load: {}", load_result.progress.failed);
            println!("   • Total bytes: {} KB", load_result.progress.bytes_loaded / 1024);
            println!("   • Success rate: {:.1}%", load_result.progress.success_rate() * 100.0);
            
            // Show cache statistics
            let cache_stats = loader.cache_stats();
            println!("\n💾 Cache statistics:");
            println!("   • Cache entries: {}", cache_stats.entry_count);
            println!("   • Cache size: {} KB", cache_stats.total_size_bytes / 1024);
            println!("   • Size utilization: {:.1}%", cache_stats.size_utilization());
            println!("   • Entry utilization: {:.1}%", cache_stats.entry_utilization());
            
            // Show successful responses
            if !load_result.responses.is_empty() {
                println!("\n🎉 Successfully loaded resources:");
                for (url, response) in load_result.responses.iter().take(5) {
                    println!(
                        "   • {} -> {} ({} bytes, from cache: {})",
                        url,
                        response.status(),
                        response.body().len(),
                        response.from_cache()
                    );
                }
                if load_result.responses.len() > 5 {
                    println!("   ... and {} more", load_result.responses.len() - 5);
                }
            }
            
            // Show errors if any
            if !load_result.errors.is_empty() {
                println!("\n⚠️  Errors encountered:");
                for (url, error) in load_result.errors.iter().take(3) {
                    println!("   • {} -> {}", url, error);
                }
                if load_result.errors.len() > 3 {
                    println!("   ... and {} more errors", load_result.errors.len() - 3);
                }
            }
            
            // Show resource details
            println!("\n📋 Detailed resource loading results:");
            for (url, details) in load_result.progress.resource_details.iter().take(8) {
                let status_icon = if details.success { "✅" } else { "❌" };
                let cache_info = if details.from_cache { " (cached)" } else { "" };
                println!(
                    "   {} {} [{:?}] {} bytes{}", 
                    status_icon, 
                    url,
                    details.resource_type,
                    details.size_bytes,
                    cache_info
                );
            }
            
            println!("\n🔒 Privacy and Security Features Active:");
            println!("   • HTTPS-only enforcement");
            println!("   • User-Agent randomization");
            println!("   • Tracking parameter removal");
            println!("   • Privacy-preserving DNS resolution");
            println!("   • LRU cache with time limits");
            println!("   • Malicious URL filtering");
            println!("   • Resource type validation");
            
        }
        Err(e) => {
            println!("❌ Resource loading failed: {}", e);
            return Err(e.into());
        }
    }
    
    println!("\n🎯 Demo completed successfully!");
    println!("This demonstrates Citadel Browser's privacy-first resource loading pipeline.");
    
    Ok(())
}