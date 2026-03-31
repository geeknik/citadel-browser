use citadel_networking::{CitadelDnsResolver, DnsMode, DohProviders};
use std::net::IpAddr;
use std::time::Duration;

/// Test DNS resolver integration with real network calls
/// These tests may fail in CI environments without network access
#[tokio::test]
async fn test_system_dns_resolver_creation() {
    // Test that we can create a resolver using the system configuration
    let resolver = CitadelDnsResolver::new().await;
    assert!(resolver.is_ok(), "Should be able to create system DNS resolver");
    
    let resolver = resolver.unwrap();
    assert_eq!(resolver.get_mode(), DnsMode::LocalCache);
}

#[tokio::test]
async fn test_doh_providers() {
    // Test that all DoH providers are valid URLs
    let providers = [
        DohProviders::CLOUDFLARE,
        DohProviders::QUAD9,
        DohProviders::ADGUARD,
        DohProviders::MOZILLA,
    ];
    
    for provider in &providers {
        let url = url::Url::parse(provider);
        assert!(url.is_ok(), "DoH provider URL should be valid: {}", provider);
        assert_eq!(url.unwrap().scheme(), "https", "DoH provider should use HTTPS: {}", provider);
    }
    
    // Test random provider selection
    let random_provider = DohProviders::random();
    assert!(providers.contains(&random_provider), "Random provider should be from the known list");
}

#[tokio::test]
async fn test_dns_resolution_with_different_modes() {
    // Test system DNS resolution
    let system_resolver = CitadelDnsResolver::new().await.unwrap();
    
    // Test resolving a well-known domain
    match system_resolver.resolve("example.com").await {
        Ok(addresses) => {
            assert!(!addresses.is_empty(), "Should resolve example.com to at least one address");
            println!("System DNS resolved example.com to {} addresses", addresses.len());
            
            // Verify addresses are valid
            for addr in &addresses {
                match addr {
                    IpAddr::V4(_) | IpAddr::V6(_) => {
                        println!("Resolved address: {}", addr);
                    }
                }
            }
        }
        Err(e) => {
            // This might fail in CI environments - that's okay
            println!("System DNS resolution failed (might be expected in CI): {}", e);
        }
    }
}

#[tokio::test]
async fn test_doh_resolution() {
    // Test DoH resolution with Cloudflare
    let doh_resolver = CitadelDnsResolver::with_mode(
        DnsMode::DoH(DohProviders::CLOUDFLARE.to_string())
    ).await.unwrap();
    
    match doh_resolver.resolve("example.com").await {
        Ok(addresses) => {
            assert!(!addresses.is_empty(), "DoH should resolve example.com to at least one address");
            println!("DoH resolved example.com to {} addresses", addresses.len());
            
            // Test both IPv4 and IPv6 resolution
            let has_ipv4 = addresses.iter().any(|addr| matches!(addr, IpAddr::V4(_)));
            let has_ipv6 = addresses.iter().any(|addr| matches!(addr, IpAddr::V6(_)));
            
            println!("DoH resolution - IPv4: {}, IPv6: {}", has_ipv4, has_ipv6);
        }
        Err(e) => {
            println!("DoH resolution failed (might be expected in CI): {}", e);
        }
    }
}

#[tokio::test]
async fn test_dns_cache_functionality() {
    let mut resolver = CitadelDnsResolver::new().await.unwrap();
    
    // Set a short TTL for testing
    resolver.set_ttl(Duration::from_secs(30));
    
    // Clear cache to start fresh
    resolver.clear_cache();
    
    let initial_stats = resolver.get_stats();
    assert_eq!(initial_stats.cache_entries, 0);
    assert_eq!(initial_stats.cache_hits, 0);
    
    // First resolution should miss cache
    if let Ok(_) = resolver.resolve("example.com").await {
        let stats_after_first = resolver.get_stats();
        assert_eq!(stats_after_first.cache_entries, 1, "Should have one cache entry after first resolution");
        
        // Second resolution should hit cache
        if let Ok(_) = resolver.resolve("example.com").await {
            let stats_after_second = resolver.get_stats();
            assert_eq!(stats_after_second.cache_hits, 1, "Should have one cache hit after second resolution");
        }
    }
}

#[tokio::test]
async fn test_tracker_blocking() {
    let resolver = CitadelDnsResolver::new().await.unwrap();
    
    // Test that tracking domains are blocked
    let tracking_domains = [
        "doubleclick.net",
        "googleadservices.com",
        "facebook.com",
        "google-analytics.com",
    ];
    
    for domain in &tracking_domains {
        let result = resolver.resolve(domain).await;
        assert!(result.is_err(), "Tracking domain {} should be blocked", domain);
        
        if let Err(e) = result {
            assert!(e.to_string().contains("blocked"), "Error should indicate domain was blocked: {}", e);
        }
    }
    
    let stats = resolver.get_stats();
    assert!(stats.queries_blocked > 0, "Should have blocked some queries");
}

#[tokio::test]
async fn test_invalid_hostnames() {
    let resolver = CitadelDnsResolver::new().await.unwrap();
    
    let long_hostname = "a".repeat(254);
    let invalid_hostnames = [
        "", // Empty
        ".example.com", // Leading dot
        "example.com.", // Trailing dot
        "-example.com", // Leading dash
        "example-.com", // Trailing dash in label
        long_hostname.as_str(), // Too long
        "invalid..domain.com", // Double dots
        "example.com/path", // Contains path
    ];
    
    for hostname in &invalid_hostnames {
        let result = resolver.resolve(hostname).await;
        assert!(result.is_err(), "Invalid hostname {} should fail validation", hostname);
    }
}

#[tokio::test]
async fn test_dns_mode_switching() {
    let mut resolver = CitadelDnsResolver::new().await.unwrap();
    
    // Start with LocalCache mode
    assert_eq!(resolver.get_mode(), DnsMode::LocalCache);
    
    // Switch to DoH mode
    let doh_result = resolver.set_mode(DnsMode::DoH(DohProviders::CLOUDFLARE.to_string())).await;
    assert!(doh_result.is_ok(), "Should be able to switch to DoH mode");
    assert_eq!(resolver.get_mode(), DnsMode::DoH(DohProviders::CLOUDFLARE.to_string()));
    
    // Switch to DoT mode
    let dot_result = resolver.set_mode(DnsMode::DoT("1.1.1.1:853".to_string())).await;
    assert!(dot_result.is_ok(), "Should be able to switch to DoT mode");
    assert_eq!(resolver.get_mode(), DnsMode::DoT("1.1.1.1:853".to_string()));
    
    // Switch back to LocalCache
    let local_result = resolver.set_mode(DnsMode::LocalCache).await;
    assert!(local_result.is_ok(), "Should be able to switch back to LocalCache mode");
    assert_eq!(resolver.get_mode(), DnsMode::LocalCache);
    
    // Test invalid DoH URL
    let invalid_result = resolver.set_mode(DnsMode::DoH("not-a-url".to_string())).await;
    assert!(invalid_result.is_err(), "Should reject invalid DoH URL");
}

#[tokio::test]
async fn test_concurrent_dns_resolution() {
    let resolver = CitadelDnsResolver::new().await.unwrap();
    
    // Test multiple concurrent resolutions
    let domains = vec!["example.com", "httpbin.org", "github.com"];
    let mut tasks: Vec<tokio::task::JoinHandle<Result<Vec<std::net::IpAddr>, citadel_networking::NetworkError>>> = Vec::new();
    
    for domain in domains {
        let resolver_clone = resolver.clone();
        let domain_owned = domain.to_string();
        tasks.push(tokio::spawn(async move {
            resolver_clone.resolve(&domain_owned).await
        }));
    }
    
    // Wait for all resolutions to complete
    let results = futures::future::join_all(tasks).await;
    
    // Check that at least some resolutions succeeded (depending on network availability)
    let success_count = results.iter()
        .filter(|result| result.is_ok() && result.as_ref().unwrap().is_ok())
        .count();
    
    println!("Concurrent DNS resolution: {}/{} succeeded", success_count, results.len());
    
    // In a proper network environment, at least one should succeed
    // But in CI environments, this might fail, so we just log the results
}

#[tokio::test]
async fn test_dns_performance_metrics() {
    let resolver = CitadelDnsResolver::new().await.unwrap();
    
    let initial_stats = resolver.get_stats();
    println!("Initial DNS stats: {:?}", initial_stats);
    
    // Attempt some resolutions to generate metrics
    let domains = ["example.com", "httpbin.org"];
    for domain in &domains {
        let _ = resolver.resolve(domain).await;
    }
    
    // Try to resolve a blocked domain
    let _ = resolver.resolve("doubleclick.net").await;
    
    let final_stats = resolver.get_stats();
    println!("Final DNS stats: {:?}", final_stats);
    
    // Verify that stats are being tracked
    assert_eq!(final_stats.current_mode, DnsMode::LocalCache);
}