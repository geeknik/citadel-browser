#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};
use citadel_networking::dns::{CitadelDnsResolver, DnsMode};

// Global counters for statistics about the fuzzer
static RESOLUTIONS_ATTEMPTED: AtomicUsize = AtomicUsize::new(0);
static CACHE_HITS: AtomicUsize = AtomicUsize::new(0);
static MODE_CHANGES: AtomicUsize = AtomicUsize::new(0);

#[derive(Arbitrary, Debug)]
struct DnsFuzzInput {
    hostname: String,
    mode: u8, // Use to select different DNS modes
    ttl_seconds: u32,
    cache_lookup_first: bool,
    clear_cache_before: bool,
}

impl DnsFuzzInput {
    fn sanitize_hostname(&self) -> String {
        // Ensure the hostname is somewhat valid to avoid excessive invalid cases
        let hostname = self.hostname.trim();
        
        if hostname.is_empty() {
            return "example.com".to_string();
        }
        
        // Remove control characters and limit length
        let hostname: String = hostname
            .chars()
            .filter(|c| !c.is_control() && *c != '\0')
            .take(253) // Max DNS name length
            .collect();
        
        if hostname.is_empty() {
            return "example.com".to_string();
        }
        
        hostname
    }
    
    fn get_dns_mode(&self) -> DnsMode {
        match self.mode % 4 {
            0 => DnsMode::LocalCache,
            1 => DnsMode::DoH("https://dns.example.com/dns-query".to_string()),
            2 => DnsMode::DoT("dns.example.com".to_string()),
            _ => DnsMode::Custom(trust_dns_resolver::config::ResolverConfig::default()),
        }
    }
}

// Custom debug function that prints diagnostics if DEBUG env var is set
fn debug_print(msg: &str) {
    if std::env::var("FUZZ_DEBUG").is_ok() {
        println!("[DNS_FUZZER] {}", msg);
    }
}

fuzz_target!(|input: DnsFuzzInput| {
    // Memory safety check: wrap the test in a panic handler to catch any memory issues
    std::panic::catch_unwind(|| {
        // We need a runtime for async DNS resolution
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime");
        
        rt.block_on(async {
            // Create DNS resolver with the fuzzed mode
            let mut resolver = match CitadelDnsResolver::with_mode(input.get_dns_mode()).await {
                Ok(resolver) => resolver,
                Err(e) => {
                    debug_print(&format!("Failed to create resolver: {:?}", e));
                    return; // If we can't create a resolver, skip this input
                }
            };
            
            // Record global mode for diagnostics
            debug_print(&format!("Testing with DNS mode: {:?}", resolver.get_mode()));
            
            // Set TTL based on fuzzed input
            let ttl = Duration::from_secs(input.ttl_seconds.min(60) as u64); // Limit to 60 seconds max
            resolver.set_ttl(ttl);
            debug_print(&format!("Set TTL to {:?}", ttl));
            
            // Clear cache if requested
            if input.clear_cache_before {
                resolver.clear_cache();
                debug_print("Cleared DNS cache");
            }
            
            // Get sanitized hostname
            let hostname = input.sanitize_hostname();
            debug_print(&format!("Resolving hostname: {}", hostname));
            
            // Assert memory integrity check before resolution
            assert!(resolver.get_mode() == input.get_dns_mode(), 
                    "DNS resolver mode mismatch before resolution");
            
            // Resolve the hostname
            RESOLUTIONS_ATTEMPTED.fetch_add(1, Ordering::SeqCst);
            match resolver.resolve(&hostname).await {
                Ok(addresses) => {
                    debug_print(&format!("Successfully resolved {} to {:?}", hostname, addresses));
                    // Ensure addresses is valid
                    assert!(!addresses.is_empty(), "Empty address list returned from successful resolution");
                    for addr in &addresses {
                        // Check that each address is valid
                        let addr_str = addr.to_string();
                        assert!(!addr_str.is_empty(), "Empty IP address string");
                    }
                },
                Err(e) => {
                    debug_print(&format!("Failed to resolve {}: {:?}", hostname, e));
                }
            }
            
            // Test cache behavior by resolving again
            if input.cache_lookup_first {
                debug_print("Testing cache lookup");
                let cache_result = resolver.resolve(&hostname).await;
                if cache_result.is_ok() {
                    CACHE_HITS.fetch_add(1, Ordering::SeqCst);
                    debug_print("Cache hit");
                } else {
                    debug_print(&format!("Cache miss: {:?}", cache_result.err()));
                }
            }
            
            // Test changing DNS mode
            let new_mode = match input.mode % 4 {
                0 => DnsMode::DoH("https://alternate-dns.example.com/dns-query".to_string()),
                _ => DnsMode::LocalCache,
            };
            
            debug_print(&format!("Changing mode to {:?}", new_mode));
            if let Ok(()) = resolver.set_mode(new_mode.clone()).await {
                MODE_CHANGES.fetch_add(1, Ordering::SeqCst);
                
                // Assert that the mode change worked
                assert!(resolver.get_mode() == new_mode, 
                        "DNS resolver mode wasn't properly changed");
                
                // Test resolution after mode change
                debug_print("Testing resolution after mode change");
                let _ = resolver.resolve(&hostname).await;
            }
            
            // Print statistics periodically
            let attempts = RESOLUTIONS_ATTEMPTED.load(Ordering::SeqCst);
            if attempts % 1000 == 0 {
                let cache_hits = CACHE_HITS.load(Ordering::SeqCst);
                let mode_changes = MODE_CHANGES.load(Ordering::SeqCst);
                eprintln!(
                    "DNS Fuzzer Stats: {} resolutions, {} cache hits, {} mode changes",
                    attempts, cache_hits, mode_changes
                );
            }
        });
    }).unwrap_or_else(|e| {
        // If we got a panic, propagate it with more information
        panic!("DNS resolver test panicked: {:?}", e);
    });
}); 