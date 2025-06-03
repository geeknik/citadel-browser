use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

use crate::error::NetworkError;

/// DNS resolution modes available in Citadel
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsMode {
    /// Local cache with system resolver as fallback (DEFAULT)
    /// This is the privacy-preserving default that doesn't rely on third-party services
    LocalCache,
    
    /// DNS over HTTPS - only used when explicitly configured by user
    DoH(String), // URL of DoH provider
    
    /// DNS over TLS - only used when explicitly configured by user
    DoT(String), // Address of DoT provider
    
    /// Custom resolver configuration (advanced users only)
    Custom(ResolverConfig),
}

/// A DNS resolution entry with time-based expiration
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    /// Resolved IP addresses for this hostname
    addresses: Vec<IpAddr>,
    /// When this entry expires
    expires: Instant,
}

/// Privacy-preserving DNS resolver with local caching
pub struct CitadelDnsResolver {
    /// Local cache to minimize network requests and tracking
    cache: Arc<RwLock<HashMap<String, DnsCacheEntry>>>,
    
    /// Current DNS resolution mode
    mode: DnsMode,
    
    /// Underlying async resolver
    resolver: TokioAsyncResolver,
    
    /// Default TTL for cached entries
    default_ttl: Duration,
}

impl std::fmt::Debug for CitadelDnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CitadelDnsResolver")
            .field("mode", &self.mode)
            .field("default_ttl", &self.default_ttl)
            .field("cache_entries", &self.cache.read().unwrap().len())
            .finish()
    }
}

impl CitadelDnsResolver {
    /// Create a new resolver with default privacy-preserving settings (LocalCache mode)
    pub async fn new() -> Result<Self, NetworkError> {
        Self::with_mode(DnsMode::LocalCache).await
    }
    
    /// Create a resolver with specified DNS mode
    pub async fn with_mode(mode: DnsMode) -> Result<Self, NetworkError> {
        // Configure resolver based on selected mode
        let (config, mut opts) = match &mode {
            DnsMode::LocalCache => {
                // Use system resolver with enhanced privacy
                let mut opts = ResolverOpts::default();
                // Normalize TTLs to prevent timing-based tracking
                opts.positive_min_ttl = Some(Duration::from_secs(300)); // 5 minutes minimum
                opts.negative_min_ttl = Some(Duration::from_secs(60));  // 1 minute minimum for negative
                (ResolverConfig::default(), opts)
            },
            DnsMode::DoH(_url) => {
                // Configure DoH - user explicitly chose this provider
                let mut opts = ResolverOpts::default();
                // Ensure we don't leak timing information
                opts.positive_min_ttl = Some(Duration::from_secs(300)); // 5 minutes minimum
                
                // TODO: Update for future DoH support
                // The current version doesn't directly support DoH
                // For now, we'll use the system resolver with privacy settings
                log::warn!("DoH not yet implemented, falling back to system resolver");
                (ResolverConfig::default(), opts)
            },
            DnsMode::DoT(_addr) => {
                // Configure DoT - user explicitly chose this provider
                let mut opts = ResolverOpts::default();
                // Ensure we don't leak timing information 
                opts.positive_min_ttl = Some(Duration::from_secs(300)); // 5 minutes minimum
                
                // TODO: Update for future DoT support
                // The current version doesn't directly support DoT
                // For now, we'll use the system resolver with privacy settings
                log::warn!("DoT not yet implemented, falling back to system resolver");
                (ResolverConfig::default(), opts)
            },
            DnsMode::Custom(custom_config) => {
                // Use the custom config with default options
                let mut opts = ResolverOpts::default();
                // Still ensure minimum privacy
                opts.positive_min_ttl = Some(Duration::from_secs(60)); // 1 minute minimum
                (custom_config.clone(), opts)
            },
        };
        
        // Common privacy-enhancing settings for all modes
        opts.preserve_intermediates = false; // Don't keep intermediate records
        opts.use_hosts_file = true;         // Use hosts file to reduce network queries
        
        // Create the resolver - this returns the resolver directly, no need to await
        let resolver = TokioAsyncResolver::tokio(config, opts);
        
        Ok(Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            mode,
            resolver,
            default_ttl: Duration::from_secs(3600), // 1 hour default TTL
        })
    }
    
    /// Resolve a hostname to IP addresses with privacy protections
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, NetworkError> {
        // First check the cache to minimize network requests
        if let Some(cached) = self.check_cache(hostname) {
            return Ok(cached);
        }
        
        // If not in cache, perform resolution
        let response = self.resolver.lookup_ip(hostname)
            .await
            .map_err(NetworkError::DnsError)?;
        
        let addresses: Vec<IpAddr> = response.iter().collect();
        
        // Cache the result for future privacy-preserving lookups
        self.update_cache(hostname.to_string(), addresses.clone());
        
        Ok(addresses)
    }
    
    // Check if hostname is in cache and not expired
    fn check_cache(&self, hostname: &str) -> Option<Vec<IpAddr>> {
        if let Ok(cache) = self.cache.read() {
            if let Some(entry) = cache.get(hostname) {
                if entry.expires > Instant::now() {
                    return Some(entry.addresses.clone());
                }
            }
        }
        None
    }
    
    // Update the cache with new resolution results
    fn update_cache(&self, hostname: String, addresses: Vec<IpAddr>) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(hostname, DnsCacheEntry {
                addresses,
                expires: Instant::now() + self.default_ttl,
            });
        }
    }
    
    /// Change the DNS resolution mode
    pub async fn set_mode(&mut self, mode: DnsMode) -> Result<(), NetworkError> {
        // Create new resolver with updated mode
        let (config, mut opts) = match &mode {
            DnsMode::LocalCache => {
                // Use system resolver with enhanced privacy
                let mut opts = ResolverOpts::default();
                // Normalize TTLs to prevent timing-based tracking
                opts.positive_min_ttl = Some(Duration::from_secs(300)); // 5 minutes minimum
                opts.negative_min_ttl = Some(Duration::from_secs(60));  // 1 minute minimum for negative
                (ResolverConfig::default(), opts)
            },
            DnsMode::DoH(_url) => {
                // TODO: implement DoH
                let mut opts = ResolverOpts::default();
                opts.positive_min_ttl = Some(Duration::from_secs(300));
                log::warn!("DoH not yet implemented, falling back to system resolver");
                (ResolverConfig::default(), opts)
            },
            DnsMode::DoT(_addr) => {
                // TODO: implement DoT
                let mut opts = ResolverOpts::default();
                opts.positive_min_ttl = Some(Duration::from_secs(300));
                log::warn!("DoT not yet implemented, falling back to system resolver");
                (ResolverConfig::default(), opts)
            },
            DnsMode::Custom(custom_config) => {
                let mut opts = ResolverOpts::default();
                opts.positive_min_ttl = Some(Duration::from_secs(60));
                (custom_config.clone(), opts)
            },
        };
        
        // Common privacy settings
        opts.preserve_intermediates = false;
        opts.use_hosts_file = true;
        
        // Create the resolver directly, no need to await
        self.resolver = TokioAsyncResolver::tokio(config, opts);
        self.mode = mode;
        
        // Clear cache on mode change for privacy reasons
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
        
        Ok(())
    }
    
    /// Get the current DNS mode
    pub fn get_mode(&self) -> DnsMode {
        self.mode.clone()
    }
    
    /// Clear the DNS cache
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }
    
    /// Set custom TTL for cached entries
    pub fn set_ttl(&mut self, ttl: Duration) {
        self.default_ttl = ttl;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_local_cache_resolver() {
        let resolver = CitadelDnsResolver::new().await.unwrap();
        
        // First resolution should go to the network
        let addresses1 = resolver.resolve("example.com").await.unwrap();
        assert!(!addresses1.is_empty());
        
        // Second resolution should use the cache
        let addresses2 = resolver.resolve("example.com").await.unwrap();
        assert_eq!(addresses1, addresses2);
    }
    
    #[tokio::test]
    async fn test_cache_expiration() {
        let mut resolver = CitadelDnsResolver::new().await.unwrap();
        
        // Set a very short TTL for testing
        resolver.set_ttl(Duration::from_millis(10));
        
        // First resolution
        let _addresses1 = resolver.resolve("example.com").await.unwrap();
        
        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(20)).await;
        
        // This should bypass the cache
        resolver.resolve("example.com").await.unwrap();
    }
} 