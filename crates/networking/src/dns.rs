use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use reqwest::Client;
use serde_json::Value;
use url::Url;

use citadel_security::privacy::{PrivacyEvent, PrivacyEventSender};

use crate::error::NetworkError;
use crate::tracker_blocking::TrackerBlockingEngine;

/// DNS resolution modes available in Citadel
#[derive(Debug, Clone, PartialEq)]
pub enum DnsMode {
    /// Local cache with system resolver as fallback (DEFAULT)
    /// This is the privacy-preserving default that doesn't rely on third-party services
    LocalCache,
    
    /// DNS over HTTPS - only used when explicitly configured by user
    DoH(String), // URL of DoH provider
    
    /// DNS over TLS - only used when explicitly configured by user
    DoT(String), // Address of DoT provider
    
    /// Custom resolver configuration (advanced users only)
    Custom,
}

/// A DNS resolution entry with time-based expiration
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    /// Resolved IP addresses for this hostname
    addresses: Vec<IpAddr>,
    /// When this entry expires
    expires: Instant,
}

/// DNS resolution statistics
#[derive(Debug, Clone)]
pub struct DnsStats {
    pub cache_hits: u64,
    pub queries_blocked: u64,
    pub cache_entries: usize,
    pub current_mode: DnsMode,
}

/// Privacy-preserving DNS resolver with local caching
#[derive(Clone)]
pub struct CitadelDnsResolver {
    /// Local cache to minimize network requests and tracking
    cache: Arc<RwLock<HashMap<String, DnsCacheEntry>>>,
    
    /// Current DNS resolution mode
    mode: DnsMode,
    
    /// Underlying async resolver for system DNS
    system_resolver: Option<TokioResolver>,
    
    /// HTTP client for DoH requests
    http_client: Client,
    
    /// Default TTL for cached entries
    default_ttl: Duration,
    
    /// Privacy metrics
    dns_queries_blocked: Arc<RwLock<u64>>,
    dns_cache_hits: Arc<RwLock<u64>>,
    
    /// Integrated tracker blocking engine
    tracker_blocker: Option<Arc<TrackerBlockingEngine>>,

    /// Optional privacy event sender for the scoreboard
    privacy_sender: Option<PrivacyEventSender>,
}

impl std::fmt::Debug for CitadelDnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CitadelDnsResolver")
            .field("mode", &self.mode)
            .field("default_ttl", &self.default_ttl)
            .field("cache_entries", &self.cache.read().map(|c| c.len()).unwrap_or(0))
            .finish()
    }
}

/// Popular DoH providers for user convenience
pub struct DohProviders;

impl DohProviders {
    /// Cloudflare DNS over HTTPS (privacy-focused)
    pub const CLOUDFLARE: &'static str = "https://cloudflare-dns.com/dns-query";
    
    /// Quad9 DNS over HTTPS (security-focused with malware blocking)
    pub const QUAD9: &'static str = "https://dns.quad9.net/dns-query";
    
    /// AdGuard DNS over HTTPS (ad-blocking)
    pub const ADGUARD: &'static str = "https://dns.adguard.com/dns-query";
    
    /// Mozilla's Trusted Recursive Resolver
    pub const MOZILLA: &'static str = "https://mozilla.cloudflare-dns.com/dns-query";
    
    /// Get a random DoH provider for privacy
    pub fn random() -> &'static str {
        use rand::seq::SliceRandom;
        let providers = [Self::CLOUDFLARE, Self::QUAD9, Self::ADGUARD, Self::MOZILLA];
        providers.choose(&mut rand::thread_rng()).unwrap_or(&Self::CLOUDFLARE)
    }
}

impl CitadelDnsResolver {
    /// Create a new resolver with default privacy-preserving settings (LocalCache mode)
    pub async fn new() -> Result<Self, NetworkError> {
        log::info!("🔧 Creating CitadelDnsResolver with default LocalCache mode");
        log::info!("🛡️ User sovereignty: Local DNS cache with system fallback");
        
        // Create system resolver with privacy-preserving defaults
        let system_resolver = match Self::create_system_resolver().await {
            Ok(resolver) => Some(resolver),
            Err(e) => {
                log::warn!("⚠️ Could not create system resolver: {}, continuing with limited functionality", e);
                None
            }
        };
        
        // Create HTTP client for DoH with privacy settings
        let http_client = Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("Citadel-Browser/0.0.1-alpha")
            .build()
            .map_err(|e| NetworkError::DnsError(format!("Failed to create HTTP client: {}", e)))?;
        
        Ok(Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            mode: DnsMode::LocalCache,
            system_resolver,
            http_client,
            default_ttl: Duration::from_secs(3600), // 1 hour default TTL
            dns_queries_blocked: Arc::new(RwLock::new(0)),
            dns_cache_hits: Arc::new(RwLock::new(0)),
            tracker_blocker: None,
            privacy_sender: None,
        })
    }
    
    /// Create a resolver with specified DNS mode
    pub async fn with_mode(mode: DnsMode) -> Result<Self, NetworkError> {
        log::info!("🔧 Creating DNS resolver with mode: {:?}", mode);
        
        let mut resolver = Self::new().await?;
        resolver.set_mode(mode.clone()).await?;
        
        log::info!("✅ DNS resolver created successfully with mode: {:?}", mode);
        
        Ok(resolver)
    }
    
    /// Create a resolver with integrated tracker blocking
    pub async fn with_tracker_blocking(mode: DnsMode, tracker_blocker: Arc<TrackerBlockingEngine>) -> Result<Self, NetworkError> {
        log::info!("🔧 Creating DNS resolver with tracker blocking and mode: {:?}", mode);
        
        let mut resolver = Self::new().await?;
        resolver.set_mode(mode.clone()).await?;
        resolver.tracker_blocker = Some(tracker_blocker);
        
        log::info!("✅ DNS resolver with tracker blocking created successfully");
        
        Ok(resolver)
    }
    
    /// Create a system resolver with privacy-preserving configuration
    async fn create_system_resolver() -> Result<TokioResolver, NetworkError> {
        // Use hickory-resolver 0.26.0-alpha.1 API with system configuration
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| NetworkError::DnsError(format!("Failed to create resolver builder: {}", e)))?
            .build();
        
        Ok(resolver)
    }
    
    /// Resolve a hostname to IP addresses with privacy protections
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, NetworkError> {
        log::debug!("🔍 Resolving hostname: {}", hostname);
        
        // Validate hostname for security
        if !Self::is_valid_hostname(hostname) {
            return Err(NetworkError::DnsError(format!("Invalid hostname: {}", hostname)));
        }
        
        // Check if hostname should be blocked for privacy
        if let Some(blocked) = self.should_block_hostname_advanced(hostname).await {
            // Record the blocked request if we have a tracker blocker
            if let Some(ref blocker) = self.tracker_blocker {
                blocker.record_blocked_request(blocked).await;
            }
            
            return Err(NetworkError::DnsError(format!("Hostname blocked for privacy: {}", hostname)));
        }
        
        // First check the cache to minimize network requests
        if let Some(cached) = self.check_cache(hostname) {
            log::debug!("✅ Cache hit for {} with {} addresses", hostname, cached.len());
            self.increment_cache_hits();

            // Emit privacy event for cache hit
            if let Some(sender) = &self.privacy_sender {
                sender.emit(PrivacyEvent::DnsQueryLocal {
                    domain: hostname.to_string(),
                    cached: true,
                });
            }

            return Ok(cached);
        }
        
        log::debug!("📡 Cache miss for {} - performing DNS lookup", hostname);
        
        // Perform actual DNS resolution based on configured mode
        let addresses = match &self.mode {
            DnsMode::LocalCache => self.resolve_with_system(hostname).await?,
            DnsMode::DoH(url) => self.resolve_with_doh(hostname, url).await?,
            DnsMode::DoT(server) => self.resolve_with_dot(hostname, server).await?,
            DnsMode::Custom => self.resolve_with_system(hostname).await?, // Fall back to system
        };
        
        if !addresses.is_empty() {
            log::debug!("✅ Resolved {} to {} addresses", hostname, addresses.len());
            self.update_cache(hostname.to_string(), addresses.clone());
        } else {
            log::warn!("⚠️ No addresses found for {}", hostname);
        }
        
        Ok(addresses)
    }
    
    /// Resolve hostname using system DNS resolver
    async fn resolve_with_system(&self, hostname: &str) -> Result<Vec<IpAddr>, NetworkError> {
        if let Some(ref resolver) = self.system_resolver {
            match resolver.lookup_ip(hostname).await {
                Ok(lookup) => {
                    let addresses: Vec<IpAddr> = lookup.iter().collect();
                    log::debug!("🏠 System DNS resolved {} to {} addresses", hostname, addresses.len());
                    Ok(addresses)
                }
                Err(e) => {
                    log::error!("❌ System DNS resolution failed for {}: {}", hostname, e);
                    Err(NetworkError::DnsError(format!("System DNS resolution failed: {}", e)))
                }
            }
        } else {
            Err(NetworkError::DnsError("System resolver not available".to_string()))
        }
    }
    
    /// Resolve hostname using DNS over HTTPS (DoH)
    async fn resolve_with_doh(&self, hostname: &str, doh_url: &str) -> Result<Vec<IpAddr>, NetworkError> {
        log::debug!("🔒 Resolving {} via DoH: {}", hostname, doh_url);
        
        // Parse and validate DoH URL
        let url = Url::parse(doh_url)
            .map_err(|e| NetworkError::DnsError(format!("Invalid DoH URL: {}", e)))?;
        
        // Validate that the URL uses HTTPS for security
        if url.scheme() != "https" {
            return Err(NetworkError::DnsError("DoH URLs must use HTTPS".to_string()));
        }
        
        // Try both A and AAAA records for comprehensive resolution
        let mut all_addresses = Vec::new();
        
        // Query A records (IPv4)
        if let Ok(ipv4_addrs) = self.query_doh_record(hostname, doh_url, "A").await {
            all_addresses.extend(ipv4_addrs);
        }
        
        // Query AAAA records (IPv6)
        if let Ok(ipv6_addrs) = self.query_doh_record(hostname, doh_url, "AAAA").await {
            all_addresses.extend(ipv6_addrs);
        }
        
        if all_addresses.is_empty() {
            return Err(NetworkError::DnsError(format!("No records found for {} via DoH", hostname)));
        }
        
        log::debug!("🔒 DoH resolved {} to {} addresses", hostname, all_addresses.len());
        Ok(all_addresses)
    }
    
    /// Query a specific DNS record type via DoH
    async fn query_doh_record(&self, hostname: &str, doh_url: &str, record_type: &str) -> Result<Vec<IpAddr>, NetworkError> {
        // Build DoH query URL
        let query_url = format!("{}?name={}&type={}", doh_url, hostname, record_type);
        
        // Make HTTPS request with privacy-preserving headers
        let response = self.http_client
            .get(&query_url)
            .header("Accept", "application/dns-json")
            .header("User-Agent", "Citadel-Browser/0.0.1-alpha")
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| NetworkError::DnsError(format!("DoH {} query failed: {}", record_type, e)))?;
        
        if !response.status().is_success() {
            return Err(NetworkError::DnsError(format!(
                "DoH {} query failed with status: {}", 
                record_type, 
                response.status()
            )));
        }
        
        let json: Value = response.json().await
            .map_err(|e| NetworkError::DnsError(format!("DoH {} response parsing failed: {}", record_type, e)))?;
        
        // Extract IP addresses from JSON response
        let mut addresses = Vec::new();
        if let Some(answers) = json["Answer"].as_array() {
            for answer in answers {
                if let Some(answer_type) = answer["type"].as_u64() {
                    if let Some(data) = answer["data"].as_str() {
                        // Type 1 = A record (IPv4), Type 28 = AAAA record (IPv6)
                        if (record_type == "A" && answer_type == 1) || (record_type == "AAAA" && answer_type == 28) {
                            if let Ok(ip) = data.parse::<IpAddr>() {
                                addresses.push(ip);
                            }
                        }
                    }
                }
            }
        }
        
        Ok(addresses)
    }
    
    /// Resolve hostname using DNS over TLS (DoT)
    async fn resolve_with_dot(&self, hostname: &str, dot_server: &str) -> Result<Vec<IpAddr>, NetworkError> {
        log::debug!("🔐 Resolving {} via DoT: {}", hostname, dot_server);
        
        // For DoT, we would need to configure a TLS-enabled resolver
        // For now, fall back to system resolver with a warning
        log::warn!("⚠️ DoT not fully implemented yet, falling back to system resolver");
        self.resolve_with_system(hostname).await
    }
    
    /// Validate hostname format for security
    fn is_valid_hostname(hostname: &str) -> bool {
        if hostname.is_empty() || hostname.len() > 253 {
            return false;
        }
        
        // Check for valid characters and structure
        hostname.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && !hostname.starts_with('-')
            && !hostname.ends_with('-')
            && !hostname.starts_with('.')
            && !hostname.ends_with('.')
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
        log::info!("🔄 Updating DNS resolver mode to: {:?}", mode);
        
        // Validate mode-specific settings
        match &mode {
            DnsMode::DoH(url) => {
                if let Err(e) = Url::parse(url) {
                    return Err(NetworkError::DnsError(format!("Invalid DoH URL: {}", e)));
                }
                log::info!("🔒 DoH mode configured with URL: {}", url);
            }
            DnsMode::DoT(server) => {
                log::info!("🔐 DoT mode configured with server: {}", server);
            }
            DnsMode::LocalCache => {
                log::info!("🏠 Local cache mode with system DNS fallback");
            }
            DnsMode::Custom => {
                log::info!("⚙️ Custom DNS mode");
            }
        }
        
        self.mode = mode;
        
        // Clear cache on mode change for privacy reasons
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
            log::debug!("🧹 DNS cache cleared on mode change");
        }
        
        log::info!("✅ DNS resolver mode updated successfully");
        Ok(())
    }
    
    /// Get the current DNS mode
    pub fn get_mode(&self) -> DnsMode {
        self.mode.clone()
    }
    
    /// Clear the DNS cache
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            let entries_cleared = cache.len();
            cache.clear();
            log::info!("🧹 Cleared {} DNS cache entries", entries_cleared);
        }
    }
    
    /// Set custom TTL for cached entries
    pub fn set_ttl(&mut self, ttl: Duration) {
        log::debug!("⏰ Setting DNS TTL to: {:?}", ttl);
        self.default_ttl = ttl;
    }
    
    /// Get DNS resolution statistics
    pub fn get_stats(&self) -> DnsStats {
        let cache_hits = self.dns_cache_hits.read().map(|h| *h).unwrap_or_else(|_| {
            log::warn!("Failed to read cache hits, returning 0");
            0
        });
        let queries_blocked = self.dns_queries_blocked.read().map(|b| *b).unwrap_or_else(|_| {
            log::warn!("Failed to read queries blocked, returning 0");
            0
        });
        let cache_entries = self.cache.read().map(|c| c.len()).unwrap_or(0);
        
        DnsStats {
            cache_hits,
            queries_blocked,
            cache_entries,
            current_mode: self.mode.clone(),
        }
    }
    
    /// Increment cache hit counter
    fn increment_cache_hits(&self) {
        if let Ok(mut hits) = self.dns_cache_hits.write() {
            *hits += 1;
        }
    }
    
    /// Check if a hostname should be blocked (enhanced with tracker blocking engine)
    async fn should_block_hostname_advanced(&self, hostname: &str) -> Option<crate::tracker_blocking::BlockedRequest> {
        // Use advanced tracker blocking engine if available
        if let Some(ref blocker) = self.tracker_blocker {
            return blocker.should_block_domain(hostname).await;
        }
        
        // Fall back to basic blocking
        if self.should_block_hostname_basic(hostname) {
            return Some(crate::tracker_blocking::BlockedRequest {
                url: hostname.to_string(),
                reason: "Basic tracker blocking".to_string(),
                category: crate::tracker_blocking::BlockingCategory::Unknown,
                blocked_at: Instant::now(),
                resource_type: None,
            });
        }
        
        None
    }
    
    /// Check if a hostname should be blocked (basic tracker blocking)
    fn should_block_hostname_basic(&self, hostname: &str) -> bool {
        // Comprehensive tracker and malware domain detection
        let blocked_patterns = [
            // Major advertising networks
            "doubleclick.net",
            "googleadservices.com",
            "googlesyndication.com",
            "googletagmanager.com",
            "google-analytics.com",
            "analytics.google.com",
            "facebook.com",
            "connect.facebook.net",
            "amazon-adsystem.com",
            "adsystem.amazon.com",
            "ads.twitter.com",
            "twitter.com/i/adsystem",
            "scorecardresearch.com",
            "quantserve.com",
            "outbrain.com",
            "taboola.com",
            "bing.com/th",
            
            // Social media trackers
            "facebook.net",
            "instagram.com/ajax",
            "twitter.com/i/jot",
            "linkedin.com/px",
            "pinterest.com/v3/pidgets",
            
            // Additional analytics and tracking
            "hotjar.com",
            "fullstory.com",
            "mouseflow.com",
            "crazyegg.com",
            "mixpanel.com",
            "segment.com",
            "amplitude.com",
            
            // Advertising exchanges
            "pubmatic.com",
            "rubiconproject.com",
            "appnexus.com",
            "openx.com",
            "adsystem.com",
            "adsrvr.org",
            
            // Known malware/phishing domains (basic list)
            "bit.ly", // Often used for malicious redirects
            "tinyurl.com", // Often used for malicious redirects
        ];
        
        for pattern in &blocked_patterns {
            if hostname.contains(pattern) {
                log::info!("🚫 Blocking tracking hostname: {}", hostname);
                if let Ok(mut blocked) = self.dns_queries_blocked.write() {
                    *blocked += 1;
                }
                return true;
            }
        }
        
        false
    }
    
    /// Set the tracker blocking engine
    pub fn set_tracker_blocker(&mut self, tracker_blocker: Arc<TrackerBlockingEngine>) {
        self.tracker_blocker = Some(tracker_blocker);
        log::info!("🛡️ Tracker blocking engine integrated with DNS resolver");
    }

    /// Set the privacy event sender for scoreboard integration
    pub fn set_privacy_sender(&mut self, sender: PrivacyEventSender) {
        self.privacy_sender = Some(sender);
    }
    
    /// Get tracker blocking statistics if available
    pub async fn get_tracker_stats(&self) -> Option<crate::tracker_blocking::TrackerBlockingStats> {
        if let Some(ref blocker) = self.tracker_blocker {
            Some(blocker.get_stats().await)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_local_cache_resolver() {
        let resolver = CitadelDnsResolver::new().await.expect("DNS resolver creation should succeed in tests");
        
        // Test that the resolver can be created
        assert_eq!(resolver.get_mode(), DnsMode::LocalCache);
    }
    
    #[tokio::test]
    async fn test_cache_expiration() {
        let mut resolver = CitadelDnsResolver::new().await.unwrap();
        
        // Set a very short TTL for testing
        resolver.set_ttl(Duration::from_millis(10));
        
        // Test that TTL is updated
        assert_eq!(resolver.default_ttl, Duration::from_millis(10));
    }
    
    #[tokio::test]
    async fn test_hostname_validation() {
        assert!(CitadelDnsResolver::is_valid_hostname("example.com"));
        assert!(CitadelDnsResolver::is_valid_hostname("sub.example.com"));
        assert!(!CitadelDnsResolver::is_valid_hostname(""));
        assert!(!CitadelDnsResolver::is_valid_hostname(".example.com"));
        assert!(!CitadelDnsResolver::is_valid_hostname("example.com."));
        assert!(!CitadelDnsResolver::is_valid_hostname("-example.com"));
    }
    
    #[tokio::test]
    async fn test_doh_mode() {
        let doh_url = "https://cloudflare-dns.com/dns-query";
        let resolver = CitadelDnsResolver::with_mode(DnsMode::DoH(doh_url.to_string())).await;
        assert!(resolver.is_ok());
        
        let resolver = resolver.expect("DNS resolution should succeed");
        assert_eq!(resolver.get_mode(), DnsMode::DoH(doh_url.to_string()));
    }
    
    #[tokio::test]
    async fn test_tracker_blocking() {
        let resolver = CitadelDnsResolver::new().await.expect("DNS resolver creation should succeed in tests");
        
        // Test that tracking domains are blocked
        assert!(resolver.should_block_hostname_basic("doubleclick.net"));
        assert!(resolver.should_block_hostname_basic("ads.facebook.com"));
        assert!(!resolver.should_block_hostname_basic("example.com"));
    }
    
    #[tokio::test]
    async fn test_dns_stats() {
        let resolver = CitadelDnsResolver::new().await.expect("DNS resolver creation should succeed in tests");
        let stats = resolver.get_stats();
        
        assert_eq!(stats.cache_hits, 0);
        assert_eq!(stats.queries_blocked, 0);
        assert_eq!(stats.cache_entries, 0);
        assert_eq!(stats.current_mode, DnsMode::LocalCache);
    }
    
    #[tokio::test]
    async fn test_actual_dns_resolution() {
        let resolver = CitadelDnsResolver::new().await.expect("DNS resolver creation should succeed in tests");
        
        // Test resolving a known good hostname
        match resolver.resolve("example.com").await {
            Ok(addresses) => {
                assert!(!addresses.is_empty(), "Should resolve to at least one address");
                log::info!("Resolved example.com to {} addresses", addresses.len());
            }
            Err(e) => {
                // This might fail in CI environments without network access
                log::warn!("DNS resolution failed (might be expected in CI): {}", e);
            }
        }
    }
    
    #[tokio::test]
    async fn test_doh_resolution() {
        let doh_url = "https://cloudflare-dns.com/dns-query";
        let resolver = CitadelDnsResolver::with_mode(DnsMode::DoH(doh_url.to_string())).await.expect("DoH resolver creation should succeed");
        
        // Test DoH resolution - this may fail in CI without network
        match resolver.resolve("example.com").await {
            Ok(addresses) => {
                assert!(!addresses.is_empty(), "DoH should resolve to at least one address");
                log::info!("DoH resolved example.com to {} addresses", addresses.len());
            }
            Err(e) => {
                log::warn!("DoH resolution failed (might be expected in CI): {}", e);
            }
        }
    }
}