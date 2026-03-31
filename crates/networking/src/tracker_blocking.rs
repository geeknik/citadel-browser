use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use url::Url;

use citadel_security::privacy::{PrivacyEvent, PrivacyEventSender, TrackerCategory};

use crate::error::NetworkError;
use crate::resource::ResourceType;

/// Comprehensive tracker blocking levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockingLevel {
    /// Disabled - no tracker blocking
    Disabled,
    /// Basic - block known major trackers only
    Basic,
    /// Standard - block trackers, analytics, and social media widgets
    Standard,
    /// Aggressive - block all third-party resources by default
    Aggressive,
    /// Paranoid - block everything except essential first-party resources
    Paranoid,
}

impl Default for BlockingLevel {
    fn default() -> Self {
        Self::Standard
    }
}

/// Configuration for tracker blocking
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlocklistConfig {
    /// Current blocking level
    pub blocking_level: BlockingLevel,
    /// Whether to enable DNS-level blocking
    pub dns_blocking: bool,
    /// Whether to enable HTTP request blocking
    pub http_blocking: bool,
    /// Whether to block fingerprinting scripts
    pub block_fingerprinting: bool,
    /// Whether to block cryptomining scripts
    pub block_cryptomining: bool,
    /// Whether to block malware domains
    pub block_malware: bool,
    /// Custom allow list (domains to never block)
    pub allow_list: HashSet<String>,
    /// Custom block list (additional domains to block)
    pub custom_block_list: HashSet<String>,
    /// Update interval for blocklists (in hours)
    pub update_interval_hours: u64,
    /// Maximum cache size for blocklist entries
    pub max_cache_entries: usize,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            blocking_level: BlockingLevel::Standard,
            dns_blocking: true,
            http_blocking: true,
            block_fingerprinting: true,
            block_cryptomining: true,
            block_malware: true,
            allow_list: HashSet::new(),
            custom_block_list: HashSet::new(),
            update_interval_hours: 24,
            max_cache_entries: 100_000,
        }
    }
}

/// Information about a blocked request
#[derive(Debug, Clone)]
pub struct BlockedRequest {
    /// URL that was blocked
    pub url: String,
    /// Reason for blocking
    pub reason: String,
    /// Category of the blocked resource
    pub category: BlockingCategory,
    /// When it was blocked
    pub blocked_at: Instant,
    /// Resource type if known
    pub resource_type: Option<ResourceType>,
}

/// Categories of blocked content
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BlockingCategory {
    /// Advertising and marketing trackers
    Advertising,
    /// Analytics and metrics trackers
    Analytics,
    /// Social media widgets and trackers
    SocialMedia,
    /// Fingerprinting scripts
    Fingerprinting,
    /// Cryptomining scripts
    Cryptomining,
    /// Malware and phishing domains
    Malware,
    /// Third-party content
    ThirdParty,
    /// Custom user-defined block
    Custom,
    /// Unknown/general tracking
    Unknown,
}

/// Statistics about tracker blocking
#[derive(Debug, Clone, Default)]
pub struct TrackerBlockingStats {
    /// Total requests blocked
    pub total_blocked: u64,
    /// Blocked by category
    pub blocked_by_category: HashMap<BlockingCategory, u64>,
    /// Blocked domains (top 50)
    pub top_blocked_domains: Vec<(String, u64)>,
    /// Data saved (in bytes) by blocking
    pub bytes_saved: u64,
    /// Last update of blocklists (as seconds since epoch for serialization)
    pub last_blocklist_update: Option<u64>,
    /// Total domains in blocklists
    pub total_blocklist_entries: usize,
}

/// Individual blocklist source
#[derive(Debug, Clone)]
struct BlocklistSource {
    /// Name of the source
    #[allow(dead_code)] // Will be used when implementing multiple blocklist sources
    name: String,
    /// Category this blocklist covers
    #[allow(dead_code)] // Will be used when implementing category-based blocking
    category: BlockingCategory,
    /// Domains in this blocklist
    domains: HashSet<String>,
    /// Regex patterns for dynamic matching
    patterns: Vec<Regex>,
    /// Last update time
    #[allow(dead_code)] // Will be used when implementing automatic blocklist updates
    last_updated: Instant,
    /// Whether this source is enabled
    enabled: bool,
}

/// Comprehensive tracker blocking engine
pub struct TrackerBlockingEngine {
    /// Configuration
    config: Arc<RwLock<BlocklistConfig>>,
    /// Compiled blocklists by category
    blocklists: Arc<RwLock<HashMap<BlockingCategory, BlocklistSource>>>,
    /// Fast lookup table for domain blocking
    domain_lookup: Arc<RwLock<HashSet<String>>>,
    /// Pattern matching for dynamic blocking
    pattern_cache: Arc<RwLock<HashMap<String, bool>>>,
    /// Statistics
    stats: Arc<Mutex<TrackerBlockingStats>>,
    /// Recently blocked requests (for logging/debugging)
    recent_blocks: Arc<RwLock<Vec<BlockedRequest>>>,
    /// Optional privacy event sender for the scoreboard
    privacy_sender: Option<PrivacyEventSender>,
}

impl TrackerBlockingEngine {
    /// Create a new tracker blocking engine with default configuration
    pub async fn new() -> Result<Self, NetworkError> {
        Self::with_config(BlocklistConfig::default()).await
    }

    /// Create a new tracker blocking engine with custom configuration
    pub async fn with_config(config: BlocklistConfig) -> Result<Self, NetworkError> {
        let engine = Self {
            config: Arc::new(RwLock::new(config.clone())),
            blocklists: Arc::new(RwLock::new(HashMap::new())),
            domain_lookup: Arc::new(RwLock::new(HashSet::new())),
            pattern_cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(Mutex::new(TrackerBlockingStats::default())),
            recent_blocks: Arc::new(RwLock::new(Vec::new())),
            privacy_sender: None,
        };

        // Initialize built-in blocklists
        engine.initialize_builtin_blocklists().await?;

        log::info!("🛡️ Tracker blocking engine initialized with level: {:?}", config.blocking_level);

        Ok(engine)
    }

    /// Initialize built-in blocklists with known tracker domains
    async fn initialize_builtin_blocklists(&self) -> Result<(), NetworkError> {
        let mut blocklists = HashMap::new();

        // Advertising trackers
        let advertising_domains = self.get_advertising_domains();
        let advertising_patterns = self.get_advertising_patterns()?;
        blocklists.insert(
            BlockingCategory::Advertising,
            BlocklistSource {
                name: "Built-in Advertising".to_string(),
                category: BlockingCategory::Advertising,
                domains: advertising_domains,
                patterns: advertising_patterns,
                last_updated: Instant::now(),
                enabled: true,
            },
        );

        // Analytics trackers
        let analytics_domains = self.get_analytics_domains();
        let analytics_patterns = self.get_analytics_patterns()?;
        blocklists.insert(
            BlockingCategory::Analytics,
            BlocklistSource {
                name: "Built-in Analytics".to_string(),
                category: BlockingCategory::Analytics,
                domains: analytics_domains,
                patterns: analytics_patterns,
                last_updated: Instant::now(),
                enabled: true,
            },
        );

        // Social media trackers
        let social_domains = self.get_social_media_domains();
        let social_patterns = self.get_social_media_patterns()?;
        blocklists.insert(
            BlockingCategory::SocialMedia,
            BlocklistSource {
                name: "Built-in Social Media".to_string(),
                category: BlockingCategory::SocialMedia,
                domains: social_domains,
                patterns: social_patterns,
                last_updated: Instant::now(),
                enabled: true,
            },
        );

        // Fingerprinting scripts
        let fingerprinting_domains = self.get_fingerprinting_domains();
        let fingerprinting_patterns = self.get_fingerprinting_patterns()?;
        blocklists.insert(
            BlockingCategory::Fingerprinting,
            BlocklistSource {
                name: "Built-in Fingerprinting".to_string(),
                category: BlockingCategory::Fingerprinting,
                domains: fingerprinting_domains,
                patterns: fingerprinting_patterns,
                last_updated: Instant::now(),
                enabled: true,
            },
        );

        // Cryptomining scripts
        let cryptomining_domains = self.get_cryptomining_domains();
        let cryptomining_patterns = self.get_cryptomining_patterns()?;
        blocklists.insert(
            BlockingCategory::Cryptomining,
            BlocklistSource {
                name: "Built-in Cryptomining".to_string(),
                category: BlockingCategory::Cryptomining,
                domains: cryptomining_domains,
                patterns: cryptomining_patterns,
                last_updated: Instant::now(),
                enabled: true,
            },
        );

        // Malware domains
        let malware_domains = self.get_malware_domains();
        let malware_patterns = self.get_malware_patterns()?;
        blocklists.insert(
            BlockingCategory::Malware,
            BlocklistSource {
                name: "Built-in Malware".to_string(),
                category: BlockingCategory::Malware,
                domains: malware_domains,
                patterns: malware_patterns,
                last_updated: Instant::now(),
                enabled: true,
            },
        );

        // Update the blocklists and rebuild lookup table
        if let Ok(mut bl) = self.blocklists.write() {
            *bl = blocklists;
        }

        self.rebuild_lookup_table().await;

        // Update last update time
        if let Ok(mut stats) = self.stats.try_lock() {
            stats.last_blocklist_update = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            );
        }

        let stats = self.stats.lock().await;
        log::info!("🛡️ Initialized {} blocklist sources with {} total domains", 
                  6, stats.total_blocklist_entries);

        Ok(())
    }

    /// Rebuild the fast lookup table from all enabled blocklists
    async fn rebuild_lookup_table(&self) {
        let mut domain_set = HashSet::new();
        let mut total_entries = 0;

        if let Ok(blocklists) = self.blocklists.read() {
            for (category, source) in blocklists.iter() {
                if source.enabled {
                    // Check if this category should be blocked based on configuration
                    if self.is_category_enabled(*category).await {
                        domain_set.extend(source.domains.iter().cloned());
                        total_entries += source.domains.len();
                    }
                }
            }
        }

        // Add custom block list
        if let Ok(config) = self.config.read() {
            domain_set.extend(config.custom_block_list.iter().cloned());
            total_entries += config.custom_block_list.len();
        }

        // Update lookup table
        if let Ok(mut lookup) = self.domain_lookup.write() {
            *lookup = domain_set;
        }

        // Update stats
        if let Ok(mut stats) = self.stats.try_lock() {
            stats.total_blocklist_entries = total_entries;
        }

        log::debug!("🔄 Rebuilt lookup table with {} domains", total_entries);
    }

    /// Check if a category should be blocked based on current configuration
    async fn is_category_enabled(&self, category: BlockingCategory) -> bool {
        if let Ok(config) = self.config.read() {
            let level_enabled = match config.blocking_level {
                BlockingLevel::Disabled => false,
                BlockingLevel::Basic => matches!(category, 
                    BlockingCategory::Advertising | BlockingCategory::Malware
                ),
                BlockingLevel::Standard => matches!(category,
                    BlockingCategory::Advertising | BlockingCategory::Analytics | 
                    BlockingCategory::SocialMedia | BlockingCategory::Malware
                ),
                BlockingLevel::Aggressive => matches!(category,
                    BlockingCategory::Advertising | BlockingCategory::Analytics | 
                    BlockingCategory::SocialMedia | BlockingCategory::Fingerprinting |
                    BlockingCategory::Cryptomining | BlockingCategory::Malware |
                    BlockingCategory::ThirdParty
                ),
                BlockingLevel::Paranoid => true, // Block everything except allow list
            };
            
            let category_enabled = match category {
                BlockingCategory::Fingerprinting => config.block_fingerprinting,
                BlockingCategory::Cryptomining => config.block_cryptomining,
                BlockingCategory::Malware => config.block_malware,
                _ => true,
            };
            
            level_enabled && category_enabled
        } else {
            false
        }
    }

    /// Check if a domain should be blocked
    pub async fn should_block_domain(&self, domain: &str) -> Option<BlockedRequest> {
        // Check allow list first - clone the data to avoid holding lock across await
        let (in_allow_list, is_disabled) = {
            if let Ok(config) = self.config.read() {
                (config.allow_list.contains(domain), config.blocking_level == BlockingLevel::Disabled)
            } else {
                (false, false)
            }
        };

        if in_allow_list || is_disabled {
            return None;
        }

        // Fast lookup in domain table - clone check result to avoid holding lock across await
        let in_domain_lookup = {
            if let Ok(lookup) = self.domain_lookup.read() {
                lookup.contains(domain)
            } else {
                false
            }
        };

        if in_domain_lookup {
            let category = self.categorize_domain(domain).await;
            return Some(self.create_blocked_request(
                domain,
                "Domain in blocklist".to_string(),
                category,
                None,
            ));
        }

        // Check subdomain matches
        if let Some(parent_domain) = self.extract_parent_domain(domain) {
            let parent_in_lookup = {
                if let Ok(lookup) = self.domain_lookup.read() {
                    lookup.contains(&parent_domain)
                } else {
                    false
                }
            };

            if parent_in_lookup {
                let category = self.categorize_domain(&parent_domain).await;
                return Some(self.create_blocked_request(
                    domain,
                    format!("Subdomain of blocked domain: {}", parent_domain),
                    category,
                    None,
                ));
            }
        }

        // Check pattern matching (cached)
        if let Some(blocked) = self.check_pattern_cache(domain).await {
            if blocked {
                return Some(self.create_blocked_request(
                    domain,
                    "Matches blocking pattern".to_string(),
                    BlockingCategory::Unknown,
                    None,
                ));
            }
        } else {
            // Pattern not in cache, check all patterns
            if let Some(category) = self.check_patterns(domain).await {
                // Cache the result
                self.update_pattern_cache(domain, true).await;
                return Some(self.create_blocked_request(
                    domain,
                    "Matches blocking pattern".to_string(),
                    category,
                    None,
                ));
            } else {
                // Cache negative result
                self.update_pattern_cache(domain, false).await;
            }
        }

        None
    }

    /// Check if a URL should be blocked
    pub async fn should_block_url(&self, url: &str, resource_type: Option<ResourceType>) -> Option<BlockedRequest> {
        let parsed_url = match Url::parse(url) {
            Ok(url) => url,
            Err(_) => return None,
        };

        let domain = match parsed_url.host_str() {
            Some(host) => host,
            None => return None,
        };

        // Check domain-level blocking first
        if let Some(mut blocked) = self.should_block_domain(domain).await {
            blocked.url = url.to_string();
            blocked.resource_type = resource_type;
            return Some(blocked);
        }

        // Check URL-specific patterns
        if let Some(category) = self.check_url_patterns(url).await {
            return Some(self.create_blocked_request(
                url,
                "URL matches blocking pattern".to_string(),
                category,
                resource_type,
            ));
        }

        // Check for third-party blocking in aggressive/paranoid modes
        if let Ok(config) = self.config.read() {
            if matches!(config.blocking_level, BlockingLevel::Aggressive | BlockingLevel::Paranoid) {
                // This would need context about the main frame to determine if third-party
                // For now, we'll skip this check as it requires integration with ResourceManager
            }
        }

        None
    }

    /// Check patterns against a domain
    async fn check_patterns(&self, domain: &str) -> Option<BlockingCategory> {
        // Collect patterns without holding the lock across await
        let patterns_to_check = {
            if let Ok(blocklists) = self.blocklists.read() {
                let mut patterns = Vec::new();
                for (category, source) in blocklists.iter() {
                    if source.enabled {
                        patterns.push((*category, source.patterns.clone()));
                    }
                }
                patterns
            } else {
                Vec::new()
            }
        };
        
        for (category, patterns) in patterns_to_check {
            if self.is_category_enabled(category).await {
                for pattern in &patterns {
                    if pattern.is_match(domain) {
                        return Some(category);
                    }
                }
            }
        }
        None
    }

    /// Check URL patterns for script-specific blocking
    async fn check_url_patterns(&self, url: &str) -> Option<BlockingCategory> {
        // Check for fingerprinting scripts
        let fingerprinting_patterns = [
            r"fingerprint",
            r"canvas.*fingerprint",
            r"webgl.*fingerprint",
            r"audio.*fingerprint",
            r"device.*fingerprint",
        ];

        for pattern_str in &fingerprinting_patterns {
            if let Ok(pattern) = Regex::new(pattern_str) {
                if pattern.is_match(url) {
                    return Some(BlockingCategory::Fingerprinting);
                }
            }
        }

        // Check for cryptomining scripts
        let mining_patterns = [
            r"coinhive",
            r"jsecoin",
            r"crypto.*mine",
            r"mine.*crypto",
            r"webminer",
        ];

        for pattern_str in &mining_patterns {
            if let Ok(pattern) = Regex::new(pattern_str) {
                if pattern.is_match(url) {
                    return Some(BlockingCategory::Cryptomining);
                }
            }
        }

        None
    }

    /// Create a blocked request record
    fn create_blocked_request(&self, url: &str, reason: String, category: BlockingCategory, resource_type: Option<ResourceType>) -> BlockedRequest {
        BlockedRequest {
            url: url.to_string(),
            reason,
            category,
            blocked_at: Instant::now(),
            resource_type,
        }
    }

    /// Set the privacy event sender for scoreboard integration
    pub fn set_privacy_sender(&mut self, sender: PrivacyEventSender) {
        self.privacy_sender = Some(sender);
    }

    /// Record a blocked request and update statistics
    pub async fn record_blocked_request(&self, blocked: BlockedRequest) {
        log::info!("🚫 Blocked {} request: {} ({})",
                  blocked.category.to_string(), blocked.url, blocked.reason);

        // Emit privacy event for the scoreboard
        if let Some(sender) = &self.privacy_sender {
            sender.emit(PrivacyEvent::TrackerBlocked {
                url: blocked.url.clone(),
                rule: blocked.reason.clone(),
                category: match blocked.category {
                    BlockingCategory::Advertising => TrackerCategory::Advertising,
                    BlockingCategory::Analytics => TrackerCategory::Analytics,
                    BlockingCategory::SocialMedia => TrackerCategory::Social,
                    BlockingCategory::Cryptomining => TrackerCategory::Cryptomining,
                    BlockingCategory::Fingerprinting => TrackerCategory::Fingerprinting,
                    _ => TrackerCategory::Unknown,
                },
            });
        }

        // Update statistics
        if let Ok(mut stats) = self.stats.try_lock() {
            stats.total_blocked += 1;
            let counter = stats.blocked_by_category.entry(blocked.category).or_insert(0);
            *counter += 1;

            // Update top blocked domains
            if let Ok(parsed_url) = Url::parse(&blocked.url) {
                if let Some(host) = parsed_url.host_str() {
                    let domain_stats = &mut stats.top_blocked_domains;
                    
                    // Find existing entry or create new one
                    if let Some(pos) = domain_stats.iter().position(|(domain, _)| domain == host) {
                        domain_stats[pos].1 += 1;
                    } else if domain_stats.len() < 50 {
                        domain_stats.push((host.to_string(), 1));
                    }
                    
                    // Sort by count (descending)
                    domain_stats.sort_by(|a, b| b.1.cmp(&a.1));
                    domain_stats.truncate(50);
                }
            }
        }

        // Add to recent blocks (keep last 100)
        if let Ok(mut recent) = self.recent_blocks.write() {
            recent.push(blocked);
            if recent.len() > 100 {
                recent.remove(0);
            }
        }
    }

    /// Get current blocking statistics
    pub async fn get_stats(&self) -> TrackerBlockingStats {
        if let Ok(stats) = self.stats.try_lock() {
            stats.clone()
        } else {
            TrackerBlockingStats::default()
        }
    }

    /// Get recent blocked requests
    pub async fn get_recent_blocks(&self) -> Vec<BlockedRequest> {
        if let Ok(recent) = self.recent_blocks.read() {
            recent.clone()
        } else {
            Vec::new()
        }
    }

    /// Update configuration
    pub async fn update_config(&self, new_config: BlocklistConfig) -> Result<(), NetworkError> {
        if let Ok(mut config) = self.config.write() {
            *config = new_config;
        }

        // Rebuild lookup table with new configuration
        self.rebuild_lookup_table().await;

        log::info!("🔄 Tracker blocking configuration updated");
        Ok(())
    }

    /// Extract parent domain (e.g., "example.com" from "sub.example.com")
    fn extract_parent_domain(&self, domain: &str) -> Option<String> {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 2 {
            Some(format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]))
        } else {
            None
        }
    }

    /// Categorize a domain based on blocklists
    async fn categorize_domain(&self, domain: &str) -> BlockingCategory {
        // Collect domain-category mappings without holding lock across await
        let domain_categories: Vec<(BlockingCategory, bool)> = {
            if let Ok(blocklists) = self.blocklists.read() {
                blocklists.iter()
                    .map(|(category, source)| (*category, source.domains.contains(domain)))
                    .collect()
            } else {
                Vec::new()
            }
        };

        for (category, contains_domain) in domain_categories {
            if contains_domain {
                return category;
            }
        }
        BlockingCategory::Unknown
    }

    /// Check pattern cache
    async fn check_pattern_cache(&self, domain: &str) -> Option<bool> {
        // No await in this method, so no need for special handling
        if let Ok(cache) = self.pattern_cache.read() {
            cache.get(domain).copied()
        } else {
            None
        }
    }

    /// Update pattern cache
    async fn update_pattern_cache(&self, domain: &str, blocked: bool) {
        // No await in this method, so no need for special handling
        let max_entries = {
            if let Ok(config) = self.config.read() {
                config.max_cache_entries
            } else {
                100_000 // default
            }
        };
        
        if let Ok(mut cache) = self.pattern_cache.write() {
            cache.insert(domain.to_string(), blocked);
            
            // Limit cache size
            if cache.len() > max_entries {
                // Remove oldest entries (simple FIFO)
                let keys_to_remove: Vec<String> = cache.keys()
                    .take(cache.len() / 4)
                    .cloned()
                    .collect();
                
                for key in keys_to_remove {
                    cache.remove(&key);
                }
            }
        }
    }

    // Built-in domain lists (these would ideally be loaded from external sources)
    
    fn get_advertising_domains(&self) -> HashSet<String> {
        [
            "doubleclick.net", "googleadservices.com", "googlesyndication.com",
            "googletagmanager.com", "adsystem.amazon.com", "amazon-adsystem.com",
            "adsrvr.org", "pubmatic.com", "rubiconproject.com", "appnexus.com",
            "openx.com", "adsystem.com", "criteo.com", "outbrain.com",
            "taboola.com", "scorecardresearch.com", "quantserve.com",
            "ads.twitter.com", "ads.facebook.com", "ads.yahoo.com",
            "bing.com", "microsoft.com", "ads.linkedin.com",
        ].iter().map(|s| s.to_string()).collect()
    }

    fn get_analytics_domains(&self) -> HashSet<String> {
        [
            "google-analytics.com", "analytics.google.com", "stats.g.doubleclick.net",
            "pixel.facebook.com", "analytics.facebook.com", "analytics.twitter.com",
            "matomo.org", "statcounter.com", "hotjar.com", "fullstory.com",
            "mouseflow.com", "crazyegg.com", "mixpanel.com", "segment.com",
            "amplitude.com", "heap.io", "kissmetrics.com", "chartbeat.com",
        ].iter().map(|s| s.to_string()).collect()
    }

    fn get_social_media_domains(&self) -> HashSet<String> {
        [
            "connect.facebook.net", "platform.twitter.com", "platform.linkedin.com",
            "platform.instagram.com", "widgets.pinterest.com", "api.tiktok.com",
            "snapchat.com", "reddit.com", "disqus.com", "addthis.com",
            "sharethis.com", "social-plugins.facebook.com",
        ].iter().map(|s| s.to_string()).collect()
    }

    fn get_fingerprinting_domains(&self) -> HashSet<String> {
        [
            "fingerprintjs.com", "deviceinfo.me", "maxmind.com",
            "browserleaks.com", "uniquemachine.org", "cross-device.io",
        ].iter().map(|s| s.to_string()).collect()
    }

    fn get_cryptomining_domains(&self) -> HashSet<String> {
        [
            "coinhive.com", "jsecoin.com", "coin-hive.com", "crypto-loot.com",
            "webminer.pro", "minero.cc", "miner.start.fyi", "coinblocker.org",
        ].iter().map(|s| s.to_string()).collect()
    }

    fn get_malware_domains(&self) -> HashSet<String> {
        [
            "malware.com", "phishing.com", "trojan.com", "virus.com",
            // These would be populated from threat intelligence feeds
        ].iter().map(|s| s.to_string()).collect()
    }

    fn get_advertising_patterns(&self) -> Result<Vec<Regex>, NetworkError> {
        let patterns = [
            r".*\.ads\.",
            r".*\.ad\.",
            r".*advertising.*",
            r".*\.doubleclick\.",
            r".*\.googlesyndication\.",
            r".*\.amazon-adsystem\.",
        ];

        patterns.iter()
            .map(|p| Regex::new(p).map_err(|e| NetworkError::UnknownError(format!("Regex error: {}", e))))
            .collect()
    }

    fn get_analytics_patterns(&self) -> Result<Vec<Regex>, NetworkError> {
        let patterns = [
            r".*analytics.*",
            r".*\.stats\.",
            r".*\.metrics\.",
            r".*tracking.*",
            r".*\.pixel\.",
        ];

        patterns.iter()
            .map(|p| Regex::new(p).map_err(|e| NetworkError::UnknownError(format!("Regex error: {}", e))))
            .collect()
    }

    fn get_social_media_patterns(&self) -> Result<Vec<Regex>, NetworkError> {
        let patterns = [
            r".*\.social\.",
            r".*\.widgets\.",
            r".*\.platform\.",
            r".*\.connect\.",
        ];

        patterns.iter()
            .map(|p| Regex::new(p).map_err(|e| NetworkError::UnknownError(format!("Regex error: {}", e))))
            .collect()
    }

    fn get_fingerprinting_patterns(&self) -> Result<Vec<Regex>, NetworkError> {
        let patterns = [
            r".*fingerprint.*",
            r".*\.fp\.",
            r".*deviceinfo.*",
            r".*browserinfo.*",
        ];

        patterns.iter()
            .map(|p| Regex::new(p).map_err(|e| NetworkError::UnknownError(format!("Regex error: {}", e))))
            .collect()
    }

    fn get_cryptomining_patterns(&self) -> Result<Vec<Regex>, NetworkError> {
        let patterns = [
            r".*coin.*",
            r".*crypto.*",
            r".*mine.*",
            r".*miner.*",
        ];

        patterns.iter()
            .map(|p| Regex::new(p).map_err(|e| NetworkError::UnknownError(format!("Regex error: {}", e))))
            .collect()
    }

    fn get_malware_patterns(&self) -> Result<Vec<Regex>, NetworkError> {
        let patterns = [
            r".*malware.*",
            r".*phishing.*",
            r".*trojan.*",
            r".*virus.*",
        ];

        patterns.iter()
            .map(|p| Regex::new(p).map_err(|e| NetworkError::UnknownError(format!("Regex error: {}", e))))
            .collect()
    }
}

impl std::fmt::Display for BlockingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockingCategory::Advertising => write!(f, "advertising"),
            BlockingCategory::Analytics => write!(f, "analytics"),
            BlockingCategory::SocialMedia => write!(f, "social-media"),
            BlockingCategory::Fingerprinting => write!(f, "fingerprinting"),
            BlockingCategory::Cryptomining => write!(f, "cryptomining"),
            BlockingCategory::Malware => write!(f, "malware"),
            BlockingCategory::ThirdParty => write!(f, "third-party"),
            BlockingCategory::Custom => write!(f, "custom"),
            BlockingCategory::Unknown => write!(f, "unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_tracker_blocking_engine_creation() {
        let engine = TrackerBlockingEngine::new().await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_domain_blocking() {
        let engine = TrackerBlockingEngine::new().await.unwrap();
        
        // Test known tracker domain
        let blocked = engine.should_block_domain("doubleclick.net").await;
        assert!(blocked.is_some());
        
        if let Some(blocked_req) = blocked {
            assert_eq!(blocked_req.category, BlockingCategory::Advertising);
        }

        // Test non-tracker domain
        let not_blocked = engine.should_block_domain("example.com").await;
        assert!(not_blocked.is_none());
    }

    #[tokio::test]
    async fn test_subdomain_blocking() {
        let engine = TrackerBlockingEngine::new().await.unwrap();
        
        // Test subdomain of blocked domain
        let blocked = engine.should_block_domain("ads.doubleclick.net").await;
        assert!(blocked.is_some());
    }

    #[tokio::test]
    async fn test_pattern_matching() {
        let engine = TrackerBlockingEngine::new().await.unwrap();
        
        // Test pattern-based blocking
        let blocked = engine.should_block_domain("analytics.example.com").await;
        assert!(blocked.is_some());
    }

    #[tokio::test]
    async fn test_allow_list() {
        let mut config = BlocklistConfig::default();
        config.allow_list.insert("doubleclick.net".to_string());
        
        let engine = TrackerBlockingEngine::with_config(config).await.unwrap();
        
        // Should not block domain in allow list
        let not_blocked = engine.should_block_domain("doubleclick.net").await;
        assert!(not_blocked.is_none());
    }

    #[tokio::test]
    async fn test_blocking_levels() {
        // Test disabled level
        let mut config = BlocklistConfig::default();
        config.blocking_level = BlockingLevel::Disabled;
        
        let engine = TrackerBlockingEngine::with_config(config).await.unwrap();
        let not_blocked = engine.should_block_domain("doubleclick.net").await;
        assert!(not_blocked.is_none());

        // Test basic level
        let mut config = BlocklistConfig::default();
        config.blocking_level = BlockingLevel::Basic;
        
        let engine = TrackerBlockingEngine::with_config(config).await.unwrap();
        let blocked = engine.should_block_domain("doubleclick.net").await;
        assert!(blocked.is_some());
    }

    #[tokio::test]
    async fn test_statistics() {
        let engine = TrackerBlockingEngine::new().await.unwrap();
        
        // Block a domain and check statistics
        if let Some(blocked) = engine.should_block_domain("doubleclick.net").await {
            engine.record_blocked_request(blocked).await;
        }
        
        let stats = engine.get_stats().await;
        assert!(stats.total_blocked > 0);
        assert!(stats.blocked_by_category.contains_key(&BlockingCategory::Advertising));
    }

    #[tokio::test]
    async fn test_url_blocking() {
        let engine = TrackerBlockingEngine::new().await.unwrap();
        
        // Test URL with tracker domain
        let blocked = engine.should_block_url("https://doubleclick.net/tracker.js", Some(ResourceType::Script)).await;
        assert!(blocked.is_some());
        
        if let Some(blocked_req) = blocked {
            assert_eq!(blocked_req.url, "https://doubleclick.net/tracker.js");
            assert_eq!(blocked_req.resource_type, Some(ResourceType::Script));
        }
    }
}