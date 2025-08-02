pub mod dns;
pub mod request;
pub mod response;
pub mod connection;
pub mod resource;
pub mod resource_manager;
pub mod error;
pub mod resource_loader;
pub mod resource_discovery;
pub mod cache;
pub mod advanced_loader;
pub mod integrity;
pub mod performance;

/// Re-export common types for easier usage
pub use dns::{DnsMode, CitadelDnsResolver};
pub use request::{Request, Method};
pub use response::Response;
pub use connection::Connection;
pub use resource::Resource;
pub use resource_manager::{ResourceManager, ResourcePolicy, CachePolicy, ResourceStats, ResourceManagerConfig, OriginType};
pub use resource_loader::{ResourceLoader, LoadProgress, LoadResult, LoadOptions};
pub use resource_discovery::{ResourceDiscovery, ResourceRef, ResourceContext};
pub use cache::{ResourceCache, CacheEntry, CacheConfig};
pub use error::NetworkError;
pub use advanced_loader::{AdvancedResourceLoader, LoadingStrategy, Priority, NetworkCondition, BandwidthTracker};
pub use integrity::{IntegrityValidator, HashAlgorithm, IntegrityResult, CSPViolation};

/// Types of privacy level configurations for the networking layer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyLevel {
    /// Maximum privacy: randomize all possible fingerprinting vectors
    Maximum,
    /// High privacy but with potential minor site compatibility
    High,
    /// Balanced between privacy and compatibility
    Balanced,
    /// Custom user-defined privacy settings
    Custom,
}

/// Central networking configuration
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkConfig {
    /// Current privacy level for network requests
    pub privacy_level: PrivacyLevel,
    /// DNS mode to use for resolution
    pub dns_mode: dns::DnsMode,
    /// Whether to enforce HTTPS for all connections
    pub enforce_https: bool,
    /// Whether to randomize User-Agent on each request
    pub randomize_user_agent: bool,
    /// Whether to strip tracking parameters from URLs
    pub strip_tracking_params: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            privacy_level: PrivacyLevel::High,
            dns_mode: dns::DnsMode::LocalCache,
            enforce_https: true,
            randomize_user_agent: true,
            strip_tracking_params: true,
        }
    }
} 