pub mod advanced_loader;
pub mod cache;
pub mod connection;
pub mod dns;
pub mod error;
pub mod http;
pub mod integrity;
pub mod performance;
pub mod privacy_engine;
pub mod request;
pub mod resource;
pub mod resource_discovery;
pub mod resource_loader;
pub mod resource_manager;
pub mod response;
pub mod tracker_blocking;

pub use advanced_loader::{
    AdvancedResourceLoader, BandwidthTracker, LoadingStrategy, NetworkCondition, Priority,
};
pub use cache::{CacheConfig, CacheEntry, ResourceCache};
pub use connection::Connection;
/// Re-export common types for easier usage
pub use dns::{CitadelDnsResolver, DnsMode, DohProviders};
pub use error::NetworkError;
pub use http::{fetch as https_fetch, HttpResponse};
pub use integrity::{CSPViolation, HashAlgorithm, IntegrityResult, IntegrityValidator};
pub use privacy_engine::{CitadelPrivacyEngine, PrivacyStats};
pub use request::{Method, Request};
pub use resource::Resource;
pub use resource_discovery::{ResourceContext, ResourceDiscovery, ResourceRef};
pub use resource_loader::{LoadOptions, LoadProgress, LoadResult, ResourceLoader};
pub use resource_manager::{
    CachePolicy, OriginType, ResourceManager, ResourceManagerConfig, ResourcePolicy, ResourceStats,
};
pub use response::Response;
pub use tracker_blocking::{
    BlockedRequest, BlockingLevel, BlocklistConfig, TrackerBlockingEngine, TrackerBlockingStats,
};

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
    /// Tracker blocking configuration
    pub tracker_blocking: tracker_blocking::BlocklistConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            privacy_level: PrivacyLevel::High,
            dns_mode: dns::DnsMode::LocalCache,
            enforce_https: true,
            randomize_user_agent: true,
            strip_tracking_params: true,
            tracker_blocking: tracker_blocking::BlocklistConfig::default(),
        }
    }
}
