use std::sync::Arc;

use crate::dns::{CitadelDnsResolver, DnsMode};
use crate::error::NetworkError;
use crate::resource_manager::{ResourceManager, ResourceManagerConfig};
use crate::tracker_blocking::{TrackerBlockingEngine, BlocklistConfig, TrackerBlockingStats};
use crate::NetworkConfig;

/// Comprehensive privacy engine that coordinates DNS resolution, 
/// resource management, and tracker blocking
pub struct CitadelPrivacyEngine {
    /// DNS resolver with tracker blocking
    pub dns_resolver: CitadelDnsResolver,
    /// Resource manager with tracker blocking
    pub resource_manager: ResourceManager,
    /// Tracker blocking engine
    pub tracker_blocker: Arc<TrackerBlockingEngine>,
}

impl CitadelPrivacyEngine {
    /// Create a new privacy engine with default configuration
    pub async fn new() -> Result<Self, NetworkError> {
        Self::with_config(NetworkConfig::default()).await
    }

    /// Create a privacy engine with custom network configuration
    pub async fn with_config(network_config: NetworkConfig) -> Result<Self, NetworkError> {
        log::info!("🛡️ Initializing Citadel Privacy Engine");

        // Create tracker blocking engine
        let tracker_blocker = Arc::new(
            TrackerBlockingEngine::with_config(network_config.tracker_blocking.clone()).await?
        );

        // Create DNS resolver with tracker blocking
        let dns_resolver = CitadelDnsResolver::with_tracker_blocking(
            network_config.dns_mode.clone(),
            tracker_blocker.clone(),
        ).await?;

        // Create resource manager with tracker blocking
        let resource_config = ResourceManagerConfig {
            network_config: network_config.clone(),
            ..ResourceManagerConfig::default()
        };

        let resource_manager = ResourceManager::with_config_and_tracker_blocking(
            resource_config,
            Some(tracker_blocker.clone()),
        ).await?;

        log::info!("✅ Citadel Privacy Engine initialized successfully");

        Ok(Self {
            dns_resolver,
            resource_manager,
            tracker_blocker,
        })
    }

    /// Create a privacy engine with custom configurations for all components
    pub async fn with_full_config(
        _network_config: NetworkConfig,
        tracker_config: BlocklistConfig,
        resource_config: ResourceManagerConfig,
        dns_mode: DnsMode,
    ) -> Result<Self, NetworkError> {
        log::info!("🛡️ Initializing Citadel Privacy Engine with full custom configuration");

        // Create tracker blocking engine
        let tracker_blocker = Arc::new(
            TrackerBlockingEngine::with_config(tracker_config).await?
        );

        // Create DNS resolver with tracker blocking
        let dns_resolver = CitadelDnsResolver::with_tracker_blocking(
            dns_mode,
            tracker_blocker.clone(),
        ).await?;

        // Create resource manager with tracker blocking
        let resource_manager = ResourceManager::with_config_and_tracker_blocking(
            resource_config,
            Some(tracker_blocker.clone()),
        ).await?;

        log::info!("✅ Citadel Privacy Engine initialized with full custom configuration");

        Ok(Self {
            dns_resolver,
            resource_manager,
            tracker_blocker,
        })
    }

    /// Get comprehensive privacy statistics
    pub async fn get_privacy_stats(&self) -> PrivacyStats {
        let dns_stats = self.dns_resolver.get_stats();
        let (resource_stats, tracker_stats) = self.resource_manager.get_comprehensive_stats().await;
        let tracker_stats = tracker_stats.unwrap_or_default();
        let total_blocked = tracker_stats.total_blocked;
        let dns_blocked = dns_stats.queries_blocked;

        PrivacyStats {
            dns: dns_stats,
            resources: resource_stats,
            tracker_blocking: tracker_stats,
            total_privacy_actions: total_blocked + dns_blocked,
        }
    }

    /// Update tracker blocking configuration
    pub async fn update_tracker_config(&self, config: BlocklistConfig) -> Result<(), NetworkError> {
        self.tracker_blocker.update_config(config).await
    }

    /// Get recent blocked requests for debugging/logging
    pub async fn get_recent_blocks(&self) -> Vec<crate::tracker_blocking::BlockedRequest> {
        self.tracker_blocker.get_recent_blocks().await
    }

    /// Clear all caches (DNS and resource caches)
    pub fn clear_all_caches(&self) {
        self.dns_resolver.clear_cache();
        self.resource_manager.clear_cache();
        log::info!("🧹 All privacy engine caches cleared");
    }

    /// Check if a domain would be blocked (for UI previews)
    pub async fn would_block_domain(&self, domain: &str) -> bool {
        self.tracker_blocker.should_block_domain(domain).await.is_some()
    }

    /// Check if a URL would be blocked (for UI previews)
    pub async fn would_block_url(&self, url: &str) -> bool {
        self.tracker_blocker.should_block_url(url, None).await.is_some()
    }

    /// Get the underlying tracker blocking engine for advanced operations
    pub fn get_tracker_blocker(&self) -> Arc<TrackerBlockingEngine> {
        self.tracker_blocker.clone()
    }

    /// Get the DNS resolver for direct DNS operations
    pub fn get_dns_resolver(&self) -> &CitadelDnsResolver {
        &self.dns_resolver
    }

    /// Get the resource manager for direct resource operations
    pub fn get_resource_manager(&self) -> &ResourceManager {
        &self.resource_manager
    }
}

/// Comprehensive privacy statistics from all components
#[derive(Debug, Clone)]
pub struct PrivacyStats {
    /// DNS resolution statistics
    pub dns: crate::dns::DnsStats,
    /// Resource loading statistics
    pub resources: crate::resource_manager::ResourceStats,
    /// Tracker blocking statistics
    pub tracker_blocking: TrackerBlockingStats,
    /// Total privacy actions taken (blocks, etc.)
    pub total_privacy_actions: u64,
}

impl PrivacyStats {
    /// Calculate the estimated data saved by privacy protections
    pub fn estimated_data_saved_mb(&self) -> f64 {
        // Estimate based on blocked requests and average tracker payload size
        let estimated_bytes = self.tracker_blocking.total_blocked * 50_000; // ~50KB per tracker
        estimated_bytes as f64 / 1_048_576.0 // Convert to MB
    }

    /// Calculate privacy protection percentage
    pub fn privacy_protection_percentage(&self) -> f64 {
        let total_requests = self.resources.total_requests as f64;
        if total_requests == 0.0 {
            return 100.0;
        }

        let blocked_requests = self.tracker_blocking.total_blocked as f64;
        (blocked_requests / (total_requests + blocked_requests)) * 100.0
    }

    /// Get a human-readable summary of privacy protections
    pub fn get_summary(&self) -> String {
        format!(
            "Privacy Protection Summary:\n\
            - Total requests blocked: {}\n\
            - DNS queries blocked: {}\n\
            - Data saved: {:.2} MB\n\
            - Privacy protection: {:.1}%\n\
            - DNS cache efficiency: {:.1}%",
            self.tracker_blocking.total_blocked,
            self.dns.queries_blocked,
            self.estimated_data_saved_mb(),
            self.privacy_protection_percentage(),
            if self.dns.cache_hits + self.dns.queries_blocked > 0 {
                (self.dns.cache_hits as f64 / (self.dns.cache_hits + self.dns.queries_blocked) as f64) * 100.0
            } else {
                0.0
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivacyLevel;

    #[tokio::test]
    async fn test_privacy_engine_creation() {
        let engine = CitadelPrivacyEngine::new().await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_privacy_engine_with_config() {
        let mut config = NetworkConfig::default();
        config.privacy_level = PrivacyLevel::Maximum;
        
        let engine = CitadelPrivacyEngine::with_config(config).await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_domain_blocking_check() {
        let engine = CitadelPrivacyEngine::new().await.unwrap();
        
        // Test known tracker domain
        let would_block = engine.would_block_domain("doubleclick.net").await;
        assert!(would_block);

        // Test regular domain
        let would_not_block = engine.would_block_domain("example.com").await;
        assert!(!would_not_block);
    }

    #[tokio::test]
    async fn test_privacy_stats() {
        let engine = CitadelPrivacyEngine::new().await.unwrap();
        let stats = engine.get_privacy_stats().await;
        
        // Should have some default stats
        assert!(stats.tracker_blocking.total_blocklist_entries > 0);
    }

    #[tokio::test]
    async fn test_cache_clearing() {
        let engine = CitadelPrivacyEngine::new().await.unwrap();
        
        // Should not panic
        engine.clear_all_caches();
    }

    #[tokio::test]
    async fn test_url_blocking_check() {
        let engine = CitadelPrivacyEngine::new().await.unwrap();
        
        // Test tracker URL
        let would_block = engine.would_block_url("https://doubleclick.net/track.js").await;
        assert!(would_block);

        // Test regular URL
        let would_not_block = engine.would_block_url("https://example.com/script.js").await;
        assert!(!would_not_block);
    }
}