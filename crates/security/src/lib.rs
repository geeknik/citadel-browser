//! Citadel Security Crate
//!
//! This crate handles security policies, context management, and enforcement mechanisms
//! crucial for maintaining user privacy and safety.

pub mod context;
pub mod error;
pub mod memory;
pub mod privacy;
// pub mod policy; // Potential future module

pub use context::{
    SecurityContext, SecurityContextBuilder, UrlScheme, 
    ContentSecurityPolicy, CspDirective, CspSource,
    FingerprintProtection, FingerprintProtectionLevel,
    SecurityViolation, SecurityMetrics, AdvancedSecurityConfig
};
pub use error::{SecurityError, SecuritySeverity, SecurityResult};
pub use privacy::{
    PrivacyEvent, PrivacyEventSender, PrivacyEventReceiver, PrivacyStats,
    TrackerCategory, create_privacy_channel, create_privacy_channel_with_capacity,
};
pub use memory::{
    MemoryProtectionSystem, MemoryProtectionBuilder, MemoryProtectionConfig,
    ResourceType, ResourcePoolConfig, MemoryProtectionError, MemoryProtectionResult,
    AttackPattern, ResourcePoolStats
}; 