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
    AdvancedSecurityConfig, ContentSecurityPolicy, CspDirective, CspSource, FingerprintProtection,
    FingerprintProtectionLevel, SecurityContext, SecurityContextBuilder, SecurityMetrics,
    SecurityViolation, UrlScheme,
};
pub use error::{SecurityError, SecurityResult, SecuritySeverity};
pub use memory::{
    AttackPattern, MemoryProtectionBuilder, MemoryProtectionConfig, MemoryProtectionError,
    MemoryProtectionResult, MemoryProtectionSystem, ResourcePoolConfig, ResourcePoolStats,
    ResourceType,
};
pub use privacy::{
    create_privacy_channel, create_privacy_channel_with_capacity, PrivacyEvent,
    PrivacyEventReceiver, PrivacyEventSender, PrivacyStats, TrackerCategory,
};
