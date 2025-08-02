//! Citadel Security Crate
//!
//! This crate handles security policies, context management, and enforcement mechanisms
//! crucial for maintaining user privacy and safety.

pub mod context;
pub mod error;
// pub mod policy; // Potential future module

pub use context::{
    SecurityContext, SecurityContextBuilder, UrlScheme, 
    ContentSecurityPolicy, CspDirective, CspSource,
    FingerprintProtection, FingerprintProtectionLevel,
    SecurityViolation, SecurityMetrics, AdvancedSecurityConfig
};
pub use error::{SecurityError, SecuritySeverity, SecurityResult}; 