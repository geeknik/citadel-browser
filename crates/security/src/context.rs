//! Defines the Security Context and its builder for Citadel.
//!
//! The Security Context holds the active security policies (e.g., blocked elements,
//! allowed schemes) applied during parsing and resource loading.

use crate::error::SecurityError;
use std::collections::HashSet;
use std::sync::RwLock;

/// Represents known and allowed URL schemes.
/// Using an enum provides type safety over raw strings.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum UrlScheme {
    Http,
    Https,
    Data,
    Blob,
    // File, // Consider if/how to support file scheme securely
    // Ftp,  // Likely discouraged due to security risks
    Custom(String), // For extensibility, though use with caution
}

impl UrlScheme {
    /// Attempts to parse a string into a known UrlScheme.
    pub fn parse(s: &str) -> Result<Self, SecurityError> {
        match s.to_lowercase().as_str() {
            "http" => Ok(UrlScheme::Http),
            "https" => Ok(UrlScheme::Https),
            "data" => Ok(UrlScheme::Data),
            "blob" => Ok(UrlScheme::Blob),
            // Add other known schemes here
            custom => {
                // Potentially validate custom schemes further
                Ok(UrlScheme::Custom(custom.to_string()))
            }
        }
    }
}

/// Enum defining the levels of fingerprint protection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintProtectionLevel {
    /// No fingerprint protection
    None,
    /// Basic fingerprint protection (minimal performance impact)
    Basic,
    /// Medium fingerprint protection (some performance impact)
    Medium,
    /// Maximum fingerprint protection (may impact functionality)
    Maximum,
}

impl Default for FingerprintProtectionLevel {
    fn default() -> Self {
        Self::Medium
    }
}

/// Configuration for fingerprint protection
#[derive(Debug, Clone)]
pub struct FingerprintProtection {
    /// The overall level of protection
    pub level: FingerprintProtectionLevel,
    /// Whether to add noise to canvas operations
    pub canvas_noise: bool,
    /// Whether to standardize navigator properties
    pub normalize_navigator: bool,
    /// Whether to spoof WebGL information
    pub spoof_webgl: bool,
    /// Whether to normalize audio context fingerprinting
    pub audio_noise: bool,
    /// Whether to normalize font fingerprinting
    pub normalize_fonts: bool,
    /// Whether to normalize screen and viewport information
    pub normalize_screen: bool,
}

impl Default for FingerprintProtection {
    fn default() -> Self {
        Self {
            level: FingerprintProtectionLevel::default(),
            canvas_noise: true,
            normalize_navigator: true,
            spoof_webgl: true,
            audio_noise: true,
            normalize_fonts: true,
            normalize_screen: true,
        }
    }
}

impl FingerprintProtection {
    /// Create a new fingerprint protection configuration with the specified level
    pub fn new(level: FingerprintProtectionLevel) -> Self {
        match level {
            FingerprintProtectionLevel::None => Self {
                level,
                canvas_noise: false,
                normalize_navigator: false,
                spoof_webgl: false,
                audio_noise: false,
                normalize_fonts: false,
                normalize_screen: false,
            },
            FingerprintProtectionLevel::Basic => Self {
                level,
                canvas_noise: true,
                normalize_navigator: true,
                spoof_webgl: false,
                audio_noise: false,
                normalize_fonts: true,
                normalize_screen: true,
            },
            FingerprintProtectionLevel::Medium => Self::default(),
            FingerprintProtectionLevel::Maximum => Self {
                level,
                canvas_noise: true,
                normalize_navigator: true,
                spoof_webgl: true,
                audio_noise: true,
                normalize_fonts: true,
                normalize_screen: true,
            },
        }
    }
}

/// Security context for enforcing content security policies
#[derive(Debug)]
pub struct SecurityContext {
    /// Set of blocked HTML elements
    blocked_elements: RwLock<HashSet<String>>,
    /// Set of blocked HTML attributes
    blocked_attributes: RwLock<HashSet<String>>,
    /// Fingerprint protection configuration
    fingerprint_protection: FingerprintProtection,
    /// Whether scripts are allowed
    allow_scripts: RwLock<bool>,
    /// Whether external resources are allowed
    allow_external_resources: RwLock<bool>,
    /// Maximum nesting depth for resource loading
    max_nesting_depth: usize,
}

impl Clone for SecurityContext {
    fn clone(&self) -> Self {
        Self {
            blocked_elements: RwLock::new(self.blocked_elements.read().unwrap().clone()),
            blocked_attributes: RwLock::new(self.blocked_attributes.read().unwrap().clone()),
            fingerprint_protection: self.fingerprint_protection.clone(),
            allow_scripts: RwLock::new(*self.allow_scripts.read().unwrap()),
            allow_external_resources: RwLock::new(*self.allow_external_resources.read().unwrap()),
            max_nesting_depth: self.max_nesting_depth,
        }
    }
}

impl SecurityContext {
    /// Create a new security context with specified maximum nesting depth
    pub fn new(max_depth: usize) -> Self {
        let mut blocked_elements = HashSet::new();
        blocked_elements.insert("script".to_string());
        blocked_elements.insert("iframe".to_string());
        blocked_elements.insert("object".to_string());
        blocked_elements.insert("embed".to_string());

        let mut blocked_attributes = HashSet::new();
        blocked_attributes.insert("onload".to_string());
        blocked_attributes.insert("onerror".to_string());
        blocked_attributes.insert("onclick".to_string());
        blocked_attributes.insert("onmouseover".to_string());

        Self {
            blocked_elements: RwLock::new(blocked_elements),
            blocked_attributes: RwLock::new(blocked_attributes),
            fingerprint_protection: FingerprintProtection::default(),
            allow_scripts: RwLock::new(false),
            allow_external_resources: RwLock::new(true),
            max_nesting_depth: max_depth,
        }
    }
    
    /// Create a new security context with default nesting depth
    pub fn new_default() -> Self {
        Self::new(10)
    }

    /// Check if an element is blocked
    pub fn is_element_blocked(&self, element_name: &str) -> bool {
        self.blocked_elements
            .read()
            .unwrap()
            .contains(&element_name.to_lowercase())
    }

    /// Check if an element is allowed (not blocked)
    pub fn is_element_allowed(&self, element_name: &str) -> bool {
        !self.is_element_blocked(element_name)
    }

    /// Check if an attribute is allowed
    pub fn is_attribute_allowed(&self, attribute_name: &str) -> bool {
        !self.blocked_attributes
            .read()
            .unwrap()
            .contains(&attribute_name.to_lowercase())
    }

    /// Block an element
    pub fn block_element(&mut self, element_name: &str) {
        self.blocked_elements
            .write()
            .unwrap()
            .insert(element_name.to_lowercase());
    }

    /// Allow an element
    pub fn allow_element(&mut self, element_name: &str) {
        self.blocked_elements
            .write()
            .unwrap()
            .remove(&element_name.to_lowercase());
    }

    /// Block an attribute
    pub fn block_attribute(&mut self, attribute_name: &str) {
        self.blocked_attributes
            .write()
            .unwrap()
            .insert(attribute_name.to_lowercase());
    }

    /// Allow an attribute
    pub fn allow_attribute(&mut self, attribute_name: &str) {
        self.blocked_attributes
            .write()
            .unwrap()
            .remove(&attribute_name.to_lowercase());
    }

    /// Get the current fingerprint protection configuration
    pub fn fingerprint_protection(&self) -> &FingerprintProtection {
        &self.fingerprint_protection
    }
    
    /// Set the fingerprint protection level
    pub fn set_fingerprint_protection_level(&mut self, level: FingerprintProtectionLevel) {
        self.fingerprint_protection = FingerprintProtection::new(level);
    }
    
    /// Customize fingerprint protection settings
    pub fn customize_fingerprint_protection(&mut self, config: FingerprintProtection) {
        self.fingerprint_protection = config;
    }
    
    /// Check if scripts are allowed
    pub fn allows_scripts(&self) -> bool {
        *self.allow_scripts.read().unwrap()
    }
    
    /// Enable script execution
    pub fn enable_scripts(&mut self) {
        *self.allow_scripts.write().unwrap() = true;
    }
    
    /// Disable script execution
    pub fn disable_scripts(&mut self) {
        *self.allow_scripts.write().unwrap() = false;
    }
    
    /// Check if external resources are allowed
    pub fn allows_external_resources(&self) -> bool {
        *self.allow_external_resources.read().unwrap()
    }
    
    /// Enable external resource loading
    pub fn enable_external_resources(&mut self) {
        *self.allow_external_resources.write().unwrap() = true;
    }
    
    /// Disable external resource loading
    pub fn disable_external_resources(&mut self) {
        *self.allow_external_resources.write().unwrap() = false;
    }
    
    /// Get the maximum nesting depth
    pub fn max_nesting_depth(&self) -> usize {
        self.max_nesting_depth
    }
    
    /// Set the maximum nesting depth
    pub fn set_max_nesting_depth(&mut self, depth: usize) {
        self.max_nesting_depth = depth;
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::new_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_blocked_elements() {
        let context = SecurityContext::new(10);
        assert!(context.is_element_blocked("script"));
        assert!(context.is_element_blocked("iframe"));
        assert!(!context.is_element_blocked("div"));
    }

    #[test]
    fn test_block_and_allow_element() {
        let mut context = SecurityContext::new(10);
        assert!(!context.is_element_blocked("div"));
        
        context.block_element("div");
        assert!(context.is_element_blocked("div"));
        
        context.allow_element("div");
        assert!(!context.is_element_blocked("div"));
    }

    #[test]
    fn test_attribute_blocking() {
        let mut context = SecurityContext::new(10);
        assert!(!context.is_attribute_allowed("onclick"));
        assert!(context.is_attribute_allowed("class"));
        
        context.block_attribute("class");
        assert!(!context.is_attribute_allowed("class"));
        
        context.allow_attribute("class");
        assert!(context.is_attribute_allowed("class"));
    }
}

/// Builder for creating SecurityContext instances.
#[derive(Default)]
pub struct SecurityContextBuilder {
    blocked_elements: HashSet<String>,
    allowed_schemes: HashSet<UrlScheme>,
    enforce_https: Option<bool>, // Use Option to distinguish between unset and false
    fingerprint_protection: Option<FingerprintProtection>,
}

impl SecurityContextBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds elements to the blocklist. Input is converted to lowercase.
    pub fn block_elements<I, S>(mut self, elements: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.blocked_elements.extend(elements.into_iter().map(|s| s.as_ref().to_lowercase()));
        self
    }

    /// Adds allowed URL schemes. Input strings are parsed into UrlScheme enums.
    /// Invalid schemes will cause an error during build().
    pub fn allow_schemes<I, S>(mut self, schemes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        // Store as strings for now, parse and validate in build()
        for s in schemes {
            match UrlScheme::parse(s.as_ref()) {
                Ok(scheme) => { self.allowed_schemes.insert(scheme); },
                Err(_) => { /* How to handle parse errors here? Log? Panic? Collect? For now, ignore */ }
            }
        }
        self
    }

    /// Sets whether to enforce HTTPS for all connections.
    pub fn enforce_https(mut self, enforce: bool) -> Self {
        self.enforce_https = Some(enforce);
        self
    }

    /// Set the fingerprint protection level
    pub fn with_fingerprint_protection(mut self, level: FingerprintProtectionLevel) -> Self {
        self.fingerprint_protection = Some(FingerprintProtection::new(level));
        self
    }
    
    /// Customize fingerprint protection settings
    pub fn with_custom_fingerprint_protection(mut self, config: FingerprintProtection) -> Self {
        self.fingerprint_protection = Some(config);
        self
    }

    /// Constructs the final SecurityContext.
    /// Performs validation on the configured rules.
    pub fn build(self) -> Result<SecurityContext, SecurityError> {
        // Set defaults if options were not specified
        let final_enforce_https = self.enforce_https.unwrap_or(true); // Default to enforcing HTTPS

        let mut final_allowed_schemes = self.allowed_schemes;
        if final_enforce_https {
            // If enforcing HTTPS, ensure only HTTPS is effectively allowed, clearing others might be too strict.
            // Let's ensure HTTPS is present if enforced.
            final_allowed_schemes.insert(UrlScheme::Https);
        } else {
            // If not enforcing HTTPS, ensure common safe schemes are allowed by default if none specified
            if final_allowed_schemes.is_empty() {
                final_allowed_schemes.insert(UrlScheme::Https);
                final_allowed_schemes.insert(UrlScheme::Http); // Allow HTTP if HTTPS is not enforced
                final_allowed_schemes.insert(UrlScheme::Data);
                final_allowed_schemes.insert(UrlScheme::Blob);
            }
        }

        // Add more validation logic here if needed.
        // Example: Ensure http is not allowed if enforce_https is true.
        if final_enforce_https && final_allowed_schemes.contains(&UrlScheme::Http) {
            return Err(SecurityError::InvalidConfiguration(
                "HTTP scheme cannot be allowed when HTTPS is enforced".to_string()
            ));
        }

        Ok(SecurityContext {
            blocked_elements: RwLock::new(self.blocked_elements),
            blocked_attributes: RwLock::new(HashSet::new()),
            fingerprint_protection: self.fingerprint_protection.unwrap_or_default(),
            allow_scripts: RwLock::new(false),
            allow_external_resources: RwLock::new(true),
            max_nesting_depth: 10, // Default nesting depth
        })
    }
} 