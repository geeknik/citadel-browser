//! Defines the Security Context and its builder for Citadel.
//!
//! The Security Context holds the active security policies (e.g., blocked elements,
//! allowed schemes) applied during parsing and resource loading.

use crate::error::SecurityError;
use std::collections::{HashSet, HashMap};
use std::sync::RwLock;
use std::net::IpAddr;
use url::Url;

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

/// Content Security Policy (CSP) directive types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CspDirective {
    DefaultSrc,
    ScriptSrc,
    StyleSrc,
    ImgSrc,
    ConnectSrc,
    FontSrc,
    ObjectSrc,
    MediaSrc,
    FrameSrc,
    ChildSrc,
    WorkerSrc,
    ManifestSrc,
    BaseUri,
    FormAction,
    FrameAncestors,
    NavigateTo,
    ReportUri,
    ReportTo,
    RequireTrustedTypesFor,
    TrustedTypes,
    UpgradeInsecureRequests,
    BlockAllMixedContent,
}

/// CSP source expression types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CspSource {
    None,
    Self_,
    UnsafeInline,
    UnsafeEval,
    UnsafeHashes,
    StrictDynamic,
    ReportSample,
    Host(String),
    Scheme(String),
    Nonce(String),
    Hash(String, String), // algorithm, hash
}

/// Content Security Policy configuration
#[derive(Debug, Clone)]
pub struct ContentSecurityPolicy {
    /// CSP directives and their allowed sources
    pub directives: HashMap<CspDirective, Vec<CspSource>>,
    /// Whether to report CSP violations
    pub report_only: bool,
    /// Report URI for violations
    pub report_uri: Option<String>,
    /// Upgrade insecure requests
    pub upgrade_insecure_requests: bool,
    /// Block all mixed content
    pub block_all_mixed_content: bool,
}

impl Default for ContentSecurityPolicy {
    fn default() -> Self {
        let mut directives = HashMap::new();
        
        // Secure defaults - deny most sources by default
        directives.insert(CspDirective::DefaultSrc, vec![CspSource::Self_]);
        directives.insert(CspDirective::ScriptSrc, vec![CspSource::Self_]);
        directives.insert(CspDirective::StyleSrc, vec![CspSource::Self_]);
        directives.insert(CspDirective::ImgSrc, vec![CspSource::Self_, CspSource::Scheme("data:".to_string())]);
        directives.insert(CspDirective::ConnectSrc, vec![CspSource::Self_]);
        directives.insert(CspDirective::FontSrc, vec![CspSource::Self_]);
        directives.insert(CspDirective::ObjectSrc, vec![CspSource::None]);
        directives.insert(CspDirective::MediaSrc, vec![CspSource::Self_]);
        directives.insert(CspDirective::FrameSrc, vec![CspSource::None]);
        directives.insert(CspDirective::BaseUri, vec![CspSource::Self_]);
        directives.insert(CspDirective::FormAction, vec![CspSource::Self_]);
        
        Self {
            directives,
            report_only: false,
            report_uri: None,
            upgrade_insecure_requests: true,
            block_all_mixed_content: true,
        }
    }
}

/// Security violation types for logging and reporting
#[derive(Debug, Clone)]
pub enum SecurityViolation {
    CspViolation {
        directive: CspDirective,
        blocked_uri: String,
        violated_directive: String,
        source_file: Option<String>,
        line_number: Option<u32>,
        column_number: Option<u32>,
    },
    BlockedElement {
        element_name: String,
        source_url: String,
    },
    BlockedAttribute {
        attribute_name: String,
        element_name: String,
        source_url: String,
    },
    SuspiciousActivity {
        activity_type: String,
        details: String,
        source_url: String,
    },
    MemoryExhaustion {
        resource_type: String,
        limit_exceeded: usize,
        attempted_size: usize,
    },
    NetworkSecurity {
        violation_type: String,
        target_host: String,
        blocked_reason: String,
    },
}

/// Security metrics for monitoring and analysis
#[derive(Debug, Clone, Default)]
pub struct SecurityMetrics {
    pub csp_violations: u64,
    pub blocked_scripts: u64,
    pub blocked_elements: u64,
    pub blocked_attributes: u64,
    pub suspicious_activities: u64,
    pub memory_exhaustion_attempts: u64,
    pub network_security_blocks: u64,
    pub total_security_events: u64,
}

/// Advanced security configuration for enterprise use
#[derive(Debug, Clone)]
pub struct AdvancedSecurityConfig {
    /// Enable strict transport security
    pub strict_transport_security: bool,
    /// Maximum age for HSTS
    pub hsts_max_age: u64,
    /// Include subdomains in HSTS
    pub hsts_include_subdomains: bool,
    /// Enable HSTS preload
    pub hsts_preload: bool,
    /// Referrer policy
    pub referrer_policy: String,
    /// X-Frame-Options
    pub frame_options: String,
    /// X-Content-Type-Options
    pub content_type_options: String,
    /// X-XSS-Protection
    pub xss_protection: String,
    /// Permissions Policy
    pub permissions_policy: HashMap<String, Vec<String>>,
    /// Cross-Origin Embedder Policy
    pub cross_origin_embedder_policy: String,
    /// Cross-Origin Opener Policy
    pub cross_origin_opener_policy: String,
    /// Cross-Origin Resource Policy
    pub cross_origin_resource_policy: String,
}

impl Default for AdvancedSecurityConfig {
    fn default() -> Self {
        let mut permissions_policy = HashMap::new();
        permissions_policy.insert("camera".to_string(), vec![]);
        permissions_policy.insert("microphone".to_string(), vec![]);
        permissions_policy.insert("geolocation".to_string(), vec![]);
        permissions_policy.insert("payment".to_string(), vec![]);
        permissions_policy.insert("usb".to_string(), vec![]);
        permissions_policy.insert("bluetooth".to_string(), vec![]);
        
        Self {
            strict_transport_security: true,
            hsts_max_age: 31536000, // 1 year
            hsts_include_subdomains: true,
            hsts_preload: true,
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            frame_options: "DENY".to_string(),
            content_type_options: "nosniff".to_string(),
            xss_protection: "1; mode=block".to_string(),
            permissions_policy,
            cross_origin_embedder_policy: "require-corp".to_string(),
            cross_origin_opener_policy: "same-origin".to_string(),
            cross_origin_resource_policy: "same-origin".to_string(),
        }
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FingerprintProtectionLevel {
    /// No fingerprint protection
    None,
    /// Basic fingerprint protection (minimal performance impact)
    Basic,
    /// Medium fingerprint protection (some performance impact)
    #[default]
    Medium,
    /// Maximum fingerprint protection (may impact functionality)
    Maximum,
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
    /// Content Security Policy configuration
    csp: RwLock<ContentSecurityPolicy>,
    /// Advanced security configuration
    advanced_config: AdvancedSecurityConfig,
    /// Security metrics for monitoring
    metrics: RwLock<SecurityMetrics>,
    /// Security violation history
    violations: RwLock<Vec<SecurityViolation>>,
    /// Allowed URL schemes
    allowed_schemes: RwLock<HashSet<UrlScheme>>,
    /// Blocked IP addresses
    blocked_ips: RwLock<HashSet<IpAddr>>,
    /// Trusted domains for security policy relaxation
    trusted_domains: RwLock<HashSet<String>>,
    /// Enable strict mode (enhanced security at cost of compatibility)
    strict_mode: bool,
    /// Maximum memory usage per context (bytes)
    max_memory_usage: usize,
    /// Maximum resource loading time (milliseconds)
    max_resource_timeout: u64,
    /// Enable detailed security logging
    detailed_logging: bool,
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
            csp: RwLock::new(self.csp.read().unwrap().clone()),
            advanced_config: self.advanced_config.clone(),
            metrics: RwLock::new(self.metrics.read().unwrap().clone()),
            violations: RwLock::new(self.violations.read().unwrap().clone()),
            allowed_schemes: RwLock::new(self.allowed_schemes.read().unwrap().clone()),
            blocked_ips: RwLock::new(self.blocked_ips.read().unwrap().clone()),
            trusted_domains: RwLock::new(self.trusted_domains.read().unwrap().clone()),
            strict_mode: self.strict_mode,
            max_memory_usage: self.max_memory_usage,
            max_resource_timeout: self.max_resource_timeout,
            detailed_logging: self.detailed_logging,
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
        blocked_attributes.insert("onmouseout".to_string());
        blocked_attributes.insert("onmousedown".to_string());
        blocked_attributes.insert("onmouseup".to_string());
        blocked_attributes.insert("onkeydown".to_string());
        blocked_attributes.insert("onkeyup".to_string());
        blocked_attributes.insert("onkeypress".to_string());
        blocked_attributes.insert("onfocus".to_string());
        blocked_attributes.insert("onblur".to_string());
        blocked_attributes.insert("onsubmit".to_string());
        blocked_attributes.insert("onchange".to_string());

        let mut allowed_schemes = HashSet::new();
        allowed_schemes.insert(UrlScheme::Https);
        allowed_schemes.insert(UrlScheme::Data);
        allowed_schemes.insert(UrlScheme::Blob);

        Self {
            blocked_elements: RwLock::new(blocked_elements),
            blocked_attributes: RwLock::new(blocked_attributes),
            fingerprint_protection: FingerprintProtection::default(),
            allow_scripts: RwLock::new(false),
            allow_external_resources: RwLock::new(true),
            max_nesting_depth: max_depth,
            csp: RwLock::new(ContentSecurityPolicy::default()),
            advanced_config: AdvancedSecurityConfig::default(),
            metrics: RwLock::new(SecurityMetrics::default()),
            violations: RwLock::new(Vec::new()),
            allowed_schemes: RwLock::new(allowed_schemes),
            blocked_ips: RwLock::new(HashSet::new()),
            trusted_domains: RwLock::new(HashSet::new()),
            strict_mode: true,
            max_memory_usage: 256 * 1024 * 1024, // 256MB default
            max_resource_timeout: 30000, // 30 seconds
            detailed_logging: true,
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
    
    /// Get the current CSP configuration
    pub fn get_csp(&self) -> ContentSecurityPolicy {
        self.csp.read().unwrap().clone()
    }
    
    /// Set the CSP configuration
    pub fn set_csp(&mut self, csp: ContentSecurityPolicy) {
        *self.csp.write().unwrap() = csp;
    }
    
    /// Parse and apply CSP header
    pub fn apply_csp_header(&mut self, csp_header: &str) -> Result<(), SecurityError> {
        let csp = self.parse_csp_header(csp_header)?;
        self.set_csp(csp);
        Ok(())
    }
    
    /// Parse CSP header string into CSP configuration
    fn parse_csp_header(&self, header: &str) -> Result<ContentSecurityPolicy, SecurityError> {
        let mut csp = ContentSecurityPolicy::default();
        
        for directive_str in header.split(';') {
            let directive_str = directive_str.trim();
            if directive_str.is_empty() {
                continue;
            }
            
            let parts: Vec<&str> = directive_str.splitn(2, ' ').collect();
            if parts.is_empty() {
                continue;
            }
            
            let directive_name = parts[0].trim().to_lowercase();
            let directive = match directive_name.as_str() {
                "default-src" => CspDirective::DefaultSrc,
                "script-src" => CspDirective::ScriptSrc,
                "style-src" => CspDirective::StyleSrc,
                "img-src" => CspDirective::ImgSrc,
                "connect-src" => CspDirective::ConnectSrc,
                "font-src" => CspDirective::FontSrc,
                "object-src" => CspDirective::ObjectSrc,
                "media-src" => CspDirective::MediaSrc,
                "frame-src" => CspDirective::FrameSrc,
                "child-src" => CspDirective::ChildSrc,
                "worker-src" => CspDirective::WorkerSrc,
                "manifest-src" => CspDirective::ManifestSrc,
                "base-uri" => CspDirective::BaseUri,
                "form-action" => CspDirective::FormAction,
                "frame-ancestors" => CspDirective::FrameAncestors,
                "navigate-to" => CspDirective::NavigateTo,
                "report-uri" => CspDirective::ReportUri,
                "report-to" => CspDirective::ReportTo,
                "upgrade-insecure-requests" => {
                    csp.upgrade_insecure_requests = true;
                    continue;
                }
                "block-all-mixed-content" => {
                    csp.block_all_mixed_content = true;
                    continue;
                }
                _ => continue, // Skip unknown directives
            };
            
            if parts.len() > 1 {
                let sources_str = parts[1].trim();
                let sources = self.parse_csp_sources(sources_str);
                csp.directives.insert(directive, sources);
            }
        }
        
        Ok(csp)
    }
    
    /// Parse CSP source list
    fn parse_csp_sources(&self, sources_str: &str) -> Vec<CspSource> {
        let mut sources = Vec::new();
        
        for source in sources_str.split_whitespace() {
            let source = source.trim().to_lowercase();
            
            let csp_source = match source.as_str() {
                "'none'" => CspSource::None,
                "'self'" => CspSource::Self_,
                "'unsafe-inline'" => CspSource::UnsafeInline,
                "'unsafe-eval'" => CspSource::UnsafeEval,
                "'unsafe-hashes'" => CspSource::UnsafeHashes,
                "'strict-dynamic'" => CspSource::StrictDynamic,
                "'report-sample'" => CspSource::ReportSample,
                s if s.starts_with("'nonce-") && s.ends_with("'") => {
                    let nonce = s[7..s.len()-1].to_string();
                    CspSource::Nonce(nonce)
                }
                s if s.starts_with("'sha") && s.contains("-") && s.ends_with("'") => {
                    let parts: Vec<&str> = s[1..s.len()-1].splitn(2, '-').collect();
                    if parts.len() == 2 {
                        CspSource::Hash(parts[0].to_string(), parts[1].to_string())
                    } else {
                        continue;
                    }
                }
                s if s.contains("://") => CspSource::Host(s.to_string()),
                s if s.ends_with(":") => CspSource::Scheme(s.to_string()),
                s => CspSource::Host(s.to_string()),
            };
            
            sources.push(csp_source);
        }
        
        sources
    }
    
    /// Validate URL against CSP directive
    pub fn validate_csp_url(&self, url: &str, directive: CspDirective) -> Result<(), SecurityError> {
        let csp = self.csp.read().unwrap();
        
        // Get sources for the directive, fall back to default-src if not found
        let sources = csp.directives.get(&directive)
            .or_else(|| csp.directives.get(&CspDirective::DefaultSrc))
            .ok_or_else(|| SecurityError::CspViolation { 
                directive: format!("{:?}", directive) 
            })?;
        
        // Check if URL is allowed by any source
        for source in sources {
            if self.url_matches_csp_source(url, source)? {
                return Ok(());
            }
        }
        
        // Record violation
        let violation = SecurityViolation::CspViolation {
            directive,
            blocked_uri: url.to_string(),
            violated_directive: format!("{:?}", directive),
            source_file: None,
            line_number: None,
            column_number: None,
        };
        
        self.record_violation(violation);
        
        Err(SecurityError::CspViolation { 
            directive: format!("{:?} violated by {}", directive, url) 
        })
    }
    
    /// Check if URL matches CSP source
    fn url_matches_csp_source(&self, url: &str, source: &CspSource) -> Result<bool, SecurityError> {
        match source {
            CspSource::None => Ok(false),
            CspSource::Self_ => {
                // For self, we need to check if URL is same-origin
                // This is a simplified check - in practice, we'd need current page origin
                Ok(true) // Placeholder
            }
            CspSource::UnsafeInline => Ok(false), // Should not allow URLs
            CspSource::UnsafeEval => Ok(false),   // Should not allow URLs
            CspSource::Host(host) => {
                if let Ok(parsed_url) = Url::parse(url) {
                    if let Some(url_host) = parsed_url.host_str() {
                        Ok(self.host_matches_pattern(url_host, host))
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            CspSource::Scheme(scheme) => {
                Ok(url.starts_with(scheme))
            }
            _ => Ok(false), // Other sources don't apply to URLs
        }
    }
    
    /// Check if host matches CSP host pattern
    fn host_matches_pattern(&self, host: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        
        if let Some(domain) = pattern.strip_prefix("*.") {
            return host == domain || host.ends_with(&format!(".{}", domain));
        }
        
        host == pattern
    }
    
    /// Record a security violation
    pub fn record_violation(&self, violation: SecurityViolation) {
        let mut violations = self.violations.write().unwrap();
        let mut metrics = self.metrics.write().unwrap();
        
        match &violation {
            SecurityViolation::CspViolation { .. } => metrics.csp_violations += 1,
            SecurityViolation::BlockedElement { .. } => metrics.blocked_elements += 1,
            SecurityViolation::BlockedAttribute { .. } => metrics.blocked_attributes += 1,
            SecurityViolation::SuspiciousActivity { .. } => metrics.suspicious_activities += 1,
            SecurityViolation::MemoryExhaustion { .. } => metrics.memory_exhaustion_attempts += 1,
            SecurityViolation::NetworkSecurity { .. } => metrics.network_security_blocks += 1,
        }
        
        metrics.total_security_events += 1;
        violations.push(violation);
        
        // Keep only recent violations (last 1000)
        let violations_len = violations.len();
        if violations_len > 1000 {
            violations.drain(0..violations_len - 1000);
        }
    }
    
    /// Get security metrics
    pub fn get_metrics(&self) -> SecurityMetrics {
        self.metrics.read().unwrap().clone()
    }
    
    /// Get recent security violations
    pub fn get_recent_violations(&self, limit: usize) -> Vec<SecurityViolation> {
        let violations = self.violations.read().unwrap();
        let start_idx = if violations.len() > limit {
            violations.len() - limit
        } else {
            0
        };
        violations[start_idx..].to_vec()
    }
    
    /// Clear security metrics and violations
    pub fn clear_security_data(&mut self) {
        *self.metrics.write().unwrap() = SecurityMetrics::default();
        self.violations.write().unwrap().clear();
    }
    
    /// Add trusted domain
    pub fn add_trusted_domain(&mut self, domain: &str) {
        self.trusted_domains.write().unwrap().insert(domain.to_lowercase());
    }
    
    /// Remove trusted domain
    pub fn remove_trusted_domain(&mut self, domain: &str) {
        self.trusted_domains.write().unwrap().remove(&domain.to_lowercase());
    }
    
    /// Check if domain is trusted
    pub fn is_domain_trusted(&self, domain: &str) -> bool {
        self.trusted_domains.read().unwrap().contains(&domain.to_lowercase())
    }
    
    /// Block IP address
    pub fn block_ip(&mut self, ip: IpAddr) {
        self.blocked_ips.write().unwrap().insert(ip);
    }
    
    /// Check if IP is blocked
    pub fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.read().unwrap().contains(ip)
    }
    
    /// Validate URL scheme
    pub fn validate_url_scheme(&self, url: &str) -> Result<(), SecurityError> {
        if let Ok(parsed_url) = Url::parse(url) {
            let scheme = parsed_url.scheme();
            let url_scheme = UrlScheme::parse(scheme)?;
            
            let allowed_schemes = self.allowed_schemes.read().unwrap();
            if allowed_schemes.contains(&url_scheme) {
                Ok(())
            } else {
                Err(SecurityError::InvalidScheme { 
                    scheme: scheme.to_string() 
                })
            }
        } else {
            Err(SecurityError::InvalidScheme { 
                scheme: "invalid-url".to_string() 
            })
        }
    }
    
    /// Check resource size against memory limits
    pub fn check_memory_usage(&self, requested_size: usize) -> Result<(), SecurityError> {
        if requested_size > self.max_memory_usage {
            let violation = SecurityViolation::MemoryExhaustion {
                resource_type: "general".to_string(),
                limit_exceeded: self.max_memory_usage,
                attempted_size: requested_size,
            };
            
            self.record_violation(violation);
            
            return Err(SecurityError::BlockedResource {
                resource_type: "memory".to_string(),
                identifier: format!("{} bytes", requested_size),
            });
        }
        
        Ok(())
    }
    
    /// Enable or disable strict mode
    pub fn set_strict_mode(&mut self, strict: bool) {
        self.strict_mode = strict;
    }
    
    /// Check if strict mode is enabled
    pub fn is_strict_mode(&self) -> bool {
        self.strict_mode
    }
    
    /// Get advanced security configuration
    pub fn get_advanced_config(&self) -> &AdvancedSecurityConfig {
        &self.advanced_config
    }
    
    /// Set advanced security configuration
    pub fn set_advanced_config(&mut self, config: AdvancedSecurityConfig) {
        self.advanced_config = config;
    }
    
    /// Generate security headers for HTTP response
    pub fn generate_security_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        let config = &self.advanced_config;
        
        // Strict Transport Security
        if config.strict_transport_security {
            let mut hsts = format!("max-age={}", config.hsts_max_age);
            if config.hsts_include_subdomains {
                hsts.push_str("; includeSubDomains");
            }
            if config.hsts_preload {
                hsts.push_str("; preload");
            }
            headers.insert("Strict-Transport-Security".to_string(), hsts);
        }
        
        // Other security headers
        headers.insert("Referrer-Policy".to_string(), config.referrer_policy.clone());
        headers.insert("X-Frame-Options".to_string(), config.frame_options.clone());
        headers.insert("X-Content-Type-Options".to_string(), config.content_type_options.clone());
        headers.insert("X-XSS-Protection".to_string(), config.xss_protection.clone());
        headers.insert("Cross-Origin-Embedder-Policy".to_string(), config.cross_origin_embedder_policy.clone());
        headers.insert("Cross-Origin-Opener-Policy".to_string(), config.cross_origin_opener_policy.clone());
        headers.insert("Cross-Origin-Resource-Policy".to_string(), config.cross_origin_resource_policy.clone());
        
        // Permissions Policy
        if !config.permissions_policy.is_empty() {
            let permissions: Vec<String> = config.permissions_policy.iter()
                .map(|(feature, allowlist)| {
                    if allowlist.is_empty() {
                        format!("{}=()", feature)
                    } else {
                        format!("{}=({})", feature, allowlist.join(" "))
                    }
                })
                .collect();
            headers.insert("Permissions-Policy".to_string(), permissions.join(", "));
        }
        
        // Content Security Policy
        let csp = self.csp.read().unwrap();
        let csp_header = self.generate_csp_header(&csp);
        if !csp_header.is_empty() {
            let header_name = if csp.report_only {
                "Content-Security-Policy-Report-Only"
            } else {
                "Content-Security-Policy"
            };
            headers.insert(header_name.to_string(), csp_header);
        }
        
        headers
    }
    
    /// Generate CSP header string from configuration
    fn generate_csp_header(&self, csp: &ContentSecurityPolicy) -> String {
        let mut directives = Vec::new();
        
        for (directive, sources) in &csp.directives {
            let directive_name = match directive {
                CspDirective::DefaultSrc => "default-src",
                CspDirective::ScriptSrc => "script-src",
                CspDirective::StyleSrc => "style-src",
                CspDirective::ImgSrc => "img-src",
                CspDirective::ConnectSrc => "connect-src",
                CspDirective::FontSrc => "font-src",
                CspDirective::ObjectSrc => "object-src",
                CspDirective::MediaSrc => "media-src",
                CspDirective::FrameSrc => "frame-src",
                CspDirective::ChildSrc => "child-src",
                CspDirective::WorkerSrc => "worker-src",
                CspDirective::ManifestSrc => "manifest-src",
                CspDirective::BaseUri => "base-uri",
                CspDirective::FormAction => "form-action",
                CspDirective::FrameAncestors => "frame-ancestors",
                CspDirective::NavigateTo => "navigate-to",
                CspDirective::ReportUri => "report-uri",
                CspDirective::ReportTo => "report-to",
                _ => continue,
            };
            
            let source_strings: Vec<String> = sources.iter().map(|source| {
                match source {
                    CspSource::None => "'none'".to_string(),
                    CspSource::Self_ => "'self'".to_string(),
                    CspSource::UnsafeInline => "'unsafe-inline'".to_string(),
                    CspSource::UnsafeEval => "'unsafe-eval'".to_string(),
                    CspSource::UnsafeHashes => "'unsafe-hashes'".to_string(),
                    CspSource::StrictDynamic => "'strict-dynamic'".to_string(),
                    CspSource::ReportSample => "'report-sample'".to_string(),
                    CspSource::Host(host) => host.clone(),
                    CspSource::Scheme(scheme) => scheme.clone(),
                    CspSource::Nonce(nonce) => format!("'nonce-{}'", nonce),
                    CspSource::Hash(alg, hash) => format!("'{}-{}'", alg, hash),
                }
            }).collect();
            
            if !source_strings.is_empty() {
                directives.push(format!("{} {}", directive_name, source_strings.join(" ")));
            }
        }
        
        if csp.upgrade_insecure_requests {
            directives.push("upgrade-insecure-requests".to_string());
        }
        
        if csp.block_all_mixed_content {
            directives.push("block-all-mixed-content".to_string());
        }
        
        if let Some(report_uri) = &csp.report_uri {
            directives.push(format!("report-uri {}", report_uri));
        }
        
        directives.join("; ")
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
            csp: RwLock::new(ContentSecurityPolicy::default()),
            advanced_config: AdvancedSecurityConfig::default(),
            metrics: RwLock::new(SecurityMetrics::default()),
            violations: RwLock::new(Vec::new()),
            allowed_schemes: RwLock::new(final_allowed_schemes),
            blocked_ips: RwLock::new(HashSet::new()),
            trusted_domains: RwLock::new(HashSet::new()),
            strict_mode: true,
            max_memory_usage: 256 * 1024 * 1024, // 256MB default
            max_resource_timeout: 30000, // 30 seconds
            detailed_logging: true,
        })
    }
} 
