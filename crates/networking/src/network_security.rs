use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use serde::{Serialize, Deserialize};

/// Network security configuration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkSecurityConfig {
    /// Enforce HTTPS for all connections
    pub enforce_https: bool,
    /// Enable certificate pinning
    pub certificate_pinning: bool,
    /// Enable malicious site detection
    pub malicious_site_detection: bool,
    /// Enable privacy headers
    pub privacy_headers: bool,
    /// Strict certificate validation
    pub strict_cert_validation: bool,
    /// Enable HSTS preload
    pub hsts_preload: bool,
    /// Block tracking domains
    pub block_tracking: bool,
    /// Enable DNS-over-HTTPS
    pub dns_over_https: bool,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Maximum redirects
    pub max_redirects: usize,
}

impl Default for NetworkSecurityConfig {
    fn default() -> Self {
        Self {
            enforce_https: true,
            certificate_pinning: true,
            malicious_site_detection: true,
            privacy_headers: true,
            strict_cert_validation: true,
            hsts_preload: true,
            block_tracking: true,
            dns_over_https: true,
            connection_timeout: 30,
            max_redirects: 5,
        }
    }
}

/// Certificate pinning entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificatePin {
    /// Domain name
    pub domain: String,
    /// SHA-256 hash of the expected certificate public key
    pub pin_hash: String,
    /// Backup pin hashes
    pub backup_pins: Vec<String>,
    /// When this pin expires
    pub expires_at: Option<SystemTime>,
}

/// Security reputation score for domains
#[derive(Debug, Clone)]
pub struct DomainReputation {
    /// Domain name
    pub domain: String,
    /// Reputation score (-1.0 to 1.0)
    pub score: f32,
    /// Last updated
    pub last_updated: SystemTime,
    /// Number of violations
    pub violations: u32,
    /// Category of the domain
    pub category: DomainCategory,
}

/// Domain categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DomainCategory {
    Safe,
    Suspicious,
    Malicious,
    Tracking,
    SocialMedia,
    News,
    Shopping,
    Financial,
    Adult,
    Unknown,
}

/// HSTS (HTTP Strict Transport Security) entry
#[derive(Debug, Clone)]
pub struct HstsEntry {
    /// Domain name
    pub domain: String,
    /// Include subdomains
    pub include_subdomains: bool,
    /// When this entry expires
    pub expires_at: SystemTime,
    /// Maximum age in seconds
    pub max_age: u64,
    /// Preload flag
    pub preload: bool,
}

/// Security audit log entry
#[derive(Debug, Clone)]
pub struct SecurityAuditEntry {
    /// Timestamp
    pub timestamp: SystemTime,
    /// Event type
    pub event_type: SecurityEventType,
    /// Domain or URL involved
    pub target: String,
    /// Action taken
    pub action: SecurityAction,
    /// Reason
    pub reason: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Security event types
#[derive(Debug, Clone)]
pub enum SecurityEventType {
    /// Certificate validation failed
    CertificateError,
    /// HSTS violation
    HstsViolation,
    /// Blocked malicious domain
    MaliciousDomain,
    /// Blocked tracking domain
    TrackingDomain,
    /// Certificate pinning failure
    PinningFailure,
    /// HTTP request when HTTPS enforced
    HttpsViolation,
    /// Too many redirects
    RedirectLoop,
    /// Suspicious content detected
    SuspiciousContent,
}

/// Security actions taken
#[derive(Debug, Clone)]
pub enum SecurityAction {
    /// Request was blocked
    Blocked,
    /// Request was allowed with warnings
    AllowedWithWarning,
    /// Request was redirected to HTTPS
    Redirected,
    /// Request was modified (headers stripped)
    Modified,
}

/// Network security manager
#[derive(Debug)]
pub struct NetworkSecurityManager {
    /// Security configuration
    config: NetworkSecurityConfig,
    /// Certificate pins
    certificate_pins: HashMap<String, CertificatePin>,
    /// Domain reputations
    domain_reputations: HashMap<String, DomainReputation>,
    /// HSTS entries
    hsts_entries: HashMap<String, HstsEntry>,
    /// Audit log
    audit_log: Vec<SecurityAuditEntry>,
    /// Blocked domains cache
    blocked_domains: HashMap<String, SystemTime>,
    /// Tracking domains list
    tracking_domains: Vec<String>,
}

impl NetworkSecurityManager {
    /// Create new security manager
    pub fn new(config: NetworkSecurityConfig) -> Self {
        Self {
            config,
            certificate_pins: HashMap::new(),
            domain_reputations: HashMap::new(),
            hsts_entries: HashMap::new(),
            audit_log: Vec::new(),
            blocked_domains: HashMap::new(),
            tracking_domains: Self::default_tracking_domains(),
        }
    }

    /// Get default list of tracking domains
    fn default_tracking_domains() -> Vec<String> {
        vec![
            "google-analytics.com".to_string(),
            "googletagmanager.com".to_string(),
            "facebook.com".to_string(),
            "doubleclick.net".to_string(),
            "googleadservices.com".to_string(),
            "googlesyndication.com".to_string(),
            "googleads.g.doubleclick.net".to_string(),
        ]
    }

    /// Validate URL before making request
    pub fn validate_url(&mut self, url: &str) -> Result<(), crate::error::NetworkError> {
        let parsed_url = url::Url::parse(url).map_err(crate::error::NetworkError::UrlError)?;

        // Check HTTPS enforcement
        if self.config.enforce_https && parsed_url.scheme() != "https" {
            self.log_security_event(
                SecurityEventType::HttpsViolation,
                url.to_string(),
                SecurityAction::Blocked,
                "HTTP not allowed when HTTPS enforcement is enabled".to_string(),
            );
            return Err(crate::error::NetworkError::SecurityViolation(
                "HTTPS enforcement violation: only HTTPS connections are allowed".to_string(),
            ));
        }

        let domain = parsed_url.host_str().unwrap_or("unknown");

        // Check HSTS
        if self.is_hsts_domain(domain) && parsed_url.scheme() != "https" {
            self.log_security_event(
                SecurityEventType::HstsViolation,
                url.to_string(),
                SecurityAction::Redirected,
                format!("HSTS violation for domain: {}", domain),
            );
            return Err(crate::error::NetworkError::SecurityViolation(
                "HSTS violation: domain requires HTTPS".to_string(),
            ));
        }

        // Check malicious domains
        if self.is_malicious_domain(domain) {
            self.log_security_event(
                SecurityEventType::MaliciousDomain,
                url.to_string(),
                SecurityAction::Blocked,
                format!("Malicious domain detected: {}", domain),
            );
            return Err(crate::error::NetworkError::SecurityViolation(
                "Access to malicious domain blocked".to_string(),
            ));
        }

        // Check tracking domains
        if self.config.block_tracking && self.is_tracking_domain(domain) {
            self.log_security_event(
                SecurityEventType::TrackingDomain,
                url.to_string(),
                SecurityAction::Blocked,
                format!("Tracking domain blocked: {}", domain),
            );
            return Err(crate::error::NetworkError::SecurityViolation(
                "Tracking domain blocked".to_string(),
            ));
        }

        // Check domain reputation
        if self.is_low_reputation_domain(domain) {
            self.log_security_event(
                SecurityEventType::SuspiciousContent,
                url.to_string(),
                SecurityAction::AllowedWithWarning,
                format!("Low reputation domain: {}", domain),
            );
        }

        Ok(())
    }

    /// Check if domain has HSTS policy
    pub fn is_hsts_domain(&self, domain: &str) -> bool {
        // Check exact match
        if let Some(entry) = self.hsts_entries.get(domain) {
            return entry.expires_at > SystemTime::now();
        }

        // Check subdomain matches
        for (entry_domain, entry) in &self.hsts_entries {
            if entry.include_subdomains && domain.ends_with(entry_domain) {
                return entry.expires_at > SystemTime::now();
            }
        }

        false
    }

    /// Add HSTS entry
    pub fn add_hsts_entry(&mut self, domain: String, max_age: u64, include_subdomains: bool, preload: bool) {
        let expires_at = SystemTime::now() + Duration::from_secs(max_age);

        let entry = HstsEntry {
            domain: domain.clone(),
            include_subdomains,
            expires_at,
            max_age,
            preload,
        };

        self.hsts_entries.insert(domain, entry);
    }

    /// Check if domain is malicious
    fn is_malicious_domain(&self, domain: &str) -> bool {
        if let Some(reputation) = self.domain_reputations.get(domain) {
            matches!(reputation.category, DomainCategory::Malicious) && reputation.score < -0.5
        } else {
            false
        }
    }

    /// Check if domain is a tracking domain
    fn is_tracking_domain(&self, domain: &str) -> bool {
        self.tracking_domains.iter().any(|tracking| domain.contains(tracking))
    }

    /// Check if domain has low reputation
    fn is_low_reputation_domain(&self, domain: &str) -> bool {
        if let Some(reputation) = self.domain_reputations.get(domain) {
            reputation.score < 0.3
        } else {
            false
        }
    }

    /// Generate privacy headers for request
    pub fn generate_privacy_headers(&self, _domain: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();

        if self.config.privacy_headers {
            headers.insert("DNT".to_string(), "1".to_string());
            headers.insert("Sec-GPC".to_string(), "1".to_string());
            headers.insert("Accept-Language".to_string(), "en-US,en;q=0.9".to_string());
        }

        headers
    }

    /// Check certificate pinning
    pub fn check_certificate_pin(&mut self, domain: &str, cert_hash: &str) -> Result<(), crate::error::NetworkError> {
        if let Some(pin) = self.certificate_pins.get(domain) {
            if pin.expires_at.map_or(false, |exp| exp <= SystemTime::now()) {
                return Err(crate::error::NetworkError::SecurityViolation(
                    "Certificate pin expired".to_string(),
                ));
            }

            if cert_hash != pin.pin_hash && !pin.backup_pins.contains(&cert_hash.to_string()) {
                self.log_security_event(
                    SecurityEventType::PinningFailure,
                    domain.to_string(),
                    SecurityAction::Blocked,
                    "Certificate pin validation failed".to_string(),
                );
                return Err(crate::error::NetworkError::SecurityViolation(
                    "Certificate pinning failed".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Calculate domain security score
    pub fn calculate_domain_score(&mut self, domain: &str) -> f32 {
        let mut score: f32 = 0.7; // Neutral score

        // Check if in HSTS preload list
        if self.config.hsts_preload && self.is_hsts_domain(domain) {
            score += 0.2;
        }

        // Check reputation
        if let Some(reputation) = self.domain_reputations.get(domain) {
            score += reputation.score * 0.3;
        }

        // Penalize tracking domains
        if self.is_tracking_domain(domain) {
            score -= 0.3;
        }

        // Penalize malicious domains
        if self.is_malicious_domain(domain) {
            score -= 0.8;
        }

        score.max(0.0).min(1.0)
    }

    /// Log security event
    fn log_security_event(&mut self, event_type: SecurityEventType, target: String, action: SecurityAction, reason: String) {
        let entry = SecurityAuditEntry {
            timestamp: SystemTime::now(),
            event_type,
            target,
            action,
            reason,
            metadata: HashMap::new(),
        };

        self.audit_log.push(entry);

        // Keep audit log size manageable
        if self.audit_log.len() > 10000 {
            let start = self.audit_log.len() - 1000;
            self.audit_log.drain(0..start);
        }
    }

    /// Get recent security events
    pub fn get_recent_events(&self, limit: usize) -> &[SecurityAuditEntry] {
        let start = if self.audit_log.len() > limit {
            self.audit_log.len() - limit
        } else {
            0
        };

        &self.audit_log[start..]
    }

    /// Get security statistics
    pub fn get_security_stats(&self) -> SecurityStats {
        let mut blocked = 0;
        let mut warnings = 0;
        let mut redirects = 0;

        for entry in &self.audit_log {
            match entry.action {
                SecurityAction::Blocked => blocked += 1,
                SecurityAction::AllowedWithWarning => warnings += 1,
                SecurityAction::Redirected => redirects += 1,
                _ => {}
            }
        }

        SecurityStats {
            total_events: self.audit_log.len(),
            blocked_requests: blocked,
            warnings,
            redirects,
            hsts_entries: self.hsts_entries.len(),
            certificate_pins: self.certificate_pins.len(),
        }
    }

    /// Clear expired HSTS entries
    pub fn cleanup_expired_entries(&mut self) {
        let now = SystemTime::now();
        self.hsts_entries.retain(|_, entry| entry.expires_at > now);

        self.certificate_pins.retain(|_, pin| {
            pin.expires_at.map_or(true, |exp| exp > now)
        });
    }
}

/// Security statistics
#[derive(Debug, Clone)]
pub struct SecurityStats {
    pub total_events: usize,
    pub blocked_requests: usize,
    pub warnings: usize,
    pub redirects: usize,
    pub hsts_entries: usize,
    pub certificate_pins: usize,
}