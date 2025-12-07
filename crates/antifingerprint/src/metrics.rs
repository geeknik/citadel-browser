//! Metrics for anti-fingerprinting protections
//!
//! This module provides tools for tracking and analyzing the effectiveness
//! of anti-fingerprinting measures and detecting fingerprinting attempts.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use parking_lot::RwLock;

/// Types of fingerprinting protection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectionType {
    /// Canvas fingerprinting protection
    Canvas,
    /// WebGL fingerprinting protection
    WebGL,
    /// Audio fingerprinting protection
    Audio,
    /// Navigator/platform fingerprinting protection
    Navigator,
    /// Font fingerprinting protection
    Font,
    /// Screen/viewport fingerprinting protection
    Screen,
    /// Timezone/locale fingerprinting protection
    Locale,
    /// Hardware fingerprinting protection
    Hardware,
    /// Behavioral fingerprinting protection
    Behavioral,
}

impl ProtectionType {
    /// Get a string representation of this protection type
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtectionType::Canvas => "canvas",
            ProtectionType::WebGL => "webgl",
            ProtectionType::Audio => "audio",
            ProtectionType::Navigator => "navigator",
            ProtectionType::Font => "font",
            ProtectionType::Screen => "screen",
            ProtectionType::Locale => "locale",
            ProtectionType::Hardware => "hardware",
            ProtectionType::Behavioral => "behavioral",
        }
    }
}

/// Metrics for anti-fingerprinting protections
#[derive(Debug)]
pub struct FingerprintMetrics {
    /// Number of fingerprinting attempts blocked
    pub blocked_attempts: AtomicUsize,
    /// Number of fingerprinting attempts normalized
    pub normalized_attempts: AtomicUsize,
    /// Protection type counters
    protection_counts: RwLock<HashMap<ProtectionType, AtomicUsize>>,
    /// Domain-specific fingerprinting attempt records
    domain_stats: RwLock<HashMap<String, DomainStats>>,
    /// Time of first fingerprinting attempt
    first_attempt: RwLock<Option<Instant>>,
}

impl Default for FingerprintMetrics {
    fn default() -> Self {
        let mut protection_counts = HashMap::new();
        
        // Initialize counters for all protection types
        for protection_type in [
            ProtectionType::Canvas,
            ProtectionType::WebGL,
            ProtectionType::Audio,
            ProtectionType::Navigator,
            ProtectionType::Font,
            ProtectionType::Screen,
            ProtectionType::Locale,
        ] {
            protection_counts.insert(protection_type, AtomicUsize::new(0));
        }
        
        Self {
            blocked_attempts: AtomicUsize::new(0),
            normalized_attempts: AtomicUsize::new(0),
            protection_counts: RwLock::new(protection_counts),
            domain_stats: RwLock::new(HashMap::new()),
            first_attempt: RwLock::new(None),
        }
    }
}

impl FingerprintMetrics {
    /// Create new fingerprint metrics
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    
    /// Record a blocked fingerprinting attempt
    pub fn record_blocked(&self, protection_type: ProtectionType, domain: &str) {
        self.blocked_attempts.fetch_add(1, Ordering::Relaxed);
        self.record_protection(protection_type, domain);
    }
    
    /// Record a normalized fingerprinting attempt (not blocked, but modified)
    pub fn record_normalized(&self, protection_type: ProtectionType, domain: &str) {
        self.normalized_attempts.fetch_add(1, Ordering::Relaxed);
        self.record_protection(protection_type, domain);
    }
    
    /// Record a protection activation
    fn record_protection(&self, protection_type: ProtectionType, domain: &str) {
        // Update first attempt timestamp if not set
        {
            let mut first_attempt = self.first_attempt.write();
            if first_attempt.is_none() {
                *first_attempt = Some(Instant::now());
            }
        }
        
        // Update protection type counter
        if let Some(counter) = self.protection_counts.read().get(&protection_type) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        
        // Update domain stats
        let mut domain_stats = self.domain_stats.write();
        let stats = domain_stats.entry(domain.to_string())
            .or_insert_with(DomainStats::new);
        
        stats.record_attempt(protection_type);
    }
    
    /// Get the total number of attempts (blocked + normalized)
    pub fn total_attempts(&self) -> usize {
        self.blocked_attempts.load(Ordering::Relaxed) + 
        self.normalized_attempts.load(Ordering::Relaxed)
    }
    
    /// Get the count for a specific protection type
    pub fn protection_count(&self, protection_type: ProtectionType) -> usize {
        self.protection_counts
            .read()
            .get(&protection_type)
            .map(|counter| counter.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
    
    /// Get statistics for a specific domain
    pub fn domain_statistics(&self, domain: &str) -> Option<DomainStats> {
        self.domain_stats.read().get(domain).cloned()
    }
    
    /// Get domains ordered by most fingerprinting attempts
    pub fn top_fingerprinting_domains(&self, limit: usize) -> Vec<(String, usize)> {
        let domain_stats = self.domain_stats.read();
        
        let mut domains: Vec<(String, usize)> = domain_stats
            .iter()
            .map(|(domain, stats)| (domain.clone(), stats.total_attempts))
            .collect();
        
        // Sort by number of attempts (descending)
        domains.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Take top N
        domains.into_iter().take(limit).collect()
    }
    
    /// Get time elapsed since first fingerprinting attempt
    pub fn time_since_first_attempt(&self) -> Option<Duration> {
        self.first_attempt.read().map(|instant| instant.elapsed())
    }
    
    /// Reset all metrics
    pub fn reset(&self) {
        self.blocked_attempts.store(0, Ordering::Relaxed);
        self.normalized_attempts.store(0, Ordering::Relaxed);
        
        for counter in self.protection_counts.read().values() {
            counter.store(0, Ordering::Relaxed);
        }
        
        *self.domain_stats.write() = HashMap::new();
        *self.first_attempt.write() = None;
    }
}

/// Statistics for a specific domain
#[derive(Debug, Clone)]
pub struct DomainStats {
    /// Total fingerprinting attempts from this domain
    pub total_attempts: usize,
    /// When this domain first attempted fingerprinting
    pub first_attempt: Instant,
    /// Most recent fingerprinting attempt
    pub last_attempt: Instant,
    /// Count of attempts by protection type
    pub protection_counts: HashMap<ProtectionType, usize>,
}

impl DomainStats {
    /// Create new domain statistics
    fn new() -> Self {
        let now = Instant::now();
        
        Self {
            total_attempts: 0,
            first_attempt: now,
            last_attempt: now,
            protection_counts: HashMap::new(),
        }
    }
    
    /// Record a fingerprinting attempt
    fn record_attempt(&mut self, protection_type: ProtectionType) {
        self.total_attempts += 1;
        self.last_attempt = Instant::now();
        
        *self.protection_counts.entry(protection_type).or_insert(0) += 1;
    }
    
    /// Get the count for a specific protection type
    pub fn protection_count(&self, protection_type: ProtectionType) -> usize {
        *self.protection_counts.get(&protection_type).unwrap_or(&0)
    }
    
    /// Get the time elapsed since the first attempt
    pub fn duration_since_first(&self) -> Duration {
        self.last_attempt.duration_since(self.first_attempt)
    }
    
    /// Get the most frequently used fingerprinting technique
    pub fn most_common_technique(&self) -> Option<(ProtectionType, usize)> {
        self.protection_counts
            .iter()
            .max_by_key(|(_, &count)| count)
            .map(|(&ptype, &count)| (ptype, count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    
    #[test]
    fn test_metrics_recording() {
        let metrics = FingerprintMetrics::new();
        
        // Record some events
        metrics.record_blocked(ProtectionType::Canvas, "fingerprint.com");
        metrics.record_normalized(ProtectionType::WebGL, "fingerprint.com");
        metrics.record_normalized(ProtectionType::Audio, "analytics.com");
        
        // Check totals
        assert_eq!(metrics.total_attempts(), 3);
        assert_eq!(metrics.blocked_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.normalized_attempts.load(Ordering::Relaxed), 2);
        
        // Check protection counts
        assert_eq!(metrics.protection_count(ProtectionType::Canvas), 1);
        assert_eq!(metrics.protection_count(ProtectionType::WebGL), 1);
        assert_eq!(metrics.protection_count(ProtectionType::Audio), 1);
        assert_eq!(metrics.protection_count(ProtectionType::Navigator), 0);
        
        // Check domain stats
        let fp_stats = metrics.domain_statistics("fingerprint.com").unwrap();
        assert_eq!(fp_stats.total_attempts, 2);
        assert_eq!(fp_stats.protection_count(ProtectionType::Canvas), 1);
        assert_eq!(fp_stats.protection_count(ProtectionType::WebGL), 1);
        
        let analytics_stats = metrics.domain_statistics("analytics.com").unwrap();
        assert_eq!(analytics_stats.total_attempts, 1);
        assert_eq!(analytics_stats.protection_count(ProtectionType::Audio), 1);
    }
    
    #[test]
    fn test_top_domains() {
        let metrics = FingerprintMetrics::new();
        
        // Record more attempts for fingerprint.com
        metrics.record_blocked(ProtectionType::Canvas, "fingerprint.com");
        metrics.record_normalized(ProtectionType::WebGL, "fingerprint.com");
        metrics.record_normalized(ProtectionType::Audio, "fingerprint.com");
        
        // Record fewer for analytics.com
        metrics.record_blocked(ProtectionType::Canvas, "analytics.com");
        
        // Record one for example.com
        metrics.record_normalized(ProtectionType::Navigator, "example.com");
        
        // Get top domains
        let top = metrics.top_fingerprinting_domains(10);
        
        // First should be fingerprint.com with 3 attempts
        assert_eq!(top[0].0, "fingerprint.com");
        assert_eq!(top[0].1, 3);
        
        // Second and third could be either analytics.com or example.com with 1 attempt each
        // Since HashMap iteration order is not guaranteed
        assert_eq!(top[1].1, 1);
        assert_eq!(top[2].1, 1);
        
        // Make sure both domains are in the results
        assert!(top[1].0 == "analytics.com" || top[1].0 == "example.com");
        assert!(top[2].0 == "analytics.com" || top[2].0 == "example.com");
        
        // Make sure they're different
        assert_ne!(top[1].0, top[2].0);
        assert_eq!(top[2].1, 1);
    }
    
    #[test]
    fn test_domain_stats() {
        let metrics = FingerprintMetrics::new();
        
        // Record multiple technique types
        metrics.record_blocked(ProtectionType::Canvas, "fingerprint.com");
        metrics.record_normalized(ProtectionType::Canvas, "fingerprint.com");
        metrics.record_normalized(ProtectionType::WebGL, "fingerprint.com");
        
        let stats = metrics.domain_statistics("fingerprint.com").unwrap();
        
        // Most common should be Canvas
        let (most_common, count) = stats.most_common_technique().unwrap();
        assert_eq!(most_common, ProtectionType::Canvas);
        assert_eq!(count, 2);
        
        // Duration should be measurable
        assert!(stats.duration_since_first().as_nanos() > 0);
    }
    
    #[test]
    fn test_metrics_reset() {
        let metrics = FingerprintMetrics::new();
        
        // Record some events
        metrics.record_blocked(ProtectionType::Canvas, "fingerprint.com");
        metrics.record_normalized(ProtectionType::WebGL, "fingerprint.com");
        
        // Verify we have data
        assert_eq!(metrics.total_attempts(), 2);
        assert!(metrics.domain_statistics("fingerprint.com").is_some());
        
        // Reset metrics
        metrics.reset();
        
        // Verify everything is reset
        assert_eq!(metrics.total_attempts(), 0);
        assert_eq!(metrics.protection_count(ProtectionType::Canvas), 0);
        assert!(metrics.domain_statistics("fingerprint.com").is_none());
        assert!(metrics.time_since_first_attempt().is_none());
    }
    
    #[test]
    fn test_thread_safety() {
        let metrics = FingerprintMetrics::new();
        let metrics_clone = metrics.clone();
        
        // Spawn a thread to record metrics
        let handle = thread::spawn(move || {
            for _ in 0..100 {
                metrics_clone.record_blocked(ProtectionType::Canvas, "thread.com");
            }
        });
        
        // Record in main thread too
        for _ in 0..100 {
            metrics.record_normalized(ProtectionType::WebGL, "main.com");
        }
        
        // Wait for thread to finish
        handle.join().unwrap();
        
        // Verify counts
        assert_eq!(metrics.total_attempts(), 200);
        assert_eq!(metrics.blocked_attempts.load(Ordering::Relaxed), 100);
        assert_eq!(metrics.normalized_attempts.load(Ordering::Relaxed), 100);
        
        // Verify domain stats
        let thread_stats = metrics.domain_statistics("thread.com").unwrap();
        assert_eq!(thread_stats.total_attempts, 100);
        
        let main_stats = metrics.domain_statistics("main.com").unwrap();
        assert_eq!(main_stats.total_attempts, 100);
    }
} 