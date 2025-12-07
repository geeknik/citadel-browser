//! Behavioral fingerprinting protection for Citadel Browser
//!
//! This module protects against behavioral fingerprinting by normalizing
//! user behavior patterns, timing information, and interaction signatures.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize, Deserializer, Serializer};
use std::sync::Arc;
use parking_lot::RwLock;
use log::{debug, info};

// Wrapper for Instant serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableInstant {
    secs: u64,
}

impl From<Instant> for SerializableInstant {
    fn from(instant: Instant) -> Self {
        Self {
            secs: instant.elapsed().as_secs(),
        }
    }
}

impl From<SerializableInstant> for Instant {
    fn from(wrapped: SerializableInstant) -> Self {
        Instant::now() - Duration::from_secs(wrapped.secs)
    }
}

/// Behavioral fingerprinting protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralProtectionConfig {
    /// Whether to normalize typing patterns
    pub normalize_typing: bool,
    /// Whether to normalize mouse movements
    pub normalize_mouse: bool,
    /// Whether to normalize scrolling behavior
    pub normalize_scrolling: bool,
    /// Whether to normalize timing information
    pub normalize_timing: bool,
    /// Whether to normalize request patterns
    pub normalize_requests: bool,
    /// Level of protection (0.0 to 1.0)
    pub protection_level: f32,
    /// Maximum delay for behavior normalization (milliseconds)
    pub max_delay_ms: u64,
    /// Whether to use consistent behavior across sessions
    pub consistent_across_sessions: bool,
}

impl Default for BehavioralProtectionConfig {
    fn default() -> Self {
        Self {
            normalize_typing: true,
            normalize_mouse: true,
            normalize_scrolling: true,
            normalize_timing: true,
            normalize_requests: true,
            protection_level: 0.7,
            max_delay_ms: 100,
            consistent_across_sessions: false,
        }
    }
}

/// Typing behavior metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingMetrics {
    /// Average typing speed (chars per minute)
    pub avg_speed: f32,
    /// Average pause duration (milliseconds)
    pub avg_pause: u64,
    /// Typing rhythm pattern
    pub rhythm_pattern: Vec<u32>,
    /// Common typing errors
    pub error_rate: f32,
}

/// Mouse behavior metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MouseMetrics {
    /// Average mouse speed (pixels per second)
    pub avg_speed: f32,
    /// Average movement smoothness
    pub smoothness: f32,
    /// Click patterns
    pub click_pattern: Vec<ClickEvent>,
    /// Idle periods
    pub idle_periods: Vec<Duration>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClickEvent {
    pub x: u32,
    pub y: u32,
    pub button: u8,
    pub duration: Duration,
    #[serde(skip)]
    pub timestamp: Instant,
}

impl<'de> Deserialize<'de> for ClickEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ClickEventHelper {
            x: u32,
            y: u32,
            button: u8,
            duration: Duration,
        }

        let helper = ClickEventHelper::deserialize(deserializer)?;
        Ok(ClickEvent {
            x: helper.x,
            y: helper.y,
            button: helper.button,
            duration: helper.duration,
            timestamp: Instant::now(),
        })
    }
}

impl Default for ClickEvent {
    fn default() -> Self {
        Self {
            x: 0,
            y: 0,
            button: 0,
            duration: Duration::default(),
            timestamp: Instant::now(),
        }
    }
}

/// Scrolling behavior metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrollMetrics {
    /// Average scroll speed (pixels per second)
    pub avg_speed: f32,
    /// Scroll acceleration pattern
    pub acceleration_pattern: Vec<f32>,
    /// Scroll bounce behavior
    pub has_bounce: bool,
}

/// Behavioral fingerprinting protection manager
#[derive(Debug)]
pub struct BehavioralProtection {
    config: BehavioralProtectionConfig,
    /// Session-specific random seed
    session_seed: u64,
    /// Typing behavior buffer
    typing_buffer: Arc<RwLock<VecDeque<TypingEvent>>>,
    /// Mouse behavior buffer
    mouse_buffer: Arc<RwLock<VecDeque<MouseEvent>>>,
    /// Scroll behavior buffer
    scroll_buffer: Arc<RwLock<VecDeque<ScrollEvent>>>,
    /// Request timing buffer
    request_buffer: Arc<RwLock<VecDeque<RequestEvent>>>,
    /// Behavior profile for the session
    behavior_profile: Arc<RwLock<BehaviorProfile>>,
}

#[derive(Debug, Clone)]
struct TypingEvent {
    timestamp: Instant,
    key_code: u16,
    duration: Duration,
}

#[derive(Debug, Clone)]
struct MouseEvent {
    timestamp: Instant,
    x: f64,
    y: f64,
    movement_x: f64,
    movement_y: f64,
}

#[derive(Debug, Clone)]
struct ScrollEvent {
    timestamp: Instant,
    delta_x: f64,
    delta_y: f64,
    position: f64,
}

#[derive(Debug, Clone)]
struct RequestEvent {
    timestamp: Instant,
    url: String,
    method: String,
    duration: Duration,
    size: usize,
}

#[derive(Debug, Clone, Default)]
struct BehaviorProfile {
    typing_base_speed: f32,
    typing_base_rhythm: Vec<u32>,
    mouse_base_speed: f32,
    mouse_base_smoothness: f32,
    scroll_base_speed: f32,
    request_base_interval: Duration,
}

impl BehavioralProtection {
    /// Create a new behavioral protection instance
    pub fn new(config: BehavioralProtectionConfig) -> Self {
        let session_seed = if config.consistent_across_sessions {
            // Use a fixed seed for consistency
            0xC5C5C5C5C5C5C5C5
        } else {
            // Generate a random seed for this session
            rand::thread_rng().gen()
        };

        let buffer_size = 100; // Keep last 100 events of each type

        Self {
            config,
            session_seed,
            typing_buffer: Arc::new(RwLock::new(VecDeque::with_capacity(buffer_size))),
            mouse_buffer: Arc::new(RwLock::new(VecDeque::with_capacity(buffer_size))),
            scroll_buffer: Arc::new(RwLock::new(VecDeque::with_capacity(buffer_size))),
            request_buffer: Arc::new(RwLock::new(VecDeque::with_capacity(buffer_size))),
            behavior_profile: Arc::new(RwLock::new(BehaviorProfile::default())),
        }
    }

    /// Record a typing event
    pub fn record_typing_event(&self, key_code: u16, duration: Duration) {
        let event = TypingEvent {
            timestamp: Instant::now(),
            key_code,
            duration,
        };

        let mut buffer = self.typing_buffer.write();
        if buffer.len() >= buffer.capacity() {
            buffer.pop_front();
        }
        buffer.push_back(event);
    }

    /// Record a mouse movement event
    pub fn record_mouse_event(&self, x: f64, y: f64, movement_x: f64, movement_y: f64) {
        let event = MouseEvent {
            timestamp: Instant::now(),
            x,
            y,
            movement_x,
            movement_y,
        };

        let mut buffer = self.mouse_buffer.write();
        if buffer.len() >= buffer.capacity() {
            buffer.pop_front();
        }
        buffer.push_back(event);
    }

    /// Record a scroll event
    pub fn record_scroll_event(&self, delta_x: f64, delta_y: f64, position: f64) {
        let event = ScrollEvent {
            timestamp: Instant::now(),
            delta_x,
            delta_y,
            position,
        };

        let mut buffer = self.scroll_buffer.write();
        if buffer.len() >= buffer.capacity() {
            buffer.pop_front();
        }
        buffer.push_back(event);
    }

    /// Record a network request event
    pub fn record_request_event(&self, url: &str, method: &str, duration: Duration, size: usize) {
        let event = RequestEvent {
            timestamp: Instant::now(),
            url: url.to_string(),
            method: method.to_string(),
            duration,
            size,
        };

        let mut buffer = self.request_buffer.write();
        if buffer.len() >= buffer.capacity() {
            buffer.pop_front();
        }
        buffer.push_back(event);
    }

    /// Get normalized typing delay
    pub fn get_typing_delay(&self, base_delay: Duration, domain: &str) -> Duration {
        if !self.config.normalize_typing {
            return base_delay;
        }

        let domain_seed = self.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(self.session_seed ^ domain_seed);

        let delay_ms = base_delay.as_millis() as u64;
        let noise_ms = (rng.gen_range(-1.0..=1.0) * self.config.protection_level * 50.0) as i64;
        let normalized_ms = (delay_ms as i64 + noise_ms).max(1).min(self.config.max_delay_ms as i64);

        Duration::from_millis(normalized_ms as u64)
    }

    /// Get normalized mouse movement delay
    pub fn get_mouse_delay(&self, domain: &str) -> Option<Duration> {
        if !self.config.normalize_mouse || self.config.protection_level < 0.5 {
            return None;
        }

        let domain_seed = self.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(self.session_seed ^ domain_seed);

        let delay_ms = rng.gen_range(0..=self.config.max_delay_ms / 4);
        Some(Duration::from_millis(delay_ms))
    }

    /// Get normalized scroll behavior
    pub fn normalize_scroll_speed(&self, base_speed: f64, domain: &str) -> f64 {
        if !self.config.normalize_scrolling {
            return base_speed;
        }

        let profile = self.behavior_profile.read();
        let domain_seed = self.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(self.session_seed ^ domain_seed);

        // Normalize towards the base speed with some variation
        let target_speed = if profile.scroll_base_speed > 0.0 {
            profile.scroll_base_speed as f64
        } else {
            base_speed
        };

        let noise_factor = self.config.protection_level * 0.3;
        let noise = rng.gen_range(-noise_factor..=noise_factor) as f64 * target_speed;
        (base_speed + noise).max(10.0).min(10000.0) // Reasonable bounds
    }

    /// Get normalized request timing
    pub fn normalize_request_timing(&self, base_timing: Duration, domain: &str) -> Duration {
        if !self.config.normalize_timing {
            return base_timing;
        }

        let domain_seed = self.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(self.session_seed ^ domain_seed);

        let base_ms = base_timing.as_millis() as u64;
        let noise_factor = self.config.protection_level * 0.1;
        let noise_ms = (rng.gen_range(-1.0f32..=1.0f32) * noise_factor * base_ms as f32) as i64;

        let normalized_ms = (base_ms as i64 + noise_ms).max(1);
        Duration::from_millis(normalized_ms as u64)
    }

    /// Generate normalized request patterns
    pub fn generate_request_pattern(&self, domain: &str, request_count: usize) -> Vec<Duration> {
        if !self.config.normalize_requests {
            return vec![Duration::from_millis(100); request_count];
        }

        let domain_seed = self.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(self.session_seed ^ domain_seed);

        let mut pattern = Vec::with_capacity(request_count);

        for i in 0..request_count {
            // Base delay with some variation
            let base_delay = 100 + (i as u64 * 50); // Increasing delay pattern
            let variation = (rng.gen_range(-1.0..=1.0) * self.config.protection_level * 30.0) as i64;
            let delay = (base_delay as i64 + variation).max(10).min(1000);

            pattern.push(Duration::from_millis(delay as u64));
        }

        pattern
    }

    /// Get typing metrics (sanitized)
    pub fn get_typing_metrics(&self, domain: &str) -> TypingMetrics {
        let buffer = self.typing_buffer.read();

        if buffer.len() < 2 {
            return TypingMetrics {
                avg_speed: 200.0, // Default typing speed
                avg_pause: 200,
                rhythm_pattern: vec![200, 150, 180, 120],
                error_rate: 0.05,
            };
        }

        let domain_seed = self.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(self.session_seed ^ domain_seed);

        // Calculate real metrics (simplified)
        let mut total_duration = Duration::ZERO;
        let mut pause_count = 0;
        let mut total_pause = Duration::ZERO;

        let mut prev_timestamp = buffer[0].timestamp;
        for event in buffer.iter().skip(1) {
            let pause = event.timestamp.duration_since(prev_timestamp);
            total_pause += pause;
            pause_count += 1;
            total_duration += event.duration;
            prev_timestamp = event.timestamp;
        }

        let avg_speed = if total_duration.as_millis() > 0 {
            (buffer.len() as f32 / total_duration.as_secs_f32()) * 60.0 // CPM
        } else {
            200.0
        };

        let avg_pause = if pause_count > 0 {
            (total_pause.as_millis() / pause_count as u128) as u64
        } else {
            200
        };

        // Generate normalized rhythm pattern
        let mut rhythm_pattern = Vec::new();
        for _ in 0..4 {
            rhythm_pattern.push(rng.gen_range(100..=300));
        }

        // Add noise to metrics
        let speed_noise = (rng.gen_range(-1.0..=1.0) * self.config.protection_level * 20.0) as f32;
        let pause_noise = (rng.gen_range(-1.0..=1.0) * self.config.protection_level * 50.0) as i64;

        TypingMetrics {
            avg_speed: (avg_speed + speed_noise).max(50.0).min(1000.0),
            avg_pause: ((avg_pause as i64 + pause_noise).max(50) as u64),
            rhythm_pattern,
            error_rate: rng.gen_range(0.01..=0.15),
        }
    }

    /// Get mouse metrics (sanitized)
    pub fn get_mouse_metrics(&self, domain: &str) -> MouseMetrics {
        let buffer = self.mouse_buffer.read();

        if buffer.len() < 2 {
            return MouseMetrics {
                avg_speed: 500.0,
                smoothness: 0.8,
                click_pattern: vec![],
                idle_periods: vec![Duration::from_millis(200)],
            };
        }

        let domain_seed = self.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(self.session_seed ^ domain_seed);

        // Calculate real metrics (simplified)
        let mut total_distance = 0.0f64;
        let mut total_time = Duration::ZERO;
        let mut smoothness_sum = 0.0f32;

        let mut prev_event = &buffer[0];
        for event in buffer.iter().skip(1) {
            let distance = ((event.x - prev_event.x).powi(2) + (event.y - prev_event.y).powi(2)).sqrt();
            total_distance += distance;
            total_time += event.timestamp.duration_since(prev_event.timestamp);

            // Calculate smoothness (simplified)
            let angle_change = ((event.movement_x * prev_event.movement_y - event.movement_y * prev_event.movement_x).atan2(
                event.movement_x * prev_event.movement_x + event.movement_y * prev_event.movement_y
            )).abs();
            smoothness_sum += (1.0 - angle_change.min(3.14159) / 3.14159) as f32;

            prev_event = event;
        }

        let avg_speed = if total_time.as_millis() > 0 {
            (total_distance / total_time.as_secs_f64()) * 1000.0 // pixels per second
        } else {
            500.0
        };

        let smoothness = if buffer.len() > 1 {
            smoothness_sum / (buffer.len() - 1) as f32
        } else {
            0.8
        };

        // Add noise
        let speed_noise = (rng.gen_range(-1.0..=1.0) * self.config.protection_level * 100.0) as f64;
        let smoothness_noise = (rng.gen_range(-1.0..=1.0) * self.config.protection_level * 0.2) as f32;

        MouseMetrics {
            avg_speed: ((avg_speed + speed_noise).max(50.0).min(5000.0) as f32),
            smoothness: (smoothness + smoothness_noise).max(0.0).min(1.0),
            click_pattern: vec![], // Would track clicks in real implementation
            idle_periods: vec![Duration::from_millis(rng.gen_range(100..=500))],
        }
    }

    /// Get scroll metrics (sanitized)
    pub fn get_scroll_metrics(&self, domain: &str) -> ScrollMetrics {
        let buffer = self.scroll_buffer.read();

        if buffer.len() < 2 {
            return ScrollMetrics {
                avg_speed: 1000.0,
                acceleration_pattern: vec![0.0, 0.5, -0.3, 0.1],
                has_bounce: false,
            };
        }

        let domain_seed = self.domain_seed(domain);
        let mut rng = ChaCha20Rng::seed_from_u64(self.session_seed ^ domain_seed);

        // Generate normalized metrics
        ScrollMetrics {
            avg_speed: rng.gen_range(500.0..=2000.0),
            acceleration_pattern: vec![
                rng.gen_range(-1.0..=1.0),
                rng.gen_range(-1.0..=1.0),
                rng.gen_range(-1.0..=1.0),
            ],
            has_bounce: rng.gen_bool(0.3),
        }
    }

    /// Update behavior profile based on collected data
    pub fn update_behavior_profile(&self) {
        if self.typing_buffer.read().len() >= 10 {
            // Update base metrics from collected data
            let mut profile = self.behavior_profile.write();

            // This is simplified - in practice would use more sophisticated analysis
            profile.typing_base_speed = 200.0;
            profile.typing_base_rhythm = vec![200, 150, 180, 120];
            profile.mouse_base_speed = 500.0;
            profile.mouse_base_smoothness = 0.8;
            profile.scroll_base_speed = 1000.0;
            profile.request_base_interval = Duration::from_millis(500);
        }
    }

    /// Generate domain-specific seed
    fn domain_seed(&self, domain: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        domain.hash(&mut hasher);
        hasher.finish()
    }

    /// Reset all behavior buffers
    pub fn reset_buffers(&self) {
        self.typing_buffer.write().clear();
        self.mouse_buffer.write().clear();
        self.scroll_buffer.write().clear();
        self.request_buffer.write().clear();
        info!("Behavior protection buffers reset");
    }

    /// Get current configuration
    pub fn config(&self) -> &BehavioralProtectionConfig {
        &self.config
    }

    /// Update configuration
    pub fn update_config(&mut self, config: BehavioralProtectionConfig) {
        self.config = config;
        self.reset_buffers();
        info!("Behavioral protection configuration updated");
    }
}

impl Clone for BehavioralProtection {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            session_seed: self.session_seed,
            typing_buffer: Arc::new(RwLock::new(self.typing_buffer.read().clone())),
            mouse_buffer: Arc::new(RwLock::new(self.mouse_buffer.read().clone())),
            scroll_buffer: Arc::new(RwLock::new(self.scroll_buffer.read().clone())),
            request_buffer: Arc::new(RwLock::new(self.request_buffer.read().clone())),
            behavior_profile: Arc::new(RwLock::new(self.behavior_profile.read().clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_typing_delay_normalization() {
        let config = BehavioralProtectionConfig::default();
        let protection = BehavioralProtection::new(config);

        let base_delay = Duration::from_millis(150);
        let delay1 = protection.get_typing_delay(base_delay, "example.com");
        let delay2 = protection.get_typing_delay(base_delay, "example.com");

        // Same domain should get consistent delay
        assert_eq!(delay1, delay2);

        // Delay should be within reasonable bounds
        assert!(delay1 <= Duration::from_millis(200));
        assert!(delay1 >= Duration::from_millis(50));
    }

    #[test]
    fn test_scroll_speed_normalization() {
        let config = BehavioralProtectionConfig::default();
        let protection = BehavioralProtection::new(config);

        let base_speed = 1500.0;
        let normalized = protection.normalize_scroll_speed(base_speed, "example.com");

        // Should be normalized but still reasonable
        assert!(normalized >= 10.0);
        assert!(normalized <= 10000.0);
    }

    #[test]
    fn test_request_pattern_generation() {
        let config = BehavioralProtectionConfig::default();
        let protection = BehavioralProtection::new(config);

        let pattern = protection.generate_request_pattern("example.com", 5);

        assert_eq!(pattern.len(), 5);

        // Pattern should have increasing base delays with some variation
        for (i, delay) in pattern.iter().enumerate() {
            assert!(*delay >= Duration::from_millis(10));
            assert!(*delay <= Duration::from_millis(1000));
        }
    }

    #[test]
    fn test_behavior_metrics() {
        let config = BehavioralProtectionConfig::default();
        let protection = BehavioralProtection::new(config);

        let typing_metrics = protection.get_typing_metrics("example.com");
        let mouse_metrics = protection.get_mouse_metrics("example.com");
        let scroll_metrics = protection.get_scroll_metrics("example.com");

        // Should return reasonable default metrics
        assert!(typing_metrics.avg_speed > 0.0);
        assert!(typing_metrics.avg_pause > 0);
        assert!(mouse_metrics.avg_speed > 0.0);
        assert!(mouse_metrics.smoothness >= 0.0 && mouse_metrics.smoothness <= 1.0);
        assert!(scroll_metrics.avg_speed > 0.0);
    }

    #[test]
    fn test_behavior_event_recording() {
        let config = BehavioralProtectionConfig::default();
        let protection = BehavioralProtection::new(config);

        // Record some events
        protection.record_typing_event(65, Duration::from_millis(100));
        protection.record_mouse_event(100.0, 200.0, 5.0, 10.0);
        protection.record_scroll_event(0.0, 50.0, 500.0);
        protection.record_request_event("https://example.com", "GET", Duration::from_millis(200), 1024);

        // Verify buffers have data
        assert!(!protection.typing_buffer.read().is_empty());
        assert!(!protection.mouse_buffer.read().is_empty());
        assert!(!protection.scroll_buffer.read().is_empty());
        assert!(!protection.request_buffer.read().is_empty());
    }

    #[test]
    fn test_domain_consistency() {
        let config = BehavioralProtectionConfig {
            consistent_across_sessions: true,
            ..Default::default()
        };
        let protection1 = BehavioralProtection::new(config.clone());
        let protection2 = BehavioralProtection::new(config);

        let delay1 = protection1.get_typing_delay(Duration::from_millis(150), "example.com");
        let delay2 = protection2.get_typing_delay(Duration::from_millis(150), "example.com");

        // Should be identical when consistent across sessions is enabled
        assert_eq!(delay1, delay2);
    }
}