//! Privacy Event Protocol for Citadel Browser
//!
//! Defines the event types emitted by various crates when privacy-relevant
//! actions occur (tracker blocking, fingerprint neutralization, DNS queries, etc.).
//! Events flow through a bounded mpsc channel to the browser UI for live display.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Privacy events emitted by the browser engine during page loads.
///
/// Each variant represents a specific privacy action taken by the engine.
/// Events are sent through a bounded channel to avoid blocking the rendering pipeline.
#[derive(Debug, Clone)]
pub enum PrivacyEvent {
    /// A tracker request was blocked by the networking layer.
    TrackerBlocked {
        /// The URL that was blocked
        url: String,
        /// The filter rule that matched
        rule: String,
        /// Category of tracker (advertising, analytics, social, etc.)
        category: TrackerCategory,
    },

    /// A fingerprinting API call was neutralized with noise or fixed values.
    FingerprintNeutralized {
        /// The API that was called (e.g., "canvas.toDataURL", "navigator.plugins")
        api_name: String,
        /// What action was taken (e.g., "noise injection", "fixed value returned")
        action_taken: String,
    },

    /// A DNS query was resolved locally (from cache) without hitting the network.
    DnsQueryLocal {
        /// The domain that was resolved
        domain: String,
        /// Whether the result was from cache
        cached: bool,
    },

    /// A web API call was made to an API that Citadel intentionally does not implement.
    ApiNotImplemented {
        /// The API name (e.g., "Battery", "DeviceOrientation", "WebRTC")
        api_name: String,
        /// The origin that attempted the call
        caller_origin: String,
    },

    /// A Content Security Policy violation was detected and blocked.
    CspViolation {
        /// The CSP directive that was violated (e.g., "script-src", "connect-src")
        directive: String,
        /// The URI that was blocked
        blocked_uri: String,
    },

    /// Summary event indicating events were dropped due to channel backpressure.
    /// Emitted when the channel was full and events could not be delivered.
    EventsDropped {
        /// Number of events that were dropped since the last successful send
        count: u64,
    },
}

/// Categories of trackers for classification in the privacy scoreboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackerCategory {
    Advertising,
    Analytics,
    Social,
    Cryptomining,
    Fingerprinting,
    Unknown,
}

impl fmt::Display for TrackerCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrackerCategory::Advertising => write!(f, "Advertising"),
            TrackerCategory::Analytics => write!(f, "Analytics"),
            TrackerCategory::Social => write!(f, "Social"),
            TrackerCategory::Cryptomining => write!(f, "Cryptomining"),
            TrackerCategory::Fingerprinting => write!(f, "Fingerprinting"),
            TrackerCategory::Unknown => write!(f, "Unknown"),
        }
    }
}

impl fmt::Display for PrivacyEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivacyEvent::TrackerBlocked { url, category, .. } => {
                write!(f, "Tracker blocked: {} ({})", url, category)
            }
            PrivacyEvent::FingerprintNeutralized { api_name, action_taken } => {
                write!(f, "Fingerprint neutralized: {} ({})", api_name, action_taken)
            }
            PrivacyEvent::DnsQueryLocal { domain, cached } => {
                write!(f, "DNS local: {} (cached: {})", domain, cached)
            }
            PrivacyEvent::ApiNotImplemented { api_name, caller_origin } => {
                write!(f, "API not implemented: {} (from: {})", api_name, caller_origin)
            }
            PrivacyEvent::CspViolation { directive, blocked_uri } => {
                write!(f, "CSP violation: {} blocked {}", directive, blocked_uri)
            }
            PrivacyEvent::EventsDropped { count } => {
                write!(f, "Events dropped: {}", count)
            }
        }
    }
}

/// Sender side of the privacy event channel.
///
/// Wraps a bounded mpsc sender with non-blocking semantics and
/// automatic drop counting for backpressure reporting.
#[derive(Clone)]
pub struct PrivacyEventSender {
    sender: mpsc::Sender<PrivacyEvent>,
    dropped_count: Arc<AtomicU64>,
}

impl fmt::Debug for PrivacyEventSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivacyEventSender")
            .field("dropped_count", &self.dropped_count.load(Ordering::Relaxed))
            .finish()
    }
}

impl PrivacyEventSender {
    /// Try to send a privacy event without blocking.
    ///
    /// If the channel is full, the event is dropped and the drop counter
    /// is incremented. An EventsDropped summary will be sent on the next
    /// available slot.
    pub fn emit(&self, event: PrivacyEvent) {
        // First, check if we have dropped events to report
        let dropped = self.dropped_count.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            // Try to send the dropped count summary first
            let _ = self.sender.try_send(PrivacyEvent::EventsDropped { count: dropped });
        }

        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped_count.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Channel closed, receiver dropped. Nothing to do.
            }
        }
    }
}

/// Receiver side of the privacy event channel.
pub type PrivacyEventReceiver = mpsc::Receiver<PrivacyEvent>;

/// Create a new privacy event channel with the specified capacity.
///
/// Returns a (sender, receiver) pair. The sender is cheaply cloneable
/// and can be shared across crates. The receiver should be consumed by
/// the browser UI's privacy scoreboard.
///
/// Default capacity: 1024 events.
pub fn create_privacy_channel() -> (PrivacyEventSender, PrivacyEventReceiver) {
    create_privacy_channel_with_capacity(1024)
}

/// Create a privacy event channel with a custom capacity.
pub fn create_privacy_channel_with_capacity(capacity: usize) -> (PrivacyEventSender, PrivacyEventReceiver) {
    let (tx, rx) = mpsc::channel(capacity);
    let sender = PrivacyEventSender {
        sender: tx,
        dropped_count: Arc::new(AtomicU64::new(0)),
    };
    (sender, rx)
}

/// Aggregated privacy statistics for display in the scoreboard.
#[derive(Debug, Clone, Default)]
pub struct PrivacyStats {
    pub trackers_blocked: u64,
    pub fingerprints_neutralized: u64,
    pub dns_queries_local: u64,
    pub apis_not_implemented: u64,
    pub csp_violations: u64,
    pub events_dropped: u64,
    /// Recent events for the expandable detail view (bounded)
    pub recent_events: Vec<PrivacyEvent>,
}

impl PrivacyStats {
    /// Maximum number of recent events to keep for the detail view.
    const MAX_RECENT: usize = 100;

    /// Process a single privacy event, updating counters and recent list.
    pub fn record(&mut self, event: PrivacyEvent) {
        match &event {
            PrivacyEvent::TrackerBlocked { .. } => self.trackers_blocked += 1,
            PrivacyEvent::FingerprintNeutralized { .. } => self.fingerprints_neutralized += 1,
            PrivacyEvent::DnsQueryLocal { .. } => self.dns_queries_local += 1,
            PrivacyEvent::ApiNotImplemented { .. } => self.apis_not_implemented += 1,
            PrivacyEvent::CspViolation { .. } => self.csp_violations += 1,
            PrivacyEvent::EventsDropped { count } => {
                self.events_dropped += count;
                return; // Don't add dropped events to the recent list
            }
        }

        if self.recent_events.len() >= Self::MAX_RECENT {
            self.recent_events.remove(0);
        }
        self.recent_events.push(event);
    }

    /// Total number of privacy actions taken.
    pub fn total_actions(&self) -> u64 {
        self.trackers_blocked
            + self.fingerprints_neutralized
            + self.dns_queries_local
            + self.apis_not_implemented
            + self.csp_violations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privacy_event_display() {
        let event = PrivacyEvent::TrackerBlocked {
            url: "https://tracker.example.com/pixel.gif".to_string(),
            rule: "||tracker.example.com^".to_string(),
            category: TrackerCategory::Analytics,
        };
        let display = format!("{}", event);
        assert!(display.contains("tracker.example.com"));
        assert!(display.contains("Analytics"));
    }

    #[test]
    fn test_tracker_category_display() {
        assert_eq!(format!("{}", TrackerCategory::Advertising), "Advertising");
        assert_eq!(format!("{}", TrackerCategory::Cryptomining), "Cryptomining");
    }

    #[tokio::test]
    async fn test_privacy_channel_basic() {
        let (sender, mut receiver) = create_privacy_channel();

        sender.emit(PrivacyEvent::TrackerBlocked {
            url: "https://ad.example.com".to_string(),
            rule: "||ad.example.com^".to_string(),
            category: TrackerCategory::Advertising,
        });

        let event = receiver.recv().await.unwrap();
        match event {
            PrivacyEvent::TrackerBlocked { url, .. } => {
                assert_eq!(url, "https://ad.example.com");
            }
            _ => panic!("Expected TrackerBlocked event"),
        }
    }

    #[tokio::test]
    async fn test_privacy_channel_backpressure() {
        // Create a tiny channel to test backpressure
        let (sender, mut receiver) = create_privacy_channel_with_capacity(2);

        // Fill the channel
        sender.emit(PrivacyEvent::DnsQueryLocal {
            domain: "a.com".to_string(),
            cached: true,
        });
        sender.emit(PrivacyEvent::DnsQueryLocal {
            domain: "b.com".to_string(),
            cached: true,
        });

        // This should be dropped (channel full)
        sender.emit(PrivacyEvent::DnsQueryLocal {
            domain: "c.com".to_string(),
            cached: true,
        });

        // Drain the channel
        let _e1 = receiver.recv().await.unwrap();
        let _e2 = receiver.recv().await.unwrap();

        // Next emit should first send an EventsDropped summary
        sender.emit(PrivacyEvent::DnsQueryLocal {
            domain: "d.com".to_string(),
            cached: true,
        });

        let dropped_event = receiver.recv().await.unwrap();
        match dropped_event {
            PrivacyEvent::EventsDropped { count } => {
                assert_eq!(count, 1, "Should report 1 dropped event");
            }
            _ => panic!("Expected EventsDropped event, got {:?}", dropped_event),
        }
    }

    #[test]
    fn test_privacy_stats_record() {
        let mut stats = PrivacyStats::default();

        stats.record(PrivacyEvent::TrackerBlocked {
            url: "https://ad.com".to_string(),
            rule: "rule".to_string(),
            category: TrackerCategory::Advertising,
        });
        stats.record(PrivacyEvent::FingerprintNeutralized {
            api_name: "canvas".to_string(),
            action_taken: "noise".to_string(),
        });
        stats.record(PrivacyEvent::DnsQueryLocal {
            domain: "example.com".to_string(),
            cached: true,
        });

        assert_eq!(stats.trackers_blocked, 1);
        assert_eq!(stats.fingerprints_neutralized, 1);
        assert_eq!(stats.dns_queries_local, 1);
        assert_eq!(stats.total_actions(), 3);
        assert_eq!(stats.recent_events.len(), 3);
    }

    #[test]
    fn test_privacy_stats_bounded_recent() {
        let mut stats = PrivacyStats::default();

        // Add more than MAX_RECENT events
        for i in 0..150 {
            stats.record(PrivacyEvent::DnsQueryLocal {
                domain: format!("site{}.com", i),
                cached: true,
            });
        }

        assert_eq!(stats.dns_queries_local, 150);
        assert_eq!(stats.recent_events.len(), PrivacyStats::MAX_RECENT);
    }

    #[test]
    fn test_events_dropped_not_in_recent() {
        let mut stats = PrivacyStats::default();
        stats.record(PrivacyEvent::EventsDropped { count: 5 });

        assert_eq!(stats.events_dropped, 5);
        assert_eq!(stats.recent_events.len(), 0);
    }
}
