use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// Metrics for tracking parser performance and behavior
#[derive(Debug)]
pub struct ParserMetrics {
    /// Number of elements parsed
    pub elements_parsed: AtomicUsize,
    /// Number of attributes parsed
    pub attributes_parsed: AtomicUsize,
    /// Number of security violations detected
    pub security_violations: AtomicUsize,
    /// Number of sanitization actions taken
    pub sanitization_actions: AtomicUsize,
    /// Parse start time
    pub parse_start: Option<Instant>,
}

impl Default for ParserMetrics {
    fn default() -> Self {
        Self {
            elements_parsed: AtomicUsize::new(0),
            attributes_parsed: AtomicUsize::new(0),
            security_violations: AtomicUsize::new(0),
            sanitization_actions: AtomicUsize::new(0),
            parse_start: None,
        }
    }
}

impl ParserMetrics {
    /// Create new parser metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the element counter
    pub fn increment_elements(&self) {
        self.elements_parsed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the attribute counter
    pub fn increment_attributes(&self) {
        self.attributes_parsed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the security violations counter
    pub fn increment_violations(&self) {
        self.security_violations.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the sanitization actions counter
    pub fn increment_sanitizations(&self) {
        self.sanitization_actions.fetch_add(1, Ordering::Relaxed);
    }

    /// Start timing a parse operation
    pub fn start_parse(&mut self) {
        self.parse_start = Some(Instant::now());
    }

    /// Get the elapsed parse time in milliseconds
    pub fn parse_time_ms(&self) -> Option<u128> {
        self.parse_start.map(|start| start.elapsed().as_millis())
    }

    /// Reset all metrics to zero
    pub fn reset(&self) {
        self.elements_parsed.store(0, Ordering::Relaxed);
        self.attributes_parsed.store(0, Ordering::Relaxed);
        self.security_violations.store(0, Ordering::Relaxed);
        self.sanitization_actions.store(0, Ordering::Relaxed);
        // Note: parse_start is not reset here as it's Option<Instant> and should be managed separately
    }
}

/// Metrics specific to a single document
#[derive(Debug, Default)]
pub struct DocumentMetrics {
    /// Total number of elements in the document
    elements: AtomicUsize,
    /// Total number of attributes
    attributes: AtomicUsize,
    /// Amount of text content (in bytes)
    text_content: AtomicUsize,
}

impl DocumentMetrics {
    /// Create new document metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the element counter
    pub fn increment_elements(&self) {
        self.elements.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the attribute counter
    pub fn increment_attributes(&self) {
        self.attributes.fetch_add(1, Ordering::Relaxed);
    }

    /// Add to the text content size
    pub fn add_text_content(&self, size: usize) {
        self.text_content.fetch_add(size, Ordering::Relaxed);
    }

    /// Get the total number of elements
    pub fn total_elements(&self) -> usize {
        self.elements.load(Ordering::Relaxed)
    }

    /// Get the total number of attributes
    pub fn total_attributes(&self) -> usize {
        self.attributes.load(Ordering::Relaxed)
    }

    /// Get the total text content size
    pub fn total_text_content(&self) -> usize {
        self.text_content.load(Ordering::Relaxed)
    }
}

/// Timer for measuring parse operations
#[derive(Debug)]
pub struct ParseTimer {
    start: Instant,
}

impl ParseTimer {
    /// Create a new parse timer
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Get the elapsed time in milliseconds
    pub fn elapsed_ms(&self) -> u128 {
        self.start.elapsed().as_millis()
    }
}

impl Default for ParseTimer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    use std::sync::Arc;

    #[test]
    fn test_metrics_counters() {
        let metrics = ParserMetrics::new();

        metrics.increment_elements();
        metrics.increment_elements();
        assert_eq!(metrics.elements_parsed.load(Ordering::Relaxed), 2);

        metrics.increment_violations();
        assert_eq!(metrics.security_violations.load(Ordering::Relaxed), 1);

        metrics.increment_sanitizations();
        metrics.increment_sanitizations();
        assert_eq!(metrics.sanitization_actions.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_parse_timer() {
        let mut metrics = ParserMetrics::new();
        metrics.start_parse();

        thread::sleep(Duration::from_millis(10));

        assert!(metrics.parse_time_ms().unwrap() >= 10);
    }

    #[test]
    fn test_document_metrics() {
        let metrics = DocumentMetrics::new();
        
        metrics.increment_elements();
        metrics.increment_attributes();
        metrics.add_text_content(100);

        assert_eq!(metrics.total_elements(), 1);
        assert_eq!(metrics.total_attributes(), 1);
        assert_eq!(metrics.total_text_content(), 100);
    }

    #[test]
    fn test_thread_safety() {
        let metrics = ParserMetrics::new();
        let metrics_arc = std::sync::Arc::new(metrics);
        let mut handles = vec![];

        for _ in 0..10 {
            let metrics = metrics_arc.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    metrics.increment_elements();
                    metrics.increment_sanitizations();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(metrics_arc.elements_parsed.load(Ordering::Relaxed), 1000);
        assert_eq!(metrics_arc.sanitization_actions.load(Ordering::Relaxed), 1000);
    }

    #[test]
    fn test_document_metrics_thread_safety() {
        let metrics = Arc::new(DocumentMetrics::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let metrics = Arc::clone(&metrics);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    metrics.increment_elements();
                    metrics.increment_attributes();
                    metrics.add_text_content(10);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(metrics.total_elements(), 1000);
        assert_eq!(metrics.total_attributes(), 1000);
        assert_eq!(metrics.total_text_content(), 10000);
    }
} 