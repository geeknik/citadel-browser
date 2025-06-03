use std::sync::atomic::{AtomicUsize, Ordering};

/// Unified metrics structure for DOM operations, designed for privacy.
/// Uses atomic operations for thread safety.
#[derive(Debug)]
pub struct DomMetrics {
    // Total elements created
    pub elements_created: AtomicUsize,
    // Count of elements deemed potentially privacy-sensitive (e.g., canvas, specific forms)
    pub privacy_sensitive_elements: AtomicUsize,
    // Count of elements blocked due to security/privacy policies (e.g., scripts, iframes)
    pub elements_blocked: AtomicUsize,
    // Total size of text content
    pub total_text_size: AtomicUsize,
}

impl Default for DomMetrics {
    fn default() -> Self {
        Self {
            elements_created: AtomicUsize::new(0),
            privacy_sensitive_elements: AtomicUsize::new(0),
            elements_blocked: AtomicUsize::new(0),
            total_text_size: AtomicUsize::new(0),
        }
    }
}

impl DomMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_elements_created(&self) {
        self.elements_created.fetch_add(1, Ordering::Relaxed);
    }

    // Alias for backward compatibility
    pub fn increment_elements(&self) {
        self.increment_elements_created();
    }

    pub fn increment_privacy_sensitive_elements(&self) {
        self.privacy_sensitive_elements.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_elements_blocked(&self) {
        self.elements_blocked.fetch_add(1, Ordering::Relaxed);
    }

    // Add size to text content metric
    pub fn add_text_content(&self, size: usize) {
        self.total_text_size.fetch_add(size, Ordering::Relaxed);
    }

    // Methods to retrieve current counts safely
    pub fn get_elements_created(&self) -> usize {
        self.elements_created.load(Ordering::Relaxed)
    }

    pub fn get_privacy_sensitive_elements(&self) -> usize {
        self.privacy_sensitive_elements.load(Ordering::Relaxed)
    }

    pub fn get_elements_blocked(&self) -> usize {
        self.elements_blocked.load(Ordering::Relaxed)
    }

    pub fn get_total_text_size(&self) -> usize {
        self.total_text_size.load(Ordering::Relaxed)
    }
}

impl Clone for DomMetrics {
    fn clone(&self) -> Self {
        Self {
            elements_created: AtomicUsize::new(self.get_elements_created()),
            privacy_sensitive_elements: AtomicUsize::new(self.get_privacy_sensitive_elements()),
            elements_blocked: AtomicUsize::new(self.get_elements_blocked()),
            total_text_size: AtomicUsize::new(self.get_total_text_size()),
        }
    }
}

#[cfg(test)]
mod tests {
// ... existing code ...
} 