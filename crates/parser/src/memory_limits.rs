//! Parser Memory Limits and Resource Protection
//!
//! This module implements memory limits and resource protection specifically
//! for the HTML/CSS/JS parser to prevent memory exhaustion attacks.

use std::sync::{Arc, Mutex};
use std::time::Instant;
use log::{warn, error, debug};

use crate::error::ParserResult;
use crate::metrics::ParserMetrics;

/// Parser-specific memory limits and tracking
#[derive(Debug, Clone)]
pub struct ParserMemoryLimits {
    /// Maximum number of DOM nodes allowed
    pub max_dom_nodes: usize,
    /// Maximum depth of DOM nesting
    pub max_dom_depth: usize,
    /// Maximum number of CSS rules
    pub max_css_rules: usize,
    /// Maximum CSS selector complexity
    pub max_css_selector_complexity: usize,
    /// Maximum JavaScript heap size (bytes)
    pub max_js_heap_size: usize,
    /// Maximum single element size (bytes)
    pub max_element_size: usize,
    /// Maximum total parsing memory (bytes)
    pub max_parsing_memory: usize,
    /// Maximum parsing time (seconds)
    pub max_parsing_time: u64,
    /// Enable resource tracking
    pub enable_tracking: bool,
}

impl Default for ParserMemoryLimits {
    fn default() -> Self {
        Self {
            max_dom_nodes: 50000,           // Reasonable limit for complex pages
            max_dom_depth: 1000,            // Prevent stack overflow
            max_css_rules: 100000,          // Large stylesheets
            max_css_selector_complexity: 1000, // Complex selectors
            max_js_heap_size: 100 * 1024 * 1024, // 100MB JS heap
            max_element_size: 10 * 1024 * 1024,   // 10MB single element
            max_parsing_memory: 200 * 1024 * 1024, // 200MB total parsing
            max_parsing_time: 30,           // 30 seconds max parse time
            enable_tracking: true,
        }
    }
}

/// Resource tracking for parser operations
#[derive(Debug)]
pub struct ParserResourceTracker {
    /// Memory limits configuration
    limits: ParserMemoryLimits,
    /// Current DOM node count
    current_dom_nodes: Arc<Mutex<usize>>,
    /// Current DOM depth
    current_dom_depth: Arc<Mutex<usize>>,
    /// Current CSS rule count
    current_css_rules: Arc<Mutex<usize>>,
    /// Current parsing memory usage
    current_parsing_memory: Arc<Mutex<usize>>,
    /// Parser start time
    parse_start_time: Option<Instant>,
    /// Parser metrics
    metrics: Arc<ParserMetrics>,
    /// Memory allocations for cleanup
    allocations: Arc<Mutex<Vec<usize>>>,
}

impl ParserResourceTracker {
    /// Create a new parser resource tracker
    pub fn new(limits: ParserMemoryLimits, metrics: Arc<ParserMetrics>) -> Self {
        Self {
            limits,
            current_dom_nodes: Arc::new(Mutex::new(0)),
            current_dom_depth: Arc::new(Mutex::new(0)),
            current_css_rules: Arc::new(Mutex::new(0)),
            current_parsing_memory: Arc::new(Mutex::new(0)),
            parse_start_time: None,
            metrics,
            allocations: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    /// Start tracking a parsing operation
    pub fn start_parsing(&mut self) {
        self.parse_start_time = Some(Instant::now());
        
        // Reset counters
        *self.current_dom_nodes.lock().unwrap() = 0;
        *self.current_dom_depth.lock().unwrap() = 0;
        *self.current_css_rules.lock().unwrap() = 0;
        *self.current_parsing_memory.lock().unwrap() = 0;
        self.allocations.lock().unwrap().clear();
        
        debug!("Started parsing operation with memory tracking");
    }
    
    /// Check if parsing should continue or timeout
    pub fn check_parsing_timeout(&self) -> ParserResult<()> {
        if let Some(start_time) = self.parse_start_time {
            let elapsed = start_time.elapsed().as_secs();
            if elapsed > self.limits.max_parsing_time {
                error!("Parser timeout exceeded: {} seconds", elapsed);
                self.metrics.increment_violations();
                return Err(crate::error::ParserError::ResourceLimitExceeded(
                    format!("Parsing timeout exceeded: {} seconds", elapsed)
                ));
            }
        }
        Ok(())
    }
    
    /// Track DOM node creation
    pub fn track_dom_node(&self, size_bytes: usize) -> ParserResult<()> {
        let mut node_count = self.current_dom_nodes.lock().unwrap();
        *node_count += 1;
        
        // Check node limit
        if *node_count > self.limits.max_dom_nodes {
            error!("DOM node limit exceeded: {} > {}", *node_count, self.limits.max_dom_nodes);
            self.metrics.increment_violations();
            return Err(crate::error::ParserError::ResourceLimitExceeded(
                format!("DOM node limit exceeded: {}", self.limits.max_dom_nodes)
            ));
        }
        
        // Track memory usage
        self.track_memory_allocation(size_bytes)?;
        
        self.metrics.increment_elements();
        debug!("Tracked DOM node creation: {} nodes, {} bytes", *node_count, size_bytes);
        
        Ok(())
    }
    
    /// Track DOM depth changes
    pub fn track_dom_depth(&self, depth: usize) -> ParserResult<()> {
        let mut current_depth = self.current_dom_depth.lock().unwrap();
        if depth > *current_depth {
            *current_depth = depth;
        }
        
        if *current_depth > self.limits.max_dom_depth {
            error!("DOM depth limit exceeded: {} > {}", *current_depth, self.limits.max_dom_depth);
            self.metrics.increment_violations();
            return Err(crate::error::ParserError::ResourceLimitExceeded(
                format!("DOM depth limit exceeded: {}", self.limits.max_dom_depth)
            ));
        }
        
        Ok(())
    }
    
    /// Track CSS rule creation
    pub fn track_css_rule(&self, selector_complexity: usize, size_bytes: usize) -> ParserResult<()> {
        let mut rule_count = self.current_css_rules.lock().unwrap();
        *rule_count += 1;
        
        // Check rule limit
        if *rule_count > self.limits.max_css_rules {
            error!("CSS rule limit exceeded: {} > {}", *rule_count, self.limits.max_css_rules);
            self.metrics.increment_violations();
            return Err(crate::error::ParserError::ResourceLimitExceeded(
                format!("CSS rule limit exceeded: {}", self.limits.max_css_rules)
            ));
        }
        
        // Check selector complexity
        if selector_complexity > self.limits.max_css_selector_complexity {
            error!("CSS selector complexity exceeded: {} > {}", 
                   selector_complexity, self.limits.max_css_selector_complexity);
            self.metrics.increment_violations();
            return Err(crate::error::ParserError::ResourceLimitExceeded(
                format!("CSS selector too complex: {}", selector_complexity)
            ));
        }
        
        // Track memory usage
        self.track_memory_allocation(size_bytes)?;
        
        debug!("Tracked CSS rule creation: {} rules, complexity {}, {} bytes", 
               *rule_count, selector_complexity, size_bytes);
        
        Ok(())
    }
    
    /// Track memory allocation for parsing
    pub fn track_memory_allocation(&self, size_bytes: usize) -> ParserResult<()> {
        // Check single element size limit
        if size_bytes > self.limits.max_element_size {
            error!("Element size limit exceeded: {} > {}", size_bytes, self.limits.max_element_size);
            self.metrics.increment_violations();
            return Err(crate::error::ParserError::ResourceLimitExceeded(
                format!("Element too large: {} bytes", size_bytes)
            ));
        }
        
        let mut memory_usage = self.current_parsing_memory.lock().unwrap();
        *memory_usage += size_bytes;
        
        // Check total parsing memory limit
        if *memory_usage > self.limits.max_parsing_memory {
            error!("Parsing memory limit exceeded: {} > {}", 
                   *memory_usage, self.limits.max_parsing_memory);
            self.metrics.increment_violations();
            return Err(crate::error::ParserError::ResourceLimitExceeded(
                format!("Parsing memory limit exceeded: {} bytes", self.limits.max_parsing_memory)
            ));
        }
        
        debug!("Tracked memory allocation: {} bytes (total: {} bytes)", 
               size_bytes, *memory_usage);
        
        Ok(())
    }
    
    /// Track JavaScript memory usage
    pub fn track_js_memory(&self, heap_size: usize) -> ParserResult<()> {
        if heap_size > self.limits.max_js_heap_size {
            error!("JavaScript heap size limit exceeded: {} > {}", 
                   heap_size, self.limits.max_js_heap_size);
            self.metrics.increment_violations();
            return Err(crate::error::ParserError::ResourceLimitExceeded(
                format!("JavaScript heap too large: {} bytes", heap_size)
            ));
        }
        
        debug!("Tracked JavaScript memory: {} bytes", heap_size);
        Ok(())
    }
    
    /// Get current resource usage
    pub fn get_current_usage(&self) -> ParserResourceUsage {
        ParserResourceUsage {
            dom_nodes: *self.current_dom_nodes.lock().unwrap(),
            dom_depth: *self.current_dom_depth.lock().unwrap(),
            css_rules: *self.current_css_rules.lock().unwrap(),
            parsing_memory: *self.current_parsing_memory.lock().unwrap(),
            parsing_time: self.parse_start_time.map(|start| start.elapsed().as_millis() as u64),
        }
    }
    
    /// Check if parsing should be throttled due to resource usage
    pub fn should_throttle(&self) -> bool {
        let usage = self.get_current_usage();
        
        // Throttle if approaching limits
        let dom_ratio = usage.dom_nodes as f64 / self.limits.max_dom_nodes as f64;
        let memory_ratio = usage.parsing_memory as f64 / self.limits.max_parsing_memory as f64;
        
        dom_ratio > 0.8 || memory_ratio > 0.8
    }
    
    /// Cleanup parser resources
    pub fn cleanup(&mut self) {
        debug!("Cleaning up parser resources");
        
        // Clear allocations
        self.allocations.lock().unwrap().clear();
        
        // Reset counters
        *self.current_dom_nodes.lock().unwrap() = 0;
        *self.current_dom_depth.lock().unwrap() = 0;
        *self.current_css_rules.lock().unwrap() = 0;
        *self.current_parsing_memory.lock().unwrap() = 0;
        
        self.parse_start_time = None;
    }
    
    /// Get resource utilization ratios
    pub fn get_utilization_ratios(&self) -> ParserUtilization {
        let usage = self.get_current_usage();
        
        ParserUtilization {
            dom_nodes: usage.dom_nodes as f32 / self.limits.max_dom_nodes as f32,
            dom_depth: usage.dom_depth as f32 / self.limits.max_dom_depth as f32,
            css_rules: usage.css_rules as f32 / self.limits.max_css_rules as f32,
            parsing_memory: usage.parsing_memory as f32 / self.limits.max_parsing_memory as f32,
            parsing_time: usage.parsing_time.unwrap_or(0) as f32 / (self.limits.max_parsing_time * 1000) as f32,
        }
    }
}

/// Current parser resource usage
#[derive(Debug, Clone)]
pub struct ParserResourceUsage {
    pub dom_nodes: usize,
    pub dom_depth: usize,
    pub css_rules: usize,
    pub parsing_memory: usize,
    pub parsing_time: Option<u64>, // milliseconds
}

/// Parser resource utilization ratios (0.0 to 1.0)
#[derive(Debug, Clone)]
pub struct ParserUtilization {
    pub dom_nodes: f32,
    pub dom_depth: f32,
    pub css_rules: f32,
    pub parsing_memory: f32,
    pub parsing_time: f32,
}

impl ParserUtilization {
    /// Check if any utilization is above the warning threshold
    pub fn has_warnings(&self, threshold: f32) -> bool {
        self.dom_nodes > threshold ||
        self.dom_depth > threshold ||
        self.css_rules > threshold ||
        self.parsing_memory > threshold ||
        self.parsing_time > threshold
    }
    
    /// Get the highest utilization ratio
    pub fn max_utilization(&self) -> f32 {
        self.dom_nodes.max(self.dom_depth)
            .max(self.css_rules)
            .max(self.parsing_memory)
            .max(self.parsing_time)
    }
}

/// Attack pattern detection for parser operations
pub struct ParserAttackDetector {
    /// Recent element creation patterns
    recent_elements: Vec<(Instant, usize)>,
    /// Recent memory allocation patterns
    recent_allocations: Vec<(Instant, usize)>,
    /// Threshold for rapid element creation
    rapid_element_threshold: usize,
    /// Threshold for memory bomb detection
    memory_bomb_threshold: usize,
}

impl ParserAttackDetector {
    /// Create a new parser attack detector
    pub fn new() -> Self {
        Self {
            recent_elements: Vec::new(),
            recent_allocations: Vec::new(),
            rapid_element_threshold: 1000, // 1000 elements per second
            memory_bomb_threshold: 50 * 1024 * 1024, // 50MB per second
        }
    }
    
    /// Detect rapid element creation attack
    pub fn detect_rapid_element_creation(&mut self, element_count: usize) -> bool {
        let now = Instant::now();
        
        // Clean old entries (older than 1 second)
        self.recent_elements.retain(|(timestamp, _)| {
            now.duration_since(*timestamp).as_secs() < 1
        });
        
        self.recent_elements.push((now, element_count));
        
        // Check if total elements in last second exceeds threshold
        let total_elements: usize = self.recent_elements.iter().map(|(_, count)| count).sum();
        
        if total_elements > self.rapid_element_threshold {
            warn!("Rapid element creation attack detected: {} elements in 1 second", total_elements);
            return true;
        }
        
        false
    }
    
    /// Detect memory bomb attack
    pub fn detect_memory_bomb(&mut self, allocation_size: usize) -> bool {
        let now = Instant::now();
        
        // Clean old entries (older than 1 second)
        self.recent_allocations.retain(|(timestamp, _)| {
            now.duration_since(*timestamp).as_secs() < 1
        });
        
        self.recent_allocations.push((now, allocation_size));
        
        // Check if total allocations in last second exceeds threshold
        let total_allocations: usize = self.recent_allocations.iter().map(|(_, size)| size).sum();
        
        if total_allocations > self.memory_bomb_threshold {
            warn!("Memory bomb attack detected: {} bytes allocated in 1 second", total_allocations);
            return true;
        }
        
        false
    }
}

impl Default for ParserAttackDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    
    #[test]
    fn test_parser_resource_tracker() {
        let limits = ParserMemoryLimits::default();
        let metrics = Arc::new(ParserMetrics::new());
        let mut tracker = ParserResourceTracker::new(limits.clone(), metrics);
        
        tracker.start_parsing();
        
        // Test DOM node tracking
        assert!(tracker.track_dom_node(1024).is_ok());
        assert_eq!(tracker.get_current_usage().dom_nodes, 1);
        
        // Test CSS rule tracking
        assert!(tracker.track_css_rule(10, 512).is_ok());
        assert_eq!(tracker.get_current_usage().css_rules, 1);
        
        // Test memory tracking
        assert_eq!(tracker.get_current_usage().parsing_memory, 1024 + 512);
    }
    
    #[test]
    fn test_dom_node_limit() {
        let mut limits = ParserMemoryLimits::default();
        limits.max_dom_nodes = 2; // Very low limit for testing
        
        let metrics = Arc::new(ParserMetrics::new());
        let mut tracker = ParserResourceTracker::new(limits.clone(), metrics);
        
        tracker.start_parsing();
        
        assert!(tracker.track_dom_node(100).is_ok());
        assert!(tracker.track_dom_node(100).is_ok());
        
        // Third node should fail
        assert!(tracker.track_dom_node(100).is_err());
    }
    
    #[test]
    fn test_memory_limit() {
        let mut limits = ParserMemoryLimits::default();
        limits.max_parsing_memory = 1000; // Very low limit for testing
        
        let metrics = Arc::new(ParserMetrics::new());
        let mut tracker = ParserResourceTracker::new(limits.clone(), metrics);
        
        tracker.start_parsing();
        
        assert!(tracker.track_memory_allocation(500).is_ok());
        assert!(tracker.track_memory_allocation(400).is_ok());
        
        // This should exceed the limit
        assert!(tracker.track_memory_allocation(200).is_err());
    }
    
    #[test]
    fn test_attack_detector() {
        let mut detector = ParserAttackDetector::new();
        
        // Simulate rapid element creation
        for _ in 0..1500 {
            if detector.detect_rapid_element_creation(1) {
                // Attack detected
                return;
            }
        }
        
        panic!("Attack detection should have triggered");
    }
    
    #[test]
    fn test_utilization_ratios() {
        let limits = ParserMemoryLimits::default();
        let metrics = Arc::new(ParserMetrics::new());
        let mut tracker = ParserResourceTracker::new(limits.clone(), metrics);
        
        tracker.start_parsing();
        
        // Fill 50% of DOM nodes
        for _ in 0..(limits.max_dom_nodes / 2) {
            tracker.track_dom_node(100).unwrap();
        }
        
        let utilization = tracker.get_utilization_ratios();
        assert!(utilization.dom_nodes > 0.4 && utilization.dom_nodes < 0.6);
        assert!(utilization.has_warnings(0.4));
    }
}