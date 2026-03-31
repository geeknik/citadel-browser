# Citadel Browser Memory Protection System

This document describes the comprehensive memory protection system implemented in Citadel Browser to prevent memory exhaustion attacks and ensure system stability.

## Overview

The memory protection system provides multi-layered defense against memory-based attacks while maintaining browser performance and functionality. It operates across all browser components with centralized monitoring and enforcement.

## Architecture

### Core Components

1. **Memory Protection System** (`citadel-security/src/memory.rs`)
   - Central memory tracking and enforcement
   - Resource pool management
   - Attack pattern detection
   - Emergency cleanup coordination

2. **Browser Memory Manager** (`citadel-browser/src/memory_protection.rs`)
   - Browser-specific integration
   - Performance monitoring integration
   - Tab-specific memory management
   - Background monitoring tasks

3. **Parser Memory Limits** (`citadel-parser/src/memory_limits.rs`)
   - Parser-specific resource tracking
   - DOM/CSS/JS memory limits
   - Parsing timeout enforcement
   - Attack pattern detection for parsing

### Resource Types

The system tracks and limits the following resource types:

- **DOM Nodes**: HTML elements and document structure
- **CSS Rules**: Stylesheets and computed styles
- **JavaScript Objects**: JS heap and execution context
- **Network Connections**: HTTP requests and responses
- **Image Data**: Image cache and decoded images
- **Font Data**: Font cache and rendered fonts
- **Media Data**: Audio/video content
- **WebGL Contexts**: GPU memory and contexts
- **Canvas Data**: Canvas buffers and contexts
- **Generic Memory**: Fallback category
- **Tab Memory**: Per-tab memory pools
- **Parser Memory**: Temporary parsing allocations

## Security Features

### Memory Limits

#### Global Limits
- **Total Memory**: 4GB browser-wide (configurable)
- **Per-Tab Memory**: 1GB per tab (configurable)
- **Single Allocation**: 100MB maximum (prevents large allocation attacks)

#### Resource-Specific Limits
- **DOM Nodes**: 100,000 nodes, 200MB memory
- **JavaScript Objects**: 2,000,000 objects, 512MB memory
- **Image Cache**: 2,000 images, 1GB memory
- **Network Connections**: 200 connections, 50MB memory
- **CSS Rules**: 500,000 rules, 100MB memory

### Attack Protection

#### Attack Pattern Detection
1. **Rapid Allocation**: Detects > 1000 allocations per second
2. **Large Allocation**: Detects single allocations > 50MB
3. **Memory Bomb**: Detects > 200MB allocated per second
4. **DOM Bomb**: Detects rapid DOM node creation
5. **CSS Bomb**: Detects complex selector patterns

#### Response Mechanisms
- **Throttling**: Slow down suspicious operations
- **Emergency Cleanup**: Aggressive resource cleanup
- **Request Blocking**: Block further allocations
- **Tab Isolation**: Prevent cross-tab memory impact

### Memory Pressure Management

#### Pressure Levels
1. **Low**: < 70% memory usage (normal operation)
2. **Medium**: 70-75% usage (preemptive cleanup)
3. **High**: 75-85% usage (aggressive cleanup)
4. **Critical**: > 85% usage (emergency mode)

#### Cleanup Priorities
1. **Critical**: Essential for browser stability (DOM nodes)
2. **High**: Important for functionality (CSS rules)
3. **Medium**: Performance optimization (image cache)
4. **Low**: Nice-to-have (network cache)

## Implementation Details

### Memory Tracking

Each allocation is tracked with metadata:
```rust
struct AllocationInfo {
    size: usize,           // Allocation size in bytes
    timestamp: Instant,    // When allocated
    source: Option<String>, // Source component/location
    critical: bool,        // Whether allocation is critical
    priority: u8,          // Cleanup priority (0 = highest)
}
```

### Resource Pools

Each resource type has its own pool with:
- Maximum count limits
- Maximum memory limits
- Soft limits for early warning
- Emergency cleanup capabilities
- Operation timeouts

### Integration Points

#### Browser Engine Integration
```rust
// Allocate DOM memory
let allocation_id = memory_manager.allocate_dom_memory(size, critical)?;

// Deallocate when no longer needed
memory_manager.deallocate_memory(ResourceType::DomNodes, allocation_id)?;

// Check if tab creation is safe
if memory_manager.can_create_tab() {
    // Create new tab
}
```

#### Parser Integration
```rust
// Track parser resources
let mut tracker = ParserResourceTracker::new(limits, metrics);
tracker.start_parsing();

// Track DOM node creation
tracker.track_dom_node(element_size)?;

// Check for parsing timeout
tracker.check_parsing_timeout()?;

// Clean up when done
tracker.cleanup();
```

## Configuration

### Memory Protection Config
```rust
MemoryProtectionConfig {
    total_memory_limit: 4 * 1024 * 1024 * 1024, // 4GB
    per_tab_memory_limit: 1024 * 1024 * 1024,   // 1GB
    emergency_threshold: 0.85,  // 85%
    aggressive_threshold: 0.70, // 70%
    attack_protection: true,
    detailed_tracking: true,
    check_interval: Duration::from_secs(5),
    max_single_allocation: 100 * 1024 * 1024, // 100MB
}
```

### Parser Memory Limits
```rust
ParserMemoryLimits {
    max_dom_nodes: 50000,
    max_dom_depth: 1000,
    max_css_rules: 100000,
    max_css_selector_complexity: 1000,
    max_js_heap_size: 100 * 1024 * 1024, // 100MB
    max_element_size: 10 * 1024 * 1024,  // 10MB
    max_parsing_memory: 200 * 1024 * 1024, // 200MB
    max_parsing_time: 30, // 30 seconds
}
```

## Monitoring and Diagnostics

### Memory Statistics

The system provides comprehensive statistics:
- Total memory usage and utilization
- Per-resource-type memory usage
- Allocation counts and patterns
- Emergency mode status
- Cleanup history and effectiveness

### Performance Metrics

Integration with performance monitoring:
- Memory pressure events
- Cleanup trigger frequency
- Allocation/deallocation rates
- Attack detection events

### Logging and Alerts

- **Debug**: Detailed allocation/deallocation tracking
- **Info**: Memory pressure events and cleanup operations
- **Warn**: Attack pattern detection and high memory usage
- **Error**: Memory limit violations and emergency conditions

## Security Considerations

### Thread Safety

- All operations are thread-safe using appropriate synchronization
- Lock-free atomic operations where possible
- Minimal lock contention through fine-grained locking

### Attack Mitigation

1. **Memory Exhaustion**: Strict limits and emergency cleanup
2. **Resource Exhaustion**: Per-resource-type limits
3. **Timing Attacks**: Operation timeouts and throttling
4. **Cross-Tab Attacks**: Tab isolation and per-tab limits

### Emergency Procedures

1. **Automatic Cleanup**: Background monitoring with automatic response
2. **Manual Cleanup**: API for forcing cleanup when needed
3. **Tab Termination**: Ability to terminate problematic tabs
4. **Browser Stability**: System-wide limits to prevent browser crashes

## Testing

Comprehensive test coverage includes:

- Unit tests for individual components
- Integration tests for cross-component functionality
- Attack simulation tests
- Concurrency and thread safety tests
- Performance and stress tests
- Memory leak detection tests

### Test Categories

1. **Basic Functionality**: Allocation, deallocation, tracking
2. **Limit Enforcement**: Memory and count limits
3. **Attack Detection**: Various attack patterns
4. **Emergency Response**: Cleanup and recovery
5. **Integration**: Browser and parser integration
6. **Performance**: Impact on browser performance

## Performance Impact

The memory protection system is designed for minimal performance impact:

- **Allocation Overhead**: < 1% CPU overhead per allocation
- **Memory Overhead**: < 5% memory overhead for tracking
- **Background Monitoring**: Low-priority background tasks
- **Cleanup Operations**: Optimized for quick execution

## Future Enhancements

Planned improvements:

1. **Machine Learning**: Predictive memory usage patterns
2. **Advanced Cleanup**: Smarter cleanup strategies
3. **Cross-Platform**: Platform-specific optimizations
4. **User Controls**: User-configurable memory limits
5. **Telemetry**: Anonymous usage statistics for optimization

## API Reference

### Core Functions

```rust
// Memory Protection System
impl MemoryProtectionSystem {
    pub fn allocate(&self, resource_type: ResourceType, size: usize, 
                   critical: bool, source: Option<String>) -> Result<usize>;
    pub fn deallocate(&self, resource_type: ResourceType, 
                     allocation_id: usize) -> Result<()>;
    pub fn force_cleanup(&self, aggressive: bool) -> usize;
    pub fn is_emergency_mode(&self) -> bool;
    pub fn total_memory_usage(&self) -> usize;
    pub fn memory_utilization(&self) -> f32;
}

// Browser Memory Manager
impl BrowserMemoryManager {
    pub fn allocate_dom_memory(&self, size: usize, critical: bool) -> Result<usize>;
    pub fn allocate_js_memory(&self, size: usize, critical: bool) -> Result<usize>;
    pub fn allocate_image_memory(&self, size: usize) -> Result<usize>;
    pub fn can_create_tab(&self) -> bool;
    pub fn get_memory_statistics(&self) -> BrowserMemoryStatistics;
}

// Parser Resource Tracker
impl ParserResourceTracker {
    pub fn track_dom_node(&self, size_bytes: usize) -> Result<()>;
    pub fn track_css_rule(&self, complexity: usize, size: usize) -> Result<()>;
    pub fn track_js_memory(&self, heap_size: usize) -> Result<()>;
    pub fn should_throttle(&self) -> bool;
    pub fn get_current_usage(&self) -> ParserResourceUsage;
}
```

This memory protection system provides comprehensive defense against memory-based attacks while maintaining browser performance and user experience. It represents a critical security component that operates transparently to protect users from malicious websites attempting to exhaust system resources.