#![no_main]
use libfuzzer_sys::fuzz_target;
use citadel_parser::metrics::{ParserMetrics, DocumentMetrics};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Fuzzing strategy:
// 1. Test concurrent access to ParserMetrics
// 2. Test boundary conditions for counters
// 3. Test timing operations
// 4. Test DocumentMetrics with various inputs

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Create static metrics for testing
    static METRICS: ParserMetrics = ParserMetrics::new();
    
    // Extract test parameters from fuzzer data
    let num_threads = (data[0] % 10 + 1) as usize; // 1-10 threads
    let iterations = (data[1] % 100 + 1) as usize; // 1-100 iterations
    let depth = (data[2] % 1000 + 1) as usize; // 1-1000 depth
    let sleep_duration = data[3] as u64; // 0-255 milliseconds
    
    // Test concurrent access
    let threads: Vec<_> = (0..num_threads)
        .map(|_| {
            thread::spawn(|| {
                for _ in 0..iterations {
                    METRICS.increment_elements();
                    METRICS.increment_attributes();
                    METRICS.increment_text_nodes();
                    METRICS.increment_comments();
                    METRICS.record_error();
                    METRICS.update_max_depth(depth);
                    METRICS.record_security_violation();
                    METRICS.record_privacy_violation();
                }
            })
        })
        .collect();

    // Wait for all threads
    for thread in threads {
        thread.join().unwrap();
    }

    // Test timing operations
    {
        let _timer = ParseTimer::new(&METRICS);
        thread::sleep(Duration::from_millis(sleep_duration));
    }

    // Verify metrics
    assert!(METRICS.elements_parsed() <= num_threads * iterations);
    assert!(METRICS.attributes_parsed() <= num_threads * iterations);
    assert!(METRICS.text_nodes_parsed() <= num_threads * iterations);
    assert!(METRICS.comments_parsed() <= num_threads * iterations);
    assert!(METRICS.parsing_errors() <= num_threads * iterations);
    assert!(METRICS.max_depth() <= depth);
    assert!(METRICS.security_violations() <= num_threads * iterations);
    assert!(METRICS.privacy_violations() <= num_threads * iterations);
    assert!(METRICS.total_parse_time() >= Duration::from_millis(sleep_duration));

    // Test DocumentMetrics
    let mut doc_metrics = DocumentMetrics::new();
    
    // Use remaining bytes for document metrics testing
    for chunk in data[4..].chunks(4) {
        if chunk.len() == 4 {
            let value = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as usize;
            doc_metrics.increment_elements();
            doc_metrics.increment_attributes();
            doc_metrics.update_max_depth(value % 1000);
            doc_metrics.add_text_content(value % 10000);
        }
    }

    // Verify document metrics
    assert!(doc_metrics.element_count() > 0);
    assert!(doc_metrics.attribute_count() > 0);
    assert!(doc_metrics.max_depth() < 1000);
    assert!(doc_metrics.text_content_size() < data.len() * 10000);
}); 