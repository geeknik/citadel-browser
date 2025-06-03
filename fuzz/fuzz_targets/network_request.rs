#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use citadel_networking::request::{Request, Method, RequestBuilder};
use std::collections::HashMap;
use std::str;

#[derive(Arbitrary, Debug)]
struct NetworkRequestFuzzInput {
    url_data: Vec<u8>,
    method_id: u8,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body_data: Vec<u8>,
    enforce_https: bool,
    timeout_ms: u32,
    remove_tracking_params: bool,
    add_privacy_headers: bool,
}

fn sanitize_header_name(data: &[u8]) -> Option<String> {
    // Header names must be ASCII
    if !data.is_empty() && data.iter().all(|&b| b.is_ascii() && !b.is_ascii_control()) {
        // Convert to string
        let header_name = str::from_utf8(data).ok()?;
        
        // Remove any characters that would make an invalid header
        let header_name = header_name
            .chars()
            .filter(|&c| c != ':' && c != '\r' && c != '\n')
            .collect::<String>();
        
        if !header_name.is_empty() {
            return Some(header_name);
        }
    }
    None
}

fn sanitize_header_value(data: &[u8]) -> Option<String> {
    // Header values should be mostly ASCII but can have some UTF-8
    if !data.is_empty() {
        // Try to convert to string
        let header_value = String::from_utf8_lossy(data).to_string();
        
        // Remove any characters that would make an invalid header
        let header_value = header_value
            .chars()
            .filter(|&c| c != '\r' && c != '\n')
            .collect::<String>();
        
        if !header_value.is_empty() {
            return Some(header_value);
        }
    }
    None
}

fuzz_target!(|input: NetworkRequestFuzzInput| {
    // Convert URL bytes to a string
    let url_str = String::from_utf8_lossy(&input.url_data).to_string();
    
    // Skip if URL is empty
    if url_str.is_empty() {
        return;
    }
    
    // Try to create a valid URL with http:// or https:// prefix if needed
    let url_str = if !url_str.starts_with("http://") && !url_str.starts_with("https://") {
        format!("https://{}", url_str)
    } else {
        url_str
    };
    
    // Determine HTTP method
    let method = match input.method_id % 5 {
        0 => Method::GET,
        1 => Method::POST,
        2 => Method::PUT,
        3 => Method::DELETE,
        _ => Method::HEAD,
    };
    
    // Create request builder
    let builder = match RequestBuilder::new(&url_str) {
        Ok(builder) => builder,
        Err(_) => return, // Skip if URL is invalid
    };
    
    // Process headers
    let mut headers = HashMap::new();
    for (name_bytes, value_bytes) in input.headers.iter() {
        if let (Some(name), Some(value)) = (
            sanitize_header_name(name_bytes),
            sanitize_header_value(value_bytes),
        ) {
            headers.insert(name, value);
        }
    }
    
    // Configure request
    let builder = builder
        .method(method)
        .headers(headers)
        .enforce_https(input.enforce_https)
        .timeout(std::time::Duration::from_millis(input.timeout_ms.min(5000) as u64)) // Max 5 seconds
        .remove_tracking_params(input.remove_tracking_params);
    
    let builder = if input.add_privacy_headers {
        builder.add_privacy_headers()
    } else {
        builder
    };
    
    // Add body for relevant methods
    let builder = if method == Method::POST || method == Method::PUT {
        if !input.body_data.is_empty() {
            builder.body(input.body_data.clone())
        } else {
            builder
        }
    } else {
        builder
    };
    
    // Build the request and check for errors
    let _ = builder.build();
}); 