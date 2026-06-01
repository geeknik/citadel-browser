#![no_main]

use citadel_networking::dns::CitadelDnsResolver;
use libfuzzer_sys::fuzz_target;

// Fuzz DNS resolution of arbitrary hostnames in the privacy-preserving default
// (LocalCache + system resolver) mode. The resolver must never panic or hit UB
// on malformed hostnames; resolution failures are expected and fine.
fuzz_target!(|data: &[u8]| {
    let Ok(hostname) = std::str::from_utf8(data) else {
        return;
    };
    if hostname.is_empty() || hostname.len() > 253 {
        return; // bound; 253 = max DNS name length
    }
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    rt.block_on(async {
        if let Ok(resolver) = CitadelDnsResolver::new().await {
            let _ = resolver.resolve(hostname).await;
        }
    });
});
