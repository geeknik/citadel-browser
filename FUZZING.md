# Citadel Browser Security: Fuzzing Strategy

## Overview

Fuzzing is a critical part of Citadel's security-first approach. As a privacy-oriented browser, we must be resilient against malicious inputs, malformed data, and attacks attempting to compromise our users' security and privacy. This document outlines our fuzzing strategy, tools, and practices.

## Principles

1. **All Critical Components Must Be Fuzzed**: Every component that handles untrusted input must have comprehensive fuzz tests.
2. **Failures Are Build Failures**: Any fuzz test failure is treated as a critical build failure and must be addressed immediately.
3. **Continuous Fuzzing**: Fuzzing runs regularly in CI and on dedicated infrastructure for longer sessions.
4. **Increased Code Coverage**: We continuously monitor and improve fuzzing coverage.
5. **No Input Assumptions**: We assume any input could be malicious, malformed, or crafted to exploit vulnerabilities.

## Fuzz Target Structure

We've established fuzz targets for critical components including:

1. **DNS Resolver**: Ensures our privacy-preserving DNS resolver handles malformed or malicious hostnames and other DNS-related inputs correctly
2. **HTML Parser**: Tests the HTML tokenizer and parser with malformed or malicious HTML content
3. **CSS Parser**: Validates that CSS parsing is robust against crafted inputs that could leak information or cause resource exhaustion
4. **Network Request/Response**: Tests URL handling, header processing, and privacy-enhancing features

## Enhanced Fuzzing Features

### Automated Corpus Generation

We provide a script to generate initial corpus files for more effective fuzzing:

```bash
# Generate initial corpus
./fuzz/scripts/generate_corpus.sh
```

This script creates tailored corpus files for each fuzzer target with both normal and edge cases.

### Dictionaries for Smarter Fuzzing

We use dictionaries to guide the fuzzer toward interesting inputs:
- `dns.dict`: DNS patterns, TLDs, special characters for DNS fuzzing
- `html.dict`: HTML tags, attributes, scripts, and malicious patterns
- `css.dict`: CSS selectors, properties, values, and functions
- `network.dict`: URL components, HTTP methods, headers, and content types

### Automated Fuzzing Script

For convenience, we provide a script to run all fuzzers with enhanced memory checks:

```bash
# Run all fuzzers (30 seconds each by default)
./fuzz/scripts/run_all_fuzzers.sh

# Or with custom duration (in seconds)
./fuzz/scripts/run_all_fuzzers.sh 120  # Run each for 2 minutes
```

## Running Fuzzing Tests

### Prerequisites

```bash
# Switch to nightly Rust (required for fuzzing)
rustup default nightly

# Install LLVM tools component
rustup component add llvm-tools-preview

# Install cargo-fuzz
cargo install cargo-fuzz
```

### Running Individual Fuzzers

```bash
# Navigate to the fuzz directory
cd fuzz

# Run the DNS resolver fuzzer
cargo fuzz run dns_resolver corpus/dns_resolver -dict=dictionaries/dns.dict

# Run the HTML parser fuzzer
cargo fuzz run html_parser corpus/html_parser -dict=dictionaries/html.dict

# Run the CSS parser fuzzer
cargo fuzz run css_parser corpus/css_parser -dict=dictionaries/css.dict

# Run the network request fuzzer
cargo fuzz run network_request corpus/network_request -dict=dictionaries/network.dict
```

### Advanced Fuzzing Options

```bash
# Run with a memory limit (4GB)
cargo fuzz run dns_resolver -- -rss_limit_mb=4096

# Run with a time limit (1 hour)
cargo fuzz run dns_resolver -- -max_total_time=3600

# Run with different sanitizers
cargo fuzz run dns_resolver -- -detect_leaks=1  # LeakSanitizer
cargo fuzz run dns_resolver -- -sanitizer=address  # AddressSanitizer
```

## Adding New Fuzz Targets

When adding new components to Citadel, corresponding fuzz targets must be added:

1. Create a new target in `fuzz/fuzz_targets/`
2. Register it in `fuzz/Cargo.toml`
3. Add it to the CI fuzzing workflow

Example of a new fuzz target:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // Define the structure of your fuzz input
    data: Vec<u8>,
    option: u8,
}

fuzz_target!(|input: FuzzInput| {
    // Your fuzzing code here
    // Call the component with the fuzzed input
});
```

## Corpus Management

We maintain and grow fuzzing corpora for each target:

```bash
# Add interesting test cases to the corpus
cargo fuzz add dns_resolver /path/to/test/case

# Use a corpus during fuzzing
cargo fuzz run dns_resolver fuzz/corpus/dns_resolver
```

## Crash Analysis and Reporting

When fuzzing identifies crashes:

1. All crashes are stored in `fuzz/artifacts/<target_name>/`
2. Open a high-priority security issue with the crash and reproduction steps
3. Include the fuzzing artifact that caused the crash
4. Apply the fix and add the crash case to the corpus to prevent regression

## Continuous Integration Integration

Our GitHub Actions workflow automatically runs fuzzers on:
- Every PR
- Every push to main
- Weekly scheduled runs

See `.github/workflows/fuzzing.yml` for implementation details.

## Current Focus Areas

As of the current development phase, our fuzzing priorities are:

1. **DNS Resolver**: Complete and comprehensive
2. **Network Request/Response**: Complete and comprehensive
3. **HTML/CSS Parsers**: Initial implementation
4. **JavaScript Engine**: Planned for future implementation

## Security Recommendations

- When writing new code, consider how it will be fuzzed
- Avoid unsafe Rust except where absolutely necessary
- Validate all inputs, even from internal sources
- Add assertions to catch invariant violations
- Report all fuzzing-discovered issues as security vulnerabilities

## Platform Compatibility

### macOS ARM64 Considerations

Fuzzing on macOS with Apple Silicon (ARM64) may require additional configuration:

1. Some sanitizers like Address Sanitizer (ASan) may not be fully supported on this platform
2. Consider using x86_64 emulation: `rustup target add x86_64-apple-darwin`
3. For CI fuzzing, Linux x86_64 runners are recommended for maximum compatibility

### Linux (Recommended for CI)

Linux platforms provide the most comprehensive support for fuzzing tools and sanitizers:

1. All sanitizers are fully supported
2. Better performance characteristics for long fuzzing runs
3. ASAN, MSAN, and other sanitizers work reliably

For serious fuzzing efforts, consider using a Linux environment or Docker container.

## References

- [cargo-fuzz Documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/) 