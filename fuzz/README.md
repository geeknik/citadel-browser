# Citadel Browser Fuzz Testing

This directory contains fuzz testing targets for critical parsing components of the Citadel browser engine.

## Available Fuzzers

### HTML Parser Fuzzer
Located in `fuzz_targets/html_parser.rs`
- Tests the HTML parsing functionality
- Converts input bytes to UTF-8 strings
- Implements a 10KB size limit
- Detects panics, crashes, and undefined behavior

### CSS Parser Fuzzer
Located in `fuzz_targets/css_parser.rs`
- Tests the CSS parsing functionality
- Converts input bytes to UTF-8 strings
- Implements a 10KB size limit
- Detects panics, crashes, and undefined behavior

### URL Parser Fuzzer
Located in `fuzz_targets/url_parser.rs`
- Tests the URL parsing functionality
- Converts input bytes to UTF-8 strings
- Implements a 10KB size limit
- Detects panics, crashes, and undefined behavior

## Running the Fuzzers

To run a specific fuzzer:

```bash
cargo fuzz run html_parser  # For HTML parser
cargo fuzz run css_parser   # For CSS parser
cargo fuzz run url_parser   # For URL parser
```

Each fuzzer will continuously generate and test inputs until a crash is found or the fuzzer is stopped.

## Security Considerations

These fuzzers are designed to:
1. Find parsing vulnerabilities that could lead to crashes
2. Identify memory safety issues
3. Detect undefined behavior
4. Test edge cases in input handling
5. Prevent resource exhaustion via size limits

## Adding New Fuzzers

When adding new fuzzers:
1. Create a new file in `fuzz_targets/`
2. Implement proper input validation
3. Add size limits to prevent resource exhaustion
4. Document the fuzzer in this README
5. Add appropriate dependencies to `Cargo.toml`

## Directory Structure

- `fuzz/`: Root directory for fuzzing infrastructure
  - `corpus/`: Directory containing test cases for fuzzing
  - `artifacts/`: Directory containing crash reports and findings
  - `fuzz_targets/`: Directory containing individual fuzz target definitions
  - `Cargo.toml`: Fuzzing-specific cargo configuration
  - `fuzz.sh`: Script to run fuzzing in Docker container

## Platform Support

- **Linux**: Full support for running fuzz tests natively
- **macOS/Windows**: Fuzzing is supported through Docker (see `../Dockerfile.fuzz`)

## Running Fuzz Tests

To run the fuzzer:

```bash
./fuzz.sh <target> <duration>
```

Where:
- `target`: The name of the fuzz target to run (e.g., "html_parser")
- `duration`: How long to run the fuzzer for (e.g., "1h", "30m", etc.)

Example:
```bash
./fuzz.sh html_parser 1h
```

## Available Fuzzing Targets

- `html_parser`: Fuzzes the HTML parser implementation
- `css_parser`: Fuzzes the CSS parser implementation
- `dns_resolver`: Fuzzes the DNS resolver
- `network_request`: Fuzzes network request handling
- `search_worker`: Fuzzes the search functionality
- `tab_persistence`: Fuzzes tab state persistence

## Fuzzing Artifacts

When running in Docker, fuzzing artifacts are preserved in the `citadel-fuzz-artifacts` volume.

## Corpus Management

- The `corpus/` directory contains test cases that guide the fuzzer
- New interesting test cases discovered during fuzzing are automatically added
- You can manually add test cases to improve coverage

## Crash Reports

When the fuzzer finds a crash:
1. A test case that triggers the crash is saved to `artifacts/`
2. A stack trace and other debug info is saved alongside it
3. The crash can be reproduced using the saved test case

## Docker Integration

The fuzzing environment runs in a Docker container to ensure:
- Consistent environment across different machines
- Isolation from the host system
- Easy resource limiting and monitoring

The Docker image is built automatically when running `fuzz.sh`.

## Notes

- Fuzzing tests are automatically excluded from builds on non-Linux platforms
- The Docker setup ensures consistent fuzzing environment across platforms
- For development on macOS/Windows, regular tests and builds work normally 