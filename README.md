# Citadel Browser Engine

A from-scratch browser engine engineered to demolish tracking, neutralize fingerprinting, and restore user privacy with extreme technical precision.

## Project Status

⚠️ **EARLY DEVELOPMENT** ⚠️  
This project is in the early stages of development and is not yet ready for production use.

### Current Implementation Status

- ✅ Core architecture and component interfaces defined
- ✅ Basic unit tests for all components with 100% pass rate
- ✅ Continuous integration and testing infrastructure
- ✅ Vertical tabs implemented and enabled by default
- ✅ Tab bar visibility controls
- ✅ UI customization (theme settings, layout preferences)
- ✅ Privacy-first networking layer with LOCAL_CACHE as default DNS mode
- ✅ Privacy-preserving DNS resolver with local caching
- ✅ HTTPS-only secure connections
- ✅ Privacy-enhancing request headers
- ✅ Tracking parameter removal from URLs
- ✅ Header fingerprint randomization
- 🔄 Enhancing additional privacy and security features
- 🔄 Implementing advanced browsing functionality

## Vision

Citadel isn't just a browser engine. It's a declaration of digital human rights. Built for those who understand that privacy is not a luxury—it's a fundamental necessity.

## Core Features

- **Radical Privacy Protection**: Eliminates tracking mechanisms at their root
- **Anti-Fingerprinting Technology**: Makes your browser fingerprint worthless to trackers
- **User Control**: You decide what data leaves your device, period
- **Security First**: Designed with a zero-trust security model
- **Modern UI**: Vertical tabs by default, customizable layouts, and clean design

## Architecture

Citadel is built with these core components, all implemented with Rust's strong encapsulation features:

### Components

- **Parser**: Weaponized HTML/CSS/JS parsing with minimal attack surface
  - HTML document parsing
  - CSS stylesheet parsing
  - JavaScript code parsing
  - Strict security protocols

- **JavaScript Engine**: Hardcore sandboxed environment with surgically removed tracking APIs
  - Execution context management
  - API restrictions and controls
  - Performance optimization
  - Security sandboxing

- **Networking Layer**: Privacy-preserving networking with connection fingerprint randomization
  - User-controlled DNS settings (LOCAL_CACHE by default - no third-party services)
  - Secure DNS modes (DOH/DOT) available as user options, but never the default
  - Strict HTTPS enforcement
  - Minimal HTTP headers
  - Connection fingerprint randomization
  - User-agent randomization
  - Tracking parameter removal from URLs

- **Privacy Management**: Comprehensive tracker blocking and fingerprinting protection
  - Dynamic tracker blocklists
  - Fingerprinting protection
  - Custom tracker management
  - Privacy reporting

- **Security Mechanisms**: Strict isolation techniques and granular content controls
  - Content Security Policy management
  - Site isolation
  - Storage policy controls
  - Custom security policy support

- **User Interface**: Clean and intuitive control interface
  - Vertical tabs by default for better screen utilization
  - Tab bar visibility controls (toggle with Ctrl+H)
  - Tab layout options (toggle vertical/horizontal with Ctrl+Shift+V)
  - Theme customization (light/dark/system)
  - Window and tab management
  - Navigation controls
  - Privacy and security settings

## Networking Features

The networking layer is the foundation of Citadel's privacy-preserving architecture:

### Privacy-First DNS

- **Local Cache by Default**: Minimize network requests that could be tracked
- **No Third-Party DNS Services**: We never use external DNS services without your explicit consent
- **Optional Secure DNS**: Support for DNS over HTTPS (DoH) and DNS over TLS (DoT) as user options
- **Normalized TTLs**: Prevent timing-based tracking through DNS

### Secure Connections

- **HTTPS Only**: All connections must use HTTPS for privacy and security
- **Strict TLS**: Modern, secure TLS configurations
- **Certificate Validation**: Thorough certificate checking
- **Connection Security Levels**: Configure security vs. compatibility

### Privacy-Enhanced Requests

- **Header Management**: Remove or normalize headers that could be used for tracking
- **Fingerprint Randomization**: Prevent browser fingerprinting through request headers
- **User-Agent Control**: Randomize or normalize your User-Agent
- **URL Cleaning**: Automatically strip tracking parameters from URLs
- **Privacy Levels**: Configure maximum, high, or balanced privacy settings

### UI Features

- **Tab Management**
  - **Vertical Tabs**: Enabled by default for better screen utilization and improved tab visibility
  - **Tab Bar Visibility**: Toggle tab bar on/off with Ctrl+H
  - **Tab Layout**: Switch between vertical and horizontal tabs with Ctrl+Shift+V
  - **Theme Support**: Choose between light, dark, or system theme

## Privacy & Security Features

### Key Privacy Principles

- **User Sovereignty**: All privacy decisions are in your hands
- **No Third-Party Dependencies**: Local cache for DNS by default - no data sent to third-party DNS providers
- **Zero Tracking**: No fingerprinting, no tracking, no exceptions

## Design Patterns

### Rust Module Architecture

All major components in Citadel use Rust's powerful module system, which provides:

- **Improved Encapsulation**: Implementation details are hidden from the public interface
- **Memory Safety**: Rust's ownership system eliminates entire classes of bugs
- **Fearless Concurrency**: Safe concurrent code without data races
- **Zero-Cost Abstractions**: High-level concepts without runtime overhead
- **Cleaner Code Organization**: Clear separation between interface and implementation

## Getting Started

### Prerequisites

- Rust and Cargo (latest stable)
- pkg-config
- OpenSSL dev packages
- Fontconfig dev packages
- X11/Wayland dev packages (Linux)

### Building from Source

```bash
git clone https://github.com/yourusername/citadel-browser-rust.git
cd citadel-browser-rust
cargo build
```

### Running Tests

```bash
cargo test
```

### Running Examples

```bash
# Run the HTML fetching example
cargo run --example fetch_html
```

## Project Structure

```
citadel-browser-rust/
├── Cargo.toml             # Workspace configuration
├── crates/                # Rust crates
│   ├── networking/        # Privacy-preserving networking components
│   │   ├── src/           # Source code
│   │   │   ├── dns.rs     # Privacy-focused DNS resolver
│   │   │   ├── request.rs # Privacy-enhancing HTTP requests
│   │   │   ├── response.rs # HTTP response handling
│   │   │   ├── connection.rs # Secure connection management
│   │   │   ├── resource.rs # Resource fetching
│   │   │   ├── error.rs   # Error handling
│   │   │   └── lib.rs     # Library entry point
│   │   ├── examples/      # Usage examples
│   │   └── tests/         # Integration tests
│   ├── parser/            # (Coming soon) HTML/CSS/JS parsing components
│   ├── js-engine/         # (Coming soon) JavaScript execution engine
│   ├── privacy/           # (Coming soon) Privacy enhancement system
│   ├── security/          # (Coming soon) Security enforcement system
│   └── ui/                # (Coming soon) User interface components
└── tests/                 # Integration tests
```

## Contributing

We welcome contributions that align with our vision of uncompromising privacy and security. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the [MIT License](LICENSE)

## Acknowledgments

Inspired by those who believe in digital autonomy and the right to privacy in an increasingly surveilled digital landscape.

See [DESIGN.md](DESIGN.md) for comprehensive information about project architecture and philosophy.

## Testing & Security

### Security-First Development

Citadel is built with a security-first mindset. We use several approaches to ensure our code is robust:

#### Comprehensive Testing

```bash
# Run the standard test suite
cargo test

# Run integration tests
cargo test --test '*'
```

#### Continuous Fuzzing

We employ aggressive fuzzing to discover and fix security issues before they reach production:

```bash
# Switch to nightly Rust (required for fuzzing)
rustup default nightly

# Install LLVM tools component
rustup component add llvm-tools-preview

# Install cargo-fuzz (required for fuzzing)
cargo install cargo-fuzz

# Generate corpus for more effective fuzzing
./fuzz/scripts/generate_corpus.sh

# Run all fuzzers with enhanced memory checking
./fuzz/scripts/run_all_fuzzers.sh

# Or run individual fuzzers with dictionaries
cd fuzz && cargo fuzz run dns_resolver corpus/dns_resolver -dict=dictionaries/dns.dict
```

Each fuzzer uses dictionaries and corpus files specifically designed to test edge cases and potential security vulnerabilities. Our CI automatically runs these fuzzers on every commit to ensure continuous security testing.

See [FUZZING.md](FUZZING.md) for our complete fuzzing strategy and details on how to contribute to our security efforts.

Any fuzzing failures are considered critical build failures and must be addressed immediately to maintain our security standards.
