# 𝗖𝗜𝗧𝗔𝗗𝗘𝗟 𝗕𝗥𝗢𝗪𝗦𝗘𝗥

## Privacy is not a feature. It's the entire fucking point.

A from-scratch browser engine engineered to obliterate tracking, crush fingerprinting, and restore user sovereignty with extreme technical precision.

## ⚠️ ALPHA SOFTWARE DISCLAIMER ⚠️

**Version: 0.0.2-alpha**

🚨 **THIS IS ALPHA SOFTWARE - USE AT YOUR OWN RISK** 🚨

- **NOT FOR PRODUCTION USE**: This software is experimental and under active development
- **EXPECT BUGS**: Features may not work as expected, crash, or behave unpredictably
- **DATA LOSS POSSIBLE**: Do not rely on this software for critical browsing or data storage
- **SECURITY VULNERABILITIES**: Alpha software may contain security flaws - do not use for sensitive activities
- **NO WARRANTY**: This software is provided "as is" without any warranty of any kind
- **BREAKING CHANGES**: APIs, features, and functionality may change dramatically between releases
- **NOT RESPONSIBLE**: We are not responsible if this software causes any issues, including but not limited to:
  - System crashes or instability
  - Data corruption or loss
  - Security breaches
  - Being eaten by a Gru
  - Spontaneous combustion of your computer
  - Temporal paradoxes
  - Existential crises
  - Or any other unforeseen consequences

**By using this software, you acknowledge that you understand these risks and use it entirely at your own discretion.**

![image](https://github.com/user-attachments/assets/facfd73d-6552-4f11-9685-fd142b7ed33d)

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
- ✅ In-house HTTPS client over rustls — no reqwest/hyper/native-tls on the page-fetch path
- ✅ Uniform, browser-like request shape — every user emits the *same* bytes (uniformity, **not** randomization)
- ✅ Tracking parameter removal from URLs
- ✅ Zero-knowledge tab rendering: untrusted HTML is parsed, sanitized, and laid out inside an AES-256-GCM-encrypted isolation boundary; the host only ever paints a sanitized display list
- ✅ **CitadelJSEngine** — Boa (pure-Rust) core inside a from-scratch privacy binding cage; JavaScript is explicit opt-in and runs inside the ZK boundary:
  - ✅ Single normalized identity (navigator/screen) — uniform across users
  - ✅ Clamped `performance.now()` — kills high-resolution timing fingerprints
  - ✅ Default-deny network exfil gate (fetch / XHR / WebSocket / sendBeacon / WebRTC) — closes the WebRTC local-IP leak
  - ✅ Ephemeral, first-party-isolated storage — structurally supercookie-proof
  - ✅ Untrusted-JS DoS bounds (loop-iteration and recursion limits)
- 🔄 DOM bindings + canvas/WebGL/audio fingerprint poisoning (active work)
- 🔄 Uniform TLS ClientHello (JA3/JA4), ECH + encrypted DNS (DoH/DoT)

## 𝗢𝘂𝗿 𝗠𝗶𝘀𝘀𝗶𝗼𝗻

Citadel isn't just a browser engine—it's a declaration of digital human rights. We're built for those who understand that privacy is not a luxury—it's a fundamental necessity.

In an era where users are treated as products and their data harvested without consent, we're taking a scorched-earth approach to browser privacy that makes surveillance capitalism weep.

Open-source. Uncompromising. Zero-tracking. Future-proof.

### 𝗦𝗲𝗰𝘂𝗿𝗶𝘁𝘆 𝗮𝘀 𝗮 𝗟𝗶𝗳𝗲𝘀𝘁𝘆𝗹𝗲
Privacy isn't just a feature. It's the entire point of our existence.

### 𝗩𝗮𝗻𝗴𝘂𝗮𝗿𝗱 𝗼𝗳 𝗔𝘂𝘁𝗼𝗻𝗼𝗺𝘆
Zero compromise on user control over their digital experience.

### 𝗨𝘀𝗲𝗿 𝗦𝗼𝘃𝗲𝗿𝗲𝗶𝗴𝗻𝘁𝘆
Users control their data with no forced third-party dependencies.

## 𝗣𝗿𝗶𝘃𝗮𝗰𝘆 𝗘𝗻𝗴𝗶𝗻𝗲𝗲𝗿𝗶𝗻𝗴

### 𝗧𝗿𝗮𝗰𝗸𝗲𝗿 𝗡𝗲𝘂𝘁𝗿𝗮𝗹𝗶𝘇𝗮𝘁𝗶𝗼𝗻
Dynamic blocklists + machine learning detection that annihilates even the most persistent tracking attempts.

### 𝗔𝗻𝘁𝗶-𝗙𝗶𝗻𝗴𝗲𝗿𝗽𝗿𝗶𝗻𝘁𝗶𝗻𝗴
A single normalized identity served to *every* user (uniformity, not randomization), high-resolution timer clamping, and a default-deny hardware/network API surface — you blend into the crowd instead of standing out. Canvas/WebGL/audio readback poisoning is in progress.

### 𝗛𝗮𝗿𝗱𝗰𝗼𝗿𝗲 𝗦𝗮𝗻𝗱𝗯𝗼𝘅𝗶𝗻𝗴
Per-site process isolation with strict content security policies and cross-site data access prevention.

### 𝗡𝗲𝘁𝘄𝗼𝗿𝗸 𝗣𝗿𝗶𝘃𝗮𝗰𝘆
User-controlled DNS resolution and a uniform, browser-like request shape — every Citadel user emits the same bytes, so the network fingerprint identifies the software, not the individual.

### 𝗖𝗼𝗼𝗸𝗶𝗲 𝗖𝗼𝗻𝘁𝗿𝗼𝗹
First-party isolation, automatic expiration, and granular user-controlled storage permissions.

### 𝗨𝘀𝗲𝗿 𝗦𝗼𝘃𝗲𝗿𝗲𝗶𝗴𝗻𝘁𝘆
Granular privacy controls, transparent data logs, and one-click protection escalation.

## 𝗔𝗿𝗰𝗵𝗶𝘁𝗲𝗰𝘁𝘂𝗿𝗮𝗹 𝗖𝗼𝗺𝗽𝗼𝗻𝗲𝗻𝘁𝘀

Citadel is built with these core components, all implemented with Rust's strong encapsulation features:

### 𝗣𝗮𝗿𝘀𝗲𝗿 𝗟𝗮𝘆𝗲𝗿
- Weaponized HTML/CSS/JS parsing with injection-proof design and malformed input termination protocols
- Attack surface minimization through careful API implementation and selective standard support
- Security-first input handling designed to fail closed rather than open when encountering edge cases

### 𝗝𝗮𝘃𝗮𝗦𝗰𝗿𝗶𝗽𝘁 𝗘𝗻𝗴𝗶𝗻𝗲 — 𝗖𝗶𝘁𝗮𝗱𝗲𝗹𝗝𝗦𝗘𝗻𝗴𝗶𝗻𝗲
- **Boa core (pure Rust, no native attack surface)** wrapped in a from-scratch **privacy binding cage** — a bare engine exposes no browser/DOM/network/storage APIs, so the page sees only what we deliberately, defensively bind. The binding layer *is* the product; we do not re-derive ECMAScript.
- **Explicit opt-in**: JavaScript is OFF by default and runs only inside the per-tab zero-knowledge boundary.
- **Normalized identity** (uniform navigator/screen) and **clamped `performance.now()`** kill identity and timing fingerprints.
- **Default-deny network exfil gate** (fetch / XHR / WebSocket / sendBeacon / WebRTC) — no request leaves the cage, and the WebRTC local-IP leak is closed.
- **Ephemeral, first-party-isolated storage** — structurally incapable of being a persistent supercookie.
- **Untrusted-JS DoS bounds** (loop-iteration and recursion limits) so a hostile script cannot hang the renderer.
- 🔄 DOM bindings and canvas/WebGL/audio fingerprint poisoning are the active work.

### 𝗡𝗲𝘁𝘄𝗼𝗿𝗸𝗶𝗻𝗴 𝗟𝗮𝘆𝗲𝗿
- In-house HTTPS client over rustls (no reqwest/hyper/native-tls) with bundled Mozilla roots — small, HTTPS-only, size-bounded, and fail-closed. We never hand-roll crypto.
- User-controlled DNS resolution with local cache by default and no reliance on third-party DNS services
- Uniform, browser-like request shape — identical for every user, so the HTTP/TLS fingerprint identifies the *software*, not the individual (per-connection randomization would make you more unique, not less)
- 🔄 Roadmap: uniform TLS ClientHello (JA3/JA4), ECH + encrypted DNS (DoH/DoT) to stop plaintext SNI/DNS leakage

### 𝗨𝘀𝗲𝗿 𝗜𝗻𝘁𝗲𝗿𝗳𝗮𝗰𝗲
- Granular privacy controls that give users complete visibility and authority over their data
- Transparent data transmission logs showing exactly what information websites are attempting to access
- Vertical tabs by default for improved usability and efficient screen space utilization

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

- **Header Management**: A fixed, browser-like header set/order/casing — identical for every user
- **Uniformity, not randomization**: every Citadel user emits the same request bytes, so per-user fingerprints collapse (per-connection jitter would make you *more* unique)
- **User-Agent**: a single normalized User-Agent, byte-identical to the JS `navigator.userAgent` (a mismatch would itself be a fingerprint)
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

### Platform Support

Citadel Browser is primarily designed for **macOS**, with limited Linux support for unit testing and development purposes.

- **macOS**: Primary platform with full feature support
- **Linux**: Limited support for development and testing only

### Prerequisites

- Rust and Cargo (latest stable)
- macOS 11.0+ (Big Sur or newer)
- Xcode Command Line Tools
- For Linux development/testing only:
  - pkg-config
  - Fontconfig dev packages (for the iced GUI)
  - (No OpenSSL: TLS is rustls, pure Rust)

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
│   │   │   ├── http.rs    # In-house HTTPS client over rustls (uniform request shape)
│   │   │   ├── request.rs # Privacy-enhancing HTTP requests
│   │   │   ├── response.rs # HTTP response handling
│   │   │   ├── connection.rs # Secure connection management
│   │   │   ├── resource.rs # Resource fetching
│   │   │   ├── error.rs   # Error handling
│   │   │   └── lib.rs     # Library entry point
│   │   ├── examples/      # Usage examples
│   │   └── tests/         # Integration tests
│   ├── parser/            # HTML/CSS/JS parsing components with integrated JS engine
│   │   ├── src/js/        # JavaScript engine integration (Boa, pure Rust)
│   ├── privacy/           # (Coming soon) Privacy enhancement system
│   ├── security/          # (Coming soon) Security enforcement system
│   └── ui/                # (Coming soon) User interface components
└── tests/                 # Integration tests
```

## 𝗥𝗼𝗮𝗱𝗺𝗮𝗽

### 1. Alpha Stage
Core engine implementation with fundamental privacy protections:
- Parser and JavaScript engine with tracking API removal
- Basic networking layer with HTTPS enforcement
- Initial fingerprinting protection implementation

### 2. Beta Stage
Enhanced protection and performance improvements:
- Machine learning tracker detection
- Advanced fingerprinting countermeasures
- User interface with privacy controls and real-time tracking visualization

### 3. Release Stage
Fully-featured browser with comprehensive privacy protection:
- Complete engine integration with all privacy modules
- Cross-platform support (desktop and mobile)
- Extension API with strict privacy requirements

### 4. Future Expansion
Beyond the horizon:
- Advanced threat intelligence integration
- Privacy-preserving cloud syncing (optional)
- Enhanced OS integration with system-wide privacy controls

## 𝗝𝗼𝗶𝗻 𝘁𝗵𝗲 𝗣𝗿𝗶𝘃𝗮𝗰𝘆 𝗥𝗲𝘃𝗼𝗹𝘂𝘁𝗶𝗼𝗻

Citadel is currently in early alpha. Help us build a more private, more secure web experience for everyone.

### Contributing

We welcome contributions that align with our vision of uncompromising privacy and security. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the [MIT License](LICENSE)

## Acknowledgments

Inspired by those who believe in digital autonomy and the right to privacy in an increasingly surveilled digital landscape.

See [DESIGN.md](DESIGN.md) for comprehensive information about project architecture and philosophy.

---

© 2025 Citadel Browser. Open-source. Uncompromising. Zero-tracking.

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
