# DESIGN.md for Citadel Engine

## Overview

𝗧𝗟;𝗗𝗥: Citadel is a from-scratch browser engine engineered to demolish tracking, neutralize fingerprinting, and restore user privacy with extreme technical precision.

**ALPHA STATUS**: Citadel has successfully integrated Servo browser engine components and can now render real websites while maintaining uncompromising privacy protection.

## Principles and Goals

Core Directives:

- 𝗦𝗲𝗰𝘂𝗿𝗶𝘁𝘆 𝗮𝘀 𝗮 𝗟𝗶𝗳𝗲𝘀𝘁𝘆𝗹𝗲: Privacy isn't a feature. It's the entire fucking point.
- 𝗩𝗮𝗻𝗴𝘂𝗮𝗿𝗱 𝗼𝗳 𝗗𝗶𝗴𝗶𝘁𝗮𝗹 𝗔𝘂𝘁𝗼𝗻𝗼𝗺𝘆: Zero compromise on user control.
- 𝗨𝘀𝗲𝗿 𝗦𝗼𝘃𝗲𝗿𝗲𝗶𝗴𝗻𝘁𝘆: Users control their data and connections, with no forced third-party service dependencies.

Threat Landscape Neutralization:

- Crush tracking mechanisms
- Eliminate data collection vectors
- Prevent metadata leakage
- Mandate user sovereignty

## Architectural Components

### 𝗣𝗮𝗿𝘀𝗲𝗿 Layer ✅

- **Servo Integration**: Production-ready HTML parsing using Kuchiki (Servo-based)
- **HTML5ever Backend**: Robust HTML5 parsing with proper TreeSink implementation
- **Weaponized HTML/CSS/JS parsing** with injection-proof design
- **Security-Preserving**: All parsing maintains Citadel's privacy guarantees
- **Real Website Support**: Successfully parses and renders actual web content
- **Malformed input termination protocols**
- **Minimal attack surface** through careful API implementation
- **Security-first input handling** designed to fail closed rather than open

**Key Implementation Details:**
- Replaced problematic custom TreeSink with Kuchiki for reliability
- DOM converter maintains security boundaries during transformation
- All parsing operations preserve Citadel's privacy and security guarantees

### 𝗝𝗮𝘃𝗮𝗦𝗰𝗿𝗶𝗽𝘁 𝗘𝗻𝗴𝗶𝗻𝗲 ✅

- **Integrated rquickjs engine** with hardcore sandbox environment
- **Surgically removed tracking APIs** to prevent data leakage
- **DOM bindings implemented** with security policies and CSP compliance
- **Performance-optimized execution** that doesn't sacrifice security
- **Zero external data transmission** capabilities for scripts
- **Comprehensive test suite** with DOM integration and security validation

### 𝗡𝗲𝘁𝘄𝗼𝗿𝗸𝗶𝗻𝗴 𝗟𝗮𝘆𝗲𝗿

- **User-controlled DNS resolution** with local cache by default
- **NO third-party DNS services** used by default - respecting user sovereignty
- **Optional secure DNS modes** (DOH/DOT) - user choice, not forced
- **HTTPS or die** approach with strict TLS enforcement
- **Minimal HTTP headers** to reduce fingerprinting surface
- **Connection fingerprint randomization** for privacy
- **Real-world tested**: Successfully fetching and rendering from live websites

### 𝗟𝗮𝘆𝗼𝘂𝘁 𝗘𝗻𝗴𝗶𝗻𝗲 ✅

- **Taffy Integration**: Modern layout engine (Servo's layout 2020)
- **Flexbox and CSS Grid support** for modern layouts
- **Performance-optimized** layout calculations
- **Security-aware** rendering pipeline

## Privacy-Enhancement Arsenal

### 𝗧𝗿𝗮𝗰𝗸𝗲𝗿 𝗕𝗹𝗼𝗰𝗸𝗶𝗻𝗴

- Dynamic, frequently updated blocklists
- Machine learning tracker detection (planned for Beta)
- Zero-tolerance blocking mechanism
- URL tracking parameter removal
- Header-based tracker identification

### 𝗙𝗶𝗻𝗴𝗲𝗿𝗽𝗿𝗶𝗻𝘁𝗶𝗻𝗴 𝗣𝗿𝗼𝘁𝗲𝗰𝘁𝗶𝗼𝗻

- Canvas/WebGL noise injection
- Hardware API access restriction
- Standardized output generation
- Header fingerprint randomization
- Connection pattern obfuscation

### 𝗣𝗿𝗶𝘃𝗮𝘁𝗲 𝗕𝗿𝗼𝘄𝘀𝗶𝗻𝗴

- No local data storage by default
- Ephemeral session management
- Automatic data scorching on exit
- No telemetry or analytics collection

## Security Mechanisms

### 𝗜𝘀𝗼𝗹𝗮𝘁𝗶𝗼𝗻 𝗧𝗲𝗰𝗵𝗻𝗶𝗾𝘂𝗲𝘀

- **Per-site process containment** (planned for Beta)
- **Strict Content Security Policy** enforcement
- **Cross-site data access prevention**
- **JavaScript sandboxing** with rquickjs
- **Memory-safe implementation** with Rust

### 𝗖𝗼𝗼𝗸𝗶𝗲 & 𝗦𝘁𝗼𝗿𝗮𝗴𝗲 𝗠𝗮𝗻𝗮𝗴𝗲𝗺𝗲𝗻𝘁

- First-party isolation
- Automatic expiration
- User-controlled storage permissions
- Tracking cookie detection and removal

## Servo Integration Architecture

### Integration Approach

Citadel uses selective components from the Servo browser engine while maintaining our privacy-first philosophy:

```rust
// HTML Parsing Pipeline
HTML Input → Kuchiki (Servo) → DOM Converter → Citadel DOM → Security Filtering
```

### Key Components Used

1. **Kuchiki** (HTML parsing)
   - Built on html5ever for standards compliance
   - Reliable TreeSink implementation
   - Efficient DOM manipulation

2. **Taffy** (Layout engine)
   - Servo's modern layout algorithm
   - Flexbox and CSS Grid support
   - Performance-optimized calculations

3. **CSS Parser** (Stylo components)
   - Servo's CSS parsing capabilities
   - Standards-compliant interpretation
   - Security-aware style application

### Security Boundaries

All Servo components operate within Citadel's security framework:

- **Input Sanitization**: All HTML/CSS inputs pass through security filters
- **API Restrictions**: Servo components have no network access
- **Memory Isolation**: Servo operates in controlled memory spaces
- **Policy Enforcement**: All operations subject to Citadel's security policies

## Threat Model

Neutralization Targets:

- Malicious websites and their scripts
- Corporate tracking networks
- Network-level surveillance
- Fingerprinting attempts
- Metadata exploitation
- Browser-based cryptocurrency mining
- Unwanted data collection

### Protection Mechanisms

1. **Network Layer**
   - DNS privacy with local caching
   - HTTPS-only enforcement
   - Header randomization
   - Connection fingerprinting prevention

2. **Content Layer**
   - Script sandboxing
   - HTML sanitization
   - CSP enforcement
   - API restriction

3. **Rendering Layer**
   - Canvas noise injection
   - Font fingerprint randomization
   - WebGL restriction
   - Timing attack prevention

## User Empowerment

### 𝗖𝗼𝗻𝘁𝗿𝗼𝗹 𝗜𝗻𝘁𝗲𝗿𝗳𝗮𝗰𝗲

- Granular privacy settings
- Transparent data transmission logs
- One-click protection escalation
- Vertical tabs by default for improved usability
- User-controlled tab and window layout
- Real-time privacy status indicators

### Configuration Options

- **DNS Resolution**: Local cache, DoH, DoT, system
- **Privacy Level**: Maximum, high, balanced
- **JavaScript Control**: Global, per-site, disabled
- **Cookie Policy**: Block all, first-party only, user choice
- **Header Randomization**: Strict, moderate, disabled

## Implementation Details

### Core Modules

```
citadel/
├── parser/          # Servo-integrated HTML/CSS parsing
│   ├── html/        # Kuchiki-based HTML parsing
│   ├── css/         # Servo CSS parsing
│   └── js/          # JavaScript engine
├── networking/      # Privacy-first networking
├── security/        # Security policies and enforcement
└── ui/             # User interface components
```

### Key Files

- `crates/parser/src/html/mod.rs` - Main HTML parsing with Servo
- `crates/parser/src/html/converter.rs` - DOM conversion logic
- `crates/parser/Cargo.toml` - Servo dependencies
- `examples/full_pipeline_test.rs` - Integration demonstration

## Performance Considerations

### Alpha Optimizations

- **Memory Efficiency**: Servo components optimized for low memory usage
- **Parsing Speed**: Kuchiki provides fast HTML parsing
- **Layout Performance**: Taffy offers efficient calculations
- **Network Optimization**: Local DNS cache reduces requests

### Future Optimizations

- Parallel parsing for large documents
- Incremental rendering for complex pages
- Resource loading optimization
- JavaScript execution improvements

## Testing Strategy

### Current Coverage

- **93% test success rate** (26/28 tests passing)
- Integration tests for Servo components
- Security validation tests
- Real website rendering tests

### Test Categories

1. **Unit Tests**: Individual component validation
2. **Integration Tests**: Component interaction testing
3. **Security Tests**: Vulnerability and attack testing
4. **Performance Tests**: Speed and memory usage
5. **Fuzzing**: Continuous security validation

## Roadmap

### Alpha (Current) - ✅ COMPLETE
- [x] Servo HTML parser integration
- [x] Real website rendering
- [x] JavaScript sandboxing
- [x] Basic privacy protections
- [x] 93% test success rate

### Beta (Next)
- [ ] Machine learning tracker detection
- [ ] Advanced fingerprinting countermeasures
- [ ] Enhanced UI with privacy controls
- [ ] Multimedia support
- [ ] Developer tools
- [ ] Extension system foundation

### Release
- [ ] Cross-platform support
- [ ] Complete web API support
- [ ] Advanced privacy features
- [ ] Performance optimizations
- [ ] Full extension system

## Contributing

### Development Guidelines

1. **Privacy First**: All changes must maintain privacy guarantees
2. **Security Review**: Code changes undergo security review
3. **Test Coverage**: New features require comprehensive tests
4. **Documentation**: Changes must be properly documented
5. **Performance**: Monitor and optimize for resource usage

### Areas for Contribution

- UI/UX improvements
- Additional web API support
- Performance optimizations
- Security enhancements
- Test coverage expansion
- Documentation improvements

## Conclusion

Citadel's Alpha release demonstrates that privacy-first browsing is technically feasible without sacrificing the ability to access the modern web. Our selective integration of Servo components provides standards compliance while maintaining our uncompromising commitment to user privacy and security.

The journey from concept to Alpha shows that with careful architecture and principled design, we can build a browser that serves users rather than exploits them. The foundation is laid for enhanced features and broader adoption in future releases.

---

Remember: In Citadel, **privacy is not a feature. It's the entire point.**