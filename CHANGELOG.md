# Citadel Browser Changelog

All notable changes to Citadel Browser will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Machine learning tracker detection
- Advanced fingerprinting countermeasures
- Enhanced multimedia support
- Web developer tools
- Extension API with strict privacy requirements

## [0.1.0-alpha] - 2025-12-05

### MAJOR MILESTONE - SERVO INTEGRATION RELEASE 🎉

This marks Citadel Browser's first Alpha release with real website rendering capabilities!

### Added
- **Servo HTML Parser Integration**
  - Replaced problematic html5ever TreeSink with Kuchiki (Servo-based)
  - Complete HTML parsing module rewrite in `crates/parser/src/html/`
  - New DOM conversion logic in `converter.rs`
  - Production-ready HTML parsing with proper security filtering
  - Support for real-world websites including example.com

- **New Components**
  - `kuchiki` dependency for robust HTML parsing (v0.8)
  - HTML to Citadel DOM converter
  - `taffy` layout engine integration (v0.5)
  - Enhanced CSS parser with Servo components

- **Examples and Tests**
  - `examples/html_parse_test.rs` - Basic HTML parsing demonstration
  - `examples/full_pipeline_test.rs` - Complete pipeline with networking
  - Comprehensive test coverage achieving 93% pass rate (26/28 tests)
  - Integration tests for Servo components

- **Enhanced Privacy Features**
  - Maintained all privacy guarantees with Servo integration
  - Security filtering during DOM conversion
  - Preserved anti-fingerprinting measures
  - Header randomization works with real website connections

- **Documentation Updates**
  - Updated README with Alpha release status
  - Servo integration architecture documentation
  - New usage examples and getting started guide
  - Project structure reflects new capabilities

### Changed
- **HTML Parsing Architecture**
  - Moved from custom TreeSink implementation to Kuchiki
  - Simplified parsing pipeline while maintaining security
  - Better error handling and performance
  - Removed `crates/parser/src/html/tree_sink.rs`

- **Dependencies**
  - Updated html5ever to v0.27.0
  - Updated cssparser to v0.34
  - Updated selectors to v0.26
  - Added Servo-compatible dependencies

- **Testing**
  - Improved test coverage and reliability
  - Added integration tests for real website fetching
  - Enhanced security validation tests

### Fixed
- HTML5 parsing compliance issues
- DOM conversion edge cases
- Security policy enforcement during parsing
- Memory leaks in HTML parsing
- Network request handling for real websites

### Performance
- Faster HTML parsing with Kuchiki
- More efficient DOM operations
- Reduced memory usage during parsing
- Better error recovery for malformed HTML

### Security
- All HTML parsing maintains Citadel security guarantees
- Sanitization during DOM conversion
- No new attack surface introduced with Servo integration
- Preserved sandboxing for JavaScript execution

## [0.0.1-pre-alpha] - 2025-11-XX

### Initial Development Release

### Added
- Core architecture and component interfaces
- Basic unit tests for all components (100% pass rate)
- Continuous integration and testing infrastructure
- Vertical tabs implemented and enabled by default
- Tab bar visibility controls
- UI customization (theme settings, layout preferences)
- Privacy-first networking layer with LOCAL_CACHE as default DNS mode
- Privacy-preserving DNS resolver with local caching
- HTTPS-only secure connections
- Privacy-enhancing request headers
- Tracking parameter removal from URLs
- Header fingerprint randomization
- JavaScript engine integration with rquickjs
- DOM bindings for JavaScript execution
- Security policies for script execution and CSP compliance
- JavaScript engine tests with DOM integration (all passing)

### Known Issues
- HTML parsing with custom TreeSink implementation
- Limited real-world website support
- Basic layout engine capabilities
- Early development stage with incomplete features

---

## Version Information

- **Version 0.1.0-alpha**: First Alpha release with real website rendering
- **Version 0.0.1-pre-alpha**: Initial development snapshot
- **Next**: Beta targeting advanced privacy features and enhanced user experience

## Release Philosophy

Citadel Browser follows a measured approach to releases:

1. **Alpha**: Core functionality with real-world capabilities
2. **Beta**: Enhanced features and improved user experience
3. **Release**: Production-ready with comprehensive privacy protection

Each release maintains our uncompromising commitment to privacy and security.

## Support

For questions about this changelog or to report issues:
- GitHub Issues: [citadel-browser/citadel-browser-rust](https://github.com/citadel-browser/citadel-browser-rust)
- Documentation: See README.md and DESIGN.md

---

© 2025 Citadel Browser. Open-source. Uncompromising. Zero-tracking.