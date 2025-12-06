# Citadel Browser Documentation

Welcome to the Citadel Browser documentation hub. This directory contains comprehensive documentation about the project, from design philosophy to development guidelines.

## 📚 Documentation Structure

### 🚀 [Releases](./releases/)
Contains release information, version history, and release notes.
- **[CHANGELOG.md](./releases/CHANGELOG.md)** - Complete version history and changelog following semantic versioning
- **[ALPHA_RELEASE_NOTES.md](./releases/ALPHA_RELEASE_NOTES.md)** - Alpha release notes and current status

### 🏗️ [Design](./design/)
Contains architectural documentation and design philosophy.
- **[DESIGN.md](./design/DESIGN.md)** - Comprehensive architecture documentation and project philosophy

### 🛠️ [Development](./development/)
Development-related documentation, guidelines, and processes.
- **[CONTRIBUTING.md](./development/CONTRIBUTING.md)** - Contribution guidelines and development workflow
- **[FUZZING.md](./development/FUZZING.md)** - Security fuzzing strategy and guidelines

## 🚀 Quick Start

### For Users
- **Project Overview**: See the main [README.md](../README.md) in the root directory
- **Current Status**: Check [Alpha Release Notes](./releases/ALPHA_RELEASE_NOTES.md) for what's available
- **Installation Instructions**: Available in the main [README.md](../README.md)

### For Developers
- **Getting Started**: See [CONTRIBUTING.md](./development/CONTRIBUTING.md)
- **Architecture**: Understand the project through [DESIGN.md](./design/DESIGN.md)
- **Security**: Learn about our security approach in [FUZZING.md](./development/FUZZING.md)

### For Security Researchers
- **Security Philosophy**: [FUZZING.md](./development/FUZZING.md) outlines our security approach
- **Vulnerability Reporting**: Details in [CONTRIBUTING.md](./development/CONTRIBUTING.md)

## 📋 Project Status

**Current Version**: 0.1.0-alpha (Servo Integration Release)

Citadel Browser is currently in Alpha with real website rendering capabilities through Servo integration. Key achievements include:

- ✅ **93% test success rate** (26/28 tests passing)
- ✅ **Servo HTML parser integration** with Kuchiki
- ✅ **Real website rendering** capabilities
- ✅ **Privacy-first networking** with HTTPS enforcement
- ✅ **JavaScript sandboxing** with rquickjs

## 🎯 Key Features

### Privacy & Security
- **Zero tracking by design**
- **Header fingerprint randomization**
- **DNS privacy with local cache**
- **HTTPS-only connections**
- **Content Security Policy enforcement**

### Technical Capabilities
- **Real-world website browsing**
- **JavaScript execution in sandboxed environment**
- **CSS parsing with Taffy layout engine**
- **Tab management and UI controls**
- **Vertical tabs by default**

## 🔗 Useful Links

- **GitHub Repository**: [citadel-browser/citadel-browser-rust](https://github.com/citadel-browser/citadel-browser-rust)
- **Issue Tracking**: [GitHub Issues](https://github.com/citadel-browser/citadel-browser-rust/issues)
- **Security Reports**: security@citadel-browser.org

## 📖 Documentation Philosophy

This documentation follows Citadel's core principle: **privacy is not a feature - it's the entire point**. All documentation is organized to:

1. **Be Accessible**: Clear organization for users, developers, and security researchers
2. **Maintain Transparency**: Open documentation about our privacy-first approach
3. **Support Contributions**: Comprehensive guides for meaningful contributions
4. **Ensure Security**: Security-first documentation to protect our users

---

© 2025 Citadel Browser. Open-source. Uncompromising. Zero-tracking.