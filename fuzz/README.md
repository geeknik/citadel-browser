# Citadel Browser Security-Focused Fuzz Testing

This directory contains comprehensive security-focused fuzz testing infrastructure for Citadel Browser, designed to discover attack vectors and validate security protection mechanisms.

## Security-First Fuzzing Approach

Our fuzzing strategy is built around **attack vector discovery** and **security boundary validation**, going beyond traditional crash detection to specifically test:

- **Privacy protection bypass attempts**
- **Security boundary violations**
- **Anti-fingerprinting mechanism bypasses**
- **JavaScript sandbox escape vectors**
- **Network security boundary enforcement**
- **Content Security Policy (CSP) bypasses**

## Available Security Fuzzers

### Anti-Fingerprinting Bypass Fuzzer
**Target**: `anti_fingerprinting_bypass`
**Location**: `fuzz_targets/anti_fingerprinting_bypass.rs`

Tests anti-fingerprinting protection mechanisms against bypass attempts:
- Canvas fingerprinting protection
- WebGL fingerprinting protection
- Audio fingerprinting protection
- Navigator API spoofing
- Screen information protection
- Font enumeration blocking
- Hardware information clamping

**Key Test Areas**:
- Consistency analysis attacks
- Statistical fingerprinting analysis
- Cross-domain correlation attempts
- Timing-based fingerprinting bypass

### CSP Policy Bypass Fuzzer
**Target**: `csp_policy_bypass`
**Location**: `fuzz_targets/csp_policy_bypass.rs`

Tests Content Security Policy parsing and enforcement:
- Script injection bypass attempts
- Style injection vectors
- Data URL abuse
- Import/export manipulation
- Nonce/hash bypass techniques
- Redirect chain exploitation

**Key Test Areas**:
- Inline script execution attempts
- External resource loading bypass
- Event handler injection
- JavaScript URL schemes
- SVG-based injection vectors

### JavaScript Sandbox Escape Fuzzer
**Target**: `js_sandbox_escape`
**Location**: `fuzz_targets/js_sandbox_escape.rs`

Tests JavaScript engine sandbox security:
- Constructor property manipulation
- Prototype chain traversal
- Global object access attempts
- Function constructor exploitation
- Error object stack manipulation
- Symbol manipulation attacks
- Proxy object exploitation

**Key Test Areas**:
- Sandbox boundary escape attempts
- Context manipulation vectors
- Memory manipulation attacks
- Prototype pollution attempts

### Network Boundary Security Fuzzer
**Target**: `network_boundary_fuzzer`
**Location**: `fuzz_targets/network_boundary_fuzzer.rs`

Tests network security boundaries and request sanitization:
- DNS rebinding attacks
- HTTP header injection
- Request smuggling attempts
- Cross-origin bypass vectors
- SSRF (Server-Side Request Forgery) attempts
- Protocol downgrade attacks
- Cache poisoning vectors

**Key Test Areas**:
- Private IP access prevention
- DNS manipulation resistance
- Header injection blocking
- Request validation bypass

### Privacy Protection Validation Fuzzer
**Target**: `privacy_protection_fuzzer`
**Location**: `fuzz_targets/privacy_protection_fuzzer.rs`

Validates privacy protection mechanisms:
- Tracking parameter removal
- Metadata scrubbing
- Cookie isolation
- Storage isolation
- DNS leak prevention
- Header randomization

**Key Test Areas**:
- Data extraction prevention
- Cross-context correlation blocking
- Behavioral analysis resistance
- Side-channel information leakage

### Security Campaign Runner
**Target**: `security_campaign_runner`
**Location**: `fuzz_targets/security_campaign_runner.rs`

Orchestrates comprehensive security testing campaigns:
- Systematic attack vector testing
- Security boundary validation
- Privacy protection verification
- Security invariant checking
- Performance constraint validation

## Core Functionality Fuzzers

### HTML Parser Security Fuzzer
**Target**: `html_parser`
**Location**: `fuzz_targets/html_parser.rs`

Security-focused HTML parsing tests:
- Script injection attempts
- Entity parsing vulnerabilities
- Deep nesting attacks
- Memory exhaustion prevention
- Malformed input handling

### Other Core Fuzzers
- `css_parser`: CSS parsing security
- `js_parser`: JavaScript parsing security
- `dns_resolver`: DNS resolution security
- `network_request`: Network request security
- `url_parser`: URL parsing security

## Security-Focused Dictionaries

### Anti-Fingerprinting Dictionary
**File**: `dictionaries/anti_fingerprinting.dict`
- Canvas fingerprinting vectors
- WebGL parameter extraction
- Audio context fingerprinting
- Navigator API access patterns
- Screen and hardware detection

### CSP Bypass Dictionary
**File**: `dictionaries/csp_bypass.dict`
- Script injection techniques
- Data URL schemes
- SVG-based vectors
- Import/export manipulation
- Encoding evasion techniques

### JavaScript Sandbox Escape Dictionary
**File**: `dictionaries/js_sandbox_escape.dict`
- Constructor access patterns
- Prototype manipulation
- Global object access
- Function creation methods
- Obfuscation techniques

### Network Security Dictionary
**File**: `dictionaries/network_security.dict`
- DNS rebinding vectors
- IP address encoding variants
- SSRF bypass techniques
- Header injection patterns
- Protocol confusion vectors

### Privacy Protection Dictionary
**File**: `dictionaries/privacy_protection.dict`
- Tracking parameter patterns
- Fingerprinting API calls
- Storage access attempts
- Metadata extraction vectors

## Running Security Campaigns

### Quick Security Campaign
```bash
# Run comprehensive security campaign (1 hour)
./scripts/run_security_campaign.sh
```

### Customized Campaign
```bash
# Set campaign duration and worker count
CAMPAIGN_DURATION=7200 MAX_WORKERS=8 ./scripts/run_security_campaign.sh
```

### Individual Security Fuzzer
```bash
# Run specific security fuzzer
cargo fuzz run anti_fingerprinting_bypass -- -max_total_time=3600
cargo fuzz run csp_policy_bypass -- -max_total_time=3600
cargo fuzz run js_sandbox_escape -- -max_total_time=3600
```

## Security Campaign Configuration

The security campaign runner supports extensive configuration:

```bash
# Environment variables
export CAMPAIGN_DURATION=3600      # Campaign duration in seconds
export MAX_WORKERS=4               # Parallel fuzzer workers
export FAILURE_TOLERANCE=5         # Max failures before abort
export COVERAGE_TARGET=80          # Target coverage percentage
```

## Security Invariants

Our fuzzing infrastructure verifies critical security invariants:

1. **No Script Execution**: JavaScript should not execute in sandboxed contexts
2. **No Fingerprinting Leakage**: No fingerprinting data should leak to untrusted contexts
3. **No Cross-Origin Access**: Cross-origin data access should be blocked
4. **No Privilege Escalation**: Sandbox escapes should be prevented
5. **No Data Exfiltration**: Unauthorized data transmission should be blocked

## Attack Vector Coverage

The fuzzing campaign systematically tests:

### Web Security Attack Vectors
- XSS (Cross-Site Scripting)
- CSRF (Cross-Site Request Forgery)
- Clickjacking
- Content injection
- Path traversal

### Network Security Attack Vectors
- DNS rebinding
- SSRF (Server-Side Request Forgery)
- Request smuggling
- Header injection
- Protocol downgrade

### Privacy Attack Vectors
- Fingerprinting bypass attempts
- Tracking parameter injection
- Cross-context correlation
- Behavioral analysis
- Side-channel attacks

### JavaScript Security Attack Vectors
- Sandbox escape attempts
- Prototype pollution
- Constructor manipulation
- Context confusion
- Memory corruption

## Security Metrics and Reporting

### Campaign Reports
- Detailed vulnerability reports
- Attack vector coverage analysis
- Security boundary validation results
- Performance impact assessment
- Remediation recommendations

### Real-time Monitoring
- Security-relevant crash detection
- Attack vector execution tracking
- Privacy protection validation
- Performance constraint monitoring

## Integration with CI/CD

### Security Gates
- **Zero Critical Vulnerabilities**: Build fails if critical vulnerabilities found
- **Coverage Requirements**: Minimum attack vector coverage required
- **Performance Constraints**: Security protections must not exceed performance limits

### Automated Security Testing
```yaml
# GitHub Actions integration
- name: Run Security Fuzzing Campaign
  run: |
    export CAMPAIGN_DURATION=1800  # 30 minutes for CI
    export MAX_WORKERS=2
    ./fuzz/scripts/run_security_campaign.sh
```

## Threat Model Coverage

Our fuzzing targets the specific threats outlined in `DESIGN.md`:

1. **Malicious Websites**: Script injection, fingerprinting, tracking
2. **Corporate Tracking**: Data collection, behavioral analysis
3. **Network Surveillance**: DNS manipulation, traffic analysis
4. **Fingerprinting Attempts**: Device/browser characteristic extraction
5. **Metadata Exploitation**: Information leakage through side channels

## Development Guidelines

### Adding Security Fuzzers
1. **Identify Attack Surface**: Focus on security-critical components
2. **Define Attack Vectors**: Enumerate specific attack techniques
3. **Create Test Vectors**: Develop comprehensive attack payloads
4. **Implement Validation**: Verify security protections work
5. **Add Invariants**: Define security properties that must hold

### Security Fuzzer Best Practices
1. **Attack Vector Focus**: Target specific security vulnerabilities
2. **Boundary Testing**: Test security boundary enforcement
3. **Protection Validation**: Verify security mechanisms work correctly
4. **Performance Awareness**: Ensure security doesn't break functionality
5. **Comprehensive Coverage**: Test all identified attack vectors

## Platform Support

- **Linux**: Native fuzzing with full security features
- **macOS**: Docker-based fuzzing with security monitoring
- **Windows**: Docker-based fuzzing (limited security features)

## Security Alert System

When security-relevant crashes are found:
1. **Immediate Alert**: Security alert file generated
2. **Impact Assessment**: Vulnerability severity analysis
3. **Reproduction Cases**: Minimal test cases for debugging
4. **Fix Verification**: Re-run campaign to verify fixes

## Results and Artifacts

### Directory Structure
```
fuzz/results/
├── security_campaign_YYYYMMDD_HHMMSS.json    # Campaign report
├── campaign_summary.txt                       # Human-readable summary
├── SECURITY_ALERT.txt                        # Security alerts (if any)
├── anti_fingerprinting_bypass/               # Fuzzer-specific results
├── csp_policy_bypass/
├── js_sandbox_escape/
├── network_boundary_fuzzer/
└── privacy_protection_fuzzer/
```

### Crash Analysis
Security-relevant crashes are automatically analyzed for:
- **Exploitability**: Can the crash be turned into an exploit?
- **Privacy Impact**: Does the crash leak sensitive information?
- **Security Boundary**: Which security boundary was violated?
- **Attack Vector**: Which attack technique triggered the crash?

## Contributing Security Tests

When contributing new security tests:
1. **Threat Analysis**: Identify specific threats to address
2. **Attack Modeling**: Model realistic attack scenarios
3. **Test Implementation**: Create comprehensive test cases
4. **Documentation**: Document attack vectors and expected behavior
5. **Integration**: Integrate with security campaign runner

## Security Contact

For security-related fuzzing issues:
- Create security-focused GitHub issues
- Tag with `security` and `fuzzing` labels
- Include attack vector details and impact assessment
- Provide reproduction cases when possible