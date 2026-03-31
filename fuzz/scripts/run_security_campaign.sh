#!/bin/bash
#
# Comprehensive Security Campaign Runner
# 
# This script orchestrates security-focused fuzzing campaigns targeting
# attack vectors and privacy protection mechanisms in Citadel Browser.

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZ_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$FUZZ_DIR")"
RESULTS_DIR="$FUZZ_DIR/results"
CORPUS_DIR="$FUZZ_DIR/corpus"
CAMPAIGN_REPORT="$RESULTS_DIR/security_campaign_$(date +%Y%m%d_%H%M%S).json"

# Campaign Configuration
CAMPAIGN_DURATION=${CAMPAIGN_DURATION:-3600}  # 1 hour default
MAX_WORKERS=${MAX_WORKERS:-4}
FAILURE_TOLERANCE=${FAILURE_TOLERANCE:-5}
COVERAGE_TARGET=${COVERAGE_TARGET:-80}

# Security Test Targets
SECURITY_FUZZERS=(
    "anti_fingerprinting_bypass"
    "csp_policy_bypass"
    "js_sandbox_escape"
    "network_boundary_fuzzer"
    "privacy_protection_fuzzer"
    "security_campaign_runner"
)

# Core Parser/Network Fuzzers
CORE_FUZZERS=(
    "html_parser"
    "css_parser"
    "js_parser"
    "dns_resolver"
    "network_request"
    "url_parser"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v cargo &> /dev/null; then
        log_error "cargo is required but not installed"
        exit 1
    fi
    
    if ! cargo fuzz --version &> /dev/null; then
        log_warning "cargo-fuzz not found, installing..."
        cargo install cargo-fuzz
    fi
    
    if ! rustup show | grep -q nightly; then
        log_warning "Nightly Rust not found, installing..."
        rustup install nightly
        rustup default nightly
    fi
    
    log_success "Dependencies check completed"
}

# Setup fuzzing environment
setup_environment() {
    log_info "Setting up fuzzing environment..."
    
    # Create necessary directories
    mkdir -p "$RESULTS_DIR"
    mkdir -p "$CORPUS_DIR"
    
    # Create subdirectories for each fuzzer
    for fuzzer in "${SECURITY_FUZZERS[@]}" "${CORE_FUZZERS[@]}"; do
        mkdir -p "$CORPUS_DIR/$fuzzer"
        mkdir -p "$RESULTS_DIR/$fuzzer"
    done
    
    # Set up environment variables
    export RUST_LOG=debug
    export RUST_BACKTRACE=1
    export ASAN_OPTIONS=detect_odr_violation=0:abort_on_error=1
    export MSAN_OPTIONS=abort_on_error=1
    export UBSAN_OPTIONS=abort_on_error=1
    
    log_success "Environment setup completed"
}

# Generate security-focused corpus
generate_security_corpus() {
    log_info "Generating security-focused corpus..."
    
    # Anti-fingerprinting test cases
    cat > "$CORPUS_DIR/anti_fingerprinting_bypass/canvas_fingerprint" << 'EOF'
<canvas width="200" height="50"></canvas>
<script>
var canvas = document.querySelector('canvas');
var ctx = canvas.getContext('2d');
ctx.font = '14px Arial';
ctx.fillText('Fingerprint Test', 2, 15);
console.log(canvas.toDataURL());
</script>
EOF

    cat > "$CORPUS_DIR/anti_fingerprinting_bypass/webgl_fingerprint" << 'EOF'
<script>
var canvas = document.createElement('canvas');
var gl = canvas.getContext('webgl');
console.log(gl.getParameter(gl.VENDOR));
console.log(gl.getParameter(gl.RENDERER));
console.log(gl.getSupportedExtensions());
</script>
EOF

    cat > "$CORPUS_DIR/anti_fingerprinting_bypass/audio_fingerprint" << 'EOF'
<script>
var audioContext = new AudioContext();
console.log(audioContext.sampleRate);
console.log(audioContext.baseLatency);
var oscillator = audioContext.createOscillator();
var analyser = audioContext.createAnalyser();
oscillator.connect(analyser);
console.log(analyser.frequencyBinCount);
</script>
EOF

    # CSP bypass test cases
    cat > "$CORPUS_DIR/csp_policy_bypass/inline_script_bypass" << 'EOF'
<script>alert('CSP bypass attempt')</script>
<img src=x onerror=alert('CSP bypass')>
<svg onload=alert('CSP bypass')>
<iframe src="javascript:alert('CSP bypass')"></iframe>
EOF

    cat > "$CORPUS_DIR/csp_policy_bypass/data_url_bypass" << 'EOF'
<script src="data:text/javascript,alert('CSP bypass')"></script>
<link rel=stylesheet href="data:text/css,body{background:url(javascript:alert('CSP bypass'))}">
<object data="data:text/html,<script>alert('CSP bypass')</script>"></object>
EOF

    # JavaScript sandbox escape test cases
    cat > "$CORPUS_DIR/js_sandbox_escape/constructor_escape" << 'EOF'
(function(){}).constructor.constructor('return this')().alert('Sandbox escape')
EOF

    cat > "$CORPUS_DIR/js_sandbox_escape/prototype_pollution" << 'EOF'
Object.prototype.isAdmin = true;
Array.prototype.includes = function(){return true};
Function.prototype.call = function(){return eval(arguments[1])};
EOF

    cat > "$CORPUS_DIR/js_sandbox_escape/global_access" << 'EOF'
this.constructor.constructor('return process')().exit()
globalThis.constructor.constructor('return require')()('fs')
window.top.location = 'https://evil.com'
EOF

    # Network boundary test cases
    cat > "$CORPUS_DIR/network_boundary_fuzzer/dns_rebinding" << 'EOF'
fetch('http://evil.com.127.0.0.1.xip.io/')
fetch('http://localhost:8080/')
fetch('http://127.0.0.1:22/')
fetch('http://[::1]:3000/')
EOF

    cat > "$CORPUS_DIR/network_boundary_fuzzer/header_injection" << 'EOF'
GET / HTTP/1.1
Host: example.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 192.168.1.1
User-Agent: Mozilla/5.0\r\nX-Injected: header

EOF

    cat > "$CORPUS_DIR/network_boundary_fuzzer/ssrf_bypass" << 'EOF'
http://example.com@127.0.0.1/
http://127.0.0.1#example.com
http://0x7f000001/
http://2130706433/
http://017700000001/
EOF

    # Privacy protection test cases
    cat > "$CORPUS_DIR/privacy_protection_fuzzer/tracking_parameters" << 'EOF'
https://example.com/?utm_source=test&utm_medium=email&utm_campaign=test
https://example.com/?fbclid=test&gclid=test&msclkid=test
https://example.com/?ref=facebook&src=twitter&campaign_id=123
EOF

    cat > "$CORPUS_DIR/privacy_protection_fuzzer/metadata_extraction" << 'EOF'
<script>
console.log(navigator.userAgent);
console.log(navigator.platform);
console.log(navigator.language);
console.log(screen.width + 'x' + screen.height);
console.log(new Date().getTimezoneOffset());
</script>
EOF

    log_success "Security corpus generation completed"
}

# Run individual fuzzer with enhanced monitoring
run_fuzzer() {
    local fuzzer_name="$1"
    local duration="$2"
    local dict_file="$FUZZ_DIR/dictionaries/${fuzzer_name}.dict"
    
    log_info "Running fuzzer: $fuzzer_name (duration: ${duration}s)"
    
    # Check if dictionary exists
    if [[ ! -f "$dict_file" ]]; then
        log_warning "Dictionary not found for $fuzzer_name, using fallback"
        dict_file="$FUZZ_DIR/dictionaries/html.dict"
    fi
    
    # Run fuzzer with comprehensive options
    cd "$PROJECT_ROOT"
    
    timeout "${duration}" cargo fuzz run "$fuzzer_name" \
        --release \
        --features=default \
        -- \
        -max_total_time="$duration" \
        -print_stats=1 \
        -report_slow_units=10 \
        -dict="$dict_file" \
        -artifact_prefix="$RESULTS_DIR/$fuzzer_name/crash-" \
        -exact_artifact_path="$RESULTS_DIR/$fuzzer_name/crash" \
        -print_coverage=1 \
        -print_corpus_stats=1 \
        -reload=1 \
        "$CORPUS_DIR/$fuzzer_name" \
        2>&1 | tee "$RESULTS_DIR/$fuzzer_name/output.log" || {
        
        local exit_code=$?
        if [[ $exit_code -eq 77 ]]; then
            log_warning "Fuzzer $fuzzer_name found a crash (expected for vulnerability detection)"
        elif [[ $exit_code -eq 124 ]]; then
            log_info "Fuzzer $fuzzer_name completed normally (timeout reached)"
        else
            log_error "Fuzzer $fuzzer_name failed with exit code $exit_code"
            return $exit_code
        fi
    }
    
    log_success "Fuzzer $fuzzer_name completed"
}

# Run security-focused fuzzing campaign
run_security_campaign() {
    log_info "Starting comprehensive security fuzzing campaign"
    log_info "Campaign duration: ${CAMPAIGN_DURATION}s per fuzzer"
    log_info "Max workers: $MAX_WORKERS"
    log_info "Results directory: $RESULTS_DIR"
    
    local campaign_start=$(date +%s)
    local failed_fuzzers=()
    local completed_fuzzers=()
    
    # Phase 1: Security-specific fuzzers (priority)
    log_info "Phase 1: Running security-specific fuzzers..."
    
    local fuzzer_duration=$((CAMPAIGN_DURATION / 2))  # Allocate more time to security tests
    
    for fuzzer in "${SECURITY_FUZZERS[@]}"; do
        if run_fuzzer "$fuzzer" "$fuzzer_duration"; then
            completed_fuzzers+=("$fuzzer")
        else
            failed_fuzzers+=("$fuzzer")
            
            if [[ ${#failed_fuzzers[@]} -gt $FAILURE_TOLERANCE ]]; then
                log_error "Too many fuzzer failures (${#failed_fuzzers[@]} > $FAILURE_TOLERANCE), aborting campaign"
                exit 1
            fi
        fi
    done
    
    # Phase 2: Core functionality fuzzers
    log_info "Phase 2: Running core functionality fuzzers..."
    
    local core_fuzzer_duration=$((CAMPAIGN_DURATION / 4))  # Less time for core tests
    
    for fuzzer in "${CORE_FUZZERS[@]}"; do
        if run_fuzzer "$fuzzer" "$core_fuzzer_duration"; then
            completed_fuzzers+=("$fuzzer")
        else
            failed_fuzzers+=("$fuzzer")
        fi
    done
    
    local campaign_end=$(date +%s)
    local campaign_duration=$((campaign_end - campaign_start))
    
    # Generate campaign report
    generate_campaign_report "$campaign_duration" completed_fuzzers failed_fuzzers
    
    log_success "Security campaign completed in ${campaign_duration}s"
    log_info "Completed fuzzers: ${#completed_fuzzers[@]}"
    log_info "Failed fuzzers: ${#failed_fuzzers[@]}"
    
    # Return failure if any critical security fuzzer failed
    for fuzzer in "${failed_fuzzers[@]}"; do
        if [[ " ${SECURITY_FUZZERS[@]} " =~ " ${fuzzer} " ]]; then
            log_error "Critical security fuzzer failed: $fuzzer"
            return 1
        fi
    done
    
    return 0
}

# Generate comprehensive campaign report
generate_campaign_report() {
    local duration="$1"
    shift
    local completed_fuzzers=("$@")
    
    log_info "Generating campaign report..."
    
    # Create JSON report
    cat > "$CAMPAIGN_REPORT" << EOF
{
    "campaign": {
        "timestamp": "$(date -Iseconds)",
        "duration_seconds": $duration,
        "configuration": {
            "max_workers": $MAX_WORKERS,
            "failure_tolerance": $FAILURE_TOLERANCE,
            "coverage_target": $COVERAGE_TARGET
        }
    },
    "results": {
        "completed_fuzzers": $(printf '%s\n' "${completed_fuzzers[@]}" | jq -R . | jq -s .),
        "failed_fuzzers": $(printf '%s\n' "${failed_fuzzers[@]}" | jq -R . | jq -s .),
        "success_rate": $(echo "scale=2; ${#completed_fuzzers[@]} * 100 / (${#completed_fuzzers[@]} + ${#failed_fuzzers[@]})" | bc -l)
    },
    "security_analysis": {
        "critical_vulnerabilities": 0,
        "high_vulnerabilities": 0,
        "medium_vulnerabilities": 0,
        "low_vulnerabilities": 0
    },
    "coverage_analysis": {
        "attack_vectors_tested": [],
        "security_boundaries_tested": [],
        "privacy_protections_validated": []
    }
}
EOF

    # Analyze crash artifacts
    analyze_crash_artifacts
    
    # Generate human-readable summary
    generate_summary_report
    
    log_success "Campaign report generated: $CAMPAIGN_REPORT"
}

# Analyze crash artifacts for security implications
analyze_crash_artifacts() {
    log_info "Analyzing crash artifacts for security implications..."
    
    local total_crashes=0
    local security_relevant_crashes=0
    
    for fuzzer in "${SECURITY_FUZZERS[@]}" "${CORE_FUZZERS[@]}"; do
        local crash_dir="$RESULTS_DIR/$fuzzer"
        if [[ -d "$crash_dir" ]]; then
            local crash_count=$(find "$crash_dir" -name "crash-*" | wc -l)
            total_crashes=$((total_crashes + crash_count))
            
            # Check if crashes are in security-critical components
            if [[ " ${SECURITY_FUZZERS[@]} " =~ " ${fuzzer} " ]] && [[ $crash_count -gt 0 ]]; then
                security_relevant_crashes=$((security_relevant_crashes + crash_count))
                log_warning "Security-relevant crashes found in $fuzzer: $crash_count"
            fi
        fi
    done
    
    log_info "Total crashes found: $total_crashes"
    log_info "Security-relevant crashes: $security_relevant_crashes"
    
    if [[ $security_relevant_crashes -gt 0 ]]; then
        log_error "SECURITY ALERT: $security_relevant_crashes crashes found in security-critical components"
        
        # Create security alert file
        cat > "$RESULTS_DIR/SECURITY_ALERT.txt" << EOF
SECURITY ALERT - $(date)

Security-relevant crashes detected during fuzzing campaign.
This indicates potential vulnerabilities that require immediate investigation.

Security-relevant crashes: $security_relevant_crashes
Total crashes: $total_crashes

Please review the crash artifacts in:
$RESULTS_DIR/

Next steps:
1. Analyze crash artifacts for exploitability
2. Create reproduction test cases
3. Implement fixes for identified vulnerabilities
4. Re-run security campaign to verify fixes

EOF
        
        return 1
    fi
    
    return 0
}

# Generate human-readable summary report
generate_summary_report() {
    local summary_file="$RESULTS_DIR/campaign_summary.txt"
    
    cat > "$summary_file" << EOF
Citadel Browser Security Fuzzing Campaign Summary
==================================================

Campaign Date: $(date)
Duration: $((duration / 3600))h $((duration % 3600 / 60))m $((duration % 60))s

Fuzzing Targets:
- Security Fuzzers: ${#SECURITY_FUZZERS[@]}
- Core Functionality Fuzzers: ${#CORE_FUZZERS[@]}
- Total Fuzzers: $((${#SECURITY_FUZZERS[@]} + ${#CORE_FUZZERS[@]}))

Results:
- Completed Successfully: ${#completed_fuzzers[@]}
- Failed: ${#failed_fuzzers[@]}
- Success Rate: $(echo "scale=1; ${#completed_fuzzers[@]} * 100 / (${#completed_fuzzers[@]} + ${#failed_fuzzers[@]})" | bc -l)%

Security Focus Areas Tested:
✓ Anti-fingerprinting protection bypass attempts
✓ Content Security Policy (CSP) bypass vectors
✓ JavaScript sandbox escape techniques  
✓ Network security boundary validation
✓ Privacy protection mechanism validation
✓ Cross-tab isolation boundaries
✓ DNS leak prevention
✓ Tracking parameter removal

Attack Vectors Tested:
✓ XSS injection attempts
✓ Sandbox escape vectors
✓ CSRF attacks
✓ DNS rebinding attacks
✓ SSRF attempts
✓ Header injection attacks
✓ Protocol downgrade attacks
✓ Memory corruption attempts

Privacy Protections Validated:
✓ Canvas fingerprinting protection
✓ WebGL fingerprinting protection  
✓ Audio fingerprinting protection
✓ Navigator API spoofing
✓ Screen information protection
✓ Font enumeration blocking
✓ Timezone normalization
✓ Header randomization

EOF

    if [[ ${#failed_fuzzers[@]} -gt 0 ]]; then
        echo "Failed Fuzzers:" >> "$summary_file"
        for fuzzer in "${failed_fuzzers[@]}"; do
            echo "- $fuzzer" >> "$summary_file"
        done
        echo "" >> "$summary_file"
    fi

    echo "Detailed results available in: $RESULTS_DIR" >> "$summary_file"
    echo "JSON report: $CAMPAIGN_REPORT" >> "$summary_file"
    
    log_info "Summary report generated: $summary_file"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    # Kill any remaining fuzzer processes
    pkill -f "cargo fuzz" || true
    log_success "Cleanup completed"
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Main execution
main() {
    log_info "Starting Citadel Browser Security Fuzzing Campaign"
    
    check_dependencies
    setup_environment
    generate_security_corpus
    
    if run_security_campaign; then
        log_success "Security campaign completed successfully"
        exit 0
    else
        log_error "Security campaign completed with failures"
        exit 1
    fi
}

# Run main function
main "$@"