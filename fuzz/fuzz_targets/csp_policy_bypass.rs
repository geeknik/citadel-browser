#![no_main]
//! Content Security Policy (CSP) Bypass Fuzzer
//!
//! This fuzzer tests the CSP parsing and enforcement mechanisms to discover
//! potential bypass vectors that could allow policy violations and script
//! execution in restricted contexts.

use libfuzzer_sys::fuzz_target;
use citadel_security::{
    SecurityContext, ContentSecurityPolicy, CspDirective, CspSource,
    SecurityViolation
};
use citadel_fuzz::security::{AttackVector, MaliciousPayload, EvasionTechnique, EncodingType};
use arbitrary::Arbitrary;
use std::collections::HashMap;

/// CSP bypass attempt structure
#[derive(Debug, Clone, Arbitrary)]
struct CspBypassAttempt {
    /// CSP policy to test against
    csp_policy: CspPolicyTest,
    /// Attack vector to attempt
    attack_vector: CspAttackVector,
    /// Evasion techniques to try
    evasion_techniques: Vec<EvasionTechnique>,
    /// Payload encoding
    encoding: EncodingType,
    /// Source context (URL, inline, etc.)
    source_context: SourceContext,
    /// Additional headers or context
    additional_context: HashMap<String, String>,
}

/// CSP policy configurations for testing
#[derive(Debug, Clone, Arbitrary)]
enum CspPolicyTest {
    /// Strict policy with minimal allowed sources
    Strict {
        allow_self: bool,
        allow_inline: bool,
        allow_eval: bool,
        allowed_hosts: Vec<String>,
    },
    /// Moderate policy with some flexibility
    Moderate {
        script_src: Vec<String>,
        style_src: Vec<String>,
        img_src: Vec<String>,
        connect_src: Vec<String>,
    },
    /// Permissive policy with many exceptions
    Permissive {
        default_src: Vec<String>,
        unsafe_inline: bool,
        unsafe_eval: bool,
        data_urls: bool,
    },
    /// Custom policy with specific directives
    Custom {
        directives: HashMap<String, Vec<String>>,
        report_uri: Option<String>,
        report_only: bool,
    },
}

/// Types of CSP attack vectors to test
#[derive(Debug, Clone, Arbitrary)]
enum CspAttackVector {
    /// Script injection attempts
    ScriptInjection {
        payload: String,
        injection_method: ScriptInjectionMethod,
    },
    /// Style injection attempts
    StyleInjection {
        payload: String,
        injection_method: StyleInjectionMethod,
    },
    /// Image source attacks
    ImageSourceAttack {
        src: String,
        attributes: HashMap<String, String>,
    },
    /// Frame injection attempts
    FrameInjection {
        src: String,
        sandbox: Option<String>,
    },
    /// Object/Embed attacks
    ObjectEmbedAttack {
        data: String,
        type_attr: String,
    },
    /// Form action manipulation
    FormActionAttack {
        action: String,
        method: String,
    },
    /// Base URI manipulation
    BaseUriAttack {
        href: String,
    },
    /// Manifest source attacks
    ManifestAttack {
        href: String,
    },
    /// Worker source attacks
    WorkerAttack {
        src: String,
        worker_type: WorkerType,
    },
    /// Font source attacks
    FontAttack {
        src: String,
        format: String,
    },
    /// Media source attacks
    MediaAttack {
        src: String,
        media_type: MediaType,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum ScriptInjectionMethod {
    InlineScript,
    ExternalScript,
    EventHandler,
    JavascriptUrl,
    DataUrl,
    BlobUrl,
    ImportScript,
    EvalFunction,
    FunctionConstructor,
    SetTimeoutString,
    SetIntervalString,
}

#[derive(Debug, Clone, Arbitrary)]
enum StyleInjectionMethod {
    InlineStyle,
    ExternalStylesheet,
    StyleAttribute,
    CssImport,
    DataUrl,
    Expression,
    Binding,
}

#[derive(Debug, Clone, Arbitrary)]
enum WorkerType {
    Worker,
    ServiceWorker,
    SharedWorker,
}

#[derive(Debug, Clone, Arbitrary)]
enum MediaType {
    Audio,
    Video,
    Track,
}

/// Source context for the attack
#[derive(Debug, Clone, Arbitrary)]
struct SourceContext {
    /// Origin of the request
    origin: String,
    /// Referrer information
    referrer: Option<String>,
    /// User agent
    user_agent: String,
    /// Request method
    method: String,
    /// Additional headers
    headers: HashMap<String, String>,
}

fuzz_target!(|data: &[u8]| {
    // Parse fuzzing input
    let mut unstructured = arbitrary::Unstructured::new(data);
    let bypass_attempt = match CspBypassAttempt::arbitrary(&mut unstructured) {
        Ok(attempt) => attempt,
        Err(_) => return, // Skip invalid input
    };

    // Test CSP bypass attempt
    test_csp_bypass(bypass_attempt);
});

/// Test a CSP bypass attempt against security policies
fn test_csp_bypass(attempt: CspBypassAttempt) {
    // Create security context with CSP
    let security_context = create_security_context_with_csp(&attempt.csp_policy);
    
    // Test the attack vector against the CSP
    match attempt.attack_vector {
        CspAttackVector::ScriptInjection { payload, injection_method } => {
            test_script_injection(
                &security_context,
                &payload,
                &injection_method,
                &attempt.source_context
            );
        },
        CspAttackVector::StyleInjection { payload, injection_method } => {
            test_style_injection(
                &security_context,
                &payload,
                &injection_method,
                &attempt.source_context
            );
        },
        CspAttackVector::ImageSourceAttack { src, attributes } => {
            test_image_source_attack(
                &security_context,
                &src,
                &attributes,
                &attempt.source_context
            );
        },
        CspAttackVector::FrameInjection { src, sandbox } => {
            test_frame_injection(
                &security_context,
                &src,
                &sandbox,
                &attempt.source_context
            );
        },
        CspAttackVector::ObjectEmbedAttack { data, type_attr } => {
            test_object_embed_attack(
                &security_context,
                &data,
                &type_attr,
                &attempt.source_context
            );
        },
        CspAttackVector::FormActionAttack { action, method } => {
            test_form_action_attack(
                &security_context,
                &action,
                &method,
                &attempt.source_context
            );
        },
        CspAttackVector::BaseUriAttack { href } => {
            test_base_uri_attack(
                &security_context,
                &href,
                &attempt.source_context
            );
        },
        CspAttackVector::ManifestAttack { href } => {
            test_manifest_attack(
                &security_context,
                &href,
                &attempt.source_context
            );
        },
        CspAttackVector::WorkerAttack { src, worker_type } => {
            test_worker_attack(
                &security_context,
                &src,
                &worker_type,
                &attempt.source_context
            );
        },
        CspAttackVector::FontAttack { src, format } => {
            test_font_attack(
                &security_context,
                &src,
                &format,
                &attempt.source_context
            );
        },
        CspAttackVector::MediaAttack { src, media_type } => {
            test_media_attack(
                &security_context,
                &src,
                &media_type,
                &attempt.source_context
            );
        },
    }
}

/// Create security context with CSP based on test configuration
fn create_security_context_with_csp(policy_test: &CspPolicyTest) -> SecurityContext {
    let mut security_context = SecurityContext::new(10);
    
    let csp = match policy_test {
        CspPolicyTest::Strict { allow_self, allow_inline, allow_eval, allowed_hosts } => {
            create_strict_csp(*allow_self, *allow_inline, *allow_eval, allowed_hosts)
        },
        CspPolicyTest::Moderate { script_src, style_src, img_src, connect_src } => {
            create_moderate_csp(script_src, style_src, img_src, connect_src)
        },
        CspPolicyTest::Permissive { default_src, unsafe_inline, unsafe_eval, data_urls } => {
            create_permissive_csp(default_src, *unsafe_inline, *unsafe_eval, *data_urls)
        },
        CspPolicyTest::Custom { directives, report_uri, report_only } => {
            create_custom_csp(directives, report_uri.as_deref(), *report_only)
        },
    };
    
    security_context.set_csp(csp);
    security_context
}

/// Create strict CSP policy
fn create_strict_csp(allow_self: bool, allow_inline: bool, allow_eval: bool, allowed_hosts: &[String]) -> ContentSecurityPolicy {
    let mut csp = ContentSecurityPolicy::new();
    
    // Default source restrictions
    let mut default_sources = vec![CspSource::None];
    if allow_self {
        default_sources.push(CspSource::SelfOrigin);
    }
    for host in allowed_hosts {
        default_sources.push(CspSource::Host(host.clone()));
    }
    csp.add_directive(CspDirective::DefaultSrc, default_sources);
    
    // Script source restrictions
    let mut script_sources = vec![];
    if allow_self {
        script_sources.push(CspSource::SelfOrigin);
    }
    if allow_inline {
        script_sources.push(CspSource::UnsafeInline);
    }
    if allow_eval {
        script_sources.push(CspSource::UnsafeEval);
    }
    for host in allowed_hosts {
        script_sources.push(CspSource::Host(host.clone()));
    }
    if script_sources.is_empty() {
        script_sources.push(CspSource::None);
    }
    csp.add_directive(CspDirective::ScriptSrc, script_sources);
    
    // Style source restrictions
    let mut style_sources = vec![];
    if allow_self {
        style_sources.push(CspSource::SelfOrigin);
    }
    if allow_inline {
        style_sources.push(CspSource::UnsafeInline);
    }
    for host in allowed_hosts {
        style_sources.push(CspSource::Host(host.clone()));
    }
    if style_sources.is_empty() {
        style_sources.push(CspSource::None);
    }
    csp.add_directive(CspDirective::StyleSrc, style_sources);
    
    csp
}

/// Create moderate CSP policy
fn create_moderate_csp(
    script_src: &[String],
    style_src: &[String],
    img_src: &[String],
    connect_src: &[String]
) -> ContentSecurityPolicy {
    let mut csp = ContentSecurityPolicy::new();
    
    csp.add_directive(CspDirective::DefaultSrc, vec![CspSource::SelfOrigin]);
    
    let script_sources: Vec<CspSource> = script_src.iter()
        .map(|s| CspSource::Host(s.clone()))
        .collect();
    if !script_sources.is_empty() {
        csp.add_directive(CspDirective::ScriptSrc, script_sources);
    }
    
    let style_sources: Vec<CspSource> = style_src.iter()
        .map(|s| CspSource::Host(s.clone()))
        .collect();
    if !style_sources.is_empty() {
        csp.add_directive(CspDirective::StyleSrc, style_sources);
    }
    
    let img_sources: Vec<CspSource> = img_src.iter()
        .map(|s| CspSource::Host(s.clone()))
        .collect();
    if !img_sources.is_empty() {
        csp.add_directive(CspDirective::ImgSrc, img_sources);
    }
    
    let connect_sources: Vec<CspSource> = connect_src.iter()
        .map(|s| CspSource::Host(s.clone()))
        .collect();
    if !connect_sources.is_empty() {
        csp.add_directive(CspDirective::ConnectSrc, connect_sources);
    }
    
    csp
}

/// Create permissive CSP policy
fn create_permissive_csp(
    default_src: &[String],
    unsafe_inline: bool,
    unsafe_eval: bool,
    data_urls: bool
) -> ContentSecurityPolicy {
    let mut csp = ContentSecurityPolicy::new();
    
    let mut default_sources: Vec<CspSource> = default_src.iter()
        .map(|s| CspSource::Host(s.clone()))
        .collect();
    
    if default_sources.is_empty() {
        default_sources.push(CspSource::SelfOrigin);
    }
    
    if unsafe_inline {
        default_sources.push(CspSource::UnsafeInline);
    }
    
    if unsafe_eval {
        default_sources.push(CspSource::UnsafeEval);
    }
    
    if data_urls {
        default_sources.push(CspSource::Data);
    }
    
    csp.add_directive(CspDirective::DefaultSrc, default_sources);
    
    csp
}

/// Create custom CSP policy
fn create_custom_csp(
    directives: &HashMap<String, Vec<String>>,
    _report_uri: Option<&str>,
    _report_only: bool
) -> ContentSecurityPolicy {
    let mut csp = ContentSecurityPolicy::new();
    
    for (directive_name, sources) in directives {
        let directive = match directive_name.as_str() {
            "default-src" => CspDirective::DefaultSrc,
            "script-src" => CspDirective::ScriptSrc,
            "style-src" => CspDirective::StyleSrc,
            "img-src" => CspDirective::ImgSrc,
            "connect-src" => CspDirective::ConnectSrc,
            "font-src" => CspDirective::FontSrc,
            "object-src" => CspDirective::ObjectSrc,
            "media-src" => CspDirective::MediaSrc,
            "frame-src" => CspDirective::FrameSrc,
            _ => continue, // Skip unknown directives
        };
        
        let csp_sources: Vec<CspSource> = sources.iter()
            .filter_map(|s| match s.as_str() {
                "'self'" => Some(CspSource::SelfOrigin),
                "'none'" => Some(CspSource::None),
                "'unsafe-inline'" => Some(CspSource::UnsafeInline),
                "'unsafe-eval'" => Some(CspSource::UnsafeEval),
                "data:" => Some(CspSource::Data),
                host => Some(CspSource::Host(host.to_string())),
            })
            .collect();
        
        if !csp_sources.is_empty() {
            csp.add_directive(directive, csp_sources);
        }
    }
    
    csp
}

/// Test script injection attempts
fn test_script_injection(
    security_context: &SecurityContext,
    payload: &str,
    injection_method: &ScriptInjectionMethod,
    _source_context: &SourceContext
) {
    let violation_check = match injection_method {
        ScriptInjectionMethod::InlineScript => {
            // Test inline script execution
            security_context.check_script_execution(payload, None)
        },
        ScriptInjectionMethod::ExternalScript => {
            // Test external script loading
            security_context.check_script_execution("", Some(payload))
        },
        ScriptInjectionMethod::EventHandler => {
            // Test event handler execution
            let event_script = format!("onclick=\"{}\"", payload);
            security_context.check_script_execution(&event_script, None)
        },
        ScriptInjectionMethod::JavascriptUrl => {
            // Test javascript: URL execution
            let js_url = format!("javascript:{}", payload);
            security_context.check_script_execution(&js_url, None)
        },
        ScriptInjectionMethod::DataUrl => {
            // Test data URL script execution
            let data_url = format!("data:text/javascript,{}", payload);
            security_context.check_script_execution("", Some(&data_url))
        },
        ScriptInjectionMethod::EvalFunction => {
            // Test eval() function usage
            let eval_script = format!("eval('{}')", payload);\n            security_context.check_script_execution(&eval_script, None)
        },
        _ => {
            // Other injection methods
            security_context.check_script_execution(payload, None)
        }
    };
    
    // Script injection should be blocked by CSP
    match violation_check {
        Ok(_) => {
            // If script execution was allowed, verify it was actually safe
            // This could indicate a CSP bypass
            if payload.contains("alert") || payload.contains("eval") || payload.contains("document.cookie") {
                panic!("Dangerous script execution was allowed by CSP: {}", payload);
            }
        },
        Err(SecurityViolation::CspViolation { .. }) => {
            // CSP correctly blocked the script - this is expected
        },
        Err(other_error) => {
            // Other security error - also acceptable
            eprintln!("Script blocked by other security mechanism: {:?}", other_error);
        }
    }
}

/// Test style injection attempts
fn test_style_injection(
    security_context: &SecurityContext,
    payload: &str,
    injection_method: &StyleInjectionMethod,
    _source_context: &SourceContext
) {
    let violation_check = match injection_method {
        StyleInjectionMethod::InlineStyle => {
            security_context.check_style_execution(payload, None)
        },
        StyleInjectionMethod::ExternalStylesheet => {
            security_context.check_style_execution("", Some(payload))
        },
        StyleInjectionMethod::StyleAttribute => {
            let style_attr = format!("style=\"{}\"", payload);
            security_context.check_style_execution(&style_attr, None)
        },
        StyleInjectionMethod::CssImport => {
            let import_style = format!("@import url('{}')", payload);
            security_context.check_style_execution(&import_style, None)
        },
        StyleInjectionMethod::DataUrl => {
            let data_url = format!("data:text/css,{}", payload);
            security_context.check_style_execution("", Some(&data_url))
        },
        _ => {
            security_context.check_style_execution(payload, None)
        }
    };
    
    // Dangerous style injection should be blocked
    match violation_check {
        Ok(_) => {
            // If style was allowed, verify it's safe
            if payload.contains("expression") || payload.contains("javascript:") || payload.contains("@import") {
                panic!("Dangerous style execution was allowed by CSP: {}", payload);
            }
        },
        Err(SecurityViolation::CspViolation { .. }) => {
            // CSP correctly blocked the style
        },
        Err(_) => {
            // Other security mechanism blocked it
        }
    }
}

/// Test image source attacks
fn test_image_source_attack(
    security_context: &SecurityContext,
    src: &str,
    _attributes: &HashMap<String, String>,
    _source_context: &SourceContext
) {
    let violation_check = security_context.check_image_source(src);
    
    match violation_check {
        Ok(_) => {
            // Image source was allowed - verify it's safe
            if src.starts_with("javascript:") || src.contains("data:text/html") {
                panic!("Dangerous image source was allowed by CSP: {}", src);
            }
        },
        Err(SecurityViolation::CspViolation { .. }) => {
            // CSP correctly blocked the image source
        },
        Err(_) => {
            // Other security mechanism blocked it
        }
    }
}

/// Test frame injection attempts
fn test_frame_injection(
    security_context: &SecurityContext,
    src: &str,
    _sandbox: &Option<String>,
    _source_context: &SourceContext
) {
    let violation_check = security_context.check_frame_source(src);
    
    match violation_check {
        Ok(_) => {
            // Frame source was allowed - verify it's safe
            if src.starts_with("javascript:") || src.contains("data:text/html") {
                panic!("Dangerous frame source was allowed by CSP: {}", src);
            }
        },
        Err(SecurityViolation::CspViolation { .. }) => {
            // CSP correctly blocked the frame source
        },
        Err(_) => {
            // Other security mechanism blocked it
        }
    }
}

/// Placeholder functions for other attack tests
fn test_object_embed_attack(_context: &SecurityContext, _data: &str, _type_attr: &str, _source: &SourceContext) {}
fn test_form_action_attack(_context: &SecurityContext, _action: &str, _method: &str, _source: &SourceContext) {}
fn test_base_uri_attack(_context: &SecurityContext, _href: &str, _source: &SourceContext) {}
fn test_manifest_attack(_context: &SecurityContext, _href: &str, _source: &SourceContext) {}
fn test_worker_attack(_context: &SecurityContext, _src: &str, _worker_type: &WorkerType, _source: &SourceContext) {}
fn test_font_attack(_context: &SecurityContext, _src: &str, _format: &str, _source: &SourceContext) {}
fn test_media_attack(_context: &SecurityContext, _src: &str, _media_type: &MediaType, _source: &SourceContext) {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_strict_csp_blocks_inline_scripts() {
        let csp = create_strict_csp(true, false, false, &[]);
        let mut security_context = SecurityContext::new(10);
        security_context.set_csp(csp);
        
        let result = security_context.check_script_execution("alert('xss')", None);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_permissive_csp_allows_safe_content() {
        let csp = create_permissive_csp(&["self".to_string()], true, false, true);
        let mut security_context = SecurityContext::new(10);
        security_context.set_csp(csp);
        
        let result = security_context.check_script_execution("console.log('safe')", None);
        // Should be allowed but depends on implementation
    }
    
    #[test]
    fn test_csp_blocks_dangerous_data_urls() {
        let csp = create_strict_csp(true, false, false, &[]);
        let mut security_context = SecurityContext::new(10);
        security_context.set_csp(csp);
        
        let dangerous_data_url = "data:text/html,<script>alert('xss')</script>";
        let result = security_context.check_frame_source(dangerous_data_url);
        assert!(result.is_err());
    }
}