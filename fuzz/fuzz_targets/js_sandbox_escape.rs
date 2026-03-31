#![no_main]
//! JavaScript Sandbox Escape Fuzzer
//!
//! This fuzzer specifically targets the JavaScript engine sandbox to discover
//! potential escape vectors that could allow malicious scripts to break out
//! of their isolated execution environment.

use libfuzzer_sys::fuzz_target;
use citadel_parser::js::{execute_js, create_js_context};
use citadel_security::SecurityContext;
use citadel_fuzz::security::{AttackVector, MaliciousPayload, EvasionTechnique, EncodingType};
use arbitrary::Arbitrary;
use std::collections::HashMap;
use std::panic;

/// JavaScript sandbox escape attempt structure
#[derive(Debug, Clone, Arbitrary)]
struct SandboxEscapeAttempt {
    /// Primary escape technique
    escape_technique: EscapeTechnique,
    /// JavaScript payload
    payload: String,
    /// Obfuscation methods
    obfuscation_methods: Vec<ObfuscationMethod>,
    /// Context manipulation attempts
    context_manipulation: Vec<ContextManipulation>,
    /// API access attempts
    api_access_attempts: Vec<ApiAccessAttempt>,
    /// Memory manipulation attempts
    memory_manipulation: Vec<MemoryManipulation>,
    /// Prototype pollution attempts
    prototype_pollution: Vec<PrototypePollution>,
}

/// Types of sandbox escape techniques
#[derive(Debug, Clone, Arbitrary)]
enum EscapeTechnique {
    /// Direct global object access
    GlobalObjectAccess {
        target: GlobalTarget,
        property_chain: Vec<String>,
    },
    /// Constructor property manipulation
    ConstructorManipulation {
        target_constructor: String,
        manipulation_chain: Vec<String>,
    },
    /// Prototype chain traversal
    PrototypeTraversal {
        start_object: String,
        traversal_path: Vec<String>,
    },
    /// Function constructor exploitation
    FunctionConstructor {
        construction_method: FunctionConstructionMethod,
        payload_code: String,
    },
    /// Eval-like function exploitation
    EvalExploitation {
        eval_method: EvalMethod,
        code_string: String,
    },
    /// Error object exploitation
    ErrorExploitation {
        error_type: ErrorType,
        stack_manipulation: bool,
    },
    /// Symbol manipulation
    SymbolManipulation {
        symbol_type: SymbolType,
        manipulation: String,
    },
    /// Proxy object exploitation
    ProxyExploitation {
        handler: ProxyHandler,
        target_object: String,
    },
    /// WeakMap/WeakSet exploitation
    WeakCollectionExploitation {
        collection_type: WeakCollectionType,
        exploitation_method: String,
    },
    /// Generator/Iterator exploitation
    GeneratorExploitation {
        generator_type: GeneratorType,
        exploitation_payload: String,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum GlobalTarget {
    Window,
    Global,
    Self,
    Top,
    Parent,
    Frames,
    GlobalThis,
}

#[derive(Debug, Clone, Arbitrary)]
enum FunctionConstructionMethod {
    DirectConstructor,
    IndirectConstructor,
    AsyncConstructor,
    GeneratorConstructor,
    ArrowFunctionEval,
}

#[derive(Debug, Clone, Arbitrary)]
enum EvalMethod {
    DirectEval,
    IndirectEval,
    SetTimeout,
    SetInterval,
    SetImmediate,
    RequestAnimationFrame,
}

#[derive(Debug, Clone, Arbitrary)]
enum ErrorType {
    Error,
    TypeError,
    ReferenceError,
    SyntaxError,
    RangeError,
    URIError,
    EvalError,
}

#[derive(Debug, Clone, Arbitrary)]
enum SymbolType {
    WellKnown,
    Global,
    Local,
    Iterator,
    AsyncIterator,
    HasInstance,
    IsConcatSpreadable,
    Species,
    ToPrimitive,
    ToStringTag,
    Unscopables,
}

#[derive(Debug, Clone, Arbitrary)]
struct ProxyHandler {
    get: Option<String>,
    set: Option<String>,
    has: Option<String>,
    delete_property: Option<String>,
    own_keys: Option<String>,
    get_own_property_descriptor: Option<String>,
    define_property: Option<String>,
    prevent_extensions: Option<String>,
    get_prototype_of: Option<String>,
    set_prototype_of: Option<String>,
    is_extensible: Option<String>,
    construct: Option<String>,
    apply: Option<String>,
}

#[derive(Debug, Clone, Arbitrary)]
enum WeakCollectionType {
    WeakMap,
    WeakSet,
    WeakRef,
    FinalizationRegistry,
}

#[derive(Debug, Clone, Arbitrary)]
enum GeneratorType {
    Generator,
    AsyncGenerator,
    Iterator,
    AsyncIterator,
}

/// JavaScript code obfuscation methods
#[derive(Debug, Clone, Arbitrary)]
enum ObfuscationMethod {
    /// String concatenation obfuscation
    StringConcatenation {
        segments: Vec<String>,
    },
    /// Bracket notation access
    BracketNotation {
        property_name: String,
    },
    /// Unicode escape sequences
    UnicodeEscape {
        target_string: String,
    },
    /// Hex encoding
    HexEncoding {
        target_string: String,
    },
    /// Template literal abuse
    TemplateLiteral {
        template: String,
        expressions: Vec<String>,
    },
    /// Dynamic property access
    DynamicProperty {
        object: String,
        property_expression: String,
    },
    /// Function expression wrapping
    FunctionWrapping {
        inner_code: String,
    },
    /// Array indexing obfuscation
    ArrayIndexing {
        array_literal: Vec<String>,
        access_pattern: Vec<usize>,
    },
}

/// Context manipulation attempts
#[derive(Debug, Clone, Arbitrary)]
enum ContextManipulation {
    /// Modify this binding
    ThisBinding {
        target_this: String,
        modification: String,
    },
    /// Scope chain manipulation
    ScopeManipulation {
        scope_level: u8,
        manipulation: String,
    },
    /// Variable hoisting exploitation
    HoistingExploitation {
        variable_name: String,
        hoisting_technique: String,
    },
    /// Closure variable access
    ClosureAccess {
        closure_chain: Vec<String>,
    },
}

/// API access attempts to restricted functions
#[derive(Debug, Clone, Arbitrary)]
enum ApiAccessAttempt {
    /// DOM access attempts
    DomAccess {
        dom_api: DomApi,
        parameters: Vec<String>,
    },
    /// Network access attempts
    NetworkAccess {
        network_api: NetworkApi,
        target_url: String,
    },
    /// File system access attempts
    FileSystemAccess {
        fs_api: FileSystemApi,
        target_path: String,
    },
    /// Storage access attempts
    StorageAccess {
        storage_api: StorageApi,
        key_value: (String, String),
    },
    /// Navigation attempts
    NavigationAccess {
        navigation_api: NavigationApi,
        target: String,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum DomApi {
    Document,
    Window,
    CreateElement,
    QuerySelector,
    GetElementById,
    AddEventListener,
    Cookie,
    Location,
}

#[derive(Debug, Clone, Arbitrary)]
enum NetworkApi {
    Fetch,
    XMLHttpRequest,
    WebSocket,
    EventSource,
    SendBeacon,
}

#[derive(Debug, Clone, Arbitrary)]
enum FileSystemApi {
    FileReader,
    Blob,
    File,
    URL,
    CreateObjectURL,
}

#[derive(Debug, Clone, Arbitrary)]
enum StorageApi {
    LocalStorage,
    SessionStorage,
    IndexedDB,
    WebSQL,
    Cache,
}

#[derive(Debug, Clone, Arbitrary)]
enum NavigationApi {
    Location,
    History,
    Open,
    Close,
    Reload,
}

/// Memory manipulation attempts
#[derive(Debug, Clone, Arbitrary)]
enum MemoryManipulation {
    /// Buffer overflow attempts
    BufferOverflow {
        buffer_type: BufferType,
        overflow_size: u32,
    },
    /// Type confusion attempts
    TypeConfusion {
        source_type: String,
        target_type: String,
    },
    /// Memory leak exploitation
    MemoryLeak {
        leak_vector: String,
        amplification_factor: u16,
    },
    /// Garbage collection manipulation
    GcManipulation {
        gc_trigger: String,
        timing_sensitive: bool,
    },
}

#[derive(Debug, Clone, Arbitrary)]
enum BufferType {
    ArrayBuffer,
    SharedArrayBuffer,
    TypedArray,
    DataView,
    String,
}

/// Prototype pollution attempts
#[derive(Debug, Clone, Arbitrary)]
enum PrototypePollution {
    /// Object.prototype pollution
    ObjectPrototype {
        property_name: String,
        property_value: String,
    },
    /// Function.prototype pollution
    FunctionPrototype {
        property_name: String,
        property_value: String,
    },
    /// Array.prototype pollution
    ArrayPrototype {
        property_name: String,
        property_value: String,
    },
    /// Custom constructor pollution
    CustomConstructor {
        constructor_name: String,
        property_name: String,
        property_value: String,
    },
}

fuzz_target!(|data: &[u8]| {
    // Parse fuzzing input
    let mut unstructured = arbitrary::Unstructured::new(data);
    let escape_attempt = match SandboxEscapeAttempt::arbitrary(&mut unstructured) {
        Ok(attempt) => attempt,
        Err(_) => return, // Skip invalid input
    };

    // Test sandbox escape attempt
    test_sandbox_escape(escape_attempt);
});

/// Test a sandbox escape attempt
fn test_sandbox_escape(attempt: SandboxEscapeAttempt) {
    // Create secure JavaScript context
    let security_context = SecurityContext::new(10);
    
    // Build the malicious JavaScript code
    let js_code = build_escape_code(&attempt);
    
    // Test with different security levels
    test_with_security_level(&js_code, &security_context, "strict");
    test_with_security_level(&js_code, &security_context, "moderate");
    test_with_security_level(&js_code, &security_context, "permissive");
}

/// Build JavaScript code for the escape attempt
fn build_escape_code(attempt: &SandboxEscapeAttempt) -> String {
    let mut code = String::new();
    
    // Add obfuscation
    for obfuscation in &attempt.obfuscation_methods {
        code.push_str(&apply_obfuscation(obfuscation));
        code.push(';');
    }
    
    // Add context manipulation
    for manipulation in &attempt.context_manipulation {
        code.push_str(&apply_context_manipulation(manipulation));
        code.push(';');
    }
    
    // Add prototype pollution
    for pollution in &attempt.prototype_pollution {
        code.push_str(&apply_prototype_pollution(pollution));
        code.push(';');
    }
    
    // Add main escape technique
    code.push_str(&apply_escape_technique(&attempt.escape_technique));
    code.push(';');
    
    // Add API access attempts
    for api_attempt in &attempt.api_access_attempts {
        code.push_str(&apply_api_access(api_attempt));
        code.push(';');
    }
    
    // Add memory manipulation
    for memory_attempt in &attempt.memory_manipulation {
        code.push_str(&apply_memory_manipulation(memory_attempt));
        code.push(';');
    }
    
    // Add the payload
    code.push_str(&attempt.payload);
    
    code
}

/// Apply obfuscation method
fn apply_obfuscation(obfuscation: &ObfuscationMethod) -> String {
    match obfuscation {
        ObfuscationMethod::StringConcatenation { segments } => {
            segments.iter()
                .map(|s| format!("\"{}\"", s))
                .collect::<Vec<_>>()
                .join(" + ")
        },
        ObfuscationMethod::BracketNotation { property_name } => {
            format!("this[{}]", property_name)
        },
        ObfuscationMethod::UnicodeEscape { target_string } => {
            target_string.chars()
                .map(|c| format!("\\u{{{:04x}}}", c as u32))
                .collect()
        },
        ObfuscationMethod::HexEncoding { target_string } => {
            let hex: String = target_string.bytes()
                .map(|b| format!("\\x{:02x}", b))
                .collect();
            format!("\"{}\"", hex)
        },
        ObfuscationMethod::TemplateLiteral { template, expressions } => {
            let mut result = template.clone();
            for (i, expr) in expressions.iter().enumerate() {
                result = result.replace(&format!("{{{}}}", i), &format!("${{{}}}", expr));
            }
            format!("`{}`", result)
        },
        ObfuscationMethod::DynamicProperty { object, property_expression } => {
            format!("{}[{}]", object, property_expression)
        },
        ObfuscationMethod::FunctionWrapping { inner_code } => {
            format!("(function(){{{}}})();", inner_code)
        },
        ObfuscationMethod::ArrayIndexing { array_literal, access_pattern } => {
            let array = format!("[{}]", array_literal.join(", "));
            let accesses: Vec<String> = access_pattern.iter()
                .map(|&i| format!("{}[{}]", array, i))
                .collect();
            accesses.join(" + ")
        },
    }
}

/// Apply context manipulation
fn apply_context_manipulation(manipulation: &ContextManipulation) -> String {
    match manipulation {
        ContextManipulation::ThisBinding { target_this, modification } => {
            format!("{}.call({}, {})", modification, target_this, "arguments")
        },
        ContextManipulation::ScopeManipulation { scope_level, manipulation } => {
            let mut scope_chain = String::new();
            for _ in 0..*scope_level {
                scope_chain.push_str("arguments.callee.caller.");
            }
            format!("{}{}", scope_chain, manipulation)
        },
        ContextManipulation::HoistingExploitation { variable_name, hoisting_technique } => {
            format!("var {} = {}; {}", variable_name, hoisting_technique, variable_name)
        },
        ContextManipulation::ClosureAccess { closure_chain } => {
            closure_chain.join(".")
        },
    }
}

/// Apply escape technique
fn apply_escape_technique(technique: &EscapeTechnique) -> String {
    match technique {
        EscapeTechnique::GlobalObjectAccess { target, property_chain } => {
            let global_ref = match target {
                GlobalTarget::Window => "window",
                GlobalTarget::Global => "global",
                GlobalTarget::Self => "self",
                GlobalTarget::Top => "top",
                GlobalTarget::Parent => "parent",
                GlobalTarget::Frames => "frames",
                GlobalTarget::GlobalThis => "globalThis",
            };
            let chain = property_chain.join(".");
            format!("{}.{}", global_ref, chain)
        },
        EscapeTechnique::ConstructorManipulation { target_constructor, manipulation_chain } => {
            let chain = manipulation_chain.join(".");
            format!("{}.constructor.{}", target_constructor, chain)
        },
        EscapeTechnique::PrototypeTraversal { start_object, traversal_path } => {
            let path = traversal_path.join(".prototype.");
            format!("{}.prototype.{}", start_object, path)
        },
        EscapeTechnique::FunctionConstructor { construction_method, payload_code } => {
            match construction_method {
                FunctionConstructionMethod::DirectConstructor => {
                    format!("(new Function('{}'))()", payload_code)
                },
                FunctionConstructionMethod::IndirectConstructor => {
                    format!("({}.constructor.constructor('{}'))()", "(function(){})", payload_code)
                },
                FunctionConstructionMethod::AsyncConstructor => {
                    format!("(async function(){{{}}})();", payload_code)
                },
                FunctionConstructionMethod::GeneratorConstructor => {
                    format!("(function*(){{{}}})().next();", payload_code)
                },
                FunctionConstructionMethod::ArrowFunctionEval => {
                    format!("(()=>eval('{}'))()", payload_code)
                },
            }
        },
        EscapeTechnique::EvalExploitation { eval_method, code_string } => {
            match eval_method {
                EvalMethod::DirectEval => format!("eval('{}')", code_string),
                EvalMethod::IndirectEval => format!("(1,eval)('{}')", code_string),
                EvalMethod::SetTimeout => format!("setTimeout('{}', 0)", code_string),
                EvalMethod::SetInterval => format!("setInterval('{}', 1)", code_string),
                EvalMethod::SetImmediate => format!("setImmediate('{}')", code_string),
                EvalMethod::RequestAnimationFrame => format!("requestAnimationFrame(function(){{eval('{}')}})", code_string),
            }
        },
        EscapeTechnique::ErrorExploitation { error_type, stack_manipulation } => {
            let error_name = match error_type {
                ErrorType::Error => "Error",
                ErrorType::TypeError => "TypeError",
                ErrorType::ReferenceError => "ReferenceError",
                ErrorType::SyntaxError => "SyntaxError",
                ErrorType::RangeError => "RangeError",
                ErrorType::URIError => "URIError",
                ErrorType::EvalError => "EvalError",
            };
            if *stack_manipulation {
                format!("try{{throw new {}()}}catch(e){{e.stack}}", error_name)
            } else {
                format!("new {}().constructor", error_name)
            }
        },
        EscapeTechnique::SymbolManipulation { symbol_type, manipulation } => {
            let symbol_ref = match symbol_type {
                SymbolType::WellKnown => "Symbol",
                SymbolType::Iterator => "Symbol.iterator",
                SymbolType::AsyncIterator => "Symbol.asyncIterator",
                SymbolType::HasInstance => "Symbol.hasInstance",
                SymbolType::IsConcatSpreadable => "Symbol.isConcatSpreadable",
                SymbolType::Species => "Symbol.species",
                SymbolType::ToPrimitive => "Symbol.toPrimitive",
                SymbolType::ToStringTag => "Symbol.toStringTag",
                SymbolType::Unscopables => "Symbol.unscopables",
                _ => "Symbol",
            };
            format!("{}.{}", symbol_ref, manipulation)
        },
        _ => "/* Complex escape technique */".to_string(),
    }
}

/// Apply prototype pollution
fn apply_prototype_pollution(pollution: &PrototypePollution) -> String {
    match pollution {
        PrototypePollution::ObjectPrototype { property_name, property_value } => {
            format!("Object.prototype.{} = {}", property_name, property_value)
        },
        PrototypePollution::FunctionPrototype { property_name, property_value } => {
            format!("Function.prototype.{} = {}", property_name, property_value)
        },
        PrototypePollution::ArrayPrototype { property_name, property_value } => {
            format!("Array.prototype.{} = {}", property_name, property_value)
        },
        PrototypePollution::CustomConstructor { constructor_name, property_name, property_value } => {
            format!("{}.prototype.{} = {}", constructor_name, property_name, property_value)
        },
    }
}

/// Apply API access attempt
fn apply_api_access(api_attempt: &ApiAccessAttempt) -> String {
    match api_attempt {
        ApiAccessAttempt::DomAccess { dom_api, parameters } => {
            let api_name = match dom_api {
                DomApi::Document => "document",
                DomApi::Window => "window",
                DomApi::CreateElement => "document.createElement",
                DomApi::QuerySelector => "document.querySelector",
                DomApi::GetElementById => "document.getElementById",
                DomApi::AddEventListener => "addEventListener",
                DomApi::Cookie => "document.cookie",
                DomApi::Location => "location",
            };
            if parameters.is_empty() {
                api_name.to_string()
            } else {
                format!("{}({})", api_name, parameters.join(", "))
            }
        },
        ApiAccessAttempt::NetworkAccess { network_api, target_url } => {
            match network_api {
                NetworkApi::Fetch => format!("fetch('{}')", target_url),
                NetworkApi::XMLHttpRequest => format!("new XMLHttpRequest().open('GET', '{}')", target_url),
                NetworkApi::WebSocket => format!("new WebSocket('{}')", target_url),
                NetworkApi::EventSource => format!("new EventSource('{}')", target_url),
                NetworkApi::SendBeacon => format!("navigator.sendBeacon('{}', 'data')", target_url),
            }
        },
        _ => "/* API access attempt */".to_string(),
    }
}

/// Apply memory manipulation
fn apply_memory_manipulation(manipulation: &MemoryManipulation) -> String {
    match manipulation {
        MemoryManipulation::BufferOverflow { buffer_type, overflow_size } => {
            let buffer_creation = match buffer_type {
                BufferType::ArrayBuffer => format!("new ArrayBuffer({})", overflow_size),
                BufferType::SharedArrayBuffer => format!("new SharedArrayBuffer({})", overflow_size),
                BufferType::TypedArray => format!("new Uint8Array({})", overflow_size),
                BufferType::DataView => format!("new DataView(new ArrayBuffer({}))", overflow_size),
                BufferType::String => format!("'A'.repeat({})", overflow_size),
            };
            buffer_creation
        },
        MemoryManipulation::TypeConfusion { source_type, target_type } => {
            format!("/* Type confusion: {} -> {} */", source_type, target_type)
        },
        MemoryManipulation::MemoryLeak { leak_vector, amplification_factor } => {
            format!("for(let i=0; i<{}; i++) {{{}}}", amplification_factor, leak_vector)
        },
        MemoryManipulation::GcManipulation { gc_trigger, timing_sensitive } => {
            if *timing_sensitive {
                format!("performance.now(); {}; performance.now()", gc_trigger)
            } else {
                gc_trigger.clone()
            }
        },
    }
}

/// Test JavaScript execution with different security levels
fn test_with_security_level(js_code: &str, security_context: &SecurityContext, level: &str) {
    // Catch any panics during execution
    let result = panic::catch_unwind(|| {
        // Create JavaScript context with security restrictions
        let js_context = create_js_context(security_context.clone());
        
        // Attempt to execute the malicious code
        match execute_js(&js_context, js_code) {
            Ok(result) => {
                // Execution succeeded - check for signs of escape
                check_for_escape_indicators(&result, js_code);
            },
            Err(error) => {
                // Execution failed - this is expected for malicious code
                eprintln!("JavaScript execution blocked ({}): {:?}", level, error);
            }
        }
    });
    
    match result {
        Ok(_) => {
            // No panic occurred - good
        },
        Err(_) => {
            // JavaScript engine panicked - this is a bug
            panic!("JavaScript engine panicked on input (security level: {}): {}", level, js_code);
        }
    }
}

/// Check execution result for signs of sandbox escape
fn check_for_escape_indicators(result: &str, original_code: &str) {
    // Look for indicators that the sandbox was bypassed
    let escape_indicators = [
        "[ESCAPED]",
        "global object accessed",
        "constructor accessed",
        "eval executed",
        "DOM accessed",
        "network request made",
        "file system accessed",
        "storage accessed",
    ];
    
    for indicator in &escape_indicators {
        if result.contains(indicator) {
            panic!("Sandbox escape detected! Indicator: {} in result: {} from code: {}", 
                   indicator, result, original_code);
        }
    }
    
    // Check for suspicious function references in output
    let suspicious_functions = [
        "Function",
        "eval",
        "setTimeout",
        "setInterval",
        "XMLHttpRequest",
        "fetch",
        "document",
        "window",
        "global",
    ];
    
    for func in &suspicious_functions {
        if result.contains(func) && original_code.contains(func) {
            eprintln!("Warning: Suspicious function '{}' appeared in result", func);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_escape_attempt() {
        let attempt = SandboxEscapeAttempt {
            escape_technique: EscapeTechnique::GlobalObjectAccess {
                target: GlobalTarget::Window,
                property_chain: vec!["location".to_string(), "href".to_string()],
            },
            payload: "alert('escape')".to_string(),
            obfuscation_methods: vec![],
            context_manipulation: vec![],
            api_access_attempts: vec![],
            memory_manipulation: vec![],
            prototype_pollution: vec![],
        };
        
        let code = build_escape_code(&attempt);
        assert!(code.contains("window.location.href"));
    }
    
    #[test]
    fn test_obfuscation_application() {
        let obfuscation = ObfuscationMethod::StringConcatenation {
            segments: vec!["al".to_string(), "ert".to_string()],
        };
        
        let result = apply_obfuscation(&obfuscation);
        assert_eq!(result, "\"al\" + \"ert\"");
    }
    
    #[test]
    fn test_prototype_pollution() {
        let pollution = PrototypePollution::ObjectPrototype {
            property_name: "isAdmin".to_string(),
            property_value: "true".to_string(),
        };
        
        let result = apply_prototype_pollution(&pollution);
        assert_eq!(result, "Object.prototype.isAdmin = true");
    }
}