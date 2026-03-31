//! Boa Engine Spike Test
//!
//! Validates that Boa supports the 5 critical operations Citadel needs
//! before committing to the full migration from rquickjs.
//!
//! Run: cargo run -p citadel-parser --example boa_spike

use boa_engine::object::ObjectInitializer;
use boa_engine::property::Attribute;
use boa_engine::{Context, JsValue, NativeFunction, Source};

fn main() {
    println!("=== Boa Engine Spike Test for Citadel Browser ===\n");

    let mut passed = 0;
    let mut failed = 0;

    // Test 1: Context creation
    print!("Test 1: Context creation... ");
    let mut ctx = Context::default();
    println!("PASS");
    passed += 1;

    // Test 2: Prototype freezing via eval
    print!("Test 2: Prototype freezing via JS eval... ");
    match ctx.eval(Source::from_bytes("Object.freeze(Object.prototype); true")) {
        Ok(val) => {
            if val.as_boolean() == Some(true) {
                // Verify freeze worked: in sloppy mode, assignment silently fails
                // (doesn't throw). Check the property wasn't actually set.
                let _ = ctx.eval(Source::from_bytes("Object.prototype.evil = 1;"));
                match ctx.eval(Source::from_bytes(
                    "Object.prototype.evil === undefined",
                )) {
                    Ok(val) => {
                        if val.as_boolean() == Some(true) {
                            println!("PASS (freeze verified, assignment silently ignored)");
                            passed += 1;
                        } else {
                            println!("FAIL (freeze did not prevent modification)");
                            failed += 1;
                        }
                    }
                    Err(e) => {
                        println!("FAIL (verification error: {})", e);
                        failed += 1;
                    }
                }
            } else {
                println!("FAIL (unexpected return value)");
                failed += 1;
            }
        }
        Err(e) => {
            println!("FAIL ({})", e);
            failed += 1;
        }
    }

    // Test 3: Real property deletion
    print!("Test 3: Real property deletion (delete_property_or_throw)... ");
    // Reset context for clean test
    let mut ctx = Context::default();
    match test_property_deletion(&mut ctx) {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL ({})", e);
            failed += 1;
        }
    }

    // Test 4: Native function registration
    print!("Test 4: Native function registration... ");
    let mut ctx = Context::default();
    match test_native_function(&mut ctx) {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL ({})", e);
            failed += 1;
        }
    }

    // Test 5: Prototype freezing via Rust API (IntegrityLevel)
    print!("Test 5: Prototype freezing via Rust API... ");
    let mut ctx = Context::default();
    match test_rust_api_freeze(&mut ctx) {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL ({})", e);
            failed += 1;
        }
    }

    // Test 6: Object creation with ObjectInitializer
    print!("Test 6: Object creation + property setting... ");
    let mut ctx = Context::default();
    match test_object_creation(&mut ctx) {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL ({})", e);
            failed += 1;
        }
    }

    // Test 7: Value type checking and conversion
    print!("Test 7: Value type checking + conversion... ");
    let mut ctx = Context::default();
    match test_value_conversion(&mut ctx) {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL ({})", e);
            failed += 1;
        }
    }

    // Test 8: Real-world JS patterns (Promises, arrow functions, destructuring)
    print!("Test 8: Real-world JS patterns... ");
    let mut ctx = Context::default();
    match test_realworld_js(&mut ctx) {
        Ok(()) => {
            println!("PASS");
            passed += 1;
        }
        Err(e) => {
            println!("FAIL ({})", e);
            failed += 1;
        }
    }

    println!("\n=== Results: {passed}/{} passed ({failed} failed) ===", passed + failed);

    if failed > 0 {
        println!("\nSPIKE FAILED: Boa does not support required operations.");
        println!("Evaluate rollback options before proceeding with migration.");
        std::process::exit(1);
    } else {
        println!("\nSPIKE PASSED: All critical operations work. Safe to proceed with migration.");
    }
}

fn test_property_deletion(ctx: &mut Context) -> Result<(), String> {
    // Set up a CONFIGURABLE property on the global object (not via var, which creates non-configurable bindings)
    let global = ctx.global_object().clone();
    global
        .set(
            boa_engine::js_string!("testProp"),
            JsValue::from(42),
            false,
            ctx,
        )
        .map_err(|e| format!("setup: {}", e))?;

    // Verify it exists
    let exists = ctx
        .eval(Source::from_bytes("typeof testProp !== 'undefined'"))
        .map_err(|e| format!("check exists: {}", e))?;
    if exists.as_boolean() != Some(true) {
        return Err("property did not exist after creation".into());
    }

    // Delete via the global object
    global
        .delete_property_or_throw(boa_engine::js_string!("testProp"), ctx)
        .map_err(|e| format!("delete: {}", e))?;

    // Verify deletion: 'testProp' in globalThis should be false
    let gone = ctx
        .eval(Source::from_bytes("typeof testProp === 'undefined'"))
        .map_err(|e| format!("check deleted: {}", e))?;
    if gone.as_boolean() != Some(true) {
        return Err("property still exists after deletion".into());
    }

    Ok(())
}

fn test_native_function(ctx: &mut Context) -> Result<(), String> {
    // Register a native Rust function
    // Register native function by defining it on the global object
    let citadel_log = NativeFunction::from_fn_ptr(|_this, args, ctx| {
        let msg = args
            .first()
            .cloned()
            .unwrap_or(JsValue::undefined())
            .to_string(ctx)?;
        println!("  [citadelLog] {}", msg.to_std_string_escaped());
        Ok(JsValue::undefined())
    });
    ctx.register_global_callable(
        boa_engine::js_string!("citadelLog"),
        1,
        citadel_log,
    )
    .map_err(|e| format!("register: {}", e))?;

    // Call the native function from JS
    ctx.eval(Source::from_bytes("citadelLog('Hello from Boa!')"))
        .map_err(|e| format!("call: {}", e))?;

    // Verify it's callable
    let type_check = ctx
        .eval(Source::from_bytes("typeof citadelLog === 'function'"))
        .map_err(|e| format!("type check: {}", e))?;
    if type_check.as_boolean() != Some(true) {
        return Err("native function not registered as function type".into());
    }

    Ok(())
}

fn test_rust_api_freeze(ctx: &mut Context) -> Result<(), String> {
    use boa_engine::object::IntegrityLevel;

    // Create an object and freeze it via Rust API
    let obj = ObjectInitializer::new(ctx)
        .property(
            boa_engine::js_string!("name"),
            boa_engine::js_string!("test"),
            Attribute::all(),
        )
        .build();

    obj.set_integrity_level(IntegrityLevel::Frozen, ctx)
        .map_err(|e| format!("freeze: {}", e))?;

    // Verify frozen
    let is_frozen = obj
        .test_integrity_level(IntegrityLevel::Frozen, ctx)
        .map_err(|e| format!("test freeze: {}", e))?;
    if !is_frozen {
        return Err("object not frozen after set_integrity_level".into());
    }

    Ok(())
}

fn test_object_creation(ctx: &mut Context) -> Result<(), String> {
    // Create a document-like object
    let document = ObjectInitializer::new(ctx)
        .property(
            boa_engine::js_string!("title"),
            boa_engine::js_string!("Citadel Test"),
            Attribute::all(),
        )
        .property(
            boa_engine::js_string!("readyState"),
            boa_engine::js_string!("complete"),
            Attribute::all(),
        )
        .build();

    ctx.register_global_property(
        boa_engine::js_string!("document"),
        document,
        Attribute::all(),
    );

    // Access from JS
    let title = ctx
        .eval(Source::from_bytes("document.title"))
        .map_err(|e| format!("get title: {}", e))?;

    let title_str = title
        .to_string(ctx)
        .map_err(|e| format!("to_string: {}", e))?;

    if title_str.to_std_string_escaped() != "Citadel Test" {
        return Err(format!(
            "title mismatch: got '{}'",
            title_str.to_std_string_escaped()
        ));
    }

    Ok(())
}

fn test_value_conversion(ctx: &mut Context) -> Result<(), String> {
    // Test each value type
    let tests = vec![
        ("42", "number"),
        ("'hello'", "string"),
        ("true", "boolean"),
        ("null", "null"),
        ("undefined", "undefined"),
    ];

    for (code, expected_type) in tests {
        let val = ctx
            .eval(Source::from_bytes(code))
            .map_err(|e| format!("{} eval: {}", code, e))?;

        let actual_type = match () {
            _ if val.is_number() => "number",
            _ if val.is_string() => "string",
            _ if val.is_boolean() => "boolean",
            _ if val.is_null() => "null",
            _ if val.is_undefined() => "undefined",
            _ => "unknown",
        };

        if actual_type != expected_type {
            return Err(format!(
                "{}: expected type '{}', got '{}'",
                code, expected_type, actual_type
            ));
        }
    }

    Ok(())
}

fn test_realworld_js(ctx: &mut Context) -> Result<(), String> {
    // Arrow functions
    ctx.eval(Source::from_bytes("const add = (a, b) => a + b; add(2, 3)"))
        .map_err(|e| format!("arrow functions: {}", e))?;

    // Destructuring
    ctx.eval(Source::from_bytes(
        "const {x, y} = {x: 1, y: 2}; x + y",
    ))
    .map_err(|e| format!("destructuring: {}", e))?;

    // Template literals
    ctx.eval(Source::from_bytes(
        "const name = 'Citadel'; `Hello ${name}`",
    ))
    .map_err(|e| format!("template literals: {}", e))?;

    // Spread operator
    ctx.eval(Source::from_bytes(
        "const arr = [1, 2, 3]; const arr2 = [...arr, 4, 5]; arr2.length",
    ))
    .map_err(|e| format!("spread: {}", e))?;

    // Promises (synchronous resolution check)
    ctx.eval(Source::from_bytes(
        "let resolved = false; Promise.resolve().then(() => { resolved = true; }); typeof Promise",
    ))
    .map_err(|e| format!("promises: {}", e))?;

    // Classes
    ctx.eval(Source::from_bytes(
        "class Animal { constructor(name) { this.name = name; } } new Animal('cat').name",
    ))
    .map_err(|e| format!("classes: {}", e))?;

    // async/await syntax (just parsing, not full execution)
    ctx.eval(Source::from_bytes(
        "async function fetchData() { return 42; } typeof fetchData",
    ))
    .map_err(|e| format!("async/await: {}", e))?;

    // Generators
    ctx.eval(Source::from_bytes(
        "function* gen() { yield 1; yield 2; } const g = gen(); g.next().value",
    ))
    .map_err(|e| format!("generators: {}", e))?;

    // for...of
    ctx.eval(Source::from_bytes(
        "let sum = 0; for (const x of [1,2,3]) { sum += x; } sum",
    ))
    .map_err(|e| format!("for...of: {}", e))?;

    // Map and Set
    ctx.eval(Source::from_bytes(
        "const m = new Map(); m.set('key', 'value'); m.get('key')",
    ))
    .map_err(|e| format!("Map: {}", e))?;

    Ok(())
}
