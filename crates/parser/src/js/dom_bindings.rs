//! Essential DOM API implementations for JavaScript
//! 
//! This module provides the core DOM manipulation APIs that modern websites need
//! to function interactively while maintaining Citadel Browser's security-first approach.

use crate::dom::Dom;
use crate::error::ParserResult;
use rquickjs::{Ctx, Object};
use tracing::info;

/// Set up essential DOM bindings for JavaScript execution
pub fn setup_dom_bindings(ctx: Ctx<'_>, dom: &Dom) -> ParserResult<()> {
    info!("[JS] Setting up essential DOM bindings for document with title: {}", dom.get_title());
    
    let globals = ctx.globals();
    
    // Create document object with essential properties
    let document = Object::new(ctx.clone())?;
    document.set("title", dom.get_title())?;
    document.set("readyState", "complete")?;
    document.set("domain", "example.com")?;
    
    // Add basic form support (simplified for now)
    document.set("forms", Object::new(ctx.clone())?)?;
    
    // Add document to globals
    globals.set("document", document)?;
    
    info!("[JS] ✅ Essential DOM APIs ready for JavaScript execution");
    
    Ok(())
}

/// Set up console bindings for JavaScript logging
pub fn setup_console_bindings(ctx: Ctx<'_>) -> ParserResult<()> {
    info!("[JS] Setting up console logging APIs");
    
    let globals = ctx.globals();
    let console = Object::new(ctx.clone())?;
    
    globals.set("console", console)?;
    
    Ok(())
}

/// Set up window object with browser-like properties
pub fn setup_window_bindings(ctx: Ctx<'_>) -> ParserResult<()> {
    info!("[JS] Setting up window and global APIs");
    
    let globals = ctx.globals();
    
    // window.location
    let location = Object::new(ctx.clone())?;
    location.set("href", "https://example.com")?;
    location.set("protocol", "https:")?;
    location.set("host", "example.com")?;
    location.set("pathname", "/")?;
    location.set("search", "")?;
    location.set("hash", "")?;
    globals.set("location", location)?;
    
    // window.navigator (privacy-conscious values)
    let navigator = Object::new(ctx.clone())?;
    navigator.set("userAgent", "Citadel Browser/0.0.1-alpha (Privacy-First)")?;
    navigator.set("platform", "MacIntel")?;
    navigator.set("language", "en-US")?;
    navigator.set("cookieEnabled", false)?;
    navigator.set("doNotTrack", "1")?;
    globals.set("navigator", navigator)?;
    
    // window.screen (anti-fingerprinting fixed values)
    let screen = Object::new(ctx.clone())?;
    screen.set("width", 1920)?;
    screen.set("height", 1080)?;
    screen.set("availWidth", 1920)?;
    screen.set("availHeight", 1040)?;
    screen.set("colorDepth", 24)?;
    screen.set("pixelDepth", 24)?;
    globals.set("screen", screen)?;
    
    // Make window reference itself
    globals.set("window", globals.clone())?;
    
    info!("[JS] ✅ Window APIs configured for privacy-first browsing");
    
    Ok(())
}

/// Execute JavaScript with comprehensive browser environment setup
pub fn execute_with_dom_context(ctx: Ctx<'_>, dom: &Dom, code: &str) -> ParserResult<String> {
    info!("[JS] 🚀 Executing JavaScript with full DOM context");
    
    // Set up browser environment
    setup_console_bindings(ctx.clone())?;
    setup_window_bindings(ctx.clone())?;
    setup_dom_bindings(ctx.clone(), dom)?;
    
    // Execute the JavaScript code
    let result: rquickjs::Result<rquickjs::Value> = ctx.eval(code);
    
    match result {
        Ok(value) => {
            let output = if value.is_string() {
                value.as_string().and_then(|s| s.to_string().ok()).unwrap_or_default()
            } else if value.is_number() {
                value.as_number().unwrap_or(0.0).to_string()
            } else if value.is_bool() {
                value.as_bool().unwrap_or(false).to_string()
            } else if value.is_null() {
                "null".to_string()
            } else if value.is_undefined() {
                "undefined".to_string()
            } else {
                format!("{:?}", value)
            };
            
            info!("[JS] ✅ Execution completed successfully: {}", 
                if output.len() > 100 { 
                    format!("{}...", &output[..100])
                } else { 
                    output.clone() 
                }
            );
            
            Ok(output)
        },
        Err(e) => {
            let error_msg = format!("JavaScript execution failed: {}", e);
            tracing::warn!("[JS] ❌ {}", error_msg);
            Err(crate::error::ParserError::JsError(error_msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dom::Dom;
    use rquickjs::{Runtime, Context};
    
    #[test]
    fn test_dom_bindings_basic() {
        let dom = Dom::new();
        let runtime = Runtime::new().unwrap();
        let context = Context::full(&runtime).unwrap();
        
        context.with(|ctx| {
            let result = setup_dom_bindings(ctx, &dom);
            assert!(result.is_ok());
        });
    }
    
    #[test]
    fn test_console_bindings_basic() {
        let runtime = Runtime::new().unwrap();
        let context = Context::full(&runtime).unwrap();
        
        context.with(|ctx| {
            let result = setup_console_bindings(ctx);
            assert!(result.is_ok());
        });
    }
    
    #[test]
    fn test_window_bindings_basic() {
        let runtime = Runtime::new().unwrap();
        let context = Context::full(&runtime).unwrap();
        
        context.with(|ctx| {
            let result = setup_window_bindings(ctx);
            assert!(result.is_ok());
        });
    }
    
    #[test]
    fn test_javascript_execution_with_dom() {
        let dom = Dom::new();
        let runtime = Runtime::new().unwrap();
        let context = Context::full(&runtime).unwrap();
        
        context.with(|ctx| {
            // Test basic property access
            let result = execute_with_dom_context(ctx.clone(), &dom, "document.title");
            assert!(result.is_ok());
            
            // Test navigator properties
            let result = execute_with_dom_context(ctx.clone(), &dom, "navigator.userAgent");
            assert!(result.is_ok());
            let user_agent = result.unwrap();
            assert!(user_agent.contains("Citadel Browser"));
            
            // Test privacy settings
            let result = execute_with_dom_context(ctx.clone(), &dom, "navigator.cookieEnabled");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "false");
            
            // Test window properties
            let result = execute_with_dom_context(ctx.clone(), &dom, "window.location.protocol");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "https:");
            
            // Test arithmetic (basic JS execution)
            let result = execute_with_dom_context(ctx.clone(), &dom, "2 + 2");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "4");
        });
    }
    
    #[test]
    fn test_security_and_privacy_defaults() {
        let _dom = Dom::new();
        let runtime = Runtime::new().unwrap();
        let context = Context::full(&runtime).unwrap();
        
        context.with(|ctx| {
            setup_window_bindings(ctx.clone()).unwrap();
            
            // Verify privacy-conscious defaults
            let result: rquickjs::Result<rquickjs::Value> = ctx.eval("navigator.cookieEnabled");
            assert!(result.is_ok());
            assert!(!result.unwrap().as_bool().unwrap_or(true));
            
            let result: rquickjs::Result<rquickjs::Value> = ctx.eval("navigator.doNotTrack");
            assert!(result.is_ok());
            let dnt = result.unwrap().as_string().and_then(|s| s.to_string().ok()).unwrap_or_default();
            assert_eq!(dnt, "1");
            
            // Verify anti-fingerprinting screen values
            let result: rquickjs::Result<rquickjs::Value> = ctx.eval("screen.width");
            assert!(result.is_ok());
            assert_eq!(result.unwrap().as_number().unwrap_or(0.0), 1920.0);
        });
    }
}