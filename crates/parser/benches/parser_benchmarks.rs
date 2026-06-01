use citadel_parser::{parse_html, security::SecurityContext};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::Arc;

const SIMPLE_HTML: &str = r#"
    <!DOCTYPE html>
    <html>
        <head>
            <title>Test Document</title>
        </head>
        <body>
            <h1>Hello, World!</h1>
            <p>This is a test document with some <strong>bold text</strong> and a <a href="https://example.com">link</a>.</p>
            <div class="container">
                <ul>
                    <li>Item 1</li>
                    <li>Item 2</li>
                    <li>Item 3</li>
                </ul>
            </div>
        </body>
    </html>
"#;

const COMPLEX_HTML: &str = r#"
    <!DOCTYPE html>
    <html>
        <head>
            <title>Complex Test</title>
            <script>alert('xss');</script>
            <style>body { color: red; }</style>
        </head>
        <body>
            <div class="container" onclick="alert('click')">
                <iframe src="http://evil.com"></iframe>
                <img src="x" onerror="alert('error')">
                <form action="http://evil.com">
                    <input type="text" name="test">
                    <button onclick="submit()">Submit</button>
                </form>
                <a href="javascript:alert('click')">Click me</a>
                <custom-element>Custom content</custom-element>
            </div>
        </body>
    </html>
"#;

fn parse_simple_document(c: &mut Criterion) {
    c.bench_function("parse_simple_document", |b| {
        b.iter(|| {
            let ctx = Arc::new(SecurityContext::new(20));
            let _ = parse_html(black_box(SIMPLE_HTML), ctx);
        })
    });
}

fn parse_complex_document(c: &mut Criterion) {
    c.bench_function("parse_complex_document", |b| {
        b.iter(|| {
            // Strict depth bound exercises the sanitizer's fail-closed paths.
            let ctx = Arc::new(SecurityContext::new(10));
            let _ = parse_html(black_box(COMPLEX_HTML), ctx);
        })
    });
}

criterion_group!(benches, parse_simple_document, parse_complex_document);
criterion_main!(benches);
