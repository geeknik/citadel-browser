use criterion::{black_box, criterion_group, criterion_main, Criterion};
use citadel_parser::{HtmlParser, ParserConfig, SecurityLevel};

fn parse_simple_document(c: &mut Criterion) {
    let config = ParserConfig::default();
    let parser = HtmlParser::new(config);

    let html = r#"
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

    c.bench_function("parse_simple_document", |b| {
        b.iter(|| {
            parser.parse_document(black_box(html)).unwrap();
        })
    });
}

fn parse_complex_document(c: &mut Criterion) {
    let mut config = ParserConfig::default();
    config.security_level = SecurityLevel::Maximum;
    let parser = HtmlParser::new(config);

    let html = r#"
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

    c.bench_function("parse_complex_document", |b| {
        b.iter(|| {
            parser.parse_document(black_box(html)).unwrap();
        })
    });
}

criterion_group!(benches, parse_simple_document, parse_complex_document);
criterion_main!(benches); 