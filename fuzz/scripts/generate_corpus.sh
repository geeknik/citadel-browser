#!/bin/bash
# Script to generate initial corpus files for Citadel Browser fuzzing

set -e

# Ensure we're in the fuzz directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.."

# Create corpus directories if they don't exist
mkdir -p corpus/dns_resolver
mkdir -p corpus/html_parser
mkdir -p corpus/css_parser
mkdir -p corpus/network_request

# Generate DNS resolver corpus
echo "Generating DNS resolver corpus..."
cat > corpus/dns_resolver/common_domains.txt << EOF
example.com
google.com
cloudflare.com
github.com
mozilla.org
rust-lang.org
wikipedia.org
localhost
EOF

cat > corpus/dns_resolver/malformed_domains.txt << EOF
a..b.com
xn--ls8h.example
example:1234
*.wildcard.com
example.com.
.example.com
exa mple.com
EOF

cat > corpus/dns_resolver/long_domain.txt << EOF
thisisaveryveryveryveryveryveryveryveryveryveryveryveryveryveryveryverylongdomainname.com
EOF

cat > corpus/dns_resolver/ipv6_domain.txt << EOF
ipv6.google.com
EOF

# Generate HTML parser corpus
echo "Generating HTML parser corpus..."
cat > corpus/html_parser/simple.html << EOF
<!DOCTYPE html>
<html>
<head>
  <title>Simple HTML</title>
  <meta charset="utf-8">
</head>
<body>
  <h1>Hello World</h1>
  <p>This is a paragraph with <a href="https://example.com">a link</a>.</p>
</body>
</html>
EOF

cat > corpus/html_parser/nested.html << EOF
<!DOCTYPE html>
<html>
<body>
  <div>
    <div>
      <div>
        <div>
          <div>
            <div>
              <div>Deeply nested</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>
EOF

cat > corpus/html_parser/script.html << EOF
<!DOCTYPE html>
<html>
<head>
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      console.log('Hello from script!');
    });
  </script>
</head>
<body>
  <script src="https://example.com/script.js"></script>
  <div onclick="alert('clicked')">Click me</div>
</body>
</html>
EOF

cat > corpus/html_parser/attributes.html << EOF
<!DOCTYPE html>
<html>
<body>
  <img src="image.jpg" alt="Image" width="100" height="100" data-custom="value" aria-label="Accessible" class="img responsive" id="main-image" loading="lazy" />
</body>
</html>
EOF

cat > corpus/html_parser/malformed.html << EOF
<html>
<not-closed
<div>
<p>Unclosed tags
<img src=no-quotes>
</ unexpected>
<div class="no-close
EOF

# Generate CSS parser corpus
echo "Generating CSS parser corpus..."
cat > corpus/css_parser/simple.css << EOF
body {
  font-family: Arial, sans-serif;
  color: #333;
  background-color: #f5f5f5;
  margin: 0;
  padding: 20px;
}

h1 {
  color: #0066cc;
  font-size: 24px;
}

.container {
  max-width: 1200px;
  margin: 0 auto;
}
EOF

cat > corpus/css_parser/complex.css << EOF
@media screen and (max-width: 768px) {
  body {
    font-size: 14px;
  }
}

@keyframes fade {
  from { opacity: 0; }
  to { opacity: 1; }
}

.header:after {
  content: "";
  display: block;
  clear: both;
}

#main > div[data-role="panel"] {
  border-radius: 4px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}
EOF

cat > corpus/css_parser/tricky.css << EOF
* { box-sizing: border-box !important; }

input[type="text"]:focus:not(.disabled) {
  border-color: var(--primary-color);
}

body {
  background: url("image.jpg") repeat fixed center;
  color: rgba(0, 0, 0, 0.8);
}

@supports (display: grid) {
  .container {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  }
}
EOF

cat > corpus/css_parser/functions.css << EOF
.element {
  width: calc(100% - 20px);
  background: linear-gradient(to right, #f00, #00f);
  transform: translate(10px, 20px) rotate(45deg);
  margin: clamp(10px, 2vw, 30px);
}
EOF

# Generate network request corpus
echo "Generating network request corpus..."
cat > corpus/network_request/simple_get.bin << EOF
GET https://example.com HTTP/1.1
Host: example.com
User-Agent: CitadelBrowser/1.0
Accept: text/html,application/xhtml+xml
EOF

cat > corpus/network_request/post_json.bin << EOF
POST https://api.example.com/data HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Length: 27

{"username":"test","id":123}
EOF

cat > corpus/network_request/headers.bin << EOF
GET https://example.com HTTP/1.1
Host: example.com
User-Agent: CitadelBrowser/1.0
Accept: text/html,application/xhtml+xml
Referer: https://referrer.com
Cookie: session=123abc; token=xyz789
X-Requested-With: XMLHttpRequest
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
Cache-Control: no-cache
Connection: keep-alive
EOF

cat > corpus/network_request/tracking_params.bin << EOF
GET https://example.com/?utm_source=test&utm_medium=email&utm_campaign=spring&fbclid=123&gclid=456 HTTP/1.1
Host: example.com
EOF

echo "Corpus generation complete!"
echo "Generated corpus files in:"
echo "  - corpus/dns_resolver/"
echo "  - corpus/html_parser/"
echo "  - corpus/css_parser/"
echo "  - corpus/network_request/" 