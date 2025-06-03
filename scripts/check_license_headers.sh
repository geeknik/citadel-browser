#!/bin/bash
# Check that all Rust source files have proper license headers

set -e

LICENSE_HEADER="// Copyright (c) 2024 Deep Fork Cyber
// SPDX-License-Identifier: MIT OR Apache-2.0"

EXIT_CODE=0

echo "Checking license headers in Rust files..."

# Find all Rust files, excluding target directory and dependencies
find . -name "*.rs" \
    -not -path "./target/*" \
    -not -path "./fuzz/target/*" \
    -not -path "./.cargo/*" \
    -type f | while read -r file; do
    
    # Skip test files - they don't need license headers
    if [[ "$file" == *"/tests/"* ]] || [[ "$file" == *"test.rs" ]] || [[ "$file" == *"tests.rs" ]]; then
        continue
    fi
    
    # Check if file starts with license header (first few lines)
    if ! head -n 3 "$file" | grep -q "Copyright (c)"; then
        echo "ERROR: Missing license header in $file"
        echo "Expected header:"
        echo "$LICENSE_HEADER"
        echo ""
        EXIT_CODE=1
    fi
done

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ All Rust files have proper license headers"
else
    echo "❌ Some files are missing license headers"
    echo ""
    echo "To fix, add this header to the top of each file:"
    echo "$LICENSE_HEADER"
fi

exit $EXIT_CODE 