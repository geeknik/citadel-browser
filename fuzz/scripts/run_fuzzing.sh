#!/bin/bash

# Exit on any error
set -e

# Build the Docker image
echo "Building fuzzing container..."
docker build -t citadel-fuzzer -f fuzz/Dockerfile .

# Function to run a specific fuzzer
run_fuzzer() {
    local target=$1
    local time=${2:-60}  # Default to 60 seconds if not specified
    
    echo "Running fuzzer for target: $target"
    docker run --rm -v "$(pwd):/citadel" \
        -v "$(pwd)/fuzz/corpus/$target:/fuzzing_corpus" \
        citadel-fuzzer run "$target" \
        -- -max_total_time=$time
}

# Create corpus directories if they don't exist
mkdir -p fuzz/corpus/{html_parser,css_parser,dns_resolver,network_request,parser_metrics}

# If a specific target is provided, run only that target
if [ $# -gt 0 ]; then
    target=$1
    time=${2:-60}
    run_fuzzer "$target" "$time"
    exit 0
fi

# Otherwise run all fuzzers sequentially
echo "Running all fuzzers..."
for target in html_parser css_parser dns_resolver network_request parser_metrics; do
    run_fuzzer "$target" 60
done 