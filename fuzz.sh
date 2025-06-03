#!/bin/bash

# Check if target and duration are provided
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <target> <duration_seconds>"
    echo "Available targets: html_parser, css_parser, url_parser"
    exit 1
fi

TARGET=$1
DURATION=$2

# Validate target
valid_targets=("html_parser" "css_parser" "url_parser")
if [[ ! " ${valid_targets[@]} " =~ " ${TARGET} " ]]; then
    echo "Error: Invalid target. Available targets are: ${valid_targets[*]}"
    exit 1
fi

# Ensure corpus and artifacts directories exist with proper permissions
mkdir -p fuzz/corpus fuzz/artifacts
chmod -R 777 fuzz/corpus fuzz/artifacts

# Set platform-specific options based on host architecture
if [[ $(uname -m) == "arm64" ]]; then
    PLATFORM_OPTS="--platform linux/amd64"
else
    PLATFORM_OPTS=""
fi

# Build the Docker image
echo "Building Docker image..."
docker build $PLATFORM_OPTS -t citadel-fuzzer -f Dockerfile.fuzz . || exit 1

# Run the fuzzer with the specified target and duration
echo "Starting fuzzer for target: $TARGET with duration: $DURATION seconds"
docker run --rm \
    $PLATFORM_OPTS \
    --security-opt seccomp=unconfined \
    -v "$(pwd)/fuzz/corpus:/citadel/fuzz/corpus:rw" \
    -v "$(pwd)/fuzz/artifacts:/fuzz-artifacts:rw" \
    citadel-fuzzer \
    run "$TARGET" -- \
    -max_total_time=$DURATION 