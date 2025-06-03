#!/bin/bash

# Default time limit in seconds (5 minutes)
TIME_LIMIT=${1:-300}

# Ensure we're in the project root
cd "$(git rev-parse --show-toplevel)" || exit 1

# Create artifacts directory if it doesn't exist
mkdir -p fuzz/artifacts

# Build the fuzzing container
echo "Building fuzzing container..."
docker build -t citadel-fuzzer -f fuzz/Dockerfile .

# Run the fuzzing container with volume mounts
echo "Running fuzzers for $TIME_LIMIT seconds each..."
docker run --rm \
    --security-opt seccomp=unconfined \
    -v "$(pwd)/fuzz/artifacts:/citadel/fuzz/artifacts" \
    -v "$(pwd)/fuzz/corpus:/citadel/fuzz/corpus" \
    citadel-fuzzer "$TIME_LIMIT"

# Check for any crashes
if [ -n "$(ls -A fuzz/artifacts 2>/dev/null)" ]; then
    echo "⚠️  Crashes found! Check fuzz/artifacts directory for details"
    exit 1
else
    echo "✅ No crashes found"
    exit 0
fi 