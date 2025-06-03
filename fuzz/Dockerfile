# Use Ubuntu as base for better LLVM/sanitizer support
FROM ubuntu:22.04

# Install essential packages and Rust
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    llvm \
    clang \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Add cargo to PATH
ENV PATH="/root/.cargo/bin:${PATH}"

# Install nightly toolchain and required components
RUN rustup default nightly && \
    rustup component add llvm-tools-preview && \
    cargo install cargo-fuzz

# Create workspace directory
WORKDIR /citadel

# Copy project files
COPY . .

# Create a script to run fuzzers
RUN echo '#!/bin/bash\n\
# Default time limit in seconds (5 minutes)\n\
TIME_LIMIT=${1:-300}\n\
\n\
# Run each fuzzer with specified time limit\n\
for fuzzer in search_worker tab_persistence dns_resolver html_parser css_parser network_request; do\n\
    echo "Running $fuzzer fuzzer for $TIME_LIMIT seconds..."\n\
    timeout $TIME_LIMIT cargo fuzz run $fuzzer -- -max_total_time=$TIME_LIMIT\n\
    \n\
    # Check exit status\n\
    if [ $? -eq 124 ]; then\n\
        echo "$fuzzer completed successfully (timeout)"\n\
    elif [ $? -ne 0 ]; then\n\
        echo "$fuzzer failed!"\n\
        exit 1\n\
    else\n\
        echo "$fuzzer completed successfully"\n\
    fi\n\
done\n\
' > /usr/local/bin/run-fuzzers.sh

# Make the script executable
RUN chmod +x /usr/local/bin/run-fuzzers.sh

# Set environment variables for better fuzzing
ENV RUSTFLAGS="-Zsanitizer=address" \
    ASAN_OPTIONS="detect_leaks=1:symbolize=1" \
    RUST_BACKTRACE=1

# Default command to run all fuzzers
CMD ["/usr/local/bin/run-fuzzers.sh"] 