#!/bin/bash
# Run all fuzzers with enhanced memory debugging

set -e

# Ensure we're in the fuzz directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/.."

# Generate corpus if needed
if [ ! -d "corpus/dns_resolver" ] || [ ! -d "corpus/html_parser" ] || [ ! -d "corpus/css_parser" ] || [ ! -d "corpus/network_request" ]; then
  echo "Generating corpus..."
  ./scripts/generate_corpus.sh
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Runtime in seconds for each fuzzer
RUNTIME=${1:-30}
echo -e "${BLUE}Running each fuzzer for ${RUNTIME} seconds${NC}"

# List of fuzzers to run
FUZZERS=(
  "dns_resolver"
  "html_parser"
  "css_parser"
  "network_request"
)

# Check if grcov is installed for coverage reporting
COVERAGE=0
if command -v grcov &> /dev/null; then
  COVERAGE=1
  echo -e "${GREEN}grcov found, will generate coverage reports${NC}"
  mkdir -p coverage_reports
else
  echo -e "${YELLOW}grcov not found, skipping coverage reports${NC}"
  echo -e "${YELLOW}Install with: cargo install grcov${NC}"
fi

# Run each fuzzer
for FUZZER in "${FUZZERS[@]}"; do
  echo -e "\n${PURPLE}========== Running $FUZZER fuzzer ==========${NC}"
  
  # Run with memory sanitizer
  echo -e "${BLUE}Building $FUZZER with Address Sanitizer...${NC}"
  
  # Check if dictionary exists
  DICT_FLAG=""
  if [ -f "dictionaries/${FUZZER}.dict" ]; then
    echo -e "${GREEN}Found dictionary for $FUZZER${NC}"
    DICT_FLAG="-dict=dictionaries/${FUZZER}.dict"
  fi
  
  # Run the fuzzer
  echo -e "${BLUE}Running $FUZZER for ${RUNTIME} seconds...${NC}"
  echo -e "${YELLOW}Memory checking enabled, performance will be slower${NC}"
  
  # Set environment variables for better detection
  export RUSTFLAGS="-Zsanitizer=address -Copt-level=0"
  export ASAN_OPTIONS="detect_leaks=1:symbolize=1:detect_stack_use_after_return=1:detect_invalid_pointer_pairs=1:detect_container_overflow=1:abort_on_error=1:allocator_may_return_null=1:check_malloc_usable_size=0:handle_abort=1:handle_sigill=1"
  
  # Start time
  START_TIME=$(date +%s)
  
  # Run the fuzzer with a timeout
  timeout ${RUNTIME}s cargo fuzz run ${FUZZER} corpus/${FUZZER} \
    ${DICT_FLAG} \
    -max_total_time=${RUNTIME} \
    -print_final_stats=1 \
    -use_value_profile=1 \
    -detect_leaks=1 \
    -rss_limit_mb=4096 \
    || if [ $? -eq 124 ]; then 
         echo -e "${GREEN}Timeout reached, no bugs found${NC}"; 
       else 
         echo -e "${RED}Fuzzer exited with error${NC}"; 
         exit 1; 
       fi
  
  # End time
  END_TIME=$(date +%s)
  ELAPSED=$((END_TIME - START_TIME))
  echo -e "${GREEN}Completed in ${ELAPSED} seconds${NC}"
  
  # Generate coverage report if grcov is available
  if [ $COVERAGE -eq 1 ]; then
    echo -e "${BLUE}Generating coverage report for $FUZZER...${NC}"
    
    # Run with coverage instrumentation
    RUSTFLAGS="-Zinstrument-coverage" cargo run --bin ${FUZZER} -- \
      corpus/${FUZZER}/* \
      2>/dev/null || true
    
    grcov . --binary-path ./target/debug/ -s . -t html --branch --ignore-not-existing \
      --ignore "/*" --ignore "target/*" \
      -o coverage_reports/${FUZZER}
    
    echo -e "${GREEN}Coverage report generated in coverage_reports/${FUZZER}/index.html${NC}"
  fi
done

echo -e "\n${GREEN}All fuzzing completed successfully!${NC}"
echo -e "${BLUE}Check for any crashes in artifacts/ directory${NC}"
if [ $COVERAGE -eq 1 ]; then
  echo -e "${BLUE}Coverage reports available in coverage_reports/ directory${NC}"
fi 