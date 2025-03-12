#!/bin/bash

set -e

echo "=== Running Code Coverage ==="

cargo clean &> /dev/null
rm -rf public
rm -rf *.profraw

export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="coverage-%p-%m.profraw"

echo "=== Installing rust nightly"
# rustup toolchain add nightly-x86_64-unknown-linux-gnu &> /dev/null

echo "=== Installing llvm-tools ==="
# rustup component add llvm-tools-preview &> /dev/null

echo "=== Installing llvm-cov... ==="
# cargo install cargo-llvm-cov &> /dev/null

echo "=== Running coverage ==="
cargo llvm-cov --all-features --html #&> /dev/null

mkdir -p public
mv target/llvm-cov/html/* public/.

if [[ "$1" == "--open" ]]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open public/index.html
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open public/index.html
    elif [[ "$OSTYPE" == "msys" ]]; then
        start public/index.html
    fi
fi

echo "=== Running Documentation Coverage ==="
DOC_OUTPUT=$(cargo doc --all-features --no-deps --document-private-items 2>&1)

if echo "$DOC_OUTPUT" | grep -qi "warning"; then
    echo "$DOC_OUTPUT" | awk '/warning: missing documentation for a function/{f=1}f' | head -n -2 > doc_coverage.txt
    echo "=== Documentation Coverage Warning ==="
    exit 1
fi

echo "=== Cargo Documentation Coverage Passed ==="

rm -rf *.profraw
