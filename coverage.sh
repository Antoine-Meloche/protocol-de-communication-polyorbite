#!/bin/bash

set -e

echo "=== Running Code Coverage ==="

cargo clean &> /dev/null
rm -rf coverage/ *.profraw

export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="coverage-%p-%m.profraw"

cargo build &> /dev/null
cargo test &> /dev/null

if ! command -v grcov &> /dev/null; then
    echo "=== Installing llvm-tools ==="
    rustup component add llvm-tools-preview
    echo "=== Installing grcov... ==="
    cargo install cargo-tarpaulin &> /dev/null
fi

cargo +nightly tarpaulin --all-features --workspace --timeout 120 --out html &> /dev/null

if [[ "$1" == "--open" ]]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open tarpaulin-report.html
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        xdg-open tarpaulin-report.html
    elif [[ "$OSTYPE" == "msys" ]]; then
        start tarpaulin-report.html
    fi
fi

mkdir public
mv tarpaulin-report.html public/index.html

echo "=== Running Documentation Coverage ==="
DOC_OUTPUT=$(cargo doc --all-features --no-deps --document-private-items 2>&1)

rm -f *.profraw

if echo "$DOC_OUTPUT" | grep -qi "warning"; then
    echo "$DOC_OUTPUT" | awk '/warning: missing documentation for a function/{f=1}f' | head -n -2 > doc_coverage.txt
    echo "=== Documentation Coverage Warning ==="
    exit 1
fi

echo "=== Cargo Documentation Coverage Passed ==="
