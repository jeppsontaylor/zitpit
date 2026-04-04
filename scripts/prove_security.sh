#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo " ZitPit Workspace Security Enforcement Proof"
echo "=========================================================="
echo ""
echo "Note: This is a convenience wrapper over xtask subcommands"
echo ""

echo "1) Validating behavior policy core rules (Rust Unit Tests)..."
cargo test -p zitpit-core -p zitpit-sessiond

echo ""
echo "2) Validating attack scenario completeness (Battle Lints)..."
cargo run -q -p xtask -- battle lint

echo ""
echo "3) Running malicious & benign shell execution assertions (Battle Packs)..."
cargo run -q -p xtask -- battle shell

echo ""
echo "3.5) Running governed egress DLP assertions..."
cargo run -q -p xtask -- battle egress

echo ""
echo "4) Firing live SSH containment penetration tests (xtask demo smoke)..."
cargo run -p xtask -- demo smoke

echo ""
echo "=========================================================="
echo " SUCCESS: All strict enforcement gates were validated!"
echo "=========================================================="
