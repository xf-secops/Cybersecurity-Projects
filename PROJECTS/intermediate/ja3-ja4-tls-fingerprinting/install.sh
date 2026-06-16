#!/usr/bin/env bash
# ©AngelaMos | 2026
# install.sh

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { printf "${CYAN}==>${NC} %s\n" "$1"; }
ok()   { printf "${GREEN}OK${NC}   %s\n" "$1"; }
warn() { printf "${YELLOW}WARN${NC} %s\n" "$1"; }
fail() { printf "${RED}ERROR${NC} %s\n" "$1" >&2; exit 1; }

JA4DB_URL="${JA4DB_URL:-https://ja4db.com/api/read/}"
JA4DB_TIMEOUT="${JA4DB_TIMEOUT:-180}"

SETCAP=0
for arg in "$@"; do
    case "$arg" in
        --live) SETCAP=1 ;;
        -h|--help)
            cat <<'EOF'
Usage: ./install.sh [--live]

Builds the release binary, seeds the bundled intelligence feeds, and pulls the
ja4db.com enrichment feed. Pass --live to also grant the capabilities live
capture needs (this step uses sudo).
EOF
            exit 0
            ;;
        *) fail "unknown argument: $arg (try --help)" ;;
    esac
done

cd "$(dirname "$0")"

command -v cargo >/dev/null 2>&1 || fail "cargo not found; install Rust from https://rustup.rs"

info "Building the release binary"
cargo build --release
BIN="$PWD/target/release/tlsfp"
[ -x "$BIN" ] || fail "build succeeded but $BIN is missing"
ok "built $BIN"

info "Seeding the bundled feeds (abuse.ch SSLBL, salesforce/ja3, curated C2)"
"$BIN" intel seed
ok "bundled feeds loaded"

info "Fetching the ja4db.com enrichment feed"
if ! command -v curl >/dev/null 2>&1; then
    warn "curl not found; skipping ja4db. The bundled feeds still work."
else
    TMP="$(mktemp)"
    trap 'rm -f "$TMP"' EXIT
    if curl -fsSL --max-time "$JA4DB_TIMEOUT" "$JA4DB_URL" -o "$TMP"; then
        "$BIN" intel import "$TMP"
        ok "ja4db imported"
    else
        warn "could not reach $JA4DB_URL (it is large and often slow)."
        warn "the bundled feeds still work; retry later with:"
        printf "       %s intel import <(curl -fsSL %s)\n" "$BIN" "$JA4DB_URL"
    fi
fi

if [ "$SETCAP" -eq 1 ]; then
    info "Granting live capture capabilities (needs sudo)"
    if command -v setcap >/dev/null 2>&1; then
        if sudo setcap cap_net_raw,cap_net_admin=eip "$BIN"; then
            ok "live capture enabled for $BIN"
        else
            warn "setcap failed; run live capture under sudo, or grant it later with:"
            printf "       sudo setcap cap_net_raw,cap_net_admin=eip %s\n" "$BIN"
        fi
    else
        warn "setcap not found (install libcap2-bin); run live capture under sudo instead"
    fi
fi

printf "\n"
ok "Done. The binary is at $BIN"
cat <<EOF

Next steps:
  $BIN intel stats                       show what the database holds
  $BIN intel lookup ja3 <hash>           look one fingerprint up
  $BIN pcap --intel <file.pcap>          fingerprint a capture and flag known intel
  $BIN live --intel <iface>              the same, live (needs --live above or sudo)

To put tlsfp on your PATH:
  cargo install --path crates/tlsfp
EOF
