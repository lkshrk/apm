#!/bin/sh
# Usage: tests/secret-references.sh <wheel path or uvx --from spec>. Runs APM from it (downloads its dependencies).
# Fails if `apm install -g` writes a secret value instead of a reference. Uses a throwaway HOME and fake values.
set -eu

spec=${1:?usage: secret-references.sh <uvx --from spec>}
uvx=$(command -v uvx) || { echo "uvx is required" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
home=$work/home
mkdir -p "$home/.apm" "$home/.codex" "$home/.claude"
printf '{}\n' > "$home/.claude.json"
: > "$home/.codex/config.toml"
cat > "$home/.apm/apm.yml" <<'EOF'
name: secret-test
version: 1.0.0
dependencies:
  mcp:
  - name: http-key
    registry: false
    transport: http
    url: https://example.invalid/mcp/
    headers:
      x-api-key: ${TEST_API_KEY}
  - name: http-bearer
    registry: false
    transport: http
    url: https://example.invalid/gh/
    headers:
      Authorization: Bearer ${TEST_TOKEN}
  - name: stdio-env
    registry: false
    transport: stdio
    command: /bin/true
    env:
      TEST_TOKEN: ${TEST_TOKEN}
targets:
- claude
- codex
EOF

env -i PATH=/usr/bin:/bin HOME="$home" XDG_CACHE_HOME="$work/cache" UV_CACHE_DIR="$HOME/.cache/uv" \
  TEST_API_KEY=fake-key-value TEST_TOKEN=fake-token-value \
  "$uvx" --python 3.12 --from "$spec" apm install -g </dev/null >"$work/install.log" 2>&1 || {
  cat "$work/install.log" >&2
  exit 1
}

if grep -l 'fake-key-value\|fake-token-value' "$home/.claude.json" "$home/.codex/config.toml"; then
  printf '%s\n' "FAIL: $spec wrote secret values into the files above" >&2
  exit 1
fi
printf '%s\n' "PASS: $spec keeps MCP secrets as references for Claude and Codex"
