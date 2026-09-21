#!/usr/bin/env bash
# The console page must not paint a fixed LIGHT background or border in an inline style.
#
# ⚠️ THE CONSOLE HAS A LIGHT AND A DARK THEME, and dark is the default. Its colours come from
# CSS variables that each theme redefines. An inline `background:#fafafa` beats every one of
# them, so it stays light in the dark theme while the text on it follows the theme and turns
# light as well. That is what the key box on the New CA, Import CA and Create CSR forms did:
# a white panel whose labels, token name and PKCS#11 URL were light grey on white, close to
# unreadable. In the light theme it looked right, which is how it shipped.
#
# The fix is a theme variable (`var(--surface-2)`, `var(--surface-sunken)`,
# `var(--border-default)`), which both themes define. This guard reads the page source, so it
# needs no build and no browser.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
SRC="$ROOT/src/web/main.cpp"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# Every background or border colour given as a hex literal whose luminance is light
# (above 160 of 255). Reads stdin, prints one offending declaration per line.
light_fixed(){
    grep -oE '(background(-color)?|border(-(top|bottom|left|right))?(-color)?)[[:space:]]*:[^;"`]*#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?\b' \
    | while IFS= read -r decl; do
        hex=$(printf '%s' "$decl" | grep -oE '#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?\b' | tail -1 | tr -d '#')
        [ ${#hex} -eq 3 ] && hex="${hex:0:1}${hex:0:1}${hex:1:1}${hex:1:1}${hex:2:1}${hex:2:1}"
        r=$((16#${hex:0:2})); g=$((16#${hex:2:2})); b=$((16#${hex:4:2}))
        [ $(( (r*299 + g*587 + b*114) / 1000 )) -gt 160 ] && printf '%s\n' "$decl"
      done
    return 0
}

echo "=== the scanner itself ==="
# ⚠️ A SCANNER THAT MATCHES NOTHING PASSES FOREVER. Prove it catches each shape it exists for,
# and leaves a dark colour and a theme variable alone.
chk "PRECONDITION: catches a light background" 1 \
    "$(printf '%s' '<div style="padding:8px;background:#fafafa">' | light_fixed | wc -l | tr -d ' ')"
chk "PRECONDITION: catches a light border"     1 \
    "$(printf '%s' '<div style="border:1px solid #ddd;padding:8px">' | light_fixed | wc -l | tr -d ' ')"
chk "PRECONDITION: catches a 3-digit hex"      1 \
    "$(printf '%s' '<input style="width:100%;background:#eee">' | light_fixed | wc -l | tr -d ' ')"
chk "PRECONDITION: ignores a dark background"  0 \
    "$(printf '%s' '<a style="background:#374151;color:#fff">' | light_fixed | wc -l | tr -d ' ')"
chk "PRECONDITION: ignores a theme variable"   0 \
    "$(printf '%s' '<div style="background:var(--surface-2)">' | light_fixed | wc -l | tr -d ' ')"

echo "=== the console page ==="
# The page is the INDEX_HTML raw string. Only its markup and inline styles matter here: the
# stylesheet's own token definitions (`--surface-1: #FFFFFF;`) are the light theme and are
# supposed to be light.
PAGE=$(awk '/R"HTML\(/{s=1} s{print} /^\)HTML";/{exit}' "$SRC")
chk "PRECONDITION: found the console page" yes "$([ "$(printf '%s\n' "$PAGE" | wc -l)" -gt 1000 ] && echo yes || echo no)"
BAD=$(printf '%s\n' "$PAGE" | grep -vE '^[[:space:]]*--[a-z0-9-]+[[:space:]]*:' | light_fixed)
chk "no fixed light background or border in the console page" "" "$BAD"

echo
echo "=== WEB THEME COLORS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
