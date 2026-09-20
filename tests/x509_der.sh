# RFC 4387 store selectors in shell — the suite is shell-only.
#
# The certstore is indexed by four SHA-1 selectors, and every one of them hashes DER, not
# text. That is why this slices bytes straight out of the certificate instead of rebuilding
# a Name from `openssl x509 -subject` output: a re-encoded Name can land on a different
# string type (PRINTABLESTRING vs UTF8STRING for the same characters) and produce a hash
# that is wrong while looking entirely plausible. The whole point of these suites is to
# recompute the selectors INDEPENDENTLY of the server, so the recomputation has to be
# byte-exact or it proves nothing.
#
#   x509_selectors <pem>   -> echoes "sHash iHash iAndSHash sKIDHash" (lowercase hex)
#
# Requires $OSSL. Layout relied upon (X.509 v3, RFC 5280 §4.1): inside tbsCertificate the
# constructed SEQUENCEs at depth 2 are, in order,
#   [0] signature AlgorithmIdentifier  [1] issuer  [2] validity  [3] subject  [4] SPKI
# and the first primitive INTEGER at depth 2 is the serial. Both are structural
# requirements of the standard, not a property of how we happen to issue.

# Raw bytes of one TLV: header + content, straight out of the file.
_der_slice() {   # <der-file> <offset> <hl> <len>
    dd if="$1" bs=1 skip="$2" count=$(( $3 + $4 )) 2>/dev/null
}

# A DER SEQUENCE header for <content-length>. Short form under 128, else long form —
# issuer+serial is usually short, but a certificate with a long issuer DN is not exotic
# and a hardcoded short form would corrupt exactly those.
_der_seq_hdr() {
    local n=$1
    if   [ "$n" -lt 128 ]; then printf '\x30'; printf "\\x$(printf %02x "$n")"
    elif [ "$n" -lt 256 ]; then printf '\x30\x81'; printf "\\x$(printf %02x "$n")"
    else printf '\x30\x82'; printf "\\x$(printf %02x $(( n >> 8 )))\\x$(printf %02x $(( n & 255 )))"
    fi
}

_sha1hex() { "$OSSL" dgst -sha1 -r "$1" 2>/dev/null | cut -d' ' -f1; }

# hex string -> raw bytes. Not `xxd -r -p`: xxd ships with vim, so it is absent on a
# minimal container, and these suites must run anywhere (§3d).
_hex2bin() {
    local h=$1
    while [ -n "$h" ]; do printf "\\x${h:0:2}"; h=${h:2}; done
}

x509_selectors() {   # <pem>
    local pem=$1 w der parse seqs serial_line off hl len i
    w=$(mktemp -d); der="$w/c.der"
    "$OSSL" x509 -in "$pem" -outform DER -out "$der" 2>/dev/null || { rm -rf "$w"; return 1; }
    parse=$("$OSSL" asn1parse -inform DER -in "$der" 2>/dev/null)

    # depth-2 constructed SEQUENCEs, in document order
    seqs=$(printf '%s\n' "$parse" \
        | sed -n 's/^ *\([0-9]*\):d=2 *hl=\([0-9]*\) *l= *\([0-9]*\) *cons: SEQUENCE.*/\1 \2 \3/p')
    # first depth-2 primitive INTEGER is the serial
    serial_line=$(printf '%s\n' "$parse" \
        | sed -n 's/^ *\([0-9]*\):d=2 *hl=\([0-9]*\) *l= *\([0-9]*\) *prim: INTEGER.*/\1 \2 \3/p' | head -1)

    i=0
    while read -r off hl len; do
        [ -n "$off" ] || continue
        case $i in
            1) _der_slice "$der" "$off" "$hl" "$len" > "$w/issuer.der" ;;
            3) _der_slice "$der" "$off" "$hl" "$len" > "$w/subject.der" ;;
        esac
        i=$((i+1))
    done <<EOF
$seqs
EOF
    set -- $serial_line
    _der_slice "$der" "$1" "$2" "$3" > "$w/serial.der"

    # issuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
    cat "$w/issuer.der" "$w/serial.der" > "$w/ias_body"
    { _der_seq_hdr "$(wc -c < "$w/ias_body" | tr -d ' ')"; cat "$w/ias_body"; } > "$w/ias.der"

    # sKIDHash is over the extension's octets, so take the value the cert publishes rather
    # than recomputing SHA-1 over the public key: an issuer is free to derive the SKI by
    # any method RFC 5280 §4.2.1.2 allows, and the store indexes what was actually issued.
    local skihex
    skihex=$("$OSSL" x509 -in "$pem" -noout -ext subjectKeyIdentifier 2>/dev/null \
        | tr -d ' \n' | grep -oE '([0-9A-Fa-f]{2}:){3,}[0-9A-Fa-f]{2}' | head -1 | tr -d ':')
    _hex2bin "$skihex" > "$w/ski.bin"

    printf '%s %s %s %s\n' \
        "$(_sha1hex "$w/subject.der")" "$(_sha1hex "$w/issuer.der")" \
        "$(_sha1hex "$w/ias.der")"     "$(_sha1hex "$w/ski.bin")"
    rm -rf "$w"
}
