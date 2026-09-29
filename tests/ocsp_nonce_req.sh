#!/usr/bin/env bash
# Emit a DER OCSP request for the given cert (as both subject and issuer, which is fine
# for a self-signed CA) carrying a nonce of an ARBITRARY length. ocsp_abuse.sh uses it to
# exercise RFC 8954 nonce-length handling, which `openssl ocsp` cannot do — the CLI has
# no nonce-length control, only -nonce/-no_nonce.
#
#   ocsp_nonce_req.sh <ca.pem> <nonce_len>  > req.der
#
# §3e: replaces tests/ocsp_nonce_req.py. The CertID is NOT hand-computed — issuerNameHash
# and issuerKeyHash are hashes over DER substructures of the certificate, and extracting
# those by offset is exactly the fragile thing that breaks on an unusual certificate. So
# openssl builds a nonce-less request for us and we lift its CertID verbatim; only the
# nonce extension and the enclosing lengths are assembled here.
#
# Proven byte-for-byte identical to the Python driver it replaces (ocsp_nonce_shell.sh).
set -u
OSSL=${OSSL:-openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
CA=${1:?ocsp_nonce_req.sh <ca.pem> <nonce_len>}
NLEN=${2:?ocsp_nonce_req.sh <ca.pem> <nonce_len>}

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT

# DER length octets for a given content length. Short form under 128, else long form —
# 0x81 for one length byte, 0x82 for two. Nothing here approaches 65535.
derlen() {
    local n=$1
    if   [ "$n" -lt 128 ];   then printf '%02x' "$n"
    elif [ "$n" -lt 256 ];   then printf '81%02x' "$n"
    else                          printf '82%02x%02x' $((n / 256)) $((n % 256))
    fi
}
# <tag-hex> <content-hex> -> a complete TLV
tlv() { printf '%s%s%s' "$1" "$(derlen $(( ${#2} / 2 )))" "$2"; }

# 1. Let openssl compute the CertID. -no_nonce, so the request carries requestList and
#    nothing else, which makes the CertID the only SEQUENCE of interest.
"$OSSL" ocsp -issuer "$CA" -cert "$CA" -no_nonce -reqout "$W/base.der" >/dev/null 2>&1 \
    || { echo "ocsp_nonce_req.sh: openssl could not build a request from $CA" >&2; exit 1; }

# 2. Lift the CertID verbatim. It is the SEQUENCE holding the SHA-1 OID, so select it by
#    that rather than by a fixed offset.
#    ⚠️ ONE LEVEL UP from the SHA-1 OID, not the SEQUENCE nearest it. CertID is
#      SEQ { AlgorithmIdentifier { sha1, NULL }, nameHash, keyHash, serial }, so the
#      SEQUENCE immediately preceding the OID is the AlgorithmIdentifier. Taking that one
#      produced a well-formed request that parsed cleanly and was 66 bytes short — the
#      whole CertID missing, with nothing complaining. Track the innermost SEQUENCE seen at
#      each depth and pick the parent's.
OFF=$("$OSSL" asn1parse -inform DER -in "$W/base.der" 2>/dev/null | awk -F: '
    /cons: SEQUENCE/ { off=$1; gsub(/ /,"",off)
                       match($0, /d=[0-9]+/)
                       dep=substr($0, RSTART+2, RLENGTH-2)
                       seq[dep]=off; lastdep=dep }
    /OBJECT.*:sha1/  { print seq[lastdep-1]; exit }')
[ -n "$OFF" ] || { echo "ocsp_nonce_req.sh: no SHA-1 CertID in the generated request" >&2; exit 1; }
"$OSSL" asn1parse -inform DER -in "$W/base.der" -strparse "$OFF" -out "$W/certid.der" -noout 2>/dev/null \
    || { echo "ocsp_nonce_req.sh: could not extract the CertID" >&2; exit 1; }
# ⚠️ `-strparse … -out` writes the COMPLETE TLV, header included — not the bare content.
# Re-adding a SEQUENCE header here produced a request that parsed cleanly, carried the
# correct issuerNameHash and issuerKeyHash, and was simply nested one level too deep. Both
# openssl and the responder read it without complaint; only a byte-for-byte comparison
# against the driver being replaced showed it.
CERTID=$(od -An -v -tx1 < "$W/certid.der" | tr -d ' \n')

# 3. The nonce. RFC 8954: extnValue is an OCTET STRING whose content is a DER-encoded
#    OCTET STRING of the nonce itself — the double wrap is not a mistake.
NONCE=$(awk -v n="$NLEN" 'BEGIN{ s=""; while (length(s) < n*2) s = s "ab"; print substr(s,1,n*2) }')
EXTNVAL=$(tlv 04 "$NONCE")                       # inner  OCTET STRING (the nonce)
OID=06092b0601050507300102                       # 1.3.6.1.5.5.7.48.1.2, id-pkix-ocsp-nonce
EXT=$(tlv 30 "$OID$(tlv 04 "$EXTNVAL")")         # Extension ::= SEQ { extnID, extnValue }
EXTS=$(tlv 30 "$EXT")                            # Extensions ::= SEQUENCE OF Extension
REQEXTS=$(tlv a2 "$EXTS")                        # [2] EXPLICIT

# 4. Assemble, outermost last.
REQUEST=$(tlv 30 "$CERTID")                      # Request ::= SEQ { reqCert }
REQLIST=$(tlv 30 "$REQUEST")                     # requestList ::= SEQUENCE OF Request
TBS=$(tlv 30 "$REQLIST$REQEXTS")                 # TBSRequest
OCSPREQ=$(tlv 30 "$TBS")                         # OCSPRequest

# 5. Emit raw DER on stdout, as OCTAL escapes.
#
# Two traps here, both of which produced a file of readable text rather than DER:
#   * `sed 's/../\\x&/g' | xargs -0 printf` — xargs eats the backslash before printf ever
#     sees it, so the output was the literal string "x30x48x30x46...".
#   * \xHH is a bash/GNU extension. \NNN octal is POSIX, so it survives busybox on the
#     Alpine CI image, which is what §3d is actually asking for.
# No xxd either — busybox does not ship it.
esc=""
for (( i = 0; i < ${#OCSPREQ}; i += 2 )); do
    esc="$esc\\$(printf '%03o' "$((16#${OCSPREQ:i:2}))")"
done
printf '%b' "$esc"
