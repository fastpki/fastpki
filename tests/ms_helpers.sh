#!/usr/bin/env bash
# Build a PKCS#10 the way a real Windows enrolment client builds one: naming the
# certificate template it wants.
#
# ⚠️ A BARE CSR IS NOT A REPRESENTATIVE MS-WSTEP REQUEST. Every suite here used to send
# `req -new -subj /CN=x` with no template extension, which `certreq` and `certlm.msc`
# cannot do — the template is how a Windows client says what it is asking for, and since
# It is also what selects the issuance policy and what the CSR is validated against.
# With the seeded grants a `requester` may use three templates, so a request naming none
# is genuinely ambiguous and is refused. That refusal is correct; the bare CSR was the
# unrepresentative part.
#
# szOID_ENROLL_CERTTYPE_EXTENSION (1.3.6.1.4.1.311.20.2) carries the template NAME as a
# BMPString. There is also a V2 form (1.3.6.1.4.1.311.21.7) carrying the template OID in a
# SEQUENCE; both are decoded by pki::csr_requested_template, and ms_template_policy.sh
# exercises that one so this file does not have to.
#
# Callers must have $OSSL set (every suite does).

# ms_csr <cn> <template> <keyfile> <csrfile> [<eku>]
# The optional 5th argument puts an extendedKeyUsage in the request. Windows DOES send
# one — CertEnroll copies the EKU out of the template it enrolled under — so a CSR
# without one exercises the default_eku branch and never the allow-list comparison.
# A template of "" produces a deliberately BARE csr — used to assert that the ambiguous
# case is refused, so keep it working.
ms_csr() {
    local cn=$1 tmpl=$2 key=$3 out=$4 eku=${5:-}
    if [ -z "$tmpl" ]; then
        "$OSSL" req -new -newkey rsa:2048 -nodes -keyout "$key" -subj "/CN=$cn" \
                -out "$out" >/dev/null 2>&1
        return
    fi
    printf '[req]\ndistinguished_name=dn\nreq_extensions=v3\nprompt=no\n[dn]\nCN=%s\n[v3]\n1.3.6.1.4.1.311.20.2=ASN1:BMPSTRING:%s\n' \
        "$cn" "$tmpl" > "$out.cnf"
    # An if, not `[ … ] && …`: with no EKU the && chain would return 1 and, under set -e,
    # abort the caller for the ordinary case.
    if [ -n "$eku" ]; then printf 'extendedKeyUsage=%s\n' "$eku" >> "$out.cnf"; fi
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout "$key" -out "$out" \
            -config "$out.cnf" >/dev/null 2>&1
}

# ms_csr_b64 <cn> <template> <keyfile> [<eku>] -> base64 DER on stdout
# The form the WS-Trust BinarySecurityToken carries.
ms_csr_b64() {
    local cn=$1 tmpl=$2 key=$3 eku=${4:-}
    local tmp; tmp="$(mktemp)"
    ms_csr "$cn" "$tmpl" "$key" "$tmp" "$eku"
    "$OSSL" req -in "$tmp" -outform DER 2>/dev/null | "$OSSL" base64 -A
    rm -f "$tmp" "$tmp.cnf"
}
