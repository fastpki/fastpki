#!/usr/bin/env bash
# MS-WSTEP Kerberos/SPNEGO + auth fallback matrix.
#
# Two layers:
#  (1) KDC-free assertions that run anywhere (incl. CI) against the default
#      fastpki-ms: the fallback matrix advertises BOTH WWW-Authenticate schemes,
#      a bogus Negotiate token is rejected, and HTTP Basic enrolls successfully.
#  (2) A real SPNEGO round-trip against a throwaway userspace MIT KDC, run only
#      when a Kerberos-enabled binary (FASTPKI_MS_KRB) and the krb5 tools
#      (KRB5_PREFIX) are present. Skipped (not failed) otherwise.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/tests/pg_helpers.sh"
source "$ROOT/tests/ms_helpers.sh"
source "$ROOT/tests/hsm_helpers.sh"
source "$ROOT/tests/user_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
# Only adopt the system openssl.cnf where it really is one. On macOS this path is a
# stub that defines no providers, and exporting it breaks every pkcs11 load — the
# CA key then cannot be minted and the suite SKIPs for a reason that looks nothing
# like "wrong openssl.cnf". Tests must not assume a Linux layout (§3d).
[ -s /etc/ssl/openssl.cnf ] && grep -q providers /etc/ssl/openssl.cnf 2>/dev/null \
    && export OPENSSL_CONF=/etc/ssl/openssl.cnf || unset OPENSSL_CONF
MS="$ROOT/build/fastpki-ms"
W="$(mktemp -d)"; cd "$W"; PORT=18456
pass=0; fail=0; skip=0
chk()  { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected $2 got $3)"; fail=$((fail+1)); fi; }
skipt(){ echo "  [SKIP] $1"; skip=$((skip+1)); }

ca_in_token ca.pem "/CN=MS CA" 3650
cp ca.pem root.pem
"$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout ms.key -out ms.pem -days 3650 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
pg_setup ms_kerberos
trap 'pg_cleanup; kill $P 2>/dev/null' EXIT
printf "internal\n" > domains.txt
seed_domains $W/domains.txt   # allowed_domains is the sole source
seed_web_user basicuser basicpw requester
ms_csr ms.internal GenericUser c.key c.csr      # the template selects the policy
CSR_B64=$("$OSSL" req -in c.csr -outform DER | "$OSSL" base64 -A)

# A keytab path is enough to *configure* Kerberos (so the fallback matrix turns
# on); the file need not be valid for the KDC-free assertions.
: > dummy.keytab
# ⚠️ THE KEYTAB BELONGS TO A DIRECTORY NOW, not to the deployment. A keytab holds ONE
# realm's service key, so a global MS_KERBEROS_KEYTAB could serve exactly one domain and
# left every other domain's clients failing SPNEGO against a key the acceptor did not
# hold. The realm and the KDCs are not configured beside it either: the realm is the DNS
# root upper-cased and the KDCs are the directory's own URIs.
seed_dir() {   # <id> <dns_root> <uris> <keytab-path>
  pg_exec "INSERT INTO auth_providers(id,kind,display_name,enabled,priority,created,updated)
             VALUES('$1','ldap','$1',true,100,0,0)
             ON CONFLICT (id) DO UPDATE SET enabled=true;
           INSERT INTO ldap_providers(provider_id,uris,base_dns,dns_root,krb_keytab)
             VALUES('$1','$3','DC=x','$2','$4')
             ON CONFLICT (provider_id) DO UPDATE SET uris=EXCLUDED.uris,
               dns_root=EXCLUDED.dns_root, krb_keytab=EXCLUDED.krb_keytab;" >/dev/null
}
common_conf() {
cat <<EOF
PKI_DNS=localhost
SIGNING_CA_PEM=$W/ca.pem
SIGNING_CA_KEY=$CA_KEY_URI
SIGNING_CA_ID=ca-global
ROOT_CA_PEM=$W/root.pem
MS_CERT=$W/ms.pem
MS_KEY=$W/ms.key
PG_CONNINFO=$PG_CONNINFO
AUTH_BACKEND=local
MS_BIND=127.0.0.1
MS_PORT=$PORT
XCEP_PATH=/msxcep
WSTEP_PATH=/mswstep
CERT_VALIDITY_DAYS=365
LOG_LEVEL=err
EOF
}

# SOAP RST with a CSR BinarySecurityToken (no UsernameToken).
rst_body() {
  printf '%s' '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><s:Body><wst:RequestSecurityToken><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType><wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10">'"$CSR_B64"'</wsse:BinarySecurityToken></wst:RequestSecurityToken></s:Body></s:Envelope>'
}

# ───────────────────────── (1) KDC-free assertions ─────────────────────────
common_conf > bootstrap.conf
seed_ca_from_conf bootstrap.conf   # register the CA (SIGNING_CA_* no longer seed it)
seed_dir corp '' '' "$W/dummy.keytab"      # a directory whose keytab is the empty file above
"$MS" --config bootstrap.conf >srv.log 2>&1 & P=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "bootstrap.conf" MS_PORT "$P" || true
# ⚠️ pg_cleanup BELONGS HERE. `trap cleanup EXIT` below REPLACES the earlier
# `trap 'pg_cleanup; kill $P' EXIT` — bash EXIT traps do not stack — so without this
# line the database this suite creates is never dropped. Measured: a completed run left
# fpki_ms_kerberos_<pid> behind.
cleanup() { for pid in "${P:-}" "${MSK:-}" "${KDCPID:-}"; do [ -n "$pid" ] && { kill "$pid" 2>/dev/null; kill -9 "$pid" 2>/dev/null; }; done; pg_cleanup; }
trap cleanup EXIT
if ! kill -0 $P 2>/dev/null; then echo "fastpki-ms died:"; cat srv.log; exit 1; fi
U="https://127.0.0.1:$PORT/mswstep/ca-global"

echo "=== fallback matrix: what a 401 may CLAIM depends on the keytab ==="
# ⚠️ THIS SECTION USED TO ASSERT THE BUG. `dummy.keytab` is created EMPTY (above), and
# the suite demanded `WWW-Authenticate: Negotiate` anyway -- pinning "a path was typed"
# as though it meant "Kerberos works". The console's keytab upload REFUSES to run until
# MS_KERBEROS_KEYTAB names a path, so every deployment passes through a window where the
# path is set and no keytab exists yet; in that window a domain-joined client was told to
# use Kerberos and failed inside GSSAPI instead of using the scheme that would have worked.
HDRS=$(curl -sk -i --data "$(rst_body)" -H "Content-Type: application/soap+xml" "$U")
chk "unauthenticated request -> 401" 401 "$(printf '%s' "$HDRS" | grep -oE 'HTTP/[0-9.]+ [0-9]+' | head -1 | grep -oE '[0-9]+$')"
neg(){ printf '%s' "$1" | grep -qi 'WWW-Authenticate: *Negotiate' && echo yes || echo no; }
bas(){ printf '%s' "$1" | grep -qi 'WWW-Authenticate: *Basic'     && echo yes || echo no; }
chk "empty keytab: does NOT offer Negotiate" no  "$(neg "$HDRS")"
chk "empty keytab: still offers Basic"       yes "$(bas "$HDRS")"

# The same server, the same request -- only the keytab appears. This is the upload
# landing on the shared volume, so it also proves the check is per-request: an admin who
# uploads a keytab does not have to restart fastpki-ms to be offered Kerberos.
printf '\005\002keytab-bytes-for-the-readiness-check' > "$W/dummy.keytab"
HDRS2=$(curl -sk -i --data "$(rst_body)" -H "Content-Type: application/soap+xml" "$U")
chk "keytab present: offers Negotiate, no restart" yes "$(neg "$HDRS2")"
chk "keytab present: still offers Basic"           yes "$(bas "$HDRS2")"
: > "$W/dummy.keytab"   # back to empty for the sections below, which render krb5.conf

echo "=== bogus Negotiate token is rejected ==="
code=$(curl -sk -o /dev/null -w '%{http_code}' --data "$(rst_body)" \
    -H "Content-Type: application/soap+xml" -H "Authorization: Negotiate QUJDREVG" "$U")
chk "garbage SPNEGO token -> 401" 401 "$code"

# ── the SERVER LOG must name WHY, not just that it failed ───────────────────────────
# Needs a Kerberos-enabled binary but NOT a KDC: an unreadable/bogus keytab already
# produces a real krb5 minor status, which is the whole point of the ticket.
#
# ⚠️ Before the fix every SPNEGO failure rendered identically:
#     gss_accept_sec_context: Unspecified GSS failure.  Minor code may provide more
#     information; Unknown error
# The minor status is MECHANISM-specific and gss_display_status picks the error table from
# its mech_type argument; that was GSS_C_NO_OID, so there was no table and three different
# faults (wrong principal in the keytab, RC4 ticket vs AES256-only keytab, suspected kvno
# mismatch) each cost a round of hypothesis-and-test against the lab AD domain.
# ⚠️ FALL BACK TO THE SHIPPED BINARY. In the image `fastpki-ms` IS built with
# -DFASTPKI_WITH_KERBEROS=ON, and the image is where the "Unknown error" this guards was
# actually observed — a section that only ran against a local build-krb would never see the
# platform the bug was reported on. Whether the binary has Kerberos is decided by ASKING IT
# (the log says so) rather than by guessing from the path.
MSKRB_EARLY="${FASTPKI_MS_KRB:-}"
[ -z "$MSKRB_EARLY" ] && [ -x "$ROOT/build-krb/fastpki-ms" ] && MSKRB_EARLY="$ROOT/build-krb/fastpki-ms"
[ -z "$MSKRB_EARLY" ] && MSKRB_EARLY="$MS"
if [ ! -x "$MSKRB_EARLY" ]; then
    skipt "GSSAPI minor-status decoding (no fastpki-ms to run)"
else
    echo "=== A SPNEGO failure names the krb5 reason, not 'Unknown error' ==="
    kill $P 2>/dev/null; wait $P 2>/dev/null
    # ⚠️ common_conf sets LOG_LEVEL=err and the Kerberos failure is logged at INFO
    # (msxcep/main.cpp: pki::log::info("... Kerberos auth failed: ...")). Reading the
    # default config's log for it finds an EMPTY FILE and the assertion below then compares
    # against "" — "not Unknown error" is vacuously true on nothing at all. Raise the level
    # for this section so the claim is about the message and not about the log level.
    # ⚠️ A READABLE KEYTAB, DELIBERATELY. With a missing keytab the failure happens in
    # gss_acquire_cred, whose minor MIT resolves even with no mechanism OID — so that case
    # cannot reproduce the ticket, and a guard built on it would be testing a NEIGHBOUR of
    # the subject. The reported "Unknown error" came from gss_accept_sec_context. Minting a
    # keytab (no KDC needed: ktutil writes one from a password) lets acquire_cred succeed so
    # the garbage token reaches the call the ticket is actually about.
    # ⚠️ NO `--help` PROBE. macOS ships Heimdal's ktutil at /usr/sbin/ktutil and it takes
    # `--help` as a request to go INTERACTIVE — the probe hung the whole suite until it was
    # killed. Just try each candidate and keep whichever actually writes a keytab; the
    # artifact answers the question and cannot hang.
    for c in "${KRB5_PREFIX:-/nonexistent}/bin/ktutil" /opt/homebrew/opt/krb5/bin/ktutil \
             /usr/lib/mit/bin/ktutil /usr/bin/ktutil; do
        [ -x "$c" ] || continue
        printf 'addent -password -p HTTP/localhost@PKITEST.LOCAL -k 1 -e aes256-cts-hmac-sha1-96\npw\nwkt %s/real.keytab\nquit\n' "$W" \
            | "$c" >/dev/null 2>&1
        [ -s "$W/real.keytab" ] && break
    done
    if [ -s "$W/real.keytab" ]; then KTAB="$W/real.keytab"; KTKIND="readable keytab -> gss_accept_sec_context"
    else
        # ⚠️ CREATE IT HERE, NOT LATER. This fallback named a file that a LATER sub-section
        # creates, so on a host with no ktutil the keytab did not exist yet -- and the
        # readiness gate correctly refuses to attempt SPNEGO with no keytab, so the request
        # never reached GSSAPI and the precondition below failed with nothing logged.
        # Invisible on this Mac, where Homebrew ships ktutil and the branch never runs;
        # caught by the run inside the shipped image, which has none.
        printf '\253\253\253\253not-a-keytab' > "$W/corrupt.keytab"
        KTAB="$W/corrupt.keytab"; KTKIND="corrupt keytab -> gss_acquire_cred (weaker: not the reported call)"
    fi
    echo "  [INFO] $KTKIND"
    seed_dir corp '' '' "$KTAB"
    common_conf | sed 's/^LOG_LEVEL=.*/LOG_LEVEL=info/' > pkikerr.conf
    "$MSKRB_EARLY" --config pkikerr.conf >srvkerr.log 2>&1 & PK=$!
    # Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
    wait_conf "pkikerr.conf" MS_PORT "$PK" || true
    if ! kill -0 $PK 2>/dev/null; then
        echo "  [SKIP] the Kerberos build would not start"; skip=$((skip+1))
        head -3 srvkerr.log | sed 's/^/        /'
    else
        curl -sk -o /dev/null --data "$(rst_body)" -H "Content-Type: application/soap+xml" \
            -H "Authorization: Negotiate QUJDREVG" "$U" || true
        sleep 1
        if grep -qi "Kerberos support not built" srvkerr.log; then
            skipt "GSSAPI minor-status decoding — this fastpki-ms has no Kerberos support"
            kill $PK 2>/dev/null; wait $PK 2>/dev/null
            "$MS" --config bootstrap.conf >srv.log 2>&1 & P=$!
            # Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
            wait_conf "bootstrap.conf" MS_PORT "$P" || true
            GERR=SKIPPED
        fi
        GERR=$(grep -iE "gss_accept_sec_context|gss_acquire_cred" srvkerr.log | head -1)
        chk "PRECONDITION: the server logged a GSSAPI failure at all" yes \
            "$([ -n "$GERR" ] && echo yes || echo no)"
        [ -n "$GERR" ] && echo "      server said: $(printf '%s' "$GERR" | sed 's/.*: //' | cut -c1-120)"
        # THE ASSERTION, in the shape the MEASUREMENT actually has two branches for.
        #
        # A malformed token fails with minor=0 — there is no minor status — so the only
        # correct behaviour is to say nothing about it. "Unknown error" here was never an
        # undecoded krb5 code; it was gss_display_status rendering the number 0.
        chk "  no phantom 'Unknown error' clause" no \
            "$(printf '%s' "$GERR" | grep -qi "Unknown error" && echo yes || echo no)"
        chk "  and no invented minor when there is none" no \
            "$(printf '%s' "$GERR" | grep -qE "minor=0\b" && echo yes || echo no)"

        # ── the OTHER branch: a REAL minor must be decoded AND carried ──────────────────
        # An unreadable keytab fails in gss_acquire_cred with a genuine krb5 minor. Both
        # branches are needed: a guard with only the first would pass on a build that
        # printed nothing at all, and one with only the second would miss the phantom.
        kill $PK 2>/dev/null; wait $PK 2>/dev/null
        # ⚠️ CORRUPT, NOT ABSENT. This branch needs gss_acquire_cred to fail with a real
        # krb5 minor, which means the request has to REACH GSSAPI -- and fastpki-ms now
        # declines to attempt Kerberos at all when the keytab is missing or empty, because
        # claiming a scheme it cannot honour is what the section above guards against. A
        # file that exists and is not a keytab fails in the same call for the same reason
        # and is what an operator actually hits: a truncated copy, or the wrong file.
        printf '\253\253\253\253not-a-keytab' > "$W/corrupt.keytab"
        seed_dir corp '' '' "$W/corrupt.keytab"
        common_conf | sed 's/^LOG_LEVEL=.*/LOG_LEVEL=info/' > pkikerr2.conf
        "$MSKRB_EARLY" --config pkikerr2.conf >srvkerr2.log 2>&1 & PK2=$!
        # Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
        wait_conf "pkikerr2.conf" MS_PORT "$PK2" || true
        curl -sk -o /dev/null --data "$(rst_body)" -H "Content-Type: application/soap+xml" \
            -H "Authorization: Negotiate QUJDREVG" "$U" || true
        sleep 1
        GERR2=$(grep -iE "gss_acquire_cred|gss_accept_sec_context" srvkerr2.log | head -1)
        [ -n "$GERR2" ] && echo "      with no keytab: $(printf '%s' "$GERR2" | sed 's/.*: //' | cut -c1-100)"
        chk "  a REAL minor is named, not 'Unknown error'" no \
            "$(printf '%s' "$GERR2" | grep -qi "Unknown error" && echo yes || echo no)"
        chk "  and its raw code is carried for grepping krb5_err.et" yes \
            "$(printf '%s' "$GERR2" | grep -qE "minor=[0-9]+" && echo yes || echo no)"
        kill $PK2 2>/dev/null; wait $PK2 2>/dev/null
        kill $PK 2>/dev/null; wait $PK 2>/dev/null
    fi
    # section 3 below expects the original server; bring it back up
    "$MS" --config bootstrap.conf >srv.log 2>&1 & P=$!
    # Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
    wait_conf "bootstrap.conf" MS_PORT "$P" || true
fi

echo "=== the krb5.conf the service renders for its realm ==="
# ⚠️ SHIPPED WITH NO TEST AT ALL. MS_KERBEROS_REALM / MS_KERBEROS_KDCS and the krb5.conf
# rendered from them went out with nothing exercising them — `git grep MS_KERBEROS_REALM`
# over tests/ matched nothing. The reason it matters is that MS-WSTEP does NOT read a
# krb5.conf of its own: without one, krb5 falls back to DNS SRV discovery against whatever
# resolver the container was handed, which in a container is not the AD DNS. So the
# difference between "authenticates" and "times out inside GSSAPI" is this file existing.
#
# ⚠️ THE RENDER IS NOT BEHIND FASTPKI_WITH_KERBEROS. write_krb5_conf and its call site are
# compiled unconditionally (the #endif for that flag closes above them), so this section
# runs on a build with the flag OFF — which is what this tree builds by default and what a
# source install gets. Asserted below rather than assumed.
chk "PRECONDITION: this binary carries the renderer" yes \
    "$(strings "$MS" 2>/dev/null | grep -q 'dns_lookup_kdc' && echo yes || echo no)"

# (a) A keytab with nothing to point it at must SAY SO. The server above is running with
# exactly that shape -- MS_KERBEROS_KEYTAB set, no realm, no KDCs, no directory rows -- so
# this reads the log it has already written. A keytab with no realm still accepts a ticket
# on a host whose resolver happens to reach AD and fails everywhere else; the two are
# indistinguishable without this line.
chk "a keytab with no realm is reported, not silently ignored" yes \
    "$(grep -q 'no Kerberos realm/KDCs' srv.log && echo yes || echo no)"
chk "  and nothing was rendered for it" no \
    "$([ -s "${TMPDIR:-/tmp}/fastpki-krb5.conf" ] && echo yes || echo no)"

# (b) Realm + KDCs given explicitly. TMPDIR is redirected so the file lands where this
# suite can find it and cannot collide with another instance's -- the product writes to
# temp_directory_path()/fastpki-krb5.conf, which is one shared name per host.
mkdir -p "$W/krb5tmp"
# ⚠️ THE REALM AND THE KDCs ARE THE DIRECTORY'S OWN FACTS. `example.test` upper-cased IS
# the realm, and the hosts in its URIs ARE its KDCs -- so a second copy in config would be
# a second source that can disagree, which is why the keys are gone rather than kept.
printf '\005\002keytab-for-example-test' > "$W/example.keytab"
seed_dir corp example.test 'ldap://dc1.example.test,ldap://dc2.example.test' "$W/example.keytab"
{ common_conf; echo "MS_PORT=$((PORT+1))"; } | grep -v '^MS_PORT=18456$' > krb5.conf
TMPDIR="$W/krb5tmp" "$MS" --config krb5.conf >krb5-srv.log 2>&1 & MSK=$!
for _ in $(seq 1 40); do [ -s "$W/krb5tmp/fastpki-krb5.conf" ] && break; command sleep 0.2 2>/dev/null || true; done
KRB=$W/krb5tmp/fastpki-krb5.conf
chk "the service renders a krb5.conf" yes "$([ -s "$KRB" ] && echo yes || echo no)"
chk "  default_realm is the configured realm" yes \
    "$(grep -q 'default_realm *= *EXAMPLE.TEST' "$KRB" 2>/dev/null && echo yes || echo no)"
# ⚠️ THE POINT OF THE WHOLE FILE. Left at krb5's default of true, a missing or wrong KDC
# is not an error -- the library goes to DNS instead and the failure surfaces much later,
# somewhere else. Both lookups are pinned off, so a bad realm fails AT the realm.
chk "  DNS discovery is pinned OFF for both lookups" yes \
    "$(grep -q 'dns_lookup_kdc *= *false' "$KRB" 2>/dev/null && \
       grep -q 'dns_lookup_realm *= *false' "$KRB" 2>/dev/null && echo yes || echo no)"
chk "  BOTH KDCs are listed, not just the first" 2 \
    "$(grep -c 'kdc *= *dc[12].example.test' "$KRB" 2>/dev/null | tr -d ' ')"
chk "  and they sit inside the realm's own stanza" yes \
    "$(awk '/^\[realms\]/{r=1} r&&/EXAMPLE.TEST *= *\{/{s=1} s&&/kdc *=/{n++} END{exit !(n==2)}' "$KRB" \
       && echo yes || echo no)"
kill $MSK 2>/dev/null; wait $MSK 2>/dev/null; MSK=

# ⚠️ ANTI-VACUITY. Every assertion above would also pass against a file this suite wrote
# itself, so prove the one that was read came from the SERVER: it did not exist before the
# server started, and it is gone once the directory is cleared and no server is running.
rm -f "$KRB"
chk "PRECONDITION: the file is the server's, not this suite's" no \
    "$([ -s "$KRB" ] && echo yes || echo no)"

# (c) A realm with no KDC is refused outright rather than rendered half-written -- a
# [realms] stanza with no kdc line is what krb5 treats as "go and ask DNS", which is the
# exact behaviour the false above exists to prevent.
# ⚠️ A FRESH TMPDIR. The previous section rendered a VALID file at the same shared name
# (temp_directory_path()/fastpki-krb5.conf), so reusing the directory means this assertion
# reads the last section's output and passes or fails on it -- measured: "renders nothing"
# saw the good file from (b) and reported yes.
mkdir -p "$W/krb5tmp-nokdc"
# A directory with a DNS root and NO URIs: a realm, no KDCs.
seed_dir corp nokdc.test '' "$W/dummy-nokdc.keytab"
printf '\005\002keytab-with-no-kdc' > "$W/dummy-nokdc.keytab"
{ common_conf; echo "MS_PORT=$((PORT+2))"; } | grep -v '^MS_PORT=18456$' > krb5-nokdc.conf
TMPDIR="$W/krb5tmp-nokdc" "$MS" --config krb5-nokdc.conf >krb5-nokdc.log 2>&1 & MSK=$!
command sleep 1 2>/dev/null || true
chk "a realm with NO KDC renders nothing" no \
    "$([ -s "$W/krb5tmp-nokdc/fastpki-krb5.conf" ] && echo yes || echo no)"
chk "  and says why" yes \
    "$(grep -q 'no Kerberos realm/KDCs' krb5-nokdc.log && echo yes || echo no)"
kill $MSK 2>/dev/null; wait $MSK 2>/dev/null; MSK=

echo "=== TWO domains at once: two realms in one file, two keytabs in one credential ==="
# ⚠️ THIS IS THE WHOLE POINT OF A PER-DIRECTORY KEYTAB. A keytab holds ONE realm's service
# key, so the deployment-wide setting this replaced could serve exactly one domain: the
# second domain's clients presented a ticket the acceptor had no key for, and the failure
# arrived as a GSSAPI error with NO minor status -- indistinguishable from a wrong
# principal or a stale kvno. One directory proves nothing here; two is the case.
mkdir -p "$W/krb5tmp2"
printf '\005\002alpha-realm-key-material' > "$W/alpha.keytab"
printf '\005\002beta-realm-key-material'  > "$W/beta.keytab"
pg_exec "DELETE FROM ldap_providers; DELETE FROM auth_providers;" >/dev/null
seed_dir alpha alpha.test 'ldap://dc1.alpha.test,ldap://dc2.alpha.test' "$W/alpha.keytab"
seed_dir beta  beta.test  'ldap://dc1.beta.test'                        "$W/beta.keytab"
{ common_conf; echo "MS_PORT=$((PORT+3))"; } | grep -v '^MS_PORT=18456$' > krb5-two.conf
TMPDIR="$W/krb5tmp2" "$MS" --config krb5-two.conf >krb5-two.log 2>&1 & MSK=$!
for _ in $(seq 1 40); do [ -s "$W/krb5tmp2/fastpki-krb5.conf" ] && break; command sleep 0.2 2>/dev/null || true; done
K2="$W/krb5tmp2/fastpki-krb5.conf"
chk "PRECONDITION: a krb5.conf was rendered for two directories" yes \
    "$([ -s "$K2" ] && echo yes || echo no)"
chk "BOTH realms are in the file" 2 \
    "$(grep -cE '^\s+(ALPHA|BETA)\.TEST = \{' "$K2" 2>/dev/null | tr -d ' ')"
chk "  each realm keeps its OWN KDCs" yes \
    "$(awk '/ALPHA.TEST = \{/{a=1} a&&/dc1.alpha.test/{ok1=1} /BETA.TEST = \{/{a=0;b=1} b&&/dc1.beta.test/{ok2=1} END{print (ok1&&ok2)?"yes":"no"}' "$K2")"
# A second domain that inherited the first one's KDCs would still LOOK configured and
# would fail every ticket request for that realm.
chk "  and beta did not inherit alpha's" no \
    "$(awk '/BETA.TEST = \{/{b=1;next} b&&/\}/{b=0} b&&/alpha.test/{print "yes"; exit}' "$K2" | grep -q yes && echo yes || echo no)"
chk "  both domain_realm mappings are present" 2 \
    "$(grep -cE '^\s+(alpha|beta)\.test = (ALPHA|BETA)\.TEST' "$K2" 2>/dev/null | tr -d ' ')"
# ⚠️ THE MERGED CREDENTIAL, asserted by CONTENT. A keytab is a 2-byte header then
# independent records, so the merge is one header followed by both bodies -- and the
# giveaway that it worked is that BOTH realms' key material is in the one file.
# ⚠️ THE MERGE HAPPENS PER REQUEST, not at startup -- deliberately, because that is what
# lets an uploaded keytab take effect without restarting the service. So ask for something
# before looking for the file, or its absence means "nobody has asked yet" rather than
# "the merge failed".
curl -sk -o /dev/null --max-time 5 -X POST -H "Content-Type: application/soap+xml" \
     --data "$(rst_body)" "https://127.0.0.1:$((PORT+3))/mswstep/ca-global" 2>/dev/null || true
# The merged keytab is named per-process now, so resolve it rather than assuming.
MK=$(ls "$W"/krb5tmp2/fastpki-merged.*.keytab 2>/dev/null | head -1)
chk "the two keytabs became one acceptor credential" yes \
    "$([ -s "$MK" ] && echo yes || echo no)"
chk "  it carries alpha's records" yes \
    "$(grep -q 'alpha-realm-key-material' "$MK" 2>/dev/null && echo yes || echo no)"
chk "  and beta's" yes \
    "$(grep -q 'beta-realm-key-material' "$MK" 2>/dev/null && echo yes || echo no)"
chk "  with ONE keytab header, not two" 1 \
    "$(od -An -tx1 "$MK" 2>/dev/null | tr -d ' \n' | grep -o '0502' | wc -l | tr -d ' ')"
kill $MSK 2>/dev/null; wait $MSK 2>/dev/null; MSK=

echo "=== the policy advertises the authentication the service actually accepts ==="
# ⚠️ THIS IS WHAT STOPPED certreq. The <cAURI> fallback emitted a default-constructed row,
# whose clientAuthentication is 4 -- USERNAME AND PASSWORD ONLY. A domain machine enrolling
# through certreq runs as SYSTEM: it holds a Kerberos ticket and has no password, so it was
# told the enrolment endpoint could not accept the one credential it has. Windows reported
# ERROR_INVALID_PARAMETER, which names no field.
#
# clientAuthentication is ONE value per <cAURI>, not a bitmask, so accepting two schemes
# means advertising two URIs. The policy must agree with the 401 challenge: Kerberos is
# offered exactly when a directory has a usable keytab.
xcep_auths(){   # -> the clientAuthentication values the policy advertises, sorted
  curl -sk --max-time 8 -u "$MS_USER:$MS_PASS" -H "Content-Type: application/soap+xml" \
       --data "$XCEP_BODY" "https://127.0.0.1:$1/msxcep/ca-global" 2>/dev/null \
    | grep -oE '<clientAuthentication>[0-9]+' | sed 's/.*>//' | sort -u | tr '\n' ' ' | sed 's/ *$//'
}
XCEP_BODY='<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"><client/><requestFilter/></GetPolicies></s:Body></s:Envelope>'
MS_USER=basicuser; MS_PASS=basicpw   # the account this suite seeds
mkdir -p "$W/krb5tmp3"
printf '\005\002keytab-for-auth-advert' > "$W/advert.keytab"
seed_dir corp advert.test 'ldap://dc1.advert.test' "$W/advert.keytab"
{ common_conf; echo "MS_PORT=$((PORT+4))"; } | grep -v '^MS_PORT=18456$' > krb5-advert.conf
TMPDIR="$W/krb5tmp3" "$MS" --config krb5-advert.conf >krb5-advert.log 2>&1 & MSK=$!
for _ in $(seq 1 40); do curl -sk --max-time 1 "https://127.0.0.1:$((PORT+4))/msxcep/ca-global" >/dev/null 2>&1 && break; command sleep 0.25 2>/dev/null || true; done
A_WITH=$(xcep_auths $((PORT+4)))
chk "PRECONDITION: the policy answered" yes "$([ -n "$A_WITH" ] && echo yes || echo no)"
chk "with a keytab, Kerberos (2) is offered" yes \
    "$(printf '%s' "$A_WITH" | grep -qw 2 && echo yes || echo no)"
chk "  and username/password (4) stays for clients with no ticket" yes \
    "$(printf '%s' "$A_WITH" | grep -qw 4 && echo yes || echo no)"
kill $MSK 2>/dev/null; wait $MSK 2>/dev/null; MSK=

# Without a keytab the service cannot accept SPNEGO, and saying it can would send a
# domain client at an endpoint that will refuse it.
# ⚠️ EVERY directory, not just this one. The two-domain section above left alpha and beta
# holding keytabs, so clearing `corp` alone left the deployment still able to accept
# SPNEGO -- and the policy correctly went on advertising Kerberos. The claim here is about
# the DEPLOYMENT having no keytab anywhere, so the setup has to make that true.
pg_exec "UPDATE ldap_providers SET krb_keytab='';" >/dev/null
{ common_conf; echo "MS_PORT=$((PORT+5))"; } | grep -v '^MS_PORT=18456$' > krb5-noadvert.conf
TMPDIR="$W/krb5tmp3" "$MS" --config krb5-noadvert.conf >krb5-noadvert.log 2>&1 & MSK=$!
for _ in $(seq 1 40); do curl -sk --max-time 1 "https://127.0.0.1:$((PORT+5))/msxcep/ca-global" >/dev/null 2>&1 && break; command sleep 0.25 2>/dev/null || true; done
A_WITHOUT=$(xcep_auths $((PORT+5)))
chk "without a keytab, Kerberos is NOT advertised" no \
    "$(printf '%s' "$A_WITHOUT" | grep -qw 2 && echo yes || echo no)"
chk "  but username/password still is" yes \
    "$(printf '%s' "$A_WITHOUT" | grep -qw 4 && echo yes || echo no)"
kill $MSK 2>/dev/null; wait $MSK 2>/dev/null; MSK=

# NOT COVERED HERE, and named so it is not mistaken for coverage: the branch that DERIVES
# the realm from a directory's dns_root and the KDCs from its ldap:// URIs. It needs an
# enabled provider row written through the console, which is web_directories.sh's ground,
# and a real SPNEGO accept still needs an AD domain and a true keytab.

echo "=== Every auth_provider value the SCHEMA documents has a writer ==="
# ⚠️ THE CENSUS, not a behaviour test — and it exists because the behaviour test cannot
# run here. The schema promises "local / LDAP / SAML / OIDC / Kerberos / DN" and
# createdb.sql documents all six, but `kerberos` had NO writer anywhere: this file never
# touched web_users, so a SPNEGO principal was authorized through subject_roles and then
# did not exist in the Users tab at all. Five of six shipped; the schema claimed six.
#
# A documented value with no writer is invisible to every behavioural suite — nothing
# fails, the column is simply never that value — so the guard has to read the claim and
# the code and compare them.
# ⚠️ THE ANCHOR IS THE COLUMN NAME, DELIBERATELY — never a ticket number. It used to be
# `auth_provider`, and the comment sweep that removed ticket numbers from tracked
# files rewrote that line to `auth_provider:`. The sed then matched nothing, the value
# list came back EMPTY, and every assertion below it would have passed over zero rows.
# Only the PRECONDITION below turned that into a red suite. Anchor on something the
# schema cannot lose without the column itself changing.
VALUES=$(sed -n '/^-- *auth_provider:/,/AUTH_BACKEND/p' "$ROOT/sql/createdb.sql" \
         | tr '\n' ' ' | sed 's/.*mechanism authenticates this identity —//; s/\. Recorded.*//' \
         | tr -d '\-' | tr '|' '\n' | tr -d ' ' | grep -v '^$' | sort -u)
# ⚠️ A census over an EMPTY list passes every assertion below it. Assert the population.
chk "PRECONDITION: the schema comment yields a value list" yes \
    "$([ "$(echo "$VALUES" | grep -c .)" -ge 5 ] && echo yes || echo no)"
# ⚠️ THE RULE HAS TO NAME auth_provider, and my first two cuts did not.
#   cut 1: `auth_provider = "X"` only — reported ldap, oidc and saml as missing, because
#          oidc/saml are ARGUMENTS to federated_role() and ldap arrives as a variable.
#   cut 2: "the literal appears anywhere in src" — VACUOUS: reverting the kerberos writer
#          left the guard green, because msxcep already contains `a.method = "kerberos"`,
#          an audit-detail string that has nothing to do with web_users. Watched it pass
#          against the bug, which is the only reason I caught it.
# So: a direct assignment to auth_provider, or membership of an allowlist that names the
# indirect producer. An allowlist entry is a claim someone can check, not a silent pass.
INDIRECT_oidc="src/web/main.cpp federated_role(..., \"oidc\")"
INDIRECT_saml="src/web/main.cpp federated_role(..., \"saml\")"
INDIRECT_ldap="src/web/main.cpp auth_provider = cfg.auth_backend (only 'ldap' is reachable)"
MISSING=""
for v in $VALUES; do
    if grep -rqE "auth_provider[[:space:]]*=[[:space:]]*\"$v\"" "$ROOT/src"; then continue; fi
    eval "why=\${INDIRECT_$v:-}"
    if [ -n "$why" ]; then echo "  [note] $v is written indirectly: $why"; continue; fi
    MISSING="$MISSING $v"
done
chk "every documented auth_provider value is actually written somewhere" "" "$MISSING"
[ -n "$MISSING" ] && echo "  ⚠️ Documented but never recorded:$MISSING — either write it at the
     onboarding path that mechanism uses, or take it out of sql/createdb.sql. A value the
     schema promises and no code produces is a column that quietly cannot mean what it says."

echo "=== a Kerberos principal is authorized by its OWN row, like every other method ==="
# ⚠️ WHY THIS MATTERS: the SSO branch used to look the principal's web_users row up ONLY to
# decide whether to onboard it, and throw the row away. The role field stayed empty, so
# authorization came from subject_roles alone — the role an admin had set on that user, and
# which the console displays, decided nothing. The same identity was then authorized two
# different ways depending on how it signed in: over Basic and UsernameToken the row's role
# counts, over Kerberos it did not.
#
# It fails as an ABSENCE — the caller is offered fewer templates, or none — so it reads as
# "the template is gone" rather than as a permission error, which is exactly how it was
# reported: machine and domain-controller enrolment stopped working.
#
# ⚠️ THIS IS A SOURCE PROXY, NOT A BEHAVIOURAL TEST, and it is here because the behavioural
# one cannot run without a KDC: the live SPNEGO round-trip below SKIPs unless FASTPKI_MS_KRB
# and the krb5 tools are present, so on a dev box and in CI nothing exercises this branch at
# runtime. Anchored to the Kerberos branch so it cannot be satisfied by an assignment
# somewhere else in the file.
KRB_BRANCH=$(awk '/a\.method = "kerberos";/,/^    \/\/ \(b\) HTTP Basic\./' "$ROOT/src/msxcep/main.cpp")
chk "fixture: the Kerberos branch was extracted" yes "$([ -n "$KRB_BRANCH" ] && echo yes || echo no)"
chk "it reads the principal's existing row"      yes \
    "$(echo "$KRB_BRANCH" | grep -qF 'if (auto existing = st.db->get_web_user(a.user))' && echo yes || echo no)"
chk "  and takes the role FROM that row"         yes \
    "$(echo "$KRB_BRANCH" | grep -qF 'a.role = existing->role;' && echo yes || echo no)"
chk "  an onboarded principal gets its role too" yes \
    "$(echo "$KRB_BRANCH" | grep -qF 'a.role = row.role;' && echo yes || echo no)"

echo "=== HTTP Basic enrollment (fallback path) ==="
RESP=$(curl -sk --data "$(rst_body)" -H "Content-Type: application/soap+xml" \
    -u basicuser:basicpw --basic "$U")
echo "$RESP" | sed 's/.*<wst:RequestedSecurityToken>//' | grep -o 'base64binary">[^<]*' | head -1 | sed 's/.*base64binary">//' | "$OSSL" base64 -d -A > basic.der 2>/dev/null || true
SUBJ=$("$OSSL" x509 -in basic.der -inform DER -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')
chk "Basic auth issues cert (CN=ms.internal)" "ms.internal" "${SUBJ:-none}"
chk "Basic-auth issuance owner recorded" "basicuser" "$(pg_exec "SELECT owner FROM certs WHERE cn='ms.internal' LIMIT 1;")"
kill $P 2>/dev/null; wait $P 2>/dev/null

# ──────────────────── (2) real SPNEGO round-trip (opt-in) ───────────────────
KPFX="${KRB5_PREFIX:-/usr}"
MSKRB="${FASTPKI_MS_KRB:-$ROOT/build/fastpki-ms}"
# ⚠️ THE CLIENT IS spnego-post, NOT curl. Alpine's curl is built WITHOUT GSS-API -- `curl -V`
# lists none -- so `curl --negotiate -u :` sends no credential whatsoever and every request
# below would come back 401 with nothing to say why. tests/tools/spnego_post.cpp is the
# client half, built into the test image beside dnsstub for exactly this reason.
SPNEGO="${FASTPKI_SPNEGO_POST:-$(command -v spnego-post 2>/dev/null)}"
# ⚠️ THIS SECTION MUST NOT SKIP IN THE TEST IMAGE. Tests run only from the production image,
# where the KDC, the client and a Kerberos-enabled fastpki-ms are all present by design -- so
# a skip here is a broken image, not an environment without Kerberos, and saying which of the
# three is missing is the difference between a one-line fix and an afternoon.
if [ ! -x "$MSKRB" ] || [ ! -x "$KPFX/sbin/krb5kdc" ] || [ -z "$SPNEGO" ]; then
    miss=""
    [ -x "$MSKRB" ]            || miss="$miss fastpki-ms(FASTPKI_MS_KRB=$MSKRB)"
    [ -x "$KPFX/sbin/krb5kdc" ] || miss="$miss krb5kdc(KRB5_PREFIX=$KPFX)"
    [ -n "$SPNEGO" ]           || miss="$miss spnego-post"
    skipt "live KDC SPNEGO round-trip — missing:$miss"
    echo; echo "=== MS-KERBEROS: PASS=$pass FAIL=$fail SKIP=$skip ==="; [ "$fail" -eq 0 ]; exit
fi

echo "=== live SPNEGO round-trip against a userspace KDC ==="
REALM=PKITEST.LOCAL; KDCPORT=18088
# ⚠️ THE LIBRARY PATH IS ONLY FOR A HAND-BUILT PREFIX. A krb5 built into $HOME keeps its
# libraries under lib/<triplet>/ and bundles its OWN OpenSSL, which must not leak to the
# servers linked against ours -- hence the wrapper rather than a global export. The system
# krb5 in the test image needs none of that, and pointing LD_LIBRARY_PATH at directories
# that do not exist is how a working environment gets blamed for a missing library.
KRBLIB=""
for d in "$KPFX/lib/x86_64-linux-gnu" "$KPFX/lib/aarch64-linux-gnu"; do
    [ -d "$d" ] && KRBLIB="${KRBLIB:+$KRBLIB:}$d:$d/mit-krb5"
done
PLUGINS=""
for d in "$KPFX/lib/x86_64-linux-gnu/krb5/plugins/kdb" "$KPFX/lib/aarch64-linux-gnu/krb5/plugins/kdb" \
         "$KPFX/lib/krb5/plugins/kdb"; do
    [ -d "$d" ] && { PLUGINS="$d"; break; }
done
if [ -n "$KRBLIB" ]; then krun() { LD_LIBRARY_PATH="$KRBLIB" "$@"; }
else                      krun() { "$@"; }; fi
KINIT="$KPFX/bin/kinit.mit"; [ -x "$KINIT" ] || KINIT=$(command -v kinit)
mkdir -p kdc
cat > krb5.conf <<EOF
[libdefaults]
  default_realm = $REALM
  dns_lookup_kdc = false
  dns_lookup_realm = false
  rdns = false
  udp_preference_limit = 1
[realms]
  $REALM = {
    kdc = 127.0.0.1:$KDCPORT
  }
[domain_realm]
  localhost = $REALM
EOF
cat > kdc.conf <<EOF
[kdcdefaults]
  kdc_ports = $KDCPORT
  kdc_tcp_ports = $KDCPORT
[dbmodules]
${PLUGINS:+  db_module_dir = $PLUGINS}
[realms]
  $REALM = {
    database_name = $W/kdc/principal
    key_stash_file = $W/kdc/.k5.$REALM
    acl_file = $W/kdc/kadm5.acl
    max_life = 1h
    max_renewable_life = 1h
  }
EOF
export KRB5_CONFIG="$W/krb5.conf"
export KRB5_KDC_PROFILE="$W/kdc.conf"
# The acceptor's default replay cache (/var/tmp/krb5_<uid>.rcache2) persists
# across runs; because each run reuses the same service principal with a fresh
# key, a stale rcache mis-reads the new authenticator as a replay ("Unspecified
# GSS failure"). Clear it so each invocation starts clean.
rm -f /var/tmp/krb5_*.rcache* 2>/dev/null || true
krun "$KPFX/sbin/kdb5_util" create -s -P masterpw -r "$REALM" >kdb.log 2>&1
krun "$KPFX/sbin/kadmin.local" -q "addprinc -pw alicepw alice@$REALM" >>kdb.log 2>&1
krun "$KPFX/sbin/kadmin.local" -q "addprinc -randkey HTTP/localhost@$REALM" >>kdb.log 2>&1
krun "$KPFX/sbin/kadmin.local" -q "ktadd -k $W/http.keytab HTTP/localhost@$REALM" >>kdb.log 2>&1
if [ ! -s "$W/http.keytab" ]; then echo "KDC setup failed:"; cat kdb.log; skipt "userspace KDC setup"; echo; echo "=== MS-KERBEROS: PASS=$pass FAIL=$fail SKIP=$skip ==="; [ "$fail" -eq 0 ]; exit; fi
# Launch via a subshell that execs, so $KDCPID is the real krb5kdc (not the
# krun wrapper subshell) and the trap can actually reap it — otherwise the KDC
# leaks and later runs talk to a stale KDC with mismatched keys.
( [ -n "$KRBLIB" ] && export LD_LIBRARY_PATH="$KRBLIB"
  exec "$KPFX/sbin/krb5kdc" -n ) >kdc.log 2>&1 & KDCPID=$!
# The KDC binds UDP as well as TCP, hence "any" (wait_listen, pg_helpers.sh).
wait_listen "$KDCPORT" "$KDCPID" 15 any || true

# ⚠️ THE KEYTAB BELONGS TO A DIRECTORY, and MS_KERBEROS_KEYTAB is no longer a config key at
# all -- the parser does not know it, so this section used to configure NOTHING, offer no
# Negotiate, and fail every assertion below. It never showed, because the whole section was
# skipped for want of a KDC and a GSS-capable client.
#
# `pkitest.local` upper-cased IS the ticket's PKITEST.LOCAL realm, which is how Windows forms
# a realm and the only thing that names the client's authority. The keytab is NOT a second
# opinion: a service ticket is encrypted with the TARGET service's key, so under a
# cross-forest trust our keytab accepts clients from every realm that trusts us -- attributing
# by "whose keytab accepted it" would hand a partner-realm alice the identity of OUR alice.
seed_dir pkitest pkitest.local "ldap://127.0.0.1:389" "$W/http.keytab"
# ⚠️ A TICKET IS NOT A PERMISSION. A SPNEGO principal with no row is onboarded with role
# `none` and cannot enrol -- deliberately, so that authenticating never implies authorizing.
# These assertions are about WHICH NAME is authorized, so the grant has to exist first or
# every one of them fails on a permission check and says nothing about naming.
#
# Through subject_roles (grant_profile), NOT by seeding a web_users row: the row is what the
# onboarding path itself must create, and pre-creating it would answer the question the
# section is asking.
# ⚠️ AND MS-XCEP NEEDS A TEMPLATE GRANT ON TOP. grant_profile builds a carrier role out of
# the user's console role, and these identities have no row yet, so it falls back to copying
# `requester`'s enrol verbs alone -- which leaves the request refused with "this identity
# holds no template permission" and nothing to do with naming at all. The `requester` builtin
# carries template:use on the built-in templates; the carrier needs the same.
krb_grant() {
    grant_profile "$1" requester
    pg_exec "INSERT INTO role_permissions(role,permission,scope)
               SELECT 'prof@$1', permission, scope FROM role_permissions
                WHERE role='requester' AND permission LIKE 'template:%'
             ON CONFLICT DO NOTHING;" >/dev/null
}
krb_grant 'pkitest\alice'
krb_grant 'unrelated\alice'   # the OTHER directory, seeded below
common_conf > pkik.conf
seed_ca_from_conf pkik.conf   # register the CA (SIGNING_CA_* no longer seed it)
"$MSKRB" --config pkik.conf >srvk.log 2>&1 & MSK=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "pkik.conf" MS_PORT "$MSK" || true
if ! kill -0 $MSK 2>/dev/null; then echo "kerberos fastpki-ms died:"; cat srvk.log; skipt "kerberos server start"; echo; echo "=== MS-KERBEROS: PASS=$pass FAIL=$fail SKIP=$skip ==="; [ "$fail" -eq 0 ]; exit; fi

export KRB5CCNAME="$W/ccache"
printf 'alicepw\n' | krun "$KINIT" alice@"$REALM" >kinit.log 2>&1
chk "kinit obtained a TGT for alice" 0 "$?"
UK="https://localhost:$PORT/mswstep/ca-global"
rst_body > rst.xml
RESP=$("$SPNEGO" "$UK" HTTP@localhost application/soap+xml rst.xml 2>spnego.err)
echo "$RESP" | sed 's/.*<wst:RequestedSecurityToken>//' | grep -o 'base64binary">[^<]*' | head -1 | sed 's/.*base64binary">//' | "$OSSL" base64 -d -A > krb.der 2>/dev/null || true
SUBJ=$("$OSSL" x509 -in krb.der -inform DER -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')
# ⚠️ SAY WHY, IN THE RUN'S OWN OUTPUT. Everything this section touches -- the ccache, the
# keytab, the server log, the client's GSSAPI minor status -- lives in a temp directory that
# is gone by the time anyone reads the result. A bare "expected ms.internal got none" is then
# indistinguishable between a client with no ticket, a server offering no Negotiate, and an
# identity with no permission to enrol.
if [ "${SUBJ:-}" != "ms.internal" ]; then
    echo "  --- spnego-post stderr ---"; head -20 spnego.err 2>/dev/null | sed 's/^/    /'
    echo "  --- response (first 300 bytes) ---"; printf '%.300s\n' "$RESP" | sed 's/^/    /'
    echo "  --- server log ---"; tail -20 srvk.log 2>/dev/null | sed 's/^/    /'
fi
chk "SPNEGO ticket enrolls a cert (CN=ms.internal)" "ms.internal" "${SUBJ:-none}"
chk "issuance owner is qualified by the realm's directory" 'pkitest\alice' \
    "$(pg_exec "SELECT owner FROM certs WHERE cn='ms.internal' AND owner='pkitest\\alice' LIMIT 1;")"
AUD=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_issued' AND actor='pkitest\\alice';")
chk "Kerberos issuance audited with the principal" 1 "$AUD"

# ── the principal is authorized under its DIRECTORY's name, not the bare one ────────
# ⚠️ THE REALM IS THE QUALIFIER. Above, the keytab came from MS_KERBEROS_KEYTAB with no
# directory behind it, so `alice` is a LOCAL name and stays unqualified -- that is the rule,
# not an exemption. Here a directory CLAIMS the realm (its dns_root upper-cased IS
# PKITEST.LOCAL), so the very same ticket must authorize `pkitest\alice`.
#
# Why it matters: the Basic and UsernameToken branches of the same auth ladder already
# authorize the provider-qualified subject. While this branch kept only the part before '@',
# one account was authorized two different ways depending on transport -- a role granted to
# `pkitest\alice` never matched over SPNEGO, and directory_groups_for(), seeing no
# qualifier, unioned the memberships of EVERY directory holding an `alice`.
kill $MSK 2>/dev/null; wait $MSK 2>/dev/null
# ⚠️ A SECOND DIRECTORY THAT DOES NOT CLAIM THE REALM. It holds a usable keytab, so it can
# accept tickets -- and it still must not be handed this identity, because the realm names
# the other one. It also holds an `alice` (granted above), so a misattribution would be
# visible as an issuance under ITS name rather than as a silent failure.
seed_dir unrelated unrelated.example "ldap://127.0.0.1:389" "$W/http.keytab"
# No MS_KERBEROS_KEYTAB: the directory's own keytab is what must be accepted here, so this
# proves the merged-keytab path as well as the naming.
common_conf > pkiq.conf
seed_ca_from_conf pkiq.conf
"$MSKRB" --config pkiq.conf >srvq.log 2>&1 & MSK=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "pkiq.conf" MS_PORT "$MSK" || true
if ! kill -0 $MSK 2>/dev/null; then echo "qualified-subject server died:"; cat srvq.log; fi
BEFORE=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_issued';")
# ⚠️ THE OTHER DIRECTORY'S alice IS THE BASELINE. Both directories now hold an `alice`, so
# this is the collision itself: issuing for pkitest\alice must leave unrelated\alice's count
# untouched. A bare-name baseline could not show that -- there is no bare alice any more.
AOTHER=$(pg_exec "SELECT COUNT(*) FROM certs WHERE owner='unrelated\\alice';")
# The realm's own directory already issued once in the section above, so growth is the
# assertion -- an absolute count would pin the number of earlier requests instead.
APRE=$(pg_exec "SELECT COUNT(*) FROM certs WHERE owner='pkitest\\alice';")
printf 'alicepw\n' | krun "$KINIT" alice@"$REALM" >kinit2.log 2>&1
"$SPNEGO" "$UK" HTTP@localhost application/soap+xml rst.xml >rstq.out 2>&1
AFTER=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_issued';")
# ⚠️ ANTI-VACUITY. Without this, every assertion below passes when the request never got in
# at all -- a zero count for the bare name reads identically to "the ticket was refused".
chk "the directory's OWN keytab still accepts the ticket" yes \
    "$([ "$AFTER" -gt "$BEFORE" ] && echo yes || echo no)"
chk "SPNEGO subject is qualified by its directory" 'pkitest\alice' \
    "$(pg_exec "SELECT actor FROM audit_log WHERE action='cert_issued' ORDER BY seq DESC LIMIT 1;")"
chk "  the certificate's owner is qualified too" "$((APRE + 1))" \
    "$(pg_exec "SELECT COUNT(*) FROM certs WHERE owner='pkitest\\alice';")"
# The bare row from the earlier, directory-less run is still there and must not have gained
# a second issuance: a principal that keeps onboarding under both names is the bug itself.
# ⚠️ NOT A COUNT ON ONE NAME -- web_users.username is the PRIMARY KEY, so any such count is
# 0 or 1 and "not onboarded twice" is unprovable that way. What IS provable is WHICH names
# exist: one per directory, and no bare one. A bare row would mean a ticket was authorized
# outside every directory's namespace, which is the widening this closes.
chk "  no BARE alice row exists at all" 0 \
    "$(pg_exec "SELECT COUNT(*) FROM web_users WHERE username='alice';")"
# ⚠️ AND THE OTHER DIRECTORY IS NOT TOUCHED AT ALL. `unrelated` holds a usable keytab and an
# `alice` with a grant, so it is a live candidate for a misattribution -- but the realm names
# `pkitest`, so nothing here may be created under its name. Zero, not one: it never presented
# a ticket, and onboarding it would mean one ticket minted two identities.
chk "  the other directory's alice is NOT onboarded" 0 \
    "$(pg_exec "SELECT COUNT(*) FROM web_users WHERE username='unrelated\\alice';")"
chk "  the qualified name has its own web_users row" 1 \
    "$(pg_exec "SELECT COUNT(*) FROM web_users WHERE username='pkitest\\alice';")"
# ⚠️ AND NOTHING NEW LANDED UNDER THE BARE NAME. One ticket must produce ONE identity; a
# count that grew here is the split-identity bug wearing both names at once.
chk "  the OTHER directory's alice gained nothing" "$AOTHER" \
    "$(pg_exec "SELECT COUNT(*) FROM certs WHERE owner='unrelated\\alice';")"

# ── and the qualifier does NOT reach the certificate's commonName ───────────────────
# ⚠️ A QUALIFIED SUBJECT IS AN AUTHORIZATION NAME, NOT A DN COMPONENT. Where a template
# does not grant enrollee-supplies-subject the CA builds the name from the authenticated
# identity -- and that identity is now `<directory>\user`, so assigning it whole put a
# backslash inside the commonName. The provider belongs in its own domainComponent.
#
# `Email` is the built-in whose subject_name_flags withhold the subject grant, so it is the
# template that takes that branch. GenericUser (0x9) grants it and never does, which is
# exactly why every other cell in this file was blind to this.
#
# ⚠️ THIS CELL IS THE ONLY THING WATCHING THAT GATE, so a template edit can silently retire
# it. Email briefly gained CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x1) to give a first enrolment
# a subject source; the CN then came from the CSR (`CN=qualified.internal`) and these two
# assertions failed. The flags say where the name comes FROM instead now
# (SUBJECT_REQUIRE_COMMON_NAME | SUBJECT_ALT_REQUIRE_EMAIL). If this fails again, check
# default_ms_templates() before suspecting the issuance path.
ms_csr qualified.internal Email q.key q.csr
CSR_SAVE=$CSR_B64
CSR_B64=$("$OSSL" req -in q.csr -outform DER | "$OSSL" base64 -A)
rst_body > rstq2.xml
QRESP=$("$SPNEGO" "$UK" HTTP@localhost application/soap+xml rstq2.xml 2>/dev/null)
echo "$QRESP" | sed 's/.*<wst:RequestedSecurityToken>//' | grep -o 'base64binary">[^<]*' | head -1 \
    | sed 's/.*base64binary">//' | "$OSSL" base64 -d -A > qual.der 2>/dev/null || true
QS=$("$OSSL" x509 -in qual.der -inform DER -noout -subject 2>/dev/null)
CSR_B64=$CSR_SAVE
# ⚠️ ANTI-VACUITY FIRST: with no certificate every grep below returns "no" and the whole
# section reads as a pass while proving nothing.
chk "PRECONDITION: a CA-built subject was issued at all" yes \
    "$([ -n "$QS" ] && echo yes || echo no)"
chk "the CN is the person ALONE (CN=alice)" yes \
    "$(printf '%s' "$QS" | grep -qE 'CN *= *alice([,/]|$)' && echo yes || echo no)"
chk "  the directory is a separate RDN, not part of the name" yes \
    "$(printf '%s' "$QS" | grep -qF 'DC=pkitest' && echo yes || echo no)"
chk "  and NO backslash survives anywhere in the DN" no \
    "$(printf '%s' "$QS" | grep -q '\\' && echo yes || echo no)"

# ── an ambiguous realm is REFUSED, not silently treated as local ────────────────────
# ⚠️ "LOCAL" WOULD BE A LIE HERE, and an expensive one. A bare name means the web_users
# table -- but directory_groups_for() reads an unqualified name as "ask every directory"
# and unions the answers, which is the cross-directory widening this whole ticket is about.
# With two directories holding keytabs and a realm naming neither, nothing can say which
# authority asserted the principal, so the ticket is refused. Ambiguity is not authority.
kill $MSK 2>/dev/null; wait $MSK 2>/dev/null
# ⚠️ TWO DIRECTORIES CLAIMING ONE REALM. Same forest through different DCs or base DNs is a
# shape multi-provider exists to express, and both rows then derive the SAME realm. Taking
# the first would resolve by priority order -- the one thing the naming rule forbids -- so a
# realm claimed twice is exactly as unattributable as a realm claimed by nobody.
pg_exec "UPDATE ldap_providers SET dns_root='pkitest.local' WHERE provider_id='unrelated';" >/dev/null
TMPDIR="$W/ambigtmp" "$MSKRB" --config pkiq.conf >srva.log 2>&1 & MSK=$!
mkdir -p "$W/ambigtmp"; sleep 1
# ⚠️ GRANT THE BARE NAME FIRST, or this cell cannot tell a refusal from a lack of
# permission. Without a grant, an implementation that fell back to local `alice` would issue
# nothing either -- and the assertion would pass against the very behaviour it exists to
# forbid. With the grant in place, only an actual refusal keeps the count still.
krb_grant 'alice'
AB0=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_issued';")
"$SPNEGO" "$UK" HTTP@localhost application/soap+xml rst.xml >/dev/null 2>&1 || true
AB1=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_issued';")
chk "an unattributable realm issues NOTHING" "$AB0" "$AB1"
chk "  and the log names the fix, not just the failure" yes \
    "$(grep -qE 'set exactly one directory.s DNS root' srva.log && echo yes || echo no)"
chk "  and NO bare-name identity was created" 0 \
    "$(pg_exec "SELECT COUNT(*) FROM web_users WHERE username='alice';")"
pg_exec "UPDATE ldap_providers SET dns_root='unrelated.example' WHERE provider_id='unrelated';" >/dev/null

# ── the merged keytab is built ONCE and rebuilt only when a keytab changes ──────────
# ⚠️ THIS IS A CONCURRENCY FIX, TESTED BY ITS OBSERVABLE PROPERTY. Merging ran on every
# request, on httplib worker threads, all writing one fixed `fastpki-merged.keytab.new`
# with ios::trunc -- so two simultaneous XCEP/WSTEP requests interleaved their record bytes
# and renamed the corrupt result into place. Windows autoenrolment polls the whole fleet at
# once, so it surfaced as intermittent SPNEGO failures with no minor status.
#
# A race is not a thing a shell test can pin down by racing it; what IS deterministic is the
# property that removes it -- the merged file is not rewritten when nothing changed, and is
# rewritten when something does. Both are asserted below, plus a concurrent burst that must
# not produce a single failure.
kill $MSK 2>/dev/null; wait $MSK 2>/dev/null
cp "$W/http.keytab" "$W/http2.keytab"
# A SECOND directory with its own keytab is what turns the merge on at all (one directory is
# handed to krb5 unmerged). It claims a different realm, so it also proves the realm->
# directory mapping above picks by realm rather than by "the first one with a keytab".
seed_dir other other.local "ldap://127.0.0.1:389" "$W/http2.keytab"
# Per-process name (see krb_merged_keytab): glob for it instead of hardcoding a pid.
merged_path(){ ls "$W"/mergetmp/fastpki-merged.*.keytab 2>/dev/null | head -1; }
MERGED=""
mkdir -p "$W/mergetmp"
TMPDIR="$W/mergetmp" "$MSKRB" --config pkiq.conf >srvm.log 2>&1 & MSK=$!
# Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
wait_conf "pkiq.conf" MS_PORT "$MSK" || true
printf 'alicepw\n' | krun "$KINIT" alice@"$REALM" >kinit3.log 2>&1
"$SPNEGO" "$UK" HTTP@localhost application/soap+xml rst.xml >/dev/null 2>&1
MERGED=$(merged_path)
chk "two directories produce a MERGED keytab" yes "$([ -n "$MERGED" ] && [ -s "$MERGED" ] && echo yes || echo no)"
# ⚠️ SIZE, NOT JUST EXISTENCE. A keytab is a 2-byte header followed by independent records,
# so a correct merge is exactly (2 + the sum of every part's body). `-s` alone is satisfied
# by a merge that dropped all but one part -- which is precisely the outcome the losing
# rename used to produce, so the one cell that should have caught it could not.
KTS=0; KTN=0
for k in $(pg_exec "SELECT krb_keytab FROM ldap_providers WHERE krb_keytab <> '' ORDER BY provider_id;"); do
    [ -s "$k" ] || continue
    KTS=$((KTS + $(wc -c < "$k") - 2)); KTN=$((KTN + 1))
done
chk "  PRECONDITION: more than one directory keytab was in play" yes     "$([ "$KTN" -gt 1 ] && echo yes || echo no)"
chk "  the merged keytab holds EVERY part's records" "$((KTS + 2))" "$(wc -c < "$MERGED" | tr -d ' ')"
M1=$(stat -c %y "$MERGED" 2>/dev/null || stat -f %m "$MERGED" 2>/dev/null)
# A ticket still has to be accepted out of the merged file -- otherwise "not rebuilt" below
# would be satisfied by a merge that produces something krb5 cannot read.
B1=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_issued' AND actor='pkitest\\alice';")
"$SPNEGO" "$UK" HTTP@localhost application/soap+xml rst.xml >/dev/null 2>&1
B2=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_issued' AND actor='pkitest\\alice';")
chk "  and SPNEGO still authenticates against it" yes "$([ "$B2" -gt "$B1" ] && echo yes || echo no)"
M2=$(stat -c %y "$MERGED" 2>/dev/null || stat -f %m "$MERGED" 2>/dev/null)
chk "  a second request does NOT rebuild it" yes "$([ "$M1" = "$M2" ] && echo yes || echo no)"

# Hot reload must survive the cache: re-uploading a keytab has to take effect without a
# restart, which is the whole reason the merge used to run per request.
sleep 1
cat "$W/http.keytab" > "$W/http2.keytab"      # same bytes, new mtime -- the cache key moves
"$SPNEGO" "$UK" HTTP@localhost application/soap+xml rst.xml >/dev/null 2>&1
M3=$(stat -c %y "$MERGED" 2>/dev/null || stat -f %m "$MERGED" 2>/dev/null)
chk "  a CHANGED keytab does rebuild it" yes "$([ "$M2" != "$M3" ] && echo yes || echo no)"

# ⚠️ THIS USED TO ASSERT NOTHING. The old code also renamed its `.new` into place on
# success, so "no .new left behind" was true before the fix and after it. The property that
# actually distinguishes them is that the staging name is UNIQUE per process -- which is
# what a second fastpki-ms sharing this TMPDIR would otherwise collide on. Read it out of
# the binary rather than inferring it from a leftover file.
# Read from the SOURCE, deliberately: both the old and the new binary carry ".new" as its
# own string literal, so nothing in the compiled output tells the two apart. The source does
# -- the staging name is built from getpid() and a counter, and that is the whole difference
# between two instances sharing one TMPDIR safely and clobbering each other.
# ⚠️ AND READ THE STAGING STATEMENT, NOT THE WHOLE FILE. `out` -- the merged keytab's own
# destination -- is built from getpid() too, so a file-wide grep for getpid() still passes
# with the staging name reverted to a fixed `out + ".new"`, which is precisely the collision
# forbidden here. Isolate the statement carrying the `".new"` suffix and require the
# per-process component to be in THAT statement. Full-line comments come off first: the
# paragraph above that code in main.cpp writes ".new" while explaining why it must not be
# fixed, and an explanation must not satisfy the check.
KTSRC=$(grep -v '^[[:space:]]*//' "$ROOT/src/msxcep/main.cpp")
KTSTAGE=$(printf '%s\n' "$KTSRC" | tr '\n' ' ' | sed -e 's/"\.new".*//' -e 's/.*;//')
chk "  the staging path is built per-process, not as a fixed .new" yes \
    "$(printf '%s\n' "$KTSRC" | grep -q '"\.new"' &&
       printf '%s' "$KTSTAGE" | grep -qE 'getpid\(\)|mkstemp|unique_path' && echo yes || echo no)"
chk "  and no staging file is left behind either" no \
    "$(ls "$W"/mergetmp/fastpki-merged.*.new 2>/dev/null | grep -q . && echo yes || echo no)"

# A cached path that has since vanished must rebuild, not be handed to krb5 as a dead path.
rm -f "$MERGED"
"$SPNEGO" "$UK" HTTP@localhost application/soap+xml rst.xml >/dev/null 2>&1 || true
chk "  a DELETED merged keytab is rebuilt, not served as a dead path" yes     "$([ -s "$MERGED" ] && echo yes || echo no)"

# The burst. Not proof on its own -- it is the shape that used to fail -- but a corrupt
# merge here shows up as a 401 rather than as nothing at all.
# ⚠️ START COLD. Three requests have already run, so with the cache warm the burst would
# never build at all -- it would exercise the fast path and prove nothing about the thing
# that used to race. Touching a keytab moves the cache key, so the ten requests below
# genuinely contend to rebuild, which is the shape that used to corrupt the file.
sleep 1; cat "$W/http.keytab" > "$W/http2.keytab"
C0=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_issued' AND actor='pkitest\\alice';")
# ⚠️ WAIT ON THESE JOBS, NOT ON `wait`. A bare `wait` waits for EVERY child of this shell --
# which here includes the KDC and fastpki-ms, neither of which ever exits. The suite hung
# until its own timeout, with the burst long finished.
BURST=""
for i in 1 2 3 4 5 6 7 8 9 10; do
    "$SPNEGO" "$UK" HTTP@localhost application/soap+xml rst.xml >/dev/null 2>&1 &
    BURST="$BURST $!"
done
for pid in $BURST; do wait "$pid" 2>/dev/null || true; done
C1=$(pg_exec "SELECT COUNT(*) FROM audit_log WHERE action='cert_issued' AND actor='pkitest\\alice';")
chk "10 concurrent SPNEGO requests ALL enrol" 10 "$((C1 - C0))"

echo
echo "=== MS-KERBEROS: PASS=$pass FAIL=$fail SKIP=$skip ==="
[ "$fail" -eq 0 ]
