#!/usr/bin/env bash
# The docs must not lie.
#
# Nothing verified them until now, and it showed. Writing four guides against the code
# today produced four wrong claims that only got caught because I happened to check:
#
#   CRL_CACHE_SECONDS      invented — the key is CRL_CACHE_TTL_SEC
#   web-user … '' …        the password argument is positional and required
#   PEM / PKCS#12 only     DER is offered too
#   "too many certificates" the message is `per-CN issuance limit reached`
#
# A guide that lies is worse than a missing one, and the failure is silent: nobody
# notices until an operator types a command that does not work, usually during an
# incident. So this asserts the two things that go stale fastest and can be checked
# mechanically — config keys and CLI subcommands. Prose is not checkable and is not
# checked; the point is to catch the parts that are.
#
# Same shape as config_keys_live.sh, which asserts no SHIPPED file names a config key
# the parser ignores. This is its mirror for the docs.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$ROOT"
# ⚠️ THE TIER, so a missing binary can be a SKIP on a laptop and a FAILURE in the image.
# env_report.sh reads /etc/fastpki-test-env, which the Dockerfile stamps.
# shellcheck source=/dev/null
[ -r "$ROOT/tests/env_report.sh" ] && . "$ROOT/tests/env_report.sh"
pass=0; fail=0; skipped=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# README.md was NOT in this list at first, which is precisely why it carried a build
# flag that does not exist (`-DFASTPKI_WITH_POSTGRES=ON`) for as long as it did. It is
# the most-read file in the repo — the last place a stale claim should be allowed to sit.
# docs/authentication.md joins the list the day it is written. It names 31 config
# keys and a great many file:line citations; the keys are exactly what this suite checks,
# and a doc about AUTHENTICATION that names a key the parser ignores is worse than most.
# ⚠️ CHANGELOG.md IS CHECKED LIKE A GUIDE, because it is read like one. It is the first thing
# an operator opens to decide whether to upgrade, and it names commands and settings while
# describing what changed — so a subcommand renamed in the same release it is announced in
# would be wrong in the one place everybody reads.
DOCS="CHANGELOG.md README.md NOTICE.md docs/deployment.md docs/high-availability.md docs/admin-guide.md docs/postgres.md docs/rbac.md docs/user-guide.md docs/config-reference.md docs/cli-reference.md docs/authentication.md docs/components.md docs/protocol-apis.md docs/api-reference.md docs/windows-autoenrolment.md demo/README.md deploy/native/README.md deploy/cloud/README.md .github/workflows/README.md third_party/README.md"

echo "=== 1. every config key a doc names must exist in the parser ==="
# The parser is the authority: config.cpp's `key == "X"` arms are the complete set of
# keys FastPKI understands. A doc naming anything else is telling an operator to set
# something that will be silently ignored — which is how 12 dead keys survived so long.
grep -oE 'key == "[A-Z0-9_]+"' src/lib/config.cpp | sed 's/key == "//; s/"//' | sort -u > /tmp/da_real.txt
REAL=$(wc -l < /tmp/da_real.txt | tr -d ' ')
chk "the parser exposes keys" yes "$([ "$REAL" -gt 50 ] && echo yes || echo no)"

# The deployment variables are NOT bootstrap.conf keys and never reach the parser: they
# configure the Kubernetes manifests through envsubst, and compose through deploy/.env.
# DERIVED FROM THE FILES THAT DEFINE THEM, not transcribed into the allowlist below: a real
# one then passes without an edit, a typo still fails because it is in neither list, and the
# set cannot go stale as the manifests grow.
#
# ⚠️ BOTH FILES, because the two paths define different variables. Reading only k8s/env.sh
# missed every compose-only one — FASTPKI_PIN, POSTGRES_PASSWORD, PG_BIND, STANDBY_OF and
# the rest live in deploy/.env.example — so documenting one of them in backticks failed this
# suite as "a config key the parser ignores", which is the opposite of what it is: a real,
# required deployment variable that simply is not a bootstrap.conf key.
{ grep -oE '^export [A-Z0-9_]+' deploy/k8s/env.sh | sed 's/^export //'
  grep -oE '^#? *[A-Z][A-Z0-9_]+=' deploy/.env.example | tr -d '#' | tr -d ' ' | sed 's/=$//'
} | sort -u > /tmp/da_deploy.txt
DEPV=$(wc -l < /tmp/da_deploy.txt | tr -d ' ')
# ⚠️ Anti-vacuity: if the extraction stops matching, every deployment variable in the
# docs would silently become "unknown" and this suite would go red for the wrong
# reason — or, if the loop below were ever reordered, pass over everything.
chk "the deployment variables were discovered" yes "$([ "$DEPV" -gt 10 ] && echo yes || echo no)"

# Candidate keys in the docs: SCREAMING_SNAKE inside backticks, which is how every doc
# writes one. Filtered to names that LOOK like config keys and are not obviously
# something else (env vars we set, SQL, HTTP verbs, placeholder text).
: > /tmp/da_doc.txt
for f in $DOCS; do
    [ -f "$f" ] || continue
    grep -oE '`[A-Z][A-Z0-9_]{3,}`' "$f" | tr -d '`' >> /tmp/da_doc.txt
done
sort -u /tmp/da_doc.txt -o /tmp/da_doc.txt

# One paragraph per line, for the past-tense test further down. Markdown wraps prose at
# ~80 columns, so "the static file backends were removed: `WEB_USERS_FILE` …" puts the
# verb and the key on different LINES -- a line-based test reads the mention as a live
# instruction and flags it. The paragraph is the unit that carries the meaning.
awk 'BEGIN{p=""} /^[[:space:]]*$/{if(p!="")print p; p=""; next} {p=(p==""?$0:p" "$0)} END{if(p!="")print p}' \
    $DOCS > /tmp/da_para.txt 2>/dev/null
# Names that are real and documented elsewhere but are NOT bootstrap.conf keys: compose/.env
# variables (FASTPKI_IMAGE, PG_BIND), an install-wizard question (KEY_BACKEND), signals,
# and plain acronyms that happen to be capitalised in backticks.
#
# SSL_VERIFY_PEER / SSL_VERIFY_FAIL_IF_NO_PEER_CERT are OpenSSL constants, in the same
# company as GENERAL_NAME and PKCS7 above. SUBJECT_DN is here for the OPPOSITE reason:
# it is an HTTP header fastpki-est no longer reads at all, named in the auth doc
# only to record what was removed and why. Its partner CLIENT_CERT_VERIFY needs no entry
# because the extractor never matched it; do not read that as a rule.
cat > /tmp/da_allow.txt <<'ALLOW'
# Not config keys: filenames and formats that legitimately appear in backticks. SHA256SUMS
# is the checksum file release.yml publishes beside the tarball, named in docs/deployment.md
# where the one-command install is described.
SHA256SUMS
# libpq and PostgreSQL names, from the HA guide: CONNECTION_BAD is a libpq enum, PGOPTIONS
# is a PostgreSQL environment variable, and PATH is the shell's. None are ours to parse.
CONNECTION_BAD
PGOPTIONS
PATH
# docker compose reads this one, not us: it selects which profiles start. Named in the
# deployment guide because the wizard writes it, and in .env.example because an operator
# edits it to add a protocol later.
COMPOSE_PROFILES
# The AWS CLI, Packer and OpenTofu all read this to choose a credential profile; nothing in
# FastPKI ever does. The cloud section names it because every command there needs the same
# profile exported, and because pointing it at the wrong account is how an apply creates a CA
# somewhere nobody meant it to.
AWS_PROFILE
# Read from the environment, never by pki::Config: the compose postgres entrypoint seeds from
# that node with pg_basebackup instead of initialising a primary, and on both compose and
# native the nightly job and the console run key sync from it. It is how a standby is marked
# and how the old primary rejoins after a promotion, so the HA runbook has to name it.
STANDBY_OF
# Companions of STANDBY_OF, read by the same entrypoint rather than by pki::Config.
# PRIMARY_HOST tells deploy/db-restore-online.sh which node to restore away from.
# STANDBY_CA is the primary's trust anchor a joining host needs (its own ca.crt is a
# self-signed cert the primary was not issued by). It is operator-facing in .env.example and
# the HA runbook, so the docs have to name it.
# The password the compose postgres image initialises the `fastpki` role with, read by
# that image and by pg_basebackup — never by pki::Config, which gets it inside PG_CONNINFO.
# A joining standby has to authenticate to the primary with the same value, so the HA
# runbook names it.
POSTGRES_PASSWORD
PRIMARY_HOST
STANDBY_CA
ALTER
DROP
BEGIN
CN
CSR
DER
DNS
EAB
EXPAND
FASTPKI_IMAGE
HTTP
KEY_BACKEND
PG_BIND
CHECK
# Signature-algorithm names as OpenSSL prints them in a certificate. SCREAMING_CASE
# in backticks like a config key, and none of our business as one -- the replication
# troubleshooting section quotes them because they are exactly what an operator reads
# out of `openssl x509 -text` when channel binding refuses a connection.
ED25519
ED448
DES3
GENERAL_NAME
PKCS7
SSL_VERIFY_PEER
SSL_VERIFY_FAIL_IF_NO_PEER_CERT
# Windows CryptoAPI error constants, same company as the OpenSSL ones above. They are
# quoted in the interoperability guide because they are literally what certutil prints:
# NTE_BAD_ALGID is how Server 2022 reports a signature algorithm it has no provider for,
# and CRYPT_E_NO_REVOCATION_CHECK is the benign complaint that must NOT be read as one.
NTE_BAD_ALGID
CRYPT_E_NO_REVOCATION_CHECK
# Browser / NSS TLS alert names. Same shape as a config key, quoted in the
# troubleshooting section because they are exactly what an operator reads off the
# screen when a listener demands a client certificate.
SSL_ERROR_RX_CERTIFICATE_REQUIRED_ALERT
ERR_BAD_SSL_CLIENT_AUTH_CERT
SUBJECT_DN
OPENSSL_CONF
P11_PROVIDER
RTLD_DEEPBIND
SOFTHSM_MODULE
SIGINT
SIGTERM
# A DNS response code, quoted in the directory-setup section because it is exactly what an
# operator reads off `nslookup` when the container cannot resolve the domain controller.
# Same shape as a config key and no more one than TLS or URI are.
NXDOMAIN
JRE
MDM
NNNN
PEM
PKCS
PSQL
MESH_BIN
RFC
SELECT
SHOW
SQL
TLS
URI
URL
UTC
ALLOW
UNKNOWN=""
while read -r k; do
    [ -z "$k" ] && continue
    grep -qx "$k" /tmp/da_real.txt && continue
    grep -qx "$k" /tmp/da_allow.txt && continue
    grep -qx "$k" /tmp/da_deploy.txt && continue
    # PKCS#11 constants are a whole namespace, not a list: CKM_ mechanisms, CKR_ return
    # values, CKA_ attributes, CKF_ flags, CKO_ object classes, CKK_ key types. They are
    # SCREAMING_SNAKE in backticks like a config key and are none of our business as
    # config keys, so match the prefix rather than adding a name every time the HSM docs
    # mention one — which is how this fired on §6.1 naming four mechanisms.
    case "$k" in CKM_*|CKR_*|CKA_*|CKF_*|CKO_*|CKK_*) continue ;; esac
    # OpenSSL C type names are the same shape as a config key and the architecture
    # sections are full of them (`X509_EXTENSION`, `OSSL_CMP_SRV_CTX`, `OCSP_CERTID`).
    # Prefix-matched for the same reason as the PKCS#11 block: they are a namespace,
    # not a list that should grow every time a doc names another type.
    case "$k" in X509*|OCSP_*|OSSL_*|EVP_*|ASN1_*) continue ;; esac
    # Windows and COM error constants, which the MS-XCEP documentation has to quote
    # verbatim: they are the strings an operator actually sees, and the whole value of the
    # symptom table in windows-autoenrolment.md is that it names them exactly. Same shape
    # as a config key and the same reason as the two blocks above — a namespace, not a list
    # that should grow every time a Windows failure is documented.
    # CERT_E_* belongs with them: CERT_E_UNTRUSTEDROOT is what `certreq -accept` prints when
    # the root is not trusted yet, quoted in both the Windows guide and the user guide.
    case "$k" in ERROR_*|WS_E_*|NTE_*|SEC_E_*|TRUST_E_*|CRYPT_E_*|CERT_E_*|CERTSRV_*) continue ;; esac
    # libpq's OWN environment variables (PGPASSWORD, PGHOST, PGSSLMODE …). The deployment
    # docs name them because that is how a password reaches a pod without passing through
    # a ConfigMap, and libpq reads them directly — they are not keys our parser has any
    # business knowing. Matched WITHOUT an underscore after PG, so this excuses PGPASSWORD
    # and still flags a typo in a real key like PG_CONNINFO.
    case "$k" in PG[A-Z]*) continue ;; esac
    # certgen.sh's OWN deploy-time environment variables. SELFSIGNED_DAYS and
    # SELFSIGNED_RENEW_DAYS set how long the self-signed transport certificates live and how
    # early they are re-issued; they are read by a shell script at deploy time, never by
    # apply(), so the parser has no business knowing them. Same reason as the libpq block
    # above: real, live, settable, and not config-table keys. They are worth documenting
    # because the daily job's renewal threshold is exactly SELFSIGNED_RENEW_DAYS, and an
    # operator asking "when does my token tunnel renew" has nowhere else to look.
    case "$k" in SELFSIGNED_*) continue ;; esac
    # And the demo harness's own variable, for the same reason. FASTPKI_BIN tells
    # pki-bench.sh where the locally built client binaries are — it is read by a shell
    # script measuring against a deployment, never by apply(). It has to be documented
    # because a release tarball carries no build/ and the bench cannot find them otherwise.
    case "$k" in FASTPKI_BIN) continue ;; esac
    # kubectl's OWN environment variable, for the same reason as the libpq block above: read
    # by kubectl, never by apply(). §8.4 has to name it because k3s writes its kubeconfig
    # root-only, so apply.sh fails on its first kubectl call with "permission denied" even
    # when a valid ~/.kube/config exists — and pointing KUBECONFIG at the copy is the fix.
    # An operator who hits that has nowhere else to look.
    case "$k" in KUBECONFIG) continue ;; esac
    # Browser error codes, which a guide has to quote verbatim because that string is what
    # the operator sees on screen and searches for. MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT and
    # ERR_CERT_AUTHORITY_INVALID are Firefox's and Chrome's names for "this certificate is
    # not signed by anyone I trust", which is the CORRECT state of a console that has no CA
    # yet. They look like config keys only to the ALL_CAPS heuristic. This excuse is narrow
    # on purpose: the two prefixes belong to browsers and can never name a config key.
    case "$k" in MOZILLA_PKIX_*|ERR_CERT_*) continue ;; esac
    # A doc may name a REMOVED key in the past tense -- "`USERS_FILE` was removed in
    # removed" is history, not an instruction. What must never happen is presenting a
    # dead key as live. So excuse the name only when EVERY line that mentions it also
    # says it is gone; one line that does not, and it is flagged.
    MENTIONS=$(grep -h -- "\`$k\`" /tmp/da_para.txt 2>/dev/null | wc -l | tr -d ' ')
    PAST=$(grep -h -- "\`$k\`" /tmp/da_para.txt 2>/dev/null \
             | grep -ciE 'remove|no longer|deleted|dropped|gone|replaced by' | tr -d ' ')
    [ "$MENTIONS" -gt 0 ] && [ "$MENTIONS" -eq "$PAST" ] && continue
    # A key the parser does not know and we have not excused.
    UNKNOWN="$UNKNOWN $k"
done < /tmp/da_doc.txt
if [ -n "$UNKNOWN" ]; then echo "    unknown:$UNKNOWN"; fi
chk "no doc names a config key the parser ignores" "" "$UNKNOWN"

echo "=== 2. every CLI subcommand a doc shows must exist ==="
# Read each tool's own usage text and check the verbs the docs tell people to type.
# CRL_CACHE_SECONDS was a config key; this is the same class of error one level up —
# a command that does not exist fails at the worst possible moment.
have_cmd(){  # <binary> <subcommand>
    local b="$ROOT/build/$1"
    [ -x "$b" ] || { echo skip; return; }
    # The verb may start the line ("  create <id> …") or follow the invocation
    # ("  fastpki-audit --config <f> verify"). Match either, or the check tests the
    # usage text's LAYOUT instead of whether the command exists.
    "$b" 2>&1 | grep -qE "(^[[:space:]]*|[[:space:]])$2([[:space:]]|$)" && echo yes || echo no
}
for spec in \
    "fastpki-ca:create" "fastpki-ca:add" "fastpki-ca:list" "fastpki-ca:enable" \
    "fastpki-ca:disable" "fastpki-ca:renew" \
    "fastpki-config:backup" "fastpki-config:restore" "fastpki-config:web-user" \
    "fastpki-config:decrypt-backup" \
    "fastpki-config:domains-import" "fastpki-config:set" "fastpki-config:get" \
    "fastpki-audit:verify" "fastpki-audit:export-signed" "fastpki-audit:verify-export" \
    "fastpki-audit:forward"; do
    b="${spec%%:*}"; c="${spec##*:}"
    r=$(have_cmd "$b" "$c")
    # ⚠️ A MISSING BINARY IS A FAILURE IN THE IMAGE, AND A HALVED SUITE EVERYWHERE ELSE.
    #
    # This used to skip unconditionally, and the consequence was measured rather than
    # imagined: with the shared build/ emptied, this suite reported
    #
    #     === DOCS ACCURATE: PASS=12 FAIL=0 ===
    #
    # instead of its usual 27. Fifteen assertions vanished and the verdict still said the
    # docs were accurate. run_all.sh already catches a suite that asserts NOTHING; nothing
    # catches one that quietly asserts HALF, which is the more dangerous of the two because
    # it looks exactly like a pass.
    #
    # In the production image every one of these binaries is present by construction, so
    # "not built" there is an IMAGE GAP and must fail — the same rule run_all.sh applies to
    # a skipped suite. On a developer box a partial build is legitimate, so it stays a skip
    # and is COUNTED, so the number is visible in the summary rather than silently absorbed.
    if [ "$r" = skip ]; then
        if [ "$(env_id 2>/dev/null || echo host)" = test-image ]; then
            echo "  [FAIL] $b not built — every CLI exists in the production image, so this is an image gap"
            fail=$((fail+1))
        else
            echo "  [SKIP] $b not built"
            skipped=$((skipped+1))
        fi
        continue
    fi
    chk "$b $c exists" yes "$r"
done

echo "=== 3. every deploy script a doc tells you to run must be there ==="
for s in $(grep -ohE '\./[a-z0-9-]+\.sh|deploy/[a-z0-9-]+\.sh' $DOCS 2>/dev/null | sed 's#^\./#deploy/#' | sort -u); do
    chk "$s exists" yes "$([ -f "$ROOT/$s" ] && echo yes || echo no)"
done

echo "=== 4. relative links between the docs must resolve ==="
# A guide that points at a missing file is a dead end, and markdown will not tell you.
BROKEN=""
for f in $DOCS; do
    [ -f "$f" ] || continue
    d=$(dirname "$f")
    for l in $(grep -oE '\]\(\.\.?/[^)]+\)' "$f" | sed 's/](//; s/)$//' | sort -u); do
        t="$d/${l%%#*}"
        [ -e "$t" ] || BROKEN="$BROKEN $f->$l"
    done
done
if [ -n "$BROKEN" ]; then echo "    broken:$BROKEN"; fi
chk "no broken relative links" "" "$BROKEN"

echo "=== 5. every -D build option a doc names must be a real option() ==="
# Same class as a dead config key, one level up: the README documented
# `-DFASTPKI_WITH_POSTGRES=ON` long after Postgres became mandatory and unconditional,
# so an operator following it got a flag CMake silently ignores. CMakeLists.txt's
# option() lines are the authority.
# Two legitimate declarations, and the check needs both: option() for booleans, and a
# plain `if(NOT DEFINED X)` guard for a string the build honours from -D (FASTPKI_VERSION
# is one -- it takes a version string, so option() would be the wrong tool). Accepting
# only option() flagged it as a lie when it is not one.
REAL_OPTS=$( { grep -oE '^option\([A-Z_]+' CMakeLists.txt | sed 's/^option(//'
               grep -oE 'if\(NOT DEFINED [A-Z_]+' CMakeLists.txt | sed 's/.*DEFINED //'
             } | sort -u )
for o in $(grep -ohE '\-D(FASTPKI|CMAKE)_[A-Z_]+' $DOCS 2>/dev/null | sed 's/^-D//' | sort -u); do
    case "$o" in
        CMAKE_*) continue ;;   # built into CMake itself, not ours to declare
    esac
    chk "$o is a real option()" yes "$(echo "$REAL_OPTS" | grep -qx "$o" && echo yes || echo no)"
done


echo "=== 6. every documented DEFAULT must be the default the code holds ==="
# ⚠️ SECTION 1 PROVES THE KEY IS REAL AND SAYS NOTHING ABOUT ITS VALUE, so the Default
# column drifted freely and ten of them were wrong. The worst had EST_KEY, ACME_KEY and
# MS_KEY defaulting to /etc/ssl/private/<proto>.key and marked "File-only", when the real
# default is a pkcs11: URI into the token — the documented default was the last-resort
# fallback, in a product whose rule is that private keys live in an HSM. Following the
# table built the one arrangement the design exists to prevent.
#
# Three extractions, each from the authority for its half:
#   KEY -> field     the apply() chain in config.cpp, which is what reads the key
#   field -> default the member initialiser in config.hpp, which is what holds it
#   KEY -> documented  column 3 of the config-reference tables
# A key whose default is computed rather than initialised simply has no field entry and is
# skipped — this compares what it can and says how many, rather than asserting over a set
# it cannot see.
# ⚠️ `[^c]*c\.` RATHER THAN `.*c\.`, because `.*` is greedy and finds the LAST `c.` in the
# line. A nested field whose own name contains one — c.scep_ra_key_spec.bits has a "c."
# inside "spec.bits" — then captures the tail alone, `bits`, which collides with the bare
# member of every other struct and compares one key's documentation against another's
# default. Matching up to the FIRST `c` gets the whole field. Same 140 keys either way.
grep -oE 'key == "[A-Z0-9_]+"\)[^;]{0,80}' src/lib/config.cpp \
  | sed -E 's/key == "([A-Z0-9_]+)"\)[^c]*c\.([a-z_0-9.]+) *=.*/\1 \2/' \
  | grep -E '^[A-Z0-9_]+ [a-z_0-9.]+$' | sort -u > /tmp/da_keyfield.txt
grep -oE '[a-z_0-9]+\{[^}]*\};' include/pki/config.hpp \
  | sed -E 's/^([a-z_0-9]+)\{(.*)\};$/\1 \2/' | sort -u > /tmp/da_fielddef.txt
grep -oE '^\| `[A-Z0-9_]+` \| [a-z0-9 ]+ \| [^|]+' docs/config-reference.md \
  | sed -E 's/^\| `([A-Z0-9_]+)` \| [a-z0-9 ]+ \| */\1 /; s/ *$//' | sort -u > /tmp/da_docdef.txt

# ⚠️ ANTI-VACUITY. All three greps returning nothing is indistinguishable from perfect
# agreement, and two of them are brittle by nature (a struct reformat, a table column added).
chk "  the key->field map was extracted"   yes \
    "$([ "$(grep -c . /tmp/da_keyfield.txt)" -gt 80 ] && echo yes || echo no)"
chk "  the field->default map was extracted" yes \
    "$([ "$(grep -c . /tmp/da_fielddef.txt)" -gt 50 ] && echo yes || echo no)"
chk "  the documented defaults were extracted" yes \
    "$([ "$(grep -c . /tmp/da_docdef.txt)" -gt 80 ] && echo yes || echo no)"

WRONG=""; compared=0
while read -r K F; do
    code=$(grep -E "^${F} " /tmp/da_fielddef.txt | head -1 | cut -d' ' -f2-); [ -z "$code" ] && continue
    doc=$(grep -E "^${K} " /tmp/da_docdef.txt | head -1 | cut -d' ' -f2-);   [ -z "$doc" ] && continue
    compared=$((compared + 1))
    # Compare the VALUES, not their punctuation: the code writes "fastpki" and the table
    # writes `fastpki`, and neither spelling is more correct than the other.
    cn=$(printf '%s' "$code" | tr -d '"` '); dn=$(printf '%s' "$doc" | tr -d '"` ')
    [ "$cn" = "$dn" ] || WRONG="$WRONG $K(doc=$doc code=$code)"
done < /tmp/da_keyfield.txt
echo "     comparing $compared documented defaults"
chk "no documented default disagrees with the code" "" "$WRONG"
echo "=== the guides describe the present, not how they got here ==="
# ⚠️ A READER OPENS THE DOCUMENTATION TO FIND OUT WHAT THE SOFTWARE DOES NOW. Every sentence
# about a previous design is one they must read, understand and then discard — and worse, it
# plants a model they have to un-learn. "MAX_SAN has been removed" makes a reader wonder
# whether they need MAX_SAN; saying nothing about it does not.
#
# Nine of these had accumulated across docs/deployment.md, README.md and four guides, and nothing
# looked for them. History belongs in commit messages and in ⚠️ source comments, which are
# aimed at the next developer editing the line rather than at an operator.
#
# The exception is narrow, which is why this matches PHRASES and not words: a live trap the
# reader can still walk into — a stale file they possess that the software will not explain
# by itself. Describing a CURRENT state ("a key the token no longer holds", "a name the
# directory no longer offers") is not history at all and must keep passing.
HIST=""
for f in "$ROOT/README.md" "$ROOT"/docs/*.md; do
    [ -f "$f" ] || continue
    if grep -inE '(has|have) been removed|(was|were|is|are) removed|previously had|this replaces the|used to be|no longer exists' "$f" \
       | grep -viE 'anchors were removed' | grep -q .; then
        HIST="$HIST $(basename "$f")"
    fi
done
chk "no guide narrates what was removed or replaced" "" "${HIST# }"

# ⚠️ AN IMAGE A GUIDE LINKS TO MUST EXIST, BECAUSE THE GUIDES ARE PUBLISHED. A screenshot is
# added by replacing the placeholder that names it with a normal image link, and a typo in
# that filename costs nothing locally and shows a broken image on the website. docs/images/
# has the convention; this is the half a person cannot check by eye once there are dozens.
MISSING_IMG=""
for f in "$ROOT/README.md" "$ROOT"/docs/*.md; do
    [ -f "$f" ] || continue
    for img in $(grep -oE '!\[[^]]*\]\(images/[^)]+\)' "$f" | sed -E 's/.*\((images\/[^)]+)\)/\1/'); do
        [ -f "$ROOT/docs/$img" ] || MISSING_IMG="$MISSING_IMG $(basename "$f"):$img"
    done
done
chk "every image a guide links to is in docs/images/" "" "${MISSING_IMG# }"

# The other half: a placeholder must name a file under images/, or the person filling it in
# has nothing to match the screenshot against. grep -rn '📷 Screenshot' docs/ is how the
# outstanding ones are listed, so the shape has to stay greppable.
BAD_PH=$(grep -rhn '📷 Screenshot' "$ROOT"/docs/*.md | grep -vcE '`images/[A-Za-z0-9._-]+`' || true)
chk "every screenshot placeholder names a file under images/" 0 "${BAD_PH:-0}"

echo
[ "$skipped" -gt 0 ] && echo "  ($skipped CLI check(s) skipped — binaries not built here)"
echo "=== DOCS ACCURATE: PASS=$pass FAIL=$fail${skipped:+ SKIP=$skipped} ==="
[ "$fail" -eq 0 ]
