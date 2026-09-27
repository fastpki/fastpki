#!/usr/bin/env bash
# What the demo and bench SCRIPTS do — assertions that never start a deployment.
#
# Split out of tests/demo_clients.sh, which drives demo/pki-demo.sh for real. Throwaway
# mode now stages a docker compose project, so that suite can only run on a host with
# docker — and the harness runs inside the production image, which has none and must not
# be handed the host socket. Everything here reads the scripts, or runs them in --target
# mode (live mode stages nothing), so none of it needs docker and all of it runs in the
# container gate with the rest of CORE.
#
# ⚠️ THESE ARE NOT STYLE CHECKS. Each one pins a behaviour a successful demo run cannot
# self-report: that cleanup revokes through the product API rather than writing to
# Postgres, that no throwaway database is left unreapable, that the bench orders a real
# certificate per iteration instead of re-serving one. A demo that did the forbidden
# thing would still print every success line and exit 0.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}

pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ grep -q "$2" <<<"$1" && echo yes || echo no; }

echo "=== the demo scripts take Postgres from the environment, not from a literal ==="
# PGUSER is `fastpki` now and PGPASSWORD is unset — it can be set from the
# container's POSTGRES_PASSWORD, but the bench needed fixes around this too.
#
# Both demos SOURCE tests/pg_helpers.sh — which resolves $PGUSER and $PGPASSWORD — and then
# ignored both, hardcoding `-U fastpki` and `password=fastpki` in a dozen places. On a
# deployment whose role or password differs (his: POSTGRES_PASSWORD from a docker variable)
# the conninfo handed to the fastpki binaries was wrong even where psql itself worked, so
# the failure surfaced as a product error rather than a configuration one.
#
# ⚠️ These three are greps, and a grep is a weak assertion. They are here because all three
# defects are INVISIBLE on this machine: trust auth accepts any password, macOS has no
# /etc/ssl/openssl.cnf worth adopting, and a leaked database is only noticed on the next
# run. A suite that only ran the demos would keep passing through every one of them.
for f in "$ROOT/demo/pki-bench.sh" "$ROOT/demo/pki-demo.sh"; do
    n=$(basename "$f")
    # -U fastpki polices REACHING OUT to an operator cluster with a hardcoded role.
    # The throwaway stack is exempt by construction: schema-apply execs INSIDE this
    # run's own postgres container, whose superuser role is whatever the same repo's
    # compose file created. Filtering those lines keeps the external-cluster guard
    # sharp without forbidding the demo from setting up its own database.
    chk "$n has no hardcoded postgres role"     0 \
        "$(grep -E '\-U +fastpki\b' "$f" | grep -vc 'exec -T postgres')"
    chk "$n has no hardcoded postgres password" 0 \
        "$(grep -cE 'password=fastpki\b' "$f" | tr -d ' ')"
    # OPENSSL_CONF: the BENCH still adopts /etc/ssl/openssl.cnf when it defines
    # providers (its host-side openssl mints keys); the DEMO deliberately does NOT any
    # more — every key lives in the throwaway stack's SoftHSM and is driven inside the
    # containers, so adopting a shadowing host config only made throwaway fragile.
    if [ "$n" = pki-bench.sh ]; then
      chk "$n guards OPENSSL_CONF"              yes \
          "$(grep -q 'grep -q providers /etc/ssl/openssl.cnf' "$f" && echo yes || echo no)"
    else
      chk "$n does NOT adopt OPENSSL_CONF"      0 \
          "$(grep -vE '^[[:space:]]*#' "$f" | grep -cE 'export +OPENSSL_CONF=' | tr -d ' ')"
    fi
    # `_pg_reap` only collects `fpki_<name>_<pid>`. A throwaway database named anything else
    # survives a run that is killed past its EXIT trap — one directory along.
    chk "$n creates no unreapable database"     0 \
        "$(grep -cE 'CREATE DATABASE +(fastpki_|\$\{?(PGDB|ACDB|ADB))' "$f" | tr -d ' ')"
done

echo "=== the demo targets the LIVE deployment and cleans up after itself ==="
# A throwaway postgres instance is not what demo tests are for; they run against the live
# deployment and clean up after themselves by revoking the certificates they requested.
D="$ROOT/demo/pki-demo.sh"
chk "demo: throwaway is opt-in, not the default" yes \
    "$(grep -q '\-\-throwaway) MODE=throwaway' "$D" && echo yes || echo no)"
chk "demo: picks up demo/.target.env on its own" yes \
    "$(grep -q 'DEFAULT_TARGET=' "$D" && echo yes || echo no)"
# The old cleanup UPDATEd certs rows straight in Postgres — no CRL, no OCSP, no audit, and
# only correct if the demo ran on the deployment host.
# ⚠️ STRIP COMMENTS FIRST. This assertion went red against a correct fix because the
# comment explaining what was DELETED quotes the very SQL it forbids — a grep hit inside a
# comment is not evidence of behaviour, and here it was evidence of the
# opposite. Match executable lines only.
chk "demo: cleanup does not poke postgres directly" 0 \
    "$(grep -vE '^[[:space:]]*#' "$D" | grep -cE 'UPDATE certs SET status' | tr -d ' ')"
chk "demo: it revokes through the product API"     yes \
    "$(grep -q 'api/certs/\$ser/revoke' "$D" && echo yes || echo no)"
# ⚠️ It must revoke only what it issued. A cleanup that discovered certificates by scanning
# the work dir would find the chain and the CA cert sitting right next to the leaves.
chk "demo: it revokes only serials it recorded"    yes \
    "$(grep -q 'record_issued' "$D" && echo yes || echo no)"

echo "=== the bench cleans up its own certificates in live mode ==="
# The bench is the half that matters: a default run is COUNT x protocols x key
# types certificates — 50 x 3 x 10 — and it left every one active, so the NEXT run measured
# the per-requester cap instead of issuance (MAX_CERTS_PER_CN is gone).
BB="$ROOT/demo/pki-bench.sh"
chk "bench: revokes what it issued"          yes \
    "$(grep -q 'revoke_bench_certs' "$BB" && echo yes || echo no)"
chk "bench: through the product API"         yes \
    "$(grep -q 'api/certs/\$ser/revoke' "$BB" && echo yes || echo no)"
chk "bench: not by poking postgres"          0 \
    "$(grep -vE '^[[:space:]]*#' "$BB" | grep -cE 'UPDATE certs SET status' | tr -d ' ')"
# ⚠️ The filter must be NARROW, AND SCOPED TO THIS RUN. The bench logs in as a real console
# user, so an unanchored serial grep over /api/certs would collect every certificate that
# account owns — including ones a human made — and revoke them. Anchoring on the CN shape
# alone is not enough either: every run produces the SAME shapes, so the cleanup swept up
# earlier runs' certificates and reported them as "this run issued", and two people
# benchmarking one deployment at the same time revoked each other's. Every name a run
# enrols now carries a per-run token, and the filter must carry it too.
chk "bench: revokes only its own CN shapes"  yes \
    "$(grep -q 'b-.*BENCH_RUN.*-\[a-z0-9\]+-\[0-9\]+' "$BB" && echo yes || echo no)"
chk "bench: and only its own RUN"            yes \
    "$(grep -q 'BENCH_RUN=' "$BB" && echo yes || echo no)"
# Matching serial and cn on the SAME line is what keeps that true; grepping the whole JSON
# blob for serials would defeat the CN filter entirely.
# ⚠️ This assertion used to look for `tr '}' '}\n'` — the BROKEN idiom. tr truncates SET2
# to SET1's length, so that maps } to } and changes nothing; the guard passed on code that
# found 1 of 3 certificates. Assert the working split, and assert tr is NOT used for it.
chk "bench: splits records with sed, not tr"  yes \
    "$(grep -q "sed 's/},{/}" "$BB" && echo yes || echo no)"
chk "bench: no no-op tr record split"         0 \
    "$(grep -vE '^[[:space:]]*#' "$BB" | grep -cE "tr '\}' '\}" | tr -d ' ')"

echo "=== the bench's ACME leg is http-01 and can actually run ==="
# ACME takes roughly 30 seconds per order, so running it 50 times is unreasonable.
#
# ⚠️ These are greps, for the same reason as the block above: the ACME leg needs docker and
# a real certbot, so no assertion here can run it. It is measured on the sandbox VM instead
# (10/10 throwaway, 5/5 live, certs decoded). What a grep CAN do is stop the two shapes that
# made this leg silently dead from coming back — under `set -u` an unset variable and a
# wrong trust anchor both abort the leg long before any timing is printed, and the run still
# ends with a tidy 0/N row that reads like a slow server.
B="$ROOT/demo/pki-bench.sh"
# ⚠️ THE LOCAL LEG IS http-01; the REMOTE leg cannot be. This asserted that
# `--manual-auth-hook` appears nowhere in the file, which was right while the bench only ever
# ran against a throwaway stack on this host. A --target run has no inbound reachability, so
# its ACME leg has to be dns-01 with a manual hook, and a whole-file grep cannot tell the two
# legs apart — it just forbids the remote one from existing.
#
# The invariant that actually matters is unchanged: nothing on the LOCAL path may need a
# manual hook. So require every occurrence to sit inside the `acme_remote_dns` branch.
HOOKS_TOTAL=$(grep -c -- '--manual-auth-hook' "$B" | tr -d ' ')
# Count hooks that sit inside a remote branch: the flag turns on at each
# `if [ -n "${acme_remote_dns:-}" ]; then` and off at the next else/fi. A hook added to the
# LOCAL path, or outside the conditional entirely, is not counted, so the two assertions
# below disagree and the guard fires.
HOOKS_REMOTE=$(awk '/if \[ -n "\$\{acme_remote_dns:-\}" \]; then/ { inb=1; next } /^[[:space:]]*(else|fi)[[:space:]]*$/ { inb=0 } inb && /--manual-auth-hook/ { n++ } END { print n+0 }' "$B")
chk "bench: every dns-01 hook is inside the remote branch" "$HOOKS_TOTAL" "$HOOKS_REMOTE"
chk "bench: the local leg still needs no manual hook" yes     "$([ "$HOOKS_TOTAL" = "$HOOKS_REMOTE" ] && echo yes || echo no)"
chk "bench: no per-cert CoreDNS churn"   0 "$(grep -cE 'coredns|fastpki-bench-dns' "$B" | tr -d ' ')"
chk "bench: certbot uses --webroot"      yes "$(grep -q -- '--webroot' "$B" && echo yes || echo no)"
# Without --force-renewal certbot answers iterations 2..N from its own store and never
# contacts the server — a very fast row that measures nothing.
chk "bench: every iteration is a real order" yes \
    "$(grep -q -- '--force-renewal' "$B" && echo yes || echo no)"
# ACME_DIR was set only on the --target path, so the throwaway leg died on
# "ACME_DIR: unbound variable" and had never run.
chk "bench: throwaway mode sets ACME_DIR" yes \
    "$(grep -q 'ACME_DIR="https://localhost:\$LAPORT' "$B" && echo yes || echo no)"
# ...and it anchored certbot on the bench ROOT, while the throwaway ACME server presents a
# self-signed transport cert, so every handshake failed even once ACME_DIR existed.
chk "bench: throwaway anchors on the ACME cert" yes \
    "$(grep -q 'CERTBOT_CA="\$WORK/acme-tls.pem"' "$B" && echo yes || echo no)"
# Moving the BENCH off dns-01 must not take its coverage with it — dns-01 is still the
# challenge most deployments use for wildcards, even though it is not the only one that CAN
# do them.
chk "dns-01 still covered by a suite"    yes \
    "$([ -f "$ROOT/tests/acme_dns01.sh" ] && echo yes || echo no)"

echo "=== The demo reaches the PER-CA ACME route, and finds SCEP_CHALLENGE ==="
D="$ROOT/demo/pki-demo.sh"; PT="$ROOT/demo/provision-target.sh"
# (b) the ACME wildcard failed with "this endpoint is per-CA: use
# /acme/{ca_id}/directory" even though CA_ID was written in the target descriptor.
#
# ⚠️ The block that appends /$CA_ID handled EST, CMP and SCEP and silently omitted ACME —
# because ACME's id sits in the MIDDLE of the path (/acme/{id}/directory), so the
# `${VAR%/}/$CA_ID` suffix trick the other three share does not fit. Assert all FOUR are
# per-CA, or the next protocol added the same way is missed the same way.
for v in EST_URL CMP_URL SCEP_URL; do
  chk "$v gets the CA id"                yes \
      "$(grep -q "$v=\"\${$v%/}/\$CA_ID\"" "$D" && echo yes || echo no)"
done
chk "ACME_DIR gets the CA id too"        yes \
    "$(grep -q 'ACME_BASE_PATH:-/acme}/\$CA_ID/directory' "$D" && echo yes || echo no)"
# ...and it must be INSIDE the `if [ -n "$CA_ID" ]` block, or a target with no CA id
# would build a URL with an empty segment (//directory) instead of the base path.
chk "  and only when a CA id is known"   yes \
    "$(awk '/if \[ -n "\$CA_ID" \]; then/{f=1} f&&/ACME_BASE_PATH:-\/acme}\/\$CA_ID\/directory/{print "y";exit} /^  fi$/{f=0}' "$D" | grep -q y && echo yes || echo no)"

# (a) "provision-target.sh fails to copy SCEP_CHALLENGE from deploy/.env".
#
# ⚠️ DELETED THE THING THIS GUARDED. The fix for (a) was to hunt the deployment-wide
# secret through four locations — the scep container's environment, the web container's,
# the running bootstrap.conf, then two files — because the value travelled as an env var and so
# was in none of the places the script had looked. There is no deployment-wide value any
# more ("it's per user now"), so every one of those greps would now assert that a
# workaround still exists for a problem that cannot occur.
#
# The bug report underneath (a) was really "the demo could not obtain a usable SCEP
# credential". That is still worth guarding, so this asserts the source it uses NOW: the
# per-user credential from /api/enrolment-credentials, on the session it already holds.
chk "provision reads the per-user SCEP credential"      yes \
    "$(grep -q 'scep_challenge' "$PT" && echo yes || echo no)"
chk "  from the enrolment-credentials endpoint"         yes \
    "$(grep -q 'api/enrolment-credentials' "$PT" && echo yes || echo no)"
chk "  and it no longer hunts a deployment-wide secret" no \
    "$(grep -q 'printenv SCEP_CHALLENGE' "$PT" && echo yes || echo no)"
chk "compose no longer passes a shared challenge"       no \
    "$(grep -q 'SCEP_CHALLENGE:' "$ROOT/deploy/docker-compose.yml" && echo yes || echo no)"
chk "  and install.sh no longer generates one"          no \
    "$(grep -q "printf 'SCEP_CHALLENGE=%s" "$ROOT/deploy/install.sh" && echo yes || echo no)"
# A silent miss is what made this take a bug report to find — so the demo must still SAY
# when the user has no credential rather than skipping quietly.
chk "a missing credential is reported, not swallowed"   yes \
    "$(grep -q 'has no SCEP credential' "$PT" && echo yes || echo no)"

echo "=== The bench's SCEP leg actually enrols — RSA and EC alike ==="
# Reported: running the bench against a target descriptor made the SCEP tests fail on a
# wrong challenge — scep RSA-2048 0/50, scep EC P-256 0/50.
#
# The bench never learned that the challengePassword became a PER-USER credential
# and that the deployment-wide SCEP_CHALLENGE was deleted. pki-demo.sh reads it from
# /api/enrolment-credentials; the bench read cmp_secret and the ACME EAB from that same
# response and skipped this one, so every SCEP CSR went out with no challengePassword and
# the server refused all of them — for every key type equally, which is why the key looked
# like the variable.
#
# ⚠️ RUN IT, AND READ THE COUNTS. A grep for `scep_challenge` in the script would pass on a
# bench that fetched the value and then failed to put it in the CSR — the challengePassword
# is a PKCS#9 attribute and has to go in at `req -new` time, which is a second place to get
# it wrong. The cells below are the product's own answer.
#
# EC is here deliberately: "I suspect that we need to skip EC P-256 and EC P-384 tests for
# the same reason we skip other keys for SCEP - CMS." It does not hold — the requester's key
# signs the pkiMessage and the CertRep comes back enveloped to its certificate, which
# OpenSSL opens with ECDH key agreement, not RSA key transport. tests/scep.sh now drives
# both curves end to end; this asserts the same thing through the bench he ran.
BOUT=$(cd "$ROOT" && OSSL="$OSSL" bash demo/pki-bench.sh -n 2 -p scep -k "rsa2048 ec256 ec384" 2>&1)
# ⚠️ NOT `awk '{print $3}'`. The key column holds "EC P-256", which awk splits into two
# fields, so the count is $3 on the RSA rows and $4 on the EC ones — and $3 on an EC row is
# the string "P-256", which compares unequal to everything and reads as a product failure.
# Pull the first <n>/<n> token on the line instead.
cell(){ printf '%s\n' "$BOUT" | grep -E "^scep +$1 " | sed -nE 's/.*[[:space:]]([0-9]+\/[0-9]+)[[:space:]].*/\1/p' | head -1; }
chk "bench SCEP with an RSA-2048 key issues"  2/2 "$(cell 'RSA-2048')"
chk "bench SCEP with an EC P-256 key issues"  2/2 "$(cell 'EC P-256')"
chk "bench SCEP with an EC P-384 key issues"  2/2 "$(cell 'EC P-384')"
chk "  and neither EC curve is skipped"       0 \
    "$(printf '%s\n' "$BOUT" | grep -cE '^scep +EC .*skip' | tr -d ' ')"
[ "$(cell 'RSA-2048')" = 2/2 ] || printf '%s\n' "$BOUT" | sed 's/^/         /'
# The other half of the fix: with no credential the bench must SAY so rather than report
# 0/N at a plausible ops/s, which reads as a throughput result for a server that issued
# nothing. Grep-only — a run without a credential cannot be staged here, because the
# throwaway bench seeds its own `requester`, and that role holds scep:enrol.
chk "a missing SCEP credential is named, not benchmarked" yes \
    "$(grep -q 'no SCEP challengePassword' "$ROOT/demo/pki-bench.sh" && echo yes || echo no)"
chk "  and the live path reads it from the credentials endpoint" yes \
    "$(grep -q 'scep_challenge' "$ROOT/demo/pki-bench.sh" && echo yes || echo no)"

echo "=== A --target run says nothing about a Postgres it never opens ==="
# The headers the demo and the bench printed had no clear meaning or purpose to whoever
# ran them, so they were removed.
#
# The headers are the role diagnostic, and they are load-bearing FOR THE HARNESS — they
# closed a real report of a Postgres log full of authentication FATALs. What was wrong is
# WHERE they fired: pg_helpers.sh ends in pg_ensure_server, so merely SOURCING it probed
# 127.0.0.1:5432, created or upgraded the `fastpki` and `pki` databases on the operator's
# own Postgres, and printed the warning — while the demo was in `--target` mode, driving a
# live deployment, never opening a local database at all.
#
# ⚠️ THE ASSERTION IS THE DEMO'S OWN OUTPUT, not a grep for the flag. A demo that set
# FASTPKI_PG_AUTOSTART=0 and then reached a local Postgres by some other route would pass a
# grep and still print the headers at him. So: run the real script, in the mode he ran, with
# a role that CANNOT connect — the exact condition that produces the message — and read what
# comes out.
T312="$(mktemp -d)"
cat > "$T312/target.env" <<EOF
TARGET_HOST=127.0.0.1
DEMO_USER=demo312
DEMO_PASS=demo312
CA_ID=demo312
EST_PORT=1
CMP_PORT=1
OCSP_PORT=1
STORE_PORT=1
SCEP_PORT=1
ACME_PORT=1
WEB_PORT=1
EOF
# A role that does not exist, against the Postgres this suite has already proved is up.
# _pg_role_usable's branch 2 ("server UP, role unusable") is what prints the five lines.
BADROLE="fpki312_$$"
"$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAc \
    "select 1 from pg_roles where rolname='$BADROLE'" 2>/dev/null | grep -q 1 \
    && { echo "  [note] role $BADROLE unexpectedly exists — skipping the probe section"; BADROLE=; }
if [ -n "$BADROLE" ]; then
    for n in pki-demo pki-bench; do
        # Port 1 is closed, so every curl fails instantly and the demo exits within a second
        # or two. Its failure is expected and irrelevant here; only its OUTPUT is asserted.
        o312=$(cd "$ROOT" && PGUSER="$BADROLE" PGPASSWORD=x \
                 bash "demo/$n.sh" --target "$T312/target.env" 2>&1)
        chk "$n --target prints no pg_helpers header" 0 \
            "$(printf '%s\n' "$o312" | grep -c '^pg_helpers:' | tr -d ' ')"
        # ...and it must not have provisioned anything either. `fastpki`/`pki` are created by
        # _pg_ensure_databases, which the source-time call reached on every run.
        chk "  and creates no database"               no \
            "$(printf '%s\n' "$o312" | grep -q 'CREATE DATABASE' && echo yes || echo no)"
    done

    # The mechanism is KEPT, not deleted — a suite that sources the helpers still gets told.
    o312=$(cd "$ROOT" && PGUSER="$BADROLE" PGPASSWORD=x \
             bash -c 'source tests/pg_helpers.sh' 2>&1)
    chk "the harness still gets the role warning"     yes \
        "$(printf '%s\n' "$o312" | grep -q '^pg_helpers:' && echo yes || echo no)"

    # And suppressing the source-time call must not cost a caller its cluster: pg_setup
    # ensures one itself. Run with the WORKING role and prove a query answers.
    # pg_setup's own CREATE/DROP DATABASE chatter goes to STDOUT, so silence everything
    # except the query — the assertion is that a real statement answers, not that it is quiet.
    o312=$(cd "$ROOT" && FASTPKI_PG_AUTOSTART=0 bash -c \
             'source tests/pg_helpers.sh >/dev/null 2>&1
              pg_setup t312 >/dev/null 2>&1
              pg_exec "select 42"
              pg_cleanup >/dev/null 2>&1' 2>/dev/null)
    chk "pg_setup still reaches a cluster with autostart off" 42 "$(printf '%s' "$o312" | tr -d ' \n')"
fi
rm -rf "$T312"

# A live deployment's listener keys are its own configuration. The flag must REFUSE
# there rather than run and quietly change nothing — an accepted no-op reads as
# "my deployment ignores this setting".
# ⚠️ A REAL descriptor file, not a missing path. `--target /nonexistent` also exits 2 —
# from the missing-file check inside the live setup — so asserting on the exit code alone
# passes whether or not the refusal exists. Measured: with a real file the refusal exits 2
# and prints the reason; with the refusal removed the same command reaches the network and
# exits 1 with no such message. 127.0.0.1 has nothing listening, and the refusal fires
# before any connection is attempted.
TSK=$(mktemp -d)
printf 'TARGET_HOST=127.0.0.1\nDEMO_USER=demo\nDEMO_PASS=demo\n' > "$TSK/t.env"
OSKL=$(cd "$ROOT" && bash demo/pki-demo.sh --target "$TSK/t.env" --server-key ec 2>&1); rckl=$?
rm -rf "$TSK"
chk "--server-key is refused against a live target" 2   "$rckl"
chk "and the refusal says why"                      yes "$(has "$OSKL" 'need --throwaway')"


echo
echo "=== DEMO SCRIPTS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
