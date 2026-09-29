#!/usr/bin/env bash
# The shipped clients demo actually issues certificates — by RUNNING it.
#
# ⚠️ THIS SUITE NEEDS DOCKER, which is why it is its own tier (RUN_DEMO=1) and runs on a
# host rather than in the production image. Throwaway mode stages a docker compose project
# — postgres, token and every protocol service — and the test container has no docker and
# must not be given the host socket. Everything that only READS the demo and bench scripts
# moved to tests/demo_scripts.sh, which needs nothing and runs in the container gate.
#
# ⚠️ THE PER-PROTOCOL ASSERTIONS ARE NOT REDUNDANT WITH THE EXIT STATUS, and it is tempting
# to think they are now that the demo has its own verdict and a full key/hash matrix. The
# demo's skip() does NOT increment DEMO_FAIL, so a run in which EST silently skipped still
# exits 0 and prints no failure. These assert the artifact was decoded back out, which is
# the only thing that separates "it worked" from "it did not run".
#
# demo/pki-demo.sh is a deliverable — the thing someone runs to see FastPKI
# work — and it was BROKEN for weeks without anyone noticing, because nothing ran it.
# It configured its CA with SIGNING_CA_PEM/SIGNING_CA_KEY, which are gone, and
# unknown config keys are silently ignored, so all five daemons started with no CA:
# EST 404'd, CMP and the store failed, SCEP skipped itself. 4 of 6 steps failed.
#
# A grep can't catch that. So this suite runs the real demo and requires it to
# succeed — the demo already exits non-zero and prints "N step(s) failed", so the
# assertion is simply that the shipped script works.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# §3d: the default path is a Linux convention and does not exist on every dev box.
# Without this the suite still RUNS — every "$OSSL" call just fails silently and each
# assertion compares against an empty string, which reads as a product bug.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}

pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
has(){ grep -q "$2" <<<"$1" && echo yes || echo no; }

[ -x "$ROOT/build/fastpki-est" ] || { echo "SKIP: no build/fastpki-est"; exit 0; }
"$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'SELECT 1' >/dev/null 2>&1 \
  || { echo "SKIP: no Postgres at $PGHOST:$PGPORT"; exit 0; }

before=$("$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAq \
          -c "SELECT count(*) FROM pg_database;" 2>/dev/null | tr -d ' ')

# --no-acme: the ACME leg needs a DNS responder port and is covered by acme_*.sh.
# ⚠️ --quick: throwaway now runs the full key/hash matrix by default; this suite's
# matrix coverage lives in the sweeps it asserts on below, so trim to one rep per
# family and keep the suite inside minutes.
# ⚠️ --throwaway is EXPLICIT. Live is the demo's default — the point of a demo
# is to run against the live deployment rather than a throwaway database — and a test
# harness has no deployment to point at. Without this flag the run
# would pick up a developer's demo/.target.env and drive their REAL lab.
OUT=$(cd "$ROOT" && OSSL="$OSSL" bash demo/pki-demo.sh --throwaway --no-acme --quick 2>&1); rc=$?

echo "=== the demo runs clean ==="
chk "exit status is 0"                     0   "$rc"
chk "no step reported a failure"           no  "$(has "$OUT" 'step(s) failed')"
[ "$rc" -eq 0 ] || printf '%s\n' "$OUT" | sed 's/^/         /'

echo "=== each protocol really issued or retrieved something ==="
# Assert on the demo's own decoded output, not on exit codes: every one of these
# lines is printed only after the artifact was parsed back out.
chk "EST issued a cert"    yes "$(has "$OUT" 'issued: subject=CN=est-client.internal')"
chk "CMP issued a cert"    yes "$(has "$OUT" 'issued: subject=CN=cmp-client.internal')"
chk "SCEP issued a cert"   yes "$(has "$OUT" 'issued: subject=CN=scep-client.internal')"
chk "OCSP said good"       yes "$(has "$OUT" 'status: good')"
chk "OCSP said revoked"    yes "$(has "$OUT" 'status: revoked')"
chk "the store found it"   yes "$(has "$OUT" 'retrieved: CN=scep-client.internal')"

echo "=== and it cleans up after itself ==="
after=$("$_PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -tAq \
         -c "SELECT count(*) FROM pg_database;" 2>/dev/null | tr -d ' ')
chk "no throwaway database left behind"    "$before" "$after"
# ── the server-credential axis ──────────────────────────────────────────────────
# The demo can run its whole client sequence against a listener whose OWN key is of a
# chosen type, which is the point: a client sees no difference. Four ways that went
# wrong while it was built, every one of them leaving a green run behind:
#
#   1. the helpers were defined BELOW their call sites, so both calls were
#      "command not found" — and the demo still exited 0, because everything
#      downstream passes whatever key the listener holds;
#   2. the port lives in a `local` inside the setup function, so reading it at the
#      call site found an unset name and the whole step returned quietly;
#   3. the demo PRE-GENERATES an RSA-2048 certificate for EST, and a listener adopts a
#      certificate that already exists rather than minting one — so the requested key
#      was ignored and the served cert was the pre-generated one;
#   4. `run_bounded` was likewise defined below, so the probe could not run.
#
# What every one of those has in common is that the flag was INERT and nothing said so.
# Hence: assert the step RAN, and assert the served key is the REQUESTED one — not
# merely that the demo exited 0.
#
# rsa:3072 on purpose: it differs from the shipped default (ec/P-256), so a served
# `rsaEncryption` cannot come from the default path, and every TLS client can talk to
# it — so the EST leg really runs instead of skipping.
OSK=$(cd "$ROOT" && OSSL="$OSSL" bash demo/pki-demo.sh --throwaway --no-acme --quick \
        --server-key rsa:3072 2>&1); rck=$?
chk "demo --server-key run succeeds"                0   "$rck"
chk "the listener certificate step ran"             yes "$(has "$OSK" 'EST listener certificate')"
chk "no helper was called before it was defined"    no  "$(has "$OSK" 'command not found')"
chk "the listener served the REQUESTED key"         yes "$(has "$OSK" 'key: *rsaEncryption (3072 bit)')"
chk "and not the ec default"                        no  "$(has "$OSK" 'key: *id-ecPublicKey')"
# The requested key must reach the ISSUED artifact path too, not just the report: with a
# 3072-bit RSA listener the EST enrolment has to complete over that handshake.
chk "EST still enrols across the changed listener"  yes "$(has "$OSK" 'issued: subject=CN=est-client')"


echo
echo "=== DEMO CLIENTS: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
