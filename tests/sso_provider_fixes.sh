#!/usr/bin/env bash
# Regression guards for four defects fixed together for the 0.1.0 release candidate.
# One suite on purpose (fast to run as a set); each section is independent and SKIPs
# cleanly when its prerequisite is absent. Self-contained (§3d) and shell-only (§3e).
#
#   1. saml_providers / oidc_providers replicate with a last-writer-wins trigger, so the
#      SAME provider id created on two data centers is ABSORBED, not a subscription-jamming
#      primary-key conflict. Contrast against ldap_providers, which always had the trigger.
#   2. Editing an LDAP directory preserves the stored krb_keytab (console) and both
#      krb_keytab and bind_pw (fastpki-config auth-providers-add re-run) — a field the form
#      cannot show must not be wiped by omission.
#   3. OIDC_* / SAML_* in the environment are IGNORED (SSO is provider rows now) AND the
#      web console says so at startup instead of coming up silently with no IdP.
#
# The fourth fix that shipped with these — the public-repo hygiene name gate catching a
# person's name spelled with a trailing letter — is guarded in tests/public_repo_hygiene.sh
# (its own home, and the only file exempt from that scan): asserting it here would mean
# embedding the very name literal the gate exists to reject, which would flag this file.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}; command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
WEB="$ROOT/build/fastpki-web"
CFG="$ROOT/build/fastpki-config"
MESH="$ROOT/build/fastpki-mesh"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# ⚠️ ONE CUMULATIVE EXIT TRAP, ARMED ONCE — bash EXIT TRAPS DO NOT STACK. A second
# `trap … EXIT` REPLACES the first, so a per-section trap silently drops whatever the
# previous one was responsible for, and an early exit then leaks it. This suite runs two
# independent sections, each starting its own servers, so every child, database and temp
# directory is torn down here. Each step is guarded to be a no-op when its section never
# ran, and nothing ever clears this trap.
W2=""; P=""; WR=""; PGBIN=""
cleanup(){
    [ -n "$P" ] && kill "$P" 2>/dev/null
    pg_cleanup >/dev/null 2>&1 || true
    if [ -n "$PGBIN" ] && [ -n "$WR" ]; then
        pg_as "$PGBIN/pg_ctl" -D "$WR/a" -m immediate stop >/dev/null 2>&1
        pg_as "$PGBIN/pg_ctl" -D "$WR/b" -m immediate stop >/dev/null 2>&1
    fi
    [ -n "$W2" ] && rm -rf "$W2"
    [ -n "$WR" ] && rm -rf "$WR"
    return 0
}
trap cleanup EXIT

# ============================================================================
echo "=== 2 & 3. provider edit keeps secrets; ignored SSO env is announced ==="
if ! "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c 'select 1' >/dev/null 2>&1; then
    echo "  SKIP: no Postgres reachable at $PGHOST:$PGPORT"
else
  pg_setup sso_fixes
  PORT=18492
  W2="$(mktemp -d)"
  cat > "$W2/web.conf" <<EOF
PG_CONNINFO=$PG_CONNINFO
WEB_BIND=127.0.0.1
WEB_PORT=$PORT
LOG_LEVEL=err
EOF
  # (3) OIDC_* deliberately set in the environment — the product must ignore them and warn.
  OIDC_ISSUER="https://accounts.google.com" OIDC_CLIENT_ID=fastpki OIDC_CLIENT_SECRET=envsecret \
    "$WEB" --config "$W2/web.conf" >"$W2/web.log" 2>&1 & P=$!
  # Poll the configured port, do not sleep at it (wait_conf, pg_helpers.sh).
  wait_conf "$W2/web.conf" WEB_PORT "$P" || true
  if ! kill -0 $P 2>/dev/null; then echo "  web failed to start:"; cat "$W2/web.log"; fail=$((fail+1)); else
    U="http://127.0.0.1:$PORT"
    curl -s -c "$W2/a.cj" -X POST "$U/api/users" -d 'username=admin&password=adminpw12&role=admin' >/dev/null
    curl -s -c "$W2/a.cj" -X POST "$U/api/login" -d 'username=admin&password=adminpw12' >/dev/null

    IDPS=$(curl -s "$U/api/auth-idps")
    chk "OIDC_* env produces no IdP" no "$(echo "$IDPS" | grep -q oidc && echo yes || echo no)"
    chk "startup warns that the ignored SSO env keys are read by nothing" yes \
        "$(grep -qE 'ignoring environment variables .*OIDC_ISSUER' "$W2/web.log" && echo yes || echo no)"

    # (2) console edit preserves the stored keytab; bind_pw's keep-logic also holds.
    curl -s -o /dev/null -b "$W2/a.cj" -X POST "$U/api/auth-providers" \
      --data-urlencode 'id=corp' --data-urlencode 'kind=ldap' \
      --data-urlencode 'uris=ldaps://dc1.corp' --data-urlencode 'base_dns=dc=corp,dc=example' \
      --data-urlencode 'bind_pw=s3cretpw'
    pg_exec "UPDATE ldap_providers SET krb_keytab='/var/pki/ms/corp.keytab' WHERE provider_id='corp';" >/dev/null
    curl -s -o /dev/null -b "$W2/a.cj" -X POST "$U/api/auth-providers" \
      --data-urlencode 'id=corp' --data-urlencode 'kind=ldap' \
      --data-urlencode 'uris=ldaps://dc1.corp' --data-urlencode 'base_dns=dc=corp,dc=example' \
      --data-urlencode 'display_name=Corp renamed'
    chk "console edit KEEPS krb_keytab" "/var/pki/ms/corp.keytab" \
        "$(pg_exec "SELECT krb_keytab FROM ldap_providers WHERE provider_id='corp';")"
    chk "console edit KEEPS bind_pw"     "s3cretpw" \
        "$(pg_exec "SELECT bind_pw FROM ldap_providers WHERE provider_id='corp';")"

    # (2) CLI re-run to change only --priority preserves BOTH.
    "$CFG" --config "$W2/web.conf" auth-providers-add corp \
        --uris ldaps://dc1.corp --base-dns 'dc=corp,dc=example' --priority 10 >/dev/null 2>&1
    chk "auth-providers-add re-run KEEPS krb_keytab" "/var/pki/ms/corp.keytab" \
        "$(pg_exec "SELECT krb_keytab FROM ldap_providers WHERE provider_id='corp';")"
    chk "auth-providers-add re-run KEEPS bind_pw"     "s3cretpw" \
        "$(pg_exec "SELECT bind_pw FROM ldap_providers WHERE provider_id='corp';")"
    chk "auth-providers-add re-run applied the change (priority=10)" "10" \
        "$(pg_exec "SELECT priority FROM auth_providers WHERE id='corp';")"
    kill $P 2>/dev/null; P=""
  fi
  pg_cleanup 2>/dev/null || true
fi

# ============================================================================
echo "=== 1. SSO provider PK conflict on two DCs is absorbed, not a subscription jam ==="
export LC_ALL=C
PGBIN=""
if command -v pg_ctl >/dev/null 2>&1; then PGBIN="$(dirname "$(command -v pg_ctl)")"
else PGBIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)"; fi
if [ -z "$PGBIN" ] || [ ! -x "$PGBIN/initdb" ]; then
  echo "  SKIP: Postgres server binaries (initdb/pg_ctl) not found"
else
  WR="$(mktemp -d)"; PA=16944; PB=16945
  # mktemp -d is 0700 and owned by whoever runs the suite; as root the dropped-privilege
  # server cannot create its data directory inside it. No-op unless we are root.
  pg_own "$WR"
  A(){ "$PGBIN/psql" -h 127.0.0.1 -p "$PA" -U postgres -d pki -tAc "$1" 2>&1; }
  B(){ "$PGBIN/psql" -h 127.0.0.1 -p "$PB" -U postgres -d pki -tAc "$1" 2>&1; }
  waitp(){ local port="$1" q="$2" want="$3" i; for i in $(seq 1 24); do [ "$("$PGBIN/psql" -h 127.0.0.1 -p "$port" -U postgres -d pki -tAc "$q" 2>&1)" = "$want" ] && { echo yes; return; }; sleep 0.5; done; echo no; }
  # ⚠️ Server binaries go through pg_as, never called raw. initdb and pg_ctl REFUSE to run
  # as root, so a raw call turns into a silent SKIP inside a green total the moment the
  # gate runs as a different user — the shape a census guard exists to catch.
  rnode(){
    pg_as "$PGBIN/initdb" -D "$1" -U postgres --auth=trust >/dev/null 2>&1
    { echo "wal_level=logical"; echo "max_wal_senders=10"; echo "max_replication_slots=10"; echo "listen_addresses='127.0.0.1'"; echo "port=$2"; echo "unix_socket_directories='$1'"; } >> "$1/postgresql.conf"
    pg_as "$PGBIN/pg_ctl" -D "$1" -l "$1/pg.log" start >/dev/null 2>&1
    local i; for i in $(seq 1 40); do "$PGBIN/pg_isready" -h 127.0.0.1 -p "$2" >/dev/null 2>&1 && break; sleep 0.5; done
    "$PGBIN/createdb" -h 127.0.0.1 -p "$2" -U postgres pki >/dev/null 2>&1
    "$PGBIN/psql" -h 127.0.0.1 -p "$2" -U postgres -d pki -f "$ROOT/sql/createdb.sql" >/dev/null 2>&1
  }
  rnode "$WR/a" "$PA"; rnode "$WR/b" "$PB"
  if ! "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PA" >/dev/null 2>&1 || ! "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PB" >/dev/null 2>&1; then
    echo "  SKIP: could not start the throwaway clusters"
  else
    cat > "$WR/topo.txt" <<EOF
node_a|host=127.0.0.1 port=$PA dbname=pki user=postgres|5|http://node_a.example
node_b|host=127.0.0.1 port=$PB dbname=pki user=postgres|6|http://node_b.example
EOF
    for p in $PA $PB; do "$MESH" --allow-plaintext-transport --topology "$WR/topo.txt" --publication | "$PGBIN/psql" -h 127.0.0.1 -p "$p" -U postgres -d pki >/dev/null 2>&1; done
    "$MESH" --allow-plaintext-transport --topology "$WR/topo.txt" --node node_a | "$PGBIN/psql" -h 127.0.0.1 -p "$PA" -U postgres -d pki >/dev/null 2>&1
    "$MESH" --allow-plaintext-transport --topology "$WR/topo.txt" --node node_b | "$PGBIN/psql" -h 127.0.0.1 -p "$PB" -U postgres -d pki >/dev/null 2>&1
    sleep 3
    # The fix: both SSO settings tables now carry the LWW pair, exactly like ldap_providers.
    for t in saml_providers oidc_providers; do
      chk "$t has the last-writer-wins trigger" "yes" \
          "$(A "select (count(*) filter (where tgname='${t}_lww'))>0 and (count(*) filter (where tgname='${t}_stamp'))>0 from pg_trigger where tgrelid='${t}'::regclass and not tgisinternal" | grep -qi t && echo yes || echo no)"
    done
    S1=$(printf '%04x%036s' 5 aa | tr ' ' 0)
    A "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$S1',0,'pre.internal',NULL);" >/dev/null
    [ "$(waitp "$PB" "select count(*) from certs where serial='$S1'" 1)" = yes ] || echo "  (note: baseline replication not confirmed)"
    # Poison: same provider id created independently on both sides during a partition.
    for s in $(B "select subname from pg_subscription"); do B "ALTER SUBSCRIPTION $s DISABLE" >/dev/null; done
    for s in $(A "select subname from pg_subscription"); do A "ALTER SUBSCRIPTION $s DISABLE" >/dev/null; done
    A "INSERT INTO auth_providers(id,kind,display_name,enabled,priority,created,updated) VALUES('sso','oidc','A',true,100,1,1);
       INSERT INTO oidc_providers(provider_id,issuer,client_id,client_secret) VALUES('sso','https://a','ca','sa');" >/dev/null
    B "INSERT INTO auth_providers(id,kind,display_name,enabled,priority,created,updated) VALUES('sso','oidc','B',true,100,2,2);
       INSERT INTO oidc_providers(provider_id,issuer,client_id,client_secret) VALUES('sso','https://b','cb','sb');" >/dev/null
    for s in $(B "select subname from pg_subscription"); do B "ALTER SUBSCRIPTION $s ENABLE" >/dev/null; done
    for s in $(A "select subname from pg_subscription"); do A "ALTER SUBSCRIPTION $s ENABLE" >/dev/null; done
    sleep 6
    S2=$(printf '%04x%036s' 5 ac | tr ' ' 0)
    A "INSERT INTO certs(serial,status,cn,ca_instance_id) VALUES('$S2',0,'post.internal',NULL);" >/dev/null
    chk "replication SURVIVES the SSO provider conflict (cert still flows A->B)" yes "$(waitp "$PB" "select count(*) from certs where serial='$S2'" 1)"
    chk "no apply error accumulated on the subscriber" "0" "$(B "select coalesce(sum(apply_error_count),0) from pg_stat_subscription_stats")"
    chk "the conflicting oidc row converged to one row" "1" "$(B "select count(*) from oidc_providers where provider_id='sso'")"
  fi
  # Tear the clusters down now rather than at exit, so the ports are free immediately —
  # but leave the EXIT trap armed: it is what covers an early exit, and clearing it here
  # is exactly the drop this suite was rewritten to avoid. cleanup is idempotent.
  cleanup
fi

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || { echo "FAIL=$fail"; exit 1; }
