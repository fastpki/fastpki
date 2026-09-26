#!/usr/bin/env bash
# Every config key we ship or document is a key the parser actually reads.
#
# `apply()` in src/lib/config.cpp is an if/else-if chain with no final `else`, so an
# unrecognised key is SILENTLY IGNORED. That is why dead keys survive removals: the
# example config kept advertising SIGNING_CA_PEM, SIGNING_CA_KEY, SIGNING_CA_DER,
# USERS_FILE, DOMAINS_FILE and SQL_DB long after each was deleted, and nothing ever
# complained — an operator who copied it got a file that looked configured and wasn't.
# The clients demo copied the same shape and quietly stopped issuing certificates.
#
# The two directions are different failures, so both are asserted:
#   shipped/documented but not parsed -> a lie the operator acts on
#   parsed but not documented         -> a feature nobody can find
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
CONFIG_CPP="$ROOT/src/lib/config.cpp"
EXAMPLE="$ROOT/config/bootstrap.conf.example"
REFERENCE="$ROOT/docs/config-reference.md"

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

for f in "$CONFIG_CPP" "$EXAMPLE" "$REFERENCE"; do
    [ -f "$f" ] || { echo "SKIP: missing $f"; exit 0; }
done

# The keys apply() compares against. This is the authority: it is the code that runs.
grep -o 'key == "[A-Z0-9_]*"' "$CONFIG_CPP" | sed 's/.*"\(.*\)"/\1/' | sort -u > "$W/parsed"

# Keys the shipped example actually SETS (uncommented assignments only — a commented
# line is prose, and prose is checked against the reference table instead).
grep -oE '^[A-Z][A-Z0-9_]*=' "$EXAMPLE" | tr -d '=' | sort -u > "$W/example"

# Keys the reference table documents: leading `| \`KEY\` |` cells.
grep -oE '^\| *`[A-Z][A-Z0-9_]*`' "$REFERENCE" | tr -d '|` ' | sort -u > "$W/documented"

# ⚠️ AND THE KEYS A SCHEMA STEP READS OUT OF THE `config` TABLE. A step that carries an
# operator's setting forward names the key in SQL, where no compiler and no config parser
# will ever look at it — so a key that does not exist reads as NULL, coalesce() substitutes
# the default, and the setting is lost with nothing said. Caught exactly that way: a step
# written here read LDAP_CA_CERT_FILE and LDAP_NETWORK_TIMEOUT_SEC, and the parser spells
# them LDAP_CA_CERT and LDAP_TIMEOUT_SEC.
#
# Matched on `key = '<NAME>'` because that is how a step asks the config table, and the
# quoting is SQL's rather than C++'s — the pattern above cannot see these.
grep -rhoE "key = '[A-Z][A-Z0-9_]*'" "$ROOT/sql/steps" 2>/dev/null \
    | sed "s/.*'\(.*\)'/\1/" | sort -u > "$W/steps"

echo "=== parsed=$(wc -l < "$W/parsed" | tr -d ' ')" \
     "example=$(wc -l < "$W/example" | tr -d ' ')" \
     "documented=$(wc -l < "$W/documented" | tr -d ' ')" \
     "read-by-steps=$(wc -l < "$W/steps" | tr -d ' ') ==="

# These assertions apply to the steps in sql/steps, which carry a database created by an
# earlier release forward. They must not report a pass over an empty set.
if [ -d "$ROOT/sql/steps" ] && ls "$ROOT/sql/steps"/[0-9]*.sql >/dev/null 2>&1; then
  # ⚠️ A CARRY-OVER STEP READS A KEY THAT IS BEING RETIRED — THAT IS ITS JOB. The first
  # version of this assertion said "every key a step reads must be one the parser writes",
  # which is right for a typo and WRONG for the one legitimate case: a step whose purpose is
  # to move an operator's old setting somewhere else reads it out of the `config` TABLE of an
  # upgraded database, where the row still exists precisely because the parser has stopped
  # knowing the key. Step 0034 does exactly that for the LDAP_* keys.
  #
  # So a retired key is allowed if the step DECLARES it, `-- CARRY-OVER KEY: NAME`. That
  # keeps the whole value of the check — a typo is a name nobody declared — while a
  # deliberate carry-over has to be written down twice and is visible in the file.
  grep -rhoE "CARRY-OVER KEY: [A-Z][A-Z0-9_]*" "$ROOT/sql/steps" 2>/dev/null \
      | sed 's/.*: //' | sort -u > "$W/carryover"
  comm -23 "$W/steps" "$W/parsed" | comm -23 - "$W/carryover" > "$W/step_unknown"
  chk "every config key a schema step reads is parsed, or declared a carry-over" "" \
      "$(tr '\n' ' ' < "$W/step_unknown" | sed 's/ $//')"
  # Anti-vacuity: the exemption must not be able to swallow everything. A declared key has to
  # be one a step actually reads, or the list is just prose.
  chk "  PRECONDITION: every declared carry-over key is really read by a step" "" \
      "$(comm -13 "$W/steps" "$W/carryover" | tr '\n' ' ' | sed 's/ $//')"
  # Anti-vacuity: a step that reads the config table and yields no key means the pattern rotted; a step
  # that never touches the table (0002 only creates tables) has nothing to find.
  if grep -rqiE "from +config([^_a-z]|$)" "$ROOT/sql/steps"; then
    chk "  PRECONDITION: the step scan found keys at all" yes \
        "$([ -s "$W/steps" ] && echo yes || echo no)"
  fi
else
  chk "no schema step exists, so none can read a retired config key" yes \
      "$([ ! -d "$ROOT/sql/steps" ] && echo yes || echo no)"
fi

echo "=== the shipped example config sets only keys that exist ==="
comm -13 "$W/parsed" "$W/example" > "$W/dead_example"
[ -s "$W/dead_example" ] && sed 's/^/         dead: /' "$W/dead_example"
chk "no dead key in config/bootstrap.conf.example" 0 "$(wc -l < "$W/dead_example" | tr -d ' ')"

echo "=== the config reference documents only keys that exist ==="
comm -13 "$W/parsed" "$W/documented" > "$W/dead_doc"
[ -s "$W/dead_doc" ] && sed 's/^/         dead: /' "$W/dead_doc"
chk "no dead key in docs/config-reference.md" 0 "$(wc -l < "$W/dead_doc" | tr -d ' ')"

echo "=== every key the parser reads is documented ==="
comm -23 "$W/parsed" "$W/documented" > "$W/undocumented"
[ -s "$W/undocumented" ] && sed 's/^/         undocumented: /' "$W/undocumented"
chk "no undocumented key in config.cpp" 0 "$(wc -l < "$W/undocumented" | tr -d ' ')"

echo "=== keys deleted by a shipped change stay deleted ==="
# Named explicitly: each was removed by a ticket, and each was still being shipped or
# documented afterwards. A regression here means a removal got half-reverted.
# ROOT_CA_PEM/ROOT_CA_KEY joined this list later. They were the last file-shaped hole
# in the CA model: ROOT_CA_PEM synthesised an `active` CA row called `root` that no
# service could resolve, and ROOT_CA_KEY put a PATH in its signing-key field — which
# load_signing_key has refused since CA keys became token-only. The anchor is a `certs`
# row now and the chain to it is walked in the database.
for k in SIGNING_CA_PEM SIGNING_CA_KEY SIGNING_CA_DER SIGNING_CA_ID USERS_FILE DOMAINS_FILE SQL_DB SQLITE_DB \
         ROOT_CA_PEM ROOT_CA_KEY; do
    chk "$k is not parsed"     no "$(grep -qx "$k" "$W/parsed"     && echo yes || echo no)"
    chk "$k is not shipped"    no "$(grep -qx "$k" "$W/example"    && echo yes || echo no)"
    chk "$k is not documented" no "$(grep -qx "$k" "$W/documented" && echo yes || echo no)"
done

echo "=== the console offers no transport role that nothing reads ==="
# The mirror of everything above, and the same silent failure. The Inventory "Serve as"
# picker writes `certs.cert_id`, which a listener reads back to find its transport
# certificate. It used to offer `store` (STORE_CERT_ID) and `scep` (SCEP_CERT_ID) — and
# NEITHER key exists anywhere in the product: the certstore builds a plain httplib::Server
# with no TLS at all, and SCEP takes its RA key from SCEP_RA_KEY (the certificate is per
# CA in the DB under SCEP_RA_CERT_ID_PREFIX).
# Picking one issued a certificate, reported success, tagged it for a listener that never
# reads the tag, and nothing happened. An operator has no way to tell that apart from a
# working configuration.
#
# So: every value the picker offers must be backed by a real <NAME>_CERT_ID key, with
# `cmp-ra` mapping to CMP_RA_CERT_ID_PREFIX (CMP consumes it as an RA credential rather than through
# resolve_transport_cert, which is why it is spelled differently).
WEB_CPP="$ROOT/src/web/main.cpp"
sed -n '/Serve as<\/label><select name="cert_id"/,/<\/select>/p' "$WEB_CPP" \
  | grep -o '<option value="[a-z-]*"' | sed 's/.*value="//; s/"//' | grep -v '^$' > "$W/serveas"
chk "the Serve-as options were parsed" yes \
    "$([ -s "$W/serveas" ] && echo yes || echo no)"
while read -r v; do
    [ -n "$v" ] || continue
    # ⚠️ SIXTH hardcoded list of builtin ids. The three SERVICE CREDENTIALS (cmp-ra,
    # ocsp-ra, scep-ra) are consumed directly rather than through
    # resolve_transport_cert, and their settings are cert_id PREFIXES — the
    # asked: "if you silently changed them to prefixes, then why didn't you reflect
    # this change in their names? And could we please be consistent?" So all three are
    # spelled <ROLE>_CERT_ID_PREFIX, and only the transport listeners take the generic
    # <option>_CERT_ID. scep-ra used to fall through to that generic rule and therefore
    # asserted against a key that no longer exists.
    # Adding a purpose without adding it here fails LOUDLY, which is what this list is for.
    case "$v" in
        cmp-ra)  key=CMP_RA_CERT_ID_PREFIX ;;
        ocsp-ra) key=OCSP_RESPONDER_CERT_ID_PREFIX ;;
        scep-ra) key=SCEP_RA_CERT_ID_PREFIX ;;
        *)       key="$(printf '%s' "$v" | tr 'a-z-' 'A-Z_')_CERT_ID" ;;
    esac
    chk "Serve-as '$v' is backed by $key" yes \
        "$(grep -q "\"$key\"" "$ROOT/src/lib/config.cpp" && echo yes || echo no)"
done < "$W/serveas"
# Named, so a well-meaning re-add is caught rather than debated.
for dead in STORE_CERT_ID SCEP_CERT_ID; do
    chk "$dead is still not a config key" no \
        "$(grep -q "\"$dead\"" "$ROOT/src/lib/config.cpp" && echo yes || echo no)"
done

echo "=== No SHIPPED config file may set a key to an EMPTY value ==="
# ⚠️ THIS IS A VALUE CHECK, AND EVERY OTHER GUARD HERE CHECKS NAMES. That is exactly why
# the bug survived: `CMP_CLIENT_CA_ID=` was a perfectly legitimate key, spelled correctly,
# parsed correctly, documented correctly — and its VALUE was the defect.
#
# Config::load() seeds from the environment and THEN parses the file, calling apply() for
# every key present; the env-wins skip covers only PG_CONNINFO (is_bootstrap_config_key).
# So a shipped key with no value silently ERASES what the deployment set in its
# environment. Measured on the lab: `.env` had CMP_CLIENT_CA_ID=labroot, the container
# environment carried it, this file blanked it, fastpki-cmp ended up with zero client-CA
# trust anchors, and every signature-protected CMP request — including revocation — was
# refused. Nothing in any log named the cause, because the skip branches never ran.
#
# A key with no value is not a setting. Comment it out and show the shape instead.
for f in "$ROOT/deploy/bootstrap.compose.conf" "$ROOT/config/bootstrap.conf.example"; do
    [ -f "$f" ] || continue
    EMPTY=$(grep -nE '^[A-Z][A-Z0-9_]*=[[:space:]]*$' "$f" | tr '\n' ' ')
    chk "$(basename "$f") sets no key to an empty value" "" "$EMPTY"
done

echo "=== The example config is BAKED AS THE LIVE CONFIG, so its values are defaults ==="
# ⚠️ Dockerfile: `COPY --from=build /src/config/bootstrap.conf.example /app/config/bootstrap.conf`.
# Anyone running the image without mounting their own config runs THIS FILE. So a value
# here is not documentation — it is what that deployment gets, and it OVERRIDES the
# compiled default in include/pki/config.hpp.
#
# That is how the GUID work half-shipped. MS_XCEP_FRIENDLY_NAME was to become
# "FastPKI Certificate Enrollment Policy"; the compiled default was changed and reported as
# done, while this file went on setting the old name. The lab happened to be unaffected
# (deploy/bootstrap.compose.conf is mounted over it and does not set the key), so every test and
# every live check agreed with us — and a bare-image deployment would still have advertised
# the old name to Windows.
#
# ⚠️ AND EVERY OTHER NAME-BASED GUARD IS BLIND TO IT. The key exists, is spelled correctly,
# is parsed and is documented; only its VALUE is wrong. Same shape as the check above.
#
# So: where the parser maps a key to a std::string member with a compiled default, the
# example must agree with that default. A key that SHOULD differ goes in the allowlist
# below with its reason — deliberately, not by silence.
# Deliberate divergences, each with its reason. The point of this check is not to forbid
# a difference — it is to make every difference a DECISION rather than an oversight.
#   LOG_LEVEL  example is deliberately chattier ('info') than the shipped default ('err').
#   PKI_DNS    the compiled default is the placeholder `pki.example.org`, which resolves
#              nowhere; a bare image run locally is better served by `localhost`. Every
#              real deployment must set its own: leaving it unset once produced four separate
#              "bugs" on the lab — wrong Endpoints page, an unusable CMP client config,
#              unreachable AIA/CRLDP in every issued cert, and a demo that hung on CRL fetch.
ALLOW_DIFF="LOG_LEVEL PKI_DNS"
# key -> member, from the parse table that actually runs
sed -n 's/.*key == "\([A-Z0-9_]*\)"[^c]*c\.\([a-z0-9_]*\) *=.*/\1 \2/p' "$CONFIG_CPP" | sort -u > "$W/k2m"
# member -> compiled default, only std::string members with a literal initialiser
sed -n 's/.*std::string  *\([a-z0-9_]*\){"\([^"]*\)"}.*/\1 \2/p' "$ROOT/include/pki/config.hpp" > "$W/m2d"
: > "$W/valdiff"
while read -r key member; do
    case " $ALLOW_DIFF " in *" $key "*) continue;; esac
    # the compiled default for this member, if it has a string literal one
    dflt=$(awk -v m="$member" '$1==m {sub($1" ",""); print; exit}' "$W/m2d")
    grep -q "^$member " "$W/m2d" || continue
    # the example's value: strip an inline comment and surrounding blanks, exactly as
    # Config::load() does (it erases from '#' and trims).
    line=$(grep -m1 "^$key=" "$EXAMPLE") || continue
    val=${line#*=}; val=${val%%#*}
    val=$(printf '%s' "$val" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [ "$val" = "$dflt" ] || printf '%s (example=%s compiled=%s)\n' "$key" "$val" "$dflt" >> "$W/valdiff"
done < "$W/k2m"
chk "no example value contradicts its compiled default" "" "$(tr '\n' ' ' < "$W/valdiff" | sed 's/ *$//')"

echo "=== the two shipped configs must agree on WHERE A PRIVATE KEY LIVES ==="
# ⚠️ A PAIRING, AND NOTHING GUARDED IT. There are two shipped configs — the one compose
# mounts, and the one the image bakes in as the live /app/config/bootstrap.conf. They are edited
# at different times for different reasons, and they drifted: compose put every listener
# key in the token while the baked-in file still pointed the HTTPS listeners at
# /etc/ssl/*.key paths and left the whole PKCS#11 block commented out. Two shipped configs
# describing two different products, and every test passed, because the lab mounts the
# compose one and never sees the other.
#
# The rule is not "no key may be a file" — a transport key legitimately accepts a path,
# unlike a CA key. The rule is that the two files must not DISAGREE: wherever compose has
# decided a key lives in the token, the baked-in default must not quietly choose a file.
#
# Compared by VALUE SHAPE rather than by key name, so a listener added tomorrow is covered
# the day it appears in compose.
: > "$W/keydrift"
grep -E '^[A-Z][A-Z0-9_]*_KEY=pkcs11:' "$ROOT/deploy/bootstrap.compose.conf" 2>/dev/null \
  | cut -d= -f1 | while read -r k; do
    ev=$(grep -m1 "^$k=" "$EXAMPLE" 2>/dev/null) || continue
    ev=${ev#*=}
    case "$ev" in
      pkcs11:*) ;;                                    # agrees
      "")       ;;                                    # not set: compiled default applies
      *) printf '%s (compose=token example=%s)\n' "$k" "$ev" >> "$W/keydrift" ;;
    esac
done
chk "no listener key is a token in one shipped config and a file in the other" "" \
    "$(tr '\n' ' ' < "$W/keydrift" | sed 's/ *$//')"
# Anti-vacuity: the loop above does nothing if the pattern stops matching, and an empty
# input would make the assertion above pass forever. Require it to still find keys.
chk "  and the pattern still finds token-backed keys to compare" yes \
    "$([ "$(grep -cE '^[A-Z][A-Z0-9_]*_KEY=pkcs11:' "$ROOT/deploy/bootstrap.compose.conf" 2>/dev/null)" -ge 3 ] \
       && echo yes || echo no)"

echo "=== a shipped config must not restate a value the code already defaults to ==="
# A key whose value EQUALS the compiled-in default teaches the reader nothing and hides the
# few keys that are real choices. The compose config carried 31 of them — every port, every
# bind but one, every path — so the handful that actually mattered were indistinguishable
# from the noise around them.
#
# ⚠️ AND THE OBVIOUS SIMPLIFICATION IS WRONG. "The config table overrides the file, so the
# file can be emptied" does not follow: the overlay wins only where a ROW EXISTS, so
# deleting a key hands it to the default rather than to the table. That is why this asserts
# equality with the default instead of merely counting keys.
#
# DERIVED, NOT LISTED. The key->field map comes from apply() and the defaults from the
# struct, so a default changed in the code changes what this test demands. A hardcoded list
# of "redundant keys" would rot the first time somebody edited a default.
DEFAULTS="$W/defaults"
grep -oE 'key == "[A-Z0-9_]+"[^;]*c\.[a-z0-9_]+ *=' "$CONFIG_CPP" \
  | sed -E 's/key == "([A-Z0-9_]+)".*c\.([a-z0-9_]+) *=/\1 \2/' | sort -u > "$W/k2f"
grep -oE '(std::string|int|long|bool|unsigned|size_t) +[a-z0-9_]+\{[^}]*\}' "$ROOT/include/pki/config.hpp" \
  | sed -E 's/^[a-z:_]+ +([a-z0-9_]+)\{"?([^"}]*)"?\}$/\1 \2/' | sort -u > "$W/f2d"
awk 'NR==FNR{d[$1]=substr($0, index($0," ")+1); next}
     ($2 in d){print $1 "\t" d[$2]}' "$W/f2d" "$W/k2f" > "$DEFAULTS"
chk "the key->default map was derived from the code" yes \
    "$([ "$(wc -l < "$DEFAULTS" | tr -d ' ')" -ge 20 ] && echo yes || echo no)"

# ⚠️ EXEMPTIONS ARE NARROW AND EACH HAS A REASON. An exemption that fires for the wrong key
# is the same class of bug as the redundancy it permits, so this is a fixed set, not a
# pattern:
#   WEB_BIND      the ONE listener whose default is loopback while every other is 0.0.0.0 —
#                 removing it binds the console inside its container and the published port
#                 answers nothing, silently.
#   AUTH_BACKEND  pinned by a separate guard, written after this file shipped a value that
#                 made any username with any password receive a certificate.
#   *_KEY         where a deployment's private keys live must not be inherited from a
#                 constant in the source.
#   PKCS11_TOKEN  paired with PKCS11_PIN_FILE, which has no default; splitting the pair
#                 would leave half a statement.
#   *_CERT_ID     same reason as *_KEY: which stored certificate a listener serves is part
#                 of what a deployment IS, not something to inherit from a constant.
exempt(){ case "$1" in WEB_BIND|AUTH_BACKEND|PKCS11_TOKEN|*_KEY|*_CERT_ID) return 0 ;; *) return 1 ;; esac; }
for conf in "$ROOT/deploy/bootstrap.compose.conf" "$EXAMPLE"; do
    [ -f "$conf" ] || continue
    redundant=""
    while IFS= read -r line; do
        case "$line" in [A-Z]*=*) ;; *) continue ;; esac
        k=${line%%=*}; v=${line#*=}
        exempt "$k" && continue
        d=$(awk -F'\t' -v k="$k" '$1==k{print $2; exit}' "$DEFAULTS")
        [ -n "$d" ] || continue
        [ "$v" = "$d" ] && redundant="$redundant $k"
    done < "$conf"
    chk "$(basename "$conf") states no value the code already defaults to" "" "$redundant"
done

# ── the environment allow-list is a SET, and both docs claimed the wrong one ──────────
#
# Config::from_env() reads a fixed list of keys. A key outside it can only come from the
# file or the DB `config` table -- and setting it in the environment does nothing AND
# raises no unknown-key error, because the parser that would object never sees it. That
# silence is why the documentation drifted unnoticed in two directions at once:
# docs/deployment.md said "every key can also be an environment variable" and
# docs/config-reference.md said "all 160 keys except these 6". The real answer is 24
# file/DB-only keys out of 138, and nothing compared either list against the code.
#
# Derive the set here rather than restating it: any key apply() knows and from_env() does
# not must appear in BOTH documents, so a new one cannot be added in silence again.
ENVK="$W/env_keys"; ALLK="$W/all_keys"; ONLYF="$W/file_only"
awk '/Config Config::from_env|Config from_env/,/^}/' "$ROOT/src/lib/config.cpp" \
    | grep -oE '"[A-Z][A-Z0-9_]+"' | tr -d '"' | sort -u > "$ENVK"
grep -oE 'key == "[A-Z][A-Z0-9_]+"' "$ROOT/src/lib/config.cpp" \
    | grep -oE '"[A-Z0-9_]+"' | tr -d '"' | sort -u > "$ALLK"
comm -23 "$ALLK" "$ENVK" > "$ONLYF"
chk "from_env() is a strict subset of the keys apply() parses" "" \
    "$(comm -13 "$ALLK" "$ENVK" | tr '\n' ' ' | sed 's/ *$//')"
for doc in "$ROOT/docs/deployment.md" "$ROOT/docs/config-reference.md"; do
    missing=""
    while IFS= read -r k; do
        [ -n "$k" ] || continue
        grep -q -- "$k" "$doc" || missing="$missing $k"
    done < "$ONLYF"
    chk "$(basename "$doc") names every file/DB-only key" "" "$missing"
done
# ⚠️ AND THE LISTS AND COUNTS THEMSELVES. "Names every key" was checked by grepping the
# whole guide, so a key named anywhere else in it passed while missing from the list: both
# lists lacked LICENSE, LICENSE_FILE or OCSP_RESPONDER_KEYS_REPLICATED, and the stated totals
# (122 of 154, 32, 34) had drifted from the code, with nothing failing. Compare the list
# blocks and the numbers directly.
N_ALL=$(wc -l < "$ALLK" | tr -d ' '); N_ENV=$(wc -l < "$ENVK" | tr -d ' ')
N_ONLY=$(wc -l < "$ONLYF" | tr -d ' ')
CR="$ROOT/docs/config-reference.md"; DP="$ROOT/docs/deployment.md"
chk "config-reference.md states '$N_ENV of the $N_ALL'" yes \
    "$(grep -q "— $N_ENV of the $N_ALL the" "$CR" && echo yes || echo no)"
chk "config-reference.md states '**$N_ONLY** are file- or DB-only'" yes \
    "$(grep -q "These \*\*$N_ONLY\*\* are file- or DB-only" "$CR" && echo yes || echo no)"
chk "deployment.md states 'all $N_ALL' and '$N_ENV of the $N_ALL'" yes \
    "$(grep -q "all $N_ALL of them" "$DP" && grep -q "$N_ENV of the $N_ALL" "$DP" && echo yes || echo no)"
chk "deployment.md states 'Only those $N_ENV' and 'These $N_ONLY have'" yes \
    "$(grep -q "Only those $N_ENV settings" "$DP" && grep -q "These $N_ONLY have to go" "$DP" && echo yes || echo no)"
CR_LIST=$(awk '/are file- or DB-only:/{f=1;next} f&&/^⚠️/{exit} f' "$CR" | grep -oE '`[A-Z][A-Z0-9_]+`' | tr -d '`' | sort -u)
DP_LIST=$(awk '/These [0-9]+ have to go in the file/{s=1} s&&/^```$/{if(f){exit} f=1;next} f' "$DP" | grep -oE '[A-Z][A-Z0-9_]+' | sort -u)
chk "config-reference.md's list is exactly the file/DB-only set" "" \
    "$(printf '%s\n' "$CR_LIST" | diff - "$ONLYF" | grep '^[<>]' | tr '\n' ' ' | sed 's/ *$//')"
chk "deployment.md's list is exactly the file/DB-only set" "" \
    "$(printf '%s\n' "$DP_LIST" | diff - "$ONLYF" | grep '^[<>]' | tr '\n' ' ' | sed 's/ *$//')"
# And neither may still carry the claim that was wrong.
for doc in "$ROOT/docs/deployment.md" "$ROOT/docs/config-reference.md"; do
    chk "$(basename "$doc") does not claim every key is an env var" "" \
        "$(grep -oE 'Every key can also be|All [0-9]+ keys can be set via environment' "$doc" | head -1)"
done

# ── an ERROR MESSAGE may not name a config key that does not exist ────────────────────
#
# ⚠️ THIS IS THE GAP THAT LET A DEAD KEY GO ON BEING ADVERTISED. The checks above prove
# every SHIPPED and DOCUMENTED key is real. Nothing proved it of the keys named in the
# product's own error strings — and those are the ones an operator actually acts on,
# because they arrive at the moment something is broken.
#
# The ten LDAP_* keys were deleted when a directory became a row, but six messages in
# ldap_auth.cpp went on telling operators to "set LDAP_BIND_DN and LDAP_BIND_PW". Those
# strings surface in the console as the directory search error, so importing users or
# groups from a directory with no service account instructed the operator to set two
# variables the parser does not know, in a file that is no longer read. Reported from a
# live deployment, not by any suite.
#
# ⚠️ ONLY STRINGS THAT TELL THE OPERATOR TO SET SOMETHING. Naming a dead key is not always
# wrong: src/web/main.cpp warns at startup when a stale config still carries OIDC_ISSUER or
# SAML_IDP_SSO_URL, which is the RIGHT thing to do — the operator can still possess such a
# file and needs to know it configures nothing. What must never happen is INSTRUCTING
# someone to set a key that does not exist. So the scan looks only inside strings that say
# "set" or "configure", which is exactly the harmful shape and leaves the warn-lists alone.
#
# Restricted further to tokens carrying one of our own prefixes, so OpenLDAP's LDAP_OPT_*
# and LDAP_SCOPE_*, OpenSSL's OCSP_BASICRESP_*, SOFTHSM2_CONF and P11_KIT_* stay out.
echo "=== no error message tells an operator to set a config key that does not exist ==="
PREFIXES='LDAP_|OIDC_|SAML_|KRB_|CMP_|EST_|ACME_|SCEP_|MS_|OCSP_|CRL_|WEB_|AUTH_|NOTIFY_|LOGIN_|SESSION_|PROFILE_|BACKUP_'
grep -rhoE "\"[^\"]*([Ss]et|[Cc]onfigure)[^\"]*\"" "$ROOT/src" 2>/dev/null \
  | grep -oE "\\b(${PREFIXES})[A-Z0-9_]+" | sort -u > "$W/named_keys"
ghosts=""
while IFS= read -r k; do
    [ -n "$k" ] || continue
    grep -qx -- "$k" "$ALLK" || ghosts="$ghosts $k"
done < "$W/named_keys"
chk "every config key named in a source string is one apply() parses" "" "$ghosts"

echo
echo "=== CONFIG KEYS LIVE: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
