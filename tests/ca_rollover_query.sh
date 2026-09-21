#!/usr/bin/env bash
# Foundation: which certificate signs, and which certificates go in the chain,
# when a CA has two live ones.
#
# ── Why two ───────────────────────────────────────────────────────────────────────
#
# CA rekeying (the confirmed design) does not swap a certificate — it adds
# one. A new key is minted in the token, the OLD key cross-signs the new public key, and
# the result is a SECOND `certs` row with the SAME id. Both are live for the length of
# the rollover, which is why `certs.id` is indexed and NOT unique.
#
# That makes two questions that used to have one answer:
#
#   which certificate SIGNS?     the newest — ORDER BY "notBefore" DESC LIMIT 1
#   which certificates SHIP?     all live ones — a relying party still anchored on the
#                                old certificate has to be able to build a path, which
#                                is the whole reason for cross-signing rather than
#                                swapping.
#
# Leaving that to one query's ordering is how "which key signs" changes by accident, so
# they are two functions and this file holds them apart.
#
# ── What it guards ───────────────────────────────────────────────────────────────
#
# 1. get_ca_cert_der addresses the CA's OWN certificate — `id` + `is_ca`. It used to ask
#    `WHERE ca_instance_id=$1 ORDER BY "notBefore" DESC LIMIT 1`, which is every cert
#    that CA ISSUED as well, newest first — so after any issuance it returned a LEAF and
#    worked only because the caller ran X509_check_ca() and fell through. Section 2 puts
#    a NEWER leaf in the way and requires the CA back.
# 2. Liveness is `"notAfter" > now`, not `status=0`. An expired CA row must stop being a
#    signer the moment it expires, whether or not a sweep has run.
# 3. The chain carries BOTH rows during a rollover, newest first.
#
# 1 and 2 are put to the PRODUCT (sections 2 and 3, through `fastpki-ca urls`, which names
# the generation get_ca_cert_der returned). 3 is a statement about the rows here: what the
# protocols actually hand a client mid-rollover is asserted end to end in
# tests/ca_rollover_chain.sh, over EST, CMP, MS and ACME.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
OSSL=${OSSL:-/opt/openssl-3.5/bin/openssl}
# ⚠️ A MISSING $OSSL USED TO PASS. Sections 1-5 assert with count(*), so when the default
# path did not exist every `openssl` call failed, every cert column went in EMPTY, and the
# suite still reported 14/0 — it was counting rows it had never encoded. Fail loudly
# instead: a suite that cannot make a certificate is not a suite that found nothing wrong.
# §3d: the default path is a Linux convention and does not exist on every dev box —
# fall back to whatever is on PATH before giving up, or this suite is unrunnable
# anywhere the file is not at that exact location.
command -v "$OSSL" >/dev/null 2>&1 || OSSL=$(command -v openssl)
[ -n "$OSSL" ] || { echo "FAIL: no openssl on PATH — set OSSL"; exit 1; }
W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

pg_setup ca_rollover
trap 'pg_cleanup' EXIT

NOW=$(date +%s)
DAY=86400

# Three certificates for one CA id: an OLD one, a NEW one (the rekey), and an EXPIRED
# one. Plus a leaf newer than all of them, which is what the old query tripped on.
#
# Every one carries a subjectKeyIdentifier, spelled out rather than left to `req -x509`'s
# default: the product names the generation it would sign under by the SKI it puts in the
# qualified caIssuers URL (ca_issuer_ski below), and a certificate without one leaves that
# URL flat with no SKI to compare.
mkcert() { "$OSSL" req -x509 -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.pem" \
             -days 3650 -subj "/CN=$2" -addext "subjectKeyIdentifier=hash" >/dev/null 2>&1; }
mkcert old  "Rollover CA (old key)"
mkcert new  "Rollover CA (new key)"
mkcert gone "Rollover CA (expired)"
mkcert leaf "leaf.example.org"

ins() { # <serial> <pem> <notBefore> <notAfter> <is_ca> <id-or-NULL>
    local der; der=$("$OSSL" x509 -in "$2.pem" -outform DER | xxd -p | tr -d '\n')
    local idcol="'$6'"; [ "$6" = "NULL" ] && idcol=NULL
    pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,cn,cert,
                               id,is_ca,ca_instance_id)
             VALUES('$1',0,$3,$4,'CN=$2','$2','\\x$der'::bytea,$idcol,$5,'roll');" >/dev/null
}
#      serial  pem   notBefore        notAfter            is_ca  id
ins    c0ld    old   $((NOW-90*DAY))  $((NOW+300*DAY))    true   roll
ins    c0new   new   $((NOW-1*DAY))   $((NOW+3650*DAY))   true   roll
ins    c0gone  gone  $((NOW-800*DAY)) $((NOW-1*DAY))      true   roll
# The leaf is the NEWEST row carrying ca_instance_id='roll' — exactly what made the old
# query return a non-CA — and it carries the CA's `id` as well, which is what makes
# `AND is_ca` in the shipped query load-bearing rather than decoration: without it,
# `WHERE id='roll'` newest-first answers with THIS row. No product path can write it —
# both statements that set certs.id either filter `WHERE serial=$1 AND is_ca` or set
# is_ca=true in the same UPDATE — so it goes straight into the table, which is the only
# way to tell a query that carries the predicate from one that does not.
ins    1eaf    leaf  $((NOW))         $((NOW+30*DAY))     false  roll

# ── asking the PRODUCT which generation it presents ──────────────────────────────
# No token and no listener needed for this: `fastpki-ca urls` qualifies the caIssuers URL
# with the subjectKeyIdentifier of the certificate get_ca_cert_der() returns
# (ca_urls_for_instance -> cert_ski_hex, src/lib/ca_instance.cpp), so the SKI in that URL
# is the product's own answer to "which generation signs".
printf 'PG_CONNINFO=%s\nPKI_DNS=localhost\nLOG_LEVEL=err\n' "$PG_CONNINFO" > bootstrap.conf
ski_of() {   # <fixture name> -> that certificate's SKI, lowercase hex, no colons
    "$OSSL" x509 -in "$1.pem" -noout -ext subjectKeyIdentifier 2>/dev/null \
        | tr -d ' \n' | grep -oE '([0-9A-Fa-f]{2}:){3,}[0-9A-Fa-f]{2}' | head -1 \
        | tr -d ':' | tr 'A-F' 'a-f'
}
ca_issuer_ski() {   # -> the SKI the product put in roll's caIssuers URL, "" if unqualified
    # stderr dropped and the label anchored on purpose: a diagnostic must not be able to
    # supply the hex this gets compared against.
    "$ROOT/build/fastpki-ca" --config bootstrap.conf urls roll 2>/dev/null \
        | sed -n 's#^AIA caIssuers: .*/roll/\([0-9a-f][0-9a-f]*\)\.p7c$#\1#p' | head -1
}

echo "=== 1. the fixture is the rollover state ==="
chk "three CA rows share the id" 3 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='roll' AND is_ca;" | tr -d ' ')"
chk "two of them are live"       2 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='roll' AND is_ca AND \"notAfter\" > $NOW;" | tr -d ' ')"
chk "and the leaf is newer than either" yes \
    "$(pg_exec "SELECT CASE WHEN (SELECT \"notBefore\" FROM certs WHERE serial='1eaf')
                          >= (SELECT max(\"notBefore\") FROM certs WHERE id='roll' AND is_ca)
                       THEN 'yes' ELSE 'no' END;" | tr -d ' ')"
# id is indexed, NOT unique — three rows sharing one id prove it, and a unique index
# would have made the rekey INSERT fail outright.
chk "certs.id is not unique" 0 \
    "$(pg_exec "SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
                 WHERE c.relname='certs_id_idx' AND i.indisunique;" | tr -d ' ')"

echo "=== 2. the signer is the NEWEST LIVE CA row, never a leaf ==="
# ⚠️ ASKED OF THE PRODUCT, NOT OF A COPY OF ITS SQL. This used to run a transcription of
# kCaCertWhere through pg_exec and compare serials, so the section executed no product code
# at all: deleting `AND is_ca` from the shipped query — the regression the header names —
# left every assertion here green, and the transcription had already drifted from the
# shipped ORDER BY. get_ca_cert_der() answers for itself now, through the SKI in the
# caIssuers URL.
chk "PRECONDITION: the fixture certificates carry an SKI" yes \
    "$([ -n "$(ski_of new)" ] && [ -n "$(ski_of leaf)" ] && [ -n "$(ski_of gone)" ] \
       && echo yes || echo no)"
SIGNER_SKI=$(ca_issuer_ski)
chk "the signer is the new certificate" "$(ski_of new)" "$SIGNER_SKI"
# Both of these insist on a NON-EMPTY answer as well: an unqualified URL yields "", which
# differs from every SKI and would satisfy "not the leaf" while proving nothing.
chk "it is not the leaf"                yes \
    "$([ -n "$SIGNER_SKI" ] && [ "$SIGNER_SKI" != "$(ski_of leaf)" ] && echo yes || echo no)"
chk "it is not the expired one"         yes \
    "$([ -n "$SIGNER_SKI" ] && [ "$SIGNER_SKI" != "$(ski_of gone)" ] && echo yes || echo no)"
# What the OLD query would have answered, kept as the contrast: this is the bug. A
# statement about the fixture rather than about the product — the query it names is gone,
# and this is what says the fixture still has the shape that caught it.
OLDQ=$(pg_exec "SELECT serial FROM certs WHERE ca_instance_id='roll' AND status=0
                  ORDER BY \"notBefore\" DESC LIMIT 1;" | tr -d ' ')
chk "the previous query really did return the leaf" "1eaf" "$OLDQ"

echo "=== 3. an expired CA row stops signing without waiting for a sweep ==="
# `status` is what a sweep maintains; `"notAfter" > now` is true the moment it is asked.
# The call: use the predicate, because a sweep that misses a row leaves the
# wrong chain live for months.
chk "the expired row still says status=0 (no sweep has run)" 1 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE serial='c0gone' AND status=0;" | tr -d ' ')"
chk "and is excluded anyway" 0 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE serial='c0gone' AND id='roll' AND is_ca
                  AND status=0 AND \"notAfter\" > $NOW;" | tr -d ' ')"
# And the PRODUCT excludes it, which neither row count above can show. Make the expired
# generation the NEWEST by "notBefore" — the one arrangement in which `"notAfter" > now`
# changes which row the query returns — and ask get_ca_cert_der() again. Put back
# afterwards, because section 4 asserts the chain's ORDER.
pg_exec "UPDATE certs SET \"notBefore\" = $NOW WHERE serial='c0gone';" >/dev/null
chk "the product presents the live generation, not the newest expired one" \
    "$(ski_of new)" "$(ca_issuer_ski)"
pg_exec "UPDATE certs SET \"notBefore\" = $((NOW-800*DAY)) WHERE serial='c0gone';" >/dev/null

echo "=== 4. the chain carries BOTH live certificates, newest first ==="
CHAIN=$(pg_exec "SELECT serial FROM certs WHERE id='roll' AND is_ca AND status=0
                   AND \"notAfter\" > $NOW ORDER BY \"notBefore\" DESC;" | tr -d ' ' | tr '\n' ' ')
chk "the chain is new then old" "c0new c0old " "$(echo "$CHAIN" | sed 's/c0ld/c0old/')"
chk "the expired one is not in it" no \
    "$(echo "$CHAIN" | grep -q c0gone && echo yes || echo no)"
chk "the leaf is not in it" no \
    "$(echo "$CHAIN" | grep -q 1eaf && echo yes || echo no)"

echo "=== 5. the binaries agree with the SQL ==="
# fastpki-ca lists CAs through list_ca_instances(), which collapses a rollover to one row
# per id — the console must not show the same CA twice while it is being rekeyed. Its
# bootstrap.conf is the one written beside the fixture above.
LIST=$("$ROOT/build/fastpki-ca" --config bootstrap.conf list 2>/dev/null | grep -c '^roll' || true)
chk "fastpki-ca shows the rekeying CA once, not twice" 1 "$LIST"

echo "=== 6. the ANCESTOR walk survives a self-signed generation ==="
# Found on a lab DC: /cacerts served the issuing CA twice and NO root, so a client could
# not build a path at all. The CA had two live certificates — an older one signed by the
# root, and a newer SELF-SIGNED one. get_ca_ancestor_ders anchored its recursion on the
# newest (`ORDER BY "notBefore" DESC LIMIT 1`), and a self-signed certificate's iHash IS
# its own sHash, so the only rows that can join are itself and its sibling — both excluded
# on purpose. The walk returned nothing and the anchor silently vanished from every chain
# the product serves: EST, CMP, ACME and the console all call this one function.
#
# Sections 1-5 never caught it because they leave sHash/iHash NULL, so the recursive half
# of the query could not fire at ALL — the ancestor walk had no coverage whatsoever.
source "$ROOT/tests/x509_der.sh"      # x509_selectors <pem> -> sHash iHash iAndSHash sKIDHash

mksigned() { # <name> <cn> <issuer-name>: a REAL subordinate, not another self-signed cert
    "$OSSL" req -new -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" \
            -subj "/CN=$2" >/dev/null 2>&1
    printf 'basicConstraints=critical,CA:TRUE\n' > "$1.ext"
    "$OSSL" x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial \
            -days 3650 -extfile "$1.ext" -out "$1.pem" >/dev/null 2>&1
}
insh() { # <serial> <pem> <notBefore> <notAfter> <id> — with the hash selectors filled in
    local der sh ih
    der=$("$OSSL" x509 -in "$2.pem" -outform DER | xxd -p | tr -d '\n')
    read -r sh ih _ _ <<<"$(x509_selectors "$2.pem")"
    pg_exec "INSERT INTO certs(serial,status,\"notBefore\",\"notAfter\",subject,cn,cert,
                               id,is_ca,\"sHash\",\"iHash\")
             VALUES('$1',0,$3,$4,'CN=$2','$2','\\x$der'::bytea,'$5',true,
                    '\\x$sh'::bytea,'\\x$ih'::bytea);" >/dev/null
}
mkcert   anchor "Rollover Anchor Root"                    # the root: self-signed, its own id
mksigned sub    "Rollover Sub CA"      anchor             # generation 1: chained to the root
mkcert   subss  "Rollover Sub CA"                         # generation 2: SELF-SIGNED, newer
insh a0root anchor $((NOW-400*DAY)) $((NOW+3650*DAY)) rootca
insh 5ub1   sub    $((NOW-90*DAY))  $((NOW+300*DAY))  subca
insh 5ub2   subss  $((NOW-1*DAY))   $((NOW+3650*DAY)) subca

anc_sql() { # <anchor-predicate> -> how many ancestors the walk finds for 'subca'
    pg_exec "WITH RECURSIVE anc(serial,cert,ihash,cid,depth) AS (
               SELECT c.serial,c.cert,c.\"iHash\",c.id,0 FROM certs c WHERE $1
               UNION ALL
               SELECT p.serial,p.cert,p.\"iHash\",p.id,a.depth+1
                 FROM certs p JOIN anc a ON p.\"sHash\"=a.ihash
                WHERE p.is_ca AND p.id IS NOT NULL AND p.id<>a.cid
                  AND p.serial<>a.serial AND a.depth<8)
             SELECT count(DISTINCT serial) FROM anc WHERE depth>0;" | tr -d ' '
}
chk "the fixture really is two live certs for one CA" 2 \
    "$(pg_exec "SELECT count(*) FROM certs WHERE id='subca' AND is_ca;" | tr -d ' ')"
chk "and the newer one really is self-signed" yes \
    "$("$OSSL" x509 -in subss.pem -noout -subject -issuer \
       | awk -F= '{print $NF}' | uniq | wc -l | grep -q '^ *1$' && echo yes || echo no)"
# The contrast: this is the bug, kept executable so it cannot quietly come back.
chk "ANCHORING ON THE NEWEST ONLY loses the root" 0 \
    "$(anc_sql "c.serial=(SELECT serial FROM certs WHERE id='subca' AND is_ca AND id IS NOT NULL
                          ORDER BY \"notBefore\" DESC LIMIT 1)")"
# What db_postgres.cpp does now: every generation is a starting point.
chk "anchoring on EVERY generation finds the root" 1 \
    "$(anc_sql "c.id='subca' AND c.is_ca AND c.id IS NOT NULL")"

echo
echo "=== CA ROLLOVER QUERY: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
