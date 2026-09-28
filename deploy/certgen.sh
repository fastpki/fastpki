#!/bin/sh
# certgen.sh — deployment transport TLS (runs in the FastPKI image, as root).
#
# A fresh FastPKI deployment has NO CA yet (CAs live in the DB, not in
# files), but the app<->Postgres link and the web console should still be encrypted
# from first boot. So this generates ONE self-signed certificate at deploy time:
#   * Postgres server cert  -> /var/pki/tls/pg/server.{crt,key}, with the same cert
#     copied to pg/ca.crt as the app's sslmode=verify-full anchor
# It is PHASE 1 of two. Phase 2 — replacing it with a CA-issued certificate carrying
# the interconnect SANs — can only happen once a CA exists, which is later and is an
# operator decision. Either `fastpki-ca pg-tls <ca-id>`, which is what a multi-data-center
# bootstrap uses because it can be scripted, or the console: Endpoints -> PostgreSQL ->
# Issue certificate. Two phases at two points in the lifecycle, not two scripts by
# preference.
#
# ⚠️ NOT owned by the postgres uid any more. The postgres container copies this
# pair into a directory of its own and chowns it there, because the console — which
# writes phase 2 — runs as the unprivileged `fastpki` user and cannot chown to 70.
# Leaving 70:70 here would mean the console could not overwrite what this wrote.
#
# Runs (idempotently) BEFORE postgres — the compose `postgres` service now depends on
# it (condition: service_completed_successfully), so a bare `docker compose up -d`
# provisions the cert first. A re-run with a still-valid cert is a no-op. The default
# admin/admin credential must be changed at first login (seeded must_reset).
# The self-signed cert this writes is the DEV/TEST default a deployment STARTS on;
# hardening it is phase 2 above, and it ships.
set -eu

TLS=/var/pki/tls
# The uid 70 chown is GONE, not commented out. The postgres container copies the
# pair to a private directory and chowns it there, so nothing here has to know the
# server's uid — and, more to the point, the console could never have known it either.
# ⚠️ PKI_DNS IS THE ONLY NAME FOR THE DEPLOYMENT HOSTNAME, on every path that calls this
# script. Do not add a second one and do not read a fallback beside it: the `localhost`
# default below means a caller spelling it differently does not fail — it issues every
# transport certificate for the wrong name, quietly, because a certificate for `localhost`
# still verifies against itself.
FQDN="${PKI_DNS:-localhost}"
# ⚠️ THE SELF-SIGNED DATABASE CERTIFICATE NAMES THIS SERVER IN ITS SUBJECT, NOT THE DEPLOYMENT.
# Every server of a pair shares PKI_DNS, so a subject of CN=$PKI_DNS gave both servers' anchors
# the same name — and a trust file holding two same-named self-signed certificates verifies
# against the FIRST only. Measured on Kubernetes, where each pod trusts every pod's anchor:
# the standby matched its own certificate, rejected the primary's with "self-signed
# certificate", and never seeded. libpq takes sslrootcert as a single file, so the names
# themselves have to differ. PG_BIND is this server's own address wherever there is more
# than one; a single server keeps PKI_DNS.
PG_CN="${PG_BIND:-}"
[ "$PG_CN" = "127.0.0.1" ] && PG_CN=""
PG_CN="${PG_CN:-$FQDN}"
DAYS="${SELFSIGNED_DAYS:-825}"
RENEW="${SELFSIGNED_RENEW_DAYS:-90}"     # regenerate when within this many days of expiry

# ⚠️ OWNED BY fastpki, not root. The console writes server.{crt,key} here when
# it issues the CA-signed replacement, and creating a file needs write on the DIRECTORY,
# not just on the file. bootstrap.sh's broad chown would fix this later, but ordering is
# not a thing to rely on for a permission — certgen creates it, so certgen sets it.
mkdir -p "$TLS/pg"
chown fastpki:fastpki "$TLS" "$TLS/pg" 2>/dev/null || true

# ⚠️ /var/pki/ca-instances is NOT created here any more. The console stopped
# writing CA material to disk — the certificate is a `certs` row and the key is a
# pkcs11: handle — so creating the directory would leave an empty one that nothing
# on either side of it uses.

CRT="$TLS/pg/server.crt"
KEY="$TLS/pg/server.key"

# A CA-ISSUED Postgres cert (issuer != subject) is phase 2, written by the console
# (POST /api/pg-tls): it chains to the shared root and carries the interconnect
# SANs. Leave it strictly alone — self-signing over it would present a cert the
# replication peers can't verify (the collision that took the mesh down). certgen only
# owns the SELF-SIGNED transport cert below. (The old code instead keyed off a stray
# /var/pki/ca/root.crt FILE and rm'd server.key assuming phase 2 had already run; on
# any deploy where it hadn't, Postgres was left keyless -> plaintext -> verify-full
# apps crash-loop. CA material lives in the DB, so a root.crt file is no signal.)
# ── SoftHSM PIN file ────────────────────────────────────────────────────────────
# FIRST, and before any early exit below. This has nothing to do with the transport
# certificate; it was written at the END of this script, so both of the "the cert is
# already fine, nothing to do" exits skipped it.
#
# Measured on the lab: once a CA-issued Postgres certificate was installed, certgen took
# the exit at "a CA-issued Postgres cert is already in place" on every subsequent deploy
# and /var/pki/tls/pin was never written — while every *_KEY in the shipped config
# points at it as `pin-source`. So no service could mint a token key:
#
#     CMP: could not mint the RA key: pkcs11 keygen params (uri/bits/group) rejected:
#          error:80000002:system library::No such file or directory
#
# which is the "est-tls and cmp-ra keys were missing in token" failure. The keys that
# DID exist (acme, ms, web) were minted before the CA-issued cert took over. A missing PIN file
# does not announce itself: the failure surfaces as a BIO error from OpenSSL, several
# layers from the cause.
#
# Writing it is idempotent and independent of every certificate decision below, so it
# belongs here rather than behind them.
#
# The PIN comes from the deployment, not from this script. install.sh generates
# one and passes it as FASTPKI_PIN; '1234' remains only as the last resort for a hand-run
# `docker compose up` that never went through the wizard, and it is announced when used
# rather than silently shipped as if it were a choice.
# ⚠️ THIS FAILS CLOSED. It used to substitute the well-known PIN `1234` and carry
# on behind a warning — and a warning is not a control. The token this PIN protects holds
# EVERY CA private key, so "no PIN was configured" has to stop the deployment, not annotate
# it.
#
# It was not hypothetical: measured on our own 3-DC lab, whose `.env` set neither
# FASTPKI_PIN nor POSTGRES_PASSWORD, so all three nodes were running this dev PIN — and,
# separately, the compose default password `${POSTGRES_PASSWORD:-fastpki}`. Nothing
# surfaced either, because the only signal was a startup line nobody reads. That is the
# same shape as a legitimate config key carrying a dangerous VALUE — every guard checks
# whether the key is SET, and none checks what it says.
#
# deploy/.env.example now carries both as REQUIRED BLANKS, so copying it and filling it in
# is a prompt rather than a silent default.
# ── --p11-only: the RENEWAL entry point ───────────────────────────────────────────────
#
# ⚠️ THE TRANSPORT CERTIFICATES EXPIRE AND NOTHING ELSE RENEWS THEM. They are self-signed
# and pinned, so they are not `certs` rows and `fastpki-ca renew-service-certs` — which
# renews everything a CA issued — never sees them. Their only renewal is this script
# running again, and on a native or cloud node that happened once, at install: at
# SELFSIGNED_DAYS the tunnel simply stops handshaking, which reads like a trust problem
# rather than an expiry.
#
# So the daily job calls `certgen.sh --p11-only`. It re-enters the P11_TLS block below,
# whose freshness gate re-issues each certificate once it is within SELFSIGNED_RENEW_DAYS
# of expiry and is a no-op before that — the same code the install path runs, rather than a
# second copy of it that would drift.
#
# ⚠️ AND IT NEEDS NO FASTPKI_PIN. Renewal re-signs with the key already in the token,
# reached through the URI's `pin-source`; only MINTING a key needs the PIN, and the block
# below asks for it exactly there. The daily job runs as the unprivileged runtime user,
# which can read the PIN file but not /etc/conf.d/fastpki, so requiring it here would make
# the renewal impossible on the one deployment shape that most needs it.
P11_ONLY=no
[ "${1:-}" = "--p11-only" ] && P11_ONLY=yes

if [ "$P11_ONLY" = no ] && [ -z "${FASTPKI_PIN:-}" ]; then
  echo "certgen: FATAL — FASTPKI_PIN is not set." >&2
  echo "certgen:   The SoftHSM token this PIN protects holds every CA private key, so this" >&2
  echo "certgen:   refuses to fall back to a well-known value." >&2
  echo "certgen:   Run   deploy/install.sh   to generate one, or set FASTPKI_PIN in deploy/.env." >&2
  exit 1
fi
if [ "$P11_ONLY" = no ]; then
  mkdir -p /var/pki/tls
  printf '%s' "$FASTPKI_PIN" > /var/pki/tls/pin
  chown fastpki:fastpki /var/pki/tls/pin
  chmod 400 /var/pki/tls/pin
  echo "[certgen] PIN file /var/pki/tls/pin written (0400 fastpki)"
fi

# ── the mTLS material for the token transport (opt-in) ────────────────────────────────
#
# p11-kit speaks neither TLS nor TCP, so a token is reachable only by processes on its own
# host. `P11_TLS=on` puts an stunnel server beside it, so a PEER CAN REPLICATE A CA PRIVATE
# KEY OUT OF THIS NODE'S TOKEN INTO ITS OWN. That is the whole purpose: every node keeps its
# own token, and after replication each signs from its own copy and needs no peer to issue,
# renew or revoke. It is not a way for a node to borrow somebody else's token.
#
# ⚠️ IT MUST WORK BEFORE ANY CA EXISTS, which is why these are self-signed and PINNED rather
# than issued: the token is what the first CA is created IN, so a transport that needed a
# CA-issued certificate could never come up. Each side trusts exactly the other's
# certificate — the client pins the server's in CAfile, the server pins each client's in a
# CApath — so there is no issuer that could vouch for a third party.
#
# ⚠️ WRITTEN HERE, BEFORE THE EARLY EXITS BELOW. Two of them return before the Postgres
# certificate work, and material placed after them is silently skipped once a CA-issued
# Postgres cert appears — exactly what stopped the PIN file being written, which is why
# tests/certgen_pin_always.sh exists. Same position, same reason.
if [ "${P11_TLS:-off}" = "on" ]; then
  P11D=/var/pki/tls/p11
  mkdir -p "$P11D/clients"
  # ⚠️ THE NODE'S OWN TOKEN, OVER THE SOCKET THAT IS NOT THE TUNNEL. Every node has exactly
  # one token; what varies is the name it answers on. Where this node publishes its token,
  # that is /run/p11/pkcs11.sock. Where this node's pkcs11.sock is the near end of the
  # tunnel, its own token is served in addition at /run/p11/local.sock, and that is the one
  # to mint in — resolving a key through pkcs11.sock there would need the tunnel the key
  # exists to open.
  P11_TOKEN="${PKCS11_TOKEN:-fastpki}"
  P11_SOCKET_URI="${P11_KIT_SERVER_ADDRESS:-unix:path=/run/p11/pkcs11.sock}"
  P11_CLIENT_MOD="${PKCS11_MODULE:-/usr/lib/pkcs11/p11-kit-client.so}"
  PIN_FILE="${PKCS11_PIN_FILE:-/var/pki/tls/pin}"
  # ⚠️ -provider-path BEFORE -provider. openssl processes these in order, so a trailing path
  # arrives after the lookup and it searches its default modules directory instead.
  P11_PROV_ARGS="-provider-path ${OSSL_MODULES_DIR:-/usr/lib/ossl-modules} -provider pkcs11 -provider default"

  # ⚠️ THE TOKEN SERVER AUTHORISES BY PEER UID, SO ROOT CANNOT USE IT. The token container
  # runs `p11-kit-server -u fastpki`, which checks the connecting process's credentials over
  # the socket and serves that user alone — while this service is deliberately `user: "0:0"`
  # in docker-compose.yml, because it has to chown the Postgres key to the postgres uid. So
  # every call through the client shim died inside C_Initialize with
  #     error: PKCS11 function C_Initialize failed: rv = CKR_DEVICE_ERROR (0x30)
  # which names a DEVICE, not a user, and reads as a token that is down — on a token every
  # other container was using at that moment. Measured: the identical pkcs11-tool probe
  # lists the slot as uid 102 and fails as uid 0, against the same socket and module.
  #
  # busybox `setpriv` cannot change uid (it only does capabilities), so this uses `su`.
  P11_RUN_USER="${P11_RUN_USER:-fastpki}"
  p11run() {   # p11run '<one shell command that touches the token>'
      if [ "$(id -u)" = 0 ]; then su -s /bin/sh "$P11_RUN_USER" -c "$1"; else sh -c "$1"; fi
  }
  export P11_KIT_SERVER_ADDRESS="$P11_SOCKET_URI"
  export PKCS11_PROVIDER_MODULE="$P11_CLIENT_MOD"
  # ⚠️ REQUIRED ONLY TO MINT, checked at the mint site below rather than here. A renewal
  # re-signs with the key the token already holds and needs nothing but the pin-source file,
  # so demanding FASTPKI_PIN up front would make `--p11-only` impossible for the daily job.
  # ⚠️ THE KEY LIVES IN THIS NODE'S TOKEN, NOT IN A FILE. FastPKI's rule is that a private
  # key lives in a token and a PEM path is a last resort; this transport shipped two
  # file-based keys on every node, which was a gap rather than a design.
  #
  # ⚠️ AND IT REACHES THAT TOKEN THROUGH p11-kit-client.so, NEVER libsofthsm2.so DIRECTLY.
  # Loading SoftHSM in-process re-enters libcrypto while it holds a lock. Measured on the
  # shipped image: openssl driving the provider straight at libsofthsm2.so HANGS or fails
  # run to run, for RSA as much as EC — a deadlock, not an algorithm limit.
  p11_pair() {   # <name> <CN> <object-label> <CKA_ID hex>
    _c="$P11D/$1.crt"
    _uri="pkcs11:token=${P11_TOKEN};object=$3;type=private?pin-source=${PIN_FILE}"
    # ⚠️ THE CERTIFICATE MUST MATCH THE KEY THE TOKEN ACTUALLY HOLDS, not merely exist. The
    # file-based version guarded against a truncated key beside a valid certificate; the
    # token version guards against the same divergence, which here means a certificate left
    # from a previous token (a re-initialised SoftHSM, a restored node) whose object is gone
    # or has been re-minted. Compare the public halves, exactly as before.
    if [ -f "$_c" ] \
       && openssl x509 -in "$_c" -noout -checkend $((RENEW * 86400)) >/dev/null 2>&1 \
       && [ "$(openssl x509 -in "$_c" -noout -pubkey 2>/dev/null)" \
            = "$(p11run "openssl pkey -in '$_uri' -pubout $P11_PROV_ARGS 2>/dev/null")" ]; then
      return 0
    fi
    # ⚠️ RESOLVE BEFORE MINTING, OR A SECOND OBJECT APPEARS UNDER THE SAME LABEL. Reaching
    # here with the key already present is the ordinary case — a certificate that expired,
    # or one deleted by hand — and SoftHSM will happily create a second `p11-server`
    # alongside the first, after which `object=p11-server` selects whichever comes back
    # first and the pinned certificate matches it only by luck.
    if ! p11run "openssl pkey -in '$_uri' -pubout $P11_PROV_ARGS >/dev/null 2>&1"; then
      if [ -z "${FASTPKI_PIN:-}" ]; then
        echo "certgen: FATAL — no $3 key in the token and no FASTPKI_PIN to generate one." >&2
        echo "certgen:   Generating a key needs the PIN; renewing an existing key does not." >&2
        exit 1
      fi
      # ⚠️ --id IS REQUIRED, AND ONLY EC NOTICES IT MISSING. Without a CKA_ID the provider
      # later fails with `p11prov_obj_find_associated: No CKA_ID in source object` when asked
      # to sign with an EC key, while RSA works — which is exactly how "openssl cannot sign
      # with an EC token key" came to be written down as a limitation of the curve.
      p11run "pkcs11-tool --module '$P11_CLIENT_MOD' --token-label '$P11_TOKEN' \
          --keypairgen --key-type EC:prime256v1 --label '$3' --id '$4' \
          --login --pin '$FASTPKI_PIN' >/dev/null 2>&1" || {
        echo "certgen: FATAL — could not generate the $1 transport key in token '$P11_TOKEN'" >&2
        echo "certgen:   over $P11_KIT_SERVER_ADDRESS. Is this node's token server running?" >&2
        exit 1; }
    fi
    # Self-signed and pinned, for the reason above: there is no CA yet to issue it.
    # ⚠️ WRITTEN SOMEWHERE THE TOKEN USER CAN WRITE, then placed by root. This openssl call
    # signs with the token, so it runs as P11_RUN_USER — and $P11D is root-owned, so it
    # cannot create its own output there. root does the move and the chown, as before.
    _tmp="$(mktemp)" || { echo "certgen: FATAL — no temp file for the $1 certificate" >&2; exit 1; }
    chown "$P11_RUN_USER" "$_tmp" 2>/dev/null || true
    p11run "openssl req -x509 -new -key '$_uri' $P11_PROV_ARGS -sha256 \
        -days '$DAYS' -subj '/CN=$2' -out '$_tmp' >/dev/null 2>&1" || {
      rm -f "$_tmp"
      echo "certgen: FATAL — could not self-sign the $1 transport certificate" >&2; exit 1; }
    mv -f "$_tmp" "$_c" || {
      echo "certgen: FATAL — could not install the $1 transport certificate" >&2; exit 1; }
    chown fastpki:fastpki "$_c" 2>/dev/null || true
    echo "[certgen] token transport: $1 key generated in the token, certificate written ($_c)"
  }
  # ⚠️ A SUBJECT PER NODE, NOT ONE SHARED NAME — OR ONLY ONE PEER IS EVER ADMITTED.
  # stunnel's verifyPeer does not verify a chain: it looks the peer's certificate up in the
  # trust directory BY SUBJECT and compares public keys. An OpenSSL CApath lookup returns
  # the FIRST file whose subject matches, so when every node mints "CN=fastpki-p11-client"
  # the second and subsequent peers are compared against the first one's key and refused
  # with "Rejected by CERT at depth=0" — while the certificate they sent is sitting in that
  # directory, correctly indexed. Nothing in either end's log names the subject as the
  # cause, and whichever node happens to sort first keeps working, so the deployment looks
  # half-broken rather than misconfigured.
  #
  # The hostname, not PKI_DNS: under a single round-robin name every node shares PKI_DNS,
  # which is precisely the shape that needs this to be unique.
  P11CN="$(hostname 2>/dev/null || echo "$FQDN")"
  p11_pair server "fastpki-p11-server-$P11CN" p11-server 01
  p11_pair client "fastpki-p11-client-$P11CN" p11-client 02
  # The server trusts clients out of a DIRECTORY, not a single file, so a second node's
  # certificate is added by dropping it in — the shape this needs the moment there is more
  # than one client. `openssl rehash`, not c_rehash: the image has no perl.
  cp "$P11D/client.crt" "$P11D/clients/client.crt"
  openssl rehash "$P11D/clients" >/dev/null 2>&1 || {
    echo "certgen: FATAL — could not index $P11D/clients" >&2; exit 1; }
  chown -R fastpki:fastpki "$P11D" 2>/dev/null || true
  echo "[certgen] token transport: client trust directory indexed ($P11D/clients)"
fi

# The renewal entry point stops here: the Postgres certificate below is phase-1 install
# material with an owner of its own (the console writes phase 2), and a daily job has no
# business re-deciding it.
if [ "$P11_ONLY" = yes ]; then
  [ "${P11_TLS:-off}" = "on" ] || echo "[certgen] --p11-only with P11_TLS off: nothing to renew"
  exit 0
fi

is_self_signed() {
    [ -f "$1" ] || return 1
    _s=$(openssl x509 -in "$1" -noout -subject 2>/dev/null | sed 's/^subject=//')
    _i=$(openssl x509 -in "$1" -noout -issuer  2>/dev/null | sed 's/^issuer=//')
    [ -n "$_s" ] && [ "$_s" = "$_i" ]
}
if [ -f "$CRT" ] && [ -f "$KEY" ] && ! is_self_signed "$CRT"; then
    echo "[certgen] a CA-issued Postgres cert is already in place — leaving it (phase 2, the console, owns it)"
    exit 0
fi

# A self-signed cert is "good" only if BOTH the cert and its key are present (a cert
# without a key = Postgres serves plaintext while verify-full apps demand TLS = the
# crash-loop), it is not near expiry, and it covers the names the app and console
# actually dial: the console FQDN and the compose service `postgres` (verify-full pins
# each name PG_CONNINFO can dial).
#
# ⚠️ A STANDBY ON ANOTHER HOST IS NOT COVERED BY THIS CERTIFICATE, and cannot be — a
# self-signed cert minted here names only compose-internal addresses, and a joining host
# dials the primary by a routable one. That is what PG_TLS_SANS + `fastpki-ca pg-tls`
# exist for, and why a primary must have been given a CA-issued transport cert before
# anything can join it. See deploy/ha-join.sh, which checks exactly that up front.
# ⚠️ THE SELF-SIGNED CERT MUST CARRY PG_TLS_SANS TOO, not only the compose-internal names.
# Anything that dials this database by an address the certificate does not name fails
# sslmode=verify-full, and phase 1 is exactly when that bites: a joining standby, or a k8s
# deployment whose apps reach the standby Service by name, both connect long before anyone
# runs `fastpki-ca pg-tls`. Leaving those names out made the ordering "issue a CA cert
# first, or nothing can connect" — a constraint with no reason behind it.
#
# Entries are comma-separated and classified by shape: digits-and-dots is an IP, anything
# else a DNS name. An empty PG_TLS_SANS adds nothing, so a single-node deployment is
# unchanged.
san_list() {
    # ⚠️ TYPE-TAG THE FQDN TOO, not only the extras below. PKI_DNS is legitimately an IP
    # literal on a deployment reached by address, and a dNSName holding one matches
    # nothing — a client connecting by IP requires an iPAddress SAN.
    case "$FQDN" in
        *[!0-9.]*) _san="DNS:$FQDN" ;;
        *)         _san="IP:$FQDN"  ;;
    esac
    _san="$_san,DNS:postgres,DNS:localhost,IP:127.0.0.1"
    # ⚠️ THIS NODE'S OWN BIND ADDRESS, FROM THE ENVIRONMENT. PG_TLS_SANS is a per-node
    # value that an HA pair shares by accident: the pair replicates the whole database
    # physically, so both hosts read one config table and one row. Reading PG_BIND directly
    # is the only form the peer cannot overwrite, and `fastpki-ca pg-tls` does the same for
    # the CA-issued replacement. Empty on deployments that have no such address.
    _extra="${PG_BIND:-}"
    [ "$_extra" = "127.0.0.1" ] && _extra=""
    [ -z "${PG_TLS_SANS:-}" ] || _extra="${_extra:+$_extra,}${PG_TLS_SANS}"
    [ -n "$_extra" ] || { printf '%s' "$_san"; return 0; }
    OLDIFS=$IFS; IFS=,
    for _n in $_extra; do
        _n=$(printf '%s' "$_n" | tr -d '[:space:]')
        [ -n "$_n" ] || continue
        case "$_n" in
            *[!0-9.]*) _san="$_san,DNS:$_n" ;;
            *)         _san="$_san,IP:$_n"  ;;
        esac
    done
    IFS=$OLDIFS
    printf '%s' "$_san"
}

cert_good() {
    [ -f "$CRT" ] && [ -f "$KEY" ] || return 1
    openssl x509 -in "$CRT" -noout -checkend $((RENEW * 86400)) >/dev/null 2>&1 || return 1
    # The subject too (PG_CN, above): a certificate still named for the deployment collides
    # with the other server's anchor.
    [ "$(openssl x509 -in "$CRT" -noout -subject -nameopt RFC2253 2>/dev/null)" = "subject=CN=$PG_CN" ] \
        || return 1
    # ⚠️ MATCH THE FORM THE SAN ACTUALLY TAKES. san_list() writes an IP literal as
    # `IP Address:` and a hostname as `DNS:`, so grepping for DNS: alone would never match
    # on a deployment reached by address — the certificate would be judged stale and
    # regenerated on every single start.
    case "$FQDN" in
        *[!0-9.]*) _want="DNS:$FQDN" ;;
        *)         _want="IP Address:$FQDN" ;;
    esac
    openssl x509 -in "$CRT" -noout -text 2>/dev/null | grep -q "$_want"               || return 1
    # ⚠️ AND EVERY NAME PG_TLS_SANS ASKS FOR. Without this the cert is "good" forever, so
    # adding an address to PG_TLS_SANS silently never reaches the certificate and the node
    # that address belongs to cannot connect — the failure appears at the far end, as a
    # verify error naming a host this side considers perfectly configured.
    # ⚠️ `IP:` IS THE INPUT SPELLING, `IP Address:` IS THE OUTPUT ONE. san_list builds the
    # -addext argument, where an address is `IP:127.0.0.1`; `openssl x509 -text` prints the
    # same entry as `IP Address:127.0.0.1`. Grepping the printed form for the input spelling
    # never matches, so cert_good() returned false forever and certgen RE-ISSUED the Postgres
    # transport certificate on every single run — every `compose up`, every Postgres pod
    # start — rewriting pg/ca.crt, which is the anchor every app and every replication peer
    # verifies against. Nothing failed loudly, which is why it survived: the new certificate
    # is valid, so the only symptom was an identity that churned for no reason.
    # ⚠️ NO PIPELINE, AND IFS SET TO NEWLINE. Two traps, both of which make this check pass
    # while testing nothing:
    #   * `IP Address:` CONTAINS A SPACE, so a `for` over an unquoted substitution splits it
    #     into `IP` and `Address:127.0.0.1` — and `IP` matches almost any certificate;
    #   * a `while read` fed by a pipeline runs in a SUBSHELL, so `return 1` from inside it
    #     cannot fail this function. Measured: with that shape, adding an address to
    #     PG_TLS_SANS reported "already valid" and never reached the certificate — exactly
    #     the failure the paragraph above exists to prevent.
    _txt=$(openssl x509 -in "$CRT" -noout -text 2>/dev/null)
    _wants=$(san_list | sed 's/IP:/IP Address:/g' | tr ',' '\n')
    _oldifs=$IFS
    IFS='
'
    for _want in $_wants; do
        [ -n "$_want" ] || continue
        case "$_txt" in
            *"$_want"*) ;;
            *) IFS=$_oldifs; return 1 ;;
        esac
    done
    IFS=$_oldifs
    # ⚠️ THE ANCHOR IS PART OF "GOOD". pg/ca.crt is what every app verifies against under
    # sslmode=verify-full, and it is written ONLY on the regeneration path below. A run
    # interrupted after writing server.crt but before copying it — which is exactly what a
    # `compose up` that died mid-certgen leaves behind — then skips forever on every later
    # attempt, and every service fails with "certificate verify failed". That message names
    # Postgres, so it reads as a database or a hostname problem, when the truth is that the
    # anchor was never written.
    #
    # Byte-for-byte is right HERE and only here: a CA-issued certificate exits well above
    # this, and in that phase the console APPENDS to ca.crt rather than replacing it, so
    # equality deliberately would not hold — this branch never runs then.
    { [ -f "$TLS/pg/ca.crt" ] && cmp -s "$CRT" "$TLS/pg/ca.crt"; } || return 1
    return 0
}

if cert_good; then
    echo "[certgen] self-signed transport cert already valid for $FQDN — skipping"
    exit 0
fi

cat > /tmp/san.cnf <<EOF
[req]
distinguished_name = dn
x509_extensions    = v3
prompt             = no
[dn]
CN = $PG_CN
[v3]
basicConstraints     = critical,CA:FALSE
# keyEncipherment is correct HERE and only here: the key below is rsa:2048, and the bit
# means RSA key transport. If that key type ever changes, this line has to
# change with it, or the certificate claims something the key cannot do.
keyUsage             = critical,digitalSignature,keyEncipherment
extendedKeyUsage     = serverAuth
subjectAltName       = $(san_list)
EOF

openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/ss.key -out /tmp/ss.crt \
    -days "$DAYS" -config /tmp/san.cnf >/dev/null 2>&1

# Postgres server cert. ⚠️ Owned by `fastpki`, NOT by the postgres uid. This
# directory is a DELIVERY point that the console also writes to when it issues the
# CA-signed replacement, and the console runs unprivileged — 70:70 here would lock it
# out. The postgres container copies this pair into a directory of its own and chowns
# it there, which is the only arrangement that works for both writers.
cp /tmp/ss.crt "$CRT"
cp /tmp/ss.key "$KEY"
chown fastpki:fastpki "$CRT" "$KEY" 2>/dev/null || true
chmod 644 "$CRT"
chmod 600 "$KEY"

# The app->DB trust ANCHOR, at a path that never changes. On a fresh deploy the
# Postgres cert is self-signed, so it is its own anchor and this is a copy of it.
# When phase 2 installs a CA-ISSUED server cert the console PREPENDS the issuing root
# to this same file rather than replacing it — Postgres does not switch over until it
# reloads, so for that window the applications have to trust both. Pinning one stable
# path is what lets the anchor follow the certificate: pointing the conninfo at
# server.crt breaks the moment the cert stops being self-signed, and pointing it at the
# root breaks before one exists.
cp "$CRT" "$TLS/pg/ca.crt"
chown fastpki:fastpki "$TLS/pg/ca.crt" 2>/dev/null || true
chmod 644 "$TLS/pg/ca.crt"

# The web console is NOT seeded here any more. It resolves its own transport cert
# like EST/ACME/MS do: it mints a key inside the token on first start,
# self-signs against it, publishes to the certs table, and adopts a CA-issued cert
# when one appears. Writing web.{crt,key} here left a private key on disk that
# nothing read — verified on a rebuilt lab, where the log says "minted a transport
# key inside the token for \'web\'" while /var/pki/tls/web.key sat there unused.
#
# Postgres keeps its file pair below because it has no alternative: libpq\'s
# ssl_key_file takes a filesystem path and cannot reference PKCS#11.

rm -f /tmp/ss.key /tmp/ss.crt /tmp/san.cnf
# ⚠️ ASK san_list() RATHER THAN RESTATING IT. This line named "$FQDN, postgres, localhost"
# and omitted IP:127.0.0.1, PG_BIND and every PG_TLS_SANS entry — which are precisely the
# names an HA standby and a mesh peer dial under sslmode=verify-full. So the install's own
# confirmation of what it issued was evidence AGAINST a SAN that was in fact present, and a
# refused ha-join read as a missing name, sending the operator to `fastpki-ca pg-tls` — which
# cannot run before a CA exists. Deriving it from the function cannot drift from the cert.
echo "[certgen] generated self-signed transport cert for $PG_CN (SAN: $(san_list))"
