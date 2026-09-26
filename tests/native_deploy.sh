#!/usr/bin/env bash
# The native Alpine deployment (deploy/native/) and the cloud image built from it.
#
# ⚠️ WHY THIS IS A TEST AND NOT A DOC NOTE. Three of the things it asserts fail SILENTLY,
# and two of them fail silently in production rather than in a build:
#
#   1. THE SUPERVISOR. FastPKI is crash-only: exit_if_token_died(), the gate_protocol()
#      watcher's off-switch and its restart marker all call std::_Exit(0) — a CLEAN exit —
#      and every one expects the supervisor to bring the process back. OpenRC's default
#      start-stop-daemon does not respawn at all, and supervise-daemon's default
#      respawn_max=10 is a budget for failures where there are none to budget. Get either
#      wrong and a protocol switched back on in the console simply never returns, with no
#      error anywhere. Nothing else in the suite reads an init script.
#
#   2. THE VERSION PINS. build-native.sh compiles the same three patched PKCS#11
#      components the Dockerfile does, and reads its pins OUT of the Dockerfile so the two
#      cannot drift. That extraction is a grep, and a grep silently stops matching when
#      the thing it greps is renamed — at which point the drift it exists to prevent is
#      exactly what happens.
#
#   3. THE CONFIG KEYS. install-native.sh writes /etc/fastpki/bootstrap.conf, and
#      config.cpp's apply() is an if/else-if chain with no final else, so a key the parser
#      does not know is silently ignored. A wizard that writes one produces a deployment
#      that runs on defaults while its config file says otherwise.
#
# No Alpine, no root, no daemons: this asserts on what the scripts WRITE and what the
# init scripts DECLARE, which is the contract between them and the code.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
NAT="$ROOT/deploy/native"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0; skip=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

echo "=== 1. every shipped script parses ==="
for f in "$NAT/build-native.sh" "$NAT/build-check.sh" "$NAT/run-check.sh" \
         "$NAT/pg-tls-sync.sh" "$NAT/periodic/fastpki-certrenew" \
         "$ROOT/deploy/cloud/image/provision.sh" \
         "$ROOT/deploy/cloud/image/build-qemu.sh" \
         "$ROOT/deploy/cloud/boot-check.sh" \
         "$ROOT/deploy/cloud/ovmf-firmware.sh"; do
    chk "$(basename "$f") parses as POSIX sh" ok "$(sh -n "$f" 2>/dev/null && echo ok || echo broken)"
done
for f in "$NAT/install-native.sh" "$ROOT/deploy/cloud/cloud-install.sh"; do
    chk "$(basename "$f") parses as bash" ok "$(bash -n "$f" 2>/dev/null && echo ok || echo broken)"
done

echo "=== 1b. the cloud image can be built as a bootable disk, on the same Alpine ==="
# ⚠️ AN AMI CANNOT BE BOOTED WITHOUT EC2, so for a long time nothing tested the artifact
# every cloud user actually boots. The qemu source emits a qcow2 from the SAME
# provision.sh, which is the only reason a local boot proves anything about the AMI — two
# builders provisioned differently would test something other than what ships.
PKR="$ROOT/deploy/cloud/image/fastpki.pkr.hcl"
chk "a qemu source exists beside amazon-ebs"       yes \
    "$(grep -q '^source "qemu" "alpine"' "$PKR" && echo yes || echo no)"
chk "  and the build runs BOTH, not one"           yes \
    "$(grep -q 'sources = \["source.amazon-ebs.alpine", "source.qemu.alpine"\]' "$PKR" && echo yes || echo no)"
# ⚠️ AND IT MUST SUPPLY FIRMWARE, because the base it names is the `-uefi-` cloud image.
# Packer's qemu builder starts SeaBIOS unless told otherwise, and SeaBIOS finds no boot code
# on a GPT disk whose bootloader lives in an EFI system partition — the guest never starts,
# and the only symptom is SSH not answering until ssh_timeout expires. Nothing else in this
# repository can catch that without booting a VM.
chk "  and boots that -uefi- base under UEFI firmware" yes \
    "$(grep -qE '^[[:space:]]*efi_boot[[:space:]]*=[[:space:]]*true' "$PKR" && echo yes || echo no)"
# ⚠️ AND IT NAMES A CPU. Packer omits `-cpu` entirely when cpu_model is unset, so the guest
# gets `qemu64` with the host's features masked off. That is invisible — the build still
# succeeds — until you notice it is tens of times slower, which on a NESTED host (the gate's
# node is itself a VM) is the difference between twenty minutes and four hours. boot-check.sh
# passes `-cpu max`; the build must not be the half that forgets.
chk "  and passes the host CPU through, not qemu64" yes \
    "$(grep -qE '^[[:space:]]*cpu_model[[:space:]]*=' "$PKR" && echo yes || echo no)"
# ⚠️ ONE ALPINE, TWO SPELLINGS. The AMI is chosen by filter (alpine-3.24.*) and AWS
# resolves the patch release; a download URL cannot glob, so the qemu path names it in
# full. Nothing but this check stops the two drifting into different operating systems.
AV=$(awk '/variable "alpine_version"/{f=1} f&&/default/{gsub(/[^0-9.]/,""); print; exit}' "$PKR")
AIV=$(awk '/variable "alpine_image_version"/{f=1} f&&/default/{gsub(/[^0-9.]/,""); print; exit}' "$PKR")
chk "  PRECONDITION: both pins were read"          yes \
    "$([ -n "$AV" ] && [ -n "$AIV" ] && echo yes || echo no)"
# ⚠️ A FUNCTION, not an inline `case` inside `$( )`: bash reads the pattern's own `)` as the end of
# the command substitution, so this check always failed on a syntax error.
patch_of(){ case "$1" in "$2".*) echo yes ;; *) echo no ;; esac; }   # patch_of <version> <base>
chk "  the disk image pin is a patch of the AMI pin" yes "$(patch_of "$AIV" "$AV")"
# ⚠️ AND THE BUILD KEY MUST NOT SHIP. cloud-init writes the ephemeral public key into the
# alpine account so Packer can connect; an artifact still carrying it would admit whoever
# holds the other half to every instance booted from it. Clearing the cloud-init instance
# state matters as much: an image that believes it is already configured IGNORES a real
# instance's user-data, which is the first-boot failure this image exists to catch.
chk "  the build key is removed from the artifact" yes \
    "$(grep -q 'rm -f /home/alpine/.ssh/authorized_keys' "$PKR" && echo yes || echo no)"
chk "  and the cloud-init instance state with it"  yes \
    "$(grep -q 'rm -rf /var/lib/cloud/instance' "$PKR" && echo yes || echo no)"
# ⚠️ ALPINE'S CLOUD IMAGE HAS NO sudo, AND HAS NOT SINCE 3.16 — it ships doas with
# `permit nopass :wheel` and the `alpine` account in wheel. Both sources log in as that
# account and neither receives a package list from us, so a provisioner reaching for sudo
# dies at `sh: sudo: not found` before it does anything — on the AMI exactly as on the
# qcow2, and the AMI lane has never been built to say so. Comment lines are stripped
# first, so explaining the absence in prose costs nothing here.
chk "  nothing in the image path CALLS sudo" 0 \
    "$(sed -E 's/^[[:space:]]*#.*//' "$PKR" "$ROOT/deploy/cloud/boot-check.sh" \
       | grep -cE '(^|[^[:alnum:]_])sudo[[:space:]]')"
chk "  and both provisioners escalate the same way" 2 \
    "$(grep -c 'execute_command[[:space:]]*=[[:space:]]*local.as_root' "$PKR")"

echo "=== 2. every service respawns on a CLEAN exit, without a budget ==="
# The three exits that make this load-bearing are all std::_Exit(0). Assert the code still
# does that, so this suite cannot go on guarding a property the product stopped having.
chk "the product still exits 0 to be restarted" yes \
    "$(grep -q 'std::_Exit(0)' "$ROOT/src/lib/endpoint_gate.cpp" && echo yes || echo no)"
# ⚠️ ONLY THE SERVICES THAT RUN A DAEMON. A service file with no `command=` does its work in
# start() and exits — fastpki-pgstale removes a socket file a killed postmaster left behind,
# before PostgreSQL starts — and there is no process for a supervisor to watch. Asserting
# "supervise-daemon" against one of those fails for being what it is, and the fix would be to
# make it pretend to be a daemon. The property under test is about LISTENERS that exit 0 and
# must come back, so the test says so.
for f in "$NAT"/openrc/*.initd; do
    b="$(basename "$f")"
    grep -qE '^command=' "$f" || continue      # one-shot: nothing to supervise
    chk "$b uses supervise-daemon" yes \
        "$(grep -qE '^supervisor=supervise-daemon' "$f" && echo yes || echo no)"
    chk "$b respawns without a limit" yes \
        "$(grep -qE '^respawn_max=0([[:space:]]|$)' "$f" && echo yes || echo no)"
done
# And the census must have seen something: a glob that matched nothing, or a rename that
# emptied the loop, would otherwise pass this section in silence.
chk "  PRECONDITION: the supervised services were examined" yes \
    "$([ "$(grep -lE '^command=' "$NAT"/openrc/*.initd 2>/dev/null | wc -l)" -ge 4 ] && echo yes || echo no)"

echo "=== 3. the template covers exactly the protocol binaries CMake builds ==="
# A symlink for a binary that does not exist is a service that fails at start with a
# confusing message; a binary with no symlink is a protocol that is simply never started.
listeners=$(grep -oE 'add_executable\(fastpki-(ocsp|est|acme|cmp|ms|store|scep|web)' "$ROOT/CMakeLists.txt" \
            | sed 's/add_executable(fastpki-//' | sort -u | tr '\n' ' ')
linked=$(sed -n 's/^for p in \(.*\); do$/\1/p' "$NAT/build-native.sh" | head -1 | tr ' ' '\n' | sort -u | tr '\n' ' ')
chk "the symlink set matches the listener binaries" "$listeners" "$linked"

echo "=== 4. build-native.sh still finds every pin in the Dockerfile ==="
# The drift detector, tested. Each of these is the exact expression build-native.sh uses.
for a in P11P_COMMIT SOFTHSM_COMMIT HTTPLIB_VERSION JSON_VERSION; do
    v="$(sed -n "s/^ARG $a=\\(.*\\)\$/\\1/p" "$ROOT/Dockerfile" | head -1)"
    chk "Dockerfile still declares ARG $a" yes "$([ -n "$v" ] && echo yes || echo no)"
done
v="$(sed -n 's|.*--branch \([0-9][0-9.]*\) https://github.com/p11-glue/p11-kit.*|\1|p' "$ROOT/Dockerfile" | head -1)"
chk "the p11-kit version is still readable from the Dockerfile" yes "$([ -n "$v" ] && echo yes || echo no)"
# And the native build must patch all three, or the image and the host diverge in the one
# place that decides whether an Ed25519 or ML-DSA CA can exist at all.
for p in pkcs11-provider-allowed-mechs p11-kit-mechanisms softhsm-allowed-mechs; do
    chk "build-native.sh applies $p.patch" yes \
        "$(grep -q "$p.patch" "$NAT/build-native.sh" && echo yes || echo no)"
done

echo "=== 5. the wizard writes only config keys the parser reads ==="
grep -oE 'key == "[A-Z0-9_]+"' "$ROOT/src/lib/config.cpp" | sed 's/key == "//; s/"//' | sort -u > "$W/real.txt"
# Two preconditions, because the comparison below is a `comm` against a file: if the
# extraction ever returns nothing, every key looks unknown (loud), and if it returned
# everything, no key could ever look unknown (silent, and the failure mode that matters).
chk "  PRECONDITION: the parser's key list was extracted" yes \
    "$([ "$(wc -l < "$W/real.txt")" -gt 50 ] && echo yes || echo no)"
chk "  PRECONDITION: a planted unknown key is caught" "FAKE_KEY_NOT_IN_PARSER" \
    "$(printf 'FAKE_KEY_NOT_IN_PARSER\n' | comm -23 - "$W/real.txt" | tr -d '\n')"
cat > "$W/answers.env" <<'ANS'
DEPLOYMENT=cluster
PKI_DNS=pki.example.org
DC_INDEX=2
PG_BIND=10.0.0.2
PG_LOCAL=yes
PG_PASSWORD=answersfilepassword
PKCS11_PIN=answersfilepin
KEY_BACKEND=softhsm
WANT_EST=yes
WANT_ACME=no
WANT_CMP=yes
WANT_SCEP=no
WANT_MS=yes
WANT_STORE=no
WEB_KEY_ALGO=rsa
WEB_KEY_BITS=4096
EST_KEY_ALGO=ec
EST_KEY_CURVE=P-384
MS_KEY_ALGO=ec
MS_KEY_CURVE=P-256
ANS
bash "$NAT/install-native.sh" --answers "$W/answers.env" --print-conf > "$W/out.txt" 2>"$W/err.txt"
chk "--print-conf succeeds without touching the host" ok \
    "$([ -s "$W/out.txt" ] && echo ok || echo "failed: $(head -1 "$W/err.txt")")"
# Only the bootstrap.conf half; /etc/conf.d/fastpki is read by the init scripts, not by
# the config parser, so its names are deliberately not config keys.
sed -n '/^── .*bootstrap.conf ──$/,/^── /p' "$W/out.txt" | grep -oE '^[A-Z][A-Z0-9_]+=' | tr -d '=' | sort -u > "$W/written.txt"
chk "the generated config names at least ten keys" yes \
    "$([ "$(wc -l < "$W/written.txt")" -ge 10 ] && echo yes || echo no)"
dead="$(comm -23 "$W/written.txt" "$W/real.txt" | tr '\n' ' ')"
chk "every key it writes is one the parser reads" "" "$(printf '%s' "$dead" | sed 's/ *$//')"

# HA_ENABLED, the pair switch every path shares (install_wizard.sh checks compose's): the
# key tunnel on in the services' environment, service keys copyable in the config.
printf 'PKI_DNS=pki.example.org\nPG_BIND=10.0.0.1\nHA_ENABLED=yes\n' > "$W/ha.env"
bash "$NAT/install-native.sh" --answers "$W/ha.env" --print-conf > "$W/ha.txt" 2>/dev/null
chk "HA_ENABLED=yes: P11_TLS=on for the services" yes \
    "$(sed -n '/^── .*conf.d.*──$/,/^── /p' "$W/ha.txt" | grep -qx 'P11_TLS=on' && echo yes || echo no)"
chk "  and SERVICE_KEYS_REPLICABLE=true in bootstrap.conf" yes \
    "$(sed -n '/^── .*bootstrap.conf ──$/,/^── /p' "$W/ha.txt" | grep -qx 'SERVICE_KEYS_REPLICABLE=true' && echo yes || echo no)"
printf 'PKI_DNS=pki.example.org\nPG_BIND=127.0.0.1\nHA_ENABLED=yes\n' > "$W/haloop.env"
bash "$NAT/install-native.sh" --answers "$W/haloop.env" --print-conf >/dev/null 2>&1
chk "  refused with a loopback PG_BIND: the standby could not connect" fail \
    "$([ $? -ne 0 ] && echo fail || echo ok)"

echo "=== 6. native and compose agree on every listener's token key ==="
# ⚠️ THIS ONE COST A DEPLOYMENT THAT LOOKED FINE. The native installer omitted WEB_TLS_KEY
# and WEB_CERT_ID, so fastpki-web came up on PLAIN HTTP — silently, because the default log
# level is `err` and falling back to cleartext is not an error. The console needs a secure
# context for in-browser key generation and the HSM slot picker, so "it started" and "it
# works" were different answers and nothing said so.
#
# deploy/bootstrap.compose.conf is the reference: whatever it says a listener's key handle
# is, the native config must say the same, or the same deployment behaves differently
# depending on how it was installed.
COMPOSE_CONF="$ROOT/deploy/bootstrap.compose.conf"
cat > "$W/all.env" <<'ALLANS'
DEPLOYMENT=single
PKI_DNS=pki.example.org
PG_LOCAL=yes
KEY_BACKEND=softhsm
PG_PASSWORD=x
PKCS11_PIN=y
WANT_EST=yes
WANT_ACME=yes
WANT_CMP=yes
WANT_SCEP=yes
WANT_MS=yes
WANT_STORE=yes
ALLANS
bash "$NAT/install-native.sh" --answers "$W/all.env" --print-conf 2>/dev/null > "$W/native.txt"
# ⚠️ SCEP_RA_KEY IS IN THIS LIST BECAUSE ITS ABSENCE WAS INVISIBLE. The installer asked for
# SCEP_RA_KEY_BITS and wrote that, but never wrote SCEP_RA_KEY, so a native or cloud install
# with SCEP enabled fell back to the CA's own key — which works only while that CA is RSA and
# fails silently on the EC CA the console offers by default. Compose had the line all along;
# this loop just never compared it. Any listener key handle that compose writes belongs here.
for k in WEB_TLS_KEY WEB_CERT_ID OCSP_RESPONDER_KEY EST_KEY EST_CERT_ID \
         ACME_KEY ACME_CERT_ID MS_KEY MS_CERT_ID CMP_RA_KEY SCEP_RA_KEY; do
    want="$(sed -n "s/^$k=//p" "$COMPOSE_CONF" | head -1)"
    got="$(sed -n "s/^$k=//p" "$W/native.txt" | head -1)"
    chk "$k matches deploy/bootstrap.compose.conf" "$want" "$got"
done

echo "=== 7. the answers file is the SAME contract as deploy/install.sh ==="
# An answers file written for a compose deployment must configure a native one unchanged,
# which is only true while both wizards read the same names.
for k in DEPLOYMENT PKI_DNS DC_INDEX PG_BIND HA_ENABLED KEY_BACKEND PKCS11_MODULE PKCS11_TOKEN \
         PG_PASSWORD PKCS11_PIN; do
    chk "install.sh and install-native.sh both read $k" yes \
        "$(grep -q "\\b$k\\b" "$ROOT/deploy/install.sh" && grep -q "\\b$k\\b" "$NAT/install-native.sh" \
           && echo yes || echo no)"
done

echo "=== 8. no secret reaches a daemon's environment or the cloud's user-data ==="
# The compose stack is careful about this and the native path has to be too: a value in
# the environment is readable in /proc/<pid>/environ for the life of the process, and
# EC2 user-data is readable by anything on the instance that can reach the metadata
# service AND is stored in the account.
chk "the init template exports no PIN" yes \
    "$(grep -qE '^[[:space:]]*export[[:space:]]+FASTPKI_PIN' "$NAT/openrc/fastpki.initd" && echo no || echo yes)"
chk "the init template exports no conninfo" yes \
    "$(grep -qE '^[[:space:]]*export[[:space:]]+PG_CONNINFO' "$NAT/openrc/fastpki.initd" && echo no || echo yes)"
chk "user-data carries no password or PIN" yes \
    "$(grep -qE '^(PG_PASSWORD|PKCS11_PIN|FASTPKI_PIN)=' "$ROOT/deploy/cloud/aws/user-data.sh.tftpl" && echo no || echo yes)"
chk "the tfvars example carries no password or PIN" yes \
    "$(grep -qiE '(password|_pin)[[:space:]]*=' "$ROOT/deploy/cloud/aws/terraform.tfvars.example" && echo no || echo yes)"

echo "=== 8b. the per-host values reach the services that read them ==="
# ⚠️ PG_BIND NAMES THE MACHINE, and the services read it — with STANDBY_OF and P11_TLS — from
# their ENVIRONMENT, falling back to PKI_DNS, which both hosts of an HA pair share. On native
# they went only into Postgres's config and a sourced-not-exported conf.d, so a pair published
# its token-transport certificates under one name (the second overwriting the first, and no
# key replicable), reported as one host, and a standby never ran or offered key sync.
confd="$(sed -n '/^── .*conf.d\/fastpki ──$/,$p' "$W/out.txt")"
chk "the wizard writes PG_BIND into conf.d"       yes \
    "$(printf '%s\n' "$confd" | grep -qx 'PG_BIND=10.0.0.2' && echo yes || echo no)"
for v in PG_BIND P11_TLS STANDBY_OF; do
    chk "  and the service template exports $v"    yes \
        "$(grep -qxF "[ -n \"\${$v:-}\" ] && export $v" "$NAT/openrc/fastpki.initd" && echo yes || echo no)"
done
chk "fastpki-p11-tls publishes both certificates under PG_BIND" 2 \
    "$(grep -A1 -F 'PG_BIND="${PG_BIND:-}" fastpki-config' "$NAT/openrc/fastpki-p11-tls.initd" | grep -c 'p11-.*-publish')"
renew="$NAT/periodic/fastpki-certrenew"
all_cmds="$(grep -c '"[^"]*/usr/local/bin/fastpki-' "$renew")"
chk "  PRECONDITION: the nightly job's FastPKI commands were found" yes \
    "$([ "$all_cmds" -ge 6 ] && echo yes || echo no)"
chk "the nightly job hands PG_BIND to every FastPKI command it runs" "$all_cmds" \
    "$(grep -c '"\$HOST_ENV /usr/local/bin/fastpki-' "$renew")"
# From every other host of this data center, not only standby-from-primary: a key minted on the
# standby otherwise never reaches the primary.
chk "  and runs key sync from this data center's other hosts" yes \
    "$(grep -q 'key sync --from-peers' "$renew" && echo yes || echo no)"

echo "=== 9. the AMI never carries a token ==="
# Every instance launched from an image that carried one would share CA key material. The
# bake creates a throwaway token to PROVE the patched stack relays ML-DSA and EdDSA, so
# the removal has to be on every exit path, not just the happy one.
prov="$ROOT/deploy/cloud/image/provision.sh"
chk "the bake probes the token through p11-kit" yes \
    "$(grep -q 'list-mechanisms' "$prov" && echo yes || echo no)"
chk "it fails the build when ML-DSA is not relayed" yes \
    "$(grep -qE 'ml-dsa\|mechtype-0x1\[cd\]' "$prov" && echo yes || echo no)"
chk "the throwaway token is removed on every exit path" yes \
    "$(grep -q 'trap bake_cleanup EXIT INT TERM' "$prov" && echo yes || echo no)"

echo "=== 10. the local bake check runs the REAL provision script ==="
# A local check that asserts the same things through a SECOND script is a check that can
# pass while the real bake fails — the same drift the Dockerfile pin extraction exists to
# prevent, one layer up. It is only worth having while it invokes provision.sh itself.
chk "build-check.sh invokes deploy/cloud/image/provision.sh" yes \
    "$(grep -q 'deploy/cloud/image/provision.sh' "$NAT/build-check.sh" && echo yes || echo no)"
chk "provision.sh honours FASTPKI_BAKE_LOCAL" yes \
    "$(grep -q 'FASTPKI_BAKE_LOCAL' "$ROOT/deploy/cloud/image/provision.sh" && echo yes || echo no)"
# Only the two steps that need a machine that boots may be skipped locally. If the local
# path ever skipped the mechanism probe or the compile, it would report PASS on a bake
# that cannot work — which is worse than not having it.
# ⚠️ THE ORDER IS THE PROOF, and the previous form proved nothing: it tested `!seen_skip`, a
# variable the awk program never assigned, so it reduced to "some line says list-mechanisms"
# — which section 9 above already asserts — and wrapping the probe in a
# `[ "$BAKE_LOCAL" = 0 ]` branch left it green. A step that runs BEFORE the script's first
# test of BAKE_LOCAL cannot be skipped by it, so line numbers are compared instead. Comments
# are stripped (grep -vn keeps the file's own numbering) so prose naming the variable cannot
# move the fork, and the `BAKE_LOCAL=` assignment is excluded because it gates nothing.
bake_fork="$(grep -vn '^[[:space:]]*#' "$prov" | grep 'BAKE_LOCAL' \
             | grep -vE '^[0-9]+:[[:space:]]*BAKE_LOCAL=' | head -1 | cut -d: -f1)"
# yes when the step exists AND no line of it sits at or after the local-skip fork.
runs_on_both() {
    grep -vn '^[[:space:]]*#' "$prov" | grep -E -- "$1" | cut -d: -f1 \
      | awk -v g="${bake_fork:-0}" '{n++; if (g+0==0 || $1+0>=g+0) bad=1}
                                    END{print (n && !bad) ? "yes" : "no"}'
}
chk "PRECONDITION: the local-skip fork was located" yes \
    "$([ -n "$bake_fork" ] && echo yes || echo no)"
chk "the local path still runs the ML-DSA/EdDSA probe" yes "$(runs_on_both 'list-mechanisms')"
chk "the local path still compiles the binaries" yes "$(runs_on_both 'build-native\.sh')"
chk "build-check.sh reads the Alpine version from the Dockerfile" yes \
    "$(grep -q 'FROM alpine:' "$NAT/build-check.sh" && echo yes || echo no)"
# The update package for a running node is the manifest build-native.sh records. Unpacked
# over a node, an entry for the token store would reset the owner and mode of the directory
# holding its CA keys, so neither the store nor its config may ever be recorded.
chk "the update package is built from the install manifest" yes \
    "$(grep -q 'installed-files' "$NAT/build-check.sh" && grep -q '^record()' "$NAT/build-native.sh" && echo yes || echo no)"
chk "the bake holds the p11-kit packages it overwrites, and the image build checks it" yes \
    "$(grep -q 'hold-p11-kit.sh' "$NAT/build-native.sh" && grep -q '\^\$pkg=' "$ROOT/deploy/cloud/image/provision.sh" && echo yes || echo no)"
chk "  the installer holds them too, for a node baked before that" yes \
    "$(grep -q '/usr/libexec/fastpki/hold-p11-kit' "$NAT/install-native.sh" && echo yes || echo no)"
chk "  and the hold names both packages at an exact version" yes \
    "$(grep -q 'for pkg in p11-kit p11-kit-server' "$NAT/hold-p11-kit.sh" && grep -q '"\$pkg=\$v"' "$NAT/hold-p11-kit.sh" && echo yes || echo no)"
# The native role is not a superuser, so the grants it needs are written out: the Replication
# page cannot see a standby's streaming state without pg_read_all_stats.
chk "the installer grants the database role what the Replication page reads" yes \
    "$(grep -vE '^[[:space:]]*#' "$NAT/install-native.sh" | grep -q "GRANT pg_read_all_stats TO fastpki" && echo yes || echo no)"
chk "the manifest never records the token store or its config" no \
    "$(grep -vE '^[[:space:]]*#' "$NAT/build-native.sh" | grep -E '^[[:space:]]*(inst|record)[[:space:]]' | grep -qE 'softhsm/tokens|softhsm2\.conf' && echo yes || echo no)"

echo "=== 11. the base image is pinned to ONE image from a NAMED owner ==="
# Both halves are supply-chain controls, and both fail silently.
#
# The OWNER, because "an image named alpine-3.24" is not "Alpine's official image":
# querying EC2 for alpine-3.2* with no owner filter also returns a third-party seller's
# build from the aws-marketplace account. Nothing in the name distinguishes them.
#
# The `-r*` SUFFIX, because Alpine publishes a `-metal-` sibling of every image under a
# name the obvious pattern also matches — and measured in us-east-1, the x86_64 pair
# carry the IDENTICAL creation timestamp, so `most_recent` has nothing to break the tie.
# A build that selects its own base image by coin flip is not a pinned build.
PKR="$ROOT/deploy/cloud/image/fastpki.pkr.hcl"
owner_default="$(sed -n '/variable "source_ami_owner"/,/^}/p' "$PKR" | sed -n 's/^[[:space:]]*default[[:space:]]*=[[:space:]]*"\([0-9]\{12\}\)".*/\1/p')"
chk "the source AMI owner is a pinned 12-digit account" yes \
    "$([ -n "$owner_default" ] && echo yes || echo no)"
chk "the source AMI name filter excludes the -metal- variant" yes \
    "$(grep -qE 'name[[:space:]]*=[[:space:]]*"alpine-.*-uefi-cloudinit-r\*"' "$PKR" && echo yes || echo no)"

echo "=== 12. the Packer template validates against the real plugin ==="
# ⚠️ -syntax-only IS NOT ENOUGH, and this cell exists because it was not. A syntax check
# parses HCL and stops; it does not ask the amazon plugin whether a provisioner argument
# exists. The first version of this template passed -syntax-only while giving the `file`
# provisioner an `exclude` argument it does not have — the build would have failed on the
# first real run, after the plugin download and the AMI lookup.
if command -v packer >/dev/null 2>&1; then
    # `packer init` is deliberately NOT run here: a suite must not reach the network. If
    # the plugin is absent, say so rather than pass on a check that did not happen.
    vout="$(cd "$ROOT" && packer validate -var release=test deploy/cloud/image 2>&1)"
    case "$vout" in
      *"The configuration is valid"*)
        chk "packer validate accepts the template" ok ok ;;
      *"Missing plugins"*|*"required_plugin"*|*"install missing plugins"*)
        echo "  [SKIP] packer validate — the amazon plugin is not installed (packer init)"
        skip=$((skip+1)) ;;
      *)
        chk "packer validate accepts the template" ok "$(printf '%s' "$vout" | tr '\n' ' ' | cut -c1-160)" ;;
    esac
else
    echo "  [SKIP] packer validate — packer is not installed on this host"
    skip=$((skip+1))
fi

echo "=== 13. a wait loop in the local checks branches on a real exit status ==="
# dexq ends in `|| true`, so it always succeeds: a loop that breaks on it either stops at once
# (`&& break`) or never early (`|| break`). The switch-on cell of run-check.sh asked once,
# before the service's 10s re-check, and reported a service that came back seconds later as
# failed. A loop condition must use dexs, which returns the command's own status.
_bad=$(grep -nE "dexq +'[^']*' *(&&|\|\|) *break" "$NAT/run-check.sh" "$ROOT/deploy/cloud/boot-check.sh" 2>/dev/null | wc -l | tr -d ' ')
chk "no wait loop breaks on dexq"                      0   "$_bad"
chk "PRECONDITION: run-check.sh has wait loops on dexs" yes "$(grep -qE "dexs +'[^']*' *&& *break" "$NAT/run-check.sh" && echo yes || echo no)"
_t="$(mktemp)"; printf '%s\n' "    dexq 'netstat -lnt | grep -q \":8080 \"' && break" > "$_t"
chk "PRECONDITION: the matcher fires on a planted loop" 1 "$(grep -cE "dexq +'[^']*' *(&&|\|\|) *break" "$_t")"
rm -f "$_t"

echo
echo "=== NATIVE DEPLOY: PASS=$pass FAIL=$fail SKIP=$skip ==="
[ "$fail" -eq 0 ] || exit 1
