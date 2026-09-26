#!/usr/bin/env bash
# REAL Windows enrolment against a real domain-joined client — the only path we ship that no
# other suite can reach.
#
# ⚠️ WHY tests/ms_*.sh IS NOT ENOUGH. Those suites drive our own SOAP against our own server.
# They prove the policy document is well-formed and that WSTEP issues, and they are genuinely
# useful — but they prove nothing about whether a Windows client will ACCEPT what we send.
# Everything below was found only by driving `certreq`/`certutil` on a real client:
#
#   * an authenticated identity with no template grant got a 200 carrying an EMPTY <policies>
#     list, which Windows reports as WS_E_INVALID_FORMAT / ERROR_INVALID_PARAMETER — an error
#     naming nothing about permissions. Rounds of investigation went into the template
#     metadata, which was never the problem.
#   * OCSP responses were stamped `thisUpdate = now`, so a client whose clock lagged ours by
#     SECONDS rejected every one of them. `openssl ocsp` applies a 300s tolerance and had
#     always said "Response verify OK", so no suite we had could see it.
#   * a CA certificate advertised an AIA OCSP URI its issuer could not answer, because an
#     offline root has no responder credential.
#
# None of those are visible from shell. That is what this suite is for.
#
# ⚠️ IT MUST NOT SKIP WHEN SELECTED. `deploy/rolling-update.sh` once guarded its whole
# verification behind `[ -x lab-test.sh ]` on a file committed 100644, so the check never ran
# while deploys reported success. A suite that quietly does nothing is worse than one that is
# absent. When its prerequisites are missing this FAILS and names which one.
#
# SAFETY. It registers a policy server and enrols certificates on a shared lab client. The
# EXIT trap always unregisters, removes the certificates it recorded issuing, and clears the
# policy cache — on Ctrl-C, a failed assertion or an SSH timeout. Certificates it REVOKED are
# left revoked: revocation happens on the CA and is the honest end state of a revocation
# test; un-revoking to tidy up would destroy the evidence.
#
# Opt-in: needs the lab and a domain-joined Windows client, so it is not in the default
# tiers. Run it explicitly, or with RUN_LAB=1.
#
#   WIN_HOST=<the domain-joined client>             \
#   WIN_USER='<DOMAIN>\<admin>'                     \
#   WIN_PW='<that account's password>'              \
#   XCEP_URL=https://<pki-host>:8446/msxcep/<ca_id> \
#   CONSOLE=https://<pki-host>:8090                 \
#   CONSOLE_USER=<console admin> CONSOLE_PW=<pw>    \
#   ROOT_THUMBPRINT=<sha1 of the root DER>          \
#   SUB_THUMBPRINT=<sha1 of the issuing CA DER>     \
#   bash tests/windows_enrolment.sh
#
# WIN_KEY defaults to ~/.ssh/fastpki_lab_ed25519. WIN_PW is separate from the key and is
# not redundant: a key-authenticated session holds no Kerberos credential (see below), so
# the sections that must authenticate OUTWARD need a password logon.
#
# Read the two thumbprints back from the LIVE deployment every time — they are SHA-1 of the
# DER, which is what the Windows certificate store keys on, and a rebuilt lab changes them
# while the stale ones stay perfectly plausible:
#
#   curl -s http://<pki-host>:8080/<ca_id>.crt \
#     | openssl x509 -inform DER -noout -fingerprint -sha1
set -u

ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1));
       else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }

# ── prerequisites, each named individually ──────────────────────────────────────────
# ⚠️ NAMED, NOT COUNTED. "prerequisites missing" sends the reader to check all of them; the
# whole value of this block is saying WHICH one.
WIN_HOST="${WIN_HOST:-}"
WIN_USER="${WIN_USER:-}"
XCEP_URL="${XCEP_URL:-}"
CONSOLE="${CONSOLE:-}"
WIN_KEY="${WIN_KEY:-$HOME/.ssh/fastpki_lab_ed25519}"
# ⚠️ ALL NINE, NOT FOUR. The gate used to check these five and let the other four arrive as
# empty strings deep in the run, where each produced a failure that named something else:
# a missing SUB_THUMBPRINT skipped four trust assertions AND left section 9 unable to
# identify the CA; missing console credentials reported themselves as a revocation fault;
# a missing WIN_PW surfaced as a Kerberos error. A by-the-book run of the header's own
# command therefore produced at least five failures on a perfectly healthy deployment,
# which is exactly the "suite that measures nothing" this file's header objects to.
#
# The thumbprints are SHA-1 of the DER, which is what the Windows store keys on. Read them
# back from the LIVE CA — a rebuilt lab changes them and the old ones still look plausible:
#   curl -s http://<pki-host>:8080/<ca_id>.crt | openssl x509 -inform DER -noout -fingerprint -sha1
ROOT_THUMBPRINT="${ROOT_THUMBPRINT:-}"
SUB_THUMBPRINT="${SUB_THUMBPRINT:-}"
CONSOLE_USER="${CONSOLE_USER:-}"
CONSOLE_PW="${CONSOLE_PW:-}"
WIN_PW="${WIN_PW:-}"

miss=""
[ -n "$WIN_HOST" ] || miss="$miss WIN_HOST"
[ -n "$WIN_USER" ] || miss="$miss WIN_USER"
[ -n "$XCEP_URL" ] || miss="$miss XCEP_URL"
[ -n "$CONSOLE"  ] || miss="$miss CONSOLE"
[ -f "$WIN_KEY"  ] || miss="$miss WIN_KEY($WIN_KEY)"
[ -n "$ROOT_THUMBPRINT" ] || miss="$miss ROOT_THUMBPRINT"
[ -n "$SUB_THUMBPRINT"  ] || miss="$miss SUB_THUMBPRINT"
[ -n "$CONSOLE_USER" ]  || miss="$miss CONSOLE_USER"
[ -n "$CONSOLE_PW" ]    || miss="$miss CONSOLE_PW"
[ -n "$WIN_PW" ]        || miss="$miss WIN_PW(needed for an outbound Kerberos ticket)"
if [ -n "$miss" ]; then
    echo "  [FAIL] windows_enrolment: missing prerequisites:$miss"
    echo "         This suite drives a real domain-joined Windows client and cannot be"
    echo "         simulated. It FAILS rather than skips when selected — see the header."
    echo; echo "=== WINDOWS ENROLMENT: PASS=0 FAIL=1 ==="; exit 1
fi

# ── the two SSH modes, and why both are needed ──────────────────────────────────────
# ⚠️ KEY AUTH CANNOT GET A KERBEROS TICKET. Measured on the lab client: a key-authenticated
# session holds no credential, so asking for a ticket to any service principal fails with
# 0x8009030e "No credentials are available in the security package" — the classic double hop. Anything that must
# authenticate OUTWARD (certreq to our MS-XCEP endpoint over SPNEGO) therefore cannot run in
# a key session, and would fail 401 in a way that reads as a keytab or server fault.
#
# So: key auth drives and tears down; machine enrolment runs as SYSTEM via a scheduled task,
# which holds the machine account's own ticket and is what autoenrolment does anyway.
# ⚠️ ONE TCP CONNECTION, REUSED. A full run makes well over a hundred SSH connections —
# forty-odd call sites, and every as_system() is an scp plus a session that registers,
# starts, polls and unregisters a scheduled task. Windows OpenSSH does not take that churn
# well: measured twice on the lab client, sshd stopped accepting mid-run and the host then
# needed a reset from the hypervisor, which reads as an unreachable client rather than as
# something this suite did to it.
#
# ControlMaster multiplexes every later session over the first connection, so the run costs
# one handshake instead of a hundred. ControlPersist keeps it briefly after the last
# session so consecutive calls do not each rebuild it; cleanup() closes it explicitly.
SSH_CTL="${TMPDIR:-/tmp}/fpki-win-ctl-$$"
# ⚠️ ConnectTimeout BOUNDS ONLY THE HANDSHAKE. Once a session is established, an SSH that
# stops receiving simply waits — forever. That is the exact failure this suite provokes:
# when the Windows client stopped accepting new connections mid-run, the session already
# open hung, the suite hung with it, and killing the script left an orphaned ssh talking to
# a dead host for an hour and a half. ServerAliveInterval/CountMax is what turns an
# unresponsive peer into a failed command after ~60s, so the suite FAILS rather than hangs
# and its assertion can say which host went away.
psk(){ ssh -i "$WIN_KEY" -o BatchMode=yes -o ConnectTimeout=20 \
           -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
           -o ControlMaster=auto -o ControlPath="$SSH_CTL" -o ControlPersist=120 \
           -o StrictHostKeyChecking=accept-new "$WIN_USER@$WIN_HOST" "$@" 2>&1; }

# Run a PowerShell block as SYSTEM and return its output. The task is removed even if the
# command fails, so a failed assertion cannot leave a scheduled task behind.
#
# ⚠️ THE COMMAND GOES OVER AS A FILE, NOT AS AN ARGUMENT STRING. The first version built the
# task action by concatenating the caller's command into a single-quoted PowerShell string:
#
#     -Argument ('-NoProfile -Command "' + '<cmd>' + ' *> out"')
#
# Every command this suite actually needs contains single quotes — a URL, 'ADD OK', an
# error prefix — and a single quote inside a single-quoted PowerShell string has to be
# DOUBLED. So the task argument was malformed and the task died parsing itself:
#
#     + FullyQualifiedErrorId : UnexpectedToken
#
# which surfaced as "the policy server did not register" and reads exactly like a server
# fault. Copying the block to a .ps1 and running -File removes the quoting question rather
# than answering it: the argument string is now a constant with no caller content in it.
#
# The redirection has to live INSIDE the script. New-ScheduledTaskAction does not go through
# a shell, so a `*>` in -Argument is passed to powershell.exe as a literal parameter.
as_system(){   # <powershell-command>
    local tn="FastPKIEnrolSuite" tmp
    tmp=$(mktemp)
    {
        printf '%s\n' '& {'
        printf '%s\n' "$1"
        printf '%s\n' "} *> 'C:\\Windows\\Temp\\fpki_sys.txt'"
    } > "$tmp"
    # Forward slashes: OpenSSH on Windows accepts them and they survive the shell here,
    # where a backslash path would need escaping at three levels.
    scp -i "$WIN_KEY" -o BatchMode=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o ControlMaster=auto -o ControlPath="$SSH_CTL" -o ControlPersist=120 -q "$tmp" \
        "$WIN_USER@$WIN_HOST:C:/Windows/Temp/fpki_sys.ps1" 2>/dev/null || {
            rm -f "$tmp"; echo "as_system: could not copy the command to the client"; return 1; }
    rm -f "$tmp"
    psk "Remove-Item 'C:\\Windows\\Temp\\fpki_sys.txt' -EA SilentlyContinue;
         \$a = New-ScheduledTaskAction -Execute 'powershell.exe' \
              -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\fpki_sys.ps1';
         Register-ScheduledTask -TaskName $tn -Action \$a -User SYSTEM -RunLevel Highest -Force | Out-Null;
         Start-ScheduledTask -TaskName $tn;
         \$n=0; while ((Get-ScheduledTask -TaskName $tn).State -ne 'Ready' -and \$n -lt 40) { Start-Sleep 1; \$n++ };
         Start-Sleep 2;
         Get-Content 'C:\\Windows\\Temp\\fpki_sys.txt' -EA SilentlyContinue;
         Unregister-ScheduledTask -TaskName $tn -Confirm:\$false -EA SilentlyContinue"
}

# Which template is imported, which role the enrolling identity holds, and how the client
# names itself. Overridable because a different domain publishes a different set.
#
# ⚠️ NOT a template that grants CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT. `WebServer` was the
# obvious pick — a V1 template certreq can drive without an INF — and it carries
# subject_name_flags 0x1, so certreq's subject-less request produced a certificate with an
# EMPTY subject and no SAN, which issuance now refuses outright. That refusal is correct and
# it is what this default avoids: `Machine` has the CA build the name from the authenticated
# principal, so the section tests the import rather than a naming edge case. It also proves
# the point more strongly, since the name then comes from the DIRECTORY's flags and not from
# anything the client chose.
AD_TMPL="${AD_TMPL:-Machine}"
ENROL_ROLE="${ENROL_ROLE:-requester}"
WIN_CN="${WIN_CN:-$(printf '%s' "$WIN_HOST" | cut -d. -f1)}"
AD_IMPORTED=0; AD_GRANTED=0; AD_GRANTS_WAS=""

# ⚠️ AN IMPORT IS NOT SERVED UNTIL fastpki-ms RESTARTS. The template list is read once in
# main() and nothing re-reads it, so a test that imports and then enrols without this in
# between is measuring the PREVIOUS set — and will pass while proving the opposite of what
# it claims.
#
# ⚠️ AND IT MUST WAIT FOR THE RESTART TO HAPPEN. The restart is a clean exit and a respawn,
# so for a moment there is still a listener on the port: the OLD process. Returning as soon
# as something answers hands the next step the very process that was supposed to go away,
# and the enrolment then fails against a template set that is one restart out of date. So
# wait for the listener to DISAPPEAR first, then for it to come back.
restart_ms(){
    local base="${XCEP_URL%/msxcep/*}" n=0
    capi -X POST "$CONSOLE/api/endpoints/ms/restart" -o /dev/null >/dev/null 2>&1 || true
    while [ "$n" -lt 20 ]; do
        curl -sk -o /dev/null --max-time 1 "$base/" >/dev/null 2>&1 || break
        n=$((n+1)); sleep 1
    done
    n=0
    while [ "$n" -lt 60 ]; do
        curl -sk -o /dev/null --max-time 2 "$base/" >/dev/null 2>&1 && return 0
        n=$((n+1)); sleep 1
    done
    return 1
}

# Run a PowerShell block under a REAL logon as WIN_USER, and return its output.
#
# ⚠️ NOT psk, AND THE DIFFERENCE IS NOT COSMETIC. A key-authenticated OpenSSH session has no
# network credentials: outbound SPNEGO produces nothing, our XCEP logs "401 — no accepted
# credential (none offered)", and the client reports WS_E_ENDPOINT_ACCESS_DENIED. A
# scheduled task started with -User/-Password performs a batch logon, which does have them.
#
# ⚠️ The password is passed to Register-ScheduledTask and never echoed, never written to the
# script file, and never logged. The script file holds only the command being run.
as_user(){   # <powershell-command>
    local tn="FastPKIEnrolUser" tmp
    tmp=$(mktemp)
    {
        printf '%s\n' '& {'
        printf '%s\n' "$1"
        printf '%s\n' "} *> 'C:\\Windows\\Temp\\fpki_usr.txt'"
    } > "$tmp"
    scp -i "$WIN_KEY" -o BatchMode=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o ControlMaster=auto -o ControlPath="$SSH_CTL" -o ControlPersist=120 -q "$tmp" \
        "$WIN_USER@$WIN_HOST:C:/Windows/Temp/fpki_usr.ps1" 2>/dev/null || {
            rm -f "$tmp"; echo "as_user: could not copy the command to the client"; return 1; }
    rm -f "$tmp"
    psk "Remove-Item 'C:\\Windows\\Temp\\fpki_usr.txt' -EA SilentlyContinue;
         \$a = New-ScheduledTaskAction -Execute 'powershell.exe' \
              -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\fpki_usr.ps1';
         Register-ScheduledTask -TaskName $tn -Action \$a -User '$WIN_USER' -Password '$WIN_PW' -RunLevel Highest -Force | Out-Null;
         Start-ScheduledTask -TaskName $tn;
         \$n=0; while ((Get-ScheduledTask -TaskName $tn).State -ne 'Ready' -and \$n -lt 60) { Start-Sleep 1; \$n++ };
         Start-Sleep 2;
         Get-Content 'C:\\Windows\\Temp\\fpki_usr.txt' -EA SilentlyContinue;
         Unregister-ScheduledTask -TaskName $tn -Confirm:\$false -EA SilentlyContinue" | tr -d '\r'
}
# The SAM account name the certificate should be issued to — the USER half of the
# provider-qualified identity, which is what lands in the CN.
WIN_SAM="${WIN_SAM:-$(printf '%s' "$WIN_USER" | sed 's/.*\\//')}"
ISSUED_USER=""
USER_REG=0

cleanup(){
    # ⚠️ THE CHAIN-CACHE RESYNC STAMP IS PERSISTENT STATE TOO, and it was the one thing this
    # suite changed and never put back. `certutil -setreg chain\ChainCacheResyncFiletime @now`
    # writes an HKLM value under CertDllCreateCertificateChainEngine\Config that forces every
    # chain build on the machine to re-fetch — it is not a cache flush despite reading like
    # one, and it outlives the run on a shared client. AEPolicy below is captured and
    # restored with care; this deserves the same treatment.
    if [ "${CHAINSTAMP_SET:-0}" = 1 ]; then
        psk '& certutil -delreg chain\ChainCacheResyncFiletime | Out-Null' >/dev/null 2>&1 || true
    fi
    # AEPolicy is client-wide Group-Policy state, so it goes back exactly as it was —
    # removed if it was absent, restored to its old value if it had one.
    if [ "${AE_SET:-0}" = 1 ]; then
        if [ -n "${AE_WAS:-}" ]; then
            as_system "Set-ItemProperty -Path '$AE_KEY' -Name AEPolicy -Value $AE_WAS -Type DWord" >/dev/null 2>&1 || true
        else
            as_system "Remove-ItemProperty -Path '$AE_KEY' -Name AEPolicy -EA SilentlyContinue" >/dev/null 2>&1 || true
        fi
    fi
    # The user context is a separate registration with its own cache and its own store, so
    # unregistering the machine one above leaves it behind on a shared client.
    if [ "${USER_REG:-0}" = 1 ] && [ -n "${WIN_PW:-}" ]; then
        for s in $ISSUED_USER; do
            as_user "Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { \$_.SerialNumber -eq '$s' } | Remove-Item -Force" >/dev/null 2>&1 || true
        done
        as_user "Remove-CertificateEnrollmentPolicyServer -Url '$XCEP_URL' -Context User -EA SilentlyContinue; certutil -f -user -policyserver * -policycache delete" >/dev/null 2>&1 || true
    fi
    # ⚠️ THE AD HALF, UNDONE IN REVERSE. Leaving an imported row behind is not untidy, it is
    # DESTRUCTIVE: while ms_templates is non-empty the three built-in templates are not
    # served at all, so a run that died mid-way would leave the lab unable to enrol what it
    # could enrol before. The role and its binding go too — a test that grants rights to a
    # machine account and leaves them is a test that changed the deployment.
    if [ -n "${CJAR:-}" ]; then
        [ "${AD_BOUND:-0}" = 1 ] && curl -sk -b "$CJAR" -X DELETE "$CONSOLE/api/subject-roles" \
             -d "selector_type=user" --data-urlencode "selector_value=$AD_SUBJ" \
             -d "role=$AD_ROLE" >/dev/null 2>&1
        [ "${AD_ROLE_MADE:-0}" = 1 ] && curl -sk -b "$CJAR" -X DELETE \
             "$CONSOLE/api/roles/$AD_ROLE" >/dev/null 2>&1
        [ "${AD_IMPORTED:-0}" = 1 ] && curl -sk -b "$CJAR" -X DELETE \
             "$CONSOLE/api/templates/$AD_TMPL" >/dev/null 2>&1
        [ "${AD_IMPORTED:-0}" = 1 ] && curl -sk -b "$CJAR" -X POST \
             "$CONSOLE/api/endpoints/ms/restart" >/dev/null 2>&1
    fi
    # ⚠️ ALWAYS, and BEFORE the summary — a suite that leaves a policy server registered on a
    # shared client changes the next run's starting state.
    psk "& '$PSSCRIPT' -Url '$XCEP_URL' -Unregister -RemoveCerts" >/dev/null 2>&1 || true
    # ⚠️ -RemoveCerts CANNOT SEE WHAT THIS SUITE ISSUED. It deletes only the rows
    # Record-IssuedCert wrote into C:\ProgramData\FastPKI\enrolled.json, and every
    # enrolment here drives `certreq` directly rather than going through that script — so
    # the state file does not exist and the teardown prints "no record, nothing removed"
    # while sections 9 and 10 leave about eleven machine certificates behind PER RUN on a
    # shared client.
    #
    # Remove them by issuer instead, through X509Store: piping to Remove-Item silently
    # removes almost none (measured elsewhere in this file: 59 in, 58 left). Only ever
    # scoped to THIS CA's name, and only when that name is actually known — an empty
    # filter would match every certificate on the machine.
    if [ -n "${CA_CN:-}" ]; then
        as_system "\$s = New-Object System.Security.Cryptography.X509Certificates.X509Store('My','LocalMachine');
                   \$s.Open('ReadWrite');
                   @(\$s.Certificates | Where-Object { \$_.Issuer -match [regex]::Escape('$CA_CN') }) | ForEach-Object { \$s.Remove(\$_) };
                   \$s.Close()" >/dev/null 2>&1 || true
    fi
    psk "& certutil -PolicyCache delete; & certutil -PolicyCache -User delete" >/dev/null 2>&1 || true
    # Close the multiplexed connection explicitly rather than leaving ControlPersist to
    # expire: the socket outlives the run otherwise, and a second run inheriting a
    # half-dead master is a confusing way to start.
    ssh -O exit -o ControlPath="$SSH_CTL" "$WIN_USER@$WIN_HOST" >/dev/null 2>&1 || true
}
PSSCRIPT='C:\Windows\Temp\Register-FastPKIEnrollment.ps1'
trap cleanup EXIT

echo "=== 1. the client is who we think it is ==="
WHO=$(psk 'whoami' | tr -d '\r' | tail -1)
# ⚠️ MATCH THE ANSWER, DO NOT MERELY CHECK FOR ONE. psk() merges stderr into stdout (2>&1),
# which every other caller here depends on to read certreq's diagnostics — so "Connection
# timed out", "Permission denied (publickey)" and "ssh: command not found" all arrive as
# non-empty output. Asserting non-emptiness made the suite's FIRST gate unable to fail: an
# unreachable client sailed past it and was caught two lines later by the domain check,
# which then reported the wrong cause. `whoami` on a domain-joined box answers
# `domain\user`, so require the backslash.
# ⚠️ COMPUTED ON ITS OWN LINE, not inside the `chk` argument. Matching one literal
# backslash is fiddly enough on its own; doing it inside a command substitution inside a
# quoted argument added two more layers and this line was wrong TWICE. `grep -q '\\\\'`
# asks for two backslashes and never matched `fastpki\administrator`; a `case` glob then
# broke because the `)` closed the `$( )` early and the assertion compared against literal
# shell text. Both failed in the direction that looks like a broken client.
REACHED=no
case "$WHO" in *\\*) REACHED=yes ;; esac
chk "key auth reaches the client" yes "$REACHED"
[ -n "$WHO" ] && printf '     client answered: %s\n' "$WHO"
DOM=$(psk '(Get-CimInstance Win32_ComputerSystem).PartOfDomain' | tr -d '\r' | tail -1)
chk "  and it is domain-joined" "True" "$DOM"
# ⚠️ NOT $env:USERDNSDOMAIN. An SSH session is a network logon and does not carry the
# environment an interactive desktop would; keying off it reports "no domain" on a joined
# machine.
PSV=$(psk '$PSVersionTable.PSVersion.Major' | tr -d '\r' | tail -1)
chk "  PowerShell is available" yes "$([ -n "$PSV" ] && echo yes || echo no)"

echo
echo "=== 2. TRUST: the anchors are the ones this CA actually uses ==="
# ⚠️ BY THUMBPRINT, NEVER BY NAME. A deployment that has been rebuilt leaves anchors from
# previous generations behind, and their subject names are as plausible as the current ones —
# same organisation, same naming scheme, differing only in a generation suffix. A name-based
# check passes while the client still trusts several CAs that no longer exist. Measured: a
# client trusting three dead CAs alongside the live one, every name looking correct.
ROOT_TP="${ROOT_THUMBPRINT:-}"
SUB_TP="${SUB_THUMBPRINT:-}"
if [ -z "$ROOT_TP" ] || [ -z "$SUB_TP" ]; then
    echo "  [FAIL] ROOT_THUMBPRINT / SUB_THUMBPRINT not given — trust cannot be asserted by"
    echo "         name (see above), so this suite will not guess. Take them from the CA:"
    echo "         curl -sk -b <jar> $CONSOLE/api/ca-instances/<id>/cert-pem \| openssl x509 -noout -fingerprint -sha1"
    fail=$((fail+1))
else
    IN_ROOT=$(psk "(Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { \$_.Thumbprint -eq '$ROOT_TP' }).Count" | tr -d '\r' | tail -1)
    chk "the CA root is in LocalMachine\\Root" 1 "$IN_ROOT"
    SELF=$(psk "(Get-Item Cert:\\LocalMachine\\Root\\$ROOT_TP -EA SilentlyContinue | ForEach-Object { \$_.Subject -eq \$_.Issuer })" | tr -d '\r' | tail -1)
    chk "  and it is self-signed, as a root must be" "True" "$SELF"
    IN_CA=$(psk "(Get-ChildItem Cert:\\LocalMachine\\CA | Where-Object { \$_.Thumbprint -eq '$SUB_TP' }).Count" | tr -d '\r' | tail -1)
    chk "the issuing CA is in LocalMachine\\CA" 1 "$IN_CA"
    # ⚠️ AND NOT ALSO IN Root. A non-self-signed certificate in the Trusted Root store makes
    # the chain terminate at the intermediate instead of the root. Found on this client: it
    # produced a two-element chain and broke OCSP responder validation, while every name in
    # the store looked correct.
    SUB_IN_ROOT=$(psk "(Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { \$_.Thumbprint -eq '$SUB_TP' }).Count" | tr -d '\r' | tail -1)
    chk "  and NOT also in Root (it is not self-signed)" 0 "$SUB_IN_ROOT"
fi

echo
echo "=== 3. the policy server registers, which means the policy is ACCEPTABLE ==="
# ⚠️ THIS ASSERTION IS THE ONE THAT CAUGHT THE EMPTY-POLICY DEFECT.
# Add-CertificateEnrollmentPolicyServer runs the same validator certreq uses, and it refuses a policy carrying zero templates with
# WS_E_INVALID_FORMAT — an error that names nothing about permissions. certutil's reader is
# more lenient and reads the identical document happily, which is why reading the policy is
# NOT a sufficient check.
scp -i "$WIN_KEY" -o BatchMode=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o ControlMaster=auto -o ControlPath="$SSH_CTL" -o ControlPersist=120 -q "$ROOT/deploy/windows/Register-FastPKIEnrollment.ps1" \
    "$WIN_USER@$WIN_HOST:$PSSCRIPT" 2>/dev/null || true
psk "& certutil -PolicyCache delete; & certutil -PolicyCache -User delete" >/dev/null 2>&1
REG=$(as_system "try { Add-CertificateEnrollmentPolicyServer -Url '$XCEP_URL' -Context Machine -AutoEnrollmentEnabled -ErrorAction Stop | Out-Null; 'ADD OK' } catch { 'ADD FAILED: ' + \$_.Exception.Message }" | tr -d '\r')
chk "the machine-context policy server registers" yes "$(echo "$REG" | grep -q 'ADD OK' && echo yes || echo no)"
if ! echo "$REG" | grep -q 'ADD OK'; then
    echo "      $(echo "$REG" | grep -i 'ADD FAILED' | head -1)"
    echo "      WS_E_INVALID_FORMAT here usually means the policy carried NO templates —"
    echo "      check the server log for 'XCEP offering 0 of N templates'."
fi

echo
echo "=== 4. an unattended machine enrolment issues a certificate ==="
# As SYSTEM, which is what autoenrolment is. A user-context certreq over SSH fails NTE_PERM:
# a network logon has no profile and cannot create a user key container — a client-side fact,
# not a server fault.
# ⚠️ THE THUMBPRINTS, NOT THE COUNT — and sections 5 and 6 must use the certificate THIS
# enrolment produced. They used to take "the newest thing in LocalMachine\My", which is a
# different statement: on a client that has ever been enrolled by hand, that is a stale
# certificate, and both sections then PASS while enrolment is broken. Measured on this
# client — section 4 failed to issue anything and sections 5 and 6 still went green against
# a certificate left over from an earlier session, which is precisely the shape of test that
# is more forgiving than the thing it is testing.
BEFORE=$(psk 'Get-ChildItem Cert:\LocalMachine\My | ForEach-Object { $_.Thumbprint }' | tr -d '\r')
ENR=$(as_system "& certreq -q -enroll -machine -policyserver '$XCEP_URL' GenericComputer" | tr -d '\r')
AFTER=$(psk 'Get-ChildItem Cert:\LocalMachine\My | ForEach-Object { $_.Thumbprint }' | tr -d '\r')
# The one thumbprint present now and absent before. Empty when nothing was issued.
NEW_TP=""
for t in $AFTER; do
    case " $BEFORE " in *" $t "*) ;; *) NEW_TP="$t" ;; esac
done
# ⚠️ A THUMBPRINT THAT IS NEW TO THE STORE IS NOT NECESSARILY A NEW CERTIFICATE. Windows
# re-installs a certificate it already holds for an existing key container, so a
# previously-issued — and by then REVOKED — certificate reappears and the before/after
# diff reports it as this run's. Measured: section 5 verified a certificate issued 45
# minutes and two runs earlier, whose status was already -1, and reported our OCSP as
# broken. The responder was answering perfectly: it said `Revoked`, because it was.
#
# certreq prints the serial it actually received, so prefer selecting by that. The diff
# stays as the fallback for a client that printed nothing, and the serial is carried
# forward so section 6 revokes the certificate this run really got.
ENR_SER=$(printf '%s' "$ENR" | grep -oE 'Serial Number: [0-9a-fA-F]+' | head -1 | sed 's/.*: //')
if [ -n "$ENR_SER" ]; then
    TP_BY_SER=$(psk "(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { \$_.SerialNumber -eq '$ENR_SER' } | Select-Object -First 1).Thumbprint" | tr -d '\r' | tail -1)
    [ -n "$TP_BY_SER" ] && NEW_TP="$TP_BY_SER"
fi
chk "certreq reports the certificate issued" yes \
    "$(echo "$ENR" | grep -qi 'has been issued' && echo yes || echo no)"
chk "  and a NEW certificate appeared in the machine store" yes \
    "$([ -n "$NEW_TP" ] && echo yes || echo no)"
[ -n "$NEW_TP" ] || echo "      $(echo "$ENR" | tail -3 | head -2)"

echo
echo "=== 5. the issued certificate VERIFIES, through the Windows revocation stack ==="
# ⚠️ THIS IS OUR OCSP AND OUR CRL, REACHED AS A WINDOWS CLIENT REACHES THEM — following the
# AIA and CDP the certificate itself carries, not a URL the test supplies.
if [ -z "$NEW_TP" ]; then
    # ⚠️ FAIL, DO NOT FALL BACK. There is nothing this section can honestly say about a
    # certificate that was never issued, and saying it about some other certificate is how
    # section 4 failed while 5 and 6 reported success.
    echo "  [FAIL] no certificate was issued in section 4, so there is nothing to verify"
    echo "         (this section refuses to fall back to another certificate in the store)"
    fail=$((fail+1))
else
psk "Get-Item Cert:\\LocalMachine\\My\\$NEW_TP | ForEach-Object { [IO.File]::WriteAllBytes('C:\\Windows\\Temp\\fpki_v.cer', \$_.RawData) }" >/dev/null 2>&1
VER=$(psk '& certutil -urlcache * delete | Out-Null; & certutil -urlfetch -verify C:\Windows\Temp\fpki_v.cer' | tr -d '\r')
chk "the chain verifies with no error status" yes \
    "$(echo "$VER" | grep -q 'dwErrorStatus=0' && echo yes || echo no)"
# ⚠️ ASSERT BOTH PATHS SEPARATELY. certutil uses OCSP or the CRL depending on what the
# certificate carries and what answers first, so a single "it verified" can pass while our
# responder is dead and the CRL carries the whole result.
chk "  the CRL was fetched and verified" yes \
    "$(echo "$VER" | grep -q 'Verified "Base CRL' && echo yes || echo no)"
chk "  the OCSP response was fetched and verified" yes \
    "$(echo "$VER" | grep -q 'Verified "OCSP"' && echo yes || echo no)"
# thisUpdate must be BACKDATED or a client whose clock lags ours refuses every response —
# and openssl would never tell us, because it applies a 300s tolerance of its own.
echo "$VER" | grep -q 'Expired "OCSP"' && \
    echo "      OCSP reported Expired — check that thisUpdate is backdated (kClockSkewBackdateSec)"
fi

echo
echo "=== 6. REVOCATION reaches the client ==="
# ⚠️ VERIFY GOOD FIRST. Without it, a client that cannot reach our CDP/AIA at all looks
# exactly like a working one, right up until the revoked assertion fails for the wrong reason.
# The serial of THAT certificate, by its thumbprint — same reason as section 5.
SER=""
[ -n "$NEW_TP" ] && SER=$(psk "(Get-Item Cert:\\LocalMachine\\My\\$NEW_TP).SerialNumber" | tr -d '\r' | tail -1)
chk "PRECONDITION: we have the issued certificate's serial to revoke" yes \
    "$([ -n "$SER" ] && echo yes || echo no)"
if [ -n "$SER" ] && [ -n "${CONSOLE_USER:-}" ] && [ -n "${CONSOLE_PW:-}" ]; then
    JAR=$(mktemp)
    curl -sk -c "$JAR" -o /dev/null -X POST --data-urlencode "username=$CONSOLE_USER" \
         --data-urlencode "password=$CONSOLE_PW" "$CONSOLE/api/login" 2>/dev/null
    RC=$(curl -sk -b "$JAR" -o /dev/null -w '%{http_code}' -X POST \
         "$CONSOLE/api/certs/$(echo "$SER" | tr 'A-F' 'a-f' | sed 's/^0*//')/revoke" 2>/dev/null)
    chk "the CA accepted the revocation" yes "$([ "$RC" = 200 ] && echo yes || echo no)"
    # ⚠️ FLUSH BOTH CACHES. Windows honours the nextUpdate WE stamp: an hour for OCSP and
    # CRL_NEXT_UPDATE_DAYS for the CRL. Without this the client keeps answering `good` from a
    # response we told it was still valid, and the test reads that as broken revocation.
    psk '& certutil -urlcache * delete | Out-Null; & certutil -setreg chain\ChainCacheResyncFiletime @now | Out-Null' >/dev/null 2>&1
    CHAINSTAMP_SET=1     # persistent HKLM state — cleanup() removes it again
    VER2=$(psk '& certutil -urlfetch -verify C:\Windows\Temp\fpki_v.cer' | tr -d '\r')
    chk "  and the client now reports it REVOKED" yes \
        "$(echo "$VER2" | grep -qiE 'revoked|CERT_TRUST_IS_REVOKED' && echo yes || echo no)"
    rm -f "$JAR"
else
    # ⚠️ SAY WHICH OF THE THREE IS ACTUALLY MISSING. This branch is reached whenever the
    # credentials are absent OR no certificate was issued to revoke — and the second is the
    # normal outcome of a wrong XCEP_URL, a stopped endpoint or a missing grant. Blaming
    # variables the operator did set is precisely the shape of failure this suite's header
    # says it exists to prevent.
    if [ -z "$SER" ]; then
        echo "  [FAIL] no certificate was issued earlier, so there is nothing to revoke."
        echo "         The credentials are not the problem — section 4 did not produce a"
        echo "         serial. Check XCEP_URL, that fastpki-ms is up, and that the enrolling"
        echo "         identity holds template:use and ms:enrol."
    else
        echo "  [FAIL] CONSOLE_USER / CONSOLE_PW not given — the revocation half did not run,"
        echo "         so section 5 proved only that a GOOD certificate verifies. A revocation"
        echo "         check that never sees 'revoked' cannot tell a working responder from an"
        echo "         unreachable one."
    fi
    fail=$((fail+1))
fi

echo

# ── 7. TEMPLATES IMPORTED FROM THE REAL DIRECTORY ───────────────────────────────────
#
# ⚠️ THE ONLY PLACE THE DISCOVERY PATH RUNS AT ALL. tests/ad_template_import.sh proves the
# decoders against a throwaway slapd carrying AD's attribute NAMES, and says so: slapd will
# not serve `configurationNamingContext`, so that suite names the templates container
# directly. Asking the directory where its templates LIVE — the step that makes an import
# work on one domain and not the next — is covered nowhere but here.
#
# ⚠️ AND AN IMPORTED TEMPLATE IS NOT ONE OF OURS. It arrives with the directory's values: a
# legacy CryptoAPI provider, key_spec 1 or 2, schema 1 or 2, and name flags that arrive
# NEGATIVE (0xA6000000 reads as -1509949440). Every assertion below is about a template we
# did not write and cannot adjust to suit the test.
echo "=== 7. templates imported from the REAL directory ==="

if [ -z "${CONSOLE_USER:-}" ] || [ -z "${CONSOLE_PW:-}" ]; then
    echo "  [FAIL] CONSOLE_USER / CONSOLE_PW not given — the AD import half did not run,"
    echo "         and a half that does not run must not read as a pass."
    fail=$((fail+1))
else
CJAR="$(mktemp)"
capi(){ curl -sk -b "$CJAR" "$@"; }
curl -sk -c "$CJAR" -o /dev/null -X POST --data-urlencode "username=$CONSOLE_USER" \
     --data-urlencode "password=$CONSOLE_PW" "$CONSOLE/api/login" 2>/dev/null

AD_JSON="$(capi "$CONSOLE/api/templates/ad" 2>/dev/null)"
AD_COUNT="$(printf '%s' "$AD_JSON" | grep -oE '"count":[0-9]+' | head -1 | sed 's/.*://')"
chk "the directory answers a template query it was never given a base for" yes \
    "$([ -n "${AD_COUNT:-}" ] && [ "${AD_COUNT:-0}" -gt 0 ] && echo yes || echo no)"
chk "  and it offers the one this section imports" yes \
    "$(printf '%s' "$AD_JSON" | grep -q "\"name\":\"$AD_TMPL\"" && echo yes || echo no)"

# ⚠️ IMPORTING ANYTHING REPLACES THE BUILT-IN SET. fastpki-ms reads ms_templates once at
# startup and falls back to the built-ins only while that table is EMPTY, so a single
# imported row means the three built-ins stop being served at the next restart. That is why
# this section runs LAST, and why its teardown empties the table again.
IMP="$(capi -X POST -d "name=$AD_TMPL" "$CONSOLE/api/templates/ad" -o /dev/null -w '%{http_code}' 2>/dev/null)"
chk "the import succeeds" 200 "$IMP"
AD_IMPORTED=1
LIST="$(capi "$CONSOLE/api/templates" 2>/dev/null)"
chk "  and it is now a template WE serve, not just one AD has" yes \
    "$(printf '%s' "$LIST" | grep -q "\"name\":\"$AD_TMPL\"" && echo yes || echo no)"
TMPL_DAYS="$(printf '%s' "$LIST" | tr '{' '\n' | grep "\"name\":\"$AD_TMPL\"" \
             | grep -oE '"validity_days":[0-9]+' | head -1 | sed 's/.*://')"

# ⚠️ A TEMPLATE WITHOUT A GRANT IS INVISIBLE, AND THE CLIENT'S ERROR NAMES NOTHING ABOUT
# PERMISSIONS. XCEP answers 200 with the template simply absent from <policies>, and certreq
# reports "Template not found ... 0x80092004 (CRYPT_E_NOT_FOUND)", which sends the reader
# into the template metadata. Asserting the REFUSAL first is what makes the success below
# mean "the grant did it" rather than "it happened to work".
restart_ms
psk "& certutil -f -policyserver * -policycache delete" >/dev/null 2>&1 || true
NOGRANT="$(psk "\$r = certreq -q -enroll -machine -policyserver '$XCEP_URL' $AD_TMPL 2>&1; (\$r -join \"\`n\")" 2>/dev/null)"
chk "an imported template with NO grant cannot be enrolled" yes \
    "$(printf '%s' "$NOGRANT" | grep -qiE 'not found|0x80092004' && echo yes || echo no)"

# ⚠️ A ROLE OF ITS OWN, NOT AN EDIT TO THE ENROLLING ROLE — for two reasons, and the second
# one is a defect this suite found.
#
# First, POST /api/roles/<r>/permissions REPLACES the list wholesale, so amending a live role
# means rewriting every grant it holds and losing any that were not thought of.
#
# Second, amending it is currently IMPOSSIBLE once anything has been imported. The scope
# validator rejects a scope naming a template it cannot find, and the built-ins are not rows
# — they are the fallback used while ms_templates is EMPTY. So the moment an import lands,
# `requester`'s own existing grants (template:use|GenericUser and friends) name templates the
# validator no longer knows, and saving the role fails with
#     {"error":"unknown template: GenericUser"}
# leaving the role uneditable until the imported row is deleted again.
#
# Effective grants are the UNION of the primary role and roles held through subject_roles,
# so binding a second role adds the template without touching the first.
AD_ROLE="${AD_ROLE:-fpki-adtest}"
# The enrolling identity, read from the deployment rather than assembled from a NetBIOS name
# and a hostname: the qualifier is the PROVIDER id, which is not the domain's short name.
#
# ⚠️ AND UN-ESCAPED. JSON renders the separator as TWO characters (`fastpki-lab\\HOST$`), so
# taking the field verbatim binds the role to a name with a literal double backslash — which
# is not the identity that enrols and matches nobody. It fails silently: every call returns
# 200/201, the grant simply never applies, and the only symptom is the server logging
# `XCEP offering 0 of N` while the client says WS_E_INVALID_FORMAT, an error that names no
# permission at all.
# ⚠️ AND IT MUST BE *THIS* CLIENT'S ACCOUNT. `head -1` over every machine account bound to
# any role picks an arbitrary computer — on a deployment where more than one has ever
# enrolled, quite possibly not WIN_HOST. The role is then granted to the wrong machine,
# the "SAME enrolment now issues" assertion below fails, and nothing in the output points
# at the mis-selected subject. Match the client's own short name, which is what the machine
# account is named after, and say which one was chosen.
# The machine account is named after the COMPUTER, so derive it from WIN_HOST's first
# label rather than from `whoami` (which is the logged-in user, not the machine).
WIN_SHORT="${WIN_HOST%%.*}"
AD_ALL="$(capi "$CONSOLE/api/subject-roles" 2>/dev/null | tr '{' '\n' \
           | grep -oE '"selector_value":"[^"]*\$"' \
           | sed 's/"selector_value":"//; s/"$//; s/\\\\/\\/g')"
AD_SUBJ="$(printf '%s\n' "$AD_ALL" | grep -iE "\\\\${WIN_SHORT}\\\$\$" | head -1)"
# Fall back to the old behaviour only when the client's own account is not bound to
# anything yet, and SAY so — the fallback is a guess and should read as one.
if [ -z "$AD_SUBJ" ]; then
    AD_SUBJ="$(printf '%s\n' "$AD_ALL" | head -1)"
    [ -n "$AD_SUBJ" ] && echo "     note: no machine account matching '$WIN_SHORT' is bound to a role;" \
                              "falling back to '$AD_SUBJ'"
fi
chk "  PRECONDITION: the machine identity is known to the deployment" yes \
    "$([ -n "$AD_SUBJ" ] && echo yes || echo no)"
[ -n "$AD_SUBJ" ] && echo "     granting to machine account: $AD_SUBJ"

# ⚠️ REFUSE TO TOUCH A ROLE THIS SUITE DID NOT CREATE. POST /api/roles is an UPSERT, and
# cleanup DELETEs whatever AD_ROLE names. So pointing AD_ROLE at an existing role — say
# `requester`, an easy thing to try — silently rewrites its description and then destroys
# it and every grant hanging off it at teardown, on a deployment other people are using.
# Check first, and only claim ownership of a name that was genuinely free.
if capi "$CONSOLE/api/roles" -o - 2>/dev/null | grep -q "\"name\":\"$AD_ROLE\""; then
    chk "PRECONDITION: AD_ROLE names a role this suite may create and delete" yes no
    echo "         '$AD_ROLE' already exists on this deployment. This suite DELETES the role"
    echo "         it creates, so it will not adopt one it did not make. Choose an unused"
    echo "         name with AD_ROLE=<name>, or remove that role first."
    AD_ROLE_MADE=0
else
    capi -X POST "$CONSOLE/api/roles" -d "name=$AD_ROLE" -d "description=windows_enrolment.sh" \
         -o /dev/null >/dev/null 2>&1
    AD_ROLE_MADE=1
fi
GRANTED="$(capi -X POST "$CONSOLE/api/roles/$AD_ROLE/permissions" \
    --data-urlencode "grants=template:use|$AD_TMPL
ms:enrol|*" -o /dev/null -w '%{http_code}' 2>/dev/null)"
chk "the template:use grant is accepted" 200 "$GRANTED"
BOUND="$(capi -X POST "$CONSOLE/api/subject-roles" -d "selector_type=user" \
    --data-urlencode "selector_value=$AD_SUBJ" -d "role=$AD_ROLE" \
    -o /dev/null -w '%{http_code}' 2>/dev/null)"
chk "  and the enrolling identity holds it" yes "$(if [ "$BOUND" = 200 ] || [ "$BOUND" = 201 ]; then echo yes; else echo no; fi)"
case "$BOUND" in 200|201) AD_BOUND=1;; esac

restart_ms
psk "& certutil -f -policyserver * -policycache delete" >/dev/null 2>&1 || true
GOT="$(psk "\$r = certreq -q -enroll -machine -policyserver '$XCEP_URL' $AD_TMPL 2>&1; (\$r -join \"\`n\")" 2>/dev/null)"
chk "the SAME enrolment now issues — the grant is the only thing that changed" yes \
    "$(printf '%s' "$GOT" | grep -qi 'certificate has been issued' && echo yes || echo no)"

# ⚠️ THE DIRECTORY'S VALIDITY, NOT OURS, AND READ OFF THE CERTIFICATE. An MS template states
# what the CA will issue and is honoured rather than capped, so this is where a regression in
# that shows up against a number nobody here chose. Read from the client's own store: the
# certificate is the artefact, and our database agreeing with itself proves less.
AD_TP="$(psk "(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { \$_.Subject -match '$WIN_CN' } | Sort-Object NotBefore -Descending | Select-Object -First 1).Thumbprint" 2>/dev/null | tr -d '\r' | tail -1)"
if [ -n "$AD_TP" ] && [ -n "${TMPL_DAYS:-}" ]; then
    AD_DAYS="$(psk "\$c = Get-Item Cert:\\LocalMachine\\My\\$AD_TP; [int]((\$c.NotAfter - \$c.NotBefore).TotalDays)" 2>/dev/null | tr -d '\r' | tail -1)"
    chk "  the certificate carries the DIRECTORY's validity, not a server default" yes \
        "$([ -n "$AD_DAYS" ] && [ "$AD_DAYS" -ge $((TMPL_DAYS - 2)) ] && [ "$AD_DAYS" -le $((TMPL_DAYS + 2)) ] && echo yes || echo no)"
fi

# ── removal, which is half of what "manage templates" means ─────────────────────────
DEL="$(capi -X DELETE "$CONSOLE/api/templates/$AD_TMPL" -o /dev/null -w '%{http_code}' 2>/dev/null)"
chk "the imported template can be removed again" 200 "$DEL"
[ "$DEL" = 200 ] && AD_IMPORTED=0
chk "  and it is gone from what we serve" no \
    "$(capi "$CONSOLE/api/templates" 2>/dev/null | grep -q "\"name\":\"$AD_TMPL\"" && echo yes || echo no)"
# Emptying the table hands the built-ins back — the inverse of the displacement above, and
# the only reason a lab that runs this suite still has its three defaults afterwards.
restart_ms
psk "& certutil -f -policyserver * -policycache delete" >/dev/null 2>&1 || true
BACK="$(psk "\$r = certreq -q -enroll -machine -policyserver '$XCEP_URL' GenericComputer 2>&1; (\$r -join \"\`n\")" 2>/dev/null)"
chk "  and the built-in templates are served again" yes \
    "$(printf '%s' "$BACK" | grep -qi 'certificate has been issued' && echo yes || echo no)"
fi


# ── 8. THE USER-CONTEXT TEMPLATES ────────────────────────────────────────────────────
#
# ⚠️ ONLY GenericComputer HAD COVERAGE. The machine path above is the autoenrolment case and
# the one that matters most, but it is one template of three, and the other two are the ones
# whose SUBJECT the CA constructs — which is where the provider-qualified name lands and
# where a regression in it would show.
#
# ⚠️ AND THIS CANNOT RUN OVER PLAIN SSH. A key-authenticated OpenSSH session holds no network
# credentials, so outbound SPNEGO produces nothing and the server logs
#     XCEP 401 — no accepted credential (none offered)
# while the client reports WS_E_ENDPOINT_ACCESS_DENIED — an error that reads as the server
# refusing us. The machine context works there because it uses the COMPUTER account, which
# the system has. A scheduled task started under a real logon has the user's credentials,
# which is why WIN_PW is required for this section and only this section.
echo "=== 8. the user-context templates ==="

if [ -z "${WIN_PW:-}" ]; then
    echo "  [FAIL] WIN_PW not given — the user-context templates did not run, and a section"
    echo "         that does not run must not read as a pass. It is needed because a"
    echo "         key-auth SSH session cannot do outbound Kerberos; see the note above."
    fail=$((fail+1))
else
USER_REG=0
as_user "Add-CertificateEnrollmentPolicyServer -Url '$XCEP_URL' -Context User -AutoEnrollmentEnabled" >/dev/null 2>&1
USER_REG=1
UREG="$(as_user "(Get-CertificateEnrollmentPolicyServer -Scope All -Context User | Where-Object { \$_.Url -eq '$XCEP_URL' } | Select-Object -First 1).AuthType")"
chk "the user-context policy server registers" yes \
    "$(printf '%s' "$UREG" | grep -qi 'kerberos' && echo yes || echo no)"

# ⚠️ Email FIRST, and the ORDER MATTERS. Email is the template whose name the CA builds, so
# it is the one that can prove the subject is the AUTHENTICATED principal rather than
# anything the client chose. GenericUser is checked after, for the opposite property.
UOUT="$(as_user "certutil -f -user -policyserver * -policycache delete; certreq -q -enroll -policyserver '$XCEP_URL' Email")"
chk "Email issues in the user context" yes \
    "$(printf '%s' "$UOUT" | grep -qi 'certificate has been issued' && echo yes || echo no)"
USER_SER="$(printf '%s' "$UOUT" | grep -oE 'Serial Number: [0-9a-fA-F]+' | head -1 | sed 's/.*: //')"
[ -n "$USER_SER" ] && ISSUED_USER="$ISSUED_USER $USER_SER"

# ⚠️ THE SUBJECT IS THE AUTHENTICATED PRINCIPAL, AND IT IS THE **USER** PART OF THE QUALIFIED
# NAME. Identities are provider-qualified internally (`provider\user`), and the qualifier is
# an internal fact, not something to stamp into a certificate. A regression either way —
# the whole qualified string in the CN, or a name the requester supplied instead — shows up
# only here, because our own suites drive a template that grants enrollee-supplies-subject.
if [ -n "$USER_SER" ]; then
    UCN="$(as_user "(Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { \$_.SerialNumber -eq '$USER_SER' } | Select-Object -First 1).Subject")"
    chk "  its subject is the authenticated user, unqualified" yes \
        "$(printf '%s' "$UCN" | grep -qiE "CN=$WIN_SAM(,|\$)" && echo yes || echo no)"
    # ⚠️ ONE BACKSLASH, AND COMPUTED ON ITS OWN LINE -- §1's trap, second instance. Inside
    # single quotes `grep -q '\\\\'` hands grep four characters, which as a BRE is two
    # ESCAPED backslashes and matches only a doubled one; a leaked `CN=fastpki-lab\alice`
    # carries exactly one, so the `||` branch fired and the check printed PASS for the single
    # regression it names. A `case` glob needs no quoting levels, and `*\\*` catches a
    # qualifier however the DN renders it -- bare or RFC 4514-escaped.
    UQUAL=no
    case "$UCN" in *\\*) UQUAL=yes ;; esac
    chk "  and the provider qualifier is NOT in the certificate" no "$UQUAL"
fi

# ⚠️ GenericUser GRANTS ENROLLEE-SUPPLIES-SUBJECT (subject_name_flags 0x9) and certreq sends
# no subject, so the result would name NOBODY. Issuance refuses that outright — a certificate
# with an empty subject and no subjectAltName has no identity in any form (RFC 5280
# §4.1.2.6), and this suite is what found it being issued. The refusal is the assertion:
# were it to come back "issued", we would be signing nameless certificates again.
GOUT="$(as_user "certutil -f -user -policyserver * -policycache delete; certreq -q -enroll -policyserver '$XCEP_URL' GenericUser")"
chk "a request that would name nobody is refused, not issued" yes \
    "$(printf '%s' "$GOUT" | grep -qi 'certificate has been issued' && echo no || echo yes)"
fi


# ── 9. AUTOENROLMENT, WHICH IS A DIFFERENT CODE PATH IN THE CLIENT ───────────────────
#
# ⚠️ certreq IS NOT AUTOENROLMENT. Everything above drives certreq, which asks for one named
# template on demand. Production does not work that way: the client's autoenrolment task
# wakes up, reads the policy, decides for ITSELF which templates apply and whether it already
# holds a valid certificate for each, and enrols the ones it does not. That decision is made
# from the flags we advertise — auto_enroll, and the enrolment flags — so it is the path that
# actually consumes the policy metadata rather than a template name a human typed.
#
# `certutil -pulse` runs it now instead of waiting for the timer.
echo "=== 9. autoenrolment (certutil -pulse) ==="

# ⚠️ A CLEAN SLATE, OR THIS MEASURES NOTHING. Autoenrolment correctly declines to replace a
# certificate that is still valid, so a client that already holds one answers "completed
# successfully" and issues nothing — indistinguishable from a policy it could not use.
# Removing this CA's machine certificates first is what makes the difference observable, and
# it is also the honest thing to do with certificates earlier runs left behind.
# The issuing CA's common name, read off the certificate the trust section already located
# by thumbprint rather than typed in again — a name that drifts from the real one would make
# every count below zero and the section would pass by measuring nothing.
CA_CN="${CA_CN:-$(psk "((Get-Item Cert:\\LocalMachine\\CA\\$SUB_TP).Subject -split ',' | Select-String -SimpleMatch 'CN=') -replace '.*CN=',''" | tr -d '\r' | tail -1)}"
chk "PRECONDITION: the issuing CA's name is known, so the counts below mean something" yes \
    "$([ -n "$CA_CN" ] && echo yes || echo no)"

# ⚠️ THE PRECONDITION ABOVE MUST *GATE* THIS SECTION, NOT MERELY RECORD IT.
#
# `chk` counts a failure and returns; it stops nothing. With CA_CN empty the filter below
# becomes `$_.Issuer -match ''`, and an empty PowerShell regex matches EVERY certificate —
# so `$s.Remove($_)` would run over the WHOLE LocalMachine\My store of a shared lab client,
# deleting certificates that have nothing to do with FastPKI. CA_CN is empty for perfectly
# ordinary reasons: SUB_THUMBPRINT unset or stale after a lab rebuild, or one `psk` call
# returning nothing because the overlay network blinked.
#
# Nothing else in this suite destroys state it did not create, and this is the one place
# where a wrong input turns a test into damage. So the section is skipped outright, loudly,
# and the run continues to section 10.
if [ -z "$CA_CN" ]; then
    echo "  [SKIP] section 9 — without the issuing CA's name the store filter would match"
    echo "         EVERY certificate on the client and delete them all. Set SUB_THUMBPRINT"
    echo "         to this deployment's issuing CA (read it back from the live CA; a rebuilt"
    echo "         lab changes it) and re-run."
else
# ⚠️ AUTOENROLMENT HAS TO BE TURNED ON AT THE CLIENT, AND WITHOUT IT THIS SECTION BLAMES US
# FOR NOTHING. `certutil -pulse` with no AEPolicy fetches our policy and then does nothing:
# measured, the server logs "XCEP offering 3 of 3 templates" twice and no WSTEP request ever
# arrives, so a reader concludes autoenrolment is broken against our policy when the client
# was never asked to enrol. In an estate this comes from Group Policy; here the suite sets
# it and puts it back, because a prerequisite a test silently depends on is one it should
# provide and account for.
AE_KEY='HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment'
AE_WAS="$(as_system "(Get-ItemProperty -Path '$AE_KEY' -Name AEPolicy -EA SilentlyContinue).AEPolicy" | tr -d '\r' | tail -1)"
as_system "New-Item -Path '$AE_KEY' -Force | Out-Null;
           Set-ItemProperty -Path '$AE_KEY' -Name AEPolicy -Value 7 -Type DWord" >/dev/null 2>&1
AE_SET=1
PRE_N="$(as_system "@(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { \$_.Issuer -match [regex]::Escape('$CA_CN') }).Count" | tr -d '\r' | tail -1)"
# ⚠️ THROUGH THE STORE API, NOT `Remove-Item` ON THE Cert: DRIVE. Piping certificates to
# Remove-Item silently removes almost none of them — measured: 59 in, 58 left — so the
# precondition below would fail while looking like the CA had issued 58 certificates during
# one run. X509Store.Remove() is the interface that actually deletes.
as_system "\$s = New-Object System.Security.Cryptography.X509Certificates.X509Store('My','LocalMachine');
           \$s.Open('ReadWrite');
           @(\$s.Certificates | Where-Object { \$_.Issuer -match [regex]::Escape('$CA_CN') }) | ForEach-Object { \$s.Remove(\$_) };
           \$s.Close()" >/dev/null 2>&1
CLEARED="$(as_system "@(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { \$_.Issuer -match [regex]::Escape('$CA_CN') }).Count" | tr -d '\r' | tail -1)"
chk "PRECONDITION: the machine holds no certificate from this CA" 0 "${CLEARED:-x}"

PULSE="$(as_system "certutil -pulse")"
chk "certutil -pulse completes" yes \
    "$(printf '%s' "$PULSE" | grep -qi 'completed successfully' && echo yes || echo no)"
# The client decided this for itself from the advertised flags — nothing here named a
# template. GenericComputer is the built-in that carries auto_enroll.
POST_N=""
i=0
while [ "$i" -lt 12 ]; do
    POST_N="$(as_system "@(Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { \$_.Issuer -match [regex]::Escape('$CA_CN') }).Count" | tr -d '\r' | tail -1)"
    [ "${POST_N:-0}" -gt 0 ] 2>/dev/null && break
    i=$((i+1))
done
chk "  and autoenrolment issued a certificate without being told which template" yes \
    "$([ "${POST_N:-0}" -gt 0 ] 2>/dev/null && echo yes || echo no)"
echo "  (this CA's machine certificates: $PRE_N before the run, $POST_N after autoenrolment)"
fi   # CA_CN known — see the gate above
# ⚠️ NOT A PASS/FAIL ON SPEED. A timing threshold on a shared lab client measures the lab, so
# this REPORTS the cost and asserts only that every enrolment succeeded. The number is here
# because "it works" and "it works when four hundred machines wake up together" are different
# claims, and the second is the one an estate makes.
#
# ⚠️ TIMED INSIDE THE CLIENT, NOT AROUND as_system. Every call out to the client registers a
# scheduled task, starts it, polls for completion and unregisters it — seconds of harness
# that have nothing to do with enrolling. Timing the wrapper reported ~7s per enrolment and
# would have gone on reporting it whatever the server did. Measure-Command around certreq
# alone is the enrolment.
echo "=== 10. cost, and a burst ==="

BENCH_N="${BENCH_N:-5}"
BENCH_OUT="$(as_system "
  \$ms = @()
  for (\$i = 1; \$i -le $BENCH_N; \$i++) {
    & certutil -f -policyserver * -policycache delete | Out-Null
    \$t = Measure-Command { \$script:o = & certreq -q -enroll -machine -policyserver '$XCEP_URL' GenericComputer 2>&1 }
    if ((\$o -join ' ') -match 'has been issued') { \$ms += [int]\$t.TotalMilliseconds }
  }
  'OK=' + \$ms.Count
  if (\$ms.Count) {
    'MEAN=' + [int](\$ms | Measure-Object -Average).Average
    'MIN='  + (\$ms | Measure-Object -Minimum).Minimum
    'MAX='  + (\$ms | Measure-Object -Maximum).Maximum
  }
  \$b = Measure-Command {
    \$j = 1..$BENCH_N | ForEach-Object { Start-Job -ScriptBlock { & certreq -q -enroll -machine -policyserver '$XCEP_URL' GenericComputer 2>&1 } }
    \$null = \$j | Wait-Job -Timeout 300
    \$script:burst = (\$j | Receive-Job | Select-String -SimpleMatch 'has been issued').Count
    \$j | Remove-Job -Force
  }
  'BURSTOK=' + \$script:burst
  'BURSTMS=' + [int]\$b.TotalMilliseconds")"

b_ok="$(printf '%s' "$BENCH_OUT" | grep -oE '^OK=[0-9]+' | head -1 | cut -d= -f2)"
chk "every sequential enrolment issued ($BENCH_N of them)" "$BENCH_N" "${b_ok:-0}"
b_mean="$(printf '%s' "$BENCH_OUT" | grep -oE '^MEAN=[0-9]+' | head -1 | cut -d= -f2)"
b_min="$(printf '%s' "$BENCH_OUT" | grep -oE '^MIN=[0-9]+' | head -1 | cut -d= -f2)"
b_max="$(printf '%s' "$BENCH_OUT" | grep -oE '^MAX=[0-9]+' | head -1 | cut -d= -f2)"
[ -n "$b_mean" ] && echo "  one enrolment, policy fetch included: mean ${b_mean}ms  min ${b_min}ms  max ${b_max}ms"

# ⚠️ CONCURRENT, BECAUSE THAT IS THE SHAPE THAT BREAKS. A fleet does not enrol in turn; it
# wakes on one schedule and arrives together, which is how the keytab merge race was found.
# Sequential requests would never have surfaced it.
#
# ⚠️ THE BURST WALL-CLOCK IS NOT A SERVER MEASUREMENT. Start-Job spawns a full PowerShell
# runspace per job — seconds each — so the elapsed time is mostly the client starting
# processes: measured 13.5s for five enrolments that take ~0.5s apiece sequentially. It is
# reported for scale, and the ASSERTION is that all of them issued. Read the sequential mean
# for cost, never this number.
b_burst="$(printf '%s' "$BENCH_OUT" | grep -oE '^BURSTOK=[0-9]+' | head -1 | cut -d= -f2)"
b_bms="$(printf '%s' "$BENCH_OUT" | grep -oE '^BURSTMS=[0-9]+' | head -1 | cut -d= -f2)"
chk "  and every enrolment in a simultaneous burst issued" "$BENCH_N" "${b_burst:-0}"
[ -n "$b_bms" ] && echo "  $BENCH_N at once: ${b_bms}ms wall clock"

echo "=== WINDOWS ENROLMENT: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
