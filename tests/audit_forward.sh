#!/usr/bin/env bash
# Audit-log forwarding to a collector — the durable shipper.
#
# The audit log is a hash-chained TABLE, not a text stream, so forwarding it means walking
# it in order and remembering how far you got. What this suite is really guarding is the
# two ways that goes silently wrong:
#
#   * FRAMING. Syslog over a stream has no message boundary, so RFC 6587 §3.4.1 prefixes
#     each message with its octet count. Get that wrong and the collector connects, accepts
#     every byte and displays nothing — the shipper reports success the whole time. So the
#     declared length is compared against the ACTUAL message length, not merely matched as
#     a pattern.
#   * THE HIGH-WATER MARK. Without a persisted position the only behaviours on restart are
#     to re-send the whole log or to skip whatever arrived while the shipper was down. A
#     duplicate audit record is noise; a missing one is the failure the audit log exists to
#     prevent. Both are asserted by shipping twice with new rows in between.
set -u
ROOT="${FASTPKI_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "$ROOT/tests/pg_helpers.sh"
export LD_LIBRARY_PATH=${OPENSSL_LIBDIR:-/opt/openssl-3.5/lib64}
BUILD="${FASTPKI_BUILD:-$ROOT/build}"
AUDIT="$BUILD/fastpki-audit"
[ -x "$AUDIT" ] || { echo "SKIP: no $AUDIT"; exit 0; }
command -v nc >/dev/null 2>&1 || { echo "SKIP: no netcat, cannot stand up a collector"; exit 0; }

W="$(mktemp -d)"; cd "$W"
pass=0; fail=0
chk(){ if [ "$2" = "$3" ]; then echo "  [PASS] $1"; pass=$((pass+1)); else echo "  [FAIL] $1 (expected '$2' got '$3')"; fail=$((fail+1)); fi; }
# ⚠️ OCCURRENCES, NOT LINES. Octet-framed syslog messages are concatenated with no newline
# between them, so `grep -c` reports 1 no matter how many arrived — which reads as "the
# shipper sent one message" when it in fact sent all of them correctly.
n_of(){ grep -o "$1" "$2" 2>/dev/null | wc -l | tr -d ' '; }

pg_setup audit_forward
trap 'pg_cleanup; kill ${LPID:-0} 2>/dev/null; rm -rf "$W"' EXIT

SPORT=19871
HPORT=19872

cat > bootstrap.conf <<EOF
PG_CONNINFO=$PG_CONNINFO
LOG_LEVEL=err
EOF
A(){ "$AUDIT" --config bootstrap.conf "$@"; }

# A collector. BSD netcat wants `-l host port`, busybox wants `-l -p port`; rather than
# guessing by platform, try one and verify it is really LISTENING.
#
# ⚠️ PROCESS-ALIVE IS NOT BOUND, and that distinction cost a red gate. This used to accept
# `kill -0 $LPID` as proof the collector was up. On busybox the BSD form starts, prints a
# usage error and is briefly still alive — so the check passed, nothing was listening, the
# shipper could not connect, and sixteen assertions failed pointing at the product. The
# fixture has to prove a LISTENING SOCKET exists, which is what netstat answers on both
# platforms (macOS prints `127.0.0.1.19871`, busybox `127.0.0.1:19871`).
#
# Probing by connecting would be stronger still and is wrong here: `nc -l` serves ONE
# connection and exits, so the probe would consume the very listener it is checking.
listening(){ netstat -an 2>/dev/null | grep -i listen | grep -qE "[.:]$1( |\t|$)"; }

listen(){                      # listen <port> <outfile> [response-file]
  local port="$1" out="$2" resp="${3:-}"
  : > "$out"
  local form
  for form in bsd busybox; do
    if [ "$form" = bsd ]; then
      if [ -n "$resp" ]; then ( { cat "$resp"; sleep 5; } | nc -l 127.0.0.1 "$port" > "$out" 2>/dev/null ) & LPID=$!
      else ( nc -l 127.0.0.1 "$port" > "$out" 2>/dev/null ) & LPID=$!; fi
    else
      if [ -n "$resp" ]; then ( { cat "$resp"; sleep 5; } | nc -l -p "$port" > "$out" 2>/dev/null ) & LPID=$!
      else ( nc -l -p "$port" > "$out" 2>/dev/null ) & LPID=$!; fi
    fi
    local i=0
    while [ $i -lt 20 ]; do
      listening "$port" && return 0
      sleep 0.25; i=$((i+1))
    done
    kill $LPID 2>/dev/null; wait $LPID 2>/dev/null
  done
  return 1
}

seed(){ A append pki_lifecycle "$1" tester success "$2" "detail for $1" >/dev/null 2>&1; }

echo "=== fixture: rows in the log, and a collector that is really listening ==="
for n in one two three; do seed "evt_$n" "target_$n"; done
q(){ "$PSQL_BIN" -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -tAc "$1" | tr -d ' '; }
chk "three events are in the log" 3 "$(q 'select count(*) from audit_log')"
listen "$SPORT" recv1.txt && BOUND=yes || BOUND=no
chk "the collector bound to the port" yes "$BOUND"
[ "$BOUND" = yes ] || { echo "=== AUDIT FORWARD: PASS=$pass FAIL=$fail ==="; exit 1; }

echo "=== syslog over TCP: the messages arrive, and they are OCTET-FRAMED ==="
cat >> bootstrap.conf <<EOF
AUDIT_FORWARD=syslog
AUDIT_FORWARD_TARGET=127.0.0.1:$SPORT
AUDIT_FORWARD_PROTO=tcp
EOF
A forward >fw1.log 2>&1
sleep 1; kill $LPID 2>/dev/null; wait $LPID 2>/dev/null
chk "the shipper reports three sent" 1 \
    "$(grep -c 'forwarded 3 event' fw1.log)"
chk "  and three messages reached the collector" 3 \
    "$(n_of 'fastpki@32473' recv1.txt)"
# ⚠️ THE FRAMING ASSERTION, and it is arithmetic rather than a pattern. `grep '^[0-9]* <'`
# would pass on a prefix that is present but WRONG, and a wrong count is precisely what
# makes a collector show nothing while every byte arrives.
FIRSTLEN="$(sed -n '1s/^\([0-9]*\) .*/\1/p' recv1.txt)"
chk "the first message carries an octet count" yes \
    "$([ -n "$FIRSTLEN" ] && echo yes || echo no)"
# Cut the declared number of octets off the stream after the count and its space, then
# check that what follows is the start of the NEXT frame — which can only be true if the
# count was right.
PREFIX=$(( ${#FIRSTLEN} + 1 ))
NEXT="$(dd if=recv1.txt bs=1 skip=$(( PREFIX + FIRSTLEN )) count=8 2>/dev/null)"
chk "  and that count lands exactly on the next frame" yes \
    "$(printf '%s' "$NEXT" | grep -qE '^[0-9]+ <' && echo yes || echo no)"
chk "the message itself is RFC 5424 (version 1 after the priority)" yes \
    "$(head -c 200 recv1.txt | grep -qE '^[0-9]+ <[0-9]+>1 ' && echo yes || echo no)"

echo "=== the position is remembered, so a restart neither repeats nor skips ==="
MARK="$(q "select last_seq from audit_forward_state where target='syslog:127.0.0.1:$SPORT'")"
HEAD="$(q 'select max(seq) from audit_log')"
chk "the mark advanced to the head of the log" "$HEAD" "$MARK"

# Two more events, then ship again. The whole point is that ONLY these two go.
seed evt_four target_four; seed evt_five target_five
listen "$SPORT" recv2.txt >/dev/null
A forward >fw2.log 2>&1
sleep 1; kill $LPID 2>/dev/null; wait $LPID 2>/dev/null
chk "the second run ships only the two NEW events" 2 \
    "$(n_of 'fastpki@32473' recv2.txt)"
# ⚠️ NECESSARY AND NOT SUFFICIENT ON ITS OWN: "two arrived" would also hold if the shipper
# re-sent everything and the collector happened to drop three. Name one of the ALREADY-SENT
# events and require its absence.
chk "  and does NOT repeat an event it already sent" 0 \
    "$(n_of 'evt_one' recv2.txt)"
# Count the `target=` structured-data param, which appears exactly ONCE per message. The
# action name appears three times (MSGID, the SD, and the message text), so counting that
# reports 6 for two messages and reads like a duplication bug that is not there.
chk "  and the two it sent are the new ones" 2 \
    "$(n_of 'target_four\|target_five' recv2.txt)"

# Nothing new: a pass with an empty read must ship nothing rather than restarting the log.
listen "$SPORT" recv3.txt >/dev/null
A forward >fw3.log 2>&1
sleep 1; kill $LPID 2>/dev/null; wait $LPID 2>/dev/null
chk "a run with nothing new ships nothing" 0 "$(n_of 'fastpki@32473' recv3.txt)"

echo "=== --after overrides the position for one run WITHOUT moving it ==="
MARKB="$(q "select last_seq from audit_forward_state where target='syslog:127.0.0.1:$SPORT'")"
listen "$SPORT" recv4.txt >/dev/null
A forward --after 0 >fw4.log 2>&1
sleep 1; kill $LPID 2>/dev/null; wait $LPID 2>/dev/null
chk "--after 0 re-reads the whole log" 5 "$(n_of 'fastpki@32473' recv4.txt)"
MARKC="$(q "select last_seq from audit_forward_state where target='syslog:127.0.0.1:$SPORT'")"
# A manual replay is a diagnostic, not a delivery. Letting it rewind the stored position
# would make the next scheduled pass re-ship everything after it.
chk "  and leaves the stored position untouched" "$MARKB" "$MARKC"

echo "=== a bare run prints to the terminal and records NOTHING ==="
# With nothing configured, a one-shot `forward` prints the messages — what a person at a
# terminal wants, and what this command has always done.
sed -i.bak '/^AUDIT_FORWARD/d' bootstrap.conf && rm -f bootstrap.conf.bak
A forward > bare.txt 2>bare.err
chk "a bare run prints the messages" 5 "$(n_of 'fastpki@32473' bare.txt)"
# ⚠️ AND IT LEAVES NO POSITION BEHIND. This shipped wrong once: the position was stored
# under a "stdout" key, so looking at the log advanced it and the same command a minute
# later printed nothing. Counting the ROWS in the table is what catches that — asserting
# only "the syslog target's mark is unchanged" would not, because the offending row was
# written under a different key entirely.
chk "  and records no position for it" 1 \
    "$(q 'select count(*) from audit_forward_state')"
chk "  the one position that exists is the real collector's" 1 \
    "$(q "select count(*) from audit_forward_state where target like 'syslog:%'")"

echo "=== HEC: one request for the batch, with the Splunk token in the header ==="
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}' > hecresp.txt
sed -i.bak '/^AUDIT_FORWARD/d' bootstrap.conf && rm -f bootstrap.conf.bak
cat >> bootstrap.conf <<EOF
AUDIT_FORWARD=hec
AUDIT_FORWARD_TARGET=http://127.0.0.1:$HPORT/services/collector/event
AUDIT_FORWARD_TOKEN=test-hec-token-123
EOF
listen "$HPORT" hecreq.txt hecresp.txt >/dev/null
A forward >fwh.log 2>&1
sleep 1; kill $LPID 2>/dev/null; wait $LPID 2>/dev/null
chk "it POSTs to the collector path" yes \
    "$(grep -q '^POST /services/collector/event' hecreq.txt && echo yes || echo no)"
chk "  with the Splunk authorization header" yes \
    "$(grep -qi '^Authorization: Splunk test-hec-token-123' hecreq.txt && echo yes || echo no)"
# The whole batch in ONE request is the reason to use HEC at all; five separate POSTs would
# work and would be the wrong shape.
chk "  the whole batch travels in one request" 1 "$(grep -c '^POST ' hecreq.txt)"
chk "  carrying one event object per row" 5 "$(n_of '"sourcetype":"fastpki:audit"' hecreq.txt)"
chk "  and the event body is the audit row, chain hash included" yes \
    "$(grep -q '"prev_hash"' hecreq.txt && echo yes || echo no)"
# ⚠️ THE TOKEN IS A SECRET. It goes in the header and must never be echoed to the log,
# where it would end up in exactly the container output this feature ships elsewhere.
chk "  the token is never printed to the shipper's own log" 0 \
    "$(grep -c 'test-hec-token-123' fwh.log)"

echo "=== the shipper reports that it started, like every listener does ==="
# The Config page decides whether a setting change has reached the process that READS it
# by comparing the change against that process's start marker. These settings are read by
# this shipper and by nothing else, so without a marker of its own the console has no
# evidence about it at all — and the section default would answer for the eight listeners
# instead, clearing "pending restart" once THEY had restarted while this process carried
# on with the previous collector address.
sed -i.bak '/^AUDIT_FORWARD/d' bootstrap.conf && rm -f bootstrap.conf.bak
{ echo "AUDIT_FORWARD=syslog"; echo "AUDIT_FORWARD_TARGET=127.0.0.1:$SPORT"; } >> bootstrap.conf
chk "no start marker before the shipper has run" 0 \
    "$(q "select count(*) from config where key='AUDITFWD_STARTED_AT'")"
listen "$SPORT" recvm.txt >/dev/null
# ⚠️ THE BINARY DIRECTLY, NOT THE `A` HELPER. Backgrounding a shell FUNCTION makes $! the
# subshell, so `kill $FWPID` reaps the wrapper and leaves fastpki-audit running — measured:
# one survived 11 minutes inside the in-image run, holding a connection to a database this
# suite drops on exit. Invoking the binary makes $! the process we actually mean to stop.
"$AUDIT" --config bootstrap.conf forward --follow >fwm.log 2>&1 & FWPID=$!
sleep 3; kill "$FWPID" 2>/dev/null; wait "$FWPID" 2>/dev/null
kill $LPID 2>/dev/null; wait $LPID 2>/dev/null
chk "  --follow stamps one"                      1 \
    "$(q "select count(*) from config where key='AUDITFWD_STARTED_AT'")"
# ⚠️ The marker must be a real epoch second, not an empty row. The console parses it with
# parseInt and treats a 0 as "no marker", so a row written with an unusable value would
# read as "this process has never started" — which is the same silence the row exists to
# remove, only now with something in the table to suggest otherwise.
STAMP="$(q "select value from config where key='AUDITFWD_STARTED_AT'")"
usable_epoch(){ case "$1" in ''|*[!0-9]*) echo no;; *) [ "$1" -gt 1600000000 ] && echo yes || echo no;; esac; }
chk "  and it is a usable timestamp"             yes "$(usable_epoch "$STAMP")"

# ⚠️ AND NOT WHEN IT SHIPS NOTHING. `--follow` with forwarding off exits immediately
# without shipping, and stamping there would tell the console a process is running and
# current when no shipper exists at all — the reader-with-no-writer shape inverted.
q "delete from config where key='AUDITFWD_STARTED_AT'" >/dev/null
sed -i.bak '/^AUDIT_FORWARD/d' bootstrap.conf && rm -f bootstrap.conf.bak
echo "AUDIT_FORWARD=off" >> bootstrap.conf
A forward --follow >fwm2.log 2>&1
chk "  switched off, it stamps nothing"          0 \
    "$(q "select count(*) from config where key='AUDITFWD_STARTED_AT'")"

echo "=== off means off, and a typo is refused rather than treated as off ==="
sed -i.bak '/^AUDIT_FORWARD/d' bootstrap.conf && rm -f bootstrap.conf.bak
echo "AUDIT_FORWARD=off" >> bootstrap.conf
listen "$SPORT" recv5.txt >/dev/null
A forward >fw5.log 2>&1
sleep 1; kill $LPID 2>/dev/null; wait $LPID 2>/dev/null
chk "AUDIT_FORWARD=off sends nothing to a collector" 0 "$(n_of 'fastpki@32473' recv5.txt)"
# ⚠️ THE SERVICE PATH IS THE ONE THAT MATTERS HERE. A one-shot `forward` with nothing
# configured prints the messages to stdout, which is what a person at a terminal wants and
# what this command has always done. `--follow` is the compose service, and it must ship
# nothing and exit: printing the whole audit log to the container's stdout every interval
# would turn "forwarding is off" into a log-spam feature. It also must EXIT rather than
# loop, or the deployment would carry a container doing nothing for ever.
A forward --follow >fw5f.log 2>&1; RCF=$?
chk "  the service exits instead of looping" 0 "$RCF"
chk "  and says why"                         1 "$(grep -c 'is off' fw5f.log)"
sed -i.bak '/^AUDIT_FORWARD/d' bootstrap.conf && rm -f bootstrap.conf.bak
echo "AUDIT_FORWARD=sylsog" >> bootstrap.conf          # a plausible typo
A forward >fw6.log 2>&1; RC=$?
# Accepting an unknown value as `off` would leave a deployment believing it forwards its
# audit trail while shipping nothing, with nothing downstream ever saying so.
chk "a misspelled AUDIT_FORWARD is refused" 1 "$([ $RC -ne 0 ] && echo 1 || echo 0)"
chk "  and the error names the key" 1 "$(grep -c 'AUDIT_FORWARD' fw6.log)"

echo
echo "=== AUDIT FORWARD: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
