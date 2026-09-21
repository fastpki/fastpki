#!/usr/bin/env bash
# Run the FastPKI verification harness and aggregate results honestly.
#
# A suite is counted FAILED if it exits non-zero, prints "RESULT: FAIL", or
# reports a non-zero failure counter (FAIL=N / GAP=N / bad=N). Several suites
# print their own count and exit 0 regardless, so we parse output, not just the
# exit code.
#
# Tiers:
#   CORE   assertion suites — always run.
#   SMOKE  demonstration scripts (loose output) — run, only a crash fails them.
#   ROOT   bind :80 for ACME HTTP-01 — opt in with RUN_ROOT=1 (run as root).
#
# Environment overrides (defaults target the WSL dev box; CI sets the system
# OpenSSL):
#   OSSL=<openssl>            default /opt/openssl-3.5/bin/openssl
#   OPENSSL_LIBDIR=<libdir>   default /opt/openssl-3.5/lib64
#   RUN_CORE=0               skip the CORE+SMOKE tiers (run only the opt-ins)
#   RUN_ROOT=1               also run the root-only ACME suites
#   RUN_PG=1                 also run the Postgres suite
#
# Usage:  tests/run_all.sh
#         RUN_ROOT=1 RUN_PG=1 tests/run_all.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"

# What this environment can and cannot prove. Printed TWICE — here and again beside the
# totals — because a banner at the top of a 200-suite log has scrolled away by the time
# anyone reads "191 passed", and the totals are where that number most needs its caveat.
. "$HERE/env_report.sh"
env_banner

# ⚠️ THE FULL HARNESS RUNS IN THE PRODUCTION IMAGE, AND NOWHERE ELSE.
#
# Off-image runs are what the whole skip problem was made of: a Mac drives an unpatched
# PKCS#11 stack and a different OpenSSL, a build-stage image drives Alpine unpatched, and
# both then report a green run whose ML-DSA, Ed25519 and token-backed RSA-PSS coverage
# never happened. Reporting that honestly was the old plan; refusing it is the policy.
#
# A SINGLE SUITE still runs anywhere — `bash tests/web_ca_create.sh` is untouched — so the
# fast inner loop survives. Only the whole-harness verdict is confined, because only the
# whole-harness verdict gets quoted as "all green".
if [ "$(env_id)" != test-image ] && [ "${FASTPKI_ALLOW_HOST_RUN:-0}" != "1" ]; then
    echo "run_all.sh: the full harness runs in the production image, not here (env=$(env_id))."
    echo
    echo "  Use:  FASTPKI_IMAGE=fastpki:local bash tests/run-in-container.sh"
    echo "    or: FASTPKI_BUILD_IMAGE=1       bash tests/run-in-container.sh"
    echo
    echo "  One suite still runs directly:  OPENSSL_CONF= bash tests/<suite>.sh"
    echo "  Override deliberately with FASTPKI_ALLOW_HOST_RUN=1 (the result is not a gate)."
    exit 2
fi

# ⚠️ Refuse to start with stray fastpki servers already running.
#
# A leftover server from an interrupted run still HOLDS ITS PORT. The next suite that
# wants that port starts its own server, the bind fails, and the suite then waits for a
# server that will never answer — with no timeout, so the whole harness hangs on one
# suite instead of failing it. That cost a 12-hour run stuck on web_cross_sign.sh, which
# passes 33/0 the moment it is run against a clean machine.
#
# Killing them is safe: every suite starts its own servers and owns them for its
# lifetime, so a `build/fastpki-*` alive BEFORE the harness starts is by definition
# an orphan. Reported, not silent — a machine that keeps producing them is itself a bug
# (bash EXIT traps do not stack, which is how they leak).
# ⚠️ pgrep -f takes a REGEX, and a checkout path can contain regex metacharacters. This was
# found when the tree lived under a directory called "C++Version"; it does not any more, so
# the escaping below no longer has anything to escape HERE — it stays because the next
# checkout path is not ours to choose.
# An unescaped path makes `++` a repetition operator applied to a repetition operator:
# pgrep exits with "repetition-operator operand invalid", prints nothing, and the guard
# silently finds zero strays FOREVER. Caught only by planting a live process and watching
# the check fail to notice it — the check that never fires looks exactly like a clean box.
_bindir="$(cd "$HERE/.." && pwd)/build/fastpki-"
_pat=$(printf '%s' "$_bindir" | sed 's/[][\\.*^$+?(){}|]/\\&/g')
_stray=$(pgrep -f "$_pat" 2>/dev/null | wc -l | tr -d ' ')
if [ "${_stray:-0}" -gt 0 ]; then
    echo "!! $_stray stray fastpki process(es) from an earlier run are holding ports — killing them first."
    pkill -f "$_pat" 2>/dev/null
    sleep 1
fi

CORE=( suite_exit_honest.sh architecture_current.sh no_insecure_settings.sh identity_union_guard.sh deploy_env.sh schema_apply_psql_argv.sh est_mtls_role.sh ca_delete.sh config_keys_live.sh config_value_hash.sh docs_accurate.sh public_repo_hygiene.sh no_loose_secrets.sh env_honest.sh build_image_gated.sh demo_functions_toplevel.sh demo_scripts.sh demo_vars_have_writers.sh demo_acme_override.sh demo_bench_webroot.sh demo_help.sh demo_target_descriptor.sh cli_help.sh version_flag.sh ca_ancestors.sh signing_digest.sh cross_sign_foreign.sh web_cross_sign.sh mesh_publication_complete.sh mesh_trigger_columns.sh trap_cleanup.sh pg_priv_census.sh pg_priv_no_source_side_effects.sh pg_helpers_no_block.sh p11kit_patch.sh hsm_tls_transport.sh crl.sh crl_delta.sh imported_crl.sh est_matrix.sh est_csrattrs.sh est_serverkeygen.sh est_dbauth.sh auth_db_only.sh schema_version.sh schema_steps_immutable.sh schema_step_transactions.sh config_overlay_ordering.sh certs_ca_columns.sh ca_no_fk.sh ca_rollover_query.sh ca_pick_tiebreak.sh ca_rekey.sh ca_rekey_carries_ca_identity.sh ca_kind_selfsigned.sh ca_rollover_chain.sh service_cert_renew.sh roles_permissions_schema.sh web_scoped_roles.sh web_role_editor.sh enrol_permissions.sh config_bootstrap_keys.sh deploy_defaults_exist.sh deploy_parity.sh api_routes_documented.sh certgen_pin_always.sh domains_db_only.sh ca_keys_token_only.sh ldap.sh ad_template_import.sh directory_group_refresh.sh est_perca.sh cert_profiles.sh profile_ca_ku.sh profile_custom_exts.sh profile_passthrough_exts.sh profile_choice.sh leaf_hash_choice.sh profile_assign.sh cmp_matrix.sh cmp_auth.sh cmp_certconf.sh cmp_concurrent.sh cmp_extracerts.sh cmp_peruser.sh cmp_onhold.sh cmp_authz.sh cmp_perca.sh cmp_client_ca_db.sh cmp_rfc9810.sh cmp_ra.sh cmp_ra_cert_id.sh cmp_response_digest.sh cmp_ra_chain.sh concurrent_enrol.sh ms_smoke.sh ms_xcep_guid.sh ms_kerberos.sh ms_xxe.sh ms_templates.sh ms_template_policy.sh ms_xcep_unsigned.sh ms_perca.sh ms_xcep_cas.sh transport_cert_stable.sh transport_cert_id_scope.sh tls_key_matrix.sh acme_keychange.sh acme_dns01.sh acme_resolver_forms.sh acme_default_eab.sh acme_wildcard.sh acme_orders.sh acme_account_authz.sh acme_alpn_responder.sh acme_preauth_alpn.sh acme_caa.sh acme_retry_after.sh acme_cert_shape.sh acme_perca.sh acme_cross_ca.sh acme_baseurl.sh store_crl.sh store_abuse.sh store_hash.sh store_uri.sh ocsp_expiry_sweep.sh crl_cache.sh ocsp_perca.sh ocsp_responder_keys.sh ocsp_rekeyed_chain.sh ocsp_responder.sh ocsp_abuse.sh acme_sweep.sh audit.sh audit_forward.sh scep.sh scep_challenge_type.sh scep_renewal.sh scep_perca.sh notify.sh notify_web.sh discover.sh web_discover.sh web.sh web_mtls.sh arch_model.sh web_sessions_persist.sh login_throttle.sh trusted_proxies.sh session_cookie_secure.sh web_hardening.sh no_sticky_sessions.sh web_openmode.sh web_first_admin_role.sh web_subject_roles_api.sh console_xss.sh web_theme_no_fixed_light_colors.sh web_master_role.sh web_cas.sh web_ca_create.sh web_ca_urls.sh web_ca_hsm.sh pss_loaded_key_signing.sh token_key_liveness.sh web_ca_import.sh web_ca_csr.sh web_pkcs11_slots.sh web_users.sh web_directories.sh saml_oidc_providers.sh user_computer_kind.sh web_users_ui.sh web_subject_pages.sh web_self_manage_users.sh inventory_filters.sh web_selfservice.sh web_issue.sh selfservice_subject_profile.sh web_keygen.sh web_keygen_der.sh web_hsm_leaf.sh serial_canonical_form.sh web_hsm_perms.sh pg_tls_issue.sh install_protocol_choice.sh rolling_update_aux.sh pg_promote_finishes.sh web_p12.sh web_signing_ca.sh web_csrmap.sh web_templates.sh web_backup.sh db_restore.sh backup_encrypted.sh sda.sh secret_leak.sh profiles_web.sh oidc.sh web_onboarding.sh saml.sh setup_wizard.sh endpoints.sh endpoint_health.sh endpoints_advertised.sh endpoint_disable.sh web_endpoint_controls.sh web_config_pending_restart.sh mesh.sh mesh_tls.sh mcp.sh pkcs11.sh ca_create_hsm.sh key_replication.sh hsm_sidecar.sh config_file_editor.sh config_malformed_row.sh config_ui_modifiable.sh client_config_store.sh enrolment_credentials.sh bootstrap_seed.sh install_wizard.sh native_deploy.sh backup.sh update.sh pqc.sh )
SMOKE=( smoke_ocsp.sh smoke_est.sh smoke_cmp.sh smoke_store.sh )
ROOT_SUITES=( acme_lifecycle.sh acme_eab.sh )
PG=( certs_role_dropped.sh mesh_listener_cert_id.sh default_admin_reset.sh pg_smoke.sh pg_no_leak.sh pg_cleanup_scope.sh pg_role_check.sh baseline.sh bench_smoke.sh pg_store_hash.sh pg_store_hash_selectors.sh pg_store_uri.sh pg_reconnect.sh acme_reconnect.sh est_cert_cap.sh auth_backend_shipped.sh replication.sh replication_stream.sh sso_provider_fixes.sh mesh_verify.sh ha_failover.sh db_restore_online.sh deploy_selfsigned_tls.sh no_default_ca.sh chain_rekeyed_ca.sh )

# ⚠️ THE LAB TIER IS OPT-IN, AND "it would just SKIP" IS NOT THE REASON.
# lab_replication_mesh.sh drives the three REAL lab DCs and deliberately CUTS the
# replication interconnect. It does skip cleanly when the lab is unreachable — but from a
# developer machine the lab IS reachable, so without this gate every ordinary local run
# would partition a shared lab, possibly while someone else is mid-test on it. It is about not
# touching shared infrastructure unasked; the SKIP is only the safety net underneath.
#
#   RUN_LAB=1 bash tests/run_all.sh          # everything, including the lab
#   bash tests/lab_replication_mesh.sh       # just the lab check, e.g. after a deploy
LAB=( lab_replication_mesh.sh windows_enrolment.sh )

# ⚠️ THE SOURCE TIER IS SEPARATE BECAUSE IT TESTS THE SOURCE, NOT THE PRODUCT.
#
# cppcheck.sh, build_warnings.sh and fuzz_lane.sh all need the SOURCE and a COMPILER:
# clean static analysis, a warning-free build, and libFuzzer harnesses compiled with clang. Neither is a property of the shipped binaries, and the production image has
# no compiler and no configured cmake tree — build_warnings.sh reads $ROOT/build/CMakeCache.txt,
# which the container runner deliberately shadows with a tmpfs.
#
# They used to sit in CORE, where they skipped on every host that lacked cmake or cppcheck
# — which is every host, including CI: cppcheck.sh has never actually run anywhere. Leaving
# them there would force the zero-skip rule to carry a permanent exception, and an
# exception list is the skip budget by another name.
#
# So they are their own tier, selected where the source and a toolchain already are (the
# build stage, via the CI fast lane) and NOT SELECTED in the production image. A suite that
# was never selected is not a skip, so the zero-skip assertion stays absolute.
SOURCE=( cppcheck.sh clang_tidy.sh build_warnings.sh fuzz_lane.sh )

# ⚠️ THE DEMO TIER NEEDS DOCKER, WHICH IS WHY IT IS NOT IN THE CONTAINER RUN.
#
# demo_clients.sh is the only suite that EXECUTES demo/pki-demo.sh rather than reading it,
# and throwaway mode now stages a docker compose project — postgres, token and every
# protocol service. Inside the test container there is no docker and there must not be:
# bind-mounting the host socket would hand a large shell harness control of the host
# daemon. So the suite fails there with "docker: command not found" through fifteen
# assertions, which says nothing about the product.
#
# It runs on the HOST, where docker already is, the same answer the compose-parse
# pre-flight got. Not selected in the production image, so it is not a skip:
#
#     RUN_CORE=0 RUN_DEMO=1 FASTPKI_ALLOW_HOST_RUN=1 bash tests/run_all.sh
#     bash tests/demo_clients.sh                      # or just run the one suite
#
# The other demo_*.sh suites READ the demo scripts (help text, function nesting, variable
# writers) and need nothing, so they stay in CORE.
DEMO=( demo_clients.sh )

SUITES=()
if [ "${RUN_CORE:-1}" = "1" ]; then
    SUITES+=( "${CORE[@]}" "${SMOKE[@]}" )
fi
if [ "${RUN_ROOT:-0}" = "1" ]; then
    [ "$(id -u)" -eq 0 ] || { echo "RUN_ROOT=1 requires running as root (ACME binds :80)"; exit 2; }
    SUITES+=( "${ROOT_SUITES[@]}" )
else
    echo "NOTE: skipping root-only ACME suites (${ROOT_SUITES[*]}); set RUN_ROOT=1 as root to include them."
fi
if [ "${RUN_SOURCE:-0}" = "1" ]; then
    SUITES+=( "${SOURCE[@]}" )
else
    echo "NOTE: not selecting the source tier (${SOURCE[*]}); set RUN_SOURCE=1 where a"
    echo "      compiler and a configured build tree exist (the build stage, not the"
    echo "      production image). These test the SOURCE, not the shipped binaries."
fi
if [ "${RUN_DEMO:-0}" = "1" ]; then
    SUITES+=( "${DEMO[@]}" )
else
    echo "NOTE: not selecting the demo tier (${DEMO[*]}); it drives docker compose, so it"
    echo "      runs on a HOST with docker (RUN_DEMO=1), never inside the test container."
fi
if [ "${RUN_LAB:-0}" = "1" ]; then
    SUITES+=( "${LAB[@]}" )
else
    echo "NOTE: skipping the lab tier (${LAB[*]}); set RUN_LAB=1 to exercise REAL cross-DC"
    echo "      replication on the 3 lab DCs (it cuts and restores their interconnect)."
fi
if [ "${RUN_PG:-0}" = "1" ]; then
    SUITES+=( "${PG[@]}" )
    # ⚠️ Bring the SHARED `fastpki` database up to the schema this build needs, BEFORE the
    # suites run. Unlike the CORE tier, the PG suites use a persistent database rather than
    # a throwaway one, so it carries whatever schema it was created with — and every binary
    # then refuses to start ("schema is version N but this build needs N+1"), failing five
    # suites for a reason that has nothing to do with what they test.
    #
    # createdb.sql alone does NOT fix it: `create table if not exists` skips an existing
    # table, so a widened primary key or a new column never lands. The ordered step is the
    # only thing that migrates an existing database — the same ordering a real deployment
    # uses (schema step first, then the binaries).
    _pgw="psql -h ${PGHOST:-127.0.0.1} -p ${PGPORT:-5432} -U ${PGUSER:-fastpki} -d ${PGDATABASE:-fastpki}"
    if PGPASSWORD="${PGPASSWORD:-fastpki}" PSQL="$_pgw" bash "$HERE/../deploy/schema-apply.sh" >/tmp/fpki-schema-apply.log 2>&1; then
        :
    else
        echo "!! schema-apply.sh failed against the shared fastpki database — the PG suites"
        echo "   will fail on the version guard. Last lines:"
        sed 's/^/   /' /tmp/fpki-schema-apply.log | tail -5
    fi
else
    # ⚠️ SAY SO. The two tiers above announce themselves when they are off; this one did
    # not, and the omission is invisible in the result: the summary counts only what was
    # selected, so a run without this tier ends "SUITES: 208 passed ... (of 211)" and reads
    # exactly like a complete green run. Twenty-five suites -- every replication, mesh,
    # HA-failover and persistent-database case -- were simply not in the list, and nothing
    # in the output said a word about it. A tier you have to remember to ask for is one you
    # will eventually forget to ask for; the fix is that it tells you.
    echo "NOTE: skipping the Postgres tier (${#PG[@]} suites, incl. replication/mesh/HA);"
    echo "      set RUN_PG=1 to include them. Without it this run is NOT the full gate."
fi

# ONE p11-kit server for the whole run (option A). Private keys live
# in a token, not a file, so suites need one — and each test process loading SoftHSM
# in-process is the configuration that DEADLOCKS, which in CI hangs rather
# than fails. SoftHSM therefore runs in a single separate process here and every
# suite reaches it through p11-kit-client.so, each with its own token.
#
# Started once, before any suite, and torn down at exit. Where the toolchain is
# absent this is a no-op: suites that need a token SKIP, the rest are unaffected.
source "$HERE/hsm_helpers.sh"
if hsm_available; then
    if hsm_server_start; then
        echo "PKCS#11: shared p11-kit server on ${P11_KIT_SERVER_ADDRESS}"
        trap 'hsm_server_stop' EXIT
    else
        echo "PKCS#11: shared server FAILED to start — token-backed suites will SKIP"
    fi
else
    echo "PKCS#11: $(hsm_skip_reason) — token-backed suites will SKIP"
fi

# ── leaked-server reaper ─────────────────────────────────────────────────────────
# A suite's EXIT trap cleans up when the suite exits normally. It runs NOTHING when the
# suite is SIGKILLed — by a CI timeout, by an impatient Ctrl-C, by the OOM killer — and
# the server it started keeps its port. Every suite binds a FIXED port, so the next run
# finds a listener already answering and can pass without the process under test being
# alive at all. That has happened: an assertion passed against a deliberately broken
# build because a leftover from an earlier run answered, and tests/mock_oidc.py was found
# still listening three days later on a port a new suite then picked.
#
# Suites run sequentially here, so a before/after snapshot attributes any survivor to the
# suite that started it — which turns a silent leak into a named one. Only processes that
# APPEARED during the suite are touched, so a server a developer is running by hand is
# never in the difference.
#
# p11-kit is deliberately not in this list: hsm_helpers owns its lifecycle and killing one
# mid-run could break a suite that legitimately shares it. Worth revisiting separately.
_procs() {
    local n
    for n in fastpki-web fastpki-est fastpki-acme fastpki-cmp fastpki-ms \
             fastpki-ocsp fastpki-scep fastpki-certstore; do
        pgrep -x "$n" 2>/dev/null            # -x, never -f: a -f pattern matches this script
    done
    pgrep -f 'tests/mock_' 2>/dev/null
}
_reap_leaked() {   # <suite> <before-list>
    local suite=$1 before=$2 after leaked
    after="$(_procs | sort -u)"
    leaked="$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after") 2>/dev/null)"
    [ -n "$leaked" ] || return 0
    echo "[run_all] WARNING: $suite left $(printf '%s\n' "$leaked" | grep -c .) server(s) running — killing"
    printf '%s\n' "$leaked" | while read -r pid; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done
}

ok=0; bad=0; failed=(); skipped=(); silent=()

# ── FASTPKI_SHARD=k/N — run only every Nth suite, offset k ──────────────────────────
#
# This is how the harness is parallelised, and the design decision worth recording is that
# the shards run in SEPARATE CONTAINERS rather than as concurrent jobs inside one.
#
# ⚠️ THE SUITES CANNOT SHARE A NETWORK NAMESPACE. Every suite binds a FIXED port, and 67
# port numbers are claimed by more than one suite — 18080 alone belongs to baseline.sh,
# cmp_matrix.sh, crl.sh, diag_cmp_rr.sh and smoke_ocsp.sh. Two of those in flight together
# is a bind failure at best, and at worst one suite's client talking to another suite's
# server and asserting against it. Giving each shard its own container gives each its own
# loopback, its own Postgres and its own p11-kit, so identical ports cannot collide and no
# suite needs editing at all. Reassigning ~190 suites to unique numbers was the obvious
# alternative and it is strictly worse: a large diff, a new invariant to police, and it
# would still leave the shared token stack contended.
#
# Round-robin rather than contiguous blocks: the arrays group related suites together
# (all the acme_*, all the cmp_*), and those have similar runtimes, so contiguous blocks
# would pile the slow ones into one shard. Interleaving spreads them.
#
# The floor on wall-clock is the SLOWEST SINGLE SUITE, not the total divided by N: no
# shard can finish before the longest suite it holds. acme_wildcard.sh is ~300s against a
# ~1700s total, so N beyond about 6 buys nothing until that suite is split.
if [ -n "${FASTPKI_SHARD:-}" ]; then
    _sk="${FASTPKI_SHARD%%/*}"; _sn="${FASTPKI_SHARD##*/}"
    case "$_sk/$_sn" in
        [0-9]*/[0-9]*) : ;;
        *) echo "FASTPKI_SHARD must look like k/N (got '$FASTPKI_SHARD')" >&2; exit 2 ;;
    esac
    if [ "$_sn" -lt 1 ] || [ "$_sk" -lt 1 ] || [ "$_sk" -gt "$_sn" ]; then
        echo "FASTPKI_SHARD=$FASTPKI_SHARD is out of range" >&2; exit 2
    fi
    # ⚠️ LONGEST-FIRST, NOT ROUND-ROBIN. Assigning by position in the tier arrays knows
    # nothing about how long a suite takes, and the arrays group related suites whose
    # runtimes are similar — so the long ones clumped. Measured at 6 shards: 394s of work
    # in one shard against 157s in another, with the whole run waiting on the slowest while
    # a third of the fleet sat idle. Total work was 1518s, so a balanced run is ~253s and
    # over two minutes was being lost to the arrangement alone.
    #
    # So: sort by duration descending and give each suite to the shard with the least work
    # so far (LPT). Placing the big rocks first is what lets the small ones fill the gaps;
    # doing it in the other order is exactly the clumping being fixed.
    #
    # Durations come from tests/suite_timings.txt, which is a HINT. A suite missing from it
    # is assumed average, so a new suite costs a slightly uneven run and never a failure,
    # and if the file is absent entirely every duration is equal and this degrades to
    # round-robin — the previous behaviour. Nothing here can fail the harness.
    #
    # Deterministic on purpose: every shard runs this same computation over the same list
    # and must reach the SAME assignment, or a suite would run twice or not at all. Hence
    # the secondary sort key on the name — ties broken by duration alone would depend on
    # input order.
    _sel=()
    while IFS= read -r _s; do
        [ -n "$_s" ] && _sel+=( "$_s" )
    done < <(printf '%s\n' "${SUITES[@]}" | awk -v tf="$HERE/suite_timings.txt" '
                BEGIN { while ((getline l < tf) > 0) {
                            if (l ~ /^#/ || l ~ /^[ \t]*$/) continue
                            split(l, a, " "); dur[a[1]] = a[2] + 0 } }
                { printf "%d\t%s\n", ($1 in dur ? dur[$1] : 6), $1 }' \
             | sort -k1,1rn -k2,2 \
             | awk -v k="$_sk" -v n="$_sn" '
                { best = 1
                  for (i = 2; i <= n; i++) if (load[i] < load[best]) best = i
                  load[best] += $1
                  if (best == k) print $2 }')
    # ⚠️ Report the shard in the banner. A shard's totals are NOT the harness's totals, and
    # a log that does not say so reads as "the suite is only 31 tests long".
    echo "SHARD $_sk of $_sn: ${#_sel[@]} of ${#SUITES[@]} suites"
    SUITES=( ${_sel[@]+"${_sel[@]}"} )
fi

# `set -u` + bash 3.2 (macOS) errors on an empty array expansion, so disabling every
# tier (RUN_CORE=0 with no opt-ins) aborted instead of reporting "nothing selected".
if [ "${#SUITES[@]}" -eq 0 ]; then
    echo "No suites selected (RUN_CORE=0 and no RUN_ROOT/RUN_PG opt-in)."
    exit 0
fi
absent=()
for s in "${SUITES[@]}"; do
    # ⚠️ ABSENT BY DESIGN, OR MISSING BY ACCIDENT — AND THE DIFFERENCE IS IN .gitattributes.
    # The published snapshot is `git archive` of this tree, which drops every export-ignore
    # path, so a suite that must not be published is simply not there. Running it would exit
    # 127 and read as a failing suite; treating every absent suite as fine would let a
    # deleted one stop running with nobody told. So: export-ignored is noted and skipped,
    # anything else absent is a failure that names itself.
    if [ ! -f "$HERE/$s" ]; then
        if git -C "$ROOT" check-attr export-ignore -- "tests/$s" 2>/dev/null | grep -q ': set$'; then
            absent+=("$s"); continue
        fi
        echo "==================================================================="
        echo ">>> $s — MISSING: tests/$s is not in this tree and is not export-ignored"
        echo "==================================================================="
        bad=$((bad+1)); failed+=("$s"); continue
    fi
    _ts_start="$(date '+%H:%M:%S')"
    echo "==================================================================="
    echo ">>> $s  [$_ts_start]"
    echo "==================================================================="
    _procs_before="$(_procs | sort -u)"
    # ⚠️ BOUND EVERY SUITE. Without this, ONE suite that blocks costs the entire run and
    # reports nothing at all: update.sh hit an unbounded `lsof` inside a --network host
    # container and stalled the DC run TWICE, before its own first echo, so the log ended
    # at ">>> update.sh" with no totals and no failure list. An empty failure list reads
    # exactly like success.
    #
    # SUITE_TIMEOUT=0 disables it. Where no timeout program exists the bound is dropped,
    # because losing it is better than not running at all — but it now SAYS SO once, at
    # the top of the run, instead of leaving the operator to infer it from a log that
    # simply stops. On macOS `timeout` is not in the base system; Homebrew coreutils
    # installs it as `gtimeout`, which is why both names are tried.
    _TMO=""
    command -v timeout  >/dev/null 2>&1 && _TMO=timeout
    [ -z "$_TMO" ] && command -v gtimeout >/dev/null 2>&1 && _TMO=gtimeout
    if [ "${SUITE_TIMEOUT:-1200}" != "0" ] && [ -z "$_TMO" ] && [ -z "${_TMO_WARNED:-}" ]; then
        echo '!! NO timeout(1) OR gtimeout(1) ON THIS HOST — the per-suite bound is OFF.'
        echo "   A suite that hangs will hang the WHOLE run with no totals and no failure"
        echo "   list, which reads exactly like success. Fix with: brew install coreutils"
        _TMO_WARNED=1
    fi
    if [ "${SUITE_TIMEOUT:-1200}" != "0" ] && [ -n "$_TMO" ]; then
        out="$("$_TMO" -k 10 "${SUITE_TIMEOUT:-1200}" bash "$HERE/$s" 2>&1)"; rc=$?
        if [ "$rc" -eq 124 ]; then
            out="$out
[run_all] TIMED OUT after ${SUITE_TIMEOUT:-1200}s — killed. This is a HANG, not a failing
[run_all] assertion: treat it as a blocked suite and find what it is waiting on."
        fi
    else
        out="$(bash "$HERE/$s" 2>&1)"; rc=$?
    fi
    _reap_leaked "$s" "$_procs_before"
    _ts_end="$(date '+%H:%M:%S')"
    echo "$out"
    if [ "$rc" -ne 0 ] \
       || grep -qE '(FAIL|GAP|bad)=[1-9]' <<<"$out" \
       || grep -q 'RESULT: FAIL' <<<"$out"; then
        bad=$((bad+1)); failed+=("$s")
        echo "<<< $s : FAILED  [$_ts_end]"
    else
        ok=$((ok+1))
        # ⚠️ A suite that asserted NOTHING is not a pass, and nothing here used to
        # said so. `ldap.sh` skips on any host without slapd — every "full suite green"
        # from a Mac excluded LDAP entirely, and it took the in-image tier to notice.
        # Exit status alone cannot tell "it all worked" from "it never ran".
        #
        # Two distinct weak outcomes, kept apart because the fix differs: a suite that
        # DECLARED a skip is missing a dependency on this host, while one that asserted
        # nothing without saying so is passing on exit code alone.
        if ! grep -qE '\[PASS\]|PASS=[1-9]|RESULT: PASS' <<<"$out"; then
            # ⚠️ THE SMOKE TIER ASSERTS NOTHING BY DESIGN — its own definition at the top of
            # this file calls it "demonstration scripts (loose output); only a crash fails
            # them". Counting those as vacuous would make the zero-skip rule permanently
            # unsatisfiable for a reason that is not a gap, and the fix would have been an
            # exception list. A tier that does not claim to assert is not failing to.
            _is_smoke=no
            for _sm in "${SMOKE[@]}"; do [ "$_sm" = "$s" ] && _is_smoke=yes; done
            if [ "$_is_smoke" = yes ]; then
                echo "<<< $s : ok (smoke — asserts nothing by design)  [$_ts_end]"
            elif grep -qiE '^[[:space:]]*(SKIP:|\[SKIP\])' <<<"$out"; then
                skipped+=("$s"); echo "<<< $s : ok (SKIPPED — asserted nothing)  [$_ts_end]"
            else
                silent+=("$s");  echo "<<< $s : ok (no assertions — exit status only)  [$_ts_end]"
            fi
        else
            echo "<<< $s : ok  [$_ts_end]"
        fi
    fi
    echo
done

echo "==================================================================="
env_banner
echo "SUITES: $ok passed, $bad failed, ${#skipped[@]} skipped, ${#silent[@]} no-assertion  (of $((ok+bad)))"
[ "${#skipped[@]}" -ne 0 ] && printf '  SKIPPED (missing dependency on this host): %s\n' "${skipped[@]}"
# Said out loud, so a published snapshot's run states what it did not run and why, rather
# than quietly reporting a smaller total than the tree it came from.
[ "${#absent[@]}" -ne 0 ] && printf '  NOT IN THIS TREE (export-ignore, private to the source repository): %s\n' "${absent[@]}"
[ "${#silent[@]}"  -ne 0 ] && printf '  NO ASSERTIONS (exit status only): %s\n'        "${silent[@]}"
if [ "$bad" -ne 0 ]; then
    printf '  FAILED: %s\n' "${failed[@]}"
    exit 1
fi
_vacuous=$(( ${#skipped[@]} + ${#silent[@]} ))
if [ "$_vacuous" -eq 0 ]; then
    echo "ALL GREEN"
elif [ "$(env_id)" = test-image ]; then
    # ⚠️ IN THE PRODUCTION IMAGE A SKIP IS A FAILURE, and there is no allow-list.
    #
    # Everything the harness needs is installed in that image ON PURPOSE, and every feature
    # the product ships is compiled in by default, so a suite that gives up there is saying
    # the IMAGE is incomplete — a bug to fix, not a fact to record. This is what replaces
    # the per-environment "skip budget" that was proposed and rejected: a manifest of
    # permitted skips manages an environment problem that testing from one image removes.
    #
    # A suite that was never SELECTED (the source, lab, root or PG tiers when they are off)
    # is not counted here at all — only suites that ran and gave up.
    #
    # Elsewhere the old behaviour stands (report, exit 0) because a developer box
    # legitimately lacks things; but the full harness refuses to run there in the first
    # place, at the top of this script.
    echo "FAILED: $_vacuous suite(s) proved nothing in the production image."
    echo "        Every dependency is meant to be present here, so this is an IMAGE GAP."
    echo "        Fix deploy/Dockerfile.test or the suite — do not add an exception."
    exit 1
else
    echo "ALL GREEN (but $_vacuous suites proved nothing — see above)"
fi

# ── host-side housekeeping, NOT part of the run ──────────────────────────────────────
#
# ⚠️ NONE OF THIS IS A TEST, and in the production image none of it means anything. It
# exists so that a DEVELOPER's local docker-compose deployment still works after the
# PG-tier suites have used the shared `fastpki` database: re-create the database and
# re-seed admin/admin. Inside the container the Postgres is a throwaway cluster this run
# created and will discard, and there is no compose deployment to repair — so running it
# there would rebuild a database nobody will look at and reach for a docker socket that is
# deliberately absent.
#
# Gated on the tier rather than on `command -v docker`, because the question is not whether
# docker happens to exist; it is whether there is a deployment worth fixing.
if [ "$(env_id)" != test-image ]; then
    # The test suite may have used the main 'fastpki' database (e.g. fixed-DB PG-tier
    # suites). Re-create it so the compose deployment is left in a working state.
    echo "[run_all] ensuring the fastpki database schema is in place..."
    source "$HERE/pg_helpers.sh"
    # $ROOT is the repo root; the script only ever set $HERE (= tests/). Without this
    # the block below died on `set -u` at the first $ROOT — after "ALL GREEN" and with
    # every command `|| true`-ed, so it failed silently and neither the database
    # re-create nor the admin re-seed ever ran.
    ROOT="$(dirname "$HERE")"
    PGPASSWORD="${PGPASSWORD:-fastpki}" psql -h "${PGHOST:-127.0.0.1}" -U "${PGUSER:-fastpki}" \
      -d postgres -c "CREATE DATABASE fastpki" 2>/dev/null || true
    PGDATABASE=fastpki pg_exec_file "$ROOT/sql/createdb.sql" 2>/dev/null

    # Re-seed the default admin user so the compose deployment is usable after tests.
    # Admin/admin is the dev default; in production the admin changes it on first login.
    if command -v docker >/dev/null 2>&1 && docker ps --filter name=fastpki-cmp --format '{{.ID}}' 2>/dev/null | grep -q .; then
        docker exec fastpki-cmp-1 fastpki-config --config /app/config/bootstrap.conf \
            web-user admin admin --role admin --if-absent 2>/dev/null || true
    elif command -v fastpki-config >/dev/null 2>&1 && [ -f "$ROOT/deploy/bootstrap.compose.conf" ]; then
        fastpki-config --config "$ROOT/deploy/bootstrap.compose.conf" \
            web-user admin admin --role admin --if-absent 2>/dev/null || true
    fi
fi
