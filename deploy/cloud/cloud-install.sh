#!/usr/bin/env bash
# deploy/cloud/cloud-install.sh — FastPKI cloud install wizard.
#
# The third member of the install.sh family, and it asks the SAME questions as the other
# two in the same order with the same defaults:
#
#   deploy/install.sh                 a docker-compose deployment on a host you have
#   deploy/native/install-native.sh   a native Alpine host you have
#   deploy/cloud/cloud-install.sh     hosts you do not have yet — it provisions them
#
# What it adds is the handful of questions only a cloud can answer (which provider, which
# region, how big, who may reach the console), and what it does with the answers is write
# a tfvars file and drive OpenTofu. It writes no HCL and hides none: the module is in
# deploy/cloud/<provider>/ and is meant to be read.
#
#   ./cloud-install.sh                      # interactive, plan + confirm before apply
#   ./cloud-install.sh --answers ans.env    # non-interactive
#   ./cloud-install.sh --plan-only          # write the tfvars, plan, stop
#   ./cloud-install.sh --destroy            # tear the deployment down
#
# ⚠️ THIS SPENDS MONEY. It creates instances, EBS volumes and Elastic IPs in a real
# account. Nothing here is free tier at three nodes.
set -euo pipefail

case "$0" in
    */*) HERE="$(cd "${0%/*}" && pwd)" ;;
    *)   HERE="$(pwd)" ;;
esac

ANSWERS=""; PLAN_ONLY=0; DESTROY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --answers) ANSWERS="${2:?--answers needs a file}"; shift 2 ;;
    --plan-only) PLAN_ONLY=1; shift ;;
    --destroy) DESTROY=1; shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

die() { echo "cloud-install: $*" >&2; exit 1; }

# OpenTofu is the tool this drives; `terraform` runs the same module unchanged, so it is
# accepted as a fallback rather than being refused on principle.
TF=""
for c in tofu terraform; do command -v "$c" >/dev/null 2>&1 && { TF="$c"; break; }; done
[ -n "$TF" ] || die "neither 'tofu' nor 'terraform' is on PATH — install OpenTofu (https://opentofu.org)"

[ -n "$ANSWERS" ] && { [ -r "$ANSWERS" ] || die "cannot read answers file: $ANSWERS"; }
ansval() { [ -n "$ANSWERS" ] && sed -n "s/^$1=//p" "$ANSWERS" | head -1 || true; }
interactive() { [ -z "$ANSWERS" ] && [ -t 0 ]; }
ask() {
  local var="$1" prompt="$2" def="${3:-}" cur ans
  cur="$(ansval "$1")"
  [ -n "$cur" ] && def="$cur"
  if interactive; then
    read -r -p "$prompt [${def}]: " ans || true
    printf -v "$var" '%s' "${ans:-$def}"
  else
    printf -v "$var" '%s' "$def"
  fi
}
yesno() {
  ask "$1" "$2 (yes/no)" "$3"
  case "${!1}" in
    y|Y|yes|YES|Yes) printf -v "$1" '%s' yes ;;
    n|N|no|NO|No)    printf -v "$1" '%s' no ;;
    *) die "$1 must be yes or no (got '${!1}')" ;;
  esac
}

echo "── FastPKI cloud install wizard ───────────────────────────────────────" >&2
ask CLOUD "Cloud provider (aws)" "aws"
case "$CLOUD" in
  aws) ;;
  gcp|azure)
    die "only the AWS module ships today. GCP and Azure modules go in deploy/cloud/$CLOUD/ and are not written yet — say so rather than provisioning something that half works." ;;
  *) die "unknown cloud '$CLOUD'" ;;
esac
MODULE="$HERE/$CLOUD"
[ -d "$MODULE" ] || die "no module at $MODULE"
TFVARS="$MODULE/terraform.tfvars"

if [ "$DESTROY" = 1 ]; then
  [ -f "$TFVARS" ] || die "no $TFVARS — nothing recorded to destroy"
  echo >&2
  echo "⚠️  This destroys the FastPKI deployment described by $TFVARS." >&2
  echo "    The data volumes carry prevent_destroy, so every issued certificate and — with" >&2
  echo "    the SoftHSM backend — every CA private key SURVIVES this and is left behind as" >&2
  echo "    an unattached volume you will be billed for. Delete them by hand once you are" >&2
  echo "    certain, which is deliberately not something this script will do for you." >&2
  if interactive; then
    read -r -p "Type the deployment name to confirm: " confirm || true
    want="$(sed -n 's/^deployment_name *= *"\(.*\)"/\1/p' "$TFVARS" | head -1)"
    [ "$confirm" = "${want:-fastpki}" ] || die "not confirmed"
  fi
  cd "$MODULE"
  "$TF" init -input=false
  # ⚠️ EXCLUDE THE PROTECTED VOLUMES, OR THE TEARDOWN REFUSES TO DO ANYTHING AT ALL.
  # prevent_destroy is not "skip this resource" — a plan that would destroy it is an ERROR,
  # so a bare `tofu destroy` stops with "Instance cannot be destroyed" and removes nothing,
  # not even the instances that are costing money. That is the opposite of what an operator
  # tearing a deployment down needs, and it is what this script promised to do for them.
  #
  # Excluding them destroys everything else and leaves the volumes as unattached EBS, which
  # is what the warning above says will happen: they hold every issued certificate and, with
  # the SoftHSM backend, every CA private key. Deleting them stays a deliberate act with a
  # volume id in it, which is the whole reason they are protected.
  "$TF" destroy -exclude="aws_ebs_volume.data"
  echo >&2
  echo "The data volumes were left behind, unattached and still billed. They are listed by:" >&2
  echo "  aws ec2 describe-volumes --filters 'Name=tag:Name,Values=${DEPLOYMENT_NAME:-fastpki}-data-*' \\" >&2
  echo "      --query 'Volumes[].{Id:VolumeId,Size:Size,State:State}' --output table" >&2
  echo "Delete one with:  aws ec2 delete-volume --volume-id <id>" >&2
  echo "⚠️  And drop it from the state as well, or the next apply adopts a volume whose" >&2
  echo "    database password this deployment no longer knows:  $TF state rm 'aws_ebs_volume.data[\"1\"]'" >&2
  exit 0
fi

ask DEPLOYMENT_NAME "Deployment name (prefixes every resource)" "fastpki"
ask REGION "AWS region" "us-east-1"

# ⚠️ WHICH ACCOUNT. Credentials are ambient — AWS_PROFILE, environment variables, an
# instance role — so without this the account is whichever one the shell was carrying, and
# nothing in the plan says which. Defaulted from the credentials in effect, so the operator
# confirms an account rather than looking one up; a mismatch is refused before anything is
# created.
default_account=""
command -v aws >/dev/null 2>&1 &&
  default_account="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)"
case "$default_account" in *[!0-9]*|'') default_account="" ;; esac
ask AWS_ACCOUNT_ID "AWS account id this deployment belongs to (blank = do not check)" "$default_account"
ask PKI_DNS "Public FQDN — one name, or one per data center, comma separated" "pki.example.org"

# The same question install.sh asks, in the same words, because it is the same decision:
# each node mints serials under a 2-octet prefix that is its own, and here each node also
# becomes its own availability zone.
# ⚠️ ONE SERVER PER DATA CENTER, and this module provisions no second one. A standby is a
# separate machine joined to a running server (docs/high-availability.md §4a), so answering
# "2" here gives two data centers, not a pair. Said out loud because the difference decides
# something irreversible one step later: a standby can only ever receive a CA key that was
# created replicable, and that is fixed when the key is generated.
echo "  Each data center gets ONE server. A standby for failover is a second machine you" >&2
echo "  add later (docs/high-availability.md §4a) — and its CA keys must be created" >&2
echo "  replicable from the start, because that cannot be granted afterwards." >&2
ask DC_COUNT "Number of data centers in the mesh (1 = single node)" "1"
case "$DC_COUNT" in ''|*[!0-9]*) die "DC_COUNT must be a positive integer" ;; esac
[ "$DC_COUNT" -ge 1 ] || die "DC_COUNT must be >= 1"

# ⚠️ CHECKED HERE so the answer is refused while it can still be retyped. The module
# validates the same rule, but by then the operator has left the wizard and is reading a
# type error out of a plan. ONE name publishes a round-robin across every node, which is
# correct only when whichever node a client lands on can SIGN with the CA it asked for —
# a mesh replicates data, not signing capability, so that means a replicable CA key
# present in every node's own token. One name PER NODE keeps each data center separately
# addressable and copies no key; it is the answer unless you meant the other thing.
pki_dns_count=$(printf '%s' "$PKI_DNS" | tr ',' '\n' | grep -c '[^[:space:]]' || true)
if [ "$pki_dns_count" -ne 1 ] && [ "$pki_dns_count" -ne "$DC_COUNT" ]; then
  die "pki_dns has $pki_dns_count names but dc_count is $DC_COUNT — give ONE shared name or exactly $DC_COUNT"
fi

# A standby is a SECOND machine in the same data center, streaming the first one's database
# so that losing the machine does not lose the data center. Asked here, next to the count it
# is so easily confused with, and empty by default because a pair is twice the cost and the
# CA keys have to be created replicable for it to be a failover at all.
echo "  A standby is a second machine in the SAME data center, taking over if the first is" >&2
echo "  lost. Name the data centers that should get one, e.g. 1 or 1,2 — blank for none." >&2
ask STANDBY_DCS "Data centers with a standby (blank = none)" ""
for _s in $(printf '%s' "$STANDBY_DCS" | tr ',' ' '); do
  case "$_s" in ''|*[!0-9]*) die "standby data centers must be numbers, e.g. 1,2" ;; esac
  [ "$_s" -ge 1 ] && [ "$_s" -le "$DC_COUNT" ] \
    || die "standby data center $_s is outside 1..$DC_COUNT"
done
unset _s
if [ -n "$STANDBY_DCS" ]; then
  echo >&2
  echo "⚠️  A standby can only ever hold a CA key that was created REPLICABLE, and that" >&2
  echo "    cannot be granted afterwards. Create every CA with --replicable (or tick" >&2
  echo "    'replicable key' in the console) — docs/deployment.md §12 step 7." >&2
  echo >&2
fi

ask INSTANCE_TYPE "Instance type per node" "t4g.medium"
# ⚠️ 443 UNLESS THERE IS A REASON. A console on 8090 has to be typed, is filtered by endpoint
# security and corporate egress rules, and is not proxied by relays — so it fails for people
# whose network is not yours, in ways they cannot diagnose. The node lowers
# net.ipv4.ip_unprivileged_port_start so the unprivileged console can bind a low port.
ask WEB_PORT "Console port (443 needs no port in the URL)" "8090"
case "$WEB_PORT" in ''|*[!0-9]*) die "WEB_PORT must be a port number" ;; esac
ask DATA_GB "Data volume per node, GB (database, /var/pki, token)" "40"
ask AMI_ID "FastPKI AMI id (blank = newest fastpki-* you own in $REGION)" ""

# ⚠️ REQUIRED, WITH NO DEFAULT OFFERED. This is the administrative console of a
# certificate authority. Accepting a blank here would open it to the internet for anyone
# who pressed Enter through the wizard, which is exactly the population that would not
# notice.
ask ADMIN_CIDRS "Who may reach SSH and the console (comma-separated CIDRs, e.g. 203.0.113.4/32)" ""
[ -n "$ADMIN_CIDRS" ] || die "admin CIDRs are required — the console of a CA is not opened to 0.0.0.0/0 by default"
case "$ADMIN_CIDRS" in
  *0.0.0.0/0*)
    echo >&2
    echo "⚠️  0.0.0.0/0 publishes the CA console and SSH to the entire internet." >&2
    if interactive; then
      yesno REALLY "    Are you certain" "no"
      [ "$REALLY" = yes ] || die "stopped — narrow admin_cidrs and re-run"
    fi ;;
esac
ask CLIENT_CIDRS "Who may reach the enrolment protocols (blank = nobody outside the VPC)" ""
ask SSH_KEY "Existing EC2 key pair name for SSH (blank = no SSH access)" ""
ask ROUTE53_ZONE "Route 53 hosted zone id to publish $PKI_DNS into (blank = none)" ""

# The one address that is billed. Asked rather than assumed, because the answer depends on
# something the module cannot see: whether every party that has to reach these nodes —
# administrators, enrolment clients, and relying parties fetching CRL and OCSP — has IPv6.
# Say no and the nodes are reachable over IPv6 alone; they keep private IPv4 addresses, so
# the metadata service, the interconnect and the mesh conninfos are unaffected.
echo >&2
echo "AWS bills \$0.005/hour for each public IPv4 address (about \$3.65/month, charged" >&2
echo "even while the instance is stopped). IPv6 addresses are free." >&2
yesno PUBLIC_IPV4 "  Give each node a public IPv4 address as well as IPv6" "yes"
if [ "$PUBLIC_IPV4" = no ] && [ -z "$ROUTE53_ZONE" ]; then
  echo >&2
  echo "⚠️  Without a public IPv4 address the AAAA records are the only published way in," >&2
  echo "    and no hosted zone was given — you will have to publish the addresses from the" >&2
  echo "    node_public_ipv6 output yourself." >&2
fi

echo >&2
echo "Which protocols should these nodes run? Anything you decline is not installed," >&2
echo "not started, and its port is not opened." >&2
yesno WANT_EST   "  EST (RFC 7030)"                     yes
yesno WANT_ACME  "  ACME (RFC 8555)"                    yes
yesno WANT_CMP   "  CMP (RFC 4210/9483)"                yes
yesno WANT_SCEP  "  SCEP (RFC 8894)"                    yes
yesno WANT_MS    "  MS-XCEP/WSTEP (Windows auto-enrol)" yes
yesno WANT_STORE "  Certificate store (RFC 4387)"       yes
# The console and OCSP are not offered, exactly as in the other two wizards: without the
# console there is no way to create a CA, and fastpki-ocsp serves the CRL endpoints too.

ask KEY_BACKEND "Key storage (softhsm = bundled token, demo; hsm = your own PKCS#11 module)" "softhsm"
PKCS11_MODULE=""
case "$KEY_BACKEND" in
  softhsm)
    echo "  note: SoftHSM keeps CA private keys in a software token on the instance's data" >&2
    echo "        volume. Right for a demo; for a SaaS offering point KEY_BACKEND=hsm at" >&2
    echo "        CloudHSM's PKCS#11 library instead — this module does not provision a" >&2
    echo "        CloudHSM cluster, because that is a five-figure resource with its own" >&2
    echo "        initialisation ceremony and no business being a side effect of an apply." >&2 ;;
  hsm)
    ask PKCS11_MODULE "Absolute path to the vendor PKCS#11 module on the instance" "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
    case "$PKCS11_MODULE" in /*) ;; *) die "PKCS11_MODULE must be an absolute path" ;; esac ;;
  *) die "KEY_BACKEND must be 'softhsm' or 'hsm'" ;;
esac

# ── write the tfvars ──────────────────────────────────────────────────────────────────
hcl_list() {   # hcl_list "a, b ,c" -> ["a", "b", "c"]  (empty input -> [])
  local IFS=',' out="" item
  [ -z "${1:-}" ] && { printf '[]'; return; }
  for item in $1; do
    item="$(printf '%s' "$item" | tr -d '[:space:]')"
    [ -z "$item" ] && continue
    out="${out:+$out, }\"$item\""
  done
  printf '[%s]' "$out"
}
protos=""
for pair in "est:$WANT_EST" "acme:$WANT_ACME" "cmp:$WANT_CMP" "scep:$WANT_SCEP" \
            "ms:$WANT_MS" "store:$WANT_STORE"; do
  [ "${pair##*:}" = yes ] && protos="${protos:+$protos,}${pair%%:*}"
done

# No secrets are written here and none are passed to the instances: the node generates its
# own database password and token PIN from the kernel CSPRNG at first boot. A tfvars file
# and a Terraform state file are both places those must never be.
{
  printf '# Generated by deploy/cloud/cloud-install.sh. Safe to edit and re-apply.\n'
  printf '# Carries NO secrets: each node generates its own database password and token PIN\n'
  printf '# at first boot, so neither is in this file or in the state.\n\n'
  printf 'deployment_name   = "%s"\n' "$DEPLOYMENT_NAME"
  printf 'region            = "%s"\n' "$REGION"
  printf 'allowed_account_id = "%s"\n' "$AWS_ACCOUNT_ID"
  printf 'pki_dns           = %s\n'   "$(hcl_list "$PKI_DNS")"
  printf 'dc_count          = %s\n'   "$DC_COUNT"
  printf 'standby_dcs       = [%s]\n' "$(printf '%s' "$STANDBY_DCS" | tr ',' ' ' | tr -s ' ' | sed 's/^ //; s/ $//; s/ /, /g')"
  printf 'instance_type     = "%s"\n' "$INSTANCE_TYPE"
  printf 'web_port          = %s\n'   "$WEB_PORT"
  printf 'data_volume_gb    = %s\n'   "$DATA_GB"
  printf 'ami_id            = "%s"\n' "$AMI_ID"
  printf 'admin_cidrs       = %s\n'   "$(hcl_list "$ADMIN_CIDRS")"
  printf 'client_cidrs      = %s\n'   "$(hcl_list "$CLIENT_CIDRS")"
  printf 'enabled_protocols = %s\n'   "$(hcl_list "$protos")"
  printf 'key_backend       = "%s"\n' "$KEY_BACKEND"
  printf 'pkcs11_module     = "%s"\n' "$PKCS11_MODULE"
  printf 'ssh_key_name      = "%s"\n' "$SSH_KEY"
  printf 'route53_zone_id   = "%s"\n' "$ROUTE53_ZONE"
  printf 'public_ipv4       = %s\n'   "$([ "$PUBLIC_IPV4" = no ] && echo false || echo true)"
} > "$TFVARS"

echo >&2
echo "Wrote $TFVARS:" >&2
sed 's/^/    /' "$TFVARS" >&2

cd "$MODULE"
echo >&2; echo "==> $TF init" >&2
"$TF" init -input=false

echo >&2; echo "==> $TF plan" >&2
"$TF" plan -input=false -out=tfplan

if [ "$PLAN_ONLY" = 1 ]; then
  echo >&2
  echo "Plan written to $MODULE/tfplan. Apply it with:  cd $MODULE && $TF apply tfplan" >&2
  exit 0
fi

if interactive; then
  echo >&2
  # ⚠️ NAME WHAT IS ACTUALLY BEING CREATED. This said "and N Elastic IP(s)" unconditionally,
  # which stopped being true the moment public_ipv4 became a question — and the Elastic IP is
  # the one line item an operator recognises as billed, so a warning that invents them where
  # there are none teaches them to discount the warning.
  # Count the standbys in, because they are machines and volumes like any other and the
  # whole point of this warning is that the number is what gets billed.
  _standby_n=$(printf '%s' "$STANDBY_DCS" | tr ',' ' ' | wc -w | tr -d ' ')
  _total_n=$((DC_COUNT + _standby_n))
  if [ "$PUBLIC_IPV4" = no ]; then
    echo "⚠️  Applying creates $_total_n instance(s) and $_total_n EBS volume(s) in $REGION," >&2
    echo "    reachable over IPv6 only. You will be billed for them until you destroy them." >&2
  else
    echo "⚠️  Applying creates $_total_n instance(s), $_total_n EBS volume(s) and $_total_n Elastic IP(s)" >&2
    echo "    in $REGION. You will be billed for them until you destroy them." >&2
  fi
  [ "$_standby_n" -eq 0 ] || echo "    $_standby_n of them are standbys, in data center(s) $STANDBY_DCS." >&2
  unset _standby_n _total_n
  read -r -p "Apply? (yes/no) [no]: " go || true
  case "${go:-no}" in y|Y|yes|YES|Yes) ;; *) echo "Not applied. The plan is at $MODULE/tfplan." >&2; exit 0 ;; esac
fi

echo >&2; echo "==> $TF apply" >&2
"$TF" apply -input=false tfplan

echo >&2
"$TF" output -raw next_steps 2>/dev/null || true
echo >&2
echo "Tear it down with:  $HERE/cloud-install.sh --destroy" >&2
