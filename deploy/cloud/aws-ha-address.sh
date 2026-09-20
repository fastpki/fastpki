#!/usr/bin/env bash
# deploy/cloud/aws-ha-address.sh — the one address an HA pair advertises, on AWS.
#
#   ./aws-ha-address.sh create --deployment fastpki --node 1
#   ./aws-ha-address.sh show   --deployment fastpki --node 1
#   ./aws-ha-address.sh move   --deployment fastpki --node 1 --to-instance i-0abc… --ssh alpine@…
#
# ── WHY THIS EXISTS ───────────────────────────────────────────────────────────────────
#
# An HA pair advertises ONE address. That is what makes a failover invisible, and
# docs/high-availability.md is explicit that per-host URLs are not an alternative: the CRLDP
# and AIA URLs inside an already-issued certificate can never be changed, and every client
# holding one would have to be reconfigured.
#
# ⚠️ ON A HYPERVISOR THAT ADDRESS IS A VIP. IN A VPC IT CANNOT BE, AND keepalived DOES
# NOTHING USEFUL THERE. VRRP needs multicast and needs a host to claim an address by
# advertising it on the wire; a VPC delivers traffic only to the interface an address is
# assigned to, and drops the rest at the source/destination check. The failure mode is the
# bad kind: keepalived installs, runs, elects a master and logs success, while the address
# it "holds" is unreachable from anywhere.
#
# What does work is moving the address between the two nodes' interfaces through the EC2
# API. With the IPv6 posture (public_ipv4 = false) this is cheap and clean: extra IPv6
# addresses cost nothing, both members of a pair sit in one subnet, and a client sees the
# SAME address before and after — so there is no DNS record to update and no TTL to wait
# out. The name in every certificate keeps resolving to an address that is now answered by
# the survivor.
#
# ⚠️ THIS RUNS ON THE OPERATOR'S MACHINE, NOT ON A NODE, AND THAT IS A SECURITY DECISION
# RATHER THAN A CONVENIENCE. Doing it from the node would need an instance profile letting a
# host that holds CA private keys reassign addresses inside its own VPC — a lateral-movement
# primitive bought to save one SSH hop. The credential belongs where the human is.
#
# ⚠️ IT DOES NOT PROMOTE ANYTHING. deploy/pg-promote.sh promotes the database; this moves the
# address afterwards. Keeping them apart is deliberate: one script that both promotes a
# database and rewrites cloud networking would concentrate far more authority than either
# job needs, and the promotion has to be judged by a person anyway.
set -eu

die() { echo "aws-ha-address: $*" >&2; exit 1; }

usage() {
  sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'
  cat >&2 <<'EOF'

Commands:
  create   Allocate the pair's service address on this node's interface and record it.
  show     Print the address and which instance currently answers on it.
  move     Move it to the surviving node: unassign, assign, configure, verify.

Options:
  --deployment NAME    deployment_name from the tfvars (default: fastpki)
  --node N             which data center of the mesh this pair is (default: 1)
  --region R           AWS region (default: $AWS_REGION, else the profile's)
  --profile P          AWS profile (default: $AWS_PROFILE, else the default chain)
  --to-instance ID     move: the instance that should answer on the address
  --to-eni ID          move: its interface, if the instance has more than one
  --ssh USER@HOST      move: how to reach the new holder to configure it locally
  --from-ssh USER@HOST move: the old holder, to remove the address there if it is alive
  -i KEY               move: the SSH private key for --ssh and --from-ssh
  --dry-run            print every API call instead of making it
EOF
  exit "${1:-2}"
}

CMD="${1:-}"; [ -n "$CMD" ] || usage
case "$CMD" in create|show|move) shift ;; -h|--help) usage 0 ;; *) die "unknown command: $CMD" ;; esac

DEPLOYMENT=fastpki NODE=1 REGION="" PROFILE="" TO_INSTANCE="" TO_ENI="" SSH_NEW="" SSH_OLD="" SSH_KEY="" DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --deployment)  DEPLOYMENT="${2:?}"; shift 2 ;;
    --node)        NODE="${2:?}"; shift 2 ;;
    --region)      REGION="${2:?}"; shift 2 ;;
    --profile)     PROFILE="${2:?}"; shift 2 ;;
    --to-instance) TO_INSTANCE="${2:?}"; shift 2 ;;
    --to-eni)      TO_ENI="${2:?}"; shift 2 ;;
    --ssh)         SSH_NEW="${2:?}"; shift 2 ;;
    --from-ssh)    SSH_OLD="${2:?}"; shift 2 ;;
    -i)            SSH_KEY="${2:?}"; shift 2 ;;
    --dry-run)     DRY=1; shift ;;
    -h|--help)     usage ;;
    *) die "unknown argument: $1" ;;
  esac
done
case "$NODE" in ''|*[!0-9]*) die "--node must be a number" ;; esac

command -v aws >/dev/null 2>&1 || die "the AWS CLI is not on PATH"
AWS=(aws)
[ -n "$PROFILE" ] && AWS+=(--profile "$PROFILE")
[ -n "$REGION" ]  && AWS+=(--region "$REGION")

# The same SSH as deploy/mesh-join.sh and deploy/ha-join-pair.sh: the operator's own key, no
# password prompt to hang on, and a first connection to a replaced machine accepted.
SSH=(ssh -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
[ -n "$SSH_KEY" ] && SSH+=(-i "$SSH_KEY" -o IdentitiesOnly=yes)
# Root on the node through doas, which is what the Alpine cloud image has; sudo elsewhere.
ROOT='$(command -v doas || command -v sudo)'

aws_do() {   # every call that CHANGES something goes through here, so --dry-run is honest
  if [ "$DRY" = 1 ]; then echo "+ aws $*" >&2; return 0; fi
  "${AWS[@]}" "$@"
}

# ⚠️ THE ADDRESS IS RECORDED IN AWS, NOT IN A FILE HERE. A failover is exactly the moment
# when the laptop that ran `create` is not the laptop in front of you, so state that lives
# only on one workstation is state that is missing when it is needed. The VPC carries a tag.
TAGKEY="FastPKIServiceAddress-${DEPLOYMENT}-dc${NODE}"

# ⚠️ RESOLVED ONCE, IN THE MAIN SHELL. `die` inside a function called as `$(f)` exits only
# the subshell, so a lookup that failed there printed its message and let the caller carry on
# to fail again differently — two errors for one cause, the first of which is the real one.
# Resolving it here means a bad --deployment/--region/--profile is one message and a stop.
vpc_id() {
  local id
  id=$("${AWS[@]}" ec2 describe-vpcs --filters "Name=tag:Name,Values=${DEPLOYMENT}" \
        --query 'Vpcs[0].VpcId' --output text 2>/dev/null || true)
  if [ -z "$id" ] || [ "$id" = None ]; then
    # ⚠️ SAY WHICH ACCOUNT WAS SEARCHED. AWS credentials are ambient, so by far the most
    # common cause of "not found" is looking in the wrong account — a shell without
    # AWS_PROFILE falls back to the default profile, which for anyone with two accounts is
    # the other one. Listing three possible causes made the operator check the two that were
    # right. The account number and region answer it at a glance: compare them with
    # allowed_account_id in the tfvars.
    local who region
    who=$("${AWS[@]}" sts get-caller-identity --query Account --output text 2>/dev/null || echo "unknown")
    # --region first: it is what the search used, and the profile's region is not.
    region=$REGION
    [ -n "$region" ] || region=$("${AWS[@]}" configure get region 2>/dev/null || true)
    [ -n "$region" ] || region="${AWS_REGION:-${AWS_DEFAULT_REGION:-unset}}"
    die "no VPC tagged Name=${DEPLOYMENT} in account ${who}, region ${region}.
    If that account number is not the one this deployment lives in, the credentials are the
    problem, not the name: pass --profile <name>, or export AWS_PROFILE. Otherwise check
    --deployment against deployment_name in deploy/cloud/aws/terraform.tfvars."
  fi
  printf '%s' "$id"
}
VPC=$(vpc_id)

recorded_address() {
  local v; v=$("${AWS[@]}" ec2 describe-vpcs --vpc-ids "$VPC" \
      --query "Vpcs[0].Tags[?Key=='${TAGKEY}'].Value | [0]" --output text 2>/dev/null || true)
  [ "$v" = None ] && v=""
  printf '%s' "$v"
}

# The interface of the module-built node, by the tag the module writes.
node_eni() {
  local id
  id=$("${AWS[@]}" ec2 describe-network-interfaces \
        --filters "Name=tag:Name,Values=${DEPLOYMENT}-mgmt-${NODE}" \
        --query 'NetworkInterfaces[0].NetworkInterfaceId' --output text 2>/dev/null || true)
  [ -n "$id" ] && [ "$id" != None ] || die "no interface tagged ${DEPLOYMENT}-mgmt-${NODE}"
  printf '%s' "$id"
}

# Which interface answers on the address right now — asked of AWS rather than remembered,
# because the answer changes without this script when somebody moves it by hand.
holder_eni() {
  local addr="$1" id
  id=$("${AWS[@]}" ec2 describe-network-interfaces \
        --filters "Name=ipv6-addresses.ipv6-address,Values=${addr}" \
        --query 'NetworkInterfaces[0].NetworkInterfaceId' --output text 2>/dev/null || true)
  [ "$id" = None ] && id=""
  printf '%s' "$id"
}

eni_subnet()   { "${AWS[@]}" ec2 describe-network-interfaces --network-interface-ids "$1" \
                   --query 'NetworkInterfaces[0].SubnetId' --output text; }
eni_instance() { "${AWS[@]}" ec2 describe-network-interfaces --network-interface-ids "$1" \
                   --query 'NetworkInterfaces[0].Attachment.InstanceId' --output text; }

case "$CMD" in
create)
  addr=$(recorded_address)
  [ -z "$addr" ] || die "a service address already exists for dc${NODE}: $addr (use show, or move)"
  eni=$(node_eni)
  echo "Allocating a service address on ${eni} (node ${NODE} of ${DEPLOYMENT})…" >&2
  if [ "$DRY" = 1 ]; then
    aws_do ec2 assign-ipv6-addresses --network-interface-id "$eni" --ipv6-address-count 1
    aws_do ec2 create-tags --resources "$VPC" --tags "Key=${TAGKEY},Value=<the new address>"
    exit 0
  fi
  addr=$("${AWS[@]}" ec2 assign-ipv6-addresses --network-interface-id "$eni" \
          --ipv6-address-count 1 --query 'AssignedIpv6Addresses[0]' --output text)
  [ -n "$addr" ] && [ "$addr" != None ] || die "AWS assigned no address"
  "${AWS[@]}" ec2 create-tags --resources "$VPC" --tags "Key=${TAGKEY},Value=${addr}" >/dev/null
  cat >&2 <<EOF

Service address for dc${NODE}: ${addr}

Next, and in this order:
  1. Configure it on the node that holds it — the address exists in AWS but the operating
     system does not know about it until it is added to the interface:
       ip -6 addr add ${addr}/128 dev eth0
     and persist it, so a reboot does not quietly drop the pair's address:
       printf 'ip -6 addr add ${addr}/128 dev eth0\\n' > /etc/local.d/fastpki-ha-address.start
       chmod +x /etc/local.d/fastpki-ha-address.start && rc-update add local default
  2. Point this data center's PKI_DNS name at ${addr} (AAAA).
  3. ⚠️ CREATE THE CA HIERARCHY ONLY AFTER 2. Every certificate's CRLDP and AIA URLs are
     derived when it is minted, so a hierarchy created against a host's own name names the
     machine a failover kills, and no certificate can be told a new URL afterwards.
EOF
  ;;

show)
  addr=$(recorded_address)
  [ -n "$addr" ] || die "no service address recorded for dc${NODE} — run: $0 create --deployment ${DEPLOYMENT} --node ${NODE}"
  eni=$(holder_eni "$addr")
  if [ -z "$eni" ]; then
    echo "${addr}  — recorded, but NO interface currently holds it."
    echo "  Nothing answers on this address. Move it to a live node:"
    echo "    $0 move --deployment ${DEPLOYMENT} --node ${NODE} --to-instance <id> --ssh <user@host>"
    exit 1
  fi
  inst=$(eni_instance "$eni")
  echo "${addr}"
  echo "  interface: ${eni}"
  echo "  instance:  ${inst}"
  echo "  subnet:    $(eni_subnet "$eni")"
  ;;

move)
  addr=$(recorded_address)
  [ -n "$addr" ] || die "no service address recorded for dc${NODE} — run create first"
  [ -n "$TO_INSTANCE" ] || [ -n "$TO_ENI" ] || die "move needs --to-instance or --to-eni"
  if [ -z "$TO_ENI" ]; then
    TO_ENI=$("${AWS[@]}" ec2 describe-network-interfaces \
      --filters "Name=attachment.instance-id,Values=${TO_INSTANCE}" \
      --query 'NetworkInterfaces[?Attachment.DeviceIndex==`0`].NetworkInterfaceId | [0]' --output text)
    [ -n "$TO_ENI" ] && [ "$TO_ENI" != None ] || die "no device-index 0 interface on ${TO_INSTANCE} — pass --to-eni"
  fi
  from_eni=$(holder_eni "$addr")

  # ⚠️ AN INTERFACE CAN ONLY HOLD ADDRESSES FROM ITS OWN SUBNET'S PREFIX. A standby launched
  # into the other AZ's subnet — which looks like the more resilient choice, and is the one
  # an operator reaches for — cannot take this address at all. Refused here, with the reason,
  # rather than as an opaque InvalidParameterValue from the API.
  # ⚠️ ALREADY ASSIGNED STILL CONFIGURES THE HOSTS. A move whose SSH half failed leaves the
  # address on the right interface and on no host's network stack; stopping here with "already
  # on" made running the same command again unable to finish it.
  if [ "$from_eni" = "$TO_ENI" ]; then
    echo "${addr} is already assigned to ${TO_ENI} in AWS; configuring the hosts." >&2
  else
    if [ -n "$from_eni" ]; then
      a=$(eni_subnet "$from_eni"); b=$(eni_subnet "$TO_ENI")
      [ "$a" = "$b" ] || die "the target interface is in ${b} but the address belongs to ${a} — a pair must share one subnet"
      echo "Unassigning ${addr} from ${from_eni}…" >&2
      aws_do ec2 unassign-ipv6-addresses --network-interface-id "$from_eni" --ipv6-addresses "$addr" >/dev/null
    else
      echo "No interface currently holds ${addr} — assigning it fresh." >&2
    fi
    echo "Assigning ${addr} to ${TO_ENI}…" >&2
    aws_do ec2 assign-ipv6-addresses --network-interface-id "$TO_ENI" --ipv6-addresses "$addr" >/dev/null
  fi

  # The API half only makes the address routable TO the instance. Until the OS holds it, the
  # kernel answers nothing on it — packets arrive and are dropped, which looks exactly like a
  # security group problem and is not one.
  if [ -n "$SSH_OLD" ]; then
    echo "Removing it from the old host (${SSH_OLD})…" >&2
    if [ "$DRY" = 1 ]; then echo "+ ssh ${SSH_OLD} ip -6 addr del ${addr}/128 dev eth0" >&2
    elif ! err=$("${SSH[@]}" "$SSH_OLD" "R=${ROOT}; \$R ip -6 addr del ${addr}/128 dev eth0 2>/dev/null; \
           \$R rm -f /etc/local.d/fastpki-ha-address.start" 2>&1); then
      # ⚠️ A HOST THAT ANSWERS AND REFUSES IS NOT THE FAILED HOST. Reported as "unreachable",
      # a key problem left the address configured on a live machine that no longer receives it.
      case "$err" in
        *"Permission denied"*|*"not permitted"*|*"doas:"*|*"sudo:"*)
          echo "  it answered but refused: ${err##*$'\n'}" >&2
          echo "  remove the address there by hand:  ip -6 addr del ${addr}/128 dev eth0" >&2 ;;
        *) echo "  (unreachable — it is the failed host, which is the normal case)" >&2 ;;
      esac
    fi
  fi
  if [ -n "$SSH_NEW" ]; then
    echo "Configuring it on ${SSH_NEW}…" >&2
    if [ "$DRY" = 1 ]; then echo "+ ssh ${SSH_NEW} ip -6 addr add ${addr}/128 dev eth0" >&2
    else
      "${SSH[@]}" "$SSH_NEW" "R=${ROOT}; \$R ip -6 addr add ${addr}/128 dev eth0 2>/dev/null || true; \
        printf 'ip -6 addr add ${addr}/128 dev eth0\\n' | \$R tee /etc/local.d/fastpki-ha-address.start >/dev/null; \
        \$R chmod +x /etc/local.d/fastpki-ha-address.start; \$R rc-update add local default >/dev/null 2>&1 || true" \
        || die "could not configure the address on ${SSH_NEW} — it is assigned in AWS but nothing answers on it yet"
    fi
  else
    echo "No --ssh given. The address is assigned in AWS but NOT yet configured on the host," >&2
    echo "so nothing answers on it. On the new holder, run:" >&2
    echo "  ip -6 addr add ${addr}/128 dev eth0" >&2
  fi

  [ "$DRY" = 1 ] && exit 0
  # The console's port is the node's WEB_PORT: 443 on a cloud node installed with web_port = 443.
  port=""
  [ -n "$SSH_NEW" ] && port=$("${SSH[@]}" "$SSH_NEW" \
      "R=${ROOT}; \$R sed -n 's/^WEB_PORT=//p' /etc/fastpki/bootstrap.conf" 2>/dev/null | head -1)
  port=${port:-8090}
  echo "Verifying…" >&2
  if command -v curl >/dev/null 2>&1 &&
     curl -sk -o /dev/null --max-time 8 "https://[${addr}]:${port}/" 2>/dev/null; then
    echo "OK: the console answers on [${addr}]:${port} — the pair's address follows the survivor."
  else
    echo "WARN: nothing answered on [${addr}]:${port} yet. Check that this workstation has IPv6," >&2
    echo "      that the services are running on the new holder, and that its security group" >&2
    echo "      admits you." >&2
  fi
  ;;
esac
