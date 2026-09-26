# A literal IPv6 address goes in brackets in a URL, so an address that reads fine in a
# terminal is not one that can be pasted into a browser without them.
output "console_urls" {
  description = "One per node. Log in as admin/admin and change it immediately — the seeded row is must_reset, so it cannot enrol anything until you do."
  # 443 is left out of the URL, because a URL that names the default port is a URL somebody
  # will retype wrongly.
  value = { for k, v in local.dcs : v.index => join("", [
    "https://",
    var.public_ipv4 ? aws_eip.node[k].public_ip : "[${local.own_ipv6[k]}]",
    var.web_port == 443 ? "" : ":${var.web_port}",
  ]) }
}

# ⚠️ EVERY MACHINE, STANDBYS INCLUDED, in one output. A standby is a machine an operator has
# to reach — to join it, to check it, to log into it — and having it in a separate output
# meant "show me my addresses" answered with two thirds of them. The standbys are keyed
# "<index>-standby" so the list says which is which.
output "node_public_ips" {
  description = "Management addresses (SSH, console, enrolment) for every machine, standbys included. Empty when public_ipv4 = false — the machines are then reachable over IPv6 only, at node_public_ipv6."
  value = merge(
    { for k, v in local.dcs : v.index => try(aws_eip.node[k].public_ip, null) },
    { for k, v in local.standbys : "${v.index}-standby" => try(aws_eip.standby[k].public_ip, null) },
  )
}

output "node_public_ipv6" {
  description = "The IPv6 address of every machine's management interface, standbys included — public and free of charge, and the only public address when public_ipv4 = false."
  value = merge(
    { for k, v in local.dcs : v.index => local.own_ipv6[k] },
    { for k, v in local.standbys : "${v.index}-standby" => local.own_ipv6_standby[k] },
  )
}

output "node_interconnect_ips" {
  description = <<-EOT
    Each data center's address on the interconnect, where the other data centers' databases
    connect to it. Private to the VPC by design. deploy/mesh-join.sh reads each one from its
    server; they are listed here for checking routes (docs/deployment.md 12, step 6).
  EOT
  value       = { for k, v in local.dcs : v.index => aws_network_interface.interconnect[k].private_ip }
}

output "mesh_join" {
  description = <<-EOT
    The command that connects the data centers, with this deployment's addresses, to run from
    your own machine. The first run tells every node about the others and stops because no
    CA exists yet; create the CAs, then run it again and it finishes
    (docs/deployment.md 12, steps 6 and 10). A data center with a standby is written
    <primary>+<standby>, so its peers are given both addresses and follow a failover.
    Empty for a single data center, which has nothing to connect.
  EOT
  value = var.dc_count < 2 ? "" : join(" ", concat(["deploy/mesh-join.sh -i <your ssh key>"], [
    for k, v in local.dcs : join("+", concat(
      ["alpine@${local.own_ipv6[k]}"],
      [for sk, sv in local.standbys : "alpine@${local.own_ipv6_standby[sk]}" if sk == k]
    ))
  ]))
}

output "standby_interconnect_ips" {
  description = "Each standby's address on the interconnect — the address its primary replicates to, and the one to give ha-join."
  value       = { for k, v in local.standbys : v.index => aws_network_interface.standby_interconnect[k].private_ip }
}

output "standby_instance_ids" {
  description = "Each standby's EC2 instance id, which aws-ha-address.sh needs as --to-instance when the pair's address moves."
  value       = { for k, v in local.standbys : v.index => aws_instance.standby[k].id }
}

output "standby_join" {
  description = <<-EOT
    What to do with a standby once it is running. The machine is provisioned; it is not yet
    part of a pair, and until it is joined it is a separate empty deployment.

    ⚠️ FIRST, THE CA KEYS. A standby can only receive a CA key that was created replicable,
    and that cannot be granted afterwards. If the CAs already exist without it, they have to
    be created again — docs/deployment.md §12 step 7.

    1. Give the pair one address, before any certificate names it:
         deploy/cloud/aws-ha-address.sh create --deployment <name> --node <i>
       Both servers must answer on that address, because every certificate the CA issues
       carries it and no certificate can be told a new one later.
    2. Join it, from your own machine, with the command this output prints — one per
       standby, with this deployment's addresses:
         deploy/ha-join-pair.sh --primary alpine@<primary> --standby alpine@<standby> \
             -i <your ssh key>
       It copies the primary's database to the standby, points both servers' services at
       both, and copies the CA keys into the standby's token (docs/high-availability.md §3,
       "The join, in one command"). It is not done at first boot because it needs the
       primary's database password and token PIN, and neither may be in user-data.
    3. Test a failover before you rely on it — §4 step 5, and aws-ha-address.sh move to
       carry the address across.
  EOT
  value = length(var.standby_dcs) == 0 ? "" : join("\n", [
    for k, v in local.standbys :
    "deploy/ha-join-pair.sh --primary alpine@${local.own_ipv6[k]} --standby alpine@${local.own_ipv6_standby[k]} -i <your ssh key>   # data center ${v.index}"
  ])
}

output "ami_id" {
  description = "The AMI the nodes were launched from."
  value       = local.ami_id
}

output "next_steps" {
  description = "What to do once apply finishes."
  value       = <<-EOT
    First, check each machine finished its first boot. From your own machine:
         ssh -i <your ssh key> alpine@<address> doas cat /var/log/fastpki-firstboot.rc
       0 means it is configured. Any other number is the exit status of the step that failed,
       and /var/log/fastpki-firstboot.log on that machine says which. No file yet means first
       boot is still running.

    1. Open a console URL above and change the admin password (it is seeded must_reset,
       so nothing else works until you do).
       ${var.dc_count < 2 ? "" : "⚠️ SET THE SAME PASSWORD ON EVERY NODE. Each one seeded its own admin row, and once\n       step 5 joins them they replicate admin as ONE account: one row survives and the\n       other passwords stop working. deploy/mesh-join.sh says which row it kept.\n       "}⚠️ THE BROWSER WILL REFUSE THE CERTIFICATE, AND THAT IS CORRECT. Nothing has issued
       one yet, so the console serves the self-signed certificate the installer made:
       Firefox says MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT, Chrome ERR_CERT_AUTHORITY_INVALID.
       Take the exception once (Firefox: Advanced -> Accept the Risk and Continue); it is
       replaced in step 3, and importing the root from step 2 removes the warning for good.
       An IPv6 address needs brackets in a URL, and the console_urls output above already
       has them — with no port when web_port is 443.
       ⚠️ IF THERE IS NO "ACCEPT THE RISK" BUTTON AT ALL, the browser has HSTS cached for
       that name and HSTS forbids exceptions. It is earned by visiting the name once over
       someone else's valid HTTPS — a DNS record published through a CDN in proxy mode does
       exactly that, before the record is corrected. Reach the node by ADDRESS instead (HSTS
       is keyed to the name), or drop the entry: Firefox History -> Manage History -> the
       domain -> Forget About This Site.
    ${var.dc_count < 2 ? "" : "⚠️ ON A MESH, DO STEP 4's FIRST RUN BEFORE STEP 2. A certificate's CRLDP and AIA entries are built when it is issued, one per row in the `datacenters` table, and those rows arrive with the first run of deploy/mesh-join.sh. A node that has only its own row — which is all the installer gives it — issues CA certificates advertising ONE data center, and a certificate can never be told a new URL afterwards.\n\n    "}2. Create the root and issuing CA — no CA exists yet, and the enrolment listeners
       stay down until one does. Console, or `fastpki-ca create` over SSH.
    3. Give the CA its service credentials in one step over SSH:
       `fastpki-ca renew-service-certs --create-missing --re-issue-self-signed`.
       --create-missing issues the OCSP responder, CMP RA and SCEP RA, generating each key in
       the token (roots are skipped — nothing enrols against a root); --re-issue-self-signed
       replaces the console/EST/ACME/MS self-signed listener certificates with CA-issued
       ones, keeping their keys. Until it runs, OCSP answers internalerror, CMP refuses
       every transaction and every listener serves a certificate nothing trusts. Restart
       the services afterwards — each reads its certificate at startup.
    ${var.dc_count < 2 ? "" : "4. FIRST, THE MESH'S FIRST RUN — before any CA exists. From your own machine: `deploy/mesh-join.sh -i <ssh key> alpine@<dc1>[+alpine@<dc1-standby>] alpine@<dc2> ...`, one argument per data center, the addresses from node_public_ipv6. It tells every node about the others and stops because no CA exists yet (docs/deployment.md 12, step 6). THEN the CAs: one root, and a sub CA per data center (or one shared by all, its key replicated over P11_TLS into every node's own token; see docs/deployment.md 9.7). All CLI, over SSH — see docs/deployment.md 9.1 'From the CLI' for the exact commands: `fastpki-ca create` the root and node 1's sub CA, `fastpki-ca show root --pem` to distribute the anchor, then on each other node `fastpki-ca csr` / `sign-csr` on node 1 / `fastpki-ca add` the anchor and its own sub CA.\n    5. The mesh's second run: the same command again. It issues every database certificate from its data center's CA, connects the data centers, and waits until they hold the same data (docs/deployment.md 12, step 10)."}
  EOT
}
