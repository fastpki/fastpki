locals {
  # The port each optional protocol listens on. OCSP and the console are handled
  # separately because they are not optional. These match the ports every FastPKI binary
  # binds by default — see docs/deployment.md §1.
  protocol_ports = {
    est   = 8443
    acme  = 8444
    cmp   = 8445
    ms    = 8446
    store = 8447
    scep  = 8448
  }
  # Only the protocols this deployment actually installs get a rule. A port opened for a
  # service that is not running is not harmless: it is a rule nobody can explain later,
  # and it survives the next person's audit as "something must need this".
  open_protocol_ports = {
    for p in var.enabled_protocols : p => local.protocol_ports[p]
  }

  # ⚠️ ONE ADDRESS FAMILY PER RULE. aws_vpc_security_group_ingress_rule takes cidr_ipv4 OR
  # cidr_ipv6 and rejects a v6 prefix in the v4 argument, so every rule below exists twice
  # and each half gets only the prefixes it can express. Splitting here rather than asking
  # for two variables keeps the question the operator answers a single one — "who may reach
  # this" — in the wizard and in the tfvars.
  admin_v4  = [for c in var.admin_cidrs : c if !strcontains(c, ":")]
  admin_v6  = [for c in var.admin_cidrs : c if strcontains(c, ":")]
  client_v4 = [for c in var.client_cidrs : c if !strcontains(c, ":")]
  client_v6 = [for c in var.client_cidrs : c if strcontains(c, ":")]
  # Who may reach the enrolment protocols and revocation: administrators plus clients.
  serving_v4 = concat(local.admin_v4, local.client_v4)
  serving_v6 = concat(local.admin_v6, local.client_v6)
}

resource "aws_security_group" "mgmt" {
  name        = "${var.deployment_name}-mgmt"
  description = "FastPKI management: SSH and the web console"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.deployment_name}-mgmt" }
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  for_each          = var.ssh_key_name == "" ? toset([]) : toset(local.admin_v4)
  security_group_id = aws_security_group.mgmt.id
  cidr_ipv4         = each.value
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  description       = "SSH from an administrator"
}

resource "aws_vpc_security_group_ingress_rule" "ssh_v6" {
  for_each          = var.ssh_key_name == "" ? toset([]) : toset(local.admin_v6)
  security_group_id = aws_security_group.mgmt.id
  cidr_ipv6         = each.value
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  description       = "SSH from an administrator (IPv6)"
}

resource "aws_vpc_security_group_ingress_rule" "console" {
  for_each          = toset(local.admin_v4)
  security_group_id = aws_security_group.mgmt.id
  cidr_ipv4         = each.value
  from_port         = var.web_port
  to_port           = var.web_port
  ip_protocol       = "tcp"
  # HTTPS. The console serves its own TLS because the in-browser key generation and the
  # HSM slot picker need a secure context — plain HTTP would disable both.
  description = "FastPKI console (HTTPS) from an administrator"
}

resource "aws_vpc_security_group_ingress_rule" "console_v6" {
  for_each          = toset(local.admin_v6)
  security_group_id = aws_security_group.mgmt.id
  cidr_ipv6         = each.value
  from_port         = var.web_port
  to_port           = var.web_port
  ip_protocol       = "tcp"
  description       = "FastPKI console (HTTPS) from an administrator (IPv6)"
}

# OCSP and CRL, on the same listener. Separated from the optional protocols below because
# it is not optional: relying parties check revocation here, and a PKI that publishes
# certificates without publishing revocation is incomplete rather than smaller. It is
# still gated on client_cidrs — a demo nobody outside your network uses should not answer
# the internet either.
resource "aws_vpc_security_group_ingress_rule" "ocsp" {
  for_each          = toset(local.serving_v4)
  security_group_id = aws_security_group.mgmt.id
  cidr_ipv4         = each.value
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
  description       = "OCSP responder and CRL distribution point"
}

resource "aws_vpc_security_group_ingress_rule" "ocsp_v6" {
  for_each          = toset(local.serving_v6)
  security_group_id = aws_security_group.mgmt.id
  cidr_ipv6         = each.value
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
  description       = "OCSP responder and CRL distribution point (IPv6)"
}

resource "aws_vpc_security_group_ingress_rule" "protocols" {
  for_each = {
    for pair in setproduct(keys(local.open_protocol_ports), local.serving_v4) :
    "${pair[0]}-${pair[1]}" => { proto = pair[0], cidr = pair[1] }
  }
  security_group_id = aws_security_group.mgmt.id
  cidr_ipv4         = each.value.cidr
  from_port         = local.open_protocol_ports[each.value.proto]
  to_port           = local.open_protocol_ports[each.value.proto]
  ip_protocol       = "tcp"
  description       = "FastPKI ${each.value.proto} enrolment"
}

resource "aws_vpc_security_group_ingress_rule" "protocols_v6" {
  for_each = {
    for pair in setproduct(keys(local.open_protocol_ports), local.serving_v6) :
    "${pair[0]}-${pair[1]}" => { proto = pair[0], cidr = pair[1] }
  }
  security_group_id = aws_security_group.mgmt.id
  cidr_ipv6         = each.value.cidr
  from_port         = local.open_protocol_ports[each.value.proto]
  to_port           = local.open_protocol_ports[each.value.proto]
  ip_protocol       = "tcp"
  description       = "FastPKI ${each.value.proto} enrolment (IPv6)"
}

resource "aws_vpc_security_group_egress_rule" "mgmt_out" {
  security_group_id = aws_security_group.mgmt.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  # Outbound is open because the node has to reach apk mirrors for security updates, an
  # OCSP/CRL of its own upstream if it has one, and whatever audit sink is configured.
  # Narrow it if your environment has a proxy; it is stated here rather than assumed.
  description = "Outbound (package mirrors, audit forwarding, upstream revocation)"
}

# ⚠️ WITHOUT THIS A NODE WITH NO PUBLIC IPv4 HAS NO EGRESS AT ALL. A security group's
# default allow-all egress is replaced the moment any egress rule is declared, and the v4
# rule above is one — so the v6 half has to be stated too, or a public_ipv4 = false
# deployment cannot reach a package mirror, an upstream CRL or a notification relay.
resource "aws_vpc_security_group_egress_rule" "mgmt_out_v6" {
  security_group_id = aws_security_group.mgmt.id
  cidr_ipv6         = "::/0"
  ip_protocol       = "-1"
  description       = "Outbound over IPv6 (package mirrors, audit forwarding, upstream revocation)"
}

# ── the interconnect ─────────────────────────────────────────────────────────────────
resource "aws_security_group" "interconnect" {
  name        = "${var.deployment_name}-interconnect"
  description = "FastPKI mesh: PostgreSQL logical replication between nodes"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.deployment_name}-interconnect" }
}

# ⚠️ SELF-REFERENTIAL, NOT A CIDR LIST. The only things allowed to open 5432 are the other
# members of this same security group. That stays correct when a node is replaced and its
# address changes, and it cannot be widened by editing a variable — which a CIDR list can.
resource "aws_vpc_security_group_ingress_rule" "mesh_pg" {
  security_group_id            = aws_security_group.interconnect.id
  referenced_security_group_id = aws_security_group.interconnect.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  description                  = "PostgreSQL logical replication from a peer node"
}

# The key tunnel (P11_TLS) between the two servers of a data center with a standby. A
# promoted standby can sign only with CA keys copied into its own token, and they are copied
# over this port. It listens on every interface, and peers dial each server's interconnect
# address, so this is the rule that decides who reaches it: the same self-reference as 5432,
# with mutual TLS on top. 12345 is the installer's P11_TLS_PORT default, which the first-boot
# script does not change.
resource "aws_vpc_security_group_ingress_rule" "mesh_p11_tls" {
  count                        = length(var.standby_dcs) > 0 ? 1 : 0
  security_group_id            = aws_security_group.interconnect.id
  referenced_security_group_id = aws_security_group.interconnect.id
  from_port                    = 12345
  to_port                      = 12345
  ip_protocol                  = "tcp"
  description                  = "FastPKI key tunnel (P11_TLS) between the two servers of a pair"
}

resource "aws_vpc_security_group_egress_rule" "mesh_out" {
  security_group_id            = aws_security_group.interconnect.id
  referenced_security_group_id = aws_security_group.interconnect.id
  ip_protocol                  = "-1"
  # ⚠️ ASCII ONLY, AND THE EM DASH THIS USED TO CARRY FAILED THE APPLY. EC2 accepts rule
  # descriptions from exactly `a-zA-Z0-9. _-:/()#,@[]+=&;{}!$*` and rejects anything else with
  # `InvalidParameterValue: Invalid rule description` — naming neither the character nor the
  # resource's own text. This tree writes em dashes in prose by habit, so every string that
  # reaches an AWS API has to be checked against that set; a Terraform `description` on a
  # variable or output is fine, because it never leaves the plan.
  description = "To peer nodes only: the interconnect has no route off the VPC"
}
