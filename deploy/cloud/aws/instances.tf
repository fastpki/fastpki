# One instance per datacenter, from the AMI deploy/cloud/image baked.

data "aws_ami" "fastpki" {
  count       = var.ami_id == "" ? 1 : 0
  owners      = ["self"] # never a public image: an AMI id is code that runs as root on a CA host
  most_recent = true
  filter {
    name   = "name"
    values = ["fastpki-*"]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
}

locals {
  ami_id = var.ami_id != "" ? var.ami_id : data.aws_ami.fastpki[0].id
  # Prefix length of the interconnect subnets, for the static address the boot script
  # puts on eth1. cidrsubnet(/16, 8, …) yields /24, but deriving it keeps this correct if
  # vpc_cidr changes.
  interconnect_prefix = tonumber(split("/", cidrsubnet(var.vpc_cidr, 8, 101))[1])
  # Per data center: every OTHER data center's interconnect subnet, and this one's router
  # (the subnet's first address). The first-boot script routes the peers through eth1, which
  # the interconnect security group requires — see section 1 of user-data.sh.tftpl.
  interconnect_peers = {
    for k, s in aws_subnet.interconnect :
    k => join(" ", [for pk, ps in aws_subnet.interconnect : ps.cidr_block if pk != k])
  }
  interconnect_gateway = { for k, s in aws_subnet.interconnect : k => cidrhost(s.cidr_block, 1) }
}

# ── BOTH INTERFACES ARE EXPLICIT RESOURCES, AND BOTH ATTACH AT LAUNCH ────────────────
#
# The obvious spelling — put subnet_id on the instance and attach the second ENI with
# aws_network_interface_attachment — has an ordering bug that only shows up at first boot:
# that attachment depends on the instance, so it happens AFTER the instance is running and
# after cloud-init has already run. The boot script configures the interconnect address
# and PostgreSQL binds to it, so on a fresh node the address would not exist yet and
# postgres would fail to start. Declaring both interfaces on the instance attaches both
# before the machine is powered on.
resource "aws_network_interface" "mgmt" {
  for_each        = local.dcs
  subnet_id       = aws_subnet.mgmt[each.key].id
  security_groups = [aws_security_group.mgmt.id]
  description     = "${var.deployment_name} node ${each.value.index} management"
  # One IPv6 address, which is PUBLIC and free — an IPv6 address in a subnet routed to the
  # internet gateway is globally reachable with no equivalent of an Elastic IP and no
  # hourly charge. With public_ipv4 = false this is the node's only public address.
  ipv6_address_count = 1
  tags               = { Name = "${var.deployment_name}-mgmt-${each.value.index}" }

  # ⚠️ A PAIR'S SERVICE ADDRESS IS A SECOND IPv6 ADDRESS ON THIS INTERFACE, assigned and moved
  # between the pair's interfaces by deploy/cloud/aws-ha-address.sh, outside OpenTofu and on
  # purpose. Without this, every later `tofu apply` removed it again, and the name clients use
  # stopped answering. The one address set here is still assigned when the interface is made.
  lifecycle {
    ignore_changes = [ipv6_address_count, ipv6_address_list, ipv6_addresses]
  }
}

# A second ENI rather than a second address on the first, so the two paths are separable
# at the interface level: a partition test blackholes this one and the SSH session on eth0
# survives, which is exactly how deploy/lab exercises the mesh. It also means the
# interconnect security group applies to the replication path and to nothing else.
resource "aws_network_interface" "interconnect" {
  for_each        = local.dcs
  subnet_id       = aws_subnet.interconnect[each.key].id
  security_groups = [aws_security_group.interconnect.id]
  description     = "${var.deployment_name} node ${each.value.index} mesh interconnect"
  tags            = { Name = "${var.deployment_name}-interconnect-${each.value.index}" }
}

# The PostgreSQL cluster, the token and /var/pki. Kept off the root volume so that
# replacing an instance replaces only the disposable half. See data_volume_gb.
resource "aws_ebs_volume" "data" {
  for_each          = local.dcs
  availability_zone = each.value.az
  size              = var.data_volume_gb
  type              = "gp3"
  encrypted         = true
  tags              = { Name = "${var.deployment_name}-data-${each.value.index}" }

  lifecycle {
    # With key_backend = softhsm this volume holds every CA private key on the node, and
    # with either backend it holds every issued certificate. A `tofu apply` that would
    # destroy it is a mistake by definition — there is no legitimate change to this module
    # whose correct outcome is "delete the CA". Removing it is a deliberate act, and
    # deliberate acts can remove this block first.
    prevent_destroy = true
  }
}

resource "aws_volume_attachment" "data" {
  for_each    = local.dcs
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.data[each.key].id
  instance_id = aws_instance.node[each.key].id
}

locals {
  # The data centers that asked for a standby, keyed the same way as local.dcs so every
  # standby resource can index the primary's subnets, AZ and answers with the same key.
  standbys = { for i in var.standby_dcs : tostring(i) => local.dcs[tostring(i)] }
}

# ⚠️ A PAIR'S INTERFACE CARRIES TWO IPv6 ADDRESSES: the machine's own, and the pair's
# service address, which deploy/cloud/aws-ha-address.sh adds, moves to the survivor at a
# failover, and records as a VPC tag. Taking "the first address" picked the service address
# for the primary, so every output that meant THIS MACHINE — SSH, its console, the mesh and
# join commands — named whichever machine held the address at the time.
locals {
  service_address = { for k, v in local.dcs :
    k => lookup(aws_vpc.this.tags_all, "FastPKIServiceAddress-${var.deployment_name}-dc${v.index}", "")
  }
  own_ipv6 = { for k, v in local.dcs :
    k => [for a in sort(tolist(aws_network_interface.mgmt[k].ipv6_addresses)) : a if a != local.service_address[k]][0]
  }
  own_ipv6_standby = { for k, v in local.standbys :
    k => [for a in sort(tolist(aws_network_interface.standby_mgmt[k].ipv6_addresses)) : a if a != local.service_address[k]][0]
  }
  # What clients reach a data center at: its pair's service address when it has one, so a
  # failover changes nothing outside; otherwise its node's own.
  client_ipv6 = { for k, v in local.dcs :
    k => local.service_address[k] != "" ? local.service_address[k] : local.own_ipv6[k]
  }
}

resource "aws_instance" "node" {
  for_each      = local.dcs
  ami           = local.ami_id
  instance_type = var.instance_type
  key_name      = var.ssh_key_name != "" ? var.ssh_key_name : null

  network_interface {
    network_interface_id = aws_network_interface.mgmt[each.key].id
    device_index         = 0
  }
  network_interface {
    network_interface_id = aws_network_interface.interconnect[each.key].id
    device_index         = 1
  }

  # ⚠️ NO volume_size HERE, DELIBERATELY. An instance's root volume can never be smaller than
  # the snapshot it is launched from, so pinning a number here can only ever be equal to or
  # larger than the AMI's — and when the two disagree, apply fails with a message about
  # snapshot sizes rather than about the number somebody edited. Omitting it inherits the
  # AMI's size, which makes the image's `root_volume_gb` the ONE place the root size is
  # decided. That is also the only place it CAN be decided: the image is built by compiling
  # four C/C++ projects on the build instance, so the floor is what that build needs, not
  # what the finished system occupies — measured at 264 MB in use, from a 175 MB image.
  root_block_device {
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    # IMDSv2 only. A host that terminates TLS and holds CA keys is precisely the host
    # where an SSRF that can read instance metadata matters, and v1's unauthenticated GET
    # is what makes that reachable.
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    # ⚠️ OFF BY DEFAULT, and first boot is what depends on it: user-data — the answers file
    # fastpki-install-native consumes — is fetched from the instance metadata service. The
    # node keeps a PRIVATE IPv4 address even with public_ipv4 = false, so cloud-init still
    # reaches 169.254.169.254; this enables fd00:ec2::254 beside it rather than instead of
    # it, so the first-boot path does not depend on the client's cloud-init version.
    http_protocol_ipv6 = "enabled"
  }

  # ⚠️ GZIPPED, BECAUSE EC2 REFUSES USER-DATA OVER 16384 BYTES and the first-boot script
  # outgrew it: 17729 bytes rendered, "expected length of user_data to be in the range (0 -
  # 16384)" at plan time, so no node could be launched at all. Compressed it is about 9300
  # bytes; cloud-init recognises gzip and unpacks it before running the script, and the
  # script keeps its comments. tests/deploy_parity.sh measures the compressed size.
  user_data_base64 = base64gzip(templatefile("${path.module}/user-data.sh.tftpl", {
    dc_index             = each.value.index
    dc_count             = var.dc_count
    pki_dns              = length(var.pki_dns) == 1 ? var.pki_dns[0] : var.pki_dns[each.value.index - 1]
    key_backend          = var.key_backend
    pkcs11_module        = var.pkcs11_module
    protocols            = var.enabled_protocols
    interconnect_ip      = aws_network_interface.interconnect[each.key].private_ip
    interconnect_prefix  = local.interconnect_prefix
    interconnect_gateway = local.interconnect_gateway[each.key]
    interconnect_peers   = local.interconnect_peers[each.key]
    web_port             = var.web_port
    # Both servers of a data center with a standby are installed with HA_ENABLED, the same
    # switch as install.sh, install-native.sh and Kubernetes: the key tunnel on, so the
    # standby can be given the CA keys, and service keys created copyable.
    ha_enabled = contains(var.standby_dcs, each.value.index)
  }))
  # Changing the answers must rebuild the node, not silently do nothing: cloud-init runs
  # user-data once per instance, so an edited template that did not force replacement
  # would leave a running deployment configured the old way with no signal at all.
  user_data_replace_on_change = true

  tags = {
    Name         = "${var.deployment_name}-${each.value.index}"
    DatacenterId = tostring(each.value.index)
  }

  depends_on = [terraform_data.az_check]
}

# ⚠️ THE ONLY BILLED ADDRESS IN THIS MODULE. AWS charges $0.005/hour for every public IPv4
# address — running, stopped, or merely allocated — while IPv6 costs nothing. public_ipv4 =
# false drops these and leaves the nodes reachable over IPv6 alone, which is correct exactly
# when every client, relying party and administrator has IPv6. The nodes keep their PRIVATE
# IPv4 addresses either way, so the interconnect, the metadata service and the mesh
# conninfos are unaffected.
resource "aws_eip" "node" {
  for_each          = var.public_ipv4 ? local.dcs : {}
  network_interface = aws_network_interface.mgmt[each.key].id
  domain            = "vpc"
  tags              = { Name = "${var.deployment_name}-${each.value.index}" }
  # An EIP on a multi-ENI instance must wait for the instance to exist, or the association
  # lands on an interface AWS has not yet attached anything to.
  depends_on = [aws_instance.node]
}

# ── STANDBY SERVERS ──────────────────────────────────────────────────────────────────────
#
# A standby is a second machine in the SAME data center, and therefore in the same two
# subnets as its primary. It is not another data center: it shares the primary's serial
# prefix, its public name and its availability zone, and it holds a streaming copy of the
# primary's database rather than a database of its own.
#
# Everything below mirrors the primary's resources. What is deliberately NOT here is the
# join: the standby has to be handed the primary's database CA certificate out of band
# before it can verify the primary, and that is an operator step with a decision in it.
# See the standby_join output and docs/high-availability.md §4.
resource "aws_network_interface" "standby_mgmt" {
  for_each           = local.standbys
  subnet_id          = aws_subnet.mgmt[each.key].id
  security_groups    = [aws_security_group.mgmt.id]
  description        = "${var.deployment_name} node ${each.value.index} standby management"
  ipv6_address_count = 1
  tags               = { Name = "${var.deployment_name}-mgmt-${each.value.index}-standby" }

  # The same as the primary's: a failover moves the pair's service address onto this one.
  lifecycle {
    ignore_changes = [ipv6_address_count, ipv6_address_list, ipv6_addresses]
  }
}

resource "aws_network_interface" "standby_interconnect" {
  for_each        = local.standbys
  subnet_id       = aws_subnet.interconnect[each.key].id
  security_groups = [aws_security_group.interconnect.id]
  description     = "${var.deployment_name} node ${each.value.index} standby interconnect"
  tags            = { Name = "${var.deployment_name}-interconnect-${each.value.index}-standby" }
}

resource "aws_ebs_volume" "standby_data" {
  for_each          = local.standbys
  availability_zone = each.value.az
  size              = var.data_volume_gb
  type              = "gp3"
  encrypted         = true
  tags              = { Name = "${var.deployment_name}-data-${each.value.index}-standby" }

  lifecycle {
    # Same reasoning as the primary's volume: once the pair is streaming, this one holds a
    # full copy of every issued certificate, and with key_backend = softhsm a copy of every
    # replicable CA key as well. Destroying it is a deliberate act.
    prevent_destroy = true
  }
}

resource "aws_volume_attachment" "standby_data" {
  for_each    = local.standbys
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.standby_data[each.key].id
  instance_id = aws_instance.standby[each.key].id
}

resource "aws_instance" "standby" {
  for_each      = local.standbys
  ami           = local.ami_id
  instance_type = var.instance_type
  key_name      = var.ssh_key_name != "" ? var.ssh_key_name : null

  network_interface {
    network_interface_id = aws_network_interface.standby_mgmt[each.key].id
    device_index         = 0
  }
  network_interface {
    network_interface_id = aws_network_interface.standby_interconnect[each.key].id
    device_index         = 1
  }

  root_block_device {
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    http_protocol_ipv6          = "enabled"
  }

  # The SAME answers as its primary, including the data center index: a standby serves the
  # same data center under the same name, and its certificates must say so. It installs as
  # a complete node and is reseeded from the primary when it is joined, which is what the
  # native procedure does too — docs/high-availability.md §4 step 2 replaces the database it
  # initialised here with a base backup.
  # Gzipped for the same reason as the node's, above: EC2 refuses user-data over 16384 bytes.
  user_data_base64 = base64gzip(templatefile("${path.module}/user-data.sh.tftpl", {
    dc_index             = each.value.index
    dc_count             = var.dc_count
    pki_dns              = length(var.pki_dns) == 1 ? var.pki_dns[0] : var.pki_dns[each.value.index - 1]
    key_backend          = var.key_backend
    pkcs11_module        = var.pkcs11_module
    protocols            = var.enabled_protocols
    interconnect_ip      = aws_network_interface.standby_interconnect[each.key].private_ip
    interconnect_prefix  = local.interconnect_prefix
    interconnect_gateway = local.interconnect_gateway[each.key]
    interconnect_peers   = local.interconnect_peers[each.key]
    web_port             = var.web_port
    ha_enabled           = true
  }))
  user_data_replace_on_change = true

  tags = {
    Name         = "${var.deployment_name}-${each.value.index}-standby"
    DatacenterId = tostring(each.value.index)
    Role         = "standby"
  }

  depends_on = [terraform_data.az_check]
}

resource "aws_eip" "standby" {
  for_each          = var.public_ipv4 ? local.standbys : {}
  network_interface = aws_network_interface.standby_mgmt[each.key].id
  domain            = "vpc"
  tags              = { Name = "${var.deployment_name}-${each.value.index}-standby" }
  depends_on        = [aws_instance.standby]
}

# Optional public DNS, and it follows the shape pki_dns was given.
#
# ONE name -> a round-robin A record across every node. There is no primary, so this is the
# honest shape for a mesh whose nodes are interchangeable — but they are interchangeable for
# ENROLMENT only when whichever node a client lands on can sign with the CA it asked for.
# A mesh replicates data, not signing capability, so that CA's key has to be replicated into
# every node's own token (`fastpki-ca create --replicable`, then `key replicate`). Without it
# TLS verifies from any node while enrolment fails on the nodes that lack the key, which
# reads as an intermittent client fault rather than a routing one. See the pki_dns variable.
#
# ONE NAME PER NODE -> one record per node, each pointing at that node alone. Every data
# center stays separately addressable and no key is copied.
#
# Either way it is opt-in, because it is only correct once the nodes are actually serving:
# a client that lands on a node whose CA has not been created yet gets a console and
# nothing else.
resource "aws_route53_record" "pki" {
  for_each = var.route53_zone_id == "" || !var.public_ipv4 ? {} : (
    length(var.pki_dns) == 1 ? { "0" = { name = var.pki_dns[0], ips = [for k in keys(local.dcs) : aws_eip.node[k].public_ip] } }
    : { for k, v in local.dcs : k => { name = var.pki_dns[v.index - 1], ips = [aws_eip.node[k].public_ip] } }
  )

  zone_id = var.route53_zone_id
  name    = each.value.name
  type    = "A"
  ttl     = 60
  records = each.value.ips
}

# The same names over IPv6. A dual-stack node publishes both and a client picks; a node
# with public_ipv4 = false publishes only this one, which is then the only way in — so the
# zone stops being optional in that configuration, and the wizard says so.
resource "aws_route53_record" "pki_v6" {
  for_each = var.route53_zone_id == "" ? {} : (
    length(var.pki_dns) == 1 ? { "0" = { name = var.pki_dns[0], ips = [for k in keys(local.dcs) : local.client_ipv6[k]] } }
    : { for k, v in local.dcs : k => { name = var.pki_dns[v.index - 1], ips = [local.client_ipv6[k]] } }
  )

  zone_id = var.route53_zone_id
  name    = each.value.name
  type    = "AAAA"
  ttl     = 60
  records = each.value.ips
}
