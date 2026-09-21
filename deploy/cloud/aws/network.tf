# ── THE MESH MAPS ONTO AVAILABILITY ZONES ────────────────────────────────────────────
#
# FastPKI's multi-data-center mode is active-active logical replication between N nodes,
# and the lab that tests it (deploy/lab/) runs that replication over an interconnect that
# is SEPARATE from the management network. That separation is not decoration: the
# partition test cuts the interconnect and must not drop its own SSH session, and a
# deployment where both ride the same path cannot be tested that way — nor can it be
# firewalled that way, which matters more.
#
# So each node gets two subnets in its own AZ:
#
#   mgmt          public. SSH, the console, the enrolment protocols. Routed to the IGW.
#   interconnect  private, no route out of the VPC at all. PostgreSQL replication only,
#                 reachable exclusively from the other nodes' interconnect interfaces.
#
# One AZ per node is what makes the DC count meaningful: nodes in the same AZ share a
# failure domain, and the whole point of the mesh is that they do not.

data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

locals {
  # Fail loudly at plan time rather than deploying two nodes into one AZ. A region with
  # fewer AZs than requested nodes cannot host this topology, and silently wrapping the
  # index around would produce a mesh whose members share a failure domain — which looks
  # exactly like a working deployment until the AZ goes.
  az_count = length(data.aws_availability_zones.available.names)
  az_names = slice(data.aws_availability_zones.available.names, 0, min(var.dc_count, local.az_count))

  # 1-based, because a node's index IS its serial prefix and the `datacenters` table
  # numbers from 1. Keeping the same numbering here means the AWS console, the topology
  # file and the certificate serials all say "node 2" about the same node.
  dcs = { for i in range(var.dc_count) : i + 1 => {
    index = i + 1
    az    = local.az_names[i % length(local.az_names)]
  } }
}

resource "terraform_data" "az_check" {
  # A validation block cannot see a data source, so the check lives here: it is evaluated
  # during plan and its failure names the actual problem.
  lifecycle {
    precondition {
      condition     = var.dc_count <= local.az_count
      error_message = "dc_count exceeds the number of availability zones in ${var.region}. Nodes in one AZ share a failure domain, which is the thing the mesh exists to avoid — choose a larger region or fewer nodes."
    }
  }
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  # A /56 from Amazon's pool, free of charge — unlike a public IPv4 address, which is
  # billed per hour whether the instance is running, stopped, or the EIP is merely
  # allocated. The nodes are DUAL-STACK rather than IPv6-only: what decides that is not
  # what a node needs to reach but who has to reach IT — enrolment clients, relying parties
  # fetching CRL and OCSP, and whatever host runs the deployment automation. Where any of
  # those is IPv4-only, so is the path to the node.
  assign_generated_ipv6_cidr_block = true
  tags                             = { Name = var.deployment_name }

  # ⚠️ deploy/cloud/aws-ha-address.sh records each pair's service address as a tag here
  # (FastPKIServiceAddress-<deployment>-dc<n>), outside OpenTofu and on purpose: it moves the
  # address at a failover. Without this, every later `tofu apply` deleted the record.
  lifecycle {
    ignore_changes = [tags, tags_all]
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = var.deployment_name }
}

resource "aws_subnet" "mgmt" {
  for_each                = local.dcs
  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value.az
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, each.value.index)
  map_public_ip_on_launch = false # the instances carry an explicit EIP instead
  # AWS requires a subnet IPv6 prefix to be exactly a /64, which is what /56 + 8 gives.
  # The index matches the IPv4 third octet, so node 2's two prefixes carry the same number.
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.this.ipv6_cidr_block, 8, each.value.index)
  assign_ipv6_address_on_creation = true
  tags                            = { Name = "${var.deployment_name}-mgmt-${each.value.index}", Tier = "mgmt" }
}

# ⚠️ NO IPv6 PREFIX HERE, DELIBERATELY. The interconnect carries PostgreSQL replication
# between nodes and must have no route off the VPC; the conninfos the mesh topology holds
# are built from these IPv4 addresses. A second address family on this path would be one
# more thing to keep closed and would buy nothing — the peers are already reachable.
resource "aws_subnet" "interconnect" {
  for_each          = local.dcs
  vpc_id            = aws_vpc.this.id
  availability_zone = each.value.az
  # +100 keeps the two ranges visibly distinct in a route table or a flow log, so
  # "10.42.102.x" reads as "node 2, interconnect" at a glance.
  cidr_block = cidrsubnet(var.vpc_cidr, 8, each.value.index + 100)
  tags       = { Name = "${var.deployment_name}-interconnect-${each.value.index}", Tier = "interconnect" }
}

resource "aws_route_table" "mgmt" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  # The same internet gateway carries IPv6 both ways. An egress-only gateway is the other
  # option and is the wrong one here: it exists to let a private subnet reach out without
  # being reachable, and these nodes serve the console and the enrolment protocols.
  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.this.id
  }
  tags = { Name = "${var.deployment_name}-mgmt" }
}

resource "aws_route_table_association" "mgmt" {
  for_each       = aws_subnet.mgmt
  subnet_id      = each.value.id
  route_table_id = aws_route_table.mgmt.id
}

# ⚠️ THE INTERCONNECT SUBNETS GET NO ROUTE TABLE OF THEIR OWN, and that is the point.
# They fall back to the VPC's main route table, which carries only the local route — so
# an interconnect interface can reach the other nodes and nothing else. No NAT gateway,
# no IGW, no egress. A replication path that cannot leave the VPC cannot be exfiltrated
# through, and it also cannot quietly acquire a dependency on the internet.
