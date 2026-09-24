# The questions this module asks are the SAME questions deploy/install.sh and
# deploy/native/install-native.sh ask, plus the ones only a cloud has: which region, how
# big an instance, who may reach the console. deploy/cloud/cloud-install.sh collects them
# interactively and writes them here as a tfvars file, so an operator never has to learn
# HCL to deploy — but the variables are plain and documented, so one who wants to can.

variable "deployment_name" {
  type        = string
  default     = "fastpki"
  description = "Name prefix for every resource, and the tag everything is grouped by."
}

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region. The data centers of the mesh become availability zones of THIS region."
}

variable "dc_count" {
  type        = number
  default     = 1
  description = <<-EOT
    Number of FastPKI nodes, one per availability zone — the same N that install.sh asks
    for as "number of data centers in the mesh".

    Each node mints certificate serials under a 2-octet prefix that is its own, so two
    nodes can never produce the same serial. The serial is the certificate's primary key,
    and a collision stalls a peer's replication apply worker.

    1 is a single-node deployment with no mesh. 3 is the tested topology.
  EOT
  validation {
    # The 2-octet prefix has its high bit reserved: a DER integer is SIGNED, and a prefix
    # with the high bit set makes OpenSSL pad the serial to 21 octets, past the RFC 5280
    # §4.1.2.2 limit. The practical ceiling here is the region's AZ count, but the
    # invariant is worth stating where the number is chosen.
    condition     = var.dc_count >= 1 && var.dc_count <= 32767
    error_message = "dc_count must be between 1 and 32767 (the serial prefix is 2 octets with the high bit reserved)."
  }
}

variable "standby_dcs" {
  type        = list(number)
  default     = []
  description = <<-EOT
    Which data centers get a SECOND server, to stand by for the first one.

    `dc_count` counts data centers, not machines: every data center gets one server, and a
    standby is a second machine in the same availability zone that streams the first one's
    database and takes over when it is lost. `standby_dcs = [1]` gives data center 1 a
    standby and leaves the others alone.

    This module provisions the machine, its disks and its interfaces. Joining it is one
    command from the operator's machine, deploy/ha-join-pair.sh
    (`docs/high-availability.md` §4), and the `standby_join` output prints it. It is not done
    at first boot because it needs the primary's database password and token PIN, and
    neither may be in user-data.

    Both servers of a data center listed here are installed with P11_TLS=on, and the
    interconnect security group admits the key tunnel's port 12345 between members. That is
    how the standby receives copies of the CA keys (§4 Step 4).

    ⚠️ THE CA KEYS HAVE TO BE CREATED `--replicable` BEFORE THE STANDBY IS JOINED, and that
    cannot be granted afterwards. A standby holding no copy of the signing key serves reads
    and cannot issue, which is not a failover. See docs/deployment.md §12 step 7.

    Same availability zone as the primary, deliberately. The pair's one address moves
    between their interfaces through the EC2 API (`deploy/cloud/aws-ha-address.sh`), and an
    address cannot move across a subnet boundary. Surviving the loss of an availability
    zone is what the MESH is for; a pair survives the loss of a machine.
  EOT
  validation {
    condition     = alltrue([for i in var.standby_dcs : i >= 1 && i <= var.dc_count])
    error_message = "every entry in standby_dcs must name a data center between 1 and dc_count."
  }
  validation {
    # The natural misreading is that the list counts standbys, so [1, 1] looks like "two
    # standbys for data center 1". It is a list of data centers, each getting one standby,
    # and a second standby is not a shape FastPKI has: a pair is one primary and one
    # machine streaming it.
    condition     = length(var.standby_dcs) == length(distinct(var.standby_dcs))
    error_message = "standby_dcs lists a data center twice. Each entry names a data center that gets ONE standby: [1, 2] gives both a standby, while [1, 1] is not two standbys for data center 1."
  }
}

variable "pki_dns" {
  type        = list(string)
  description = <<-EOT
    The public FQDN each node answers on — its PKI_DNS, which is the name in its transport
    certificate and the host in the CRL and AIA URLs it issues. Give either ONE name or
    exactly dc_count of them; the choice decides whether the nodes are interchangeable.

    ONE name publishes a round-robin A record across every node (see route53_zone_id).
    That makes the nodes interchangeable for ENROLMENT too, which requires that whichever
    node a client lands on can SIGN with the CA it asked for. A mesh replicates DATA, not
    signing capability: by default each node has its own sub CA, and a node asked to issue
    from a CA whose key it does not hold refuses with "no signing key for this CA on this
    node" (src/lib/ca_instance.cpp) while TLS still verifies — so it looks healthy and
    enrolment fails intermittently. Correct only when that CA's private key exists in EVERY
    node's own token: create the CA with `fastpki-ca create --replicable`, because
    CKA_EXTRACTABLE is fixed when the key is generated and cannot be granted afterwards, and
    replicate it to each node over the P11_TLS channel (docs/deployment.md 9.7). This module
    sets that tunnel up only between the two servers of a pair (standby_dcs), not across data
    centers, so across them it is the procedure there rather than a variable here.

    ONE NAME PER NODE publishes a record per node instead. Each data center is separately
    addressable, every node keeps its own sub CA, and no key is ever copied — the shape
    docs/deployment.md 9.1 describes, and the one to pick unless you are deliberately
    replicating key material.
  EOT

  validation {
    condition     = length(var.pki_dns) == 1 || length(var.pki_dns) == var.dc_count
    error_message = "pki_dns must be either a single shared name or exactly one name per node (length 1 or dc_count)."
  }
}

variable "ami_id" {
  type        = string
  default     = ""
  description = <<-EOT
    Empty (the default): Alpine's official cloud image, and each server installs FastPKI at
    first boot from release_mirror, after checking the release signature.

    An AMI built with deploy/cloud/image: FastPKI is already on it and first boot downloads
    nothing. Use this when the servers cannot reach the internet at first boot.

    ⚠️ An AMI id is code that runs as root on a host that will hold CA keys, so the default is
    Alpine's own image, found by its publisher's account id (alpine_ami_owner) rather than by
    name — the name alone also matches third-party builds.
  EOT
}

variable "alpine_version" {
  type        = string
  default     = "3.24"
  description = <<-EOT
    Alpine release of the default image. It must be the release the FastPKI package was built
    on — the installer refuses a mismatch, because a package built on one Alpine release
    unpacks cleanly on another and then fails to start anything. It tracks the Dockerfile's
    `FROM alpine:<version>`.
  EOT
}

variable "alpine_ami_owner" {
  type        = string
  default     = "538276064493"
  description = <<-EOT
    The AWS account that publishes Alpine's official cloud images. Verified against the EC2
    API; deploy/cloud/image/fastpki.pkr.hcl records how, and why the owner is what separates
    Alpine's image from somebody else's image named alpine.
  EOT
}

variable "fastpki_version" {
  type        = string
  default     = ""
  description = <<-EOT
    The FastPKI release a server installs at first boot, e.g. "v1.2.3". Empty means the newest
    signed release at the moment that server first boots. Ignored with an ami_id that already
    carries FastPKI.

    Pin it for a deployment that will grow: with it empty, a standby or data center added
    later installs whatever is newest then, which can be newer than the servers already
    running. Changing it later replaces the servers, because it is part of their first-boot
    script.
  EOT
}

variable "release_mirror" {
  type        = string
  default     = "https://fastpki.com/releases"
  description = <<-EOT
    Where first boot downloads FastPKI from. github.com is not used because it has no IPv6
    address and these servers are IPv6-only unless public_ipv4 is set. What is downloaded is
    checked against the release signature using the key in docs/release-keys/ of this
    checkout, so the mirror has to be reachable, not trusted.
  EOT
}

variable "instance_type" {
  type        = string
  default     = "t4g.medium"
  description = <<-EOT
    Per-node instance type. Must match the AMI's architecture — the default AMI build is
    arm64, so this default is a Graviton type.

    t4g.medium is sized for a demo. A production CA is not CPU-hungry (signing is
    milliseconds) but Postgres wants memory; m7g.large upward is the honest starting point
    for anything real.

    MEASURED, on the shipped image with the console, OCSP, EST, the token and the p11
    tunnel running: 107 MB used on the whole machine. Each listener is 13-17 MB RSS, each
    p11-kit-remote about 9 MB, and Postgres shares most of its pages between backends, so a
    full deployment with every protocol enabled sits near 220 MB before load. 1 GB is
    therefore a working demo rather than a gamble — what a small instance runs out of first
    is burst credit and the headroom for a spike, since there is no swap, not memory at rest.
  EOT
}

variable "vpc_cidr" {
  type        = string
  default     = "10.42.0.0/16"
  description = "VPC address space. Must not overlap anything you intend to peer with."
}

variable "admin_cidrs" {
  type        = list(string)
  description = <<-EOT
    Who may reach SSH and the web console (port 8090). IPv4 and IPv6 prefixes may be
    mixed in one list; each is turned into a rule of its own address family.

    ⚠️ NO DEFAULT, ON PURPOSE. A default of 0.0.0.0/0 here would publish an administrative
    console holding a certificate authority to the internet, and it would do it silently
    for anyone who did not read this far. Making it required turns that into a question.
  EOT
  validation {
    condition     = length(var.admin_cidrs) > 0
    error_message = "admin_cidrs must list at least one CIDR — the console and SSH are not opened to everyone."
  }
}

variable "client_cidrs" {
  type        = list(string)
  default     = []
  description = <<-EOT
    Who may reach the ENROLMENT protocols (OCSP/CRL 8080, EST 8443, ACME 8444, CMP 8445,
    MS-XCEP 8446, store 8447, SCEP 8448). Empty means nobody outside the VPC, which is the
    right default for a demo you drive from your own machine — put your own CIDR in
    admin_cidrs and leave this empty.

    Note that OCSP and CRL are PUBLIC information by design: relying parties have to reach
    them, so a real deployment usually does open 8080 broadly. That is a decision, so it
    is a variable.
  EOT
}

variable "enabled_protocols" {
  type        = list(string)
  default     = ["est", "acme", "cmp", "scep", "ms", "store"]
  description = <<-EOT
    Which optional protocols the nodes install. The console and OCSP are not on this list
    because neither is optional: without the console there is no way to create a CA, and
    fastpki-ocsp serves the CRL endpoints too, so a PKI without it issues certificates and
    publishes no revocation information at all. Neither is a smaller deployment; both are
    an incomplete one.

    A protocol left out is not started and not monitored, and its port is not opened.
  EOT
  validation {
    condition = alltrue([
      for p in var.enabled_protocols : contains(["est", "acme", "cmp", "scep", "ms", "store"], p)
    ])
    error_message = "enabled_protocols may contain only: est, acme, cmp, scep, ms, store."
  }
}

variable "key_backend" {
  type        = string
  default     = "softhsm"
  description = <<-EOT
    Where CA private keys live.

      softhsm  the bundled token, served out of process by p11-kit. Dev and DEMO posture.
      hsm      your own PKCS#11 module, loaded directly — on AWS that means CloudHSM's
               client library. Set pkcs11_module to its absolute path.

    A private key never lives in a file either way; the question is which token. For a
    SaaS offering the answer is `hsm`: CA keys in a software token on a shared-tenancy
    instance is not a story that survives a customer's security review.

    ⚠️ This module does NOT provision a CloudHSM cluster. That is a five-figure-a-year
    resource with its own initialisation ceremony (its own trust anchor, its own crypto
    officer), and creating one as a side effect of `tofu apply` would be the wrong kind of
    surprise. Point this at a cluster you have already stood up.
  EOT
  validation {
    condition     = contains(["softhsm", "hsm"], var.key_backend)
    error_message = "key_backend must be 'softhsm' or 'hsm'."
  }
}

variable "pkcs11_module" {
  type        = string
  default     = ""
  description = "Absolute path to the vendor PKCS#11 module on the instance. Required when key_backend = hsm."
  validation {
    condition     = var.pkcs11_module == "" || startswith(var.pkcs11_module, "/")
    error_message = "pkcs11_module must be an absolute path."
  }
}

variable "ssh_key_name" {
  type        = string
  default     = ""
  description = "Existing EC2 key pair for SSH. Empty means no key — the instance is then reachable only through whatever else you arrange."
}

variable "data_volume_gb" {
  type        = number
  default     = 40
  description = <<-EOT
    Size of the separate encrypted volume that holds the PostgreSQL cluster, the token and
    /var/pki.

    ⚠️ SEPARATE FROM THE ROOT VOLUME, ON PURPOSE. The root volume is disposable — it is
    the AMI plus configuration, and replacing an instance replaces it. This one holds
    every issued certificate and, with key_backend = softhsm, every CA private key. Its
    lifecycle (snapshots, restore, resize, and NOT being deleted with the instance) is a
    different lifecycle, and mixing the two is how a rebuild becomes a data loss.
  EOT
}

variable "allowed_account_id" {
  type        = string
  default     = ""
  description = <<-EOT
    The AWS account this deployment belongs to, as its 12-digit id. Every operation is
    refused if the credentials in the environment resolve to a different account.

    Set it. AWS credentials are ambient — a profile, an environment variable, an instance
    role — so the account an apply lands in is whichever one the shell was carrying, and a
    plan does not say which that is. Someone with a work account and a personal one will
    eventually point this module at the wrong one; this turns that into an error before
    anything is created. `aws sts get-caller-identity --query Account --output text` prints
    it.

    Empty disables the check, which is only correct when the credentials can reach exactly
    one account.
  EOT
  validation {
    condition     = var.allowed_account_id == "" || can(regex("^[0-9]{12}$", var.allowed_account_id))
    error_message = "allowed_account_id must be a 12-digit AWS account id, or empty to disable the check."
  }
}

variable "web_port" {
  type        = number
  default     = 8090
  description = <<-EOT
    The port the console listens on, opened to admin_cidrs and used in the console_urls
    output.

    ⚠️ 443 IS THE RIGHT ANSWER FOR ANYTHING PUBLIC, and 8090 costs more than a few
    keystrokes. A non-standard port is filtered by endpoint security, refused by corporate
    egress rules and not proxied by relays — including Apple's Private Relay, which handles
    80 and 443 and nothing else — so a demo on 8090 fails for people whose network is not
    yours, in ways they cannot diagnose and you cannot see. It also has to be typed, and a
    URL with a port in it does not look like a product.

    Below 1024 the console cannot bind it as itself: the service runs as the fastpki user.
    Rather than granting the binary a capability that a package update would silently drop,
    the node lowers net.ipv4.ip_unprivileged_port_start to this port, which covers IPv6 as
    well and survives reboots through /etc/sysctl.d. Ports below it — 22 and 80 in the 443
    case — stay privileged.
  EOT
  validation {
    condition     = var.web_port > 0 && var.web_port < 65536
    error_message = "web_port must be a TCP port number."
  }
}

variable "public_ipv4" {
  type        = bool
  default     = true
  description = <<-EOT
    Give each node a public IPv4 address (an Elastic IP) beside its IPv6 one.

    ⚠️ THIS IS THE ONLY BILLED ADDRESS IN THE DEPLOYMENT. AWS charges $0.005/hour per
    public IPv4 address — whether the instance is running, stopped, or the address is
    merely allocated — which is about $3.65 a month each, and IPv6 costs nothing. On a
    parked three-node demo that is most of the standing cost.

    Setting it false is the right answer exactly when EVERY party that has to reach the
    node has IPv6: the administrators, the enrolment clients, and the relying parties
    fetching CRL and OCSP. What the node itself reaches does not decide this — it keeps a
    private IPv4 address either way, so the metadata service, the mesh interconnect and
    the replication conninfos are unchanged, and only its route to the IPv4 INTERNET is
    gone (there is no NAT gateway in this module, deliberately: one costs ~$32/month,
    which is nine times the addresses it would replace).

    With it false, route53_zone_id stops being optional in practice — the AAAA records
    become the only published way to reach the deployment.
  EOT
}

variable "route53_zone_id" {
  type        = string
  default     = ""
  description = "Optional hosted zone to publish pki_dns into. Empty publishes no DNS record."
}
