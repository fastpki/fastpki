variable "deployment_name" {
  type        = string
  default     = "fastpki"
  description = "Prefix for every VM name. Nodes are <deployment_name>-<n>."
}

variable "pve_endpoint" {
  type        = string
  description = "Proxmox API endpoint, e.g. https://pve.example.org:8006/"
}

variable "pve_node" {
  type        = string
  description = "Proxmox node name to create the VMs on (the hostname shown in the web UI)."
}

variable "pve_insecure" {
  type        = bool
  default     = false
  description = <<-EOT
    Skip TLS verification against the Proxmox API.

    A lab hypervisor usually presents its own self-signed certificate, which is the only
    reason this exists. It is NOT a FastPKI setting and nothing in the product reads it —
    the product has no setting that turns a security control off. Point it at a trusted
    certificate and leave this false wherever that is possible.
  EOT
}

variable "pve_ssh_username" {
  type        = string
  default     = "root"
  description = "User the provider opens an SSH session as, to write cloud-init snippets. Needs write access to the snippets datastore."
}

variable "pve_ssh_agent" {
  type        = bool
  default     = true
  description = "Use the local SSH agent for that session. Set false and give pve_ssh_private_key_file when there is no agent — the provider has no third option."
}

variable "pve_ssh_private_key_file" {
  type        = string
  default     = ""
  description = <<-EOT
    Path to the private key for that SSH session, used when pve_ssh_agent is false.

    The provider does NOT read ~/.ssh/config and does not look for keys on its own: with
    no agent and no key here it offers only `none` and `password` and fails with "no
    supported methods remain", however well an interactive ssh to the same host works.

    A path, not a key — the file stays where it is and nothing secret enters the
    configuration or the state.
  EOT
}

variable "template_vm_id" {
  type        = number
  description = <<-EOT
    VMID of the template to clone. Either of two, and first boot tells them apart by whether
    FastPKI is already on the disk:

      * Alpine's own generic cloud image (generic_alpine-<version>-x86_64-uefi-cloudinit),
        made into a template. Each node installs FastPKI at first boot from release_mirror,
        after checking the release signature.
      * An image built with deploy/cloud/image/build-qemu.sh, which already carries FastPKI.
        First boot downloads nothing — for a lab with no route to the internet.

    Either way it must be a `-uefi-` cloud image with bios=ovmf and an EFI disk, because that
    is what those images are: GPT with an EFI system partition and no BIOS boot code.
  EOT
}

variable "fastpki_version" {
  type        = string
  default     = ""
  description = <<-EOT
    The FastPKI release a node installs at first boot, e.g. "v1.2.3". Empty means the newest
    signed release at that node's first boot. Ignored with a template that already carries
    FastPKI. Pin it for a deployment that will grow, or later nodes can install a newer release.
  EOT
}

variable "release_mirror" {
  type        = string
  default     = "https://fastpki.com/releases"
  description = <<-EOT
    Where first boot downloads FastPKI from. What is downloaded is checked against the release
    signature using the key in docs/release-keys/ of this checkout, so the mirror has to be
    reachable, not trusted.
  EOT
}

variable "node_count" {
  type        = number
  default     = 1
  description = <<-EOT
    How many FastPKI nodes to create.

    One is a single-node deployment. More than one gives each node its own serial prefix
    (DATACENTER_ID) so two nodes can never mint the same certificate serial, and puts them
    on the interconnect bridge — but this module does NOT mesh them: replication is
    configured with `fastpki-mesh`, which needs every peer's address and so cannot run
    while the first node is still being created.
  EOT
  validation {
    condition     = var.node_count >= 1 && var.node_count <= 9
    error_message = "node_count must be between 1 and 9 — the serial prefix is one octet per node."
  }
}

variable "first_vm_id" {
  type        = number
  description = "VMID of the first node. Subsequent nodes take consecutive ids, so leave that range free."
}

variable "pki_dns" {
  type = list(string)
  description = <<-EOT
    The DNS name each node answers on — its PKI_DNS, which is the name in its transport
    certificate and the host in the CRL and AIA URLs it issues. Give either ONE name or
    exactly node_count of them, and the choice is a real design decision:

    ONE name, round-robined across every node. The nodes are interchangeable, including
    for enrolment — which requires that whichever node a client lands on can SIGN with the
    CA it asked for. A mesh replicates DATA, not signing capability: by default each node
    has its own sub CA, and a node asked to issue from a CA whose key it does not hold
    refuses with "no signing key for this CA on this node" (src/lib/ca_instance.cpp). TLS
    still verifies in that case, so the deployment looks healthy while enrolment fails
    intermittently. So this shape is correct only when that CA's private key exists in
    EVERY node's own token: create the CA with `fastpki-ca create --replicable`, because
    CKA_EXTRACTABLE is fixed when the key is generated and cannot be granted afterwards,
    and replicate it to each node over the channel p11_tls opens.

    ONE NAME PER NODE, in node order. Each data center is separately addressable, every
    node keeps its own sub CA, and no key is ever copied. This is the shape docs/deployment.md
    9.1 describes and the one to pick if you are not deliberately replicating key material.

    Either way OCSP, CRLs and the RFC 4387 store are fungible — they read replicated data
    and answer correctly from any node — so a round-robin record across all of them is
    always fine for those, as a record separate from these.
  EOT

  validation {
    condition     = length(var.pki_dns) == 1 || length(var.pki_dns) == var.node_count
    error_message = "pki_dns must be either a single shared name or exactly one name per node (length 1 or node_count)."
  }
}

variable "mgmt_bridge" {
  type        = string
  default     = "vmbr0"
  description = "Bridge carrying management and protocol traffic."
}

variable "mgmt_cidr_prefix" {
  type        = string
  description = "First three octets of the management network, e.g. 192.0.2 — the node's own octet comes from mgmt_first_octet."
}

variable "mgmt_first_octet" {
  type        = number
  description = <<-EOT
    Last octet of the first node's management address; subsequent nodes take consecutive
    ones.

    ⚠️ CHECK THE RANGE IS FREE FIRST. A hypervisor's bridge is a shared L2 segment and
    nothing on it will stop you configuring an address another machine already holds: the
    VM boots, answers on port 22, and the traffic goes to whichever host answered ARP
    first. The symptom is a machine that looks reachable and behaves like somebody else.
    `ip neigh show dev <bridge>` on the hypervisor lists what is already there.
  EOT
}

variable "mgmt_gateway" {
  type        = string
  description = "Default gateway for the management network."
}

variable "nameservers" {
  type        = list(string)
  default     = ["1.1.1.1"]
  description = "Resolvers for the nodes. A deployment authenticating against Active Directory needs the directory's own DNS here, because a directory is reached by NAME."
}

variable "interconnect_bridge" {
  type        = string
  default     = ""
  description = "Bridge for replication traffic between nodes. Empty gives the nodes a single interface, which is right for a single-node deployment."
}

variable "interconnect_cidr_prefix" {
  type        = string
  default     = ""
  description = "First three octets of the interconnect network. The node's octet matches its management one, so the two addresses stay legible together."
}

variable "cores" {
  type        = number
  default     = 2
  description = "vCPUs per node. The image is already built, so this sizes SERVING, not compiling — two is enough for a lab node."
}

variable "memory_mb" {
  type        = number
  default     = 3072
  description = "Megabytes per node. A node runs the protocol binaries, the console and, with pg_local, PostgreSQL as well."
}

variable "disk_gb" {
  type        = number
  default     = 20
  description = "Root disk. Must be at least the template's size; Proxmox grows a clone but cannot shrink one."
}

variable "pg_local" {
  type        = bool
  default     = true
  description = "Run PostgreSQL on the node itself. False expects an external database and the answers file then needs PG_CONNINFO."
}

variable "key_backend" {
  type        = string
  default     = "softhsm"
  description = <<-EOT
    Where CA private keys live, with the install wizard's values.

      softhsm  the bundled token, served out of process by p11-kit. The lab default.
      hsm      your own PKCS#11 module, loaded directly. Set pkcs11_module to its absolute
               path inside the VM, and pkcs11_token to its token label.
  EOT
  validation {
    condition     = contains(["softhsm", "hsm"], var.key_backend)
    error_message = "key_backend must be 'softhsm' or 'hsm'."
  }
}

variable "pkcs11_module" {
  type        = string
  default     = ""
  description = "Absolute path to the vendor PKCS#11 module inside the VM. Required when key_backend = hsm."
  validation {
    condition     = var.pkcs11_module == "" || startswith(var.pkcs11_module, "/")
    error_message = "pkcs11_module must be an absolute path."
  }
}

variable "pkcs11_token" {
  type        = string
  default     = "fastpki"
  description = "Token label on the vendor PKCS#11 module. Used when key_backend = hsm; the bundled token is always labelled fastpki."
}

variable "service_keys" {
  type        = map(string)
  default     = {}
  description = <<-EOT
    Each service's key, as the install wizard asks for it: WEB_KEY_ALGO, WEB_KEY_CURVE,
    WEB_KEY_BITS, WEB_KEY_MD, the same for EST_, ACME_ and MS_, OCSP_RESPONDER_KEY_ALGO /
    _BITS / _CURVE, CMP_RA_KEY_ALGO / _BITS / _CURVE, and SCEP_RA_KEY_BITS. A key left out
    takes the default: ec / P-256, and RSA 3072 for the SCEP RA.
  EOT
  validation {
    condition = alltrue([for k in keys(var.service_keys) :
      can(regex("^((WEB|EST|ACME|MS)_KEY_(ALGO|BITS|CURVE|MD)|(OCSP_RESPONDER|CMP_RA)_KEY_(ALGO|BITS|CURVE)|SCEP_RA_KEY_BITS)$", k))])
    error_message = "service_keys takes only the install wizard's key settings, for example WEB_KEY_ALGO or SCEP_RA_KEY_BITS."
  }
}

variable "enabled_protocols" {
  type        = list(string)
  default     = ["est"]
  description = <<-EOT
    Enrolment protocols to switch on. The console and OCSP are always on.

    A protocol NOT listed here is not merely closed — pki::gate_protocol() refuses to bind
    its port at all, so an unlisted protocol is absent rather than firewalled.
  EOT
  validation {
    condition     = alltrue([for p in var.enabled_protocols : contains(["est", "acme", "cmp", "scep", "ms", "store"], p)])
    error_message = "enabled_protocols may contain only: est, acme, cmp, scep, ms, store."
  }
}

variable "ssh_public_keys" {
  type        = list(string)
  default     = []
  description = "Keys authorised on the node's login account. Empty leaves only the console, which is reachable through the hypervisor."
}

variable "ci_user" {
  type        = string
  default     = "fastpki"
  description = <<-EOT
    Login account cloud-init creates.

    Not `alpine`, which already exists in the image: cloud-init's pre-existing-user path
    skips some of what it would otherwise do, so a name of our own keeps the account this
    module creates entirely ours.

    ⚠️ A FRESH NAME DOES NOT AVOID THE LOCK, and assuming it did cost a full debugging
    round. cloud-init applies lock_passwd — which defaults to TRUE — to accounts it
    creates as much as to ones it finds, so this account is locked either way and OpenSSH
    then refuses PUBLIC KEY logins for it, Alpine having no PAM to soften that. The
    vendor-data sets the shadow field to `*` for exactly this reason; see the comment
    there, and do not remove it on the theory that the username makes it unnecessary.
  EOT
}

variable "snippets_datastore" {
  type        = string
  default     = "local"
  description = "Datastore holding cloud-init snippets. Must have the `snippets` content type enabled — most Proxmox installs do not by default."
}

variable "vm_datastore" {
  type        = string
  default     = "local-lvm"
  description = "Datastore for the cloned disks."
}

# ── publishing this node's token, so a peer can replicate a key out of it ─────────────
variable "p11_tls" {
  type        = bool
  default     = false
  description = <<-EOT
    Publish each node's own token over mutually authenticated TLS (docs/deployment.md 8.3).

    Every node keeps its own token; this is the channel over which a CA private key is
    replicated from one node's token into another's, so that losing a node does not take
    the CAs it held with it. It is not a way for a node to sign through somebody else's
    token — a deployment arranged that way stops signing entirely when that host is lost.

    The tunnel runs over the INTERCONNECT, not the management network: C_Login carries the
    PIN protecting every CA private key, and the interconnect has no route off the segment.
    So this needs interconnect_bridge set.
  EOT
}

variable "p11_tls_port" {
  type        = number
  default     = 12345
  description = "Port the token host publishes its p11-kit socket on, over the interconnect."
}

variable "pkcs11_pin" {
  type        = string
  default     = ""
  sensitive   = true
  description = <<-EOT
    The token PIN. Blank means each node generates its own, which is the normal case: every
    node has its own token and nothing else has to open it.

    Set it to give every node the same PIN, which is what compose and Kubernetes do within
    one deployment — install.sh writes FASTPKI_PIN into deploy/.env and apply.sh stores it in
    the fastpki-secret Secret.
  EOT
}
