locals {
  # Every protocol the answers file has a WANT_ key for. Rendered as yes/no rather than
  # omitted, so the file states a position on each one instead of relying on a default.
  all_protocols = ["est", "acme", "cmp", "scep", "ms", "store"]

  # One node per index. DC_INDEX is the serial prefix and must be unique and stable per
  # node — a certificate's serial carries it, so two nodes sharing one could mint the same
  # serial, which is the failure a CA cannot recover from.
  nodes = {
    for i in range(var.node_count) : tostring(i) => {
      index          = i + 1
      vm_id          = var.first_vm_id + i
      name           = "${var.deployment_name}-${i + 1}"
      mgmt_ip        = "${var.mgmt_cidr_prefix}.${var.mgmt_first_octet + i}"
      pki_dns        = length(var.pki_dns) == 1 ? var.pki_dns[0] : var.pki_dns[i]
      interconnect_ip = var.interconnect_bridge == "" ? "" : "${var.interconnect_cidr_prefix}.${var.mgmt_first_octet + i}"
    }
  }
}

# ⚠️ THE SNIPPET IS A RESOURCE, so editing the template re-uploads it and the VM below
# picks the change up. Written per node because DC_INDEX and PKI_DNS differ between them.
resource "proxmox_virtual_environment_file" "vendor_data" {
  for_each = local.nodes

  content_type = "snippets"
  datastore_id = var.snippets_datastore
  node_name    = var.pve_node

  source_raw {
    file_name = "${var.deployment_name}-${each.value.index}-vendor.yaml"
    data = templatefile("${path.module}/vendor-data.yaml.tftpl", {
      deployment        = var.node_count > 1 ? "cluster" : "single"
      ci_user           = var.ci_user
      pki_dns           = each.value.pki_dns
      dc_index          = each.value.index
      pg_local          = var.pg_local ? "yes" : "no"
      key_backend       = var.key_backend
      nameservers       = var.nameservers
      p11_tls           = var.p11_tls ? "on" : "off"
      pkcs11_pin        = var.pkcs11_pin
      interconnect_ip   = each.value.interconnect_ip
      enabled_protocols = var.enabled_protocols
      all_protocols     = local.all_protocols
    })
  }
}

resource "proxmox_virtual_environment_vm" "node" {
  for_each = local.nodes

  vm_id     = each.value.vm_id
  name      = each.value.name
  node_name = var.pve_node
  tags      = ["fastpki", var.deployment_name]

  # Cloning a template rather than importing a disk: the image is baked separately by
  # deploy/cloud/image/build-qemu.sh, exactly as the AWS module consumes an AMI packer
  # built. `full = true` gives each node its own disk rather than a linked clone whose
  # lifetime is tied to the template — a CA's storage must not depend on an image somebody
  # may delete.
  clone {
    vm_id = var.template_vm_id
    full  = true
  }

  # ⚠️ UEFI, BECAUSE THE IMAGE IS ALPINE'S -uefi- CLOUD BUILD. It is GPT with an EFI system
  # partition and carries no BIOS boot code, so SeaBIOS finds nothing to execute: the VM
  # runs, the console stays blank, and the only symptom is that SSH never answers. The
  # template already has bios=ovmf and an EFI disk; this states the requirement where a
  # reader will look for it.
  bios    = "ovmf"
  machine = "q35"

  cpu {
    cores = var.cores
    # Pass the host processor through. On a hypervisor that is itself virtualised this is
    # the difference between a usable node and one an order of magnitude slower, because a
    # generic model stops CPU features being passed through and starts emulating them.
    type = "host"
  }

  memory {
    dedicated = var.memory_mb
  }

  disk {
    datastore_id = var.vm_datastore
    interface    = "scsi0"
    size         = var.disk_gb
    discard      = "on"
    ssd          = true
  }

  network_device {
    bridge = var.mgmt_bridge
  }

  dynamic "network_device" {
    for_each = var.interconnect_bridge == "" ? [] : [var.interconnect_bridge]
    content {
      bridge = network_device.value
    }
  }

  # A serial console, because the image directs its own console to ttyS0 and because a VM
  # whose network never came up can still be reached this way. `qm terminal <vmid>` on the
  # hypervisor is then the last resort that always works.
  serial_device {}
  vga {
    type = "serial0"
  }

  # ⚠️ OFF, BECAUSE THE IMAGE DOES NOT SHIP qemu-guest-agent. Enabling it makes Proxmox
  # believe it can ask the guest questions and issue it a clean shutdown; with no agent
  # installed, `qm agent <id> ping` answers "QEMU guest agent is not running" and a
  # shutdown waits for a timeout before falling back. The image stays minimal on purpose —
  # a CA node runs the binaries it needs and nothing else — and ACPI shutdown, which the
  # guest does honour, is enough. Turn this on only if the agent is added to the image.
  agent {
    enabled = false
  }

  initialization {
    datastore_id = var.vm_datastore

    # ⚠️ FALSE, OR FIRST BOOT NEEDS THE INTERNET AND SILENTLY DOES NOTHING WITHOUT IT.
    # Proxmox writes `package_upgrade: true` into the user-data it generates, so cloud-init
    # runs `apk upgrade` against dl-cdn.alpinelinux.org on every first boot. On a node with
    # no egress that fails — six minutes of "TLS: unspecified error" — and the exception
    # aborts the FINAL stage, which is the stage that runs `scripts-user`. Our whole install
    # is a runcmd, so it never executes: the node boots, takes its address, answers ping,
    # listens on nothing, and writes no fastpki-firstboot.log to say why. Measured on three
    # nodes in the lab, which is exactly how it presents.
    #
    # Nothing in the image needs upgrading — the bake is the whole point, and the vendor
    # data says in as many words that it reaches nothing. This makes that true of the boot
    # as well as of our half of it.
    upgrade = false

    ip_config {
      ipv4 {
        address = "${each.value.mgmt_ip}/24"
        gateway = var.mgmt_gateway
      }
    }

    dynamic "ip_config" {
      for_each = each.value.interconnect_ip == "" ? [] : [each.value.interconnect_ip]
      content {
        ipv4 {
          # No gateway on the interconnect: it has no route off this segment, and a second
          # default route appearing at boot is a blackhole that comes and goes depending on
          # which interface configured itself last.
          address = "${ip_config.value}/24"
        }
      }
    }

    dns {
      servers = var.nameservers
    }

    user_account {
      username = var.ci_user
      keys     = var.ssh_public_keys
    }

    vendor_data_file_id = proxmox_virtual_environment_file.vendor_data[each.key].id
  }

  lifecycle {
    # The template is consumed at clone time and never read again. Letting a template
    # change replace a running CA node would destroy its database and its token.
    ignore_changes = [clone]
  }
}

# ⚠️ THE TUNNEL CARRIES C_LOGIN, so it belongs on the segment with no route off it. What
# crosses it is the PIN protecting every CA private key in the token it fronts.
resource "terraform_data" "p11_tls_preconditions" {
  count = var.p11_tls ? 1 : 0
  lifecycle {
    precondition {
      condition     = var.interconnect_bridge != ""
      error_message = "p11_tls needs interconnect_bridge: the tunnel carries the token PIN and belongs on the segment with no route off it, not on the management network."
    }
  }
}
