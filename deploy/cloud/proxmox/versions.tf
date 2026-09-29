# OpenTofu, not Terraform — MPL-2.0 and a drop-in replacement, so nothing here is
# BUSL-encumbered. `terraform` also runs this module unchanged; the `tofu` CLI is what the
# docs use, exactly as in deploy/cloud/aws.
#
# ── WHY A SECOND IaC TARGET ──────────────────────────────────────────────────────────
# deploy/cloud/aws provisions the product in somebody's cloud account, billed by the hour,
# and that is the module an operator runs for real. It is also the module nothing can
# test: an AMI cannot be booted without EC2, so the whole first-boot contract — cloud-init
# delivers a KEY=VALUE answers file and fastpki-install-native consumes it — is exercised
# nowhere except in production.
#
# This module provisions the SAME contract against a Proxmox hypervisor, where a VM costs
# nothing and can be destroyed and rebuilt in a minute. What it shares with the AWS module
# is the part worth testing; what it does not share is the part that is purely AWS (ENIs,
# EBS volumes, security groups, Route 53). So this is not a port of that module and must
# not be refactored into one — the overlap is the cloud-init contract and nothing else.
#
# ── THE TEMPLATE IS THIS MODULE'S AMI ────────────────────────────────────────────────
# AWS: packer bakes an AMI, tofu launches instances from it. Here: packer bakes a qcow2
# (deploy/cloud/image/build-qemu.sh), that becomes a Proxmox TEMPLATE, and tofu clones VMs
# from it. The split is the same in both — the image is built once and separately, and this
# module only ever consumes one. It never builds, and it never compiles anything.
terraform {
  required_version = ">= 1.6"
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.66"
    }
  }
}

# ⚠️ THE TOKEN COMES FROM THE ENVIRONMENT, NEVER FROM A .tfvars FILE. Set
# PROXMOX_VE_API_TOKEN='user@realm!tokenid=uuid' before running. A tfvars file sits in the
# working tree where it is one `git add` away from being committed, and a Proxmox token
# with privsep=0 carries its user's full privileges over every VM on the hypervisor.
# terraform.tfvars.example shows the export rather than the variable for that reason.
provider "proxmox" {
  endpoint = var.pve_endpoint
  insecure = var.pve_insecure

  # The provider uploads cloud-init snippets over SSH rather than through the API, because
  # the API has no endpoint for writing into a snippets datastore. Without an agent this
  # needs a username and private key; with one it reuses the key already loaded.
  ssh {
    agent    = var.pve_ssh_agent
    username = var.pve_ssh_username

    # ⚠️ A PATH, AND THE PROVIDER IGNORES ~/.ssh/config. With no agent it attempts only
    # `none` and `password`, so without a key named here it fails with "no supported
    # methods remain" no matter what an interactive ssh to the same host would do. The
    # PATH is not a secret, unlike the API token, so it belongs in tfvars where it is
    # visible; the key itself never enters the configuration.
    private_key = var.pve_ssh_private_key_file == "" ? null : file(var.pve_ssh_private_key_file)
  }
}
