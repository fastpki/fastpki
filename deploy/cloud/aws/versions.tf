# OpenTofu, not Terraform — MPL-2.0 and a drop-in replacement, so nothing here is
# BUSL-encumbered. `terraform` also runs this module unchanged; the `tofu` CLI is what the
# wizard drives and what the docs use.
#
# ── ON HCL BEING HERE AT ALL ─────────────────────────────────────────────────────────
# FastPKI's standing rule is C++ for binaries and shell for tests and deploys, and this
# directory is a deliberate, argued exception rather than something that arrived with a
# commit. Provisioning a VPC, subnets, security groups, network interfaces and instances
# from shell means hand-rolling `aws` CLI calls with no state, no dependency graph and no
# teardown — every re-run has to re-derive what already exists, and a partial failure
# leaves resources nobody can find. That is worse than a second language, and it is worse
# in exactly the place (someone else's cloud account, billed by the hour) where "worse"
# costs money. Everything ABOVE this layer — the wizard, the image build, the installer —
# is still shell.
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

# ⚠️ WHICH ACCOUNT THIS IS ALLOWED TO TOUCH. Credentials are ambient — a profile, an
# environment variable, an instance role — so the account an apply lands in is decided by
# whatever the shell happened to be carrying, and nothing in a plan says which one it is
# until resources appear there. Anyone who works with more than one AWS account will
# eventually point this module at the wrong one. Naming the account in the deployment's own
# tfvars turns that into a refusal before the first API call that changes anything.
provider "aws" {
  region              = var.region
  allowed_account_ids = var.allowed_account_id == "" ? null : [var.allowed_account_id]
  default_tags {
    tags = {
      Product    = "FastPKI"
      Managed    = "opentofu"
      Deployment = var.deployment_name
    }
  }
}
