terraform {
  # 1.10 is the floor because of `use_lockfile` in the backend block below. It is
  # also what the sibling stacks require, and there is no reason for this one to
  # be the odd stack out.
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80, < 7.0"
    }
  }

  # ---------------------------------------------------------------------------
  # Remote state with locking.
  #
  # The bucket is account-level shared infrastructure, created and owned OUTSIDE
  # this repository — nothing here manages it and there is no bootstrap stack.
  # It already has versioning enabled, which is what makes a corrupt or truncated
  # state write recoverable.
  #
  # `use_lockfile` uses S3-native conditional writes for locking (Terraform
  # >= 1.10), so there is no DynamoDB table to provision or pay for.
  #
  # PARTIAL configuration on purpose. Backend blocks accept only literals — no
  # variables, no locals — so spelling out bucket, key, region, and profile here
  # would duplicate var.region and var.profile with no way to keep them in
  # step. The Makefile supplies those via `-backend-config`, which makes it
  # the single source of truth and the required entry point: `terraform init` run
  # bare will prompt for them.
  #
  # What stays here is policy rather than location, which has no reason to vary
  # between environments.
  #
  # State key convention: this stack is applied once per account, so the key has
  # no environment segment:
  # BaretraceAuditControls/state.tfstate
  # ---------------------------------------------------------------------------
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region  = var.region
  profile = var.profile

  default_tags {
    tags = local.tags
  }
}
