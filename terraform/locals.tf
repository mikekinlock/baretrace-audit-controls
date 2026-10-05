locals {
  # Name prefix for this stack's resources: baretrace-account-audit-<account id>,
  # baretrace-account-trail, and so on. "account" instead of an environment name
  # because there is one of each per account, covering stage and production.
  # Not a published contract: no other repository looks these up by name.
  account_prefix = "${var.project}-account"

  # Applied to everything through `default_tags` on the provider.
  #
  # No Environment tag: this stack is applied once per account and its trail and
  # detector cover both environments. Claiming one environment would be a lie in
  # the audit record, so the tag is omitted rather than set to a value that is
  # not true.
  tags = {
    Project    = var.project
    Owner      = var.owner
    ManagedBy  = "terraform"
    Repository = "baretrace-audit-controls"
  }
}
