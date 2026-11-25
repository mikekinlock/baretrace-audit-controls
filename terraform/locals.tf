locals {
  # Name prefix for this stack's resources: baretrace-account-audit-<account id>,
  # baretrace-account-trail, and so on. "account" instead of an environment name
  # because there is one of each per account, covering stage and production.
  # Not a published contract: no other repository looks these up by name.
  account_prefix = "${var.project}-account"

  # One alert parameter per environment, all in this one account-level state:
  # /baretrace/<env>/audit/security-alert-email. The other stacks of an environment
  # read their own environment's parameter (alert_subscription_enabled in each repo).
  environments = toset(["stage", "production"])
  alert_email_parameters = {
    for env in local.environments : env => "/${var.project}/${env}/audit/security-alert-email"
  }

  # The parameter holds a JSON document, {"email": "..."}, that the owner fills in
  # by hand. try() turns a missing field or a non-JSON value into "", which the
  # subscription precondition (an address must contain "@") refuses. The account's
  # security topic covers both environments and mails the address of one of them.
  alert_email = try(jsondecode(aws_ssm_parameter.security_alert_email[var.alert_address_environment].value).email, "")

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
