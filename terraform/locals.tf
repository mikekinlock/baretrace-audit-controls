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

  # The PII key and the guest blind-index (MAC) key of each listed environment, by the
  # aliases baretrace-db-setup gives them. Keyed "<env>/<alias suffix>" for the lookup.
  pii_key_aliases = {
    for pair in setproduct(var.pii_key_environments, ["clients-pii", "guest-mac"]) :
    "${pair[0]}/${pair[1]}" => "alias/${var.project}-${pair[0]}-${pair[1]}"
  }

  # ARNs of those keys, for filtering key events. Empty until an environment is listed.
  watched_key_arns = [for k in sort(keys(data.aws_kms_alias.pii_key)) : data.aws_kms_alias.pii_key[k].target_key_arn]

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
