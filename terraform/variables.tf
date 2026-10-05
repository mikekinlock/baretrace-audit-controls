# ---------------------------------------------------------------------------
# This stack has no per-environment posture: it is applied once per account and
# covers both environments. There are therefore no variables without defaults
# and no tfvars files — every variable here carries its own default.
# ---------------------------------------------------------------------------

# --- Identity ---------------------------------------------------------------

variable "region" {
  description = "AWS region. GuardDuty is regional, so the detector watches only this region; the trail is multi-region but its audit bucket lives here. EU only (GDPR), see PROJECT.md."
  type        = string
  default     = "eu-central-1"
}

variable "profile" {
  description = "AWS CLI profile. The profile has no default region configured, so region is always explicit."
  type        = string
  default     = "private"
}

variable "project" {
  description = "Project name. Combined with \"account\" to form the resource name prefix (see locals.tf)."
  type        = string
  default     = "baretrace"
}

variable "owner" {
  description = "Owner tag value, for cost attribution."
  type        = string
  default     = "michaelkinlock"
}

# --- Detective controls -----------------------------------------------------

variable "cloudtrail_retention_days" {
  description = <<-EOT
    Days to keep CloudTrail log objects before the bucket lifecycle rule expires
    them.

    90 rather than the 30 the action plan set for flow logs, and the difference is
    deliberate. Art. 33 gives 72 hours to notify from becoming AWARE of a breach,
    and the gap between compromise and discovery is routinely measured in weeks —
    a 30-day trail can leave an investigation unable to see the initial access it
    is trying to describe. 90 days is also what CloudTrail's own free Event history
    retains, so this is the floor at which the trail adds durable value rather than
    duplicating something AWS already gives away.

    NOT SETTLED ON ENGINEERING GROUNDS. A retention period is exactly the kind of
    judgement the review said to frame rather than answer. Recorded as an open
    question for the DPO in baretrace-global-infrastructure specs/HANDOVER.md; 90 is a defensible starting point,
    not a ruling.
  EOT
  type        = number
  default     = 90

  validation {
    condition     = var.cloudtrail_retention_days >= 1
    error_message = "cloudtrail_retention_days must be at least 1; an S3 lifecycle expiration of 0 days is rejected."
  }
}

variable "security_alert_email" {
  description = <<-EOT
    Address subscribed to the GuardDuty finding topic. Null by default, which
    means THE TOPIC IS CREATED AND NOBODY IS SUBSCRIBED TO IT.

    That default is a real gap, stated rather than hidden: a detector with no
    subscriber satisfies "GuardDuty is enabled" and does nothing for Art. 33,
    which turns on somebody becoming aware. Findings sit in a console no one is
    required to open.

    Null rather than a committed address on purpose. A named individual's work
    address in a public-ish repository is itself personal data in a file nobody
    reviews for it, and it would go stale the moment that person changes role.
    Supply it at apply time instead:

      make apply TF_CLI_ARGS="-var=security_alert_email=..."

    or, better, point it at a distribution list or an alerting integration that is
    not one person. Confirming the SNS subscription still requires clicking a link
    in the delivered email; Terraform cannot do that step.
  EOT
  type        = string
  default     = null
}
