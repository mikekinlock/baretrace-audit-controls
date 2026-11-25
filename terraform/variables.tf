# ---------------------------------------------------------------------------
# This stack has no per-environment posture: it is applied once per account and
# covers both environments, so it has no environment variable. It creates the alert
# parameter of BOTH environments. The variable without a default
# (alert_subscription_enabled) comes from terraform/variables/account.tfvars; every
# other variable carries its own default.
# ---------------------------------------------------------------------------

variable "alert_address_environment" {
  description = "Whose alert parameter the account's security topic mails: GuardDuty findings cover the whole account, so the topic takes the address of one environment. Stage, because its parameter is the one filled in today."
  type        = string
  default     = "stage"

  validation {
    condition     = contains(["stage", "production"], var.alert_address_environment)
    error_message = "alert_address_environment must be \"stage\" or \"production\"."
  }
}

variable "alert_subscription_enabled" {
  description = "Whether the email subscription to the GuardDuty finding topic exists. Keep false until the owner has set the alert parameter by hand; see the order in security.tf."
  type        = bool
}

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
