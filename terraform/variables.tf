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
