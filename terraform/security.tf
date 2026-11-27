# ---------------------------------------------------------------------------
# DETECTIVE CONTROLS — GuardDuty, CloudTrail, and somewhere for findings to go.
#
# GDPR Art. 33 gives 72 hours to notify a supervisory authority FROM BECOMING AWARE
# of a personal data breach. Every other control in BareTrace is preventive; none can
# tell you that something happened. Without detection the clock never starts.
#
# This stack is applied once per account (GuardDuty allows one detector per account
# per region), so nothing here is gated or per-environment. It covers stage and
# production alike.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  # ---------------------------------------------------------------------------
  # GuardDuty features to enable, with the reason each is worth its usage charge.
  #
  # CloudTrail management event analysis is NOT in this map, and cannot be: it is on
  # by default for every enabled detector and is not configurable. So the detector
  # below is already analysing KMS and IAM activity without a line here.
  #
  # Rates verified against the Pricing API for eu-central-1 on 2026-09-23. All
  # usage-priced; the detector itself has no standing charge.
  # ---------------------------------------------------------------------------
  guardduty_features = {
    # Asked for by name in action plan item 1.C. VERIFIED SUPPORTED FOR THIS
    # WORKLOAD rather than assumed: RDS Protection covers Aurora and Amazon RDS for
    # PostgreSQL, and baretrace-db-setup runs RDS for PostgreSQL. Had it been
    # Aurora-only, enabling this would have cost money to monitor nothing.
    #
    # What it detects is the case that matters most here: anomalous login activity
    # against the clients database, which is the insider-or-stolen-credential story
    # behind most personal data breaches. $1.23 per vCPU/month.
    "RDS_LOGIN_EVENTS" = "Anomalous RDS login activity, including against the clients database. Supports RDS for PostgreSQL, which is what baretrace-db-setup runs."

    # Also asked for by name. The invoice PDFs behind billings.document_s3_key are
    # personal data at rest in S3, and this is what notices unusual access patterns
    # against them. $1.04 per million S3 data events analysed.
    #
    # Note the dependency worth knowing: this analyses S3 data events, which is the
    # same source the CloudTrail selector below records. They are billed separately
    # and neither is a substitute for the other — GuardDuty judges, CloudTrail
    # evidences.
    "S3_DATA_EVENTS" = "Unusual access to S3 objects, including the invoice PDFs referenced by billings.document_s3_key."

    # NOT REQUESTED BY THE ACTION PLAN. Added deliberately, because it is the one
    # GuardDuty feature aimed squarely at this repository's central claim.
    #
    # This stack asserts that functions in private-app can reach three named AWS
    # services and nothing else. Lambda Protection analyses the network activity of
    # Lambda functions and alerts on connections to known-bad destinations — it is
    # the detective half of a control that is otherwise purely preventive, and it
    # covers exactly the compromised-dependency scenario the NAT gateway was
    # rejected over.
    #
    # Costs nothing today: $1.15/GB of Lambda network data analysed, and there are
    # no Lambdas yet. Re-cost when the services exist. Remove this line to return
    # to the action plan's literal scope.
    "LAMBDA_NETWORK_LOGS" = "Network activity of Lambda functions in private-app. The detective counterpart to the bounded-egress posture; not requested by the GDPR review, added because it tests this stack's main claim."
  }
}

# ===========================================================================
# GUARDDUTY
# ===========================================================================

# ---------------------------------------------------------------------------
# finding_publishing_frequency is set rather than defaulted, and it is an Art. 33
# decision disguised as a tuning knob. The default is SIX_HOURS. Against a 72-hour
# notification deadline that spends up to 8% of the budget before anyone can know,
# for no saving — the frequency does not affect price. FIFTEEN_MINUTES is the
# shortest available.
#
# It governs publication of updates to EXISTING findings. New findings of high
# severity are published as they are generated regardless.
# ---------------------------------------------------------------------------
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = {
    Name = "${local.account_prefix}-guardduty"
  }
}

# ---------------------------------------------------------------------------
# Features as separate resources, not a `datasources` block on the detector.
#
# The inline datasources form is deprecated in the AWS provider and the two forms
# conflict over ownership in the same way inline security group rules do. One
# resource per feature also means enabling a fourth is a one-line map addition with
# its own cost comment, rather than an edit to a nested block.
# ---------------------------------------------------------------------------
resource "aws_guardduty_detector_feature" "enabled" {
  for_each = local.guardduty_features

  detector_id = aws_guardduty_detector.main.id
  name        = each.key
  status      = "ENABLED"

  # AWS adds sub-features on its own (RDS_LOGIN_EVENTS came back from the first
  # apply with RDS_DATA_RISK enabled). Without this every plan would try to strip
  # them; AWS's defaults for sub-features are kept, the features themselves are ours.
  lifecycle {
    ignore_changes = [additional_configuration]
  }
}

# ---------------------------------------------------------------------------
# SOMEWHERE FOR FINDINGS TO GO.
#
# Not in the action plan, and the item is incomplete without it. "Enable GuardDuty"
# satisfies an audit checklist; Art. 33 turns on somebody BECOMING AWARE. A detector
# whose findings land only in a console nobody is required to open has not started
# any clock. EventBridge is the only supported way out of GuardDuty — there is no
# native subscription on the detector.
#
# NO ENCRYPTION AT REST ON THIS TOPIC, AND THAT IS A DELIBERATE CHOICE RATHER THAN
# AN OVERSIGHT. The obvious move is kms_master_key_id = "alias/aws/sns", and it
# produces a topic that silently drops every message EventBridge sends it:
# publishing to an encrypted topic requires kms:GenerateDataKey* for the calling
# service principal, the AWS-managed SNS key's policy cannot be edited to grant it,
# and the failure is a delivery error nobody sees. Fixing it properly costs a
# customer-managed key at $1/month plus its key policy.
#
# Not spent, because of what is in the message: a GuardDuty finding carries resource
# identifiers, internal addresses, and a severity. It does not carry customer
# personal data. SNS encrypts in transit regardless. If findings are ever routed
# somewhere that enriches them with personal data, this decision must be revisited
# — and a CMK would then be the cheap part.
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "security_alerts" {
  name         = "${local.account_prefix}-security-alerts"
  display_name = "BareTrace security findings"

  tags = {
    Name = "${local.account_prefix}-security-alerts"
  }
}

data "aws_iam_policy_document" "security_alerts" {
  statement {
    sid    = "AllowEventBridgeToPublish"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]

    # Confused-deputy guard. Without it the topic accepts publishes from
    # EventBridge acting on behalf of any account.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.security_alerts.json
}

# ---------------------------------------------------------------------------
# Severity 4.0 and above — MEDIUM, HIGH and CRITICAL.
#
# Not everything. GuardDuty LOW findings are dominated by reconnaissance noise that
# nobody will action, and a topic that cries wolf gets filtered to a folder, which
# is a worse outcome than no alerting because it looks like alerting. 4.0 is
# GuardDuty's own MEDIUM floor.
#
# The tradeoff, stated: LOW findings are then visible only in the console. If that
# is not acceptable, lower this number rather than adding a second rule.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${local.account_prefix}-guardduty-findings"
  description = "GuardDuty findings at MEDIUM severity and above, to the security alert topic."

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 4.0] }]
    }
  })

  tags = {
    Name = "${local.account_prefix}-guardduty-findings"
  }
}

resource "aws_cloudwatch_event_target" "guardduty_findings" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "security-alerts"
  arn       = aws_sns_topic.security_alerts.arn
}

# ---------------------------------------------------------------------------
# The PII and blind-index keys, looked up by alias.
#
# CreateGrant, PutKeyPolicy and the rest happen routinely on other keys (RDS and
# Secrets Manager create grants all the time), so the key-change rule below must be
# filtered to the two keys that guard personal data. Their ARNs are needed, and the
# keys belong to baretrace-db-setup, so this stack reads them rather than creating
# them. The lookup fails for a key that does not exist yet, hence
# var.pii_key_environments: an environment is listed once its database stack exists.
# ---------------------------------------------------------------------------
data "aws_kms_alias" "pii_key" {
  for_each = local.pii_key_aliases

  name = each.value
}

# ---------------------------------------------------------------------------
# Changes to the PII keys' policy, grants or state -> security alert topic.
#
# The key policy of the PII key is what stops every identity outside the database
# stack's functions from decrypting customer data (spec admin-and-pii-access 3.2).
# Whoever weakens that policy, grants themselves use of the key, or disables or
# schedules deletion of it has defeated the control without ever calling Decrypt, so
# the change itself is what must raise the alarm.
#
# A Terraform apply that changes the policy on purpose also alerts. That is
# intended: a policy change on these keys should never go unnoticed, and the mail
# that follows a deliberate change is cheap confirmation that it was the owner.
#
# These are write management events, so a rule in the normal ENABLED state sees
# them. The trail logs all management events, which is what EventBridge needs.
# The key is matched on `detail.resources[].ARN`, the CloudTrail record's own
# resource list, which names the key ARN for KMS calls (checked on a stage Decrypt
# record, 2026-11-27). NOT the top-level `resources` of the EventBridge event: for
# events delivered via CloudTrail that list is empty, so a pattern on it would never
# match and the rule would stay silent. Count 0 while no environment is listed: an
# empty list is not a valid pattern.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "pii_key_changes" {
  count = length(local.watched_key_arns) > 0 ? 1 : 0

  name        = "${local.account_prefix}-pii-key-changes"
  description = "Policy, grant and state changes on the PII and blind-index KMS keys, to the security alert topic."

  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["kms.amazonaws.com"]
      resources   = { ARN = local.watched_key_arns }
      eventName = [
        "PutKeyPolicy",
        "CreateGrant",
        "RetireGrant",
        "RevokeGrant",
        "ScheduleKeyDeletion",
        "DisableKey",
        "DisableKeyRotation",
      ]
    }
  })

  tags = {
    Name = "${local.account_prefix}-pii-key-changes"
  }
}

resource "aws_cloudwatch_event_target" "pii_key_changes" {
  count = length(aws_cloudwatch_event_rule.pii_key_changes)

  rule      = aws_cloudwatch_event_rule.pii_key_changes[0].name
  target_id = "security-alerts"
  arn       = aws_sns_topic.security_alerts.arn
}

# ---------------------------------------------------------------------------
# A refused use of any KMS key -> security alert topic.
#
# This is what fires when an identity outside the key policy's
# DenyUseOutsideTheServices list (baretrace-db-setup) tries to use the PII key: the
# call is refused and CloudTrail records it with an AccessDenied error code.
#
# kms:Encrypt, Decrypt, GenerateDataKey and GenerateMac are READ-ONLY management
# events. EventBridge delivers those only to rules whose state is
# ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS, and only when the trail logs
# read-only management events; this trail logs all of them (see the management
# selector below). Source:
# https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail-management.html
#
# NOT filtered by key. An AccessDenied on any KMS key is rare and worth a look, and
# not filtering also covers keys whose ARN this stack cannot look up yet (an
# environment missing from pii_key_environments).
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "kms_access_denied" {
  name        = "${local.account_prefix}-kms-access-denied"
  description = "Refused KMS cryptographic calls on any key, to the security alert topic."
  state       = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"

  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["kms.amazonaws.com"]
      eventName = [
        "Encrypt",
        "Decrypt",
        "ReEncrypt",
        "GenerateDataKey",
        "GenerateDataKeyWithoutPlaintext",
        "GenerateMac",
        "VerifyMac",
      ]
      errorCode = [{ prefix = "AccessDenied" }]
    }
  })

  tags = {
    Name = "${local.account_prefix}-kms-access-denied"
  }
}

resource "aws_cloudwatch_event_target" "kms_access_denied" {
  rule      = aws_cloudwatch_event_rule.kms_access_denied.name
  target_id = "security-alerts"
  arn       = aws_sns_topic.security_alerts.arn
}

# ---------------------------------------------------------------------------
# The alert address: an SSM parameter Terraform creates and the owner fills in.
#
# The repository is PUBLIC, so a committed address would be personal data in a
# file nobody reviews for it, and the Actions logs are public too. Terraform
# therefore creates the parameter with a placeholder and never holds the address
# in code. The value is sensitive, so it stays out of plans and logs.
# ---------------------------------------------------------------------------
# One per environment (stage and production) in this single state; every BareTrace
# stack of that environment reads it for its own alert topic.
resource "aws_ssm_parameter" "security_alert_email" {
  for_each = local.alert_email_parameters

  name  = each.value
  type  = "SecureString"             # default alias/aws/ssm key
  value = jsonencode({ email = "" }) # placeholder: the owner fills in the email field
  # Unchanged text, so the existing stage parameter is not rewritten (a new description is a new version).
  description = "Address for GuardDuty finding alerts. Set by hand; Terraform only creates it."

  # The owner sets the real address by hand, so a later apply must not reset it to
  # the placeholder. A refresh still reads the real value into state; the state
  # bucket is private and encrypted. To set it:
  #   aws ssm put-parameter --profile private --region eu-central-1 \
  #     --name <path> --type SecureString --overwrite \
  #     --value '{"email":"alerts@example.com"}'
  lifecycle {
    ignore_changes = [value]
  }
}

# Until 2026-11-25 the stack had one parameter, named after an `environment` variable,
# so production's could only replace stage's. The stage parameter keeps its address:
# this renames it in state, nothing is destroyed or recreated.
moved {
  from = aws_ssm_parameter.security_alert_email
  to   = aws_ssm_parameter.security_alert_email["stage"]
}

# The order matters, because the subscription needs the real address:
#   1. Deploy with alert_subscription_enabled = false; the parameter is created
#      with the placeholder document {"email": ""}.
#   2. The owner sets the email field by hand.
#   3. A pull request flips the tfvars to true; the subscription is created.
#   4. The owner clicks the confirmation link in the email.
#
# Terraform cannot finish step 4 — an email subscription stays
# `pending confirmation` until someone clicks the link AWS sends, and the resource
# reads as created regardless. Verify with `aws sns list-subscriptions-by-topic`
# and check SubscriptionArn is an ARN rather than the literal string
# "PendingConfirmation". See baretrace-global-infrastructure specs/tasks.md task 25.
resource "aws_sns_topic_subscription" "security_alerts_email" {
  count = var.alert_subscription_enabled ? 1 : 0

  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = local.alert_email

  lifecycle {
    precondition {
      condition     = strcontains(local.alert_email, "@")
      error_message = "Set the email field of the alert parameter by hand first (see the comment on aws_ssm_parameter.security_alert_email), then enable the subscription."
    }
  }
}

# ===========================================================================
# CLOUDTRAIL
# ===========================================================================
#
# ONE CORRECTION TO THE ACTION PLAN, AND IT MATTERS FOR WHAT GETS BUILT BELOW.
#
# Item 1.C asks for "CloudTrail with Data Events configured for S3 and KMS". Half of
# that is not a thing. CloudTrail data events cover S3 objects, Lambda functions,
# DynamoDB items and a handful of other data-plane resource types. THERE IS NO KMS
# DATA EVENT TYPE. kms:Decrypt, GenerateDataKey and Encrypt are MANAGEMENT events.
#
# The practical consequence is the opposite of what the instruction implies: KMS
# activity needs nothing configured, because management events are recorded by
# default and the first copy of them in a trail is free. What it needs is to NOT be
# excluded — KMS is high volume, so excluding kms.amazonaws.com is a common cost
# optimisation, and doing it here would discard the audit record of every decryption
# of a customer name or address. That is the most security-relevant management event
# in the account.
#
# So: management events included, nothing excluded, and the intent written down so
# that a future cost review has to argue past this comment.
# ===========================================================================

# ---------------------------------------------------------------------------
# The bucket holding the evidence.
#
# Account-scoped name, suffixed with the account id because S3 bucket names are
# globally unique. Matches the convention of the pre-existing state bucket,
# terraform-<account-id>-state.
#
# force_destroy is LEFT AT FALSE, deliberately. It means `terraform destroy` fails
# while objects remain rather than deleting the audit trail. For an audit log that
# refusal is the desired behaviour — see the hazard note at the top of this file.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "audit" {
  bucket = "${local.account_prefix}-audit-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${local.account_prefix}-audit"
  }
}

# Audit logs are not public. This is four settings rather than one because the
# bucket-level and account-level defaults have changed over time and being explicit
# costs nothing.
resource "aws_s3_bucket_public_access_block" "audit" {
  bucket = aws_s3_bucket.audit.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# Versioning on, for tamper evidence rather than recovery.
#
# An attacker who reaches this bucket and overwrites a log object leaves the
# previous version in place. Combined with log file validation on the trail below,
# that is two independent ways to notice the audit trail being edited.
#
# The lifecycle rule expires noncurrent versions too, or versioning would quietly
# defeat the retention policy by keeping every overwritten object forever.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ---------------------------------------------------------------------------
# SSE-S3 rather than SSE-KMS, and the reasoning is the same shape as the SNS topic
# above: SSE-KMS here would mean a customer-managed key at $1/month, a key policy
# granting the CloudTrail service principal, and a second thing to get wrong on a
# bucket whose contents are AWS API metadata rather than personal data. CloudTrail
# log objects record who called what; they do not carry the decrypted values.
#
# bucket_key_enabled has no effect under AES256 and is omitted rather than set to
# something misleading.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ---------------------------------------------------------------------------
# Retention. Bounded in both directions and for two different reasons:
#
#   Long enough that an Art. 33 investigation can see the initial access it is
#   trying to describe. Detection lags compromise by weeks, routinely.
#   Short enough to satisfy Art. 5(1)(e). An indefinite audit trail is an
#   indefinite retention of records about identifiable people's API activity.
#
# 90 days is the default and it is a starting point, not a ruling — flagged for the
# DPO in baretrace-global-infrastructure specs/HANDOVER.md. The abort-incomplete-upload rule is unrelated hygiene:
# failed multipart uploads are invisible in the console and billed indefinitely.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    id     = "expire-audit-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = var.cloudtrail_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.cloudtrail_retention_days
    }
  }

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  # The API rejects a lifecycle configuration on a bucket whose versioning state is
  # still settling, and the noncurrent rule above is meaningless without it.
  depends_on = [aws_s3_bucket_versioning.audit]
}

# ---------------------------------------------------------------------------
# Bucket policy for the CloudTrail service principal.
#
# Both statements are required and the trail will not create without them —
# CloudTrail checks the bucket ACL before it writes anything, so a policy with only
# PutObject fails at create time with an "insufficient permissions" error that reads
# like an IAM problem with the caller.
#
# aws:SourceArn on both statements is the confused-deputy guard AWS documents for
# this case. Without it, CloudTrail acting for a DIFFERENT account could be pointed
# at this bucket. With it, only this specific trail can write here.
#
# bucket-owner-full-control on the ACL condition is also documented as required;
# without it CloudTrail writes objects this account cannot read, which surfaces
# much later as an unreadable audit trail.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "audit_bucket" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.region}:${data.aws_caller_identity.current.account_id}:trail/${local.account_prefix}-trail"]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.region}:${data.aws_caller_identity.current.account_id}:trail/${local.account_prefix}-trail"]
    }
  }

  # ---------------------------------------------------------------------------
  # TLS-only on the audit bucket.
  #
  # The trail's own writes come from the CloudTrail service over TLS, so this
  # denies only insecure access. Without it, anyone with s3 permissions could
  # read or write audit evidence over plain HTTP where it can be intercepted or
  # altered in transit. Evidence integrity matters for GDPR Art. 33
  # investigations.
  # ---------------------------------------------------------------------------
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.audit_bucket.json
}

# ---------------------------------------------------------------------------
# The trail.
#
# is_multi_region_trail = true even though everything BareTrace runs is in
# eu-central-1 — because that is the point. An attacker with credentials does not
# confine themselves to the region you use; unused regions are where the
# cryptomining and the quiet IAM changes happen, and a single-region trail is blind
# to exactly that. The first copy of management events is free in any region, so
# this costs nothing.
#
# No Chapter V transfer question arises: a multi-region trail created here writes to
# the eu-central-1 bucket above. The logs do not leave the region, only the events'
# origins differ.
#
# enable_log_file_validation produces signed digest files, so a modified or deleted
# log file is detectable. Free, and it is what makes this trail evidence rather than
# just a record.
#
# NOT sent to CloudWatch Logs. That would cost $0.63/GB of ingestion and its only
# advantage is metric filters and alarms on trail content. GuardDuty already analyses
# these same management events and has a route to the alert topic above, so the
# alarm path exists without paying to duplicate the stream. Revisit if a specific
# alarm is needed that GuardDuty does not produce.
# ---------------------------------------------------------------------------
resource "aws_cloudtrail" "main" {
  name           = "${local.account_prefix}-trail"
  s3_bucket_name = aws_s3_bucket.audit.id

  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true

  # ---------------------------------------------------------------------------
  # MANAGEMENT EVENTS — where the KMS audit trail actually lives.
  #
  # This selector is the answer to "data events for KMS", which is not available.
  # kms:Decrypt on the clients-pii key is a management event and it is captured
  # here, at no charge for the first copy.
  #
  # NOTHING IS EXCLUDED. There is no exclude_management_event_sources and there must
  # not be: excluding kms.amazonaws.com is the standard way to cut CloudTrail cost
  # and it would throw away the record of every decryption of a customer name or
  # address. If a future cost review wants this, the thing being traded is the
  # Art. 33 audit trail over personal data access.
  # ---------------------------------------------------------------------------
  advanced_event_selector {
    name = "Management events, including every KMS cryptographic operation"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  # ---------------------------------------------------------------------------
  # S3 DATA EVENTS — object-level access, including the invoice PDFs.
  #
  # This is the half of item 1.C that is genuinely a data event. billings.document_s3_key
  # points at invoice PDFs containing names and addresses, and object-level access to
  # them is not recorded by management events at all.
  #
  # $1.00 per million events, so unlike the selector above this one has a bill
  # attached, which is why the audit bucket is excluded from it. CloudTrail writing
  # log objects would otherwise generate data events describing CloudTrail writing
  # log objects — a feedback loop that is pure cost and no information. The state
  # bucket is NOT excluded: who read or wrote Terraform state is worth knowing.
  # ---------------------------------------------------------------------------
  advanced_event_selector {
    name = "S3 object-level access, excluding this trail's own log writes"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field           = "resources.ARN"
      not_starts_with = ["${aws_s3_bucket.audit.arn}/"]
    }
  }

  # ---------------------------------------------------------------------------
  # LAMBDA DATA EVENTS — every Invoke of admin_service and the pii_* functions.
  #
  # Records each invocation and who called it. The owner sees customer data only
  # through these functions, and each such access must be logged (spec
  # admin-and-pii-access 2.2); an Invoke is not a management event, so without this
  # selector nothing would record it.
  #
  # Both environments, not just pii_key_environments: an ARN prefix needs no lookup,
  # so production is covered before its functions exist.
  #
  # Cost: $0.10 per 100,000 data events. Admin calls are few and pii_* functions run
  # one to three times per order, so cents per month.
  #
  # The first prefix has no trailing separator, so it matches admin_service and, by
  # accident, a hypothetical admin_service* name; acceptable, such a function
  # would be an admin function too. The second ends in "pii_" for the pii_* family.
  # ---------------------------------------------------------------------------
  advanced_event_selector {
    name = "Lambda invocations of admin_service and the pii_ functions"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::Lambda::Function"]
    }

    field_selector {
      field = "resources.ARN"
      starts_with = flatten([
        for env in sort(tolist(local.environments)) : [
          "arn:${data.aws_partition.current.partition}:lambda:${var.region}:${data.aws_caller_identity.current.account_id}:function:${var.project}-${env}-admin_service",
          "arn:${data.aws_partition.current.partition}:lambda:${var.region}:${data.aws_caller_identity.current.account_id}:function:${var.project}-${env}-pii_",
        ]
      ])
    }
  }

  tags = {
    Name = "${local.account_prefix}-trail"
  }

  # The bucket policy must exist before the trail, or CloudTrail's create-time
  # permission check on the bucket fails. Terraform does not infer this from the
  # s3_bucket_name reference, which points at the bucket rather than its policy.
  depends_on = [aws_s3_bucket_policy.audit]
}
