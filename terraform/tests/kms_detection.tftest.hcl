# KMS key detection rules and the Lambda data selector. Plan-only, with every data
# source mocked, so no AWS call is made.

mock_provider "aws" {}

# The topic ARN is computed, so without this the target comparisons see "unknown".
override_resource {
  target          = aws_sns_topic.security_alerts
  override_during = plan
  values          = { arn = "arn:aws:sns:eu-central-1:111122223333:baretrace-account-security-alerts" }
}

override_data {
  target = data.aws_iam_policy_document.security_alerts
  values = { json = "{}" }
}

override_data {
  target = data.aws_iam_policy_document.audit_bucket
  values = { json = "{}" }
}

override_data {
  target = data.aws_caller_identity.current
  values = { account_id = "111122223333" }
}

override_data {
  target = data.aws_partition.current
  values = { partition = "aws" }
}

override_data {
  target = data.aws_kms_alias.pii_key["stage/clients-pii"]
  values = { target_key_arn = "arn:aws:kms:eu-central-1:111122223333:key/11111111-1111-1111-1111-111111111111" }
}

override_data {
  target = data.aws_kms_alias.pii_key["stage/guest-mac"]
  values = { target_key_arn = "arn:aws:kms:eu-central-1:111122223333:key/22222222-2222-2222-2222-222222222222" }
}

run "key_changes_rule" {
  command = plan

  variables {
    alert_subscription_enabled = false
    pii_key_environments       = ["stage"]
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.pii_key_changes) == 1
    error_message = "the key-change rule must exist when an environment is listed"
  }

  assert {
    condition = toset(jsondecode(aws_cloudwatch_event_rule.pii_key_changes[0].event_pattern).detail.eventName) == toset([
      "PutKeyPolicy", "CreateGrant", "RetireGrant", "RevokeGrant",
      "ScheduleKeyDeletion", "DisableKey", "DisableKeyRotation",
    ])
    error_message = "the key-change rule must match exactly the seven key policy, grant and state calls"
  }

  assert {
    condition = toset(jsondecode(aws_cloudwatch_event_rule.pii_key_changes[0].event_pattern).detail.resources.ARN) == toset([
      "arn:aws:kms:eu-central-1:111122223333:key/11111111-1111-1111-1111-111111111111",
      "arn:aws:kms:eu-central-1:111122223333:key/22222222-2222-2222-2222-222222222222",
    ])
    error_message = "the key-change rule must be filtered to the two stage keys"
  }

  assert {
    condition     = !contains(keys(jsondecode(aws_cloudwatch_event_rule.pii_key_changes[0].event_pattern)), "resources")
    error_message = "the top-level resources list of a CloudTrail-delivered event is empty: match detail.resources.ARN instead"
  }

  assert {
    condition     = aws_cloudwatch_event_target.pii_key_changes[0].arn == aws_sns_topic.security_alerts.arn
    error_message = "the key-change rule must target the security alert topic"
  }
}

run "no_environment_listed" {
  command = plan

  variables {
    alert_subscription_enabled = false
    pii_key_environments       = []
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.pii_key_changes) == 0
    error_message = "no key-change rule while no environment is listed"
  }

  assert {
    condition     = aws_cloudwatch_event_rule.kms_access_denied.name == "baretrace-account-kms-access-denied"
    error_message = "the access-denied rule does not depend on the key lookup"
  }
}

run "access_denied_rule" {
  command = plan

  variables {
    alert_subscription_enabled = false
  }

  assert {
    condition     = aws_cloudwatch_event_rule.kms_access_denied.state == "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
    error_message = "Decrypt is a read-only management event; the rule needs the ALL state to receive it"
  }

  assert {
    condition     = contains(jsondecode(aws_cloudwatch_event_rule.kms_access_denied.event_pattern).detail.eventName, "Decrypt")
    error_message = "the access-denied rule must match Decrypt"
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.kms_access_denied.event_pattern).detail.errorCode[0].prefix == "AccessDenied"
    error_message = "the access-denied rule must match the AccessDenied error code prefix"
  }

  assert {
    condition     = aws_cloudwatch_event_target.kms_access_denied.arn == aws_sns_topic.security_alerts.arn
    error_message = "the access-denied rule must target the security alert topic"
  }
}

run "lambda_data_events" {
  command = plan

  variables {
    alert_subscription_enabled = false
  }

  assert {
    condition = anytrue([
      for s in aws_cloudtrail.main.advanced_event_selector :
      anytrue([for f in s.field_selector : f.field == "resources.type" && contains(f.equals, "AWS::Lambda::Function")])
      && anytrue([
        for f in s.field_selector : f.field == "resources.ARN" && toset(f.starts_with) == toset([
          "arn:aws:lambda:eu-central-1:111122223333:function:baretrace-stage-admin_service",
          "arn:aws:lambda:eu-central-1:111122223333:function:baretrace-stage-pii_",
          "arn:aws:lambda:eu-central-1:111122223333:function:baretrace-production-admin_service",
          "arn:aws:lambda:eu-central-1:111122223333:function:baretrace-production-pii_",
        ])
      ])
    ])
    error_message = "the trail needs a Lambda data selector with the four admin_service and pii_ ARN prefixes"
  }

  assert {
    condition = anytrue([
      for s in aws_cloudtrail.main.advanced_event_selector :
      length(s.field_selector) == 1 && one(s.field_selector).field == "eventCategory" && one(s.field_selector).equals == tolist(["Management"])
    ])
    error_message = "the management selector must stay: all management events, nothing excluded"
  }
}

run "bad_key_environment" {
  command = plan

  variables {
    alert_subscription_enabled = false
    pii_key_environments       = ["uat"]
  }

  expect_failures = [var.pii_key_environments]
}
