# The alert parameter path and the subscription gate. Plan-only, with every data
# source mocked, so no AWS call is made.

mock_provider "aws" {}

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
  values = { account_id = "609106090153" }
}

run "stage_path" {
  command = plan

  variables {
    environment                = "stage"
    alert_subscription_enabled = false
  }

  assert {
    condition     = aws_ssm_parameter.security_alert_email.name == "/baretrace/stage/audit/security-alert-email"
    error_message = "the stage parameter path must carry stage"
  }

  assert {
    condition     = aws_ssm_parameter.security_alert_email.type == "SecureString"
    error_message = "the alert address must be stored as a SecureString"
  }

  assert {
    condition     = aws_ssm_parameter.security_alert_email.value == jsonencode({ email = "" })
    error_message = "Terraform must create the parameter with the placeholder, never an address"
  }

  assert {
    condition     = length(aws_sns_topic_subscription.security_alerts_email) == 0
    error_message = "no subscription while alert_subscription_enabled is false"
  }
}

run "production_path" {
  command = plan

  variables {
    environment                = "production"
    alert_subscription_enabled = false
  }

  assert {
    condition     = aws_ssm_parameter.security_alert_email.name == "/baretrace/production/audit/security-alert-email"
    error_message = "the production parameter path is carries production"
  }
}

# Not tested: the enabled path with a real address (endpoint, protocol) and a
# non-JSON value. The value is a configured attribute, and override_resource only
# fills computed ones, so a mocked plan or apply always sees the empty placeholder
# document. Both cases are checked by the first real plan after the owner sets
# the parameter.

run "placeholder_refused" {
  command = plan

  variables {
    environment                = "stage"
    alert_subscription_enabled = true
  }

  expect_failures = [aws_sns_topic_subscription.security_alerts_email]
}

run "bad_environment" {
  command = plan

  variables {
    environment                = "prod"
    alert_subscription_enabled = false
  }

  expect_failures = [var.environment]
}
