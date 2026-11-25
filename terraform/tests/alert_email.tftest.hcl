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

run "both_parameters" {
  command = plan

  variables {
    alert_subscription_enabled = false
  }

  assert {
    condition     = aws_ssm_parameter.security_alert_email["stage"].name == "/baretrace/stage/audit/security-alert-email"
    error_message = "the stage parameter path must carry stage"
  }

  assert {
    condition     = aws_ssm_parameter.security_alert_email["production"].name == "/baretrace/production/audit/security-alert-email"
    error_message = "the production parameter path must carry production"
  }

  assert {
    condition     = length(aws_ssm_parameter.security_alert_email) == 2
    error_message = "exactly one parameter per environment, stage and production"
  }

  assert {
    condition     = alltrue([for p in aws_ssm_parameter.security_alert_email : p.type == "SecureString"])
    error_message = "every alert address must be stored as a SecureString"
  }

  assert {
    condition     = alltrue([for p in aws_ssm_parameter.security_alert_email : p.value == jsonencode({ email = "" })])
    error_message = "Terraform must create every parameter with the placeholder, never an address"
  }

  assert {
    condition     = length(aws_sns_topic_subscription.security_alerts_email) == 0
    error_message = "no subscription while alert_subscription_enabled is false"
  }
}

# Not tested: the enabled path with a real address (endpoint, protocol) and a
# non-JSON value. The value is a configured attribute, and override_resource only
# fills computed ones, so a mocked plan or apply always sees the empty placeholder
# document. Both cases are checked by the first real plan after the owner sets
# the parameter. The `moved` block (stage parameter kept, not replaced) is checked
# by the real plan too: a mocked plan starts from an empty state.

run "placeholder_refused" {
  command = plan

  variables {
    alert_subscription_enabled = true
  }

  expect_failures = [aws_sns_topic_subscription.security_alerts_email]
}

run "placeholder_refused_for_production_address" {
  command = plan

  variables {
    alert_subscription_enabled = true
    alert_address_environment  = "production"
  }

  expect_failures = [aws_sns_topic_subscription.security_alerts_email]
}

run "bad_address_environment" {
  command = plan

  variables {
    alert_subscription_enabled = false
    alert_address_environment  = "prod"
  }

  expect_failures = [var.alert_address_environment]
}
