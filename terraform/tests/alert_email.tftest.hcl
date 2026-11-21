# The alert address comes from SSM, never from a committed value. Plan-only, with
# every data source mocked, so no AWS call is made.

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

override_data {
  target = data.aws_ssm_parameter.security_alert_email
  values = { value = "alerts@example.com" }
}

run "subscription" {
  command = plan

  assert {
    condition     = aws_sns_topic_subscription.security_alerts_email.protocol == "email"
    error_message = "the alert subscription must use the email protocol"
  }

  assert {
    condition     = aws_sns_topic_subscription.security_alerts_email.endpoint == "alerts@example.com"
    error_message = "the subscription endpoint must come from the SSM parameter"
  }
}

run "parameter_name" {
  command = plan

  variables {
    security_alert_email_parameter = "/x/y"
  }

  assert {
    condition     = data.aws_ssm_parameter.security_alert_email.name == "/x/y"
    error_message = "the SSM parameter name must follow the variable"
  }
}

run "bad_parameter_name" {
  command = plan

  variables {
    security_alert_email_parameter = "x"
  }

  expect_failures = [var.security_alert_email_parameter]
}
