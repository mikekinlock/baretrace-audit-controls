# Selected by `make plan ENVIRONMENT=production`. Carries no address: the alert address
# lives in an SSM parameter the owner sets by hand.
# Keep false until the owner has set that parameter; see security.tf for the order.
alert_subscription_enabled = false
