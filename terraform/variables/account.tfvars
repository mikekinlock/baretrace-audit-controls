# The only var file: this stack is applied once per account (one state, detector and
# trail) and creates the alert parameter of both environments. Carries no address: the
# alert address lives in the SSM parameters the owner sets by hand.
# The owner set the stage email field on 2026-11-21; see security.tf for the order.
alert_subscription_enabled = true
