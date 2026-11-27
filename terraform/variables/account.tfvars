# The only var file: this stack is applied once per account (one state, detector and
# trail) and creates the alert parameter of both environments. Carries no address: the
# alert address lives in the SSM parameters the owner sets by hand.
# The owner set the stage email field on 2026-11-21; see security.tf for the order.
alert_subscription_enabled = true
# The PII and blind-index keys are created by each environment's database stack, and the
# lookup fails for a key that does not exist yet. Production is added here when its
# database stack exists.
pii_key_environments = ["stage"]
