# ---------------------------------------------------------------------------
# Terraform entry point.
#
# This stack is applied ONCE PER ACCOUNT and has no environment dimension.
# It holds the account's only GuardDuty detector and the only CloudTrail
# trail, because AWS permits one detector per account per region. A trail
# covering both environments must not claim one, so there is no
# `environment` variable, no per-environment tfvars file, and no
# `Environment` tag on any resource.
#
# The same two plumbing problems as the sibling stacks apply. The `private`
# AWS profile has no default region, so every bare `terraform` or `aws`
# invocation that omits --region fails confusingly; every command here
# passes it. Backend blocks accept only literals, so the state location
# cannot reference the same variables the resources use — declaring it once
# here and injecting it with -backend-config keeps region from drifting
# apart from the resources.
#
# Consequence: `terraform init` must go through `make init`. Run bare it has
# no backend configuration and will prompt interactively.
#
# BOTH DIRECTIONS GO THROUGH A SAVED PLAN, and neither apply nor destroy will
# run without one:
#
#   make plan          -> terraform.tfplan          -> make apply
#   make plan-destroy  -> terraform-destroy.tfplan  -> make destroy
#
# The plan file is the approval. That is why the pairs use separate
# filenames: a saved plan carries its own direction, so one shared name
# would let `make destroy` execute a create plan, or `make apply` execute a
# teardown.
#
# ORDER OF APPLY. GuardDuty allows one detector per account per region, and the
# account has one trail, so exactly one stack may own them. That stack is this
# one. baretrace-global-infrastructure must have its own copy removed (work-queue
# T22) BEFORE its first production apply; otherwise it would try to create a
# second detector and a second trail. This stack itself can be applied at any
# time, once.
#
# There is no disarm/rearm pair here. Nothing in this stack has deletion
# protection, so there is nothing to disarm before a teardown.
# ---------------------------------------------------------------------------

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

# --- Identity ---------------------------------------------------------------

AWS_PROFILE    ?= private
AWS_REGION     ?= eu-central-1
AWS_ACCOUNT_ID ?= 609106090153

PROJECT ?= baretrace
OWNER   ?= michaelkinlock

# --- Remote state -----------------------------------------------------------
# The bucket is pre-existing, account-level shared infrastructure. Nothing in
# this repository creates or manages it, and there is no bootstrap stack.
#
# There is no environment segment in the key: this stack is applied once per
# account and covers both environments.

STATE_BUCKET ?= terraform-$(AWS_ACCOUNT_ID)-state
STATE_KEY    ?= BaretraceAuditControls/state.tfstate
STATE_REGION ?= $(AWS_REGION)

# --- Wiring -----------------------------------------------------------------

TF_DIR := terraform

# TWO plan files, and the separation is load-bearing rather than tidiness.
#
# A saved plan carries its own direction: `terraform apply <file>` does whatever the
# file says, create or destroy, without re-reading the configuration. So a single
# shared filename would make `make plan` followed by `make destroy` execute a CREATE
# plan, and `make plan-destroy` followed by `make apply` execute a TEARDOWN — each
# silently, each with the wrong target having written the file. Encoding the direction
# in the name makes that unrepresentable.
#
# Both match the `*.tfplan` pattern already in .gitignore.
PLAN_FILE         := terraform.tfplan
DESTROY_PLAN_FILE := terraform-destroy.tfplan

TF := terraform -chdir=$(TF_DIR)

AWS := aws --profile $(AWS_PROFILE) --region $(AWS_REGION)

# The four state-location values are exported so scripts/init.sh can build
# the -backend-config flags from them.
export STATE_BUCKET STATE_KEY STATE_REGION AWS_PROFILE

# No environment variable and no var-file: this stack is applied once per
# account and covers both environments. The four -var flags are the whole
# posture.
TF_VARS := \
	-var="region=$(AWS_REGION)" \
	-var="profile=$(AWS_PROFILE)" \
	-var="project=$(PROJECT)" \
	-var="owner=$(OWNER)"

.PHONY: help fmt fmt-check validate check preflight init init-upgrade init-migrate \
        plan plan-destroy apply destroy output show state-list whoami clean build

help: ## Show this help
	@echo "Targets:"
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Settings (override on the command line, e.g. make plan PROJECT=other):"
	@printf "  %-16s %s\n" \
		AWS_PROFILE   "$(AWS_PROFILE)" \
		AWS_REGION    "$(AWS_REGION)" \
		PROJECT       "$(PROJECT)" \
		STATE_BUCKET  "$(STATE_BUCKET)" \
		STATE_KEY     "$(STATE_KEY)"

# --- Static checks ----------------------------------------------------------

fmt: ## Rewrite .tf files to canonical format
	$(TF) fmt -recursive

fmt-check: ## Fail if any .tf file is not canonically formatted
	$(TF) fmt -check -recursive

validate: ## Validate configuration (requires init)
	$(TF) validate

check: fmt-check validate ## Everything a commit should pass

# Confirms credentials and the state bucket before a plan spends a minute
# failing on them. There is no var file to check and no upstream stack to
# verify — this stack is the account-level audit trail.
preflight: ## Verify credentials and the state bucket
	@echo "identity : $$($(AWS) sts get-caller-identity --query Arn --output text)"
	@echo "state    : $$($(AWS) s3api head-bucket --bucket $(STATE_BUCKET) 2>&1 \
		&& echo "s3://$(STATE_BUCKET) reachable" || echo "UNREACHABLE")"

# --- Build ------------------------------------------------------------------

build: ## Format-check, validate, and compile all Go code (no AWS credentials needed)
	@bash scripts/build.sh

# --- Lifecycle --------------------------------------------------------------

init: ## Initialise the backend and download providers
	bash scripts/init.sh init

init-upgrade: ## Re-initialise and accept newer provider versions within constraints
	bash scripts/init.sh init-upgrade

init-migrate: ## Re-initialise after changing the state bucket or key, moving existing state
	bash scripts/init.sh init-migrate

# Writes the plan to disk so apply executes exactly what was reviewed rather than
# re-planning against whatever the account looks like a few minutes later.
plan: ## Plan and save the result to terraform/terraform.tfplan
	$(TF) plan $(TF_VARS) -out=$(PLAN_FILE)

# Saved for the same reason `plan` is, and the reason is stronger here: the
# destroy you reviewed must be the destroy that runs. Without a saved plan,
# Terraform re-plans against whatever the account looks like by then and says so
# itself ("Terraform can't guarantee to take exactly these actions"). For the
# irreversible direction that note is not noise.
plan-destroy: ## Plan a full teardown and save it to terraform/terraform-destroy.tfplan
	$(TF) plan -destroy $(TF_VARS) -out=$(DESTROY_PLAN_FILE)

# Applying a saved plan is non-interactive by design — Terraform takes the review
# that produced the file as the approval. `plan` is the gate; read its output.
apply: ## Apply the saved plan (run make plan first)
	@test -f $(TF_DIR)/$(PLAN_FILE) \
		|| { echo "No saved plan at $(TF_DIR)/$(PLAN_FILE). Run 'make plan' and read it first."; exit 1; }
	$(TF) apply $(PLAN_FILE)
	@rm -f $(TF_DIR)/$(PLAN_FILE)

# Executes a SAVED destroy plan, mirroring `apply`.
#
# The gate is the plan file: `make plan-destroy` produces it and reading that output is
# the approval, exactly as `plan` is the gate for `apply`. On top of that the typed
# confirmation below is unconditional, because there is no stage-like environment here
# where the friction could safely be dropped.
#
# This stack holds the account's only audit trail and the only threat detector for
# BOTH stage and production. There is no environment condition here: destroying it
# leaves every environment running with no threat detection and no audit trail.
# The audit bucket has force_destroy = false, so the destroy will fail partway
# while log objects remain. That refusal is a safety net, not a plan.
destroy: ## Execute the saved destroy plan (run make plan-destroy first)
	@test -f $(TF_DIR)/$(DESTROY_PLAN_FILE) \
		|| { echo "No saved destroy plan at $(TF_DIR)/$(DESTROY_PLAN_FILE)."; \
		     echo "Run 'make plan-destroy' and read it first."; exit 1; }
	@echo "This stack holds the account's only audit trail and the only threat detector"; \
	echo "for BOTH stage and production. Destroying it leaves every environment"; \
	echo "running with no threat detection and no audit trail."; \
	echo "The audit bucket has force_destroy = false, so the destroy will fail"; \
	echo "partway while log objects remain. That refusal is a safety net, not a plan."; \
	echo; \
	printf 'Type audit-controls to confirm: '; \
	read -r CONFIRM; \
	if [ "$$CONFIRM" != "audit-controls" ]; then echo "Aborted."; exit 1; fi
	$(TF) apply $(DESTROY_PLAN_FILE)
	@rm -f $(TF_DIR)/$(DESTROY_PLAN_FILE)

# --- Inspection -------------------------------------------------------------

output: ## Show stack outputs
	$(TF) output

# Shows whichever plan is saved, and says which one it is. Both can exist at once —
# nothing stops you planning a create and a teardown before running either — so the
# label matters more than the convenience.
show: ## Show a saved plan in human-readable form (apply plan, or destroy plan)
	@if [ -f $(TF_DIR)/$(PLAN_FILE) ]; then \
		echo "=== $(PLAN_FILE) (apply) ==="; \
		$(TF) show $(PLAN_FILE); \
	fi
	@if [ -f $(TF_DIR)/$(DESTROY_PLAN_FILE) ]; then \
		echo "=== $(DESTROY_PLAN_FILE) (DESTROY) ==="; \
		$(TF) show $(DESTROY_PLAN_FILE); \
	fi
	@test -f $(TF_DIR)/$(PLAN_FILE) -o -f $(TF_DIR)/$(DESTROY_PLAN_FILE) \
		|| { echo "No saved plan. Run 'make plan' or 'make plan-destroy' first."; exit 1; }

state-list: ## List resources tracked in state
	$(TF) state list

whoami: ## Confirm which AWS identity the configured profile resolves to
	$(AWS) sts get-caller-identity

clean: ## Remove both saved plans
	rm -f $(TF_DIR)/$(PLAN_FILE) $(TF_DIR)/$(DESTROY_PLAN_FILE)
