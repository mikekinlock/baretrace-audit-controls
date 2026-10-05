#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Build pipeline: format-check, validate, and compile all Go code.
#
# Uses a SEPARATE Terraform data directory so that `terraform init -backend=false`
# never reconfigures the real S3 backend. A `-backend=false` init in the default
# .terraform/ directory would overwrite the backend block that `make init` set up,
# forcing a re-init before the next plan or apply. Isolating the data dir keeps
# the real backend untouched.
# ---------------------------------------------------------------------------
set -euo pipefail

# Always run from the repository root, so the script works when called from elsewhere.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Separate data dir: a -backend=false init would otherwise reconfigure the S3
# backend that `make init` established, breaking subsequent plan/apply.
export TF_DATA_DIR="$PWD/terraform/.terraform-build"

echo "==> terraform init (backend=false)"
terraform -chdir=terraform init -backend=false -input=false

echo "==> terraform fmt -check"
terraform -chdir=terraform fmt -check -recursive

echo "==> terraform validate"
terraform -chdir=terraform validate

# --- Go builds (only if the directories exist) ------------------------------

# Lambda handlers: compile each lambdas/ subdirectory as a linux/arm64 binary.
# There are no lambdas yet, so this is a no-op today.
if [ -d lambdas ]; then
	for dir in lambdas/*/; do
		[ -d "$dir" ] || continue
		name="$(basename "$dir")"
		echo "==> go build lambda: $name"
		(
			cd "$dir"
			GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
				go build -tags lambda.norpc -o "../../build/$name/bootstrap" .
		)
	done
fi

# Plan checker: vet, test, and build the Go tool in scripts/plancheck.
if [ -f scripts/plancheck/go.mod ]; then
	echo "==> go vet + test + build: scripts/plancheck"
	(
		cd scripts/plancheck
		go vet ./...
		go test ./...
		go build ./...
	)
fi

echo "==> build complete"
