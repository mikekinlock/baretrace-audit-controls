#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Terraform init wrapper.
#
# Builds the four -backend-config flags from environment variables so the
# Makefile does not need to interpolate them into a shell string. The Makefile
# exports STATE_BUCKET, STATE_KEY, STATE_REGION, and AWS_PROFILE; this script
# validates that the first three are set and passes them to `terraform init`, plus the
# profile when AWS_PROFILE is non-empty.
#
# Usage: scripts/init.sh <init|init-upgrade|init-migrate>
# ---------------------------------------------------------------------------
set -euo pipefail

# Always run from the repository root, so the script works when called from elsewhere.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

usage() {
	echo "usage: $(basename "$0") <init|init-upgrade|init-migrate>" >&2
	exit 2
}

if [ $# -ne 1 ]; then
	usage
fi

MODE="$1"
EXTRA_FLAG=""

case "$MODE" in
	init)
		EXTRA_FLAG=""
		;;
	init-upgrade)
		EXTRA_FLAG="-upgrade"
		;;
	init-migrate)
		EXTRA_FLAG="-migrate-state"
		;;
	*)
		usage
		;;
esac

# Validate that every required variable is set; ${VAR:?msg} prints the message
# and exits non-zero if the variable is unset or empty.
BUCKET="${STATE_BUCKET:?STATE_BUCKET is not set}"
KEY="${STATE_KEY:?STATE_KEY is not set}"
REGION="${STATE_REGION:?STATE_REGION is not set}"

# An empty AWS_PROFILE (CI: `make init AWS_PROFILE=`) means the credentials come
# from the environment (GitHub OIDC), so no profile is passed to the backend.
PROFILE_FLAG=()
if [ -n "${AWS_PROFILE:-}" ]; then
	PROFILE_FLAG=(-backend-config="profile=${AWS_PROFILE}")
fi

echo "==> terraform init (mode: $MODE)"
terraform -chdir=terraform init -input=false $EXTRA_FLAG \
	-backend-config="bucket=${BUCKET}" \
	-backend-config="key=${KEY}" \
	-backend-config="region=${REGION}" \
	"${PROFILE_FLAG[@]}"

echo "==> init complete"
