# baretrace-audit-controls

Account-level detective controls: GuardDuty, CloudTrail, the audit bucket and the security alert topic. Applied **once per account** (one state, one detector, one trail; `ENVIRONMENT` only names the alert SSM parameter path, `/baretrace/<stage|production>/audit/security-alert-email`), and **before the first production apply** of baretrace-global-infrastructure (GuardDuty allows one detector per account per region).

## Read first
- Project requirements and rules: `../baretrace-global-infrastructure/specs/PROJECT.md` (canonical; wins over anything here).
- Open tasks: `../baretrace-global-infrastructure/specs/work-queue.md` (section D, T20-T22). Do one task at a time, exactly as written.

## Rules that apply here
- Region `eu-central-1` only. One stack covers both stage and production; `ENVIRONMENT` (stage, production) selects `terraform/variables/<environment>.tfvars` and the alert parameter path, nothing else. CI deploys from `stage` only.
- Use `make`, never bare `terraform`. Required targets: `init`, `build`, `plan`, `apply`, `plan-destroy`, `destroy`.
  `make build` is offline and needs no AWS credentials. Never run `apply` or `destroy`.
- Folder structure is fixed: `/lambdas`, `/terraform` (one `.tf` file per AWS service), `/scripts`. See `PROJECT.md`.
- Languages: Terraform, Go, Makefiles. Comments explain why, in the style already in the file.
- Never exclude `kms.amazonaws.com` from CloudTrail management events: they are the audit record of every decryption of personal data.
- `destroy` always needs a typed confirmation. It would delete the account's only audit trail and threat detector.
- No `Environment` tag on anything here: the resources cover both environments.
- Architect reviews every change. Report real command output, not expectations.
