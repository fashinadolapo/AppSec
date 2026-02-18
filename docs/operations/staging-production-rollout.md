# Staging/Production Rollout and Validation Runbook

This runbook operationalizes the AWS deployment checklist for the CI/CD pipeline (ECR + App Runner).

## 1) Configure GitHub Environment secrets

The CI/CD workflow expects the following secrets:

- `staging`: `AWS_ROLE_TO_ASSUME`, `AWS_REGION`, `ECR_REPOSITORY`, `APP_RUNNER_SERVICE_ARN_STAGING`, `APP_BASE_URL_STAGING`
- `production`: `AWS_ROLE_TO_ASSUME`, `AWS_REGION`, `ECR_REPOSITORY`, `APP_RUNNER_SERVICE_ARN_PRODUCTION`, `APP_BASE_URL_PRODUCTION`

Use helper script:

```bash
export AWS_ROLE_TO_ASSUME='arn:aws:iam::<account-id>:role/github-actions-deploy'
export AWS_REGION='us-east-1'
export ECR_REPOSITORY='appsec-fusion-dashboard'
export APP_RUNNER_SERVICE_ARN_STAGING='arn:aws:apprunner:...:service/appsec-staging/...'
export APP_BASE_URL_STAGING='https://staging.example.com'
export APP_RUNNER_SERVICE_ARN_PRODUCTION='arn:aws:apprunner:...:service/appsec-production/...'
export APP_BASE_URL_PRODUCTION='https://app.example.com'
./scripts/configure_github_env_secrets.sh <owner/repo>
```

## 2) Enable production gate policy

In GitHub repository settings:

1. `Settings -> Environments -> production`
2. Add `Required reviewers`
3. Optionally add wait timer and branch restrictions

This ensures production deployment requires explicit approval.

## 3) Trigger and monitor deployment

Use either:

- push to `main`, or
- GitHub Actions `workflow_dispatch`

Watch `.github/workflows/ci-cd.yml` jobs:

1. `test-and-security`
2. `build-image`
3. `deploy-staging`
4. `deploy-production` (after approval gate)

## 4) Validate staging service

Run automated smoke + scoped-ingest checks:

```bash
export INGEST_API_KEY='<staging-ingest-key>'
./scripts/validate_staging.sh <staging-app-url>
```

This validates:

- `/healthz` and `/readyz`
- scanner-family ingest with scoped `project_id`
- MCP scoped ingest

Manual OIDC/session checks (required when staging runs OIDC):

- `GET /auth/login` -> authenticate through your IdP
- confirm `GET /api/me`
- verify websocket behavior:
  - logged-in viewer can keep `/ws`
  - unauthenticated session is rejected

## 5) Verify project isolation and admin deletion

From authenticated session, verify:

- `GET /api/findings?project_id=team-a`
- `GET /api/findings?project_id=team-b`
- `GET /api/ai/insights?project_id=team-a`
- `DELETE /api/admin/findings?project_id=team-a`

Expected: team-a operations only affect team-a findings.

## 6) Approve production deploy and re-run probes

After staging is clean and validated:

1. approve the production environment in GitHub Actions
2. verify production `/healthz` and `/readyz`

## 7) Start testing phase plan (SAST/DAST/chaos)

Recommended first pass:

1. ingest representative payloads from each scanner connector
2. run DAST against staging app and confirm ingestion
3. enable chaos mode (`latency_ms`, `error_percent`) briefly
4. record baseline error rate and MTTR

Capture results in your incident/testing log for trend tracking.
