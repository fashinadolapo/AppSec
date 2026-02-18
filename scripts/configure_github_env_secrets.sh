#!/usr/bin/env bash
set -euo pipefail

if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR: GitHub CLI (gh) is required." >&2
  exit 1
fi

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <owner/repo>" >&2
  echo "Example: $0 my-org/appsec-fusion-dashboard" >&2
  exit 1
fi

REPO="$1"

required_vars=(
  AWS_ROLE_TO_ASSUME
  AWS_REGION
  ECR_REPOSITORY
  APP_RUNNER_SERVICE_ARN_STAGING
  APP_BASE_URL_STAGING
  APP_RUNNER_SERVICE_ARN_PRODUCTION
  APP_BASE_URL_PRODUCTION
)

missing=0
for var in "${required_vars[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "ERROR: Missing env var: $var" >&2
    missing=1
  fi
done

if [[ $missing -eq 1 ]]; then
  cat >&2 <<MSG

Set required values in your shell first, for example:
  export AWS_ROLE_TO_ASSUME='arn:aws:iam::<account-id>:role/github-actions-deploy'
  export AWS_REGION='us-east-1'
  export ECR_REPOSITORY='appsec-fusion-dashboard'
  export APP_RUNNER_SERVICE_ARN_STAGING='arn:aws:apprunner:...:service/appsec-staging/...'
  export APP_BASE_URL_STAGING='https://staging.example.com'
  export APP_RUNNER_SERVICE_ARN_PRODUCTION='arn:aws:apprunner:...:service/appsec-production/...'
  export APP_BASE_URL_PRODUCTION='https://app.example.com'
MSG
  exit 1
fi

echo "Setting staging secrets on $REPO ..."
printf '%s' "$AWS_ROLE_TO_ASSUME" | gh secret set AWS_ROLE_TO_ASSUME --repo "$REPO" --env staging --body -
printf '%s' "$AWS_REGION" | gh secret set AWS_REGION --repo "$REPO" --env staging --body -
printf '%s' "$ECR_REPOSITORY" | gh secret set ECR_REPOSITORY --repo "$REPO" --env staging --body -
printf '%s' "$APP_RUNNER_SERVICE_ARN_STAGING" | gh secret set APP_RUNNER_SERVICE_ARN_STAGING --repo "$REPO" --env staging --body -
printf '%s' "$APP_BASE_URL_STAGING" | gh secret set APP_BASE_URL_STAGING --repo "$REPO" --env staging --body -

echo "Setting production secrets on $REPO ..."
printf '%s' "$AWS_ROLE_TO_ASSUME" | gh secret set AWS_ROLE_TO_ASSUME --repo "$REPO" --env production --body -
printf '%s' "$AWS_REGION" | gh secret set AWS_REGION --repo "$REPO" --env production --body -
printf '%s' "$ECR_REPOSITORY" | gh secret set ECR_REPOSITORY --repo "$REPO" --env production --body -
printf '%s' "$APP_RUNNER_SERVICE_ARN_PRODUCTION" | gh secret set APP_RUNNER_SERVICE_ARN_PRODUCTION --repo "$REPO" --env production --body -
printf '%s' "$APP_BASE_URL_PRODUCTION" | gh secret set APP_BASE_URL_PRODUCTION --repo "$REPO" --env production --body -

echo "Done. Configure production environment protection rules in GitHub UI:"
echo "  Settings -> Environments -> production -> Required reviewers / wait timer"
