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
  GCP_SA_KEY
  GCP_REGION
  CLOUDRUN_SERVICE_STAGING
  CLOUDRUN_SERVICE_PRODUCTION
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

Set the required values in your shell first, for example:
  export GCP_REGION=us-central1
  export CLOUDRUN_SERVICE_STAGING=appsec-staging
  export CLOUDRUN_SERVICE_PRODUCTION=appsec-prod
  export GCP_SA_KEY='{"type":"service_account",...}'
MSG
  exit 1
fi

echo "Setting staging secrets on $REPO ..."
printf '%s' "$GCP_SA_KEY" | gh secret set GCP_SA_KEY --repo "$REPO" --env staging --body -
printf '%s' "$GCP_REGION" | gh secret set GCP_REGION --repo "$REPO" --env staging --body -
printf '%s' "$CLOUDRUN_SERVICE_STAGING" | gh secret set CLOUDRUN_SERVICE_STAGING --repo "$REPO" --env staging --body -

echo "Setting production secrets on $REPO ..."
printf '%s' "$GCP_SA_KEY" | gh secret set GCP_SA_KEY --repo "$REPO" --env production --body -
printf '%s' "$GCP_REGION" | gh secret set GCP_REGION --repo "$REPO" --env production --body -
printf '%s' "$CLOUDRUN_SERVICE_PRODUCTION" | gh secret set CLOUDRUN_SERVICE_PRODUCTION --repo "$REPO" --env production --body -

echo "Done. Configure production environment protection rules in GitHub UI:"
echo "  Settings -> Environments -> production -> Required reviewers / wait timer"
