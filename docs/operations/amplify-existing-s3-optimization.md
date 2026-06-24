# Amplify Existing S3 Bucket and Deployment Optimization Notes

Use this note when wiring AWS Amplify Hosting to an already-created S3 bucket or when deciding whether Amplify should create storage resources for the AppSec dashboard deployment.

## Should Amplify create a new S3 bucket?

No. Prefer reusing the existing environment bucket when the bucket is already governed, encrypted, tagged, and covered by lifecycle and backup controls.

Recommended pattern:

- Keep one pre-provisioned artifact/static-assets bucket per environment, such as `appsec-staging-artifacts` and `appsec-production-artifacts`.
- Point Amplify build or deployment steps at that existing bucket instead of adding a new Amplify-managed storage resource.
- Do not run `amplify add storage` unless the application needs a new user-facing storage backend.
- Keep bucket ownership in infrastructure-as-code outside Amplify so encryption, public-access blocks, versioning, lifecycle, logging, and tags remain consistent.

Amplify should only create a bucket when there is no existing compliant bucket or when a deliberately isolated bucket is required for a new workload boundary.

## Existing S3 bucket baseline controls

Before using the bucket with Amplify, confirm the bucket has these controls enabled:

- Block Public Access enabled at bucket level.
- SSE-S3 or SSE-KMS encryption enabled by default.
- Versioning enabled for production artifacts.
- Lifecycle rules to expire old build artifacts and noncurrent object versions.
- Server access logging or CloudTrail data events enabled for production-sensitive artifacts.
- Least-privilege IAM allowing Amplify or GitHub Actions to read/write only the expected prefixes.
- Environment-specific prefixes, for example `amplify/staging/` and `amplify/production/`, if one shared bucket is unavoidable.

## Additional optimization checklist

- Reuse the existing ECR repository and App Runner services; avoid creating parallel services for each deployment unless blue/green isolation is required.
- Keep immutable image tags such as `sha-<commit-sha>` and avoid `latest` for promotion paths.
- Add lifecycle cleanup for ECR images so old unreferenced images do not accumulate indefinitely.
- Cache Python dependencies and Docker layers in CI to reduce build time.
- Run smoke checks against `/healthz` and `/readyz` immediately after each deployment.
- Keep production behind a GitHub Environment approval gate.
- Scope IAM roles per environment, with staging unable to update production resources.
- Store secrets in GitHub Environment secrets or AWS Secrets Manager; do not bake them into Amplify, Docker images, or static assets.
- Prefer CloudFront or Amplify-managed CDN caching for static assets with long cache headers and content-hashed filenames.
- Use short cache TTLs for HTML entry points so users receive new deployments quickly.
- Configure budgets and cost alerts for Amplify, S3, ECR, App Runner, CloudWatch Logs, and data transfer.

## Decision summary

Use the existing S3 bucket by default. Create a new bucket only when governance, isolation, compliance, or blast-radius requirements explicitly justify it.
