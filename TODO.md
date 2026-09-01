# Future Improvements (v1.0.x)

This document tracks architectural considerations and enhancements for future major or minor releases.

### 1. Configurable Exempt Paths
Currently, `BearerAuthMiddleware` hardcodes `exemptPaths` to exactly `/health`, `/docs`, and `/openapi.yaml`. While this covers common Vapor setups, consumers building generic APIs might have metrics on `/metrics`, webhooks on `/api/webhooks`, or another documentation path like `/swagger`.
- **Proposal:** Expose an `exemptPaths: Set<String>` option in `BearerAuthEnvironmentConfig` to allow consumers to override or extend the list of unprotected paths.

### 2. Multi-Resource Discovery
When passing multiple comma-separated `WORKOS_RESOURCE_INDICATORS`, they are currently treated sequentially to resolve the primary domain, and only the first indicator gets its `/.well-known/oauth-protected-resource` discovery endpoint registered. For alternative audiences behind a single API gateway, this is correct.
- **Proposal:** If consumers genuinely want to protect multiple disjoint API resources in a single Application, we could iterate over the parsed indicators and register independent `discoveryPathComponents` and endpoints for each unique base path.

### 3. Exponential Backoff for JWKS Fetching
The `RemoteJWKS` implementation employs a rigid 30-second `forcedRefreshCooldown` to prevent thundering herd behavior against the WorkOS JWKS endpoint during outages or unrecognized token attacks.
- **Proposal:** While sufficient for early stages, moving to an exponential backoff strategy (e.g. 2s, 4s, 8s, 16s, 30s) with Jitter will provide better resilience and quicker recovery for legitimate bursts immediately after an outage.

