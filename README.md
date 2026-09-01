# WorkOSBearerAuth

Bearer-token authentication for Vapor 4 apps against a [WorkOS AuthKit](https://workos.com/docs/authkit)
issuer — one middleware, attached once, that protects REST and any other HTTP-based
interface (e.g. an MCP server mounted on the same `Application`) behind the same rule.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [1. Configure bearer auth](#1-configure-bearer-auth)
  - [2. Read the authenticated identity](#2-read-the-authenticated-identity)
- [Behavior](#behavior)
  - [The four configuration cases](#the-four-configuration-cases)
  - [Exempt paths](#exempt-paths)
  - [Discovery route (RFC 9728)](#discovery-route-rfc-9728)
  - [401 vs. 503](#401-vs-503)
  - [JWKS refresh](#jwks-refresh)
- [Design notes](#design-notes)
- [Testing](#testing)

## Requirements

- Swift 6 (strict concurrency, `swiftLanguageModes: [.v6]`)
- macOS 13+ / Linux
- Vapor 4.115+

## Installation

```swift
.package(url: "https://github.com/manugs8/WorkOSBearerAuth.git", from: "0.1.0")
```

Add `"WorkOSBearerAuth"` as a dependency of the target that calls `configure(_:)` on your
`Application`.

## Usage

### 1. Configure bearer auth

Call `configureBearerAuth(_:environment:)` once, during your app's own `configure(_:)`,
after `app.client` is available. It reads nothing from the process environment itself —
your app reads its own environment variables (however it names them) and passes the
values in:

```swift
import WorkOSBearerAuth

func configure(_ app: Application) throws {
    // ...

    try configureBearerAuth(
        app,
        environment: BearerAuthEnvironmentConfig(
            authDisabled: Environment.get("AUTH_DISABLED").flatMap(Bool.init) == true,
            workOSIssuer: Environment.get("WORKOS_ISSUER"),
            workOSResourceIndicatorsRaw: Environment.get("WORKOS_RESOURCE_INDICATORS")
        )
    )
}
```

`workOSResourceIndicatorsRaw` is WorkOS's own comma-separated format for
`WORKOS_RESOURCE_INDICATORS` (e.g. `"https://api.example.com/mcp,http://localhost:8080/mcp"`)
— splitting, trimming, and validating it is this library's job, not the caller's.

### 2. Read the authenticated identity

Once a request passes the middleware, its validated claims are available on the request:

```swift
app.get("whoami") { req in
    req.authenticatedClaims?.sub.value ?? "anonymous"
}
```

`nil` when auth is disabled or the route is exempt (see below).

## Behavior

### The four configuration cases

`configureBearerAuth` branches on `app.environment` and `environment`:

1. **`.testing`** — unconditionally skipped, regardless of `environment`. Your own test
   suite can still exercise a route's auth requirement by attaching a second
   `BearerAuthMiddleware`-backed setup manually if it needs to (this library's own test
   suite does exactly that against a throwaway `Application` — see
   `BearerAuthMiddlewareTests`).
2. **`environment.authDisabled` in `.production`** — throws. A test-only escape hatch must
   never silently reach a real deployment.
3. **`environment.authDisabled` outside production, or neither `authDisabled` nor
   `workOSIssuer`/`workOSResourceIndicatorsRaw` set** — authentication is disabled, with a
   logged warning so it's never silent.
4. **`workOSIssuer`/`workOSResourceIndicatorsRaw` set** — real JWT/JWKS validation is
   enforced, including in production, where it's required (missing config throws).

### Exempt paths

`/health`, `/docs`, `/openapi.yaml`, and `/.well-known/oauth-protected-resource` are never
authenticated — the first three so platform healthchecks and documentation stay reachable,
the last one because a client has to be able to fetch it *before* it has a token.

### Discovery route (RFC 9728)

`configureBearerAuth` also registers `GET /.well-known/oauth-protected-resource`, so a
client that gets a 401 knows which authorization server (WorkOS) to redirect the user to,
without a human pasting a token in by hand.

### 401 vs. 503

A rejected token (missing, malformed, wrong issuer/audience/algorithm, expired, bad
signature) is a 401. A JWKS fetch failure (WorkOS or the network unreachable) is a 503 —
the token itself was never evaluated, so claiming it's invalid would be wrong.

### JWKS refresh

Keys are cached and refreshed on a timer, plus on demand: a token whose `kid` isn't
recognized by the current cache triggers exactly one forced refresh (a plausible key
rotation), not a refresh per rejected request — that would let an attacker cheaply trigger
repeated remote fetches just by sending garbage tokens. Concurrent refreshes are coalesced
into a single in-flight fetch.

## Design notes

- **`Request.storage`, not a `@TaskLocal`.** A task-local set inside `BearerAuthMiddleware`
  does not reliably reach a route handler in Vapor's current architecture: `AsyncMiddleware`
  and the router both bridge from async back to `EventLoopFuture` via `Task { ... }` at more
  than one point between a middleware and the route it dispatches to, and that bridging does
  not preserve task-local values — verified empirically. `Request` is a reference type
  threaded through that whole chain regardless of which `Task` ends up running which part of
  it, so `request.storage` is not affected by that problem.
- **Configuration is a struct, not `Environment.get(...)` calls inside this library.**
  Keeping the actual environment-variable reads in the consumer's own `configure.swift`
  means this library is never hardcoded to a specific set of variable *names*, and its own
  configuration branching (the four cases above) can be tested by constructing different
  `BearerAuthEnvironmentConfig` values directly, without mutating real process environment
  variables per test case.
- **Minimal public surface.** Only `configureBearerAuth`, `BearerAuthEnvironmentConfig`,
  and `WorkOSClaims` (as the type of `Request.authenticatedClaims`) are public. Everything
  else this library uses internally (`BearerTokenVerifier`, `BearerAuthMiddleware`,
  `RemoteJWKS`, `JWKSSource`, the internal `ConfigurationError`) stays module-internal — no
  consumer needs to construct any of them directly.

## Testing

This library's own test suite (`swift test`) covers both pieces end-to-end against a
throwaway `Application` and a local, non-network `JWTKeyCollection` — no real WorkOS
credentials or network access needed:

- `BearerTokenVerifierTests` — algorithm/issuer/audience/expiry/not-before/`kid` policy.
- `BearerAuthMiddlewareTests` — wiring: exempt vs. protected paths, the
  `WWW-Authenticate` challenge, JWKS refresh-on-unrecognized-`kid`, 401 vs. 503, and that a
  single globally-attached instance covers every route regardless of how it was mounted.

A consuming app generally doesn't need to re-test any of this — it only needs to call
`configureBearerAuth` correctly and, if it wants to, assert that its own routes are reached
through it (a live integration test against a real request is enough; there's no need to
reconstruct this library's internals to do that).
