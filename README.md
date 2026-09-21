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
  - [The three configuration cases](#the-three-configuration-cases)
  - [Exempt paths](#exempt-paths)
  - [Discovery route (RFC 9728)](#discovery-route-rfc-9728)
  - [401 vs. 503](#401-vs-503)
  - [JWKS refresh](#jwks-refresh)
- [Signing test tokens for your own E2E suite](#signing-test-tokens-for-your-own-e2e-suite)
- [Exercising real auth in an in-process E2E suite](#exercising-real-auth-in-an-in-process-e2e-suite)
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

    let bearerAuthEnvironment: BearerAuthEnvironmentConfig
    if let issuer = Environment.get("WORKOS_ISSUER"), let indicators = Environment.get("WORKOS_RESOURCE_INDICATORS") {
        bearerAuthEnvironment = .workOS(issuer: issuer, resourceIndicatorsRaw: indicators)
    } else if let port = Environment.get("AUTHMOCK_PORT").flatMap(Int.init), let indicators = Environment.get("WORKOS_RESOURCE_INDICATORS") {
        bearerAuthEnvironment = .local(port: port, resourceIndicatorsRaw: indicators)
    } else {
        bearerAuthEnvironment = .disabled
    }
    try configureBearerAuth(app, environment: bearerAuthEnvironment)
}
```

`resourceIndicatorsRaw` is WorkOS's own comma-separated format for
`WORKOS_RESOURCE_INDICATORS` (e.g. `"https://api.example.com/mcp,https://api.example.com/rest"`)
— splitting, trimming, and validating it is this library's job, not the caller's, for both
cases below.

`BearerAuthEnvironmentConfig` is an `enum`, not a struct with optional fields, so an
impossible combination (a real WorkOS issuer that's also somehow "loopback", or a loopback
config with no way to tell it's one) can't even be constructed:

- **`.workOS(issuer:resourceIndicatorsRaw:)`** — a real WorkOS AuthKit issuer. Must be
  `https://`, no exceptions. The only case `configureBearerAuth` accepts in `.production`.
- **`.local(port:resourceIndicatorsRaw:)`** — a real auth-server mock (e.g. `AuthMock`)
  running on the same machine, so token verification still runs for real instead of
  disabling auth outright. Only takes a port, not an issuer string: the host is always
  `http://127.0.0.1`, never a caller-supplied value, so there's nothing to parse or
  validate to confirm it's actually loopback. Rejected in `.production`
  (`localConfigInProduction`) — that restriction lives in the library itself, not just in
  which environment variables happen to be set in a deployment config.
- **`.disabled`** — no WorkOS configuration. Fine outside production (a warning is logged);
  refused in `.production` (`missingWorkOSEnvironment`).

Resource indicators are unaffected by which case you use — always required to be `https://`.

### 2. Read the authenticated identity

Once a request passes the middleware, its validated claims are available on the request:

```swift
app.get("whoami") { req in
    req.authenticatedClaims?.sub.value ?? "anonymous"
}
```

`nil` when auth is disabled or the route is exempt (see below).

## Behavior

### The three configuration cases

`configureBearerAuth` branches on `app.environment` and `environment`:

1. **`.testing`** — skipped for `.disabled` and `.workOS`, regardless of which credentials
   `environment` carries. Your own test suite can still exercise a route's auth requirement
   by attaching a second `BearerAuthMiddleware`-backed setup manually if it needs to (this
   library's own test suite does exactly that against a throwaway `Application` — see
   `BearerAuthMiddlewareTests`). **`.local` is the exception**: it's never skipped under
   `.testing`, because by construction it only ever talks to a loopback mock, never to
   WorkOS's real JWKS endpoint — see [Exercising real auth in an in-process E2E
   suite](#exercising-real-auth-in-an-in-process-e2e-suite) below.
2. **`.disabled`** — in `.production`, throws (there's no escape hatch to silently disable
   auth on a real deployment); outside production, authentication is disabled, with a
   logged warning so it's never silent.
3. **`.workOS`/`.local`** — real JWT/JWKS validation is enforced. `.workOS` works in any
   environment, including production, where it's required (`.disabled` throws, per case 2).
   `.local` works in any environment *except* production, which it refuses outright
   (`localConfigInProduction`) — only `.workOS` is allowed there.

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

## Signing test tokens for your own E2E suite

If your app's E2E suite talks to a real, already-running server over the network (rather
than an in-process `Application`), it needs a bearer token the server will accept exactly
as it would a genuine WorkOS-issued one — typically paired with a fake Authorization
Server that serves the matching public key as a JWKS document, so the server under test
verifies the token through its normal `RemoteJWKS`/`BearerAuthMiddleware` path, no
test-only bypass involved.

`WorkOSBearerAuthTesting` is a separate product for exactly this — deliberately
dependency-light (`JWTKit` + `Foundation`, no `Vapor`), since a test-support module has no
reason to link the server-side stack:

```swift
.package(url: "https://github.com/manugs8/WorkOSBearerAuth.git", from: "0.1.0")

// in the target that needs it:
.product(name: "WorkOSBearerAuthTesting", package: "WorkOSBearerAuth")
```

```swift
import WorkOSBearerAuthTesting

let signer = WorkOSTestTokenSigner(
    issuer: ProcessInfo.processInfo.environment["E2E_AUTH_TEST_ISSUER"] ?? "http://fake-authkit",
    resource: ProcessInfo.processInfo.environment["E2E_AUTH_TEST_RESOURCE"] ?? "http://localhost:8080",
    privateKeyPEM: ProcessInfo.processInfo.environment["E2E_AUTH_TEST_PRIVATE_KEY"]
)

let token = try await signer.validToken()      // nil if privateKeyPEM is nil
let expired = try await signer.expiredToken()  // exp already in the past
```

As with `BearerAuthEnvironmentConfig`, `WorkOSTestTokenSigner` takes every value as a
parameter rather than reading the environment itself — your own E2E setup decides where
`issuer`/`resource`/the private key come from and under what variable names.

## Exercising real auth in an in-process E2E suite

The section above covers a suite that talks to an already-running, separately-deployed
server — the heavier CI-style setup. `BearerAuthEnvironmentConfig.local` exists for the
lighter alternative: an E2E suite that boots its own `Application` in-process (typically via
`Application.make(.testing)`, the same way a Fluent-backed suite already boots an ephemeral
database for itself) and wants genuine bearer-auth verification — missing/invalid/expired/valid
token scenarios — without reaching for a genuinely-running server just to get that coverage.

`.local` is the one `BearerAuthEnvironmentConfig` case that registers the real
`BearerAuthMiddleware` even when `app.environment == .testing`: by construction it only ever
verifies against `http://127.0.0.1:<port>`, never WorkOS's real JWKS endpoint, so the
real-network rationale that makes `.disabled`/`.workOS` skip under `.testing` doesn't apply
to it (see [The three configuration cases](#the-three-configuration-cases)).

The pattern: boot a real, loopback-only OAuth mock (e.g.
[`AuthMock`](https://github.com/manugs8/AuthMock), which serves both a token endpoint and
`/oauth2/jwks`) on an ephemeral port alongside your `Application`, point `.local` at that
port, and tear the mock process down the same way you already tear down an ephemeral test
database — before or after the `Application` itself, whichever your own E2E harness does for
its other ephemeral resources.

```swift
import WorkOSBearerAuth
import Vapor

func withE2EServer(
    authMockPort: Int, resourceIndicator: String, test: (Application) async throws -> Void
) async throws {
    let app = try await Application.make(.testing)
    do {
        try configureBearerAuth(
            app,
            environment: .local(port: authMockPort, resourceIndicatorsRaw: resourceIndicator)
        )
        // ... your app's own configure(_:), migrations, etc.
        try await test(app)
    } catch {
        try? await app.asyncShutdown()
        throw error
    }
    try await app.asyncShutdown()
}
```

Inside `test`, drive requests through `app.testing()` as usual: a request with no
`Authorization` header exercises the missing-token path, a token fetched from the mock's
token endpoint exercises the valid-token path, and a token with a tampered signature or an
`exp` in the past exercises the invalid/expired paths — all against the real
`BearerAuthMiddleware`/`BearerTokenVerifier`/`RemoteJWKS` chain, no test-only bypass
involved.

## Design notes

- **`Request.storage`, not a `@TaskLocal`.** A task-local set inside `BearerAuthMiddleware`
  does not reliably reach a route handler in Vapor's current architecture: `AsyncMiddleware`
  and the router both bridge from async back to `EventLoopFuture` via `Task { ... }` at more
  than one point between a middleware and the route it dispatches to, and that bridging does
  not preserve task-local values — verified empirically. `Request` is a reference type
  threaded through that whole chain regardless of which `Task` ends up running which part of
  it, so `request.storage` is not affected by that problem.
- **Configuration is an `enum`, not `Environment.get(...)` calls inside this library.**
  Keeping the actual environment-variable reads in the consumer's own `configure.swift`
  means this library is never hardcoded to a specific set of variable *names*, and its own
  configuration branching (the cases above) can be tested by constructing different
  `BearerAuthEnvironmentConfig` values directly, without mutating real process environment
  variables per test case. An `enum` over a struct with optional fields, specifically, so
  each case only carries the data that configuration actually needs — no field that's
  meaningful for `.workOS` but meaningless for `.local`, or vice versa.
- **Minimal public surface.** In `WorkOSBearerAuth`, only `configureBearerAuth`,
  `BearerAuthEnvironmentConfig`, and `WorkOSClaims` (as the type of
  `Request.authenticatedClaims`) are public. Everything else this library uses internally
  (`BearerTokenVerifier`, `BearerAuthMiddleware`, `RemoteJWKS`, `JWKSSource`, the internal
  `ConfigurationError`) stays module-internal — no consumer needs to construct any of them
  directly. `WorkOSBearerAuthTesting` is smaller still: just `WorkOSTestTokenSigner`.
- **Two products, not one.** `WorkOSBearerAuthTesting` depends on `JWTKit` alone; folding
  it into `WorkOSBearerAuth` would force anything that only wants to sign a test token to
  also link `Vapor` and everything it pulls in.

## Testing

This library's own test suite (`swift test`) covers both pieces end-to-end against a
throwaway `Application` and a local, non-network `JWTKeyCollection` — no real WorkOS
credentials or network access needed:

- `BearerTokenVerifierTests` — algorithm/issuer/audience/expiry/not-before/`kid` policy.
- `BearerAuthMiddlewareTests` — wiring: exempt vs. protected paths, the
  `WWW-Authenticate` challenge, JWKS refresh-on-unrecognized-`kid`, 401 vs. 503, and that a
  single globally-attached instance covers every route regardless of how it was mounted.
- `ConfigureTests` — the branching in `configureBearerAuth` itself, including that the
  `.testing` short-circuit covers `.disabled`/`.workOS` but not `.local`, and that `.local`
  under `.testing` doesn't just register the discovery route but actually enforces
  authentication on other routes too.

A consuming app generally doesn't need to re-test any of this — it only needs to call
`configureBearerAuth` correctly and, if it wants to, assert that its own routes are reached
through it (a live integration test against a real request is enough; there's no need to
reconstruct this library's internals to do that).
