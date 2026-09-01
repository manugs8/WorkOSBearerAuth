import Vapor

/// The environment-derived inputs `configureBearerAuth` needs. Reading the actual
/// `Environment.get(...)` calls is left to the consuming application's own
/// `configure.swift` — this type only carries the raw values — so that:
///
/// 1. This library never hardcodes a specific set of environment variable *names*; a
///    consumer is free to source these values however it wants (env vars under any
///    name, a secrets manager, etc.).
/// 2. `configureBearerAuth`'s own branching logic (below) can be exercised in tests by
///    constructing different `BearerAuthEnvironmentConfig` values directly, instead of
///    mutating real process environment variables per test case.
///
/// `workOSResourceIndicatorsRaw` stays a single comma-separated string (WorkOS's own
/// format for `WORKOS_RESOURCE_INDICATORS`) rather than already being split into a
/// `Set<String>` — the splitting/trimming/empty-check is WorkOS-format parsing, not
/// project-specific, so it stays this library's job, not the consumer's.
public struct BearerAuthEnvironmentConfig: Sendable {
    public let authDisabled: Bool
    public let workOSIssuer: String?
    public let workOSResourceIndicatorsRaw: String?

    public init(authDisabled: Bool, workOSIssuer: String?, workOSResourceIndicatorsRaw: String?) {
        self.authDisabled = authDisabled
        self.workOSIssuer = workOSIssuer
        self.workOSResourceIndicatorsRaw = workOSResourceIndicatorsRaw
    }
}

/// Registers `BearerAuthMiddleware` globally (so REST and `/mcp` share one authentication
/// path) and the RFC 9728 OAuth Protected Resource Metadata discovery route it needs.
///
/// Four cases, driven by `environment`:
/// 1. `.testing` — unconditionally skipped regardless of what `environment` carries. A
///    consumer's own `.env.local` may carry real WorkOS staging credentials for `swift
///    run`, so an env-var check alone isn't enough to keep `swift test` free of a live
///    network dependency on WorkOS's JWKS endpoint. `BearerAuthMiddleware` itself is
///    still exercised end-to-end in this library's own tests — see
///    `BearerAuthMiddlewareTests`, which wires it up with a local, non-network
///    `JWKSSource` instead of the real `RemoteJWKS`.
/// 2. `environment.authDisabled` in production — refuses to boot. A test-only escape
///    hatch must never silently reach a real deployment.
/// 3. `environment.authDisabled` outside production, or neither `authDisabled` nor
///    `workOSIssuer`/`workOSResourceIndicatorsRaw` set — authentication is disabled with
///    a loud warning instead of every route silently being reachable with no signal.
/// 4. `workOSIssuer`/`workOSResourceIndicatorsRaw` set — real JWT/JWKS validation is
///    enforced, including in production, where it's required (missing config throws).
///
/// - Throws: `authDisabledInProduction`, `missingWorkOSEnvironment`, or
///   `emptyResourceIndicators` (all private to this module — a consumer that wants to
///   log or propagate the failure doesn't need to pattern-match the specific case).
public func configureBearerAuth(_ app: Application, environment: BearerAuthEnvironmentConfig) throws {
    guard app.environment != .testing else {
        app.logger.warning("Running in .testing — skipping bearer auth regardless of WorkOS environment.")
        return
    }

    if environment.authDisabled {
        guard app.environment != .production else {
            throw ConfigurationError.authDisabledInProduction
        }
        app.logger.warning("Bearer auth disabled — REST and MCP requests are not authenticated.")
        return
    }

    guard
        let issuer = environment.workOSIssuer,
        let resourceIndicatorsRaw = environment.workOSResourceIndicatorsRaw
    else {
        guard app.environment != .production else {
            throw ConfigurationError.missingWorkOSEnvironment
        }
        app.logger.warning(
            """
            WorkOS issuer/resource indicators are not set and auth is not explicitly \
            disabled — treating authentication as disabled for this non-production run. \
            Set both WorkOS values, or disable auth explicitly, to silence this warning.
            """
        )
        return
    }
    
    guard let issuerURL = URL(string: issuer), issuerURL.scheme != nil, issuerURL.host != nil else {
        throw ConfigurationError.invalidIssuer
    }

    let resourceIndicators = Set(
        resourceIndicatorsRaw.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    )
    guard !resourceIndicators.isEmpty else {
        throw ConfigurationError.emptyResourceIndicators
    }
    
    for resourceIndicator in resourceIndicators {
        guard let url = URL(string: resourceIndicator), url.scheme != nil, url.host != nil else {
            throw ConfigurationError.invalidResourceIndicator
        }
    }

    let primaryResourceIndicator = resourceIndicators.first!

    let jwksURL = URI(string: issuer + "/oauth2/jwks")
    let remoteJWKS = RemoteJWKS(jwksURL: jwksURL, client: app.client)
    let verifier = makeProductionBearerTokenVerifier(issuer: issuer, audiences: resourceIndicators)
    let resourceMetadataURL = publicBaseURL(of: primaryResourceIndicator) + "/.well-known/oauth-protected-resource"

    app.middleware.use(
        BearerAuthMiddleware(jwksSource: remoteJWKS, verifier: verifier, resourceMetadataURL: resourceMetadataURL)
    )

    let metadata = OAuthProtectedResourceMetadata(
        resource: primaryResourceIndicator,
        authorizationServers: [issuer],
        bearerMethodsSupported: ["header"]
    )
    app.get(".well-known", "oauth-protected-resource") { _ in metadata }

    app.logger.info("Bearer authentication enabled — issuer: \(issuer), resources: \(resourceIndicators)")
}

/// Builds the production `BearerTokenVerifier` — pulled out of `configureBearerAuth` so a
/// test can assert its policy (algorithm, `kid` requirement) directly, without needing to
/// fight `configureBearerAuth`'s own `.testing` short-circuit. Passes neither
/// `allowedAlgorithms` nor `requiresKeyID` on purpose — production always gets
/// `BearerTokenVerifier`'s own defaults (RS256-only, `kid` required). If this function
/// ever grows those parameters, `productionVerifierUsesDefaultPolicy` in
/// `BearerTokenVerifierTests` should fail loudly rather than silently loosen the policy.
func makeProductionBearerTokenVerifier(issuer: String, audiences: Set<String>) -> BearerTokenVerifier {
    BearerTokenVerifier(issuer: issuer, audiences: audiences)
}

/// `GET /.well-known/oauth-protected-resource` — OAuth 2.0 Protected Resource Metadata
/// (RFC 9728), so an MCP client that gets a 401 from `/mcp` can discover which
/// Authorization Server (WorkOS) to redirect the user to, without a human having to paste
/// in a token by hand.
struct OAuthProtectedResourceMetadata: Content {
    let resource: String
    let authorizationServers: [String]
    let bearerMethodsSupported: [String]

    enum CodingKeys: String, CodingKey {
        case resource
        case authorizationServers = "authorization_servers"
        case bearerMethodsSupported = "bearer_methods_supported"
    }
}

/// The scheme+host (no path) of a resource indicator URL, e.g.
/// `https://api.example.com/mcp` → `https://api.example.com` — used to build the
/// discovery endpoint's URL alongside the actual protected routes.
private func publicBaseURL(of resourceIndicator: String) -> String {
    guard let url = URL(string: resourceIndicator),
        let scheme = url.scheme, let host = url.host
    else {
        return resourceIndicator
    }
    let port = url.port.map { ":\($0)" } ?? ""
    return "\(scheme)://\(host)\(port)"
}

/// Errors that can occur while configuring bearer authentication. Not public: a consumer
/// that wants to log or propagate the failure works with `any Error`, and doesn't need to
/// pattern-match the specific case.
enum ConfigurationError: Error, CustomStringConvertible {
    /// Auth was disabled while running in the `.production` environment.
    case authDisabledInProduction
    /// Running in `.production` without a WorkOS issuer/resource indicators and without
    /// auth explicitly disabled.
    case missingWorkOSEnvironment
    /// `workOSResourceIndicatorsRaw` was set but empty after splitting on commas.
    case emptyResourceIndicators
    /// The provided WorkOS issuer is not a valid absolute URL.
    case invalidIssuer
    /// One or more provided resource indicators are not valid absolute URLs.
    case invalidResourceIndicator

    var description: String {
        switch self {
        case .authDisabledInProduction:
            return "Disabling bearer auth is not allowed when the environment is production."
        case .missingWorkOSEnvironment:
            return "Missing WorkOS configuration: set both the issuer and resource indicators, " +
                "or disable auth explicitly outside production."
        case .emptyResourceIndicators:
            return "workOSResourceIndicatorsRaw is set but contains no valid values."
        case .invalidIssuer:
            return "workOSIssuer must be a valid absolute URL."
        case .invalidResourceIndicator:
            return "Each workOSResourceIndicator must be a valid absolute URL."
        }
    }
}
