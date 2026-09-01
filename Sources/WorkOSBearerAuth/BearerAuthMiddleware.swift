import JWTKit
import Vapor

/// Requires a valid bearer token on every route except the exempt paths below — applied
/// globally so REST and `/mcp` share one authentication path, instead of REST having none
/// (as before) and `/mcp` having its own separate mechanism.
///
/// Registered by `configureBearerAuth` with a ``RemoteJWKS`` backed by real WorkOS
/// credentials — and unconditionally skipped in `.testing`, so the REST/MCP test suites
/// of a consuming app don't need those credentials. `jwksSource` is typed as
/// ``JWKSSource`` rather than the concrete `RemoteJWKS` so `BearerAuthMiddlewareTests`
/// can still exercise this middleware end-to-end against a local key collection.
///
/// Internal, not public: `configureBearerAuth` is the only production call site, and
/// nothing outside this module needs to construct one directly.
struct BearerAuthMiddleware: AsyncMiddleware {
    /// Paths that stay public: `/health` so a platform healthcheck (which can't
    /// authenticate) keeps working, `/docs`/`/openapi.yaml` because they're
    /// documentation, not data, and the discovery endpoint itself — an MCP client has to
    /// be able to fetch it *before* it has a token.
    static let exemptPaths: Set<String> = [
        "/health", "/docs", "/openapi.yaml", "/.well-known/oauth-protected-resource",
    ]

    let jwksSource: any JWKSSource
    let verifier: BearerTokenVerifier
    let resourceMetadataURL: String

    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        guard !Self.exemptPaths.contains(request.url.path) else {
            return try await next.respond(to: request)
        }

        let token: String
        let header: JWTHeader
        do {
            token = try bearerToken(from: request)
            // Parsed once, here, and reused below both for the `kid`-based refresh
            // decision and for the real `verify(_:header:using:)` call — rather than a
            // `try?` re-parse for the refresh check that silently swallows a malformed
            // header, leaving it to `verify` to notice on a second, separate parse.
            header = try verifier.header(of: token)
        } catch {
            request.logger.notice("Rejected unauthenticated request to \(request.url.path): \(error)")
            return unauthorizedResponse()
        }

        var keys: JWTKeyCollection
        do {
            keys = try await jwksSource.currentKeys(forceRefresh: false)
            // Refresh only when the token's own `kid` isn't one this cache recognizes —
            // the one situation that plausibly means WorkOS rotated its signing key since
            // our last fetch. Deliberately *not* a catch-and-retry around `verify` below:
            // that would force a JWKS fetch for every rejected token regardless of cause
            // (bad signature, expired, wrong issuer/audience/algorithm), letting an
            // attacker cheaply trigger repeated remote fetches just by sending garbage.
            if let kid = header.kid, await !jwksSource.hasKey(kid: kid) {
                keys = try await jwksSource.currentKeys(forceRefresh: true)
            }
        } catch {
            // The token itself was never evaluated here — this is WorkOS or the network
            // being unreachable, not an invalid token. Reporting 401 would claim we know
            // the token is bad, when we actually couldn't check it at all; 503 (via Vapor's
            // own ErrorMiddleware, same as any other infrastructure failure) says the right
            // thing — try again — instead of telling a legitimate client its token is bad.
            request.logger.error("Could not fetch the WorkOS JWKS for \(request.url.path): \(error)")
            throw Abort(.serviceUnavailable, reason: "Authentication is temporarily unavailable.")
        }

        let claims: WorkOSClaims
        do {
            claims = try await verifier.verify(token, header: header, using: keys)
        } catch {
            request.logger.notice("Rejected unauthenticated request to \(request.url.path): \(error)")
            return unauthorizedResponse()
        }
        // Publishes the validated claims on `request.storage` for whatever this request ends
        // up calling to read — see `Request.authenticatedClaims`'s doc comment for why.
        // Deliberately outside every `do` above: once the token itself checks out, any error
        // the handler throws (e.g. a database failure) must propagate as-is to Vapor's own
        // ErrorMiddleware (→ 500), not get relabeled as a 401 by this middleware.
        request.authenticatedClaims = claims
        return try await next.respond(to: request)
    }

    private func bearerToken(from request: Request) throws -> String {
        guard let header = request.headers.bearerAuthorization else {
            throw BearerTokenError.missingBearerToken
        }
        return header.token
    }

    private func unauthorizedResponse() -> Response {
        let response = Response(status: .unauthorized)
        response.headers.replaceOrAdd(
            name: .wwwAuthenticate,
            value: "Bearer resource_metadata=\"\(resourceMetadataURL)\""
        )
        return response
    }
}
