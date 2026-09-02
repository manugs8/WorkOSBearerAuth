import Foundation
import JWTKit

/// Signs short-lived, WorkOS-shaped test tokens for E2E-style tests that talk to a real,
/// already-running server over the network — rather than an in-process `Application` —
/// and need a bearer token the server will accept exactly as it would a genuine
/// WorkOS-issued one. Pairs with a fake Authorization Server serving the corresponding
/// public key as a JWKS document (so the server under test verifies against it via the
/// normal `RemoteJWKS`/`BearerAuthMiddleware` path, no test-only bypass involved).
///
/// A separate product from `WorkOSBearerAuth` itself, and deliberately dependency-light
/// (`JWTKit` + `Foundation`, no `Vapor`): an E2E test-support module has no reason to link
/// the server-side stack just to sign a token, and shouldn't be forced to.
///
/// Every value is a parameter rather than something this type reads from the environment
/// itself — same reasoning as `BearerAuthEnvironmentConfig`: this library isn't tied to a
/// specific set of variable names, and a consuming project's own test suite decides how
/// it discovers `issuer`/`resource`/the private key (env vars, a secrets file, whatever
/// its own CI pipeline uses).
public struct WorkOSTestTokenSigner: Sendable {
    public let issuer: String
    public let resource: String
    /// PEM-encoded RSA private key, or `nil` if none is configured. When `nil`,
    /// `validToken()`/`expiredToken()` return `nil` instead of throwing — so a project
    /// without this infrastructure standing up locally can still run its E2E suite
    /// against a server that has auth disabled too, rather than failing outright.
    public let privateKeyPEM: String?
    public let keyID: String

    public init(issuer: String, resource: String, privateKeyPEM: String?, keyID: String = "e2e-test-key-1") {
        self.issuer = issuer
        self.resource = resource
        self.privateKeyPEM = privateKeyPEM
        self.keyID = keyID
    }

    /// A valid, currently-live token — `nil` if no private key is configured.
    public func validToken() async throws -> String? {
        try await signedToken(expiration: .distantFuture)
    }

    /// Correctly signed, but with `exp` in the past — for exercising the "rejects an
    /// expired token" scenario against a real server.
    public func expiredToken() async throws -> String? {
        try await signedToken(expiration: Date(timeIntervalSinceNow: -3600))
    }

    private func signedToken(expiration: Date) async throws -> String? {
        guard let privateKeyPEM else { return nil }
        let keys = JWTKeyCollection()
        try await keys.add(
            rsa: Insecure.RSA.PrivateKey(pem: privateKeyPEM), digestAlgorithm: .sha256, kid: JWKIdentifier(string: keyID)
        )
        let claims = Claims(
            iss: IssuerClaim(value: issuer), aud: AudienceClaim(value: [resource]),
            exp: ExpirationClaim(value: expiration), sub: SubjectClaim(value: "e2e-test-user")
        )
        return try await keys.sign(claims, kid: JWKIdentifier(string: keyID))
    }

    private struct Claims: JWTPayload, Sendable {
        let iss: IssuerClaim
        let aud: AudienceClaim
        let exp: ExpirationClaim
        let sub: SubjectClaim

        func verify(using key: some JWTAlgorithm) throws {
            try exp.verifyNotExpired()
        }
    }
}
