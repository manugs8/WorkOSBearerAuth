import JWTKit

/// Verifies a JWT's algorithm, signature, issuer, audience, expiry, and (when present)
/// not-before time against a given key collection. This is *not* where the
/// `Authorization: Bearer <token>` header itself is parsed — `BearerAuthMiddleware`
/// strips the `Bearer ` prefix before ever calling this type; `verify(_:using:)` only
/// ever sees the raw JWT string. Deliberately takes the `JWTKeyCollection` as a
/// parameter rather than owning a ``RemoteJWKS`` itself, so tests can exercise the
/// actual verification logic — the part that matters for security — against a
/// locally-generated test key, with no network dependency on WorkOS. ``RemoteJWKS``
/// (fetching/caching the real keys over HTTP) and this type's claim checks are
/// deliberately separate concerns.
///
/// Internal, not public: nothing outside this module needs to construct or call one
/// directly — `configureBearerAuth` is the only production call site, and the test
/// target reaches this via `@testable import`.
struct BearerTokenVerifier: Sendable {
    let issuer: String
    let audiences: Set<String>

    /// The only signing algorithms this application trusts, checked against the token's
    /// own (unverified) header *before* any signature check. WorkOS AuthKit signs access
    /// tokens with RS256 (https://workos.com/guide/jwt-validation) — pinned explicitly
    /// here rather than implicitly trusting whichever algorithm `JWTKeyCollection` would
    /// otherwise select for a matching `kid`, so a token whose header claims an
    /// unexpected algorithm is rejected outright. Overridable per instance so tests can
    /// exercise this same code path against locally-signed HMAC fixtures instead of a
    /// real RSA keypair. `let`, not `var` — a verifier's policy doesn't change after
    /// it's built.
    let allowedAlgorithms: Set<String>

    /// Whether a token without a `kid` header is rejected outright, instead of falling
    /// back to whichever key `JWTKeyCollection` treats as its default. `true` in
    /// production: with real key rotation (more than one WorkOS signing key live at
    /// once), a legitimate token always carries `kid` — one that doesn't is either
    /// malformed or crafted, and "try the default key and see if the signature happens
    /// to match" is exactly the kind of implicit, library-dependent fallback a bearer
    /// token policy shouldn't rely on. Overridable per instance for the same reason as
    /// `allowedAlgorithms`.
    let requiresKeyID: Bool

    /// - Precondition: `allowedAlgorithms` must not be empty. An empty set isn't a
    ///   stricter policy — it's a verifier that rejects every token unconditionally, and
    ///   silently: nothing about `verify(_:using:)`'s 401s would tell you the real cause
    ///   is a misconfigured allow-list. This can only happen from a hardcoded mistake in
    ///   source (the one production call site, `makeProductionBearerTokenVerifier`,
    ///   never overrides the default), so it fails loudly here instead of quietly at
    ///   request time.
    init(
        issuer: String, audiences: Set<String>, allowedAlgorithms: Set<String> = ["RS256"],
        requiresKeyID: Bool = true
    ) {
        precondition(
            !allowedAlgorithms.isEmpty,
            "BearerTokenVerifier.allowedAlgorithms must not be empty — that rejects every token."
        )
        self.issuer = issuer
        self.audiences = audiences
        self.allowedAlgorithms = allowedAlgorithms
        self.requiresKeyID = requiresKeyID
    }

    /// Decodes (without verifying) a token's header. Shared by this type's own algorithm
    /// check below and by `BearerAuthMiddleware`'s decision of whether an unrecognized
    /// `kid` warrants a forced JWKS refresh, so the header is parsed in one place rather
    /// than two independent implementations that could drift apart.
    func header(of token: String) throws -> JWTHeader {
        try DefaultJWTParser().parse([UInt8](token.utf8), as: WorkOSClaims.self).header
    }

    /// Verifies `token` against `keys`, parsing its header itself. Prefer
    /// `verify(_:header:using:)` when the caller already parsed the header for another
    /// reason (e.g. `BearerAuthMiddleware`'s `kid` check), to avoid parsing it twice.
    func verify(_ token: String, using keys: JWTKeyCollection) async throws -> WorkOSClaims {
        try await verify(token, header: header(of: token), using: keys)
    }

    /// Verifies `token` against `keys`, reusing an already-parsed `header` instead of
    /// decoding it again.
    ///
    /// - Throws: ``BearerTokenError`` if the algorithm, issuer, or audience don't check
    ///   out; whatever `JWTKeyCollection.verify` / `WorkOSClaims.verify(using:)` throws
    ///   for a bad signature, an unknown `kid`, or a token that's expired or not yet
    ///   valid.
    func verify(_ token: String, header: JWTHeader, using keys: JWTKeyCollection) async throws -> WorkOSClaims {
        guard let alg = header.alg, allowedAlgorithms.contains(alg) else {
            throw BearerTokenError.unexpectedAlgorithm(header.alg)
        }
        guard !requiresKeyID || header.kid != nil else {
            throw BearerTokenError.missingKeyID
        }

        // `keys.verify` invokes `WorkOSClaims.verify(using:)` as part of verification,
        // which checks `exp` and (when present) `nbf` — the single source of truth for
        // those two, not duplicated here. This type owns application policy (algorithm,
        // issuer, audience); `WorkOSClaims` owns the token's own temporal validity.
        let claims = try await keys.verify(token, as: WorkOSClaims.self)
        guard claims.iss.value == issuer else {
            throw BearerTokenError.unexpectedIssuer(claims.iss.value)
        }
        guard !Set(claims.aud.value).isDisjoint(with: audiences) else {
            throw BearerTokenError.unexpectedAudience(claims.aud.value)
        }
        return claims
    }
}

enum BearerTokenError: Error, CustomStringConvertible {
    case missingBearerToken
    case unexpectedAlgorithm(String?)
    case missingKeyID
    case unexpectedIssuer(String)
    case unexpectedAudience([String])

    var description: String {
        switch self {
        case .missingBearerToken:
            return "Missing or malformed Authorization: Bearer header."
        case .unexpectedAlgorithm(let alg):
            return "Token algorithm \(alg ?? "(missing)") is not in the set of algorithms this deployment trusts."
        case .missingKeyID:
            return "Token has no kid header, and this deployment requires one."
        case .unexpectedIssuer(let issuer):
            return "Token issuer \(issuer) does not match the configured WorkOS issuer."
        case .unexpectedAudience(let audiences):
            return "Token audience \(audiences) does not match any configured resource indicator."
        }
    }
}
