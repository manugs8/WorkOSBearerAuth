import JWTKit

/// The claims this application relies on from a WorkOS AuthKit access token.
///
/// `iss`/`aud` are checked explicitly by ``BearerTokenVerifier`` against the configured
/// issuer and accepted audiences (resource indicators) — not inside ``verify(using:)`` —
/// because those expected values are runtime configuration (different per environment),
/// not something this type can know on its own.
///
/// `nbf` is optional per RFC 7519 §4.1.5 — WorkOS documents checking it "if present"
/// rather than guaranteeing it's always issued (https://workos.com/guide/jwt-validation)
/// — decoded here so ``verify(using:)`` can still enforce it when it does show up,
/// instead of a token that isn't valid yet slipping through because this type never
/// looked at the claim at all.
///
/// Public (and its properties too) because `Request.authenticatedClaims` — the one thing
/// a consuming application reads — returns this type directly; nothing outside this
/// module ever constructs one, so no public initializer is needed.
public struct WorkOSClaims: JWTPayload, Sendable {
    public let iss: IssuerClaim
    public let aud: AudienceClaim
    public let exp: ExpirationClaim
    public let nbf: NotBeforeClaim?
    public let sub: SubjectClaim

    public func verify(using key: some JWTAlgorithm) throws {
        try exp.verifyNotExpired()
        try nbf?.verifyNotBefore()
    }
}
