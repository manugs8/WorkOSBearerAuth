@testable import WorkOSBearerAuth
import Foundation
import JWTKit
import Testing

/// Ejercita `BearerTokenVerifier` contra una `JWTKeyCollection` firmada localmente (HMAC
/// de prueba) — sin red, sin depender de las claves reales de WorkOS — para cubrir la
/// lógica que de verdad importa: la firma la valida `jwt-kit`, pero el algoritmo, la
/// presencia de `kid`, el issuer, la audiencia, la expiración y el not-before los
/// comprobamos nosotros. Todo verifier construido aquí con issuer/audiencia reales pasa
/// `allowedAlgorithms: ["HS256"]` para encajar con estos fixtures firmados por HMAC —
/// `rejectsUnexpectedAlgorithm` es la única excepción, usa deliberadamente el valor por
/// defecto de producción (`["RS256"]`) para probar que de verdad rechaza un token firmado
/// con HMAC.
@Suite("Bearer Token Verifier")
struct BearerTokenVerifierTests {
    static let issuer = "https://auth.test.example"
    static let resource = "https://api.test.example/mcp"
    /// El `kid` que incrusta `signedToken` salvo que se indique lo contrario — todo test
    /// al que no le importe el `kid` en concreto igualmente obtiene un token que lo
    /// lleva, porque `requiresKeyID` es `true` por defecto y un token real de WorkOS
    /// siempre lo lleva.
    static let defaultKeyID = JWKIdentifier(string: "test-key")

    /// Firma un `WorkOSClaims` con una clave HMAC de prueba y devuelve tanto el JWT
    /// como la colección de claves que lo puede verificar (imitando, en miniatura, lo
    /// que `RemoteJWKS` le daría al verifier en producción).
    static func signedToken(
        issuer: String = issuer,
        audience: [String] = [resource],
        expiration: Date = .distantFuture,
        notBefore: Date? = nil,
        kid: JWKIdentifier? = defaultKeyID
    ) async throws -> (token: String, keys: JWTKeyCollection) {
        let keys = JWTKeyCollection()
        await keys.add(hmac: "test-secret", digestAlgorithm: .sha256, kid: kid)
        let claims = WorkOSClaims(
            iss: IssuerClaim(value: issuer),
            aud: AudienceClaim(value: audience),
            exp: ExpirationClaim(value: expiration),
            nbf: notBefore.map(NotBeforeClaim.init(value:)),
            sub: SubjectClaim(value: "user_test")
        )
        let token = try await keys.sign(claims, kid: kid)
        return (token, keys)
    }

    /// Un token con issuer y audiencia correctos, sin expirar, se acepta y devuelve el
    /// `sub` tal cual venía firmado.
    @Test("Accepts a valid token whose issuer and audience match")
    func acceptsValidToken() async throws {
        let (token, keys) = try await Self.signedToken()
        let verifier = BearerTokenVerifier(issuer: Self.issuer, audiences: [Self.resource], allowedAlgorithms: ["HS256"])

        let claims = try await verifier.verify(token, using: keys)

        #expect(claims.sub.value == "user_test")
    }

    /// Varios resource indicators configurados a la vez (p. ej. local + producción) —
    /// basta con que el token coincida con uno solo para aceptarse.
    @Test("Accepts a token whose audience matches any one of several configured resources")
    func acceptsAnyConfiguredAudience() async throws {
        let (token, keys) = try await Self.signedToken(audience: ["http://localhost:8080/mcp"])
        let verifier = BearerTokenVerifier(
            issuer: Self.issuer,
            audiences: ["http://localhost:8080/mcp", Self.resource],
            allowedAlgorithms: ["HS256"]
        )

        let claims = try await verifier.verify(token, using: keys)

        #expect(claims.sub.value == "user_test")
    }

    /// Un `nbf` ya pasado no debe bloquear un token por lo demás válido.
    @Test("Accepts a token whose not-before time is already in the past")
    func acceptsTokenWithPastNotBefore() async throws {
        let (token, keys) = try await Self.signedToken(notBefore: Date(timeIntervalSinceNow: -3600))
        let verifier = BearerTokenVerifier(issuer: Self.issuer, audiences: [Self.resource], allowedAlgorithms: ["HS256"])

        let claims = try await verifier.verify(token, using: keys)

        #expect(claims.sub.value == "user_test")
    }

    /// Un token firmado por otro issuer se rechaza aunque la firma sea válida contra las
    /// claves dadas.
    @Test("Rejects a token whose issuer doesn't match the configured one")
    func rejectsWrongIssuer() async throws {
        let (token, keys) = try await Self.signedToken(issuer: "https://not-the-configured-issuer.example")
        let verifier = BearerTokenVerifier(issuer: Self.issuer, audiences: [Self.resource], allowedAlgorithms: ["HS256"])

        await #expect(throws: BearerTokenError.self) {
            try await verifier.verify(token, using: keys)
        }
    }

    /// Un token válido para un recurso distinto (p. ej. emitido para otra app WorkOS) no
    /// debe colar aquí solo porque la firma es correcta.
    @Test("Rejects a token whose audience isn't among the configured resource indicators")
    func rejectsWrongAudience() async throws {
        let (token, keys) = try await Self.signedToken(audience: ["https://someone-elses-app.example"])
        let verifier = BearerTokenVerifier(issuer: Self.issuer, audiences: [Self.resource], allowedAlgorithms: ["HS256"])

        await #expect(throws: BearerTokenError.self) {
            try await verifier.verify(token, using: keys)
        }
    }

    /// Un token expirado se rechaza — esta comprobación vive en
    /// `WorkOSClaims.verify(using:)`, no en el verifier, pero confirmamos aquí que
    /// `BearerTokenVerifier` no la salta.
    @Test("Rejects an expired token")
    func rejectsExpiredToken() async throws {
        let (token, keys) = try await Self.signedToken(expiration: .distantPast)
        let verifier = BearerTokenVerifier(issuer: Self.issuer, audiences: [Self.resource], allowedAlgorithms: ["HS256"])

        await #expect(throws: (any Error).self) {
            try await verifier.verify(token, using: keys)
        }
    }

    /// Un `nbf` todavía en el futuro rechaza el token — mismo criterio que `exp`, pero en
    /// el sentido contrario.
    @Test("Rejects a token whose not-before time is still in the future")
    func rejectsTokenNotYetValid() async throws {
        let (token, keys) = try await Self.signedToken(notBefore: Date(timeIntervalSinceNow: 3600))
        let verifier = BearerTokenVerifier(issuer: Self.issuer, audiences: [Self.resource], allowedAlgorithms: ["HS256"])

        await #expect(throws: (any Error).self) {
            try await verifier.verify(token, using: keys)
        }
    }

    /// Un token firmado con un algoritmo fuera del conjunto permitido se rechaza antes de
    /// comprobar la firma. Deliberadamente sin `allowedAlgorithms` (usa el valor por
    /// defecto de producción, `["RS256"]`) — estos fixtures firman con HMAC (HS256), así
    /// que esto prueba que la política real rechaza HS256, no solo que una lista
    /// artificialmente estrecha lo haría.
    @Test("Rejects a token signed with an algorithm outside the trusted set")
    func rejectsUnexpectedAlgorithm() async throws {
        let (token, keys) = try await Self.signedToken()
        let verifier = BearerTokenVerifier(issuer: Self.issuer, audiences: [Self.resource])

        await #expect(throws: BearerTokenError.self) {
            try await verifier.verify(token, using: keys)
        }
    }

    /// Sin `kid` y sin sobreescribir `requiresKeyID` (el valor real de producción,
    /// `true`), el token se rechaza.
    @Test("Rejects a token with no kid when the verifier requires one")
    func rejectsMissingKeyIDByDefault() async throws {
        let (token, keys) = try await Self.signedToken(kid: nil)
        let verifier = BearerTokenVerifier(issuer: Self.issuer, audiences: [Self.resource], allowedAlgorithms: ["HS256"])

        await #expect(throws: BearerTokenError.self) {
            try await verifier.verify(token, using: keys)
        }
    }

    /// Con `requiresKeyID: false` explícito, un token sin `kid` sí se acepta.
    @Test("Accepts a token with no kid when the verifier explicitly doesn't require one")
    func acceptsMissingKeyIDWhenNotRequired() async throws {
        let (token, keys) = try await Self.signedToken(kid: nil)
        let verifier = BearerTokenVerifier(
            issuer: Self.issuer, audiences: [Self.resource], allowedAlgorithms: ["HS256"], requiresKeyID: false
        )

        let claims = try await verifier.verify(token, using: keys)

        #expect(claims.sub.value == "user_test")
    }

    /// Protege contra un futuro cambio en `configureBearerAuth`/
    /// `makeProductionBearerTokenVerifier` que afloje la política de producción sin
    /// querer (p. ej. añadir `allowedAlgorithms: ["RS256", "HS256"]` "solo para depurar"
    /// y olvidarlo). El riesgo no está en el valor por defecto de `BearerTokenVerifier`
    /// — está en si el único sitio de producción que importa sigue confiando en ese
    /// valor por defecto en vez de sobreescribirlo.
    @Test("Production verifier construction never overrides the default algorithm/kid policy")
    func productionVerifierUsesDefaultPolicy() {
        let verifier = makeProductionBearerTokenVerifier(
            issuer: "https://issuer.example.authkit.app", audiences: ["https://api.example.com/mcp"]
        )

        #expect(verifier.allowedAlgorithms == ["RS256"])
        #expect(verifier.requiresKeyID == true)
    }
}
