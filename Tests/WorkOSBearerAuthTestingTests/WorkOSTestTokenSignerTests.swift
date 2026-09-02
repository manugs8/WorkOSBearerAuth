import Foundation
import JWTKit
import Testing
import WorkOSBearerAuthTesting

/// Clave RSA de 2048 bits generada solo para estos tests (`openssl genrsa 2048`), sin
/// relación con ninguna clave real de CI de ningún proyecto — su único propósito es
/// firmar/verificar dentro de este fichero.
private let testPrivateKeyPEM = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9zU6bIf+fID3d
w/Mqy0kgvnd8vcnAjITD72i4dkmtn4pgXFpoC6TnHmop/sO1fH01FWxde6F0GCTm
rh8ppoPgEckwM5scqWghBzAd7ff9lW1a+WU48bOI5khoa5Z4fLc6GnoWEOULWYRA
sROzEwxjDnrgLRrv6k+5hXANojEgA1SfaJQs05RKiK1lCrgpKsfijnHzlRvP7m7a
uv2Pu94WTWlADOPdd9nP3eVSLnhj0SGf8T51wZfAmK4EaDqn8bTmxx+0z392f6qW
8gRQPUWCcjnLpx+rPVS/qInmWyJYTT0quynk/CjLE1jNoIL0SJVzG1Q56T0rjjAQ
xebRThkJAgMBAAECggEADQJhfOibqMCA/Q5NQIWmgYQMlJQ9m+EFyJhESUByVGA3
D9vEppUFvIGtLSu1Jl9eBaFuSAoNSvPMs7MDl8s+BsGxVIh0/UXvSTRA7Aw/jzYK
xM2LTpfigmOmWuHk8mU5+dWOwKxvxpNgKT755rBLjQ6VBYCR9BfPVxv6TjTrwRHa
/Qou0ky7Da4BifDt5Kxh6sYeUnXIApW0wLr80tKHtrrq/Z0LPx7M9szz1XFYFu1l
/9amFn8A1l+WbpC8Xp0O/B9K7158dQiB7CGjdwNnbhED9wCrFGhSEboPaPg6OARc
DW3CsBtIeXx+mESfjqg5I2OF5PFwBFyLWiqcMRrswQKBgQD0tMvMt9c4NaINm51g
2+sfnYXATUrLOsAO/pL+EXpseMb9REmXhMxu3FfcVuGnAGMWFSVTgF0Yrri/5eUt
fe4SW9qGUUD/fgzjYax+Jsp7QXpgTM2kG3K7FkOjnP+6b06OSjlFCTASWV16Wc4g
aYR5zt6X1niy4mNNsgZlit7lbQKBgQDGj9E30GxwdfOpl5dLlZxKK4AVPEhZrii2
kv7gYypGdXthsebPpHbBB3mTN6R+2eJ68cxDkfCAlku1sK6nEyMAn4nyJFSblMZF
dkPzi8OTr/Wuo0mFTX0uLOuPQsRQao7AGZ9LVaTYZR4K3IAZ3RKJxMxHMKR15Q+L
lyum56csjQKBgCx6UDC9mZjV5saialCYqHvuncj+Q4H9A7u1+fHEK4Rbz49pQhcQ
RDhCRJYAFLPOFjSFU2uCAWnjGCGJH8bNBODBYU7Ypf/KYX1S249ybYtJs3ydeSNC
+e+XdGPgvXqdkKG8S/yIVvx+0cbTW+v4QeQB/eOLUBTzoSkWGqOKQklhAoGAfnvQ
Z0ByQzUvsOFqs/AqraiGH4DWCaKCNsLubttca6Oco7/ianS2XQG49Qll1JRQy8ZJ
OuW1EQQsWCGjL7RmAJigE8oGx1B++HJ8mKB4RhS5aLSFOdABpK9iolCCo0MtibsI
mMGGj33iJEMPquoDTBU7l0GqEZuHSoFSgjBgcmUCgYEAllZRPUtXb2hx9Hf6Bhlm
qWMEU/JF9Hagby0cZRTqWJxlF6KVn4oxjexA4lxP9WuvDU5tao92Ml4E8wiT5Z5q
SNmnKZWPpfjlNaG6af11nrA90tHpqc1vsNXTZcFylwoHu51XMNxEcBxHi5+kFzWk
aHWM0powtcAKPzYBzhiCkhc=
-----END PRIVATE KEY-----
"""

@Suite("WorkOSTestTokenSigner")
struct WorkOSTestTokenSignerTests {
    static let issuer = "https://auth.test.example"
    static let resource = "https://api.test.example/mcp"

    /// Sin clave configurada, ambos métodos devuelven `nil` en vez de fallar — así un
    /// proyecto que no tenga la infraestructura de la Authorization Server falsa montada
    /// en local puede seguir corriendo su suite E2E contra un servidor con auth
    /// deshabilitada.
    @Test("Returns nil for both tokens when no private key is configured")
    func returnsNilWithoutAPrivateKey() async throws {
        let signer = WorkOSTestTokenSigner(issuer: Self.issuer, resource: Self.resource, privateKeyPEM: nil)

        #expect(try await signer.validToken() == nil)
        #expect(try await signer.expiredToken() == nil)
    }

    /// El token firmado se verifica correctamente contra su propia clave pública — mismo
    /// camino que seguiría `RemoteJWKS`/`BearerTokenVerifier` en el servidor real.
    @Test("Produces a token that verifies against its own key, with the configured issuer/audience/kid")
    func producesAVerifiableToken() async throws {
        let signer = WorkOSTestTokenSigner(
            issuer: Self.issuer, resource: Self.resource, privateKeyPEM: testPrivateKeyPEM, keyID: "test-key"
        )
        guard let token = try await signer.validToken() else {
            Issue.record("Expected a token since a private key was configured")
            return
        }

        let keys = JWTKeyCollection()
        try await keys.add(
            rsa: Insecure.RSA.PublicKey(pem: publicKeyPEM(from: testPrivateKeyPEM)), digestAlgorithm: .sha256,
            kid: JWKIdentifier(string: "test-key")
        )

        let payload = try await keys.verify(token, as: TestClaims.self)
        #expect(payload.iss.value == Self.issuer)
        #expect(payload.aud.value == [Self.resource])
    }

    /// `exp` en el pasado — el propio `verify` de `ExpirationClaim` debe rechazarlo,
    /// igual que rechazaría un token real caducado.
    @Test("expiredToken produces a token whose exp is already in the past")
    func expiredTokenIsRejectedOnVerification() async throws {
        let signer = WorkOSTestTokenSigner(
            issuer: Self.issuer, resource: Self.resource, privateKeyPEM: testPrivateKeyPEM, keyID: "test-key"
        )
        guard let token = try await signer.expiredToken() else {
            Issue.record("Expected a token since a private key was configured")
            return
        }

        let keys = JWTKeyCollection()
        try await keys.add(
            rsa: Insecure.RSA.PublicKey(pem: publicKeyPEM(from: testPrivateKeyPEM)), digestAlgorithm: .sha256,
            kid: JWKIdentifier(string: "test-key")
        )

        await #expect(throws: (any Error).self) {
            try await keys.verify(token, as: TestClaims.self)
        }
    }

    /// Dos llamadas usan el mismo `kid` — el servidor bajo test no tiene que refrescar su
    /// JWKS entre una petición y otra dentro del mismo test.
    @Test("Uses the same kid across calls")
    func usesAStableKeyID() async throws {
        let signer = WorkOSTestTokenSigner(
            issuer: Self.issuer, resource: Self.resource, privateKeyPEM: testPrivateKeyPEM, keyID: "stable-kid"
        )
        let first = try await signer.validToken()
        let second = try await signer.validToken()

        #expect(first != nil)
        #expect(second != nil)
        #expect(header(of: first!).kid == "stable-kid")
        #expect(header(of: second!).kid == "stable-kid")
    }
}

/// Réplica local de `WorkOSTestTokenSigner`'s private `Claims` — no se puede reutilizar
/// directamente (es `private`), y no hace falta: el test solo necesita decodificar los
/// mismos tres campos.
private struct TestClaims: JWTPayload, Sendable {
    let iss: IssuerClaim
    let aud: AudienceClaim
    let exp: ExpirationClaim

    func verify(using key: some JWTAlgorithm) throws {
        try exp.verifyNotExpired()
    }
}

private func header(of token: String) -> JWTHeader {
    (try? DefaultJWTParser().parse([UInt8](token.utf8), as: TestClaims.self).header) ?? JWTHeader()
}

/// Deriva la clave pública PEM a partir de la privada — evita mantener dos fixtures
/// (privada + pública) sincronizadas a mano en este fichero.
private func publicKeyPEM(from privateKeyPEM: String) -> String {
    let privateKey = try! Insecure.RSA.PrivateKey(pem: privateKeyPEM)
    return privateKey.publicKey.pemRepresentation
}
