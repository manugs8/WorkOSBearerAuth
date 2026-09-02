import Foundation
import JWTKit

/// Firma tokens de prueba de corta duración, con la misma forma que los de WorkOS, para
/// tests de estilo E2E que hablan con un servidor real ya en marcha a través de la red —
/// en vez de con una `Application` en el mismo proceso — y necesitan un token Bearer que
/// el servidor acepte exactamente igual que aceptaría uno auténtico emitido por WorkOS.
/// Se combina con una Authorization Server falsa que sirve la clave pública
/// correspondiente como documento JWKS (de modo que el servidor bajo test verifica contra
/// ella siguiendo el camino normal de `RemoteJWKS`/`BearerAuthMiddleware`, sin ningún
/// atajo pensado solo para tests).
///
/// Es un producto separado de `WorkOSBearerAuth`, y deliberadamente ligero en
/// dependencias (`JWTKit` + `Foundation`, sin `Vapor`): un módulo de apoyo para tests E2E
/// no tiene ningún motivo para enlazar la pila del lado servidor solo para firmar un
/// token, y no debería verse obligado a ello.
///
/// Cada valor es un parámetro, en vez de algo que este tipo lea del entorno por sí mismo
/// — el mismo razonamiento que `BearerAuthEnvironmentConfig`: esta librería no está atada
/// a un conjunto concreto de nombres de variables, y la propia suite de tests de un
/// proyecto consumidor decide cómo descubre el `issuer`/`resource`/la clave privada
/// (variables de entorno, un fichero de secretos, lo que use su propio pipeline de CI).
public struct WorkOSTestTokenSigner: Sendable {
    /// El issuer que llevarán los tokens firmados — debe coincidir con el `WORKOS_ISSUER`
    /// (o equivalente) que espera el servidor bajo test.
    public let issuer: String
    /// El resource indicator (audiencia) que llevarán los tokens firmados — debe coincidir
    /// con uno de los configurados en el servidor bajo test.
    public let resource: String
    /// Clave privada RSA en formato PEM, o `nil` si no hay ninguna configurada. Cuando es
    /// `nil`, `validToken()`/`expiredToken()` devuelven `nil` en vez de lanzar un error —
    /// así, un proyecto que no tenga montada esta infraestructura en local puede seguir
    /// ejecutando su suite E2E contra un servidor que también tenga la autenticación
    /// desactivada, en vez de fallar sin más.
    public let privateKeyPEM: String?
    /// El `kid` que llevará la cabecera de los tokens firmados — debe coincidir con el
    /// `kid` bajo el que la Authorization Server falsa publica esta misma clave pública
    /// en su documento JWKS.
    public let keyID: String

    /// Crea un firmante de tokens de prueba. `keyID` tiene un valor por defecto porque su
    /// valor exacto rara vez importa: solo debe coincidir con el `kid` del documento JWKS
    /// que sirva la Authorization Server falsa.
    public init(issuer: String, resource: String, privateKeyPEM: String?, keyID: String = "e2e-test-key-1") {
        self.issuer = issuer
        self.resource = resource
        self.privateKeyPEM = privateKeyPEM
        self.keyID = keyID
    }

    /// Un token válido y vigente en este momento — `nil` si no hay clave privada configurada.
    public func validToken() async throws -> String? {
        try await signedToken(expiration: .distantFuture)
    }

    /// Firmado correctamente, pero con `exp` en el pasado — para ejercitar contra un
    /// servidor real el escenario de "rechaza un token caducado".
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

    /// Claims mínimas para firmar un token de prueba — deliberadamente sin `nbf`: ningún
    /// test de esta librería necesita ejercitar el camino de "todavía no válido".
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
