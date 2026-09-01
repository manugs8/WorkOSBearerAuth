@testable import WorkOSBearerAuth
import Foundation
import JWTKit
import Testing
import Vapor
import VaporTesting

/// Un `JWKSSource` que siempre devuelve la misma `JWTKeyCollection` ya construida — el
/// sustituto local de `RemoteJWKS` aquí, para poder ejercitar `BearerAuthMiddleware` de
/// extremo a extremo (middleware real, request/response HTTP reales) sin una petición de
/// red ni credenciales reales de WorkOS. No rota claves, así que `hasKey` siempre responde
/// `true` — no hay nada que un refresh forzado deba arreglar aquí, y así los tests a los
/// que no les importa el refresco no tienen que pensar en él.
struct StaticJWKS: JWKSSource {
    let keys: JWTKeyCollection

    func currentKeys(forceRefresh: Bool) async throws -> JWTKeyCollection {
        keys
    }

    func hasKey(kid: String) async -> Bool {
        true
    }
}

/// Un doble de `JWKSSource` que registra cuántas veces se pidió un refresh forzado y deja
/// que un test controle qué `kid`s dice reconocer ya — usado específicamente para
/// ejercitar la política de "solo refrescar ante un `kid` no reconocido" de
/// `BearerAuthMiddleware`. Un actor (igual que el `RemoteJWKS` real) en vez de una clase
/// normal, para que mutar `forceRefreshCallCount` desde peticiones de test concurrentes
/// sea de verdad seguro, no solo asumido como seguro.
actor RefreshTrackingJWKS: JWKSSource {
    let keys: JWTKeyCollection
    let recognizedKeyIDs: Set<String>
    private(set) var forceRefreshCallCount = 0

    init(keys: JWTKeyCollection, recognizedKeyIDs: Set<String>) {
        self.keys = keys
        self.recognizedKeyIDs = recognizedKeyIDs
    }

    func currentKeys(forceRefresh: Bool) async throws -> JWTKeyCollection {
        if forceRefresh {
            forceRefreshCallCount += 1
        }
        return keys
    }

    func hasKey(kid: String) async -> Bool {
        recognizedKeyIDs.contains(kid)
    }
}

/// Un doble de `JWKSSource` cuyo `currentKeys` siempre falla — simula que WorkOS o la red
/// no están disponibles, para probar que `BearerAuthMiddleware` responde 503 (fallo de
/// infraestructura), no 401 (el token del cliente fue rechazado) — nunca llegó a
/// comprobarse.
struct FailingJWKS: JWKSSource {
    func currentKeys(forceRefresh: Bool) async throws -> JWTKeyCollection {
        throw Abort(.serviceUnavailable, reason: "JWKS unreachable (test double).")
    }

    func hasKey(kid: String) async -> Bool {
        false
    }
}

/// Ejercita `BearerAuthMiddleware` end-to-end — ruta real, request HTTP real, respuesta
/// real — usando `StaticJWKS` en vez de `RemoteJWKS` como fuente de claves. No hace falta
/// Postgres en ningún test de esta suite: cada uno monta una `Application` mínima con solo
/// las rutas que necesita, sin pasar por `withMigratedApp`/`configure(_:)` ni por el
/// dominio de negocio de ningún proyecto concreto — deliberado, para que esta suite entera
/// se pueda mover tal cual a una librería compartida.
///
/// `BearerTokenVerifierTests` ya cubre algoritmo/issuer/audiencia/expiración/not-before
/// contra una `JWTKeyCollection` local; esto cubre la pieza que falta: que el middleware
/// esté bien conectado (ruta exenta vs protegida, encabezado `WWW-Authenticate`, refresco
/// de claves ante un `kid` desconocido, y que una única instancia global cubra varias
/// rutas montadas de formas distintas). El verifier se construye con
/// `allowedAlgorithms: ["HS256"]` porque estos fixtures firman con HMAC.
@Suite("Bearer Auth Middleware")
struct BearerAuthMiddlewareTests {
    static let issuer = "https://auth.test.example"
    static let resource = "https://api.test.example/mcp"
    static let resourceMetadataURL = "https://api.test.example/.well-known/oauth-protected-resource"
    /// El `kid` que incrusta `makeKeys`/`signedToken` salvo que se indique lo contrario —
    /// mismo razonamiento que `BearerTokenVerifierTests.defaultKeyID`: `requiresKeyID` es
    /// `true` por defecto, así que un token necesita `kid` para aceptarse siquiera.
    static let defaultKeyID = JWKIdentifier(string: "test-key")

    /// Monta una `Application` de test con `BearerAuthMiddleware` real delante de una
    /// ruta protegida (`/protected`) y una exenta (`/health`), verificando contra `keys`.
    static func withTestApp(
        keys: JWTKeyCollection, _ test: (Application) async throws -> Void
    ) async throws {
        let verifier = BearerTokenVerifier(issuer: issuer, audiences: [resource], allowedAlgorithms: ["HS256"])
        try await withTestApp(jwksSource: StaticJWKS(keys: keys), verifier: verifier, test)
    }

    /// Igual que arriba, pero recibiendo el `JWKSSource`/`BearerTokenVerifier`
    /// directamente — permite a `refreshesForUnrecognizedKeyID`/
    /// `doesNotRefreshForExpiredTokenWithKnownKeyID` usar `RefreshTrackingJWKS` en vez de
    /// `StaticJWKS`. `second-interface` se registra vía `app.on(..., body: .collect,
    /// use:)` en vez de `app.get`/`app.post` normales — a propósito, para imitar cómo se
    /// monta MCP en producción y así poder probar que el middleware, atado una sola vez
    /// vía `app.middleware.use(...)`, cubre igual cualquier ruta registrada después,
    /// sea cual sea el mecanismo con el que se registró.
    static func withTestApp(
        jwksSource: any JWKSSource, verifier: BearerTokenVerifier, _ test: (Application) async throws -> Void
    ) async throws {
        let app = try await Application.make(.testing)
        do {
            app.middleware.use(
                BearerAuthMiddleware(
                    jwksSource: jwksSource, verifier: verifier, resourceMetadataURL: resourceMetadataURL
                )
            )
            app.get("protected") { _ in "ok" }
            app.get("health") { _ in "ok" }
            app.get("whoami") { req in req.authenticatedClaims?.sub.value ?? "none" }
            app.on(.POST, "second-interface", body: .collect) { _ in "ok" }
            try await test(app)
        } catch {
            try? await app.asyncShutdown()
            throw error
        }
        try await app.asyncShutdown()
    }

    /// Una `JWTKeyCollection` de test con una clave HMAC — igual que
    /// `BearerTokenVerifierTests`, no hace falta RSA/EC: `RemoteJWKS` (el parseo real de
    /// un JWKS por HTTP) es una pieza deliberadamente distinta, no lo que este test cubre.
    static func makeKeys(secret: String = "test-secret", kid: JWKIdentifier? = defaultKeyID) async -> JWTKeyCollection {
        let keys = JWTKeyCollection()
        await keys.add(hmac: HMACKey(from: secret), digestAlgorithm: .sha256, kid: kid)
        return keys
    }

    static func signedToken(
        keys: JWTKeyCollection, issuer: String = issuer, audience: [String] = [resource],
        expiration: Date = .distantFuture, kid: JWKIdentifier? = defaultKeyID
    ) async throws -> String {
        let claims = WorkOSClaims(
            iss: IssuerClaim(value: issuer), aud: AudienceClaim(value: audience),
            exp: ExpirationClaim(value: expiration), nbf: nil, sub: SubjectClaim(value: "user_test")
        )
        return try await keys.sign(claims, kid: kid)
    }

    @Test("Allows a request with a valid bearer token through to the route")
    func allowsValidToken() async throws {
        let keys = await Self.makeKeys()
        let token = try await Self.signedToken(keys: keys)

        try await Self.withTestApp(keys: keys) { app in
            try await app.testing().test(.GET, "protected", headers: ["Authorization": "Bearer \(token)"]) {
                res async throws in
                #expect(res.status == .ok)
            }
        }
    }

    /// El `sub` validado debe quedar disponible en `request.authenticatedClaims` para lo
    /// que sea que la petición acabe llamando, sin volver a decodificar el JWT.
    @Test("Publishes the validated sub on request.authenticatedClaims for the route to read")
    func propagatesAuthenticatedClaims() async throws {
        let keys = await Self.makeKeys()
        let token = try await Self.signedToken(keys: keys)

        try await Self.withTestApp(keys: keys) { app in
            try await app.testing().test(.GET, "whoami", headers: ["Authorization": "Bearer \(token)"]) {
                res async throws in
                #expect(res.status == .ok)
                #expect(res.body.string == "user_test")
            }
        }
    }

    @Test("Rejects a request with no Authorization header")
    func rejectsMissingToken() async throws {
        try await Self.withTestApp(keys: Self.makeKeys()) { app in
            try await app.testing().test(.GET, "protected") { res async throws in
                #expect(res.status == .unauthorized)
                #expect(res.headers.first(name: .wwwAuthenticate)?.contains(Self.resourceMetadataURL) == true)
            }
        }
    }

    @Test("Rejects a request whose token has an unknown signing key")
    func rejectsUnknownSigningKey() async throws {
        let otherKeys = await Self.makeKeys(secret: "a-completely-different-secret")
        let forgedToken = try await Self.signedToken(keys: otherKeys)

        try await Self.withTestApp(keys: Self.makeKeys()) { app in
            try await app.testing().test(
                .GET, "protected", headers: ["Authorization": "Bearer \(forgedToken)"]
            ) { res async throws in
                #expect(res.status == .unauthorized)
            }
        }
    }

    @Test("Rejects a token with the wrong issuer even if the signature checks out")
    func rejectsWrongIssuer() async throws {
        let keys = await Self.makeKeys()
        let token = try await Self.signedToken(keys: keys, issuer: "https://not-the-configured-issuer.example")

        try await Self.withTestApp(keys: keys) { app in
            try await app.testing().test(.GET, "protected", headers: ["Authorization": "Bearer \(token)"]) {
                res async throws in
                #expect(res.status == .unauthorized)
            }
        }
    }

    /// El `kid` firmado en el token no existe en lo que `RefreshTrackingJWKS` dice
    /// reconocer — plausible rotación de clave real — así que debe forzar exactamente un
    /// refresh antes de aceptar el token.
    @Test("Forces a JWKS refresh when the token's kid isn't recognized by the cache")
    func refreshesForUnrecognizedKeyID() async throws {
        let keys = JWTKeyCollection()
        let kid = JWKIdentifier(string: "rotated-key")
        await keys.add(hmac: HMACKey(from: "test-secret"), digestAlgorithm: .sha256, kid: kid)
        let token = try await Self.signedToken(keys: keys, kid: kid)

        let jwksSource = RefreshTrackingJWKS(keys: keys, recognizedKeyIDs: [])
        let verifier = BearerTokenVerifier(issuer: Self.issuer, audiences: [Self.resource], allowedAlgorithms: ["HS256"])

        try await Self.withTestApp(jwksSource: jwksSource, verifier: verifier) { app in
            try await app.testing().test(
                .GET, "protected", headers: ["Authorization": "Bearer \(token)"]
            ) { res async throws in
                #expect(res.status == .ok)
            }
        }
        #expect(await jwksSource.forceRefreshCallCount == 1)
    }

    /// Un token expirado, pero con un `kid` que sí está en `recognizedKeyIDs`, no
    /// justifica ningún refresh — el problema es la expiración, no la clave.
    @Test("Does not force a JWKS refresh for an expired token whose kid is already recognized")
    func doesNotRefreshForExpiredTokenWithKnownKeyID() async throws {
        let keys = JWTKeyCollection()
        let kid = JWKIdentifier(string: "known-key")
        await keys.add(hmac: HMACKey(from: "test-secret"), digestAlgorithm: .sha256, kid: kid)
        let token = try await Self.signedToken(keys: keys, expiration: .distantPast, kid: kid)

        let jwksSource = RefreshTrackingJWKS(keys: keys, recognizedKeyIDs: ["known-key"])
        let verifier = BearerTokenVerifier(issuer: Self.issuer, audiences: [Self.resource], allowedAlgorithms: ["HS256"])

        try await Self.withTestApp(jwksSource: jwksSource, verifier: verifier) { app in
            try await app.testing().test(
                .GET, "protected", headers: ["Authorization": "Bearer \(token)"]
            ) { res async throws in
                #expect(res.status == .unauthorized)
            }
        }
        #expect(await jwksSource.forceRefreshCallCount == 0)
    }

    /// Si `RemoteJWKS` no puede resolver las claves (WorkOS caído, red rota...), el token
    /// nunca llega a comprobarse — debe ser un 503, no un 401.
    @Test("Reports 503, not 401, when the JWKS source itself fails")
    func reportsServiceUnavailableWhenJWKSFetchFails() async throws {
        // Token bien formado, aunque `FailingJWKS` nunca llegue a verificarlo contra nada
        // — este test es sobre el fallo al obtener el JWKS, no sobre el token, así que
        // solo necesita una cabecera parseable (una mal formada daría 401 antes de llegar
        // siquiera al fetch del JWKS, terreno de `rejectsUnexpectedAlgorithm`, no de este
        // test).
        let token = try await Self.signedToken(keys: Self.makeKeys())
        let verifier = BearerTokenVerifier(issuer: Self.issuer, audiences: [Self.resource], allowedAlgorithms: ["HS256"])

        try await Self.withTestApp(jwksSource: FailingJWKS(), verifier: verifier) { app in
            try await app.testing().test(
                .GET, "protected", headers: ["Authorization": "Bearer \(token)"]
            ) { res async throws in
                #expect(res.status == .serviceUnavailable)
            }
        }
    }

    @Test("Lets an exempt path through with no token at all")
    func exemptPathBypassesAuth() async throws {
        try await Self.withTestApp(keys: Self.makeKeys()) { app in
            try await app.testing().test(.GET, "health") { res async throws in
                #expect(res.status == .ok)
            }
        }
    }

    /// `configureBearerAuth` attaches exactly one `BearerAuthMiddleware` instance to the
    /// whole `Application`, so it must cover every route a consuming app registers
    /// afterward — regardless of the project's own domain, and regardless of how a given
    /// route was registered. This proves that generically: a plain `app.get` route (the
    /// shape REST handlers typically take) and a route mounted separately via
    /// `app.on(..., body: .collect, use:)` (the shape a second protocol like MCP tends to
    /// take) are both protected by the same middleware instance, and the exempt path
    /// stays exempt with those other protected routes also present.
    @Test("A single globally-attached instance protects every route, however it was mounted, while the exempt path stays exempt")
    func protectsEveryRouteRegardlessOfHowItWasMounted() async throws {
        let keys = await Self.makeKeys()
        let token = try await Self.signedToken(keys: keys)

        try await Self.withTestApp(keys: keys) { app in
            try await app.testing().test(.GET, "protected") { res async throws in
                #expect(res.status == .unauthorized)
            }
            try await app.testing().test(.POST, "second-interface") { res async throws in
                #expect(res.status == .unauthorized)
            }

            try await app.testing().test(
                .GET, "protected", headers: ["Authorization": "Bearer \(token)"]
            ) { res async throws in
                #expect(res.status == .ok)
            }
            try await app.testing().test(
                .POST, "second-interface", headers: ["Authorization": "Bearer \(token)"]
            ) { res async throws in
                #expect(res.status == .ok)
            }

            try await app.testing().test(.GET, "health") { res async throws in
                #expect(res.status == .ok)
            }
        }
    }

    @Test("Discovery endpoint bypass is exact, not a prefix (regression)")
    func discoveryEndpointBypassIsExact() async throws {
        // Our resourceMetadataURL is "https://example.com/.well-known/oauth-protected-resource" in this suite
        try await Self.withTestApp(keys: Self.makeKeys()) { app in
            // Exact match bypasses middleware -> Vapor responds with 404 (because route is not defined in this suite)
            try await app.testing().test(.GET, "/.well-known/oauth-protected-resource") { res async throws in
                #expect(res.status == .notFound) // 404 means it reached the router
            }

            // Prefix match should NOT bypass middleware -> Middleware catches and responds with 401
            try await app.testing().test(.GET, "/.well-known/oauth-protected-resource/mcp") { res async throws in
                #expect(res.status == .unauthorized)
            }
            try await app.testing().test(.GET, "/.well-known/oauth-protected-resource-evil") { res async throws in
                #expect(res.status == .unauthorized)
            }
        }
    }
}
