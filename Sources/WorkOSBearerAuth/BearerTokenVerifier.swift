import JWTKit

/// Verifica el algoritmo, la firma, el issuer, la audiencia, la caducidad y (cuando está
/// presente) el not-before de un JWT contra una colección de claves dada. Este *no* es el
/// sitio donde se analiza la propia cabecera `Authorization: Bearer <token>` —
/// `BearerAuthMiddleware` retira el prefijo `Bearer ` antes de llamar siquiera a este
/// tipo; `verify(_:using:)` solo llega a ver la cadena JWT en crudo. Recibe la
/// `JWTKeyCollection` como parámetro de forma deliberada, en vez de poseer un
/// ``RemoteJWKS`` propio, para que los tests puedan ejercitar la lógica de verificación
/// real — la parte que de verdad importa para la seguridad — contra una clave de prueba
/// generada localmente, sin ninguna dependencia de red con WorkOS. ``RemoteJWKS`` (la
/// obtención/caché de las claves reales por HTTP) y las comprobaciones de claims de este
/// tipo son, deliberadamente, responsabilidades separadas.
///
/// Internal, no public: nada fuera de este módulo necesita construir uno o llamarlo
/// directamente — `configureBearerAuth` es el único punto de llamada en producción, y el
/// target de tests llega hasta aquí vía `@testable import`.
struct BearerTokenVerifier: Sendable {
    let issuer: String
    let audiences: Set<String>

    /// Los únicos algoritmos de firma en los que confía esta aplicación, comprobados
    /// contra la cabecera (todavía sin verificar) del propio token *antes* de cualquier
    /// comprobación de firma. WorkOS AuthKit firma los access tokens con RS256
    /// (https://workos.com/guide/jwt-validation) — fijado aquí de forma explícita en vez
    /// de confiar implícitamente en el algoritmo que `JWTKeyCollection` elegiría para un
    /// `kid` coincidente, de modo que un token cuya cabecera declare un algoritmo
    /// inesperado se rechaza sin más. Se puede sobreescribir por instancia para que los
    /// tests ejerciten esta misma ruta de código contra fixtures HMAC firmados
    /// localmente, en vez de un par de claves RSA real. `let`, no `var` — la política de
    /// un verifier no cambia una vez construido.
    let allowedAlgorithms: Set<String>

    /// Si un token sin cabecera `kid` se rechaza directamente, en vez de recurrir a la
    /// clave que `JWTKeyCollection` trate como su valor por defecto. `true` en
    /// producción: con rotación de claves real (más de una clave de firma de WorkOS viva
    /// a la vez), un token legítimo siempre lleva `kid` — uno que no lo lleve está
    /// malformado o ha sido manipulado, y "probar la clave por defecto a ver si la firma
    /// cuadra" es exactamente el tipo de comportamiento implícito y dependiente de la
    /// librería en el que una política de tokens Bearer no debería apoyarse. Se puede
    /// sobreescribir por instancia por el mismo motivo que `allowedAlgorithms`.
    let requiresKeyID: Bool

    /// - Precondition: `allowedAlgorithms` no puede estar vacío. Un conjunto vacío no es
    ///   una política más estricta — es un verifier que rechaza todos los tokens
    ///   incondicionalmente, y en silencio: nada en los 401 de `verify(_:using:)` diría
    ///   que la causa real es una lista de algoritmos permitidos mal configurada. Esto
    ///   solo puede ocurrir por un error fijado en el propio código fuente (el único
    ///   punto de llamada en producción, `makeProductionBearerTokenVerifier`, nunca
    ///   sobreescribe el valor por defecto), así que falla aquí de forma ruidosa en vez
    ///   de hacerlo calladamente en tiempo de petición.
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

    /// Decodifica (sin verificar) la cabecera de un token. La comparten tanto la propia
    /// comprobación de algoritmo de este tipo, más abajo, como la decisión de
    /// `BearerAuthMiddleware` sobre si un `kid` no reconocido justifica un refresco
    /// forzado del JWKS, de modo que la cabecera se analiza en un único sitio en vez de en
    /// dos implementaciones independientes que podrían acabar divergiendo.
    func header(of token: String) throws -> JWTHeader {
        try DefaultJWTParser().parse([UInt8](token.utf8), as: WorkOSClaims.self).header
    }

    /// Verifica `token` contra `keys`, analizando su cabecera por sí mismo. Prefiere
    /// `verify(_:header:using:)` cuando quien llama ya ha analizado la cabecera por otro
    /// motivo (p. ej. la comprobación de `kid` de `BearerAuthMiddleware`), para evitar
    /// analizarla dos veces.
    func verify(_ token: String, using keys: JWTKeyCollection) async throws -> WorkOSClaims {
        try await verify(token, header: header(of: token), using: keys)
    }

    /// Verifica `token` contra `keys`, reutilizando una `header` ya analizada en vez de
    /// volver a decodificarla.
    ///
    /// - Throws: ``BearerTokenError`` si el algoritmo, el issuer o la audiencia no son
    ///   correctos; o lo que sea que lancen `JWTKeyCollection.verify` /
    ///   `WorkOSClaims.verify(using:)` ante una firma incorrecta, un `kid` desconocido, o
    ///   un token caducado o todavía no válido.
    func verify(_ token: String, header: JWTHeader, using keys: JWTKeyCollection) async throws -> WorkOSClaims {
        guard let alg = header.alg, allowedAlgorithms.contains(alg) else {
            throw BearerTokenError.unexpectedAlgorithm(header.alg)
        }
        guard !requiresKeyID || header.kid != nil else {
            throw BearerTokenError.missingKeyID
        }

        // `keys.verify` invoca a `WorkOSClaims.verify(using:)` como parte de la
        // verificación, que comprueba `exp` y (cuando está presente) `nbf` — la única
        // fuente de verdad para esas dos cosas, no duplicada aquí. Este tipo es dueño de
        // la política de la aplicación (algoritmo, issuer, audiencia); `WorkOSClaims` es
        // dueño de la validez temporal propia del token.
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

/// Errores que puede producir la verificación de un token Bearer durante una petición.
/// Todos ellos terminan en una respuesta 401 con cabecera `WWW-Authenticate` — nunca en
/// un 503, porque en todos estos casos el token sí ha llegado a comprobarse.
enum BearerTokenError: Error, CustomStringConvertible {
    /// Falta la cabecera `Authorization: Bearer …`, o no tiene el formato esperado.
    case missingBearerToken
    /// El algoritmo declarado en la cabecera del token no está en `allowedAlgorithms`.
    case unexpectedAlgorithm(String?)
    /// El token no lleva `kid` y el verifier lo exige (`requiresKeyID == true`).
    case missingKeyID
    /// El `iss` del token no coincide con el issuer configurado.
    case unexpectedIssuer(String)
    /// El `aud` del token no coincide con ninguno de los resource indicators configurados.
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
