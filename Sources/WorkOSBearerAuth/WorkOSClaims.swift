import JWTKit

/// Las claims de un access token de WorkOS AuthKit de las que depende esta aplicación.
///
/// `iss`/`aud` los comprueba explícitamente `BearerTokenVerifier` contra el issuer
/// configurado y las audiencias aceptadas (resource indicators) — no dentro de
/// ``verify(using:)`` — porque esos valores esperados son configuración de tiempo de
/// ejecución (distinta en cada entorno), algo que este tipo no puede conocer por sí
/// mismo.
///
/// `nbf` es opcional según el RFC 7519 §4.1.5 — WorkOS documenta que se comprueba "si
/// está presente", en vez de garantizar que siempre se emite
/// (https://workos.com/guide/jwt-validation) — se decodifica aquí para que
/// ``verify(using:)`` pueda exigirlo igualmente cuando aparece, en vez de dejar pasar un
/// token que todavía no es válido solo porque este tipo nunca llegó a mirar esa claim.
///
/// Public (y también sus propiedades) porque `Request.authenticatedClaims` — lo único
/// que lee una aplicación consumidora — devuelve este tipo directamente; nada fuera de
/// este módulo construye uno nunca, así que no hace falta un inicializador público.
public struct WorkOSClaims: JWTPayload, Sendable {
    /// El emisor del token — la URL del issuer de WorkOS AuthKit. Ver `BearerTokenVerifier`.
    public let iss: IssuerClaim
    /// Para qué recurso(s) es válido este token (los resource indicators). Ver `BearerTokenVerifier`.
    public let aud: AudienceClaim
    /// El instante a partir del cual el token deja de ser válido.
    public let exp: ExpirationClaim
    /// El instante a partir del cual el token empieza a ser válido, si WorkOS lo incluyó.
    public let nbf: NotBeforeClaim?
    /// El identificador del usuario autenticado.
    public let sub: SubjectClaim

    public func verify(using key: some JWTAlgorithm) throws {
        try exp.verifyNotExpired()
        try nbf?.verifyNotBefore()
    }
}
