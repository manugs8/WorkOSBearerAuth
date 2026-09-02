import JWTKit
import Vapor

/// Exige un token Bearer válido en cualquier ruta salvo las rutas exentas de abajo —
/// aplicado de forma global para que REST y `/mcp` compartan un único camino de
/// autenticación, en vez de que REST no tuviera ninguno (como antes) y `/mcp` tuviera su
/// propio mecanismo separado.
///
/// Lo registra `configureBearerAuth` con un ``RemoteJWKS`` respaldado por credenciales
/// reales de WorkOS — y se salta incondicionalmente en `.testing`, para que las suites de
/// test REST/MCP de una app consumidora no necesiten esas credenciales. `jwksSource` está
/// tipado como ``JWKSSource`` en vez de como el `RemoteJWKS` concreto para que
/// `BearerAuthMiddlewareTests` pueda seguir ejercitando este middleware de extremo a
/// extremo contra una colección de claves local.
///
/// Internal, no public: `configureBearerAuth` es el único punto de llamada en producción,
/// y nada fuera de este módulo necesita construir uno directamente.
struct BearerAuthMiddleware: AsyncMiddleware {
    /// Rutas que permanecen públicas: `/health` para que un healthcheck de la plataforma
    /// (que no puede autenticarse) siga funcionando, `/docs`/`/openapi.yaml` porque son
    /// documentación, no datos. El endpoint de descubrimiento también está exento, pero se
    /// compara de forma exacta a través de `exemptWellKnownPath`.
    static let exemptPaths: Set<String> = [
        "/health", "/docs", "/openapi.yaml"
    ]

    let jwksSource: any JWKSSource
    let verifier: BearerTokenVerifier
    let resourceMetadataURL: String
    private let exemptWellKnownPath: String

    init(jwksSource: any JWKSSource, verifier: BearerTokenVerifier, resourceMetadataURL: String) {
        self.jwksSource = jwksSource
        self.verifier = verifier
        self.resourceMetadataURL = resourceMetadataURL
        if let url = URL(string: resourceMetadataURL) {
            self.exemptWellKnownPath = url.path.isEmpty ? "" : url.path
        } else {
            self.exemptWellKnownPath = "/.well-known/oauth-protected-resource"
        }
    }

    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let path = request.url.path
        let isExempt = Self.exemptPaths.contains(path) || path == exemptWellKnownPath
        guard !isExempt else {
            return try await next.respond(to: request)
        }

        let token: String
        let header: JWTHeader
        do {
            token = try bearerToken(from: request)
            // Se analiza una sola vez, aquí, y se reutiliza más abajo tanto para la
            // decisión de refresco basada en `kid` como para la llamada real a
            // `verify(_:header:using:)` — en vez de un `try?` que la volviera a analizar
            // para la comprobación de refresco y tragase en silencio una cabecera mal
            // formada, dejando que `verify` lo detectase en un segundo análisis separado.
            header = try verifier.header(of: token)
        } catch {
            request.logger.notice("Rejected unauthenticated request to \(request.url.path): \(error)")
            return unauthorizedResponse()
        }

        var keys: JWTKeyCollection
        do {
            keys = try await jwksSource.currentKeys(forceRefresh: false)
            // Solo se refresca cuando el `kid` del propio token no es uno que esta caché
            // reconozca — la única situación que plausiblemente significa que WorkOS ha
            // rotado su clave de firma desde nuestra última consulta. Deliberadamente
            // *no* se hace un catch-and-retry alrededor del `verify` de más abajo: eso
            // forzaría una consulta al JWKS por cada token rechazado sin importar la causa
            // (firma incorrecta, caducado, issuer/audiencia/algoritmo equivocados),
            // permitiendo que un atacante provocase repetidas consultas remotas baratas
            // sin más que enviar basura.
            if let kid = header.kid, await !jwksSource.hasKey(kid: kid) {
                keys = try await jwksSource.currentKeys(forceRefresh: true)
            }
        } catch {
            // El token en sí nunca ha llegado a evaluarse aquí — esto es que WorkOS o la
            // red no están disponibles, no que el token sea inválido. Responder 401
            // afirmaría que sabemos que el token es incorrecto, cuando en realidad no ha
            // podido ni comprobarse; 503 (a través del propio ErrorMiddleware de Vapor,
            // igual que cualquier otro fallo de infraestructura) transmite lo correcto —
            // inténtalo de nuevo — en vez de decirle a un cliente legítimo que su token es
            // incorrecto.
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
        // Publica las claims validadas en `request.storage` para que lo lea lo que sea que
        // esta petición acabe invocando — el porqué está en el comentario de documentación
        // de `Request.authenticatedClaims`. Deliberadamente fuera de todos los `do`
        // anteriores: una vez que el token en sí es correcto, cualquier error que lance el
        // handler (p. ej. un fallo de base de datos) debe propagarse tal cual hacia el
        // propio ErrorMiddleware de Vapor (→ 500), no ser reetiquetado como un 401 por
        // este middleware.
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
