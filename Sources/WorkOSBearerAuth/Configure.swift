import Vapor

/// Los valores derivados del entorno que necesita `configureBearerAuth`. Leer las
/// llamadas reales a `Environment.get(...)` se deja al propio `configure.swift` de la
/// aplicación consumidora — este tipo solo transporta los valores en crudo — para que:
///
/// 1. Esta librería nunca fije de forma rígida un conjunto concreto de *nombres* de
///    variables de entorno; quien la consume es libre de obtener estos valores como
///    quiera (variables de entorno con cualquier nombre, un gestor de secretos, etc.).
/// 2. La propia lógica de bifurcación de `configureBearerAuth` (más abajo) se pueda
///    ejercitar en tests construyendo directamente distintos valores de
///    `BearerAuthEnvironmentConfig`, en vez de mutar variables de entorno reales del
///    proceso en cada caso de test.
///
/// `workOSResourceIndicatorsRaw` se mantiene como una única cadena separada por comas
/// (el formato propio de WorkOS para `WORKOS_RESOURCE_INDICATORS`) en vez de venir ya
/// dividida en un `Set<String>` — el trabajo de dividir/recortar/comprobar que no esté
/// vacío es analizar el formato de WorkOS, no algo específico del proyecto, así que sigue
/// siendo responsabilidad de esta librería, no de quien la consume.
public struct BearerAuthEnvironmentConfig: Sendable {
    /// Vía de escape para desactivar la autenticación fuera de producción (tests locales,
    /// entornos de desarrollo sin WorkOS a mano). `configureBearerAuth` la rechaza en
    /// `.production`.
    public let authDisabled: Bool
    /// La URL del issuer de WorkOS AuthKit (p. ej. `https://tu-proyecto.authkit.app`).
    /// Debe ser una URL absoluta `https://` con host — `configureBearerAuth` la valida
    /// antes de usarla.
    public let workOSIssuer: String?
    /// El valor en crudo, tal cual, de `WORKOS_RESOURCE_INDICATORS`: uno o varios
    /// indicadores de recurso separados por comas (p. ej.
    /// `"https://api.example.com/mcp,http://localhost:8080/mcp"`). `configureBearerAuth`
    /// se encarga de dividirlo, recortar espacios y validar cada valor.
    public let workOSResourceIndicatorsRaw: String?

    /// Crea la configuración de entrada para ``configureBearerAuth(_:environment:)``.
    public init(authDisabled: Bool, workOSIssuer: String?, workOSResourceIndicatorsRaw: String?) {
        self.authDisabled = authDisabled
        self.workOSIssuer = workOSIssuer
        self.workOSResourceIndicatorsRaw = workOSResourceIndicatorsRaw
    }
}

/// Registra `BearerAuthMiddleware` de forma global (para que REST y `/mcp` compartan un
/// único camino de autenticación) y la ruta de descubrimiento RFC 9728 (OAuth Protected
/// Resource Metadata) que necesita.
///
/// Cuatro casos, según `environment`:
/// 1. `.testing` — se salta incondicionalmente, sin importar lo que lleve `environment`.
///    El propio `.env.local` de una app consumidora puede llevar credenciales reales de
///    staging de WorkOS para `swift run`, así que una comprobación de variables de
///    entorno por sí sola no basta para mantener `swift test` libre de una dependencia de
///    red real contra el endpoint JWKS de WorkOS. `BearerAuthMiddleware` en sí se sigue
///    ejercitando de extremo a extremo en los propios tests de esta librería — ver
///    `BearerAuthMiddlewareTests`, que lo monta con un `JWKSSource` local sin red en vez
///    del `RemoteJWKS` real.
/// 2. `environment.authDisabled` en producción — se niega a arrancar. Una vía de escape
///    pensada solo para tests nunca debe llegar en silencio a un despliegue real.
/// 3. `environment.authDisabled` fuera de producción, o ni `authDisabled` ni
///    `workOSIssuer`/`workOSResourceIndicatorsRaw` están fijados — la autenticación se
///    desactiva con un aviso bien visible, en vez de que todas las rutas queden
///    silenciosamente accesibles sin ninguna señal.
/// 4. `workOSIssuer`/`workOSResourceIndicatorsRaw` fijados — se exige una validación real
///    de JWT/JWKS, también en producción, donde es obligatoria (si falta la
///    configuración, lanza un error).
///
/// - Throws: `authDisabledInProduction`, `missingWorkOSEnvironment`, o
///   `emptyResourceIndicators` (los tres son privados a este módulo — quien consuma la
///   librería y quiera registrar o propagar el fallo no necesita distinguir el caso
///   concreto).
public func configureBearerAuth(_ app: Application, environment: BearerAuthEnvironmentConfig) throws {
    guard app.environment != .testing else {
        app.logger.warning("Running in .testing — skipping bearer auth regardless of WorkOS environment.")
        return
    }

    if environment.authDisabled {
        guard app.environment != .production else {
            throw ConfigurationError.authDisabledInProduction
        }
        app.logger.warning("Bearer auth disabled — REST and MCP requests are not authenticated.")
        return
    }

    guard
        let issuer = environment.workOSIssuer,
        let resourceIndicatorsRaw = environment.workOSResourceIndicatorsRaw
    else {
        guard app.environment != .production else {
            throw ConfigurationError.missingWorkOSEnvironment
        }
        app.logger.warning(
            """
            WorkOS issuer/resource indicators are not set and auth is not explicitly \
            disabled — treating authentication as disabled for this non-production run. \
            Set both WorkOS values, or disable auth explicitly, to silence this warning.
            """
        )
        return
    }
    
    guard let issuerURL = URL(string: issuer), issuerURL.scheme == "https", issuerURL.host != nil else {
        throw ConfigurationError.invalidIssuer
    }

    let parsedIndicators = resourceIndicatorsRaw.split(separator: ",")
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .filter { !$0.isEmpty }

    guard !parsedIndicators.isEmpty else {
        throw ConfigurationError.emptyResourceIndicators
    }
    
    for resourceIndicator in parsedIndicators {
        guard let url = URL(string: resourceIndicator), url.scheme == "https", url.host != nil else {
            throw ConfigurationError.invalidResourceIndicator
        }
    }

    // Se conserva el orden para elegir el indicador primario de forma determinista
    let primaryResourceIndicator = parsedIndicators.first!
    let resourceIndicators = Set(parsedIndicators)

    let jwksURL = URI(string: issuer + "/oauth2/jwks")
    let remoteJWKS = RemoteJWKS(jwksURL: jwksURL, client: app.client)
    let verifier = makeProductionBearerTokenVerifier(issuer: issuer, audiences: resourceIndicators)
    let resourceMetadataURL = oauthProtectedResourceDiscoveryURL(for: primaryResourceIndicator)

    app.middleware.use(
        BearerAuthMiddleware(jwksSource: remoteJWKS, verifier: verifier, resourceMetadataURL: resourceMetadataURL)
    )

    let metadata = OAuthProtectedResourceMetadata(
        resource: primaryResourceIndicator,
        authorizationServers: [issuer],
        bearerMethodsSupported: ["header"]
    )

    // RFC 9728: el endpoint de descubrimiento incorpora el path del recurso, si tiene uno.
    var discoveryPathComponents: [PathComponent] = [".well-known", "oauth-protected-resource"]
    if let url = URL(string: primaryResourceIndicator) {
        let trimmedPath = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        if !trimmedPath.isEmpty {
            discoveryPathComponents.append(contentsOf: trimmedPath.split(separator: "/").map { PathComponent(stringLiteral: String($0)) })
        }
    }
    app.get(discoveryPathComponents) { _ in metadata }

    app.logger.info("Bearer authentication enabled — issuer: \(issuer), resources: \(resourceIndicators)")
}

/// Construye el `BearerTokenVerifier` de producción — extraído de `configureBearerAuth`
/// para que un test pueda comprobar su política (algoritmo, exigencia de `kid`)
/// directamente, sin tener que lidiar con el cortocircuito de `.testing` de la propia
/// `configureBearerAuth`. No pasa ni `allowedAlgorithms` ni `requiresKeyID` a propósito —
/// producción recibe siempre los valores por defecto del propio `BearerTokenVerifier`
/// (solo RS256, `kid` obligatorio). Si esta función alguna vez incorpora esos parámetros,
/// `productionVerifierUsesDefaultPolicy` en `BearerTokenVerifierTests` debería fallar de
/// forma ruidosa en vez de relajar la política en silencio.
func makeProductionBearerTokenVerifier(issuer: String, audiences: Set<String>) -> BearerTokenVerifier {
    BearerTokenVerifier(issuer: issuer, audiences: audiences)
}

/// `GET /.well-known/oauth-protected-resource` — OAuth 2.0 Protected Resource Metadata
/// (RFC 9728), para que un cliente MCP que reciba un 401 de `/mcp` pueda descubrir a qué
/// Authorization Server (WorkOS) redirigir al usuario, sin que un humano tenga que pegar
/// un token a mano.
struct OAuthProtectedResourceMetadata: Content {
    let resource: String
    let authorizationServers: [String]
    let bearerMethodsSupported: [String]

    enum CodingKeys: String, CodingKey {
        case resource
        case authorizationServers = "authorization_servers"
        case bearerMethodsSupported = "bearer_methods_supported"
    }
}

/// Construye la URL de descubrimiento RFC 9728 a partir de un resource indicator, p. ej.
/// `https://api.example.com/mcp` → `https://api.example.com/.well-known/oauth-protected-resource/mcp`.
/// Toma el scheme+host (sin el path) del resource indicator y, si este tenía un path,
/// inserta `.well-known/oauth-protected-resource` entre el host y ese path.
private func oauthProtectedResourceDiscoveryURL(for resourceIndicator: String) -> String {
    guard let url = URL(string: resourceIndicator),
        let scheme = url.scheme, let host = url.host
    else {
        return resourceIndicator
    }
    let port = url.port.map { ":\($0)" } ?? ""
    let path = url.path.isEmpty ? "" : url.path
    return "\(scheme)://\(host)\(port)/.well-known/oauth-protected-resource\(path)"
}

/// Errores que pueden ocurrir al configurar la autenticación Bearer. No es public: quien
/// consuma la librería y quiera registrar o propagar el fallo trabaja con `any Error`, y
/// no necesita distinguir el caso concreto.
enum ConfigurationError: Error, CustomStringConvertible {
    /// La autenticación estaba desactivada mientras se ejecutaba en el entorno `.production`.
    case authDisabledInProduction
    /// Se ejecuta en `.production` sin issuer/resource indicators de WorkOS y sin haber
    /// desactivado la autenticación explícitamente.
    case missingWorkOSEnvironment
    /// `workOSResourceIndicatorsRaw` estaba fijado pero ha quedado vacío tras dividirlo por comas.
    case emptyResourceIndicators
    /// El issuer de WorkOS proporcionado no es una URL absoluta válida.
    case invalidIssuer
    /// Uno o más de los resource indicators proporcionados no son URLs absolutas válidas.
    case invalidResourceIndicator

    var description: String {
        switch self {
        case .authDisabledInProduction:
            return "Disabling bearer auth is not allowed when the environment is production."
        case .missingWorkOSEnvironment:
            return "Missing WorkOS configuration: set both the issuer and resource indicators, " +
                "or disable auth explicitly outside production."
        case .emptyResourceIndicators:
            return "workOSResourceIndicatorsRaw is set but contains no valid values."
        case .invalidIssuer:
            return "workOSIssuer must be a valid absolute HTTPS URL."
        case .invalidResourceIndicator:
            return "Each workOSResourceIndicator must be a valid absolute HTTPS URL."
        }
    }
}
