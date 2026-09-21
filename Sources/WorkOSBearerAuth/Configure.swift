import Vapor

/// La configuración de entrada de ``configureBearerAuth(_:environment:)``. Un `enum`, no un
/// struct con campos sueltos, para que las combinaciones sin sentido (un issuer de WorkOS
/// con la excepción de loopback activada, o un issuer local sin ninguna forma de saber que
/// lo es) no se puedan ni construir — cada caso lleva exactamente los datos que le hacen
/// falta a esa configuración concreta, ni uno más.
///
/// Los valores en crudo (issuer, resource indicators) se pasan tal cual, sin leer
/// `Environment.get(...)` dentro de esta librería — eso se deja al propio `configure.swift`
/// de la aplicación consumidora — para que:
///
/// 1. Esta librería nunca fije de forma rígida un conjunto concreto de *nombres* de
///    variables de entorno; quien la consume es libre de obtener estos valores como
///    quiera (variables de entorno con cualquier nombre, un gestor de secretos, etc.).
/// 2. La propia lógica de bifurcación de `configureBearerAuth` (más abajo) se pueda
///    ejercitar en tests construyendo directamente distintos valores de
///    `BearerAuthEnvironmentConfig`, en vez de mutar variables de entorno reales del
///    proceso en cada caso de test.
public enum BearerAuthEnvironmentConfig: Sendable {
    /// Ninguna configuración de WorkOS disponible. Fuera de producción, la autenticación
    /// queda desactivada con un aviso; en producción, `configureBearerAuth` se niega a
    /// arrancar (`missingWorkOSEnvironment`) — no hay ninguna vía de escape explícita para
    /// desactivarla ahí.
    case disabled
    /// Un issuer real de WorkOS AuthKit (p. ej. `https://tu-proyecto.authkit.app`) — debe
    /// ser una URL absoluta `https://` con host, sin excepción. El único caso permitido en
    /// producción, donde además es el único que `configureBearerAuth` acepta.
    ///
    /// `resourceIndicatorsRaw` es el valor en crudo, tal cual, de
    /// `WORKOS_RESOURCE_INDICATORS`: uno o varios indicadores de recurso separados por comas
    /// (p. ej. `"https://api.example.com/mcp,https://api.example.com/rest"`).
    /// `configureBearerAuth` se encarga de dividirlo, recortar espacios y validar cada
    /// valor — siempre `https://`, sin excepción, también bajo `.local`.
    case workOS(issuer: String, resourceIndicatorsRaw: String)
    /// Un `AuthMock`/servidor de prueba real corriendo en la misma máquina, en
    /// `http://127.0.0.1:<port>` — nunca para desarrollo general ni para exponer tu propia
    /// API por HTTP. El host no es un parámetro: siempre `127.0.0.1`, nunca `localhost` ni
    /// nada configurable, así que no hace falta parsear ni validar ningún issuer para
    /// confirmar que de verdad es loopback — este caso ya lo garantiza por construcción.
    /// `configureBearerAuth` rechaza este caso en `.production` (`localConfigInProduction`),
    /// para que la excepción no dependa solo de que nadie la active por error en un
    /// despliegue real.
    ///
    /// A diferencia de `.disabled`/`.workOS`, este es el único caso que **sí** registra
    /// `BearerAuthMiddleware` incluso bajo `app.environment == .testing` — por construcción
    /// nunca habla con el JWKS real de WorkOS, así que el motivo por el que `.testing` se
    /// salta los otros dos casos (evitar una dependencia de red real durante `swift test`)
    /// no aplica aquí. Esto permite que una suite E2E en proceso, montada con
    /// `Application.make(.testing)`, ejercite la verificación de tokens de verdad contra un
    /// `AuthMock` efímero arrancado junto a ella — ver <doc:10-GuiaDeTesting>.
    case local(port: Int, resourceIndicatorsRaw: String)
}

/// Registra `BearerAuthMiddleware` de forma global (para que REST y `/mcp` compartan un
/// único camino de autenticación) y la ruta de descubrimiento RFC 9728 (OAuth Protected
/// Resource Metadata) que necesita.
///
/// Cuatro casos: el cortocircuito de `.testing`, más los tres de ``BearerAuthEnvironmentConfig``.
/// 1. `.testing` — se salta incondicionalmente para ``BearerAuthEnvironmentConfig/disabled``
///    y ``BearerAuthEnvironmentConfig/workOS(issuer:resourceIndicatorsRaw:)``, sin importar
///    qué credenciales lleven. El propio `.env.local` de una app consumidora puede llevar
///    credenciales reales de staging de WorkOS para `swift run`, así que una comprobación
///    de variables de entorno por sí sola no basta para mantener `swift test` libre de una
///    dependencia de red real contra el endpoint JWKS de WorkOS. `BearerAuthMiddleware` en
///    sí se sigue ejercitando de extremo a extremo en los propios tests de esta librería —
///    ver `BearerAuthMiddlewareTests`, que lo monta con un `JWKSSource` local sin red en
///    vez del `RemoteJWKS` real. Este cortocircuito **no** aplica a
///    ``BearerAuthEnvironmentConfig/local(port:resourceIndicatorsRaw:)`` — ver el porqué en
///    su propio doc comment.
/// 2. ``BearerAuthEnvironmentConfig/disabled`` — en producción se niega a arrancar
///    (`missingWorkOSEnvironment`); fuera de producción, la autenticación se desactiva con
///    un aviso bien visible, en vez de que todas las rutas queden silenciosamente
///    accesibles sin ninguna señal.
/// 3. ``BearerAuthEnvironmentConfig/workOS(issuer:resourceIndicatorsRaw:)`` — se exige una
///    validación real de JWT/JWKS, en cualquier entorno, incluida producción.
/// 4. ``BearerAuthEnvironmentConfig/local(port:resourceIndicatorsRaw:)`` — igual que el
///    caso anterior, pero contra `http://127.0.0.1:<port>` en vez de un issuer `https://`.
///    Lanza `localConfigInProduction` si `app.environment == .production`.
///
/// - Throws: `missingWorkOSEnvironment`, `localConfigInProduction`, `emptyResourceIndicators`,
///   o `invalidResourceIndicator` (todos privados a este módulo — quien consuma la librería
///   y quiera registrar o propagar el fallo no necesita distinguir el caso concreto).
public func configureBearerAuth(_ app: Application, environment: BearerAuthEnvironmentConfig) throws {
    // Narrowed to `.disabled`/`.workOS`: `.local` only ever talks to a loopback mock, by
    // construction, so the real-network rationale for skipping under `.testing` doesn't
    // apply to it — it falls through to the switch below and registers for real.
    if app.environment == .testing {
        switch environment {
        case .disabled, .workOS:
            app.logger.warning("Running in .testing — skipping bearer auth regardless of WorkOS environment.")
            return
        case .local:
            break
        }
    }

    let issuer: String
    let resourceIndicatorsRaw: String

    switch environment {
    case .disabled:
        guard app.environment != .production else {
            throw ConfigurationError.missingWorkOSEnvironment
        }
        app.logger.warning(
            """
            No WorkOS configuration was provided (BearerAuthEnvironmentConfig.disabled) — \
            treating authentication as disabled for this non-production run.
            """
        )
        return

    case .workOS(let workOSIssuer, let workOSResourceIndicatorsRaw):
        guard let issuerURL = URL(string: workOSIssuer), issuerURL.scheme == "https", issuerURL.host != nil else {
            throw ConfigurationError.invalidIssuer
        }
        issuer = workOSIssuer
        resourceIndicatorsRaw = workOSResourceIndicatorsRaw

    case .local(let port, let localResourceIndicatorsRaw):
        guard app.environment != .production else {
            throw ConfigurationError.localConfigInProduction
        }
        issuer = "http://127.0.0.1:\(port)"
        resourceIndicatorsRaw = localResourceIndicatorsRaw
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
    /// Se ejecuta en `.production` con `BearerAuthEnvironmentConfig.disabled`.
    case missingWorkOSEnvironment
    /// Se ejecuta en `.production` con `BearerAuthEnvironmentConfig.local` — solo `.workOS`
    /// está permitido ahí.
    case localConfigInProduction
    /// `resourceIndicatorsRaw` estaba fijado pero ha quedado vacío tras dividirlo por comas.
    case emptyResourceIndicators
    /// El issuer de WorkOS proporcionado no es una URL absoluta `https://` con host.
    case invalidIssuer
    /// Uno o más de los resource indicators proporcionados no son URLs absolutas `https://`
    /// con host.
    case invalidResourceIndicator

    var description: String {
        switch self {
        case .missingWorkOSEnvironment:
            return "Missing WorkOS configuration: pass .workOS in production, " +
                "or .disabled/.local outside production."
        case .localConfigInProduction:
            return "BearerAuthEnvironmentConfig.local is not allowed when the environment is " +
                "production — use .workOS."
        case .emptyResourceIndicators:
            return "resourceIndicatorsRaw is set but contains no valid values."
        case .invalidIssuer:
            return "workOS issuer must be a valid absolute HTTPS URL."
        case .invalidResourceIndicator:
            return "Each resource indicator must be a valid absolute HTTPS URL."
        }
    }
}
