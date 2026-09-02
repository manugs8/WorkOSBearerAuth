import JWTKit
import NIOCore
import Vapor

/// De dónde obtiene ``BearerAuthMiddleware`` la `JWTKeyCollection` contra la que verifica
/// los tokens. Está extraído para que los tests puedan darle al middleware una colección
/// de claves local, ya construida (sin red, sin credenciales reales de WorkOS) en vez del
/// ``RemoteJWKS`` real — ver `BearerAuthMiddlewareTests`.
protocol JWKSSource: Sendable {
    func currentKeys(forceRefresh: Bool) async throws -> JWTKeyCollection

    /// Si el conjunto de claves actualmente en caché reconoce este `kid`. Permite que
    /// ``BearerAuthMiddleware`` decida forzar un refresco solo cuando aparece un `kid`
    /// que todavía no conoce (una plausible rotación de clave) — no ante cualquier fallo
    /// de verificación, lo que permitiría a un atacante forzar consultas JWKS
    /// innecesarias sin más que enviar tokens basura.
    func hasKey(kid: String) async -> Bool
}

/// Obtiene y cachea el JSON Web Key Set publicado en una URL remota (el
/// `<issuer>/oauth2/jwks` de WorkOS AuthKit), refrescándolo de forma periódica y bajo
/// demanda.
///
/// Es un actor porque la ``JWTKeyCollection`` cacheada la mutan peticiones concurrentes —
/// cada petición que llega a una ruta protegida llama aquí para obtener las claves
/// actuales.
actor RemoteJWKS: JWKSSource {
    /// Límite defensivo sobre el cuerpo de la respuesta del JWKS. El JWKS de WorkOS es
    /// diminuto en la práctica (un puñado de claves, como mucho unos pocos KB) — cualquier
    /// cosa que se acerque a este tamaño significa que algo va mal (una URL mal dirigida,
    /// una página de error en vez de JSON, WorkOS sirviendo algo inesperado), así que se
    /// rechaza sin más en vez de volcarlo en un `String` y pasárselo al decodificador JSON.
    private static let maxResponseBytes = 1_048_576  // 1 MiB

    private let jwksURL: URI
    private let client: any Client
    private let refreshInterval: TimeInterval
    /// Cuánto tiempo puede tardar como máximo una única consulta al JWKS antes de darse
    /// por fallida. Esto está en pleno camino de autenticación — cualquier petición que
    /// necesite un refresco (una caché vacía/caducada, o un `kid` no reconocido) espera a
    /// que termine — así que necesita su propio límite corto y explícito, en vez de
    /// depender de cuál sea el valor por defecto (si tiene alguno) del propio `client`.
    private let fetchTimeout: TimeAmount
    private let forcedRefreshCooldown: TimeInterval

    private var keys = JWTKeyCollection()
    /// Se lleva por separado de `keys`: `JWTKeyCollection` no tiene ninguna forma pública
    /// de preguntar "¿reconoces este `kid`?" sin recurrir también a un firmante por
    /// defecto cuando no lo reconoce, lo que anularía el propósito de `hasKey(kid:)`.
    private var knownKeyIDs: Set<String> = []
    private var lastFetchedAt: Date?
    private var lastAttemptedAt: Date?
    /// El refresco en curso, si lo hay — ver `refreshOnce()`.

    private var refreshTask: Task<Void, any Error>?

    init(
        jwksURL: URI, client: any Client, refreshInterval: TimeInterval = 3600,
        fetchTimeout: TimeAmount = .seconds(5),
        forcedRefreshCooldown: TimeInterval = 30
    ) {
        self.jwksURL = jwksURL
        self.client = client
        self.refreshInterval = refreshInterval
        self.fetchTimeout = fetchTimeout
        self.forcedRefreshCooldown = forcedRefreshCooldown
    }

    /// La colección de claves actual, refrescándola primero si la caché está vacía,
    /// caducada, o si se indica `forceRefresh`.
    func currentKeys(forceRefresh: Bool = false) async throws -> JWTKeyCollection {
        let isStale = lastFetchedAt.map { Date().timeIntervalSince($0) > refreshInterval } ?? true
        if isStale || forceRefresh {
            try await refreshOnce()
        }
        
        if lastFetchedAt == nil {
            throw Abort(.serviceUnavailable, reason: "JWKS is unavailable and fetch is on cooldown.")
        }
        return keys
    }

    func hasKey(kid: String) -> Bool {
        knownKeyIDs.contains(kid)
    }

    /// Fusiona las peticiones de refresco concurrentes en una única consulta en curso. El
    /// aislamiento del actor, por sí solo, no evita aquí duplicar consultas: `refresh()`
    /// espera una respuesta HTTP, y mientras está suspendida otra llamada puede volver a
    /// entrar en este actor, ver que `lastFetchedAt` sigue caducado (la primera consulta
    /// no ha terminado todavía), y lanzar una segunda petición redundante a WorkOS — una
    /// estampida (thundering herd) justo en el momento en que la caché expira bajo
    /// tráfico real. Unirse al mismo `Task` en vez de lanzar otros en paralelo evita esto.
    /// `refreshTask` lo limpia el `defer` de la invocación que lo haya creado — solo la
    /// rama de más abajo que de verdad crea la tarea llega a ejecutar ese `defer`;
    /// cualquier otra llamada concurrente devuelve el control antes, desde el `if let` de
    /// arriba, sin llegar a registrar ninguno.
    private func refreshOnce() async throws {
        if let refreshTask {
            return try await refreshTask.value
        }
        
        let isCoolingDown = lastAttemptedAt.map { Date().timeIntervalSince($0) < forcedRefreshCooldown } ?? false
        if isCoolingDown {
            return
        }
        
        let task = Task { 
            lastAttemptedAt = Date()
            try await self.refresh() 
        }
        refreshTask = task
        defer { refreshTask = nil }
        try await task.value
    }

    private func refresh() async throws {
        // Se captura primero en una variable local: el closure `beforeSend` de más abajo
        // se ejecuta fuera del aislamiento de este actor, así que no puede leer
        // `self.fetchTimeout` directamente de forma segura.
        let timeout = fetchTimeout
        let response = try await client.get(jwksURL) { $0.timeout = timeout }
        guard response.status == .ok, var body = response.body else {
            throw Abort(.serviceUnavailable, reason: "Could not fetch the WorkOS JWKS (\(jwksURL)).")
        }
        guard body.readableBytes <= Self.maxResponseBytes else {
            throw Abort(
                .serviceUnavailable,
                reason: "WorkOS JWKS response exceeded \(Self.maxResponseBytes) bytes (\(jwksURL))."
            )
        }
        guard let jsonString = body.readString(length: body.readableBytes) else {
            throw Abort(.serviceUnavailable, reason: "Could not read the WorkOS JWKS response body (\(jwksURL)).")
        }
        let jwks = try JSONDecoder().decode(JWKS.self, from: Data(jsonString.utf8))
        keys = try await JWTKeyCollection().add(jwks: jwks)
        knownKeyIDs = Set(jwks.keys.compactMap { $0.keyIdentifier?.string })
        lastFetchedAt = Date()
    }
}
