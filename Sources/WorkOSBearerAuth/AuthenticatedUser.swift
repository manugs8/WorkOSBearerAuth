import Vapor

extension Request {
    private struct AuthenticatedClaimsKey: StorageKey {
        typealias Value = WorkOSClaims
    }

    /// Las claims validadas del token Bearer que autenticó esta petición — las fija
    /// `BearerAuthMiddleware` justo después de un `BearerTokenVerifier.verify(_:using:)`
    /// correcto. Es `nil` cuando la autenticación está desactivada (`AUTH_DISABLED=true`)
    /// o la petición ha llegado por una ruta exenta.
    ///
    /// `Request.storage`, no un task-local: un task-local fijado en el middleware no llega
    /// de forma fiable al código que se invoca más adelante en la cadena de una app Vapor.
    /// Tanto `AsyncMiddleware` como el router de Vapor puentean de async de vuelta a
    /// `EventLoopFuture` mediante `completeWithTask` (`Task { ... }`) en más de un punto
    /// entre un middleware y la ruta a la que despacha, y ese puente no conserva aquí los
    /// valores task-local — comprobado empíricamente: un task-local fijado por el
    /// middleware no era visible desde un closure de ruta normal alcanzado vía
    /// `next.respond`, con o sin `.grouped()`. `Request` es un tipo por referencia que
    /// atraviesa toda esa cadena sin importar qué `Task` acabe ejecutando cada tramo, así
    /// que leer/escribir su `storage` no se ve afectado por ese problema.
    ///
    /// Los propios handlers REST de una app consumidora pueden no estar ligados en
    /// absoluto a un `Vapor.Request` — algunos montajes generados a partir de OpenAPI
    /// mantienen deliberadamente la conformidad de protocolo generada desacoplada de
    /// `Request` (p. ej. para usar `app.db` en vez de `req.db`). Dar acceso REST a la
    /// identidad autenticada en ese caso exige revisar esa decisión en el lado del
    /// consumidor, no solo cambiar el mecanismo de propagación.
    public var authenticatedClaims: WorkOSClaims? {
        get { self.storage[AuthenticatedClaimsKey.self] }
        set { self.storage[AuthenticatedClaimsKey.self] = newValue }
    }
}
