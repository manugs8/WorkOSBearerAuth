import Vapor

extension Request {
    private struct AuthenticatedClaimsKey: StorageKey {
        typealias Value = WorkOSClaims
    }

    /// The validated claims of the bearer token that authenticated this request — set by
    /// `BearerAuthMiddleware` right after a successful `BearerTokenVerifier.verify(_:using:)`.
    /// `nil` when authentication is disabled (`AUTH_DISABLED=true`) or the request hit an
    /// exempt path.
    ///
    /// `Request.storage`, not a task-local: a task-local set in the middleware does not
    /// reliably reach code invoked further down the chain in a Vapor app. Vapor's
    /// `AsyncMiddleware` and its router both bridge from async back to `EventLoopFuture`
    /// via `completeWithTask` (`Task { ... }`) at more than one point between a middleware
    /// and the route it dispatches to, and that bridging does not preserve task-local
    /// values here — verified empirically: a task-local set by the middleware was not
    /// visible from a plain route closure reached via `next.respond`, with or without
    /// `.grouped()`. `Request` is a reference type threaded through that whole chain
    /// regardless of which `Task` ends up running which part of it, so reading/writing its
    /// `storage` isn't affected by that problem.
    ///
    /// A consuming app's own REST handlers may not be scoped to a `Vapor.Request` at all
    /// — some OpenAPI-generator-driven setups deliberately keep the generated protocol
    /// conformance decoupled from `Request` (e.g. to use `app.db` instead of `req.db`).
    /// Giving REST access to the authenticated identity in that case needs that decision
    /// revisited on the consumer's side, not just a different propagation mechanism.
    public var authenticatedClaims: WorkOSClaims? {
        get { self.storage[AuthenticatedClaimsKey.self] }
        set { self.storage[AuthenticatedClaimsKey.self] = newValue }
    }
}
