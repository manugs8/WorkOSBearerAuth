import JWTKit
import NIOCore
import Vapor

/// Where ``BearerAuthMiddleware`` gets the ``JWTKeyCollection`` it verifies tokens against.
/// Extracted so tests can hand the middleware a local, already-built key collection (no
/// network, no real WorkOS credentials) instead of the real ``RemoteJWKS`` — see
/// `BearerAuthMiddlewareTests`.
protocol JWKSSource: Sendable {
    func currentKeys(forceRefresh: Bool) async throws -> JWTKeyCollection

    /// Whether the currently cached key set recognizes this `kid`. Lets
    /// ``BearerAuthMiddleware`` decide that a forced refresh is warranted only for a
    /// `kid` it doesn't know about yet (a plausible key rotation) — not for every
    /// verification failure, which would let an attacker force wasted JWKS fetches
    /// just by sending garbage tokens.
    func hasKey(kid: String) async -> Bool
}

/// Fetches and caches the JSON Web Key Set published at a remote URL (WorkOS AuthKit's
/// `<issuer>/oauth2/jwks`), refreshing it periodically and on demand.
///
/// An actor because the cached ``JWTKeyCollection`` is mutated by concurrent requests —
/// every request hitting a protected route calls into this to get the current keys.
actor RemoteJWKS: JWKSSource {
    /// Defensive cap on the JWKS response body. WorkOS's JWKS is tiny in practice (a
    /// handful of keys, a few KB at most) — anything anywhere near this size means
    /// something's wrong (a misdirected URL, an error page instead of JSON, WorkOS
    /// serving something unexpected), so it's rejected outright rather than buffered
    /// into a `String` and handed to the JSON decoder.
    private static let maxResponseBytes = 1_048_576  // 1 MiB

    private let jwksURL: URI
    private let client: any Client
    private let refreshInterval: TimeInterval
    /// How long a single JWKS fetch is allowed to take before failing. This sits on the
    /// authentication path — every request needing a refresh (an empty/stale cache, or
    /// an unrecognized `kid`) waits on it — so it needs its own short, explicit bound
    /// rather than depending on whatever `client`'s own default (if any) happens to be.
    private let fetchTimeout: TimeAmount
    private let forcedRefreshCooldown: TimeInterval

    private var keys = JWTKeyCollection()
    /// Tracked separately from `keys`: `JWTKeyCollection` has no public way to ask "do
    /// you recognize this `kid`" without also falling back to a default signer when it
    /// doesn't, which would defeat the point of `hasKey(kid:)`.
    private var knownKeyIDs: Set<String> = []
    private var lastFetchedAt: Date?
    private var lastAttemptedAt: Date?
    /// The in-flight refresh, if any — see `refreshOnce()`.

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

    /// The current key collection, refreshing first if the cache is empty, stale, or
    /// `forceRefresh` is set.
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

    /// Coalesces concurrent refresh requests into a single in-flight fetch. Actor
    /// isolation on its own doesn't prevent duplicate fetches here: `refresh()` awaits an
    /// HTTP response, and while it's suspended another call can re-enter this actor, see
    /// `lastFetchedAt` still stale (the first fetch hasn't completed yet), and kick off a
    /// second, redundant request to WorkOS — a thundering herd the moment the cache
    /// expires under real traffic. Joining the same `Task` instead of racing separate
    /// ones avoids that. `refreshTask` is cleared by whichever invocation's own `defer`
    /// fires — only the branch below that actually creates the task ever reaches that
    /// `defer` at all; every other concurrent call returns earlier, from the `if let`
    /// above, without registering one.
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
        // Captured into a local first: the `beforeSend` closure below runs outside this
        // actor's isolation, so it can't safely read `self.fetchTimeout` directly.
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
