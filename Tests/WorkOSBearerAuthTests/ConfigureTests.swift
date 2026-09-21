@testable import WorkOSBearerAuth
import Foundation
import Testing
import Vapor
import VaporTesting

@Suite("Configure bearer auth tests")
struct ConfigureTests {
    static func withApp(environment: Environment, _ test: (Application) async throws -> Void) async throws {
        let app = try await Application.make(environment)
        do {
            try await test(app)
        } catch {
            try? await app.asyncShutdown()
            throw error
        }
        try await app.asyncShutdown()
    }

    // 1. `.testing` env skips
    @Test("Testing environment skips auth setup")
    func testingEnvironmentSkipsAuthSetup() async throws {
        try await Self.withApp(environment: .testing) { app in
            let env = BearerAuthEnvironmentConfig.workOS(issuer: "https://example.workos.com", resourceIndicatorsRaw: "https://api.example.com")
            try configureBearerAuth(app, environment: env)

            let routeMatch = app.routes.all.filter { $0.path.map(\.description) == [".well-known", "oauth-protected-resource"] }
            #expect(routeMatch.isEmpty)
        }
    }

    // 2. .disabled outside production skips setup
    @Test(".disabled outside production skips setup")
    func disabledOutsideProductionSkipsSetup() async throws {
        try await Self.withApp(environment: .development) { app in
            try configureBearerAuth(app, environment: .disabled)

            let routeMatch = app.routes.all.filter { $0.path.map(\.description) == [".well-known", "oauth-protected-resource"] }
            #expect(routeMatch.isEmpty)
        }
    }

    // 3. .disabled in production throws
    @Test(".disabled in production throws")
    func disabledInProductionThrows() async throws {
        try await Self.withApp(environment: .production) { app in
            #expect(throws: ConfigurationError.missingWorkOSEnvironment) {
                try configureBearerAuth(app, environment: .disabled)
            }
        }
    }

    // 4. Valid .workOS sets up route and middleware
    @Test(".workOS sets up auth and route")
    func workOSSetsUpAuthAndRoute() async throws {
        try await Self.withApp(environment: .production) { app in
            let env = BearerAuthEnvironmentConfig.workOS(
                issuer: "https://example.workos.com",
                resourceIndicatorsRaw: "https://api.example.com"
            )
            try configureBearerAuth(app, environment: env)

            let route = try #require(app.routes.all.first { $0.path.map(\.description) == [".well-known", "oauth-protected-resource"] })
            #expect(route.path.count == 2)

            try await app.testing().test(.GET, ".well-known/oauth-protected-resource") { res async throws in
                #expect(res.status == .ok)
                struct OAuthProtectedResourceMetadata: Codable {
                    let resource: String
                    let authorizationServers: [String]
                    let bearerMethodsSupported: [String]

                    enum CodingKeys: String, CodingKey {
                        case resource
                        case authorizationServers = "authorization_servers"
                        case bearerMethodsSupported = "bearer_methods_supported"
                    }
                }
                let metadata = try res.content.decode(OAuthProtectedResourceMetadata.self)
                #expect(metadata.resource == "https://api.example.com")
                #expect(metadata.authorizationServers == ["https://example.workos.com"])
                #expect(metadata.bearerMethodsSupported == ["header"])
            }
        }
    }

    // 5. empty resource indicators throws
    @Test("Empty resource indicators throws")
    func emptyResourceIndicatorsThrows() async throws {
        try await Self.withApp(environment: .production) { app in
            let env = BearerAuthEnvironmentConfig.workOS(
                issuer: "https://example.workos.com",
                resourceIndicatorsRaw: ""
            )

            #expect(throws: ConfigurationError.emptyResourceIndicators) {
                try configureBearerAuth(app, environment: env)
            }
        }
    }

    // 6. blank resource indicators throws
    @Test("Blank resource indicators throws")
    func blankResourceIndicatorsThrows() async throws {
        try await Self.withApp(environment: .production) { app in
            let env = BearerAuthEnvironmentConfig.workOS(
                issuer: "https://example.workos.com",
                resourceIndicatorsRaw: "   "
            )

            #expect(throws: ConfigurationError.emptyResourceIndicators) {
                try configureBearerAuth(app, environment: env)
            }
        }
    }

    // 7. invalid issuer URL throws
    @Test("Invalid issuer URL throws")
    func invalidIssuerThrows() async throws {
        try await Self.withApp(environment: .production) { app in
            let env = BearerAuthEnvironmentConfig.workOS(
                issuer: "not-a-valid-url",
                resourceIndicatorsRaw: "https://api.example.com"
            )

            #expect(throws: ConfigurationError.invalidIssuer) {
                try configureBearerAuth(app, environment: env)
            }
        }
    }

    // 8. invalid resource indicator URL throws
    @Test("Invalid resource indicator URL throws")
    func invalidResourceIndicatorThrows() async throws {
        try await Self.withApp(environment: .production) { app in
            let env = BearerAuthEnvironmentConfig.workOS(
                issuer: "https://example.workos.com",
                resourceIndicatorsRaw: "not-a-valid-url"
            )

            #expect(throws: ConfigurationError.invalidResourceIndicator) {
                try configureBearerAuth(app, environment: env)
            }
        }
    }

    // 9. http issuer URL throws — .workOS always requires https, no exceptions
    @Test("HTTP issuer URL throws under .workOS")
    func httpIssuerThrows() async throws {
        try await Self.withApp(environment: .production) { app in
            let env = BearerAuthEnvironmentConfig.workOS(
                issuer: "http://example.workos.com",
                resourceIndicatorsRaw: "https://api.example.com"
            )

            #expect(throws: ConfigurationError.invalidIssuer) {
                try configureBearerAuth(app, environment: env)
            }
        }
    }

    // 10. http resource indicator URL throws — never relaxed, not even under .local
    @Test("HTTP resource indicator URL throws")
    func httpResourceIndicatorThrows() async throws {
        try await Self.withApp(environment: .production) { app in
            let env = BearerAuthEnvironmentConfig.workOS(
                issuer: "https://example.workos.com",
                resourceIndicatorsRaw: "http://api.example.com"
            )

            #expect(throws: ConfigurationError.invalidResourceIndicator) {
                try configureBearerAuth(app, environment: env)
            }
        }
    }

    // 11. .local builds the loopback issuer itself and sets up route and middleware
    @Test(".local sets up auth and route against http://127.0.0.1:<port>")
    func localSetsUpAuthAndRoute() async throws {
        try await Self.withApp(environment: .development) { app in
            let env = BearerAuthEnvironmentConfig.local(port: 8090, resourceIndicatorsRaw: "https://api.example.com")
            try configureBearerAuth(app, environment: env)

            try await app.testing().test(.GET, ".well-known/oauth-protected-resource") { res async throws in
                #expect(res.status == .ok)
                struct OAuthProtectedResourceMetadata: Codable {
                    let authorizationServers: [String]
                    enum CodingKeys: String, CodingKey {
                        case authorizationServers = "authorization_servers"
                    }
                }
                let metadata = try res.content.decode(OAuthProtectedResourceMetadata.self)
                #expect(metadata.authorizationServers == ["http://127.0.0.1:8090"])
            }
        }
    }

    // 12. .local is rejected in production — only .workOS is allowed there
    @Test(".local in production throws")
    func localInProductionThrows() async throws {
        try await Self.withApp(environment: .production) { app in
            let env = BearerAuthEnvironmentConfig.local(port: 8090, resourceIndicatorsRaw: "https://api.example.com")

            #expect(throws: ConfigurationError.localConfigInProduction) {
                try configureBearerAuth(app, environment: env)
            }
        }
    }

    // 13. resource indicator validation is shared — exercised here under .local too
    @Test("Invalid resource indicator URL throws under .local")
    func localInvalidResourceIndicatorThrows() async throws {
        try await Self.withApp(environment: .development) { app in
            let env = BearerAuthEnvironmentConfig.local(port: 8090, resourceIndicatorsRaw: "http://api.example.com")

            #expect(throws: ConfigurationError.invalidResourceIndicator) {
                try configureBearerAuth(app, environment: env)
            }
        }
    }

    // 14. Discovery endpoint with path works according to RFC 9728
    @Test("Discovery endpoint inserts path per RFC 9728")
    func discoveryEndpointWithPath() async throws {
        try await Self.withApp(environment: .production) { app in
            let env = BearerAuthEnvironmentConfig.workOS(
                issuer: "https://example.workos.com",
                resourceIndicatorsRaw: "https://api.example.com/mcp"
            )
            try configureBearerAuth(app, environment: env)

            let route = try #require(app.routes.all.first { $0.path.map(\.description) == [".well-known", "oauth-protected-resource", "mcp"] })
            #expect(route.path.count == 3)

            try await app.testing().test(.GET, ".well-known/oauth-protected-resource/mcp") { res async throws in
                #expect(res.status == .ok)
            }
        }
    }

    // 15. .disabled still skips under .testing — the short-circuit narrowed to .disabled/.workOS still covers this case
    @Test(".disabled skips setup under .testing")
    func disabledSkipsSetupUnderTesting() async throws {
        try await Self.withApp(environment: .testing) { app in
            try configureBearerAuth(app, environment: .disabled)

            let routeMatch = app.routes.all.filter { $0.path.map(\.description) == [".well-known", "oauth-protected-resource"] }
            #expect(routeMatch.isEmpty)
        }
    }

    // 16. .local registers the route even under .testing — it only ever talks to a loopback mock, so the
    // real-network rationale behind the .testing short-circuit doesn't apply to it.
    @Test(".local sets up auth and route under .testing")
    func localSetsUpAuthAndRouteUnderTesting() async throws {
        try await Self.withApp(environment: .testing) { app in
            let env = BearerAuthEnvironmentConfig.local(port: 8090, resourceIndicatorsRaw: "https://api.example.com")
            try configureBearerAuth(app, environment: env)

            try await app.testing().test(.GET, ".well-known/oauth-protected-resource") { res async throws in
                #expect(res.status == .ok)
                struct OAuthProtectedResourceMetadata: Codable {
                    let authorizationServers: [String]
                    enum CodingKeys: String, CodingKey {
                        case authorizationServers = "authorization_servers"
                    }
                }
                let metadata = try res.content.decode(OAuthProtectedResourceMetadata.self)
                #expect(metadata.authorizationServers == ["http://127.0.0.1:8090"])
            }
        }
    }

    // 17. .local under .testing doesn't just register the discovery route — the real BearerAuthMiddleware
    // is attached and actually enforces authentication on other routes, not merely skipped like .workOS/.disabled.
    @Test(".local under .testing enforces authentication on other routes, not just the discovery route")
    func localUnderTestingEnforcesAuth() async throws {
        try await Self.withApp(environment: .testing) { app in
            let env = BearerAuthEnvironmentConfig.local(port: 8090, resourceIndicatorsRaw: "https://api.example.com")
            try configureBearerAuth(app, environment: env)

            app.get("protected") { _ in "ok" }

            try await app.testing().test(.GET, "protected") { res async throws in
                #expect(res.status == .unauthorized)
            }
        }
    }
}
