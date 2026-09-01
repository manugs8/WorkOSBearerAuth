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
            let env = BearerAuthEnvironmentConfig(authDisabled: false, workOSIssuer: "https://example.workos.com", workOSResourceIndicatorsRaw: "https://api.example.com")
            try configureBearerAuth(app, environment: env)

            let routeMatch = app.routes.all.filter { $0.path.map(\.description) == [".well-known", "oauth-protected-resource"] }
            #expect(routeMatch.isEmpty)
        }
    }

    // 2. authDisabled but not testing, not production
    @Test("Auth disabled outside production skips setup")
    func authDisabledOutsideProductionSkipsSetup() async throws {
        try await Self.withApp(environment: .development) { app in
            let env = BearerAuthEnvironmentConfig(authDisabled: true, workOSIssuer: nil, workOSResourceIndicatorsRaw: nil)
            try configureBearerAuth(app, environment: env)

            let routeMatch = app.routes.all.filter { $0.path.map(\.description) == [".well-known", "oauth-protected-resource"] }
            #expect(routeMatch.isEmpty)
        }
    }

    // 3. authDisabled in production throws
    @Test("Auth disabled in production throws")
    func authDisabledInProductionThrows() async throws {
        try await Self.withApp(environment: .production) { app in
            let env = BearerAuthEnvironmentConfig(authDisabled: true, workOSIssuer: nil, workOSResourceIndicatorsRaw: nil)

            #expect(throws: ConfigurationError.authDisabledInProduction) {
                try configureBearerAuth(app, environment: env)
            }
        }
    }

    // 4. Missing workos env outside production skips setup
    @Test("Missing WorkOS env outside production skips setup")
    func missingWorkOSEnvOutsideProductionSkipsSetup() async throws {
        try await Self.withApp(environment: .development) { app in
            let env = BearerAuthEnvironmentConfig(authDisabled: false, workOSIssuer: nil, workOSResourceIndicatorsRaw: nil)
            try configureBearerAuth(app, environment: env)

            let routeMatch = app.routes.all.filter { $0.path.map(\.description) == [".well-known", "oauth-protected-resource"] }
            #expect(routeMatch.isEmpty)
        }
    }

    // 5. Missing workos env in production throws
    @Test("Missing WorkOS env in production throws")
    func missingWorkOSEnvInProductionThrows() async throws {
        try await Self.withApp(environment: .production) { app in
            let env = BearerAuthEnvironmentConfig(authDisabled: false, workOSIssuer: nil, workOSResourceIndicatorsRaw: nil)

            #expect(throws: ConfigurationError.missingWorkOSEnvironment) {
                try configureBearerAuth(app, environment: env)
            }
        }
    }

    // 6. Valid env sets up route and middleware
    @Test("Valid environment sets up auth and route")
    func validEnvironmentSetsUpAuthAndRoute() async throws {
        try await Self.withApp(environment: .production) { app in
            let env = BearerAuthEnvironmentConfig(
                authDisabled: false, 
                workOSIssuer: "https://example.workos.com", 
                workOSResourceIndicatorsRaw: "https://api.example.com"
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

    // 7. empty resource indicators throws
    @Test("Empty resource indicators throws")
    func emptyResourceIndicatorsThrows() async throws {
        try await Self.withApp(environment: .production) { app in
            let env = BearerAuthEnvironmentConfig(
                authDisabled: false, 
                workOSIssuer: "https://example.workos.com", 
                workOSResourceIndicatorsRaw: ""
            )

            #expect(throws: ConfigurationError.emptyResourceIndicators) {
                try configureBearerAuth(app, environment: env)
            }
        }
    }
}
