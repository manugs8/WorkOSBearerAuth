@testable import WorkOSBearerAuth
import Foundation
import Testing
import Vapor
import JWTKit

@Suite("RemoteJWKS tests")
struct RemoteJWKSTests {

    // A mock client that tracks request counts and allows configuring the response.
    final class MockClient: Client, @unchecked Sendable {
        var eventLoop: any EventLoop
        var requestCount: Int = 0
        var responseToReturn: ClientResponse
        
        /// Optional hook to simulate latency so we can easily test concurrency
        var onSend: (() async throws -> Void)?

        init(eventLoop: any EventLoop, response: ClientResponse) {
            self.eventLoop = eventLoop
            self.responseToReturn = response
        }
        
        func delegating(to eventLoop: any EventLoop) -> any Client {
            self
        }
        
        func send(_ request: ClientRequest) -> EventLoopFuture<ClientResponse> {
            requestCount += 1
            if let onSend {
                let promise = eventLoop.makePromise(of: ClientResponse.self)
                promise.completeWithTask {
                    try await onSend()
                    return self.responseToReturn
                }
                return promise.futureResult
            } else {
                return eventLoop.makeSucceededFuture(responseToReturn)
            }
        }
    }

    /// Helper to create a valid JWKS JSON response
    private func validJWKSResponse(allocator: ByteBufferAllocator) -> ClientResponse {
        let json = """
        {
          "keys": [
            {
              "kty": "RSA",
              "alg": "RS256",
              "use": "sig",
              "kid": "key-123",
              "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
              "e": "AQAB"
            }
          ]
        }
        """
        var body = allocator.buffer(capacity: json.utf8.count)
        body.writeString(json)
        return ClientResponse(status: .ok, headers: [:], body: body)
    }

    static func withApp(_ test: (Application) async throws -> Void) async throws {
        let app = try await Application.make(.testing)
        do {
            try await test(app)
        } catch {
            try? await app.asyncShutdown()
            throw error
        }
        try await app.asyncShutdown()
    }

    @Test("Coalesces concurrent JWKS fetches into a single HTTP request (Thundering Herd)")
    func coalescesConcurrentFetches() async throws {
        try await Self.withApp { app in
            let client = MockClient(eventLoop: app.eventLoopGroup.next(), response: validJWKSResponse(allocator: app.allocator))
            client.onSend = {
                try await Task.sleep(nanoseconds: 50_000_000) // 50ms
            }

            let jwks = RemoteJWKS(jwksURL: "https://example.com/oauth2/jwks", client: client)

            // Launch 10 concurrent requests for currentKeys
            try await withThrowingTaskGroup(of: JWTKeyCollection.self) { group in
                for _ in 0..<10 {
                    group.addTask {
                        try await jwks.currentKeys(forceRefresh: true)
                    }
                }
                for try await _ in group { }
            }

            #expect(client.requestCount == 1)
        }
    }
    
    @Test("Rejects response larger than 1MB defensive limit")
    func rejectsLargeResponse() async throws {
        try await Self.withApp { app in
            // Exceed maxResponseBytes (1_048_576)
            let hugeSize = 1_048_576 + 10
            let allocator = app.allocator
            var body = allocator.buffer(capacity: hugeSize)
            body.writeBytes(Array(repeating: UInt8(ascii: " "), count: hugeSize))
            let response = ClientResponse(status: .ok, headers: [:], body: body)
            
            let client = MockClient(eventLoop: app.eventLoopGroup.next(), response: response)
            let jwks = RemoteJWKS(jwksURL: "https://example.com/oauth2/jwks", client: client)
            
            do {
                _ = try await jwks.currentKeys(forceRefresh: true)
                Issue.record("Expected Abort error due to large response")
            } catch let abort as Abort {
                #expect(abort.status == .serviceUnavailable)
                #expect(abort.reason.contains("exceeded"))
            }
        }
    }
    
    @Test("Updates knownKeyIDs successfully")
    func updatesKnownKeyIDsSuccessfully() async throws {
        try await Self.withApp { app in
            let client = MockClient(eventLoop: app.eventLoopGroup.next(), response: validJWKSResponse(allocator: app.allocator))
            let jwks = RemoteJWKS(jwksURL: "https://example.com/oauth2/jwks", client: client)
            
            _ = try await jwks.currentKeys()
            
            let knowsKey = await jwks.hasKey(kid: "key-123")
            #expect(knowsKey == true)
            
            let doesNotKnowKey = await jwks.hasKey(kid: "unknown-key")
            #expect(doesNotKnowKey == false)
        }
    }
}
