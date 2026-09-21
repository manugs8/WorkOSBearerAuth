# Guía de testing

Cómo probar una aplicación que usa esta librería, con y sin credenciales reales de WorkOS.

## Descripción general

Hay tres escenarios de test distintos, y esta librería está pensada para que casi nunca
necesites los dos más complicados.

## Tests normales de tu aplicación

Cuando tu propia suite de tests corre con `swift test`, `app.environment` es `.testing`. Si tu
`configure(_:)` construye ``BearerAuthEnvironmentConfig/disabled`` o
``BearerAuthEnvironmentConfig/workOS(issuer:resourceIndicatorsRaw:)`` (el **Caso 1** de
<doc:07-LasTresConfiguraciones>), `configureBearerAuth` se salta la autenticación por completo,
sin importar qué contengan tus variables de entorno. Esto significa que, para la inmensa
mayoría de tus tests, no tienes que hacer nada especial: tus rutas responden como si la
autenticación no existiera.

Como explica el README de esta librería, si necesitas comprobar específicamente que una ruta
concreta *exige* un token —no solo que responde bien cuando lo hay—, tu propia suite de tests
puede montar un `BearerAuthMiddleware` adicional a mano, vía `@testable import WorkOSBearerAuth`,
tal como hace la propia suite de esta librería en `BearerAuthMiddlewareTests`. En la práctica,
la mayoría de aplicaciones consumidoras no necesitan llegar a este nivel de detalle: les basta
con confiar en que `configureBearerAuth` está bien probado por esta librería, y limitarse a
comprobar que sus propias rutas responden correctamente una vez pasada la autenticación.

## Tests E2E en el mismo proceso, con autenticación real

Un escenario intermedio: quieres una suite E2E de verdad —que ejerza el camino completo de
`BearerAuthMiddleware`/`BearerTokenVerifier`/`RemoteJWKS`, no un `BearerAuthMiddleware` montado
a mano contra una fuente de claves local— pero sin pagar el coste de un servidor genuinamente en
marcha fuera de `.testing`, como exige el escenario E2E contra un servidor real de más abajo.
Para esto está pensado ``BearerAuthEnvironmentConfig/local(port:resourceIndicatorsRaw:)``: es el
único caso que `configureBearerAuth` registra de verdad incluso bajo `app.environment ==
.testing` (ver <doc:07-LasTresConfiguraciones>), porque por construcción nunca habla con el
JWKS real de WorkOS, solo con `http://127.0.0.1:<puerto>`.

El patrón: arrancas un `AuthMock` (o cualquier mock de OAuth real y loopback) en un puerto
efímero junto a tu `Application` de test —igual que ya arrancarías una base de datos efímera
para la misma suite—, apuntas `.local` a ese puerto, y apagas el mock al terminar exactamente
igual que apagarías esa base de datos:

```swift
import WorkOSBearerAuth
import Vapor

func withE2EServer(
    authMockPort: Int, resourceIndicator: String, test: (Application) async throws -> Void
) async throws {
    let app = try await Application.make(.testing)
    do {
        try configureBearerAuth(
            app,
            environment: .local(port: authMockPort, resourceIndicatorsRaw: resourceIndicator)
        )
        // ... el resto de tu configure(_:), migraciones, etc.
        try await test(app)
    } catch {
        try? await app.asyncShutdown()
        throw error
    }
    try await app.asyncShutdown()
}
```

Dentro de `test`, cada escenario de autenticación se ejerce con una petición HTTP real vía
`app.testing()`: sin `Authorization` para el camino de token ausente, un token obtenido del
propio mock para el camino válido, y un token manipulado o con `exp` en el pasado para los
caminos inválido/caducado — todo contra el `BearerAuthMiddleware` real, sin ningún atajo
pensado solo para tests.

## Tests E2E contra un servidor real

Este es el escenario distinto: una suite que no levanta una `Application` en el mismo proceso,
sino que hace peticiones HTTP de verdad contra un servidor ya arrancado — por ejemplo, en un
pipeline de CI que despliega la aplicación completa antes de probarla. Aquí `app.environment`
probablemente **no** sea `.testing` (el servidor arrancó como lo haría en producción), así que
la autenticación real está activa — y la suite necesita un token que el servidor acepte
exactamente como aceptaría uno genuino de WorkOS.

Para esto existe **`WorkOSBearerAuthTesting`**, un producto aparte con un único tipo público:
`WorkOSTestTokenSigner`. Firma tokens con la misma forma que los de WorkOS (mismo issuer,
misma audiencia, mismo `kid`), usando una clave privada de prueba que tú controlas — nunca una
credencial real de WorkOS.

```swift
import WorkOSBearerAuthTesting

let signer = WorkOSTestTokenSigner(
    issuer: ProcessInfo.processInfo.environment["E2E_AUTH_TEST_ISSUER"] ?? "http://fake-authkit",
    resource: ProcessInfo.processInfo.environment["E2E_AUTH_TEST_RESOURCE"] ?? "http://localhost:8080",
    privateKeyPEM: ProcessInfo.processInfo.environment["E2E_AUTH_TEST_PRIVATE_KEY"]
)

let token = try await signer.validToken()      // nil si privateKeyPEM es nil
let expired = try await signer.expiredToken()  // exp ya en el pasado
```

La documentación completa de este producto —incluyendo cómo montar la Authorization Server
falsa que hace que todo esto funcione de extremo a extremo— vive en su propio catálogo:
`WorkOSBearerAuthTesting`, empezando por su artículo **Guía E2E**.

## Por qué esta librería no necesita que la vuelvas a probar tú

`BearerTokenVerifierTests` cubre exhaustivamente la lógica de verificación (algoritmo, `kid`,
issuer, audiencia, expiración, not-before) contra claves generadas localmente,
`BearerAuthMiddlewareTests` cubre el cableado completo (rutas exentas frente a protegidas, la
cabecera `WWW-Authenticate`, el refresco de JWKS ante un `kid` desconocido, 401 frente a 503, y
que una única instancia global protege cualquier ruta sin importar cómo se registró), y
`ConfigureTests` cubre la propia bifurcación de `configureBearerAuth` — incluido que el
cortocircuito de `.testing` cubre `.disabled`/`.workOS` pero no `.local`, y que `.local` bajo
`.testing` no se limita a registrar la ruta de descubrimiento, sino que de verdad exige
autenticación en el resto de rutas. Tu propia aplicación no necesita reconstruir nada de esto —
solo necesita llamar a `configureBearerAuth` correctamente (<doc:09-GuiaDeImplantacion>) y, si
quiere, una prueba de integración liviana que confirme que sus propias rutas quedan alcanzadas a
través de ese middleware.

## Siguiente paso

<doc:11-PreguntasFrecuentes> recoge las dudas más habituales al integrar y probar esta librería.
