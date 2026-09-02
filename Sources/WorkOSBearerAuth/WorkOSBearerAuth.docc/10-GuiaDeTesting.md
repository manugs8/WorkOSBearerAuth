# Guía de testing

Cómo probar una aplicación que usa esta librería, con y sin credenciales reales de WorkOS.

## Descripción general

Hay dos escenarios de test completamente distintos, y esta librería está pensada para que casi
nunca necesites el más complicado de los dos.

## Tests normales de tu aplicación

Cuando tu propia suite de tests corre con `swift test`, `app.environment` es `.testing`, y por
el **Caso 1** de <doc:07-LasCuatroConfiguraciones>, `configureBearerAuth` se salta la
autenticación por completo, sin importar qué contengan tus variables de entorno. Esto significa
que, para la inmensa mayoría de tus tests, no tienes que hacer nada especial: tus rutas
responden como si la autenticación no existiera.

Como explica el README de esta librería, si necesitas comprobar específicamente que una ruta
concreta *exige* un token —no solo que responde bien cuando lo hay—, tu propia suite de tests
puede montar un `BearerAuthMiddleware` adicional a mano, vía `@testable import WorkOSBearerAuth`,
tal como hace la propia suite de esta librería en `BearerAuthMiddlewareTests`. En la práctica,
la mayoría de aplicaciones consumidoras no necesitan llegar a este nivel de detalle: les basta
con confiar en que `configureBearerAuth` está bien probado por esta librería, y limitarse a
comprobar que sus propias rutas responden correctamente una vez pasada la autenticación.

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
issuer, audiencia, expiración, not-before) contra claves generadas localmente, y
`BearerAuthMiddlewareTests` cubre el cableado completo (rutas exentas frente a protegidas, la
cabecera `WWW-Authenticate`, el refresco de JWKS ante un `kid` desconocido, 401 frente a 503, y
que una única instancia global protege cualquier ruta sin importar cómo se registró). Tu propia
aplicación no necesita reconstruir nada de esto — solo necesita llamar a `configureBearerAuth`
correctamente (<doc:09-GuiaDeImplantacion>) y, si quiere, una prueba de integración liviana que
confirme que sus propias rutas quedan alcanzadas a través de ese middleware.

## Siguiente paso

<doc:11-PreguntasFrecuentes> recoge las dudas más habituales al integrar y probar esta librería.
