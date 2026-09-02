# Referencia: errores y códigos de estado

Todos los errores que puede producir esta librería, cuándo ocurre cada uno, y qué código HTTP —o
qué fallo de arranque— provoca.

## Descripción general

Esta librería distingue dos familias de errores completamente separadas, que conviene no
confundir:

- **Errores de arranque** (`ConfigurationError`): algo en la configuración que le has pasado a
  `configureBearerAuth` no es válido. Ocurren una vez, al arrancar la aplicación, nunca por
  petición.
- **Errores de petición** (`BearerTokenError`, y el caso particular de un fallo del propio
  JWKS): algo en una petición HTTP concreta no pasa la verificación. Ocurren por cada petición
  rechazada, y no afectan a ninguna otra.

## La regla mental: 401 frente a 503

Antes de la tabla, la idea que hay detrás de todas las decisiones de código de estado:

> **401** significa "he mirado tu token, y no vale."
> **503** significa "no he podido ni mirar tu token."

Un token rechazado (firma incorrecta, caducado, issuer o audiencia equivocados, algoritmo no
permitido, cabecera ausente o mal formada) siempre es 401 — el token sí se evaluó, y el
resultado fue "no". Un fallo al obtener las claves JWKS (WorkOS caído, un problema de red) es
siempre 503 — el token de quien hizo la petición nunca llegó a mirarse siquiera, así que decir
"tu token es inválido" sería sencillamente incorrecto. Devolver 503 en su lugar le dice a un
cliente legítimo lo que de verdad ha pasado: *inténtalo de nuevo en un momento*, no *tu
credencial está mal*.

## Errores de arranque — `ConfigurationError`

Ninguno de estos es público: si tu aplicación quiere registrar o propagar el fallo, le basta con
tratarlo como `any Error` — no hace falta distinguir el caso concreto para eso.

| Caso | Cuándo ocurre | Qué hacer |
|---|---|---|
| `authDisabledInProduction` | `authDisabled == true` y `app.environment == .production` | Nunca desactives la autenticación en producción — revisa la configuración del entorno. |
| `missingWorkOSEnvironment` | Falta `workOSIssuer` o `workOSResourceIndicatorsRaw` en producción, sin `authDisabled` | Define ambos valores para el entorno de producción. |
| `emptyResourceIndicators` | `workOSResourceIndicatorsRaw` está definido pero queda vacío tras dividir por comas | Comprueba que la variable no esté vacía ni compuesta solo de comas o espacios. |
| `invalidIssuer` | `workOSIssuer` no es una URL absoluta `https://` con host | Usa la URL completa de tu proyecto de WorkOS AuthKit, con `https://`. |
| `invalidResourceIndicator` | Algún resource indicator no es una URL absoluta `https://` con host | Revisa cada valor de la lista separada por comas. |

Ver <doc:07-LasCuatroConfiguraciones> para el razonamiento completo detrás de cuáles de estos
casos aplican solo en producción.

## Errores de petición — `BearerTokenError`

Todos terminan en una respuesta **401** con la cabecera `WWW-Authenticate: Bearer
resource_metadata="…"` (ver <doc:04-OAuthYDescubrimientoRFC9728>) — nunca en 503, porque en
todos estos casos el token sí ha llegado a evaluarse.

| Caso | Cuándo ocurre |
|---|---|
| `missingBearerToken` | Falta la cabecera `Authorization`, o no tiene el formato `Bearer <token>` |
| `unexpectedAlgorithm` | El `alg` del header no está en el conjunto de algoritmos permitidos (RS256, en producción) |
| `missingKeyID` | El token no lleva `kid` y el verifier lo exige (el caso de producción) |
| `unexpectedIssuer` | El `iss` del token no coincide con el issuer configurado |
| `unexpectedAudience` | El `aud` del token no coincide con ninguno de los resource indicators configurados |

A estos se suman los fallos que decodifica y comprueba directamente `JWTKit` durante
`keys.verify(...)` — firma incorrecta, `kid` que no existe en la colección de claves, o un
token cuyo `exp`/`nbf` (comprobados por ``WorkOSClaims``) lo sitúan fuera de su ventana de
validez. Todos ellos se tratan exactamente igual: 401 con la misma cabecera.

## El caso especial: fallo al obtener el JWKS

Este no es un `BearerTokenError` — es un `Abort(.serviceUnavailable, ...)` directo, lanzado por
`RemoteJWKS` cuando no puede completar una descarga (WorkOS no responde, la red falla, la
respuesta supera el límite defensivo de tamaño, o el cuerpo no es JSON válido). Vapor lo convierte
en una respuesta 503 a través de su propio `ErrorMiddleware` — el mismo mecanismo que usaría
cualquier otro fallo de infraestructura de tu aplicación.

## Qué nivel de log usa cada situación

Una decisión operativa deliberada: no todos los rechazos merecen la misma atención.

- **`.notice`** — un token rechazado (401). Internet está lleno de tráfico automatizado probando
  rutas al azar; un goteo de 401 es ruido esperable, no una emergencia.
- **`.error`** — un fallo al obtener el JWKS (503). Esto sí es una señal real de que algo va mal
  con la conectividad hacia WorkOS, y merece la atención de quien opera el servicio.
- **`.warning`** — autenticación desactivada (casos 2–3 de <doc:07-LasCuatroConfiguraciones>).
  Nunca silencioso, para que no se descubra por sorpresa.
- **`.info`** — autenticación activada correctamente al arrancar, con el issuer y los recursos
  configurados.

## Siguiente paso

Con el funcionamiento interno ya cubierto, <doc:09-GuiaDeImplantacion> es la guía paso a paso
para integrar esta librería en tu propia aplicación.
