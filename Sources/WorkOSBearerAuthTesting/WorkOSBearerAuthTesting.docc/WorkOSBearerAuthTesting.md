# ``WorkOSBearerAuthTesting``

Firma tokens de prueba con la misma forma que los de WorkOS, para suites de test end-to-end que
hablan con un servidor real por la red.

## Descripción general

`WorkOSBearerAuthTesting` es un producto independiente de `WorkOSBearerAuth`, pensado para un
único escenario: una suite de tests que **no** levanta una `Application` de Vapor en el mismo
proceso, sino que hace peticiones HTTP de verdad contra un servidor ya arrancado en otro sitio
—por ejemplo, en un pipeline de CI que despliega la aplicación completa antes de probarla—.

En ese escenario, la autenticación real está activa en el servidor bajo test, así que la suite
necesita un token Bearer que el servidor acepte exactamente igual que aceptaría uno auténtico de
WorkOS: mismo formato, mismo issuer, misma audiencia, mismo mecanismo de verificación por
`kid` — sin ningún atajo de test en el propio servidor. ``WorkOSTestTokenSigner`` firma
precisamente ese tipo de token, usando una clave privada de prueba que tú controlas, nunca una
credencial real de WorkOS.

## Por qué es un producto aparte

Firmar un JWT solo requiere [JWTKit](https://github.com/vapor/jwt-kit) y `Foundation` — no hace
falta nada del lado servidor. Si este tipo viviera dentro del producto `WorkOSBearerAuth`,
cualquier proyecto que solo necesitara esto para su suite E2E se vería obligado a enlazar
también Vapor y todo lo que trae consigo, sin ningún motivo. Mantenerlo separado evita ese coste.

## Por dónde empezar

<doc:GuiaE2E> explica el escenario completo paso a paso: cómo generar una clave de prueba, cómo
levantar una Authorization Server falsa que sirva el JWKS correspondiente, y cómo encaja
``WorkOSTestTokenSigner`` en medio de todo eso.

Si quieres entender primero los conceptos de fondo —qué es un JWT, qué es un JWKS, por qué hace
falta una clave pública para verificar una firma—, esos están explicados desde cero en el
catálogo de `WorkOSBearerAuth`, empezando por su artículo "¿Qué son la autenticación y la
autorización?".

## Topics

### Guías

- <doc:GuiaE2E>

### Referencia pública

- ``WorkOSTestTokenSigner``
