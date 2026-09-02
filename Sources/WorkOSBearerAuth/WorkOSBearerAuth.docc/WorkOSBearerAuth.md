# ``WorkOSBearerAuth``

Autenticación por token Bearer para aplicaciones Vapor 4, verificada contra un emisor de WorkOS AuthKit.

## Descripción general

`WorkOSBearerAuth` añade un único middleware a tu aplicación [Vapor](https://vapor.codes) que
exige un token Bearer válido —emitido por [WorkOS AuthKit](https://workos.com/docs/authkit)—
en cualquier ruta HTTP, ya sea REST o un servidor MCP montado en la misma `Application`. Se
registra una sola vez, en tu `configure(_:)`, y a partir de ahí protege todo por igual: no hay
que "apuntar" cada ruta nueva a la autenticación, ni mantener dos mecanismos distintos para dos
interfaces distintas.

La librería se ocupa de las partes que son fáciles de hacer mal en una integración manual:
comprobar el algoritmo de firma, exigir y rotar las claves públicas de WorkOS (JWKS), validar
issuer/audiencia/caducidad, distinguir un token inválido (401) de una WorkOS inalcanzable (503),
y publicar un endpoint de descubrimiento (RFC 9728) para que un cliente automatizado sepa a
dónde ir a por un token sin que un humano lo configure a mano.

## Por dónde empezar

Si es la primera vez que trabajas con JWT, JWKS u OAuth, o simplemente quieres entender **por
qué** esta librería hace las cosas como las hace antes de tocar código, empieza por los
artículos de la sección **Conceptos fundamentales**: están escritos para alguien que no ha
tocado nunca un sistema de autenticación, con analogías antes que jerga.

Si ya conoces esos conceptos y solo quieres integrar la librería en tu proyecto, ve directo a
<doc:09-GuiaDeImplantacion>.

Si lo que buscas es entender el funcionamiento interno para depurar un problema o revisar el
diseño, la sección **Arquitectura y funcionamiento interno** describe cada pieza y por qué está
construida así.

## Topics

### Conceptos fundamentales — para quien no conozca la autenticación

- <doc:01-AutenticacionYAutorizacion>
- <doc:02-AnatomiaDeUnJWT>
- <doc:03-JWKSyRotacionDeClaves>
- <doc:04-OAuthYDescubrimientoRFC9728>

### Arquitectura y funcionamiento interno

- <doc:05-ArquitecturaGeneral>
- <doc:06-FlujoDeUnaPeticion>
- <doc:07-LasCuatroConfiguraciones>
- <doc:08-ManejoDeErrores>

### Guías prácticas

- <doc:09-GuiaDeImplantacion>
- <doc:10-GuiaDeTesting>
- <doc:11-PreguntasFrecuentes>
- <doc:12-ComoGenerarEstaDocumentacion>

### Referencia pública

- ``configureBearerAuth(_:environment:)``
- ``BearerAuthEnvironmentConfig``
- ``WorkOSClaims``
