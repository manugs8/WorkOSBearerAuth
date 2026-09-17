# Guía de implantación

Cómo integrar `WorkOSBearerAuth` en tu aplicación Vapor, de principio a fin, incluyendo los
errores más comunes al hacerlo.

## Antes de empezar

Necesitas:

1. Un proyecto de [WorkOS AuthKit](https://workos.com/docs/authkit) ya configurado, con su
   **issuer** a mano (una URL con forma `https://tu-proyecto.authkit.app`, o tu dominio
   personalizado si has configurado uno).
2. Decidir tus **resource indicators**: normalmente, la URL pública de tu propia API — por
   ejemplo `https://api.tuempresa.com/mcp` si expones un servidor MCP, o
   `https://api.tuempresa.com` a secas para una API REST.
3. Registrar esos mismos resource indicators en la configuración de tu proyecto de WorkOS
   (`WORKOS_RESOURCE_INDICATORS` en su terminología) — deben coincidir **carácter a carácter**
   con lo que le pases a esta librería, porque la comprobación de audiencia es una intersección
   exacta de conjuntos, no una comparación aproximada.

Si todavía no conoces estos términos, <doc:04-OAuthYDescubrimientoRFC9728> los explica desde
cero.

## 1. Añade la dependencia

```swift
.package(url: "https://github.com/manugs8/WorkOSBearerAuth.git", from: "0.1.0")
```

Y añade `"WorkOSBearerAuth"` como dependencia del target que llama a `configure(_:)` en tu
aplicación.

## 2. Define tus propias variables de entorno

Esta librería no impone nombres de variables de entorno — los lee tu propio `configure.swift`.
Una convención razonable, y la que usan los ejemplos de esta documentación:

| Variable | Contenido |
|---|---|
| `WORKOS_ISSUER` | La URL del issuer de tu proyecto de WorkOS |
| `WORKOS_RESOURCE_INDICATORS` | Uno o varios resource indicators, separados por comas |
| `AUTHMOCK_PORT` | El puerto de un `AuthMock` local (opcional — solo fuera de producción) |

No hace falta ninguna variable para desactivar la autenticación explícitamente: si no fijas
ninguna de las anteriores fuera de producción, tu `configure.swift` construye
`BearerAuthEnvironmentConfig.disabled` y la autenticación queda desactivada (ver
<doc:07-LasTresConfiguraciones>).

## 3. Llama a `configureBearerAuth`

Dentro de tu `configure(_:)`, después de que `app.client` exista (lo necesita internamente
`RemoteJWKS` para hablar con WorkOS). `BearerAuthEnvironmentConfig` es un `enum` — tu propio
`configure.swift` decide qué caso construir a partir de sus variables de entorno:

```swift
import WorkOSBearerAuth

func configure(_ app: Application) throws {
    // ...

    let bearerAuthEnvironment: BearerAuthEnvironmentConfig
    if let issuer = Environment.get("WORKOS_ISSUER"), let indicators = Environment.get("WORKOS_RESOURCE_INDICATORS") {
        bearerAuthEnvironment = .workOS(issuer: issuer, resourceIndicatorsRaw: indicators)
    } else if let port = Environment.get("AUTHMOCK_PORT").flatMap(Int.init), let indicators = Environment.get("WORKOS_RESOURCE_INDICATORS") {
        bearerAuthEnvironment = .local(port: port, resourceIndicatorsRaw: indicators)
    } else {
        bearerAuthEnvironment = .disabled
    }
    try configureBearerAuth(app, environment: bearerAuthEnvironment)
}
```

A partir de este punto, **todas** las rutas de tu aplicación —las que ya existían y las que
registres después, sea cual sea el mecanismo (`app.get`, `app.on`, un servidor MCP montado
encima...)— quedan protegidas por igual, salvo las rutas exentas (ver
<doc:06-FlujoDeUnaPeticion>). No hace falta "apuntar" cada ruta nueva a nada.

## 4. Lee la identidad autenticada en tus rutas

```swift
app.get("whoami") { req in
    req.authenticatedClaims?.sub.value ?? "anonymous"
}
```

`authenticatedClaims` es `nil` exactamente en dos casos: la autenticación está desactivada, o la
ruta es una de las exentas. En cualquier ruta protegida que se haya llegado a ejecutar, siempre
tiene un valor.

## 5. Comprueba el endpoint de descubrimiento

Con tu servidor arrancado:

```bash
curl https://tuapi.example.com/.well-known/oauth-protected-resource
```

Deberías recibir algo como:

```json
{
  "resource": "https://tuapi.example.com/mcp",
  "authorization_servers": ["https://tu-proyecto.authkit.app"],
  "bearer_methods_supported": ["header"]
}
```

## 6. Comprueba el rechazo de una petición sin token

```bash
curl -i https://tuapi.example.com/mcp
```

Deberías ver `401 Unauthorized` y una cabecera:

```
WWW-Authenticate: Bearer resource_metadata="https://tuapi.example.com/.well-known/oauth-protected-resource"
```

## 7. Antes de desplegar a producción

En producción no hay red de seguridad: no existe ninguna variable para desactivar la
autenticación explícitamente, así que si falta configuración de WorkOS, la aplicación **no
arrancará** (ver <doc:07-LasTresConfiguraciones>). Esto es intencionado: es preferible un
despliegue que falla de inmediato a una API abierta por una variable de entorno olvidada.

## Errores comunes

- **Usar `http://` en vez de `https://`** en el issuer o en un resource indicator — se rechaza
  explícitamente con `invalidIssuer`/`invalidResourceIndicator` (ver
  <doc:08-ManejoDeErrores>). Los resource indicators no tienen excepción posible, en ningún
  caso. El issuer sí tiene una, pero estrecha y estructural: usando
  `BearerAuthEnvironmentConfig.local(port:resourceIndicatorsRaw:)` en vez de `.workOS`, el
  issuer siempre es `http://127.0.0.1:<puerto>` — pensado para un `AuthMock`/servidor de
  prueba real corriendo en la misma máquina (el tráfico loopback no sale de la máquina),
  nunca para exponer tu propia API por HTTP. `configureBearerAuth` rechaza `.local` en
  `.production` (`localConfigInProduction`), así que una variable de entorno mal puesta en
  un despliegue real no rebaja esta protección en silencio. Para probar el flujo completo
  desde fuera de tu máquina, sigue usando un túnel HTTPS (como `ngrok`).
- **Dejar `WORKOS_RESOURCE_INDICATORS` vacío, o solo con comas/espacios** — produce
  `emptyResourceIndicators`. Comprueba el valor real de la variable de entorno en el entorno de
  destino.
- **Confundir el issuer con el propio recurso** — el issuer es la URL de WorkOS (quien emite el
  token); el resource indicator es la URL de tu propia API (quien lo consume). Son cosas
  distintas y no deben coincidir.
- **Esperar que una ruta protegida necesite algo especial** — no lo necesita: la protección es
  automática y global desde que se llama a `configureBearerAuth`.
- **Necesitar una ruta pública que no sea ninguna de las cuatro exentas** — hoy no es
  configurable (`exemptPaths` está fijado en el propio middleware). Está recogido como mejora
  futura en el `TODO.md` del proyecto; mientras tanto, esa ruta tendrá que vivir protegida.

## Siguiente paso

Para probar todo esto sin depender de credenciales reales de WorkOS —tanto en tests locales como
en una suite E2E contra un servidor real—, sigue con <doc:10-GuiaDeTesting>.
