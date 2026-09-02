# Preguntas frecuentes

Respuestas cortas a las dudas que aparecen más a menudo al integrar o depurar esta librería.

### ¿Por qué a veces recibo 503 en vez de 401?

Porque tu token nunca llegó a evaluarse: WorkOS o la red no respondieron cuando esta librería
intentó obtener las claves JWKS necesarias para verificarlo. Un 401 afirmaría "tu token no
vale", lo cual sería falso en este caso — nadie lo comprobó. Ver <doc:08-ManejoDeErrores>.

### ¿Por qué las claves JWKS se cachean en vez de pedirse en cada petición?

Por dos motivos: pedirlas por red en cada petición añadiría latencia al camino crítico de cada
request, y generaría un volumen de tráfico innecesario contra WorkOS. Se cachean y se refrescan
solo cuando hay un indicio real de que han cambiado. Ver <doc:03-JWKSyRotacionDeClaves>.

### ¿Qué pasa si WorkOS rota sus claves de firma?

El primer token firmado con la clave nueva que llegue traerá un `kid` que tu caché todavía no
reconoce — eso dispara, automáticamente, un refresco forzado antes de rechazarlo. No hace falta
reiniciar tu aplicación ni intervenir manualmente. Ver <doc:03-JWKSyRotacionDeClaves>.

### ¿Por qué la comprobación de la ruta de descubrimiento es exacta y no por prefijo?

Porque comparar por prefijo dejaría sin autenticar cualquier ruta que simplemente *empezara
igual* que la ruta de descubrimiento (por ejemplo, `/.well-known/oauth-protected-resource-evil`),
ampliando sin querer qué queda público. Ver <doc:04-OAuthYDescubrimientoRFC9728>.

### ¿Cómo pruebo mi aplicación sin credenciales reales de WorkOS?

En tests normales (`swift test`), no necesitas hacer nada: el entorno `.testing` desactiva la
autenticación automáticamente. Para una suite E2E contra un servidor real, usa
`WorkOSBearerAuthTesting`. Ver <doc:10-GuiaDeTesting>.

### ¿Puedo dejar pública una ruta adicional, además de las cuatro ya exentas?

No, hoy no es configurable — `BearerAuthMiddleware.exemptPaths` es un conjunto fijo. Está
recogido como mejora futura (`exemptPaths` configurable vía `BearerAuthEnvironmentConfig`) en el
`TODO.md` del proyecto. Mientras tanto, cualquier ruta que no sea `/health`, `/docs`,
`/openapi.yaml` o el endpoint de descubrimiento necesita un token válido.

### ¿Puedo proteger dos recursos (audiencias) distintos con endpoints de descubrimiento independientes?

Hoy no: si pasas varios resource indicators, todos se aceptan como audiencia válida, pero solo
el primero de la lista obtiene su propio endpoint de descubrimiento RFC 9728. Para un único
gateway con varias audiencias equivalentes esto es correcto; para recursos genuinamente
independientes, está anotado como posible mejora futura en el `TODO.md` del proyecto.

### ¿Por qué la librería no lee las variables de entorno directamente?

Para no atarse a un nombre concreto de variable, y para poder comprobar la lógica de
`configureBearerAuth` en tests construyendo valores de ``BearerAuthEnvironmentConfig``
directamente, sin mutar variables de entorno reales del proceso. Ver
<doc:05-ArquitecturaGeneral>.

### ¿Qué algoritmos de firma acepta?

Solo **RS256** en producción (el que usa WorkOS AuthKit), comprobado explícitamente contra el
header del token antes de intentar siquiera verificar la firma. Es configurable a nivel de tipo
(`BearerTokenVerifier.allowedAlgorithms`) para que los tests puedan usar HMAC local, pero el
único punto de construcción en producción (`makeProductionBearerTokenVerifier`) nunca lo
sobreescribe — y hay un test dedicado (`productionVerifierUsesDefaultPolicy`) que falla si algún
día alguien lo hiciera sin querer.

### ¿Necesito HTTPS en local para probar el flujo completo?

El issuer y los resource indicators deben ser URLs `https://` sin excepción, también en
desarrollo — ver <doc:09-GuiaDeImplantacion>. Si necesitas probar contra un servidor local
expuesto a Internet, una herramienta como `ngrok` te da una URL HTTPS que reenvía a tu máquina.
