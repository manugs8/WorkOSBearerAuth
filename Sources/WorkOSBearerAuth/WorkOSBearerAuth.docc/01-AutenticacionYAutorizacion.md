# ¿Qué son la autenticación y la autorización?

Los dos conceptos que sostienen todo lo demás en esta librería, explicados sin dar nada por
sabido.

## Descripción general

Antes de hablar de JWT, JWKS o WorkOS, conviene separar dos preguntas que se confunden con
facilidad porque casi siempre aparecen juntas:

- **Autenticación**: ¿quién eres?
- **Autorización**: ¿qué se te permite hacer?

Imagina la entrada a un edificio de oficinas. En recepción muestras tu tarjeta de identificación
y el guardia comprueba que la foto coincide contigo: eso es **autenticación**. Una vez dentro,
tu tarjeta solo abre las puertas de tu planta, no las del departamento financiero: eso es
**autorización**. Son dos comprobaciones distintas, hechas por partes distintas, y una no
sustituye a la otra — puedes estar perfectamente identificado y aun así no tener permiso para
entrar en una sala concreta.

`WorkOSBearerAuth` resuelve **solo la primera pregunta**. `BearerAuthMiddleware` (ver
<doc:05-ArquitecturaGeneral>) comprueba que quien hace la petición lleva un token válido emitido
por WorkOS, y expone quién es esa persona a través de `request.authenticatedClaims`. Qué puede
hacer esa persona concreta —si puede leer un recurso, escribir en otro, administrar una
organización— es una decisión de negocio que le corresponde a tu aplicación, no a esta librería.
Mezclar ambas cosas en un mismo sitio suele acabar en un código difícil de razonar: aquí se
mantienen deliberadamente separadas.

## ¿Qué es un token "Bearer"?

La palabra inglesa *bearer* significa "portador". Un token Bearer funciona como la pulsera de
un festival de música: quien la lleva puesta, entra — el personal de seguridad no vuelve a pedir
el DNI en cada puerta, ni comprueba de nuevo que esa pulsera te pertenece a ti y no a otra
persona. La verificación fuerte (comprar la entrada, cambiarla por la pulsera) ocurrió una vez,
al principio, en otro sitio.

Con un token Bearer pasa lo mismo: alguien inició sesión una vez, en algún momento anterior,
directamente ante WorkOS (con contraseña, con un proveedor de identidad corporativo, con un
enlace mágico...). Como prueba de ese inicio de sesión, WorkOS le entregó un token. A partir de
ahí, cada petición a tu API que incluya ese token en la cabecera `Authorization` se trata como
si viniera de esa persona — sin volver a pedirle la contraseña. Esta librería es precisamente el
"personal de seguridad en la puerta" de tu API: comprueba que la pulsera es auténtica y no ha
caducado, pero no participa en absoluto en el proceso de "venderla" (el login en sí, que ocurre
enteramente dentro de WorkOS, fuera de esta librería).

Esto también explica un riesgo importante: igual que quien roba una pulsera física puede
entrar con ella, quien intercepta un token Bearer puede usarlo como si fuera su dueño legítimo,
sin que el servidor tenga forma de notar la diferencia. Por eso los tokens que verifica esta
librería llevan una fecha de caducidad corta (la claim `exp`, ver <doc:02-AnatomiaDeUnJWT>) y
por eso **siempre** deben viajar sobre HTTPS — nunca en texto plano.

## El papel exacto de esta librería

Resumiendo con precisión qué hace y qué no hace `WorkOSBearerAuth`:

| Pregunta | ¿La resuelve esta librería? |
|---|---|
| ¿Ha iniciado sesión esta persona alguna vez? | No — eso ocurre en WorkOS, antes de que esta librería intervenga. |
| ¿El token que trae esta petición es genuino y sigue siendo válido? | **Sí — esto es exactamente lo que hace.** |
| ¿Puede esta persona en concreto acceder a este recurso en concreto? | No — eso es autorización, decisión de tu aplicación. |

## Siguiente paso

El token Bearer que verifica esta librería tiene un formato concreto y muy extendido: JSON Web
Token (JWT). El siguiente artículo, <doc:02-AnatomiaDeUnJWT>, diseca uno pieza por pieza.
