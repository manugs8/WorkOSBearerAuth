# Cómo generar y ver esta documentación

Este catálogo (`WorkOSBearerAuth.docc`) es un catálogo de [DocC](https://www.swift.org/documentation/docc/)
estándar de Swift Package Manager. No requiere ningún paso previo especial: basta con
compilarlo.

## Desde Xcode

Abre el paquete (`Package.swift`) en Xcode y selecciona **Product ▸ Build Documentation**
(`⌃⇧⌘D`). Xcode genera y abre el visor de documentación, con la navegación entre artículos, los
diagramas y la referencia de símbolos ya montada.

## Desde la línea de comandos

Este paquete no depende de [swift-docc-plugin](https://github.com/apple/swift-docc-plugin) —
deliberadamente: esta tarea de documentación no debía tocar `Package.swift`. Aun así, puedes
generar la documentación con las herramientas que ya trae el propio toolchain de Swift, en dos
pasos.

1. Compila el target extrayendo su grafo de símbolos:

   ```bash
   swift build --target WorkOSBearerAuth \
     -Xswiftc -emit-symbol-graph -Xswiftc -emit-symbol-graph-dir -Xswiftc .build/symbol-graph
   ```

2. Convierte el catálogo con `docc`:

   ```bash
   xcrun docc convert Sources/WorkOSBearerAuth/WorkOSBearerAuth.docc \
     --additional-symbol-graph-dir .build/symbol-graph \
     --output-path .build/docs/WorkOSBearerAuth.doccarchive \
     --fallback-display-name WorkOSBearerAuth \
     --fallback-bundle-identifier com.manugarcia.WorkOSBearerAuth \
     --fallback-bundle-version 1.0.0
   ```

El resultado es un `.doccarchive` que puedes abrir haciendo doble clic (se abre con Xcode) o
servir como una web estática con `docc preview` durante el desarrollo de la propia
documentación:

```bash
xcrun docc preview Sources/WorkOSBearerAuth/WorkOSBearerAuth.docc \
  --additional-symbol-graph-dir .build/symbol-graph
```

Repite el mismo procedimiento para el segundo catálogo, cambiando el target y la ruta:

```bash
swift build --target WorkOSBearerAuthTesting \
  -Xswiftc -emit-symbol-graph -Xswiftc -emit-symbol-graph-dir -Xswiftc .build/symbol-graph-testing

xcrun docc convert Sources/WorkOSBearerAuthTesting/WorkOSBearerAuthTesting.docc \
  --additional-symbol-graph-dir .build/symbol-graph-testing \
  --output-path .build/docs/WorkOSBearerAuthTesting.doccarchive \
  --fallback-display-name WorkOSBearerAuthTesting \
  --fallback-bundle-identifier com.manugarcia.WorkOSBearerAuthTesting \
  --fallback-bundle-version 1.0.0
```

## Si en el futuro quieres publicarla (p. ej. en GitHub Pages)

`swift-docc-plugin` automatiza los dos pasos anteriores y añade soporte directo para
`swift package generate-documentation --hosting-base-path <repo>`, pensado para publicar en
GitHub Pages. Añadirlo es una decisión aparte —requiere declararlo como dependencia en
`Package.swift`— que se ha dejado deliberadamente fuera de esta tarea de documentación, para no
modificar el manifiesto del paquete. Si decides incorporarlo más adelante, los comandos de
`xcrun docc` de más arriba dejan de hacer falta: el propio plugin los sustituye.
