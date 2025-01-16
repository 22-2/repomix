---
layout: home
title: Repomix
titleTemplate: Empaqueta tu código en formatos amigables para la IA
aside: false
editLink: false

features:
  - icon: 🤖
    title: Optimizado para IA
    details: Formatea tu código de una manera que sea fácil de entender y procesar para la IA.

  - icon: ⚙️
    title: Compatible con Git
    details: Respeta automáticamente tus archivos .gitignore.

  - icon: 🛡️
    title: Enfocado en la seguridad
    details: Incorpora Secretlint para realizar robustas comprobaciones de seguridad que detectan y previenen la inclusión de información sensible.

  - icon: 📊
    title: Conteo de tokens
    details: Proporciona recuentos de tokens para cada archivo y para todo el repositorio, útil para los límites de contexto de los LLM.

---

<div class="cli-section">

## Inicio rápido

Una vez que hayas generado un archivo empaquetado (`repomix-output.txt`) usando Repomix, puedes enviarlo a un asistente de IA con un prompt como:

```
Este archivo contiene todos los archivos del repositorio combinados en uno.
Quiero refactorizar el código, así que por favor revísalo primero.
```

La IA analizará todo tu código y proporcionará información completa:

![Repomix File Usage 1](/images/docs/repomix-file-usage-1.png)

Al discutir cambios específicos, la IA puede ayudar a generar código. Con funciones como los Artefactos de Claude, incluso puedes recibir múltiples archivos interdependientes:

![Repomix File Usage 2](/images/docs/repomix-file-usage-2.png)

¡Feliz programación! 🚀



## Guía para usuarios avanzados

Para los usuarios avanzados que necesitan más control, Repomix ofrece amplias opciones de personalización a través de su interfaz de línea de comandos.

### Inicio rápido

Puedes probar Repomix instantáneamente en el directorio de tu proyecto sin necesidad de instalación:

```bash
npx repomix
```

O instalarlo globalmente para uso repetido:

```bash
# Instalar usando npm
npm install -g repomix

# Alternativamente usando yarn
yarn global add repomix

# Alternativamente usando Homebrew (macOS)
brew install repomix

# Luego ejecutar en cualquier directorio de proyecto
repomix
```

¡Eso es todo! Repomix generará un archivo `repomix-output.txt` en tu directorio actual, que contendrá todo tu repositorio en un formato amigable para la IA.



### Uso

Para empaquetar todo tu repositorio:

```bash
repomix
```

Para empaquetar un directorio específico:

```bash
repomix ruta/al/directorio
```

Para empaquetar archivos o directorios específicos usando [patrones glob](https://github.com/mrmlnc/fast-glob?tab=readme-ov-file#pattern-syntax):

```bash
repomix --include "src/**/*.ts,**/*.md"
```

Para excluir archivos o directorios específicos:

```bash
repomix --ignore "**/*.log,tmp/"
```

Para empaquetar un repositorio remoto:
```bash
repomix --remote https://github.com/yamadashy/repomix

# También puedes usar la abreviatura de GitHub:
repomix --remote yamadashy/repomix

# Puedes especificar el nombre de la rama, la etiqueta o el hash de confirmación:
repomix --remote https://github.com/yamadashy/repomix --remote-branch main

# O usar un hash de confirmación específico:
repomix --remote https://github.com/yamadashy/repomix --remote-branch 935b695
```

Para inicializar un nuevo archivo de configuración (`repomix.config.json`):

```bash
repomix --init
```

Una vez que hayas generado el archivo empaquetado, puedes usarlo con herramientas de IA generativa como Claude, ChatGPT y Gemini.

#### Uso de Docker

También puedes ejecutar Repomix usando Docker 🐳  
Esto es útil si deseas ejecutar Repomix en un entorno aislado o prefieres usar contenedores.

Uso básico (directorio actual):

```bash
docker run -v .:/app -it --rm ghcr.io/yamadashy/repomix
```

Para empaquetar un directorio específico:
```bash
docker run -v .:/app -it --rm ghcr.io/yamadashy/repomix ruta/al/directorio
```

Procesar un repositorio remoto y generar la salida en un directorio `output`:

```bash
docker run -v ./output:/app -it --rm ghcr.io/yamadashy/repomix --remote https://github.com/yamadashy/repomix
```

### Formatos de salida

Elige tu formato de salida preferido:

```bash
# Formato XML (predeterminado)
repomix --style xml

# Formato Markdown
repomix --style markdown

# Formato de texto plano
repomix --style plain
```

### Personalización

Crea un archivo `repomix.config.json` para configuraciones persistentes:

```json
{
  "output": {
    "style": "markdown",
    "filePath": "custom-output.md",
    "removeComments": true,
    "showLineNumbers": true,
    "topFilesLength": 10
  },
  "ignore": {
    "customPatterns": ["*.test.ts", "docs/**"]
  }
}
```

### Más ejemplos
::: tip
💡 ¡Consulta nuestro [repositorio de GitHub](https://github.com/yamadashy/repomix) para obtener la documentación completa y más ejemplos!
:::

</div>
