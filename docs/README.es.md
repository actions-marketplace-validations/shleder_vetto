<div align="center">

<pre align="center">
██╗   ██╗███████╗████████╗████████╗ ██████╗ 
██║   ██║██╔════╝╚══██╔══╝╚══██╔══╝██╔═══██╗
██║   ██║█████╗     ██║      ██║   ██║   ██║
╚██╗ ██╔╝██╔══╝     ██║      ██║   ██║   ██║
 ╚████╔╝ ███████╗   ██║      ██║   ╚██████╔╝
  ╚═══╝  ╚══════╝   ╚═╝      ╚═╝    ╚═════╝ 
</pre>

# VETTO

<p align="center">
  <b>Sandbox a nivel de kernel de Linux de sub-milisegundo para agentes CLI de IA</b>
</p>

[![CI](https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/shleder/vetto/actions)
[![Release](https://img.shields.io/github/v/release/shleder/vetto?label=release&color=blue&style=flat-square)](https://github.com/shleder/vetto/releases)
[![npm version](https://img.shields.io/badge/npm-v0.6.1-CB3837?logo=npm&logoColor=white&style=flat-square)](https://www.npmjs.com/package/@shledery/vetto)
[![crates.io](https://img.shields.io/badge/crates.io-v0.6.1-orange?logo=rust&logoColor=white&style=flat-square)](https://crates.io/crates/vetto)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)](https://github.com/shleder/vetto)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square)](../LICENSE)

<p align="center">
  <a href="../README.md">English</a> |
  <a href="README.ru.md">Русский</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.ja.md">日本語</a> |
  <a href="README.es.md"><b>Español</b></a> |
  <a href="README.de.md">Deutsch</a>
</p>

</div>

Vetto es un sandbox no privilegiado para agentes CLI de programación con IA como Claude Code, OpenAI Codex, Cursor, OpenCode y Aider. Aísla el acceso al sistema de archivos, sockets de red y procesos secundarios entre `fork()` y `execve()` usando mecanismos nativos del kernel en Linux y macOS sin requerir un demonio en segundo plano ni privilegios de root.

---

## Aplicación de límites a nivel de kernel

Los agentes de programación con IA ejecutan comandos de shell y scripts de compilación generados. Si un agente intenta leer credenciales privadas, abrir sockets de red sin procesar o generar procesos demonio huérfanos, Vetto bloquea la operación a nivel de kernel:

```text
> Reading ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> Opening raw socket...             BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...       TERMINATED (process tree extinction, exit 125)
```

### Ejecución fail-closed (código de salida 125)

Cuando un agente viola la política o cuando el kernel del host carece de un mecanismo de aislamiento requerido, Vetto finaliza inmediatamente con el código 125. Los procesos descendientes y los trabajadores en segundo plano se terminan sincrónicamente a través de `cgroup.kill` de cgroups v2. Si el sistema operativo host no puede aplicar una regla configurada, Vetto informa la capacidad ausente y se detiene en lugar de ejecutarse con seguridad reducida.

---

## Inicio rápido

### 1. Instalación

Mediante administradores de paquetes estándar:

```bash
# npm (binario global multiplataforma)
npm install -g @shledery/vetto

# Homebrew (macOS y Linux)
brew install shleder/tap/vetto

# Cargo (crates.io)
cargo install vetto
```

O mediante el instalador curl independiente:

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

### 2. Envoltura transparente de agentes (Shims)

Envuelva los agentes de IA instalados sin modificar configuraciones de shell ni alias:

```bash
vetto enable --all
```

Vetto busca en `$PATH` los binarios de agentes compatibles (`claude`, `codex`, `cursor`, `opencode`, `aider`, `antigravity`, etc.) y coloca shims interceptores en `~/.vetto/shims`.

Tras habilitarlo, ejecute el agente normalmente:

```bash
claude                # se ejecuta en el sandbox bajo políticas de Landlock LSM
cursor                # se ejecuta con credenciales protegidas y salida de red restringida
```

Para administrar agentes individuales:

```bash
vetto enable claude    # envolver solo claude
vetto disable claude   # restaurar ejecución directa sin sandbox
```

### Comparación con Docker

Los agentes de código necesitan compiladores locales, cachés de paquetes existentes y terminal interactiva. Ejecutarlos dentro de Docker requiere una configuración pesada, mientras que Vetto aplica el aislamiento de kernel directamente a los procesos del host:

| Dimensión | Docker / DinD | Vetto |
| :--- | :--- | :--- |
| Sobrecarga de inicio | Creación de contenedor de 500 ms a 2000 ms | Arranque en frío inferior a 4 ms entre `fork()` y `execve()` |
| Consumo de memoria | Proceso `dockerd` residente en segundo plano | 0 MB de memoria en segundo plano (sin demonio) |
| Modelo de privilegios | Requiere membresía en grupo `root` o `docker` | Espacios de nombres de usuario no privilegiados, Landlock LSM y cgroups v2 |
| Herramientas del host | Requiere reconstruir imágenes de contenedor | Acceso directo a `cargo`, `npm`, `pip` y `uv` del host |
| Cachés de paquetes | Montajes de volumen o descargas repetidas | Reutiliza directamente las cachés de paquetes del host |
| Limpieza de procesos | Puede dejar contenedores huérfanos | Terminación sincrónica del árbol de procesos mediante `cgroup.kill` de cgroups v2 |

Para mediciones detalladas de rendimiento y guías para bancos de pruebas de evaluación, consulte el [Benchmark SWE-bench vs Docker](benchmarks/swe-bench.md).

### 3. Ejecución directa

Ejecute comandos o scripts arbitrarios dentro del sandbox:

```bash
vetto run -- python script.py
vetto -- npm test
```

### 4. Reversión de instantáneas del espacio de trabajo

Vetto toma una instantánea copy-on-write del directorio del proyecto antes de que el agente comience a trabajar:

```bash
vetto diff        # muestra archivos modificados, añadidos o eliminados por el agente
vetto undo        # revierte el espacio de trabajo al estado previo a la ejecución
```

### 5. Diagnóstico del host

Compruebe qué funciones de aislamiento del kernel están disponibles en la máquina:

```bash
vetto doctor --preflight          # inspecciona Landlock ABI, espacios de nombres y cgroups v2
vetto doctor --preflight --json   # emite el informe de diagnóstico en formato JSON
```

---

## Integración con GitHub Actions

Ejecute agentes de IA de forma segura en sus pipelines de CI sin Docker ni privilegios de root mediante la acción oficial `shleder/vetto`:

```yaml
- name: Run Sandboxed Agent
  uses: shleder/vetto@v0.6.1
  with:
    command: 'npx @anthropic-ai/claude-code -p "Fix linter errors"'
    agent: 'claude'
    profile: 'strict'
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Consulte la [Guía de integración de CI/CD](ci-cd.md) para conocer las opciones completas de configuración, flujos multietapa e informes de seguridad SARIF.

---

## Manejo de terminal y statusline

Los agentes interactivos como Claude Code y Codex gestionan su propio estado de terminal (PTY). Vetto preserva la entrada y salida directa del terminal mientras muestra el estado del sandbox:

- **Línea de estado (`--tui=statusline`)**: Predeterminado para comandos no interactivos. Muestra las políticas activas de archivos y red en la última línea del terminal.
- **Modo headless (`--tui=none` / `--ci`)**: Desactiva el renderizado de la interfaz en terminal. Utilice este parámetro en entornos de CI, scripts o al redirigir flujos estándar.

---

## Compatibilidad de plataformas

Vetto utiliza las características de aislamiento no privilegiadas de cada sistema operativo:

| Plataforma | Aislamiento de archivos | Aislamiento de red | Ciclo de vida de procesos | Nivel |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Nativo)** | **Landlock LSM (ABI 1 a 6)**<br>Enmascaramiento tmpfs sobre `~/.ssh`, `~/.aws`, `.env` | **Espacios de nombres de red (`CLONE_NEWNET`)**<br>Aislamiento de loopback con proxy TCP/TLS local | **Espacios de nombres PID (`CLONE_NEWPID`)**<br>Limpieza del árbol mediante `cgroup.kill` de cgroups v2 | Tier 1 (Completo) |
| **Linux (WSL2)** | **Landlock LSM mediante kernel WSL2**<br>Restricciones de acceso a rutas | **Espacios de nombres de red en VM**<br>Conexiones salientes filtradas | **Espacios de nombres PID y barrido `/proc`**<br>Terminación completa del árbol | Tier 1 (Completo) |
| **macOS (Darwin)** | **Seatbelt (`libsandbox.1.dylib`)**<br>Restringe escritura al directorio del proyecto y `/tmp` | **Restricción de red**<br>`--net=off` bloquea salida IP; `--net=allowlist` mediante proxy loopback | **Supervisión de procesos**<br>Watchdog que rastrea grupos de procesos secundarios | Tier 2 (Objetivo Tier 1.5) |
| **Windows Nativo** | **AppContainer y LPAC**<br>Control de acceso basado en tokens | **Restricciones de capacidades**<br>SIDs de red restringidos | **Job Objects**<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Tier 3 (Guardrail) |

### Nota sobre Seatbelt en macOS

macOS no ofrece espacios de nombres de red no privilegiados. Vetto utiliza el framework nativo Seatbelt de Apple (`libsandbox.1.dylib`) para restringir el acceso de escritura al sistema de archivos y proteger las credenciales. Cuando se establece `--net=off`, se bloquea el tráfico de red y el IPC hacia `mDNSResponder`. Cuando se establece `--net=allowlist`, Vetto ejecuta un proxy loopback efímero en `127.0.0.1` y configura variables de entorno de proxy. Las restricciones de lectura en macOS son amplias para contemplar el comportamiento de la caché compartida dyld.

---

## Agentes de IA compatibles

Vetto incluye perfiles preconfigurados para más de 25 herramientas de programación con IA. Cada perfil delimita la salida de red a los puntos finales conocidos del proveedor y protege las credenciales manteniendo disponibles las cachés de paquetes:

| Agente | Binario / Preajuste | Puntos finales de red | Configuraciones y cachés protegidas |
| :--- | :--- | :--- | :--- |
| **Claude Code** | `claude` | `api.anthropic.com`, `claude.ai` | `~/.claude`, `~/.config/claude`, plugins |
| **OpenAI Codex** | `codex` | `api.openai.com`, ChatGPT OAuth | `~/.codex`, `~/.config/codex`, plugins |
| **Cursor** | `cursor` | Backend de Cursor, mercado de extensiones | Sockets IPC de VS Code, `~/.cursor` |
| **Aider** | `aider` | Puntos finales de proveedores LLM configurados | Raíz del repositorio Git, cachés de historial |

Para consultar la lista completa de agentes admitidos, alcances de red y reglas de rutas, consulte el [Registro de compatibilidad de agentes](agents.md).

---

## Verificación e integridad

Las versiones se compilan mediante flujos de trabajo automatizados de GitHub Actions con verificación criptográfica pública:

- **SLSA Level 3 Provenance**: Atestaciones de compilación in-toto generadas para los binarios de cada versión.
- **Firmas Minisign**: Publicadas con cada archivo bajo la clave pública `75ECEC9B5080C590`.
- **Sumas de comprobación SHA-256**: Verificadas automáticamente por los scripts de instalación.

---

## Documentación

- [Backends de plataformas y especificaciones de aislamiento](platform-backends.md)
- [Preajustes de agentes y configuración](agents.md)
- [Benchmark SWE-bench vs Docker](benchmarks/swe-bench.md)
- [Modelo de amenazas y límites de seguridad](threat-model.md)
- [Integración con CI/CD y GitHub Actions](ci-cd.md)
- [Códigos de salida y modos de falla](exit-codes.md)
- [Política de seguridad y reporte de vulnerabilidades](../SECURITY.md)

---

## Contribuciones

Las contribuciones son bienvenidas. Abra pull requests contra la rama `main`. Todas las modificaciones de límites de seguridad deben incluir sus pruebas de validación correspondientes. Los pull requests se evalúan en ejecutores de Linux, macOS y Windows en GitHub Actions CI.

---

## Licencia

Distribuido bajo la Licencia Apache, Versión 2.0 ([LICENSE](../LICENSE)).
