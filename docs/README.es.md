![vetto - un muro en el kernel entre el agente de IA y su máquina](../assets/readme/hero.png)

<p align="center">
  <a href="https://github.com/shleder/vetto/actions"><img src="https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/shleder/vetto/releases/tag/v0.5.15"><img src="https://img.shields.io/badge/version-0.5.15-blue?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@shledery/vetto"><img src="https://img.shields.io/badge/npm-v0.5.15-CB3837?logo=npm&logoColor=white&style=flat-square" alt="npm"></a>
  <a href="https://crates.io/crates/vetto"><img src="https://img.shields.io/badge/crates.io-v0.5.15-orange?logo=rust&logoColor=white&style=flat-square" alt="crates.io"></a>
  <a href="../LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="../README.md">English</a> |
  <a href="README.ru.md">Русский</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.ja.md">日本語</a> |
  <a href="README.es.md"><b>Español</b></a> |
  <a href="README.de.md">Deutsch</a>
</p>

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

Ejecutar agentes de IA en CI suele implicar Docker-in-Docker, lo que añade sobrecarga de descarga de imágenes, suele requerir ejecutores privilegiados y no es portátil en máquinas virtuales que no sean Linux.

La acción `shleder/vetto` ejecuta agentes en ejecutores estándar de GitHub Actions sin Docker:

- Arranque en frío inferior a 4 ms con verificación del binario.
- Aplicación de Landlock LSM y cgroups v2 sin root en ejecutores estándar de Ubuntu.
- Acceso directo a `$GITHUB_WORKSPACE` y a las cachés de acciones (`actions/cache`, `actions/setup-node`, `actions/setup-python`).
- Limpieza completa de subprocesos mediante `cgroup.kill`.
- Soporte multiplataforma en ejecutores de Ubuntu, macOS y Windows.

### Opción A: Ejecutar un paso de agente aislado

Ejecute un agente con lista blanca de políticas y salida de auditoría SARIF opcional:

```yaml
name: Agent Security Gate
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Run Sandboxed Agent
        uses: shleder/vetto@v0.5.15
        with:
          command: 'npx @anthropic-ai/claude-code -p "Run linter and fix basic formatting"'
          agent: 'claude'
          profile: 'strict'
          fail-on-block: '1'
          upload-sarif: 'true'
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Opción B: Instalar Vetto para flujos de trabajo multietapa

Omita la entrada `command` para instalar el binario `vetto` en `$GITHUB_PATH`:

```yaml
      - name: Setup Vetto
        uses: shleder/vetto@v0.5.15
        with:
          version: 'latest'

      - name: Run Sandboxed Commands
        run: |
          vetto doctor --preflight
          vetto run -- aider --message "Refactor parser error handling"
```

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

## Python SDK (`vetto-python`)

El paquete en `../sdk/python/` proporciona enlaces para ejecutar comandos aislados y proteger pasos de agentes:

```python
from vetto import VettoSandbox, VettoSecurityError, VettoTimeoutError

sandbox = VettoSandbox(
    project_dir=".",
    network="allowlist:api.anthropic.com,api.openai.com",
    profile="default",
    timeout_secs=60,
)

# Ejecuta el comando dentro del sandbox. Lanza VettoSecurityError en violación de política (código 125).
result = sandbox.run(["pytest", "tests/"])
```

### Integración con LangGraph

El paquete incluye `VettoToolNode` para aislar la ejecución de herramientas dentro de flujos de trabajo de LangGraph:

```python
from vetto.langgraph import VettoToolNode

tool_node = VettoToolNode(
    tools=[search_tool, execute_code_tool],
    network="off",
    timeout_secs=30,
)
```

---

## Integraciones en proyectos upstream

Vetto proporciona Pull Requests de aislamiento de procesos sin contenedores para varios frameworks de agentes de código abierto:

| Framework | Issue | Pull Request | Detalles |
| :--- | :--- | :--- | :--- |
| **CrewAI** | [#7830](https://github.com/crewAIInc/crewAI/issues/7830) | [PR #7831](https://github.com/crewAIInc/crewAI/pull/7831) | Aislamiento no privilegiado de procesos con `VettoExecTool` y `VettoPythonTool`, control de límites de espacio de trabajo y tiempos de espera. |
| **Microsoft AutoGen** | [#8298](https://github.com/microsoft/autogen/issues/8298) | [PR #8299](https://github.com/microsoft/autogen/pull/8299) | Sandbox sin contenedores `VettoCommandLineCodeExecutor` en `autogen-ext`. |
| **OpenClaw** | [#160522](https://github.com/openclaw/openclaw/issues/160522) | [PR #161125](https://github.com/openclaw/openclaw/pull/161125) | Contención de memoria y umbrales de heap bajo `--max-old-space-size`. |
| **Hugging Face smolagents** | [#2845](https://github.com/huggingface/smolagents/issues/2845) | [PR #2860](https://github.com/huggingface/smolagents/pull/2860) | `ProcessIsolatedExecutor` con tiempo de espera estricto y terminación de grupo de procesos. |
| **browser-use** | [#5879](https://github.com/browser-use/browser-use/issues/5879) | [PR #5929](https://github.com/browser-use/browser-use/pull/5929) | Verificación previa de DNS bloqueando loopback, RFC 1918, CGNAT y direcciones de metadatos de nube. |
| **OpenHands** | [#4266](https://github.com/OpenHands/software-agent-sdk/issues/4266) | [PR #5344](https://github.com/OpenHands/software-agent-sdk/pull/5344) | Backend `LandlockWorkspace` con detección de ABI 1 a 6 de Linux Landlock. |
| **Block goose** | [#12522](https://github.com/aaif-goose/goose/issues/12522) | [PR #12545](https://github.com/aaif-goose/goose/pull/12545) | Aislamiento `SubprocessExt` sin contenedores con rastreo de subreaper y espacios de nombres. |
| **Block goose (ACP)** | [#12513](https://github.com/aaif-goose/goose/issues/12513) | [PR #12563](https://github.com/aaif-goose/goose/pull/12563) | Política de ejecución de shell (`GOOSE_ACP_CLIENT_TERMINAL`) con detección de sandbox. |
| **Cline** | [#14544](https://github.com/cline/cline/issues/14544) | [PR #14583](https://github.com/cline/cline/pull/14583) | Ejecución en sandbox de terminal y enmascaramiento de secretos (`~/.ssh`, `.env`) en `ClineIgnoreController`. |
| **Qwen Code** | [#12856](https://github.com/QwenLM/qwen-code/issues/12856) | [PR #12953](https://github.com/QwenLM/qwen-code/pull/12953) | Depuración de credenciales de salida y protección del espacio de trabajo. |
| **Claude Code History Viewer** | [#509](https://github.com/jhlee0409/claude-code-history-viewer/issues/509) | [PR #595](https://github.com/jhlee0409/claude-code-history-viewer/pull/595) | Parámetros de reanudación de sesión y validación de entradas. |

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
- [Modelo de amenazas y límites de seguridad](threat-model.md)
- [Comprobaciones diagnósticas preflight](architecture/verify-ng.md)
- [Códigos de salida y modos de falla](exit-codes.md)
- [Política de seguridad y reporte de vulnerabilidades](../SECURITY.md)

---

## Contribuciones

Las contribuciones son bienvenidas. Abra pull requests contra la rama `main`. Todas las modificaciones de límites de seguridad deben incluir sus pruebas de validación correspondientes. Los pull requests se evalúan en ejecutores de Linux, macOS y Windows en GitHub Actions CI.

---

## Licencia

Distribuido bajo la Licencia Apache, Versión 2.0 ([LICENSE](../LICENSE)).
