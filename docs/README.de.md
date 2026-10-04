![vetto - eine Kernel-Sicherheitswand zwischen dem KI-Agenten und Ihrem System](../assets/readme/hero.png)

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
  <a href="README.es.md">Español</a> |
  <a href="README.de.md"><b>Deutsch</b></a>
</p>

Vetto ist eine unprivilegierte Sandbox für KI-Coding-CLI-Agenten wie Claude Code, OpenAI Codex, Cursor, OpenCode und Aider. Es isoliert Dateisystemzugriffe, Netzwerk-Sockets und Kindprozesse zwischen `fork()` und `execve()` über native Kernel-Mechanismen unter Linux und macOS, ohne Hintergrund-Daemon und ohne Root-Rechte.

---

## Durchsetzung von Sicherheitsgrenzen auf Kernel-Ebene

KI-Coding-Agenten führen generierte Shell-Befehle und Build-Skripte aus. Wenn ein Agent versucht, private Schlüssel zu lesen, Raw-Sockets zu öffnen oder unüberwachte Hintergrundprozesse zu starten, blockiert Vetto die Operation direkt auf Kernel-Ebene:

```text
> Reading ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> Opening raw socket...             BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...       TERMINATED (process tree extinction, exit 125)
```

### Fail-Closed-Ausführung (Exit-Code 125)

Verletzt ein Agent eine Richtlinie oder fehlen dem Host-Kernel erforderliche Isolationsmechanismen, bricht Vetto die Ausführung unverzüglich mit Code 125 ab. Alle Kindprozesse und Hintergrund-Worker werden synchron über `cgroup.kill` in cgroups v2 terminiert. Wenn das Betriebssystem eine konfigurierte Regel nicht erzwingen kann, meldet Vetto das fehlende Feature und stoppt, anstatt mit reduzierter Sicherheit weiterzulaufen.

---

## Schnellstart

### 1. Installation

Über Standard-Paketmanager:

```bash
# npm (plattformübergreifendes globales Binary)
npm install -g @shledery/vetto

# Homebrew (macOS & Linux)
brew install shleder/tap/vetto

# Cargo (crates.io)
cargo install vetto
```

Oder über das Standalone-curl-Installationsskript:

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

### 2. Transparente Agent-Kapselung (Shims)

Installierte KI-Agenten ohne Änderungen an Shell-Konfigurationen oder Aliasen in die Sandbox einbinden:

```bash
vetto enable --all
```

Vetto durchsucht `$PATH` nach unterstützten Agent-Binaries (`claude`, `codex`, `cursor`, `opencode`, `aider`, `antigravity` usw.) und legt abfangende Shims in `~/.vetto/shims` ab.

Nach der Aktivierung wird der Agent wie gewohnt gestartet:

```bash
claude                # läuft geschützt in der Sandbox unter Landlock LSM
cursor                # läuft mit geschützten Zugangsdaten und Netzwerkfilter
```

Verwaltung einzelner Agenten:

```bash
vetto enable claude    # nur claude kapseln
vetto disable claude   # direkte Ausführung ohne Sandbox wiederherstellen
```

### Vergleich mit Docker

KI-Coding-Agenten benötigen lokale Compiler, vorhandene Paket-Caches und ein interaktives Terminal. Der Betrieb in Docker erfordert schwere Container-Setups, während Vetto die Kernel-Sandbox direkt auf Host-Prozesse anwendet:

| Dimension | Docker / DinD | Vetto |
| :--- | :--- | :--- |
| Start-Overhead | 500 ms bis 2000 ms Container-Erstellung | Kaltstart unter 4 ms zwischen `fork()` und `execve()` |
| Speicherbedarf | Hintergrund-Daemon `dockerd` | 0 MB Hintergrund-Speicher (kein Daemon) |
| Berechtigungsmodell | Erfordert `root` oder Mitgliedschaft in `docker`-Gruppe | Unprivilegierte User Namespaces, Landlock LSM und cgroups v2 |
| Toolchains | Erfordert Neubau von Container-Images | Direkter Zugriff auf Host-`cargo`, `npm`, `pip` und `uv` |
| Paket-Caches | Volume Mounts oder wiederholte Downloads | Direkte Wiederverwendung lokaler Paket-Caches |
| Prozessbereinigung | Kann verwaiste Container hinterlassen | Synchrone Prozessbaum-Terminierung via cgroups v2 `cgroup.kill` |

### 3. Direkte Ausführung

Beliebige Befehle oder Skripte in der Sandbox ausführen:

```bash
vetto run -- python script.py
vetto -- npm test
```

### 4. Workspace-Snapshot-Rollback

Vetto erstellt vor Beginn der Agent-Ausführung einen Copy-on-Write-Snapshot des Projektverzeichnisses:

```bash
vetto diff        # zeigt vom Agenten geänderte, hinzugefügte oder gelöschte Dateien
vetto undo        # setzt das Arbeitsverzeichnis auf den Stand vor der Ausführung zurück
```

### 5. Host-Diagnose

Überprüfung der auf dem System verfügbaren Kernel-Isolationsfeatures:

```bash
vetto doctor --preflight          # prüft Landlock ABI, Namespaces und cgroups v2
vetto doctor --preflight --json   # gibt den Diagnosebericht als JSON aus
```

---

## Integration in GitHub Actions

Das Ausführen von KI-Coding-Agenten in CI nutzt häufig Docker-in-Docker, was zu Image-Download-Verzögerungen führt, oft privilegierte Runner erfordert und auf Nicht-Linux-VMs nicht portabel ist.

Die Action `shleder/vetto` führt Agenten auf Standard-GitHub-Actions-Runnern ohne Docker aus:

- Kaltstart unter 4 ms mit kryptografischer Binary-Verifikation.
- Rootlose Landlock LSM- und cgroups v2-Isolierung auf Standard-Ubuntu-Runnern.
- Direkter Zugriff auf `$GITHUB_WORKSPACE` und Caches (`actions/cache`, `actions/setup-node`, `actions/setup-python`).
- Zuverlässige Bereinigung aller Subprozesse über `cgroup.kill`.
- Multi-Plattform-Unterstützung auf Ubuntu-, macOS- und Windows-Runnern.

### Option A: Einzelnen isolierten Agent-Schritt ausführen

Agenten mit Domain-Allowlist und optionalem SARIF-Sicherheitsbericht ausführen:

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

### Option B: Vetto für mehrstufige Workflows einrichten

Wird der Parameter `command` weggelassen, installiert die Action das Binary `vetto` in `$GITHUB_PATH`:

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

## Terminal-Verarbeitung und Statuszeile

Interaktive Agenten wie Claude Code und Codex steuern ihren eigenen Terminal-Status (PTY). Vetto erhält die direkte Terminal-Ein-/Ausgabe und zeigt gleichzeitig den Sandbox-Status an:

- **Statuszeilen-Overlay (`--tui=statusline`)**: Standardmodus für nicht-interaktive Befehle. Zeigt aktive Dateisystem- und Netzwerkrichtlinien in der untersten Zeile des Terminals an.
- **Headless-Modus (`--tui=none` / `--ci`)**: Deaktiviert die UI-Darstellung. Wird in CI-Umgebungen, Shell-Skripten oder bei Pipe-Umleitungen verwendet.

---

## Plattformunterstützung

Vetto nutzt die unprivilegierten Isolationsfunktionen des jeweiligen Betriebssystems:

| Plattform | Dateisystemisolation | Netzwerkisolation | Prozess-Lebenszyklus | Stufe |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Nativ)** | **Landlock LSM (ABI 1 bis 6)**<br>Tmpfs-Maskierung über `~/.ssh`, `~/.aws`, `.env` | **Netzwerk-Namespaces (`CLONE_NEWNET`)**<br>Loopback-Isolation mit lokalem TCP/TLS-Proxy | **PID-Namespaces (`CLONE_NEWPID`)**<br>Prozessbaum-Bereinigung via cgroups v2 `cgroup.kill` | Tier 1 (Vollständig) |
| **Linux (WSL2)** | **Landlock LSM über WSL2-Kernel**<br>Pfadzugriffsbeschränkungen | **Netzwerk-Namespaces in VM**<br>Gefilterte ausgehende Verbindungen | **PID-Namespaces und `/proc`-Sweep**<br>Vollständige Baumterminierung | Tier 1 (Vollständig) |
| **macOS (Darwin)** | **Seatbelt (`libsandbox.1.dylib`)**<br>Schreibzugriff beschränkt auf Projektordner und `/tmp` | **Netzwerkbeschränkung**<br>`--net=off` blockiert IP; `--net=allowlist` via Loopback-Proxy | **Prozessüberwachung**<br>Watchdog überwacht Kindprozessgruppen | Tier 2 (Ziel: Tier 1.5) |
| **Windows Nativ** | **AppContainer und LPAC**<br>Token-basierte Zugriffskontrolle | **Capability-Beschränkungen**<br>Eingeschränkte Netzwerk-SIDs | **Job Objects**<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Tier 3 (Guardrail) |

### Hinweis zu macOS Seatbelt

macOS bietet keine unprivilegierten Netzwerk-Namespaces. Vetto nutzt Apples natives Seatbelt-Framework (`libsandbox.1.dylib`), um Schreibzugriffe auf das Dateisystem zu beschränken und Benutzerdaten zu schützen. Mit `--net=off` werden Netzwerkverkehr und IPC zu `mDNSResponder` blockiert. Mit `--net=allowlist` startet Vetto einen temporären Loopback-Proxy auf `127.0.0.1` und setzt Proxy-Umgebungsvariablen. Lesezugriffe unter macOS sind bewusst breit gefasst, um die Stabilität des dyld-Caches zu gewährleisten.

---

## Unterstützte KI-Agenten

Vetto enthält vordefinierte Profile für mehr als 25 KI-Entwicklungswerkzeuge. Jedes Profil beschränkt den ausgehenden Netzwerkverkehr auf offizielle Endpunkte und schützt Zugangsdaten, während Paket-Caches zugänglich bleiben:

| Agent | Binary / Preset | Netzwerkendpunkte | Geschützte Konfigurationen und Caches |
| :--- | :--- | :--- | :--- |
| **Claude Code** | `claude` | `api.anthropic.com`, `claude.ai` | `~/.claude`, `~/.config/claude`, Plugins |
| **OpenAI Codex** | `codex` | `api.openai.com`, ChatGPT OAuth | `~/.codex`, `~/.config/codex`, Plugins |
| **Cursor** | `cursor` | Cursor-Backend, Erweiterungsmarktplatz | VS Code IPC-Sockets, `~/.cursor` |
| **Aider** | `aider` | Konfigurierte LLM-Provider-Endpunkte | Git-Repository-Root, Verlaufs-Caches |

Die vollständige Liste der unterstützten Agenten, Netzwerkbereiche und Pfadregeln finden Sie in der [Agent-Kompatibilitätsübersicht](agents.md).

---

## Python SDK (`vetto-python`)

Das Python-Paket in `../sdk/python/` bietet Anbindungen zum Ausführen isolierter Befehle und Absichern von Agent-Schritten:

```python
from vetto import VettoSandbox, VettoSecurityError, VettoTimeoutError

sandbox = VettoSandbox(
    project_dir=".",
    network="allowlist:api.anthropic.com,api.openai.com",
    profile="default",
    timeout_secs=60,
)

# Führt Befehl in der Sandbox aus. Löst VettoSecurityError bei Richtlinienverletzung aus (Exit 125).
result = sandbox.run(["pytest", "tests/"])
```

### LangGraph-Integration

Das Paket enthält `VettoToolNode` zur Isolierung von Werkzeugausführungen in LangGraph-Workflows:

```python
from vetto.langgraph import VettoToolNode

tool_node = VettoToolNode(
    tools=[search_tool, execute_code_tool],
    network="off",
    timeout_secs=30,
)
```

---

## Upstream-Integrationen

Vetto stellt Pull Requests zur containerlosen Prozessisolierung für verschiedene Open-Source-Agenten-Frameworks bereit:

| Framework | Issue | Pull Request | Details |
| :--- | :--- | :--- | :--- |
| **CrewAI** | [#7830](https://github.com/crewAIInc/crewAI/issues/7830) | [PR #7831](https://github.com/crewAIInc/crewAI/pull/7831) | Unprivilegierte Prozessisolierung mit `VettoExecTool` und `VettoPythonTool`, Workspace-Begrenzung und Timeout-Verwaltung. |
| **Microsoft AutoGen** | [#8298](https://github.com/microsoft/autogen/issues/8298) | [PR #8299](https://github.com/microsoft/autogen/pull/8299) | Containerlose Sandbox `VettoCommandLineCodeExecutor` in `autogen-ext`. |
| **OpenClaw** | [#160522](https://github.com/openclaw/openclaw/issues/160522) | [PR #161125](https://github.com/openclaw/openclaw/pull/161125) | Speicherbegrenzung und Heap-Schwellenwerte unter `--max-old-space-size`. |
| **Hugging Face smolagents** | [#2845](https://github.com/huggingface/smolagents/issues/2845) | [PR #2860](https://github.com/huggingface/smolagents/pull/2860) | `ProcessIsolatedExecutor` mit absolutem Timeout und Prozessgruppen-Terminierung. |
| **browser-use** | [#5879](https://github.com/browser-use/browser-use/issues/5879) | [PR #5929](https://github.com/browser-use/browser-use/pull/5929) | DNS-Vorabprüfung zur Blockierung von Loopback, RFC 1918, CGNAT und Cloud-Metadaten. |
| **OpenHands** | [#4266](https://github.com/OpenHands/software-agent-sdk/issues/4266) | [PR #5344](https://github.com/OpenHands/software-agent-sdk/pull/5344) | `LandlockWorkspace`-Backend mit Erkennung von Linux Landlock ABI 1 bis 6. |
| **Block goose** | [#12522](https://github.com/aaif-goose/goose/issues/12522) | [PR #12545](https://github.com/aaif-goose/goose/pull/12545) | `SubprocessExt` Prozess-Isolation mit Subreaper-Tracking und Namespace-Sandboxing. |
| **Block goose (ACP)** | [#12513](https://github.com/aaif-goose/goose/issues/12513) | [PR #12563](https://github.com/aaif-goose/goose/pull/12563) | Shell-Ausführungsrichtlinie (`GOOSE_ACP_CLIENT_TERMINAL`) mit Sandbox-Erkennung. |
| **Cline** | [#14544](https://github.com/cline/cline/issues/14544) | [PR #14583](https://github.com/cline/cline/pull/14583) | Terminal-Sandbox-Ausführung und Maskierung von Geheimnissen (`~/.ssh`, `.env`) in `ClineIgnoreController`. |
| **Qwen Code** | [#12856](https://github.com/QwenLM/qwen-code/issues/12856) | [PR #12953](https://github.com/QwenLM/qwen-code/pull/12953) | Bereinigung ausgehender Zugangsdaten und Workspace-Schutz. |
| **Claude Code History Viewer** | [#509](https://github.com/jhlee0409/claude-code-history-viewer/issues/509) | [PR #595](https://github.com/jhlee0409/claude-code-history-viewer/pull/595) | Validierung von Eingaben und Sitzungs-Wiederaufnahme-Flags. |

---

## Verifikation und Integrität

Releases werden über automatisierte GitHub-Actions-Workflows erstellt und sind öffentlich kryptografisch verifizierbar:

- **SLSA Level 3 Provenance**: in-toto Build-Attestierungen für alle Release-Binaries.
- **Minisign-Signaturen**: Veröffentlicht mit jedem Release-Archiv unter dem öffentlichen Schlüssel `75ECEC9B5080C590`.
- **SHA-256-Prüfsummen**: Werden von Installationsskripten automatisch überprüft.

---

## Dokumentation

- [Plattform-Backends und Isolationsspezifikation](platform-backends.md)
- [Agent-Presets und Konfiguration](agents.md)
- [Bedrohungsmodell und Sicherheitsgrenzen](threat-model.md)
- [Preflight-Diagnoseprüfungen](architecture/verify-ng.md)
- [Exit-Codes und Fehlermodi](exit-codes.md)
- [Sicherheitsrichtlinie und Schwachstellenmeldung](../SECURITY.md)

---

## Beitragen

Beiträge sind willkommen. Bitte erstellen Sie Pull Requests gegen den `main`-Branch. Alle Änderungen an Sicherheitsgrenzen müssen entsprechende Validierungstests enthalten. Pull Requests werden in GitHub Actions CI auf Linux-, macOS- und Windows-Runnern automatisch getestet.

---

## Lizenz

Lizenziert unter der Apache-Lizenz, Version 2.0 ([LICENSE](../LICENSE)).
