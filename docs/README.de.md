<div align="center">

```text
██╗   ██╗███████╗████████╗████████╗ ██████╗ 
██║   ██║██╔════╝╚══██╔══╝╚══██╔══╝██╔═══██╗
██║   ██║█████╗     ██║      ██║   ██║   ██║
╚██╗ ██╔╝██╔══╝     ██║      ██║   ██║   ██║
 ╚████╔╝ ███████╗   ██║      ██║   ╚██████╔╝
  ╚═══╝  ╚══════╝   ╚═╝      ╚═╝    ╚═════╝ 
```

# VETTO

<p align="center">
  <b>Sub-Millisekunden Linux-Kernel-Sandbox für KI-Coding-CLI-Agenten</b>
</p>

[![CI](https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/shleder/vetto/actions)
[![Release](https://img.shields.io/github/v/release/shleder/vetto?label=release&color=blue&style=flat-square)](https://github.com/shleder/vetto/releases)
[![npm version](https://img.shields.io/badge/npm-v0.6.0-CB3837?logo=npm&logoColor=white&style=flat-square)](https://www.npmjs.com/package/@shledery/vetto)
[![crates.io](https://img.shields.io/badge/crates.io-v0.6.0-orange?logo=rust&logoColor=white&style=flat-square)](https://crates.io/crates/vetto)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)](https://github.com/shleder/vetto)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square)](../LICENSE)

<p align="center">
  <a href="../README.md">English</a> |
  <a href="README.ru.md">Русский</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.ja.md">日本語</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.de.md"><b>Deutsch</b></a>
</p>

</div>

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

Detaillierte Leistungsmessungen und Integrationsanleitungen für Benchmark-Harnesses finden Sie unter [SWE-bench vs Docker Benchmark](benchmarks/swe-bench.md).

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

Führen Sie KI-Agenten sicher in Ihren CI-Pipelines ohne Docker oder Root-Rechte mit der offiziellen `shleder/vetto`-Action aus:

```yaml
- name: Run Sandboxed Agent
  uses: shleder/vetto@v0.6.0
  with:
    command: 'npx @anthropic-ai/claude-code -p "Fix linter errors"'
    agent: 'claude'
    profile: 'strict'
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Detaillierte Konfigurationsoptionen, mehrstufige Workflows und SARIF-Sicherheitsberichte finden Sie im [CI/CD-Integrationsleitfaden](ci-cd.md).

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

## Verifikation und Integrität

Releases werden über automatisierte GitHub-Actions-Workflows erstellt und sind öffentlich kryptografisch verifizierbar:

- **SLSA Level 3 Provenance**: in-toto Build-Attestierungen für alle Release-Binaries.
- **Minisign-Signaturen**: Veröffentlicht mit jedem Release-Archiv unter dem öffentlichen Schlüssel `75ECEC9B5080C590`.
- **SHA-256-Prüfsummen**: Werden von Installationsskripten automatisch überprüft.

---

## Dokumentation

- [Plattform-Backends und Isolationsspezifikation](platform-backends.md)
- [Agent-Presets und Konfiguration](agents.md)
- [SWE-bench vs Docker Benchmark](benchmarks/swe-bench.md)
- [Bedrohungsmodell und Sicherheitsgrenzen](threat-model.md)
- [CI/CD-Integration und GitHub Actions](ci-cd.md)
- [Exit-Codes und Fehlermodi](exit-codes.md)
- [Sicherheitsrichtlinie und Schwachstellenmeldung](../SECURITY.md)

---

## Beitragen

Beiträge sind willkommen. Bitte erstellen Sie Pull Requests gegen den `main`-Branch. Alle Änderungen an Sicherheitsgrenzen müssen entsprechende Validierungstests enthalten. Pull Requests werden in GitHub Actions CI auf Linux-, macOS- und Windows-Runnern automatisch getestet.

---

## Lizenz

Lizenziert unter der Apache-Lizenz, Version 2.0 ([LICENSE](../LICENSE)).
