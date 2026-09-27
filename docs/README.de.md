![vetto — Kernel-Isolationsbarriere zwischen KI-Agent und Host-System](../assets/readme/hero.png)

<p align="center">
  <a href="https://github.com/shleder/vetto/actions"><img src="https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/shleder/vetto/releases/tag/v0.5.2"><img src="https://img.shields.io/badge/version-0.5.2-blue?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@shledery/vetto"><img src="https://img.shields.io/badge/npm-v0.5.2-CB3837?logo=npm&logoColor=white&style=flat-square" alt="npm"></a>
  <a href="https://crates.io/crates/vetto"><img src="https://img.shields.io/badge/crates.io-v0.5.2-orange?logo=rust&logoColor=white&style=flat-square" alt="crates.io"></a>
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

Daemon-lose, unprivilegierte (rootless) Kernel-Sandbox und Richtlinien-Laufzeitumgebung für KI-Programmier-CLI-Agenten (**Claude Code**, **OpenAI Codex**, **Cursor**, **OpenCode**, **Aider**, **Antigravity**, **OMP**, **ZCode**, **Kimi**, **Grok**). Vetto injiziert unveränderliche Sicherheitsgrenzen direkt zwischen `fork()` und `execve()` mit einer Startlatenz von unter 4 ms und ohne Docker-Overhead.

---

## Interaktives TUI Mission Control

Starten Sie das interaktive Mission Control Dashboard einfach durch Ausführen von `vetto` im Terminal:

```bash
vetto
```

Beinhaltet Live-Erkennung von KI-Agenten, One-Touch-Aktivierung von PATH-Shims, VFS-Geheimnismatrix-Audit, Kernel-Diagnose, sofortiges Rollback, Echtzeit-Sicherheitsereignis-Stream (`[5: SECURITY STREAM]`) und Multi-Agenten-Schwarm-Orchestrierung (`[6: FLEET SWARM]`).

Tastenbelegungen, Ansichten und Designkonfiguration finden Sie im [Mission Control TUI Handbuch](tui.md).

---

## Beweise statt Versprechen

Autonome Agenten führen nicht-deterministischen Code aus. Nicht vertrauenswürdige Abhängigkeiten, Prompt-Injektionen oder halluzinierte Befehle können Host-Zugangsdaten (`~/.ssh`, `~/.aws`, `.env`) kompromittieren oder verwaiste Hintergrundprozesse hinterlassen. Unter Vetto werden unautorisierte Systemaufrufe deterministisch blockiert:

```text
> Lesen von ~/.ssh/id_rsa...         BLOCKIERT (Geheimnisschutz, EACCES)
> Öffnen von Raw-Sockets...          BLOCKIERT (Netzwerk-Namensraum, EAFNOSUPPORT)
> Starten von Hintergrund-Dienst...  BEENDET (Prozessbaum-Eliminierung, Exit 125)
```

![Blockierter Exfiltrationsversuch unter vetto](../assets/demo.svg)

### Fail-Closed Vertrag (Exit-Code 125)

Wird eine Isolationsgrenze verletzt oder können erforderliche Kernel-Primitive nicht erzwungen werden, bricht die Ausführung sofort mit **Exit-Code 125** ab. Alle Kind- und Waisenprozesse werden synchron über cgroups v2 `cgroup.kill` beendet. Nicht unterstützte OS-Funktionen werden transparent als solche gemeldet—Sicherheit wird niemals stillschweigend herabgestuft.

---

## Schnellstart

### 1. Installation

Über Standard-Paketmanager:

```bash
# npm (plattformübergreifende Binärdatei)
npm install -g @shledery/vetto

# Homebrew (macOS & Linux)
brew install shleder/tap/vetto

# Cargo (crates.io)
cargo install vetto
```

Oder über den direkten Curl-Installer:

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

### 2. Transparente Agenten-Isolation (PATH-Shims)

Aktivieren Sie die konfigurationsfreie Sandbox für Ihren Agenten. Vetto installiert einen transparenten Shim in `~/.vetto/shims` mit Vorrang im `PATH`:

```bash
vetto enable claude   # unterstützt codex, opencode, cursor, aider, antigravity und 18 Profile
claude                # läuft wie gewohnt — vollständig durch den Kernel geschützt
```

Zurück zur nativen, ungeschützten Ausführung:

```bash
vetto disable claude
```

### 3. Direkte Ausführung & Sicheres Eval

Führen Sie eigenständige Skripte unter strikter Standardisolation aus:

```bash
vetto run -- python script.py
vetto -- npm test
```

Sichere Auswertung von Code mit cgroups v2 Speicherobergrenzen und Hardware-Timeouts:

```bash
vetto eval --python -c "print(1 + 1)" --timeout 5 --memory 256
```

### 4. Sofortiges Snapshot-Rollback

Vetto erstellt vor der Ausführung des Agenten automatisch leichtgewichtige Copy-on-Write-Snapshots:

```bash
vetto diff        # Änderungen anzeigen, die der Agent an Dateien vorgenommen hat
vetto undo        # Arbeitsverzeichnis sofort in den sauberen Zustand vor der Ausführung zurücksetzen
```

### 5. Kernel-Diagnose

Überprüfen Sie die Isolationsfähigkeiten des Host-Kernels:

```bash
vetto doctor --preflight          # prüft Landlock ABI, Namensräume und cgroups v2
vetto doctor --preflight --json   # maschinenlesbare JSON-Ausgabe
```

### 6. Multi-Agenten-Flottenparallelität (`vetto fleet`)

Orchestrieren Sie Schwärme isolierter KI-Programmieragenten mit cgroups v2 Fair-Share-Ressourcenkontingenten, paarweiser Namensraum-Isolation und ephemeren CoW-Zweigen:

```bash
# Flottenkapazität, Fair-Share-Limits und aktive Worker-Scopes prüfen
vetto fleet status
vetto fleet status --json

# Gleichzeitiges Starten isolierter Worker-Agenten mit Fair-Share-Cgroups
vetto fleet spawn claude --count 3
vetto fleet spawn --count 4 -- sh -c "python agent.py"

# Automatisierte paarweise Isolationsüberprüfung über N Worker (28 Prüfungen für N=8)
vetto fleet verify --workers 8 --json

# Beenden eines Workers oder Bereinigen des gesamten Flottenschwarms
vetto fleet kill agent-01
vetto fleet kill --all
```

---

## Plattform-Garantien

| Plattform / Tier | Dateisystem-Isolation | Netzwerk-Isolation | Prozess-Lebenszyklus | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Nativ)**<br>Tier 1 | **Landlock LSM (ABI 1–6)**<br>Inode-Maskierung für `~/.ssh`, `~/.aws`, `.env` (tmpfs 0000) | **Netzwerk-Namensräume (`CLONE_NEWNET`)**<br>Loopback-Isolation + lokaler L7-Broker mit SNI-Prüfung | **PID-Namensräume (`CLONE_NEWPID`)**<br>Deterministische Prozessbaum-Beendigung über `cgroups v2` | Produktiv |
| **Linux (WSL2)**<br>Tier 1 | **Landlock LSM über WSL2-Kernel**<br>Vollständige Inode-Beschränkung | **Netzwerk-Namensräume in VM**<br>Isolierter Broker-Egress | **PID-Namensräume + `/proc`-Bereinigung**<br>Vollständige Beseitigung von Waisenprozessen | Produktiv (Empfohlen für Windows) |
| **macOS (Darwin)**<br>Tier 2 | **Seatbelt (`libsandbox.1.dylib`)**<br>Schreibzugriff beschränkt auf `$PROJECT` und `/tmp` | **Netzwerk-Sperre**<br>`--net=off` über `(deny network*)`-Regeln | **Prozessgruppen-Bereinigung**<br>Überwachung durch kqueue / `pidfd`-Watchdog | Standard (Erfordert Festplattenvollzugriff für `~/Documents`) |
| **Windows Nativ**<br>Tier 3 | **AppContainer & LPAC**<br>DACL-Token-Beschränkung | **Fähigkeiten-Sperre**<br>Eingeschränkte Netzwerk-SIDs | **Job-Objekte**<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Basisschutz (WSL2 für Tier 1 empfohlen) |

---

## Kryptografische Integrität

Alle Releases werden in isolierten GitHub Actions-Workflows gebaut und kryptografisch signiert:

- **SLSA Level 3 Provenance**: In-toto-Nachweise für alle Release-Binärdateien.
- **Minisign-Signaturen**: Veröffentlicht unter dem öffentlichen Schlüssel `75ECEC9B5080C590`.
- **SHA-256 Prüfsummen**: Automatische Integritätsprüfung bei der Installation.

---

## Lizenz

Lizenziert unter der Apache License 2.0 ([LICENSE](../LICENSE)).
