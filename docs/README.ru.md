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
  <b>Субмиллисекундный sandbox на уровне ядра Linux для AI CLI-агентов</b>
</p>

[![CI](https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square)](https://github.com/shleder/vetto/actions)
[![Release](https://img.shields.io/github/v/release/shleder/vetto?label=release&color=blue&style=flat-square)](https://github.com/shleder/vetto/releases)
[![npm version](https://img.shields.io/badge/npm-v0.6.0-CB3837?logo=npm&logoColor=white&style=flat-square)](https://www.npmjs.com/package/@shledery/vetto)
[![crates.io](https://img.shields.io/badge/crates.io-v0.6.0-orange?logo=rust&logoColor=white&style=flat-square)](https://crates.io/crates/vetto)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)](https://github.com/shleder/vetto)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square)](../LICENSE)

<p align="center">
  <a href="../README.md">English</a> |
  <a href="README.ru.md"><b>Русский</b></a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.ja.md">日本語</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.de.md">Deutsch</a>
</p>

</div>

Vetto — это непривилегированный sandbox для AI CLI-агентов (Claude Code, OpenAI Codex, Cursor, OpenCode, Aider). Он изолирует файловую систему, сетевые сокеты и дочерние процессы между вызовами `fork()` и `execve()`, используя встроенные механизмы ядра Linux и macOS без фонового демона и без root-привилегий.

---

## Контроль границ на уровне ядра

AI-агенты запускают сгенерированные шелл-команды и скрипты сборки. Если агент попытается прочитать приватные ключи, открыть сырой сетевой сокет или создать фоновый процесс-демон, Vetto блокирует операцию на уровне ядра:

```text
> Reading ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> Opening raw socket...             BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...       TERMINATED (process tree extinction, exit 125)
```

### Завершение по принципу fail-closed (код 125)

При нарушении политики или отсутствии в ядре необходимого механизма изоляции Vetto немедленно завершает работу с кодом 125. Все дочерние процессы и фоновые задачи синхронно уничтожаются через `cgroup.kill` в cgroups v2. Если операционная система не может применить заданное правило, Vetto сообщает об отсутствующей возможности и останавливается, не допуская работы со сниженным уровнем безопасности.

---

## Быстрый старт

### 1. Установка

Через пакетные менеджеры:

```bash
# npm (кроссплатформенный бинарник)
npm install -g @shledery/vetto

# Homebrew (macOS и Linux)
brew install shleder/tap/vetto

# Cargo (crates.io)
cargo install vetto
```

Либо через скрипт установки curl:

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

### 2. Прозрачный перехват агентов

Подключение изоляции для установленных AI-агентов без изменения настроек шелла и алиасов:

```bash
vetto enable --all
```

Vetto находит в `$PATH` поддерживаемые бинарники агентов (`claude`, `codex`, `cursor`, `opencode`, `aider`, `antigravity` и др.) и размещает перехватывающие шимы в `~/.vetto/shims`.

После включения запускайте агентов как обычно:

```bash
claude                # выполняется в песочнице с политиками Landlock LSM
cursor                # выполняется с защитой учетных данных и фильтрацией сети
```

Управление отдельными агентами:

```bash
vetto enable claude    # изолировать только claude
vetto disable claude   # вернуть прямой запуск без изоляции
```

### Сравнение с Docker

AI-агентам нужны локальные компиляторы, существующие кэши пакетов и интерактивный терминал. Запуск в Docker требует развертывания тяжелых контейнеров, тогда как Vetto накладывает ограничения ядра прямо на процессы хоста:

| Параметр | Docker / DinD | Vetto |
| :--- | :--- | :--- |
| Накладные расходы на запуск | 500–2000 мс на создание контейнера | Менее 4 мс холодного старта между `fork()` и `execve()` |
| Использование памяти | Фоновый процесс `dockerd` | 0 МБ фоновой памяти (нет демона) |
| Модель привилегий | Требует `root` или группу `docker` | Непривилегированные user namespaces, Landlock LSM и cgroups v2 |
| Инструментарий | Требует пересборки образов | Прямой доступ к хостовым `cargo`, `npm`, `pip`, `uv` |
| Кэши пакетов | Volume mounts или повторные загрузки | Прямое переиспользование кэшей хоста |
| Очистка процессов | Может оставлять осиротевшие контейнеры | Синхронное уничтожение дерева процессов через `cgroup.kill` cgroups v2 |

### 3. Прямой запуск

Запуск произвольных команд внутри песочницы:

```bash
vetto run -- python script.py
vetto -- npm test
```

### 4. Откат изменений рабочего каталога (снапшоты)

Перед началом работы агента Vetto создает copy-on-write снимок рабочего каталога:

```bash
vetto diff        # показать измененные, добавленные или удаленные агентом файлы
vetto undo        # вернуть рабочую директорию в состояние до запуска
```

### 5. Диагностика хоста

Проверка доступных на машине примитивов изоляции ядра:

```bash
vetto doctor --preflight          # аудит Landlock ABI, пространств имен и cgroups v2
vetto doctor --preflight --json   # отчет о диагностике в формате JSON
```

---

## Интеграция с GitHub Actions

Запускайте AI-агентов безопасно в CI-пайплайнах без Docker и root-привилегий с помощью официального экшена `shleder/vetto`:

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

Подробные параметры, многошаговые сценарии и экспорт отчетов SARIF описаны в [Руководстве по CI/CD](ci-cd.md).

---

## Работа с терминалом и статуслайн

Интерактивные агенты (Claude Code, Codex) сами управляют состоянием терминала (PTY). Vetto сохраняет прямой ввод-вывод терминала и отображает состояние песочницы:

- **Статуслайн (`--tui=statusline`)**: режим по умолчанию для неинтерактивных команд. Показывает активные политики файлов и сети в нижней строке терминала.
- **Headless-режим (`--tui=none` / `--ci`)**: отключает отрисовку терминального интерфейса. Используется в CI, скриптах и при перенаправлении стандартных потоков.

---

## Поддержка платформ

Vetto использует непривилегированные средства изоляции каждой операционной системы:

| Платформа | Изоляция файлов | Изоляция сети | Жизненный цикл процессов | Тир |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Native)** | **Landlock LSM (ABI 1–6)**<br>Маскирование tmpfs над `~/.ssh`, `~/.aws`, `.env` | **Сетевые пространства имен (`CLONE_NEWNET`)**<br>Изоляция loopback с локальным TCP/TLS прокси | **PID namespaces (`CLONE_NEWPID`)**<br>Зачистка дерева процессов через `cgroup.kill` cgroups v2 | Tier 1 (Полный) |
| **Linux (WSL2)** | **Landlock LSM через ядро WSL2**<br>Ограничение путей файловой системы | **Сетевые пространства внутри VM**<br>Фильтрация исходящих соединений | **PID namespaces и сканирование `/proc`**<br>Полное уничтожение дерева | Tier 1 (Полный) |
| **macOS (Darwin)** | **Seatbelt (`libsandbox.1.dylib`)**<br>Запрет записи вне рабочего каталога и `/tmp` | **Ограничение сети**<br>`--net=off` блокирует IP; `--net=allowlist` через loopback-прокси | **Надзор за процессами**<br>Watchdog отслеживает группы дочерних процессов | Tier 2 (Целевой Tier 1.5) |
| **Windows Native** | **AppContainer и LPAC**<br>Контроль доступа на уровне токенов | **Ограничение возможностей**<br>Ограниченные сетевые SID | **Job Objects**<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Tier 3 (Guardrail) |

### Особенности Seatbelt на macOS

В macOS отсутствуют непривилегированные сетевые пространства имен. Vetto применяет Apple Seatbelt (`libsandbox.1.dylib`) для ограничения записи и защиты учетных данных. В режиме `--net=off` блокируется сетевой трафик и IPC к `mDNSResponder`. В режиме `--net=allowlist` Vetto запускает локальный прокси на `127.0.0.1` и разрешает исходящий TCP-трафик на этот порт. Чтение файлов в macOS настроено широко для корректного взаимодействия с системным кэшем dyld.

---

## Поддерживаемые AI-агенты

Vetto содержит готовые профили для более чем 25 инструментов AI-разработки. Профили ограничивают сетевой трафик официальными эндпоинтами провайдеров и защищают учетные данные, сохраняя доступ к кэшам пакетов:

| Агент | Бинарник / Пресет | Сетевые эндпоинты | Защищаемые конфигурации и кэши |
| :--- | :--- | :--- | :--- |
| **Claude Code** | `claude` | `api.anthropic.com`, `claude.ai` | `~/.claude`, `~/.config/claude`, плагины |
| **OpenAI Codex** | `codex` | `api.openai.com`, ChatGPT OAuth | `~/.codex`, `~/.config/codex`, плагины |
| **Cursor** | `cursor` | Бэкенд Cursor, маркетплейс расширений | Сокеты IPC VS Code, `~/.cursor` |
| **Aider** | `aider` | Эндпоинты настроенных LLM-провайдеров | Корень git-репозитория, история сессий |

Полный список поддерживаемых агентов, сетевых правил и путей доступен в [Реестре совместимости агентов](agents.md).

---

## Верификация и целостность

Релизы собираются через автоматизированные процессы GitHub Actions с публичной проверкой:

- **SLSA Level 3 Provenance**: аттестации сборки in-toto генерируются для релизных бинарников.
- **Подписи Minisign**: публикуются с каждым релизным архивом под публичным ключом `75ECEC9B5080C590`.
- **Контрольные суммы SHA-256**: проверяются установочными скриптами автоматически.

---

## Документация

- [Бэкенды платформ и спецификация изоляции](platform-backends.md)
- [Пресеты агентов и конфигурация](agents.md)
- [Модель угроз и границы безопасности](threat-model.md)
- [Интеграция с CI/CD и GitHub Actions](ci-cd.md)
- [Коды возврата и режимы сбоев](exit-codes.md)
- [Политика безопасности и сообщение об уязвимостях](../SECURITY.md)

---

## Участие в разработке

Мы приветствуем предложения и код. Создавайте пулл-реквесты в ветку `main`. Любые изменения границ безопасности должны сопровождаться интеграционными тестами. Проверки PR выполняются на раннерах Linux, macOS и Windows в GitHub Actions CI.

---

## Лицензия

Распространяется на условиях лицензии Apache License, Version 2.0 ([LICENSE](../LICENSE)).
