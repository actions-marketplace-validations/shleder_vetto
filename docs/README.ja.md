![vetto - AIエージェントとマシンの間のカーネル隔離壁](../assets/readme/hero.png)

<p align="center">
  <a href="https://github.com/shleder/vetto/actions"><img src="https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/shleder/vetto/releases/tag/v0.6.0"><img src="https://img.shields.io/badge/version-0.6.0-blue?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@shledery/vetto"><img src="https://img.shields.io/badge/npm-v0.6.0-CB3837?logo=npm&logoColor=white&style=flat-square" alt="npm"></a>
  <a href="https://crates.io/crates/vetto"><img src="https://img.shields.io/badge/crates.io-v0.6.0-orange?logo=rust&logoColor=white&style=flat-square" alt="crates.io"></a>
  <a href="../LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="../README.md">English</a> |
  <a href="README.ru.md">Русский</a> |
  <a href="README.zh.md">简体中文</a> |
  <a href="README.ja.md"><b>日本語</b></a> |
  <a href="README.es.md">Español</a> |
  <a href="README.de.md">Deutsch</a>
</p>

Vetto は、Claude Code、OpenAI Codex、Cursor、OpenCode、Aider などの AI コーディング CLI エージェント向けの非特権サンドボックスです。バックグラウンドデーモンや root 権限を必要とせず、Linux および macOS のネイティブカーネル機能を利用して、`fork()` と `execve()` の間でファイルシステムアクセス、ネットワークソケット、子プロセスを隔離します。

---

## カーネルレベルの境界強制

AI コーディングエージェントは、生成されたシェルコマンドやビルドスクリプトを実行します。エージェントが秘密鍵の読み取り、未加工のネットワークソケットの開放、または監視されないバックグラウンドプロセスの生成を試みた場合、Vetto はカーネルレイヤーで直接ブロックします：

```text
> Reading ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> Opening raw socket...             BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...       TERMINATED (process tree extinction, exit 125)
```

### フェイルクローズ実行（終了コード 125）

エージェントがポリシーに違反した場合、またはホストカーネルに必要な分離メカニズムが存在しない場合、Vetto は直ちに終了コード 125 で停止します。すべての子孫プロセスおよびバックグラウンドワーカーは、cgroups v2 の `cgroup.kill` を通じて同期的に終了されます。ホスト OS が設定されたルールを強制できない場合、Vetto はセキュリティレベルを低下させて実行するのではなく、不足している機能を報告して停止します。

---

## クイックスタート

### 1. インストール

標準的なパッケージマネージャーによるインストール：

```bash
# npm (クロスプラットフォーム対応グローバルバイナリ)
npm install -g @shledery/vetto

# Homebrew (macOS および Linux)
brew install shleder/tap/vetto

# Cargo (crates.io)
cargo install vetto
```

またはスタンドアロンの curl インストーラ：

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

### 2. 透過的なエージェントラッピング

シェルの設定やエイリアスを変更することなく、インストール済みの AI コーディングエージェントをサンドボックスでラップします：

```bash
vetto enable --all
```

Vetto は `$PATH` からサポート対象のエージェントバイナリ（`claude`、`codex`、`cursor`、`opencode`、`aider`、`antigravity` など）を検索し、`~/.vetto/shims` にインターセプタシムを配置します。

有効化後は、通常通りエージェントを実行するだけです：

```bash
claude                # Landlock LSM ポリシー下でサンドボックス実行
cursor                # 資格情報保護およびネットワーク制限付きで実行
```

個別のエージェントを管理する場合：

```bash
vetto enable claude    # claude のみラップ
vetto disable claude   # サンドボックスなしの直接実行に戻す
```

### Docker との比較

AI コーディングエージェントには、ローカルコンパイラ、既存のパッケージキャッシュ、インタラクティブ端末が必要です。Docker 内での実行には重いコンテナ環境が必要ですが、Vetto はホストプロセスに直接カーネルサンドボックスを適用します：

| 項目 | Docker / DinD | Vetto |
| :--- | :--- | :--- |
| 起動オーバーヘッド | コンテナ作成に 500ms 〜 2000ms | `fork()` と `execve()` の間で 4ms 未満のコールドスタート |
| メモリ使用量 | バックグラウンドで常駐する `dockerd` プロセス | 0 MB バックグラウンドメモリ（デーモンなし） |
| 特権モデル | `root` または `docker` グループ権限が必要 | 非特権ユーザー名前空間、Landlock LSM、cgroups v2 |
| ツールチェーン | コンテナイメージの再ビルドが必要 | ホストの `cargo`、`npm`、`pip`、`uv` への直接アクセス |
| パッケージキャッシュ | ボリュームマウントまたは再ダウンロード | ホストのパッケージキャッシュを直接再利用 |
| プロセスのクリーンアップ | 孤立したコンテナが残る場合がある | cgroups v2 `cgroup.kill` によるプロセスツリーの同期的終了 |

### 3. 直接実行

サンドボックス内で任意のコマンドやスクリプトを実行：

```bash
vetto run -- python script.py
vetto -- npm test
```

### 4. ワークスペースのスナップショットとロールバック

エージェントの作業開始前に、Vetto はプロジェクトディレクトリの Copy-on-Write スナップショットを作成します：

```bash
vetto diff        # エージェントが変更、追加、削除したファイルを表示
vetto undo        # ワークスペースを実行前の状態にロールバック
```

### 5. ホスト診断

現在のマシンで利用可能なカーネル分離機能を確認：

```bash
vetto doctor --preflight          # Landlock ABI、名前空間、cgroups v2 を検査
vetto doctor --preflight --json   # 診断結果を JSON 形式で出力
```

---

## GitHub Actions との連携

CI 環境で AI コーディングエージェントを実行する場合、通常 Docker-in-Docker が使用されますが、イメージのプル遅延が発生し、特権ランナーを必要とすることが多く、非 Linux VM では動作しません。

`shleder/vetto` アクションは、Docker なしで標準の GitHub Actions ランナー上でエージェントを実行します：

- バイナリ検証付きで 4ms 未満のコールドスタート。
- 標準 Ubuntu ランナー上でのルートレス Landlock LSM および cgroups v2 の適用。
- `$GITHUB_WORKSPACE` およびキャッシュ（`actions/cache`、`actions/setup-node`、`actions/setup-python`）への直接アクセス。
- `cgroup.kill` によるすべてのサブプロセスの確実なクリーンアップ。
- Ubuntu、macOS、Windows ランナーのクロスプラットフォームサポート。

### オプション A：サンドボックス化されたエージェントステップの実行

ポリシー許可リストおよびオプションの SARIF 監査出力を備えたエージェント実行：

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
        uses: shleder/vetto@v0.6.0
        with:
          command: 'npx @anthropic-ai/claude-code -p "Run linter and fix basic formatting"'
          agent: 'claude'
          profile: 'strict'
          fail-on-block: '1'
          upload-sarif: 'true'
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### オプション B：マルチステップワークフロー用の Vetto セットアップ

`command` 入力を省略すると、`vetto` バイナリが `$GITHUB_PATH` にインストールされます：

```yaml
      - name: Setup Vetto
        uses: shleder/vetto@v0.6.0
        with:
          version: 'latest'

      - name: Run Sandboxed Commands
        run: |
          vetto doctor --preflight
          vetto run -- aider --message "Refactor parser error handling"
```

---

## 端末処理とステータスライン

Claude Code や Codex などのインタラクティブエージェントは、独自に端末状態（PTY）を管理します。Vetto は直接の端末入出力を維持しながら、サンドボックスの状態を表示します：

- **ステータスラインオーバーレイ (`--tui=statusline`)**：非インタラクティブコマンドのデフォルト。端末の最下行にアクティブなファイルシステムおよびネットワークポリシーを表示します。
- **ヘッドレスモード (`--tui=none` / `--ci`)**：端末 UI の描画を無効化します。CI 環境、シェルスクリプト、または標準ストリームをパイプで渡す場合に使用します。

---

## プラットフォームサポート

Vetto は各 OS が提供する非特権分離機能を利用します：

| プラットフォーム | ファイルシステム分離 | ネットワーク分離 | プロセスライフサイクル | 区分 |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (ネイティブ)** | **Landlock LSM (ABI 1 〜 6)**<br>`~/.ssh`、`~/.aws`、`.env` の tmpfs マスク | **ネットワーク名前空間 (`CLONE_NEWNET`)**<br>ローカル TCP/TLS プロキシによるループバック分離 | **PID 名前空間 (`CLONE_NEWPID`)**<br>cgroups v2 `cgroup.kill` によるプロセスツリー終了 | Tier 1 (完全) |
| **Linux (WSL2)** | **WSL2 カーネル経由の Landlock LSM**<br>パスアクセス制限 | **VM 内のネットワーク名前空間**<br>アウトバウンド通信のフィルタリング | **PID 名前空間と `/proc` スイープ**<br>完全なツリー終了 | Tier 1 (完全) |
| **macOS (Darwin)** | **Seatbelt (`libsandbox.1.dylib`)**<br>プロジェクトディレクトリおよび `/tmp` への書き込み制限 | **ネットワーク制限**<br>`--net=off` による IP 遮断、`--net=allowlist` によるループバックプロキシ | **プロセス監視**<br>子プロセスグループを追跡する Watchdog | Tier 2 (目標 Tier 1.5) |
| **Windows ネイティブ** | **AppContainer および LPAC**<br>トークンベースのアクセス制御 | **機能制限**<br>制限付きネットワーク SID | **Job Objects**<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Tier 3 (Guardrail) |

### macOS Seatbelt に関する注意

macOS は非特権のネットワーク名前空間を提供していません。Vetto は Apple ネイティブの Seatbelt フレームワーク (`libsandbox.1.dylib`) を使用して、ファイルシステムの書き込みアクセスを制限し、資格情報を保護します。`--net=off` を指定すると、ネットワークトラフィックと `mDNSResponder` への IPC がブロックされます。`--net=allowlist` を指定すると、Vetto は `127.0.0.1` でエフェメラルなループバックプロキシを実行し、プロキシ環境変数を設定します。macOS の読み取り制限は、システム dyld キャッシュの動作に対応するため広く設定されています。

---

## サポート対象の AI エージェント

Vetto には、25 種類以上の AI コーディングツール用の事前設定済みプロファイルが含まれています。各プロファイルは、ネットワーク送信を既知のプロバイダーエンドポイントに限定し、パッケージキャッシュを利用可能な状態に保ちながらホストの資格情報を保護します：

| エージェント | バイナリ / プリセット | ネットワークエンドポイント | 保護される設定およびキャッシュ |
| :--- | :--- | :--- | :--- |
| **Claude Code** | `claude` | `api.anthropic.com`, `claude.ai` | `~/.claude`, `~/.config/claude`, プラグイン |
| **OpenAI Codex** | `codex` | `api.openai.com`, ChatGPT OAuth | `~/.codex`, `~/.config/codex`, プラグイン |
| **Cursor** | `cursor` | Cursor バックエンド、拡張機能マーケットプレイス | VS Code IPC ソケット、`~/.cursor` |
| **Aider** | `aider` | 設定された LLM プロバイダーのエンドポイント | Git リポジトリルート、履歴キャッシュ |

サポートされているエージェント、ネットワーク範囲、およびパスルールの完全なリストについては、[エージェント互換性レジストリ](agents.md) を参照してください。

---

## Python SDK (`vetto-python`)

`../sdk/python/` にある Python パッケージは、サンドボックス化されたコマンドの実行やエージェントステップの分離を行うバインディングを提供します：

```python
from vetto import VettoSandbox, VettoSecurityError, VettoTimeoutError

sandbox = VettoSandbox(
    project_dir=".",
    network="allowlist:api.anthropic.com,api.openai.com",
    profile="default",
    timeout_secs=60,
)

# サンドボックス内でコマンドを実行。ポリシー違反時 (exit 125) に VettoSecurityError を送出。
result = sandbox.run(["pytest", "tests/"])
```

### LangGraph 連携

LangGraph ワークフロー内でツール実行を分離するための `VettoToolNode` が含まれています：

```python
from vetto.langgraph import VettoToolNode

tool_node = VettoToolNode(
    tools=[search_tool, execute_code_tool],
    network="off",
    timeout_secs=30,
)
```

---

## アップストリーム連携

Vetto は、複数のオープンソースエージェントフレームワークにコンテナレスプロセス分離の Pull Request を提供しています：

| フレームワーク | Issue | Pull Request | 詳細 |
| :--- | :--- | :--- | :--- |
| **CrewAI** | [#7830](https://github.com/crewAIInc/crewAI/issues/7830) | [PR #7831](https://github.com/crewAIInc/crewAI/pull/7831) | ワークスペース境界の保護とタイムアウト処理を備えた `VettoExecTool` および `VettoPythonTool` による非特権プロセス分離。 |
| **Microsoft AutoGen** | [#8298](https://github.com/microsoft/autogen/issues/8298) | [PR #8299](https://github.com/microsoft/autogen/pull/8299) | `autogen-ext` における `VettoCommandLineCodeExecutor` コンテナレスサンドボックス。 |
| **OpenClaw** | [#160522](https://github.com/openclaw/openclaw/issues/160522) | [PR #161125](https://github.com/openclaw/openclaw/pull/161125) | `--max-old-space-size` に基づくメモリ封じ込めとヒープ閾値制御。 |
| **Hugging Face smolagents** | [#2845](https://github.com/huggingface/smolagents/issues/2845) | [PR #2860](https://github.com/huggingface/smolagents/pull/2860) | ハードタイムアウトとプロセスグループ終了を備えた `ProcessIsolatedExecutor`。 |
| **browser-use** | [#5879](https://github.com/browser-use/browser-use/issues/5879) | [PR #5929](https://github.com/browser-use/browser-use/pull/5929) | ループバック、RFC 1918、CGNAT、およびクラウドメタデータアドレスをブロックする DNS プリフライトチェック。 |
| **OpenHands** | [#4266](https://github.com/OpenHands/software-agent-sdk/issues/4266) | [PR #5344](https://github.com/OpenHands/software-agent-sdk/pull/5344) | Linux Landlock ABI 1 〜 6 自動検出を使用する `LandlockWorkspace` バックエンド。 |
| **Block goose** | [#12522](https://github.com/aaif-goose/goose/issues/12522) | [PR #12545](https://github.com/aaif-goose/goose/pull/12545) | subreaper 追跡と名前空間サンドボックスを備えた `SubprocessExt` プロセスフェンサー。 |
| **Block goose (ACP)** | [#12513](https://github.com/aaif-goose/goose/issues/12513) | [PR #12563](https://github.com/aaif-goose/goose/pull/12563) | サンドボックス検出付きシェル実行ポリシー (`GOOSE_ACP_CLIENT_TERMINAL`)。 |
| **Cline** | [#14544](https://github.com/cline/cline/issues/14544) | [PR #14583](https://github.com/cline/cline/pull/14583) | `ClineIgnoreController` における端末サンドボックス実行とシークレットマスキング (`~/.ssh`, `.env`)。 |
| **Qwen Code** | [#12856](https://github.com/QwenLM/qwen-code/issues/12856) | [PR #12953](https://github.com/QwenLM/qwen-code/pull/12953) | 資格情報の送信除去とワークスペース保護。 |
| **Claude Code History Viewer** | [#509](https://github.com/jhlee0409/claude-code-history-viewer/issues/509) | [PR #595](https://github.com/jhlee0409/claude-code-history-viewer/pull/595) | セッション再開フラグと入力検証。 |

---

## 検証と完全性

リリースバイナリは自動化された GitHub Actions ワークフローでビルドされ、公開暗号検証が適用されます：

- **SLSA Level 3 Provenance**：リリースバイナリに対して生成される in-toto ビルド証明。
- **Minisign 署名**：公開鍵 `75ECEC9B5080C590` で署名された各リリースアーカイブ。
- **SHA-256 チェックサム**：インストールスクリプトによって自動的に検証。

---

## ドキュメント

- [プラットフォームバックエンドと分離仕様](platform-backends.md)
- [エージェントプリセットと設定](agents.md)
- [脅威モデルとセキュリティ境界](threat-model.md)
- [Preflight 診断チェック](architecture/verify-ng.md)
- [終了コードと失敗モード](exit-codes.md)
- [セキュリティポリシーと脆弱性報告](../SECURITY.md)

---

## コントリビューション

コントリビューションを歓迎します。Pull Request は `main` ブランチに対して作成してください。セキュリティ境界の変更には、対応する検証テストを含める必要があります。Pull Request は GitHub Actions CI の Linux、macOS、Windows ランナーで自動テストされます。

---

## ライセンス

Apache License, Version 2.0 に基づいて公開されています ([LICENSE](../LICENSE))。
