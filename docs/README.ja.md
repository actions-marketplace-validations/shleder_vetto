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
  <b>AI コーディング CLI エージェントのためのサブミリ秒 Linux カーネルサンドボックス</b>
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
  <a href="README.ja.md"><b>日本語</b></a> |
  <a href="README.es.md">Español</a> |
  <a href="README.de.md">Deutsch</a>
</p>

</div>

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

詳細なベンチマーク測定結果および評価ハーネス連携については、[SWE-bench と Docker の比較ベンチマーク](benchmarks/swe-bench.md) を参照してください。

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

公式の `shleder/vetto` アクションを使用することで、Docker や root 特権なしで CI パイプライン内で AI エージェントを安全に実行できます：

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

設定オプション、複数ステップのワークフロー、SARIF セキュリティレポートの詳細については、[CI/CD 連携ガイド](ci-cd.md) を参照してください。

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

## 検証と完全性

リリースバイナリは自動化された GitHub Actions ワークフローでビルドされ、公開暗号検証が適用されます：

- **SLSA Level 3 Provenance**：リリースバイナリに対して生成される in-toto ビルド証明。
- **Minisign 署名**：公開鍵 `75ECEC9B5080C590` で署名された各リリースアーカイブ。
- **SHA-256 チェックサム**：インストールスクリプトによって自動的に検証。

---

## ドキュメント

- [プラットフォームバックエンドと分離仕様](platform-backends.md)
- [エージェントプリセットと設定](agents.md)
- [SWE-bench と Docker の比較ベンチマーク](benchmarks/swe-bench.md)
- [脅威モデルとセキュリティ境界](threat-model.md)
- [CI/CD 連携と GitHub Actions](ci-cd.md)
- [終了コードと失敗モード](exit-codes.md)
- [セキュリティポリシーと脆弱性報告](../SECURITY.md)

---

## コントリビューション

コントリビューションを歓迎します。Pull Request は `main` ブランチに対して作成してください。セキュリティ境界の変更には、対応する検証テストを含める必要があります。Pull Request は GitHub Actions CI の Linux、macOS、Windows ランナーで自動テストされます。

---

## ライセンス

Apache License, Version 2.0 に基づいて公開されています ([LICENSE](../LICENSE))。
