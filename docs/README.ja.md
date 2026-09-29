![vetto — AIエージェントとマシンの間のカーネル隔離境界](../assets/readme/hero.png)

<p align="center">
  <a href="https://github.com/shleder/vetto/actions"><img src="https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/shleder/vetto/releases/tag/v0.5.11"><img src="https://img.shields.io/badge/version-0.5.11-blue?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@shledery/vetto"><img src="https://img.shields.io/badge/npm-v0.5.11-CB3837?logo=npm&logoColor=white&style=flat-square" alt="npm"></a>
  <a href="https://crates.io/crates/vetto"><img src="https://img.shields.io/badge/crates.io-v0.5.11-orange?logo=rust&logoColor=white&style=flat-square" alt="crates.io"></a>
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

AIコーディングCLIエージェント（**Claude Code**、**OpenAI Codex**、**Cursor**、**OpenCode**、**Aider**、**Antigravity**、**OMP**、**ZCode**、**Kimi**、**Grok**）のための、デーモン不要（daemon-less）・root権限不要（rootless）のカーネルレベルサンドボックスおよびポリシー適用ランタイムです。Vettoは、`fork()` と `execve()` の間に直接、変更不可能なセキュリティ境界を注入し、4ms未満の起動レイテンシとDockerオーバーヘッドゼロを実現します。

---

## インタラクティブTUI Mission Control

任意のターミナルで `vetto` を実行するだけで、Mission Control ダッシュボードが起動します：

```bash
vetto
```

AIエージェントの自動検出、ワンタッチでのPATHシム切り替え、VFS秘密情報マトリクスの監査、カーネル診断プローブ、即時ロールバック、リアルタイムセキュリティイベントストリーム（`[5: SECURITY STREAM]`）、マルチエージェントスウォーム統合（`[6: FLEET SWARM]`）を備えています。

キーバインドや詳細なビューについては、[Mission Control TUI ガイド](tui.md) をご覧ください。

---

## 約束ではなく証明を

自律エージェントは非決定的なコードを実行します。信頼できない依存関係フック、プロンプトインジェクション、幻覚によるBashコマンドが、ホストの機密情報（`~/.ssh`、`~/.aws`、`.env`）を漏洩させたり、孤児プロセスを放置する危険があります。Vettoの監視下では、未許可のシステムコールは決定論的にブロックされます：

```text
> Reading ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> Opening raw socket...             BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...       TERMINATED (process tree extinction, exit 125)
```

### フェイルクローズド契約 (Exit 125)

隔離境界の侵害が検知された場合、または必要なカーネル機能が適用できない場合、実行は直ちに終了し、**終了コード 125** が返されます。すべての子プロセスおよび孤児プロセスは、cgroups v2 `cgroup.kill` によって同期的に完全に終了されます。OSがサポートしていない機能は「非対応」として明確に報告され、暗黙的にセキュリティレベルが低下することはありません。

---

## クイックスタート

### 1. インストール

標準パッケージマネージャーからインストール：

```bash
# npm (クロスプラットフォーム対応グローバルバイナリ)
npm install -g @shledery/vetto

# Homebrew (macOS & Linux)
brew install shleder/tap/vetto

# Cargo (crates.io)
cargo install vetto
```

またはワンライナーインストーラーで直接導入：

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

### 2. 透過的エージェント保護 (PATHシム)

設定ファイル不要でAIエージェントのサンドボックス化を有効化。Vettoは非破壊的なシムを `~/.vetto/shims` に配置し、`PATH` の最優先で読み込みます：

```bash
vetto enable claude   # codex, opencode, cursor, aider, antigravity など18のプロファイルに対応
claude                # 通常通り実行するだけで、カーネル境界内で完全保護されます
```

隔離を解除してネイティブ実行に戻す場合：

```bash
vetto disable claude
```

### 3. 直接実行と安全なEval

スタンドアロンスクリプトをデフォルトの厳格なポリシーで実行：

```bash
vetto run -- python script.py
vetto -- npm test
```

cgroups v2 メモリ制限とハードウェアタイムアウトを設定した安全な評価：

```bash
vetto eval --python -c "print(1 + 1)" --timeout 5 --memory 256
```

### 4. 即時スナップショットとロールバック

Vettoはエージェント実行前にワークスペースの軽量なスナップショットを自動作成します：

```bash
vetto diff        # エージェントが変更したファイルの差分とセキュリティレポートを確認
vetto undo        # ワークスペースを実行前のクリーンな状態に即座に巻き戻し
```

### 5. カーネル診断プローブ

ホストカーネルの隔離能力とコンテナ制約を検証：

```bash
vetto doctor --preflight          # Landlock ABI、名前空間、cgroups v2 を診断
vetto doctor --preflight --json   # 機械可読な JSON レポートを出力
```

### 6. マルチエージェントフリート並行実行 (`vetto fleet`)

cgroups v2 による公平なリソース配分（Fair-Share）、ペアワイズな名前空間分離、エフェメラルな CoW ブランチを備えた独立した AI コーディングエージェントのスウォームをオーケストレーション：

```bash
# フリートのキャパシティ、Fair-Share 制限、アクティブなワーカーを確認
vetto fleet status
vetto fleet status --json

# Fair-Share cgroups を適用して複数の隔離ワーカーを並行起動
vetto fleet spawn claude --count 3
vetto fleet spawn --count 4 -- sh -c "python agent.py"

# N個のワーカー間で自動ペアワイズ隔離検証を実行（N=8 の場合は28組をチェック）
vetto fleet verify --workers 8 --json

# ワーカーの終了、またはフリートスウォーム全体のクリーンアップ
vetto fleet kill agent-01
vetto fleet kill --all
```

---

## プラットフォーム保証レベル

Vettoは、非特権ユーザー空間で利用可能なカーネル機能に応じて、厳密な3階層のセキュリティモデルを提供します：

| プラットフォーム / 階層 | ファイルシステム分離 | ネットワーク分離 | プロセスライフサイクル管理 | 状態 |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (ネイティブ)**<br>Tier 1 | **Landlock LSM (ABI 1–6)**<br>`~/.ssh`、`~/.aws`、`.env` の Inode マスキング（0000モード tmpfs） | **ネットワーク名前空間 (`CLONE_NEWNET`)**<br>ループバック隔離 + SNI検査付きL7ローカルプロキシ | **PID名前空間 (`CLONE_NEWPID`)**<br>`cgroups v2` による決定論的プロセスツリー完全終了 | 本番運用推奨 |
| **Linux (WSL2)**<br>Tier 1 | **WSL2 カーネル Landlock LSM**<br>完全な Inode アクセス制御 | **VM内ネットワーク名前空間**<br>分離されたブローカー経由通信 | **PID名前空間 + `/proc` スイープ**<br>孤児プロセスの完全排除 | 本番運用推奨（Windows推奨構成） |
| **macOS (Darwin)**<br>Tier 2 | **Seatbelt (`libsandbox.1.dylib`)**<br>書き込み権限を `$PROJECT` と `/tmp` に限定 | **ネットワーク遮断**<br>`(deny network*)` ルールによる `--net=off` | **プロセスグループ監視**<br>`pidfd` / kqueue ウォッチドッグ監視 | 標準運用（`~/Documents` にはフルディスクアクセス権限が必要） |
| **Windows ネイティブ**<br>Tier 3 | **AppContainer & LPAC**<br>DACL トークン制限 | **権限ロックダウン**<br>制限されたネットワークSID | **ジョブオブジェクト (Job Objects)**<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | ガードレール（Tier 1 の保証には WSL2 を推奨） |

---

## 暗号署名とサプライチェーン検証

すべてのリリースバイナリは GitHub Actions の隔離環境で自動ビルドされ、公開暗号署名が付与されています：

- **SLSA Level 3 Provenance**：全プラットフォームのバイナリに対して in-toto 構成証明を生成。
- **Minisign 署名**：公開鍵 `75ECEC9B5080C590` を用いて配布アーカイブを検証可能。
- **独立した SHA-256 チェックサム**：インストール時に自動整合性検証。

---

## ライセンス

本プロジェクトは Apache License 2.0 の下で公開されています（[LICENSE](../LICENSE)）。
