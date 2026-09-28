![vetto — AI 编程助手与主机系统之间的内核隔离壁垒](../assets/readme/hero.png)

<p align="center">
  <a href="https://github.com/shleder/vetto/actions"><img src="https://img.shields.io/github/actions/workflow/status/shleder/vetto/ci.yml?branch=main&label=CI&style=flat-square" alt="CI"></a>
  <a href="https://github.com/shleder/vetto/releases/tag/v0.5.7"><img src="https://img.shields.io/badge/version-0.5.7-blue?style=flat-square" alt="Version"></a>
  <a href="https://www.npmjs.com/package/@shledery/vetto"><img src="https://img.shields.io/badge/npm-v0.5.7-CB3837?logo=npm&logoColor=white&style=flat-square" alt="npm"></a>
  <a href="https://crates.io/crates/vetto"><img src="https://img.shields.io/badge/crates.io-v0.5.7-orange?logo=rust&logoColor=white&style=flat-square" alt="crates.io"></a>
  <a href="../LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="../README.md">English</a> |
  <a href="README.ru.md">Русский</a> |
  <a href="README.zh.md"><b>简体中文</b></a> |
  <a href="README.ja.md">日本語</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.de.md">Deutsch</a>
</p>

专为 AI 编程 CLI 助手（**Claude Code**、**OpenAI Codex**、**Cursor**、**OpenCode**、**Aider**、**Antigravity**、**OMP**、**ZCode**、**Kimi**、**Grok**）打造的无守护进程（daemon-less）、无特权（rootless）内核级沙箱与安全策略运行时。Vetto 直接在 `fork()` 与 `execve()` 之间注入确定性的内核安全边界，初始化延迟低于 4 毫秒，且无需 Docker 容器开销。

---

## 交互式终端 Mission Control

在任何交互式终端中直接运行 `vetto` 即可唤起 Mission Control 仪表盘：

```bash
vetto
```

包含实时 AI 编程助手检测、一键 PATH 垫片切换、VFS 凭据掩码矩阵实时审计、内核预检诊断、零损耗即时快照回滚、实时安全事件流（`[5: SECURITY STREAM]`）与多智能体集群调度遥测（`[6: FLEET SWARM]`）。

关于完整快捷键、界面视图与主题切换，请参阅 [Mission Control TUI 详细指南](tui.md)。

---

## 严苛验证：杜绝空泛保证

自主智能体执行非确定性代码。不受信任的依赖项钩子、提示词注入或幻觉 Bash 命令可能窃取主机机密（`~/.ssh`、`~/.aws`、`.env`）或遗留不可控的后台孤儿进程。在 Vetto 下，非授权系统调用将被内核级确定性阻断：

```text
> 读取 ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> 打开原始套接字 (Raw Socket)...  BLOCKED (net namespace, EAFNOSUPPORT)
> 派生后台驻留进程 (Daemon)...    TERMINATED (process tree extinction, exit 125)
```

### 故障安全契约 (Fail-Closed Exit 125)

一旦检测到隔离边界被越过或关键内核原语无法生效，进程将立即被内核强制终止，并返回**退出代码 125**。所有派生子进程和孤儿进程均通过 cgroups v2 `cgroup.kill` 同步清除。操作系统无法支持的特性将被如实报告为不支持——绝不进行隐式静默降级。

---

## 快速上手

### 1. 安装

通过标准包管理器全局安装：

```bash
# npm (全平台二进制)
npm install -g @shledery/vetto

# Homebrew (macOS 与 Linux)
brew install shleder/tap/vetto

# Cargo (crates.io)
cargo install vetto
```

或使用独立一键脚本安装：

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

### 2. 透明智能体接管 (PATH-Shims)

为您的 AI 编程助手启用零配置沙箱接管。Vetto 会在 `~/.vetto/shims` 中安装无侵入垫片并优先加载至 `PATH`：

```bash
vetto enable claude   # 支持 codex, opencode, cursor, aider, antigravity 等 18 款预置配置
claude                # 照常运行 — 全程受内核边界严格保护
```

随时恢复原生未受限运行：

```bash
vetto disable claude
```

### 3. 直接执行与安全 Eval

在默认严苛隔离策略下运行独立脚本：

```bash
vetto run -- python script.py
vetto -- npm test
```

在具备 cgroups v2 内存上限与硬件单调超时的微型沙箱中安全评估代码片段：

```bash
vetto eval --python -c "print(1 + 1)" --timeout 5 --memory 256
```

### 4. 即时快照与回滚

Vetto 在智能体启动前自动对工作区创建极轻量的写时复制快照：

```bash
vetto diff        # 查看智能体修改的文件差异与安全报告
vetto undo        # 一键恢复工作区至执行前的干净状态
```

### 5. 内核能力深度自检

检测当前操作系统与容器环境下的内核沙箱能力：

```bash
vetto doctor --preflight          # 检测 Landlock ABI、命名空间与 cgroups
vetto doctor --preflight --json   # 机器可解析的 JSON 诊断报告
```

### 6. 多智能体集群并发调度 (`vetto fleet`)

基于 cgroups v2 公平配额（Fair-Share）、两两成对命名空间隔离与瞬态 CoW 分支编排隔离 AI 编程智能体集群：

```bash
# 查看集群容量、Fair-Share 配额及活跃 Worker 状态
vetto fleet status
vetto fleet status --json

# 启动并发隔离 Worker 并绑定 Fair-Share cgroups
vetto fleet spawn claude --count 3
vetto fleet spawn --count 4 -- sh -c "python agent.py"

# 对 N 个 Worker 运行全量两两隔离自动化验证（N=8 时验证全部 28 组对照）
vetto fleet verify --workers 8 --json

# 终止指定 Worker 或清理整个智能体集群
vetto fleet kill agent-01
vetto fleet kill --all
```

---

## 平台隔离层级

Vetto 根据非特权用户空间可用的内核特性，严格划分三级安全保障体系：

| 平台 / 层级 | 文件系统隔离 | 网络隔离 | 进程生命周期与清理 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (原生)**<br>Tier 1 | **Landlock LSM (ABI 1–6)**<br>`~/.ssh`、`~/.aws`、`.env` 的 Inode 级 VFS 掩码（0000 模式 tmpfs） | **网络命名空间 (`CLONE_NEWNET`)**<br>本地环回隔离 + 带 SNI 校验的 L7 本地代理 | **PID 命名空间 (`CLONE_NEWPID`)**<br>通过 `cgroups v2` 实施确定性进程树灭绝 | 生产可用 |
| **Linux (WSL2)**<br>Tier 1 | **WSL2 内核 Landlock LSM**<br>完整 Inode 级访问控制 | **虚拟机内网络命名空间**<br>隔离的出站模型代理 | **PID 命名空间 + `/proc` 扫描**<br>彻底清除孤儿进程 | 生产可用（Windows 推荐方案） |
| **macOS (Darwin)**<br>Tier 2 | **Seatbelt (`libsandbox.1.dylib`)**<br>限制写入仅限 `$PROJECT` 与 `/tmp` | **网络封锁**<br>通过 `(deny network*)` 规则实现 `--net=off` | **进程组清理**<br>`pidfd` / kqueue 看门狗监控 | 标准级（访问 `~/Documents` 需授予完全磁盘访问权限） |
| **Windows 原生**<br>Tier 3 | **AppContainer 与 LPAC**<br>DACL 令牌访问控制 | **功能权限锁定**<br>受限网络 SID | **作业对象 (Job Objects)**<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | 基础防护（推荐使用 WSL2 获取 Tier 1 级保证） |

---

## 兼容智能体矩阵

Vetto 为 18 款主流 AI 助手提供预置沙箱配置文件（`profiles/agents/*.toml`）、动态包管理器缓存支持（`npm`、`uv`、`bun`）以及 Computer Use 桌面图形透传：

| 智能体 | 命令 / 预设 | 预置出站网络域名 | 插件与缓存挂载路径 |
| :--- | :--- | :--- | :--- |
| **Claude Code** | `claude` | `api.anthropic.com`, `claude.ai` | `~/.claude`, `~/.config/claude`, 插件目录 |
| **OpenAI Codex** | `codex` | `api.openai.com`, ChatGPT OAuth | `~/.codex`, `~/.config/codex`, 插件目录 |
| **OpenCode** | `opencode` | 动态 JSONC 端点（AIHubMix, Nvidia 等） | `~/.local/share/opencode`, `~/.config/opencode` |
| **Antigravity** | `agy`, `antigravity` | Google APIs, Google CDN, 遥测端点 | `~/.gemini/antigravity`, 技能与插件 |
| **OMP** | `omp` | `omp.sh`, Anthropic, OpenAI, Google, OpenRouter | `~/.config/omp`, `~/.omp`, project local `.omp` |
| **ZCode** | `zcode` | `z.ai`, `api.z.ai`, `glm.z.ai`, OpenAI | `~/.zcode`, `~/.config/zcode` |
| **Kimi Code** | `kimi` | `code.kimi.com`, `api.moonshot.cn`, `api.moonshot.ai` | `~/.kimi`, `~/.config/kimi` |
| **Grok Build** | `grok` | `x.ai`, `api.x.ai`, `grok.com` | `~/.grok`, `~/.config/grok` |
| **Cursor** | `cursor` | Cursor 后端服务, 扩展市场 | VS Code IPC 套接字, `~/.cursor` |
| **Aider** | `aider` | 所配置的 LLM 服务提供商端点 | Git 仓库根目录, 历史缓存 |
| **Cline** | `cline` | `api.cline.bot`, `data.cline.bot` | VS Code 扩展宿主, 浏览器缓存 |
| **Windsurf** | `windsurf` | `api.codeium.com`, `windsurf.codeium.com` | `~/.windsurf`, Cascade 状态目录 |
| **Goose** | `goose` | Block API, Anthropic, Databricks | `~/.config/goose`, 扩展模块 |
| **OpenHands** | `openhands` | 所选模型提供商网络端点 | 免 Docker 本地隔离执行 |
| **Devin** | `devin` | `api.devin.ai`, `cognition.ai` | `~/.devin`, `~/.config/devin` |
| **GitHub Copilot** | `copilot` | `api.github.com`, Copilot 端点 | `~/.config/github-copilot` |
| **Smolagents** | `smolagents` | `huggingface.co`, `hf.co` | `~/.cache/huggingface`, PyTorch 缓存 |

---

## 密码学完整性与 SLSA 签名

每个版本的二进制文件均在 GitHub Actions 隔离环境中构建，并附带公开密码学凭证：

- **SLSA Level 3 Provenance**：为全平台二进制生成 in-toto 供应链证明。
- **Minisign 签名**：通过公钥 `75ECEC9B5080C590` 签名每个发布包。
- **独立 SHA-256 校验和**：安装时自动比对校验。

---

## 完整文档

- [平台底层实现与边界规范](platform-backends.md)
- [智能体配置文件注册表](agents.md)
- [威胁模型与安全假设](threat-model.md)
- [诊断验证体系](architecture/verify-ng.md)
- [退出代码与错误模式](exit-codes.md)
- [漏洞披露机制 (SECURITY.md)](../SECURITY.md)

---

## 开源协议

本项目采用 Apache License 2.0 许可证开源（[LICENSE](../LICENSE)）。
