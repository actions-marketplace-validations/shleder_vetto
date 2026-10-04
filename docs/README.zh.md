![vetto - AI Agent 与操作系统之间的内核隔离墙](../assets/readme/hero.png)

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
  <a href="README.zh.md"><b>简体中文</b></a> |
  <a href="README.ja.md">日本語</a> |
  <a href="README.es.md">Español</a> |
  <a href="README.de.md">Deutsch</a>
</p>

Vetto 是专为 Claude Code、OpenAI Codex、Cursor、OpenCode、Aider 等 AI 编码 CLI 代理设计的无特权沙箱。它在 `fork()` 与 `execve()` 之间利用 Linux 和 macOS 的原生内核机制隔离文件系统访问、网络套接字及子进程，无需后台守护进程或 root 权限。

---

## 内核边界强制隔离

AI 编码代理会执行自主生成的 Shell 命令与构建脚本。如果代理试图读取私钥、创建原始网络套接字或生成脱离监管的后台进程，Vetto 会在内核层直接拦截：

```text
> Reading ~/.ssh/id_rsa...         BLOCKED (secret mask, EACCES)
> Opening raw socket...             BLOCKED (net namespace, EAFNOSUPPORT)
> Spawning detached daemon...       TERMINATED (process tree extinction, exit 125)
```

### 故障安全关闭机制 (fail-closed, 退出码 125)

当代理违反安全策略或主机内核缺少所需的隔离机制时，Vetto 立即以状态码 125 退出。所有派生子进程和后台工作线程均通过 cgroups v2 的 `cgroup.kill` 同步终止。如果宿主操作系统无法完全强制执行配置的安全规则，Vetto 会明确报告缺失的功能并终止运行，绝不在降级安全性的前提下盲目运行。

---

## 快速上手

### 1. 安装

通过标准包管理器安装：

```bash
# npm (跨平台全局二进制)
npm install -g @shledery/vetto

# Homebrew (macOS 与 Linux)
brew install shleder/tap/vetto

# Cargo (crates.io)
cargo install vetto
```

或通过独立 curl 安装脚本：

```bash
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | sh
```

### 2. 透明代理包装 (Shims)

无需修改 Shell 配置或别名即可对已安装的 AI 编码代理进行沙箱包装：

```bash
vetto enable --all
```

Vetto 会在 `$PATH` 中自动搜索受支持的代理二进制文件（`claude`、`codex`、`cursor`、`opencode`、`aider`、`antigravity` 等），并在 `~/.vetto/shims` 中放置拦截 shim。

启用后，像往常一样正常启动代理即可：

```bash
claude                # 在 Landlock LSM 内核策略下沙箱化运行
cursor                # 在受保护的凭证与网络过滤策略下运行
```

单独管理各个代理：

```bash
vetto enable claude    # 仅包装 claude
vetto disable claude   # 恢复无沙箱的直接执行
```

### 与 Docker 的对比

AI 编码代理依赖本地编译器、现有的软件包缓存以及交互式终端。在 Docker 容器内运行需要繁琐的容器环境初始化，而 Vetto 将内核沙箱直接施加于宿主机进程：

| 维度 | Docker / DinD | Vetto |
| :--- | :--- | :--- |
| 启动延迟 | 容器创建耗时 500ms 至 2000ms | 在 `fork()` 与 `execve()` 之间冷启动低于 4ms |
| 内存占用 | 依赖后台常驻 `dockerd` 进程 | 0 MB 后台常驻内存（无后台守护进程） |
| 特权模型 | 需要 `root` 或 `docker` 用户组权限 | 非特权用户命名空间、Landlock LSM 与 cgroups v2 |
| 开发工具链 | 需要重新构建容器镜像 | 直接使用宿主机的 `cargo`、`npm`、`pip` 和 `uv` |
| 包管理器缓存 | Volume 挂载或重复下载依赖 | 直接复用宿主机的包缓存 |
| 进程生命周期清理 | 容易遗留孤儿容器或脱管进程 | 通过 cgroups v2 `cgroup.kill` 彻底同步终止进程树 |

### 3. 直接执行

在沙箱内运行任意命令或脚本：

```bash
vetto run -- python script.py
vetto -- npm test
```

### 4. 工作区快照与即时回滚

在代理开始执行前，Vetto 会为项目目录创建写时复制 (Copy-on-Write) 快照：

```bash
vetto diff        # 显示代理修改、新增或删除的文件
vetto undo        # 将工作区即时恢复至运行前的初始状态
```

### 5. 主机环境诊断

检查当前机器支持的内核隔离功能：

```bash
vetto doctor --preflight          # 检查 Landlock ABI、命名空间和 cgroups v2
vetto doctor --preflight --json   # 以 JSON 格式输出诊断报告
```

---

## GitHub Actions 集成

使用官方 `shleder/vetto` Action 在 CI 流水线中安全运行 AI 代理，无需 Docker 或 root 特权：

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

完整配置参数、多步骤工作流与 SARIF 安全报告支持请参阅 [CI/CD 集成指南](ci-cd.md)。

---

## 终端管理与状态栏 (Statusline)

像 Claude Code 和 Codex 这样的交互式代理拥有自己的终端控制 (PTY)。Vetto 在保留直接终端交互的同时展示沙箱安全状态：

- **状态栏覆盖层 (`--tui=statusline`)**：非交互式命令的默认模式，在终端底部实时显示活跃的文件系统与网络策略计数。
- **无头模式 (`--tui=none` / `--ci`)**：禁用终端界面渲染。在 CI 环境、Shell 脚本或标准流重定向中建议使用此参数。

---

## 平台支持矩阵

Vetto 充分利用各操作系统提供的无特权隔离机制：

| 平台 | 文件系统隔离 | 网络隔离 | 进程生命周期管理 | 等级 |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (原生)** | **Landlock LSM (ABI 1 至 6)**<br>`~/.ssh`、`~/.aws`、`.env` 的 tmpfs 遮蔽 | **网络命名空间 (`CLONE_NEWNET`)**<br>回环隔离搭配本地 TCP/TLS 代理 | **PID 命名空间 (`CLONE_NEWPID`)**<br>通过 cgroups v2 `cgroup.kill` 清理进程树 | Tier 1 (完整) |
| **Linux (WSL2)** | **通过 WSL2 内核启用 Landlock**<br>路径访问限制 | **虚拟机内部网络命名空间**<br>过滤出站连接 | **PID 命名空间与 `/proc` 扫描**<br>彻底清除进程树 | Tier 1 (完整) |
| **macOS (Darwin)** | **Seatbelt (`libsandbox.1.dylib`)**<br>限制写入仅限项目目录与 `/tmp` | **网络限制**<br>`--net=off` 阻止 IP 出站；`--net=allowlist` 通过本地回环代理 | **进程监管**<br>通过 Watchdog 监控并清理子进程组 | Tier 2 (目标 Tier 1.5) |
| **Windows 原生** | **AppContainer 与 LPAC**<br>基于 Token 的访问控制 | **权能限制**<br>受限网络 SID | **Job Objects**<br>`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` | Tier 3 (Guardrail) |

### 关于 macOS Seatbelt 的技术说明

macOS 内核不提供无特权网络命名空间。Vetto 使用苹果原生 Seatbelt 框架 (`libsandbox.1.dylib`) 限制文件系统写入并保护用户凭证。在 `--net=off` 模式下，网络流量与到 `mDNSResponder` 的 IPC 均被阻止；在 `--net=allowlist` 模式下，Vetto 在 `127.0.0.1` 上启动临时回环代理并导出代理环境变量。在 macOS 上对只读权限设置较宽，以规避 dyld 动态链接器共享缓存的限制。

---

## 支持的 AI 代理

Vetto 为 25 种以上的 AI 编码工具提供了预置策略文件。每个配置都精确限定了官方模型端点出站并遮蔽了敏感凭证，同时保持本地包管理缓存可用：

| 代理名称 | 命令 / 预置 | 网络端点 | 受保护的配置与缓存目录 |
| :--- | :--- | :--- | :--- |
| **Claude Code** | `claude` | `api.anthropic.com`, `claude.ai` | `~/.claude`, `~/.config/claude`, 插件 |
| **OpenAI Codex** | `codex` | `api.openai.com`, ChatGPT OAuth | `~/.codex`, `~/.config/codex`, 插件 |
| **Cursor** | `cursor` | Cursor 后端 API、插件市场 | VS Code IPC 套接字、`~/.cursor` |
| **Aider** | `aider` | 已配置的模型提供商端点 | Git 仓库根目录、历史缓存 |

完整支持列表、网络范围与路径规则请参阅 [代理兼容性注册表](agents.md)。

---

## 验证与完整性

所有发布包均通过自动化 GitHub Actions 工作流构建，并支持公开密码学验证：

- **SLSA Level 3 Provenance**：为所有平台的发布包生成 in-toto 构建证明。
- **Minisign 签名**：每个归档文件均使用公钥 `75ECEC9B5080C590` 提供签名。
- **SHA-256 校验和**：安装脚本在解压前自动验证 SHA-256 哈希值。

---

## 文档

- [平台后端与隔离规范](platform-backends.md)
- [代理预设与配置参考](agents.md)
- [威胁模型与安全边界](threat-model.md)
- [CI/CD 集成与 GitHub Actions](ci-cd.md)
- [Python SDK 绑定](../sdk/python/)
- [退出代码与故障模式](exit-codes.md)
- [安全政策与漏洞提报](../SECURITY.md)

---

## 贡献指南

欢迎社区贡献代码。请向 `main` 分支提交 Pull Request。所有涉及安全边界的修改必须包含对应的内核测试用例。PR 会在 GitHub Actions CI 的 Linux、macOS 和 Windows runner 上进行自动测试。

---

## 许可证

本项目基于 Apache License 2.0 许可证开源 ([LICENSE](../LICENSE))。
