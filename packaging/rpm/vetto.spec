Name:           vetto
Version: 0.5.14
Release:        1%{?dist}
Summary:        Daemon-less sandbox and audit layer for AI coding agents
License:        Apache-2.0
URL:            https://github.com/shleder/vetto
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  cargo >= 1.75

%description
vetto wraps local coding agents in an operating-system sandbox and produces
terminal-native visibility and post-session reports.

%prep
%autosetup

%build
cargo build --locked --release

%check
cargo test --locked

%install
install -Dm0755 target/release/vetto %{buildroot}%{_bindir}/vetto
install -Dm0644 LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE
install -Dm0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
mkdir -p %{buildroot}%{_datadir}/vetto/profiles
cp -a profiles/. %{buildroot}%{_datadir}/vetto/profiles/

%files
%license %{_licensedir}/%{name}/LICENSE
%doc %{_docdir}/%{name}/README.md
%{_bindir}/vetto
%{_datadir}/vetto/profiles

%changelog
* Wed Sep 30 2026 vetto contributors - 0.5.14-1
- Native CrewAI and AutoGen sandbox presets, ecosystem integrations showcase.

* Wed Sep 30 2026 vetto contributors - 0.5.12-1
- macOS network allowlist proxy and net-off hardening.

* Tue Sep 29 2026 vetto contributors - 0.5.11-1
- Release 0.5.11: SWE-bench high-throughput runtime adapter, GitHub Actions Marketplace universal action, and Aider CLI native preset & Git Guard Exit 125 hardening.

* Tue Sep 29 2026 vetto contributors - 0.5.10-1
- Release 0.5.10: Quick Start enable-all onboarding, GitHub Actions runner fixes, and policy warnings suppression.

* Tue Sep 29 2026 vetto contributors - 0.5.9-1
- Release 0.5.9: Linux seccomp SYS_clone3 ENOSYS fallback, ephemeral rollback fix, and TUI live policy.

* Tue Sep 29 2026 vetto contributors - 0.5.8-1
- Release 0.5.8: Interactive live policy Allow/Deny in TUI Mission Control and SYS_openat2 Landlock hardening.

* Mon Sep 28 2026 vetto contributors - 0.5.7-1
- Release 0.5.7: Interactive TUI Mission Control Dashboard and real-time security monitor.

* Mon Sep 28 2026 vetto contributors - 0.5.6-1
- Release 0.5.6: Omnigent profile support and L7 anti-SSRF loopback hardening.

* Sun Sep 27 2026 vetto contributors - 0.5.5-1
- Dedicated token leaderboard agent profiles and 24-agent roster.

* Sun Sep 27 2026 vetto contributors - 0.5.4-1
- Adversarial stress hardening, vulnerability remediation & 12-scenario test suite.

* Sun Sep 27 2026 vetto contributors - 0.5.3-1
- Maintenance and synchronization.

* Sun Sep 27 2026 vetto contributors - 0.5.2-1
- Anti-SSRF bypass protection, TUI live security event stream, and English architecture documentation.

* Sat Sep 26 2026 vetto contributors - 0.5.1-1
- Frontier 2026 AI coding CLI agents (omp, zcode, kimi, grok) and Gemini CLI purge.

* Sat Sep 26 2026 vetto contributors - 0.5.0-1
- Interactive TUI Mission Control Dashboard and repository modernization.

* Fri Sep 25 2026 vetto contributors - 0.4.7-1
- Diagnostic preflight verification (vetto doctor --preflight), container restriction probe, structured JSON report.

* Fri Sep 25 2026 vetto contributors - 0.4.6-1
- Maintenance and synchronization.

* Thu Sep 24 2026 vetto contributors - 0.4.5-1
- feat(release): v0.4.5 - unblock Computer Use, display sockets, agent plugins, and browser caches.

* Thu Sep 24 2026 vetto contributors - 0.4.4-1
- Dynamic MCP runtimes, package manager cache access, and VS Code extension parity.

* Thu Sep 24 2026 vetto contributors - 0.4.3-1
- Unblock Computer Use CDP, MCP sockets, and loopback dev servers.

* Wed Sep 23 2026 vetto contributors - 0.4.2-1
- Antigravity Google CDN allowlist, OpenCode full filesystem & dynamic custom provider support, safe loopback relay.

* Wed Sep 23 2026 vetto contributors - 0.4.1-1
- OpenCode 2 GiB SQLite ceiling, Cline network allowlist, test isolation hardening.

* Tue Sep 22 2026 vetto contributors - 0.4.0-1
- Full LOCAL-100 completion: enterprise network proxying, DNS security, and multi-agent runtime.

* Sun Sep 13 2026 vetto contributors - 0.2.23-1
- Sync the source-only recipe with the published 0.2.23 release.

* Fri Sep 05 2026 vetto contributors - 0.2.15-1
- Opt-in background self-update, upgrade rollback, supply-chain gate.

* Thu Sep 04 2026 vetto contributors - 0.2.14-1
- Stabilization: secret-proxy fail-open closed, rescue/policy hardening, hermetic tests.

* Thu Sep 03 2026 vetto contributors - 0.2.13-1
- Sync the source-only recipe with the published 0.2.13 release.

* Wed Sep 02 2026 vetto contributors - 0.2.11-1
- Sync the source-only recipe with the published 0.2.11 release.

* Wed Sep 02 2026 vetto contributors - 0.2.10-1
- Sync the source-only recipe with the published 0.2.10 release.

* Mon Aug 31 2026 vetto contributors - 0.2.9-1
- Sync the source-only recipe with the published 0.2.9 release.


* Fri Aug 28 2026 vetto contributors - 0.2.5-1
- Sync the source-only recipe with the published 0.2.5 release.

* Fri Aug 28 2026 vetto contributors - 0.2.3-1
- Sync the source-only recipe with the published 0.2.3 release.

* Sun Aug 23 2026 vetto contributors - 0.2.0-0.alpha.2
- Universal read-only rescue alpha metadata.

* Sun Aug 23 2026 vetto contributors - 0.1.0-0.1
- Source-only packaging recipe; no release performed.
