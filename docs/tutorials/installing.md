# Installing vetto in two minutes

Target length: 2 minutes.

1. Show the supported-platform table and explain FULL versus FS-ONLY in one
   sentence.
2. Install via npm (`npm install --global @shledery/vetto`), Homebrew
   (`brew install shleder/tap/vetto`), Cargo (`cargo install vetto`), or curl.
   To pin this release via npm, use `npm install --global @shledery/vetto@0.6.0`.
   The prebuilt package contains native executables for Linux x64/ARM64,
   macOS x64/Apple Silicon, and Windows x64.
3. Run `vetto doctor` and read the selected tier aloud.
4. In a temporary project, run `vetto -- sh -c 'printf "sandbox works\n"'`.
5. Close with the fail-closed rule: an unavailable backend stops the command;
   vetto never silently runs it unsandboxed.
