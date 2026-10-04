# Packaging sources

These files build vetto from source or act as checksum-gated templates. They
are repository code only: no workflow in this directory publishes a release,
uploads an artifact, or changes an external package registry.

- `scoop/vetto.json.template`: rendered by release-train (`Render Scoop manifest`
  step) into `vetto.json` from the real Windows archive + its `.sha256`
  sidecar and attached to the GitHub Release. Never hand-edit checksums.
- `release.pub`: minisign public key for release archives (key id
  `75ECEC9B5080C590`). The private key lives only in the `RELEASE_SIGNING_KEY`
  GitHub secret (+ `RELEASE_SIGNING_KEY_PASSWORD`); release-train signs every
  archive and verifies each `.minisig` against this file before publishing.
- `scripts/package-macos-pkg.sh`: macOS `.pkg` packaging and notarization script.
- `scripts/sign-windows.ps1`: Windows Authenticode code signing script.
- the root `flake.nix`: reproducible Nix build from the checked-out source.

Templates deliberately contain no fake URL or checksum.
