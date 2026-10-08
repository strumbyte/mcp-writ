# Agent rules for mcp-writ

## Disk hygiene (mandatory)

The container/e2e suites are disk-heavy and several artifacts land on the
**system drive (C:)** even though the repo lives on D:. A previous session let
C: fill to the point of an OS crash — follow this every session:

- **Before** a heavy `cargo build` / `cargo test` / container suite: check free
  space with `df -h` (WSL: `/`; Windows: the drive holding `%TEMP%` and
  `target/`). With less than 40 GiB free, run `cargo clean` first — `target/` is
  fully regenerable.
- **After** container test runs: `scripts/clean-test-container-artifacts.sh`
  removes test-tagged images (`mcp-writ-test-*`, `mcp-writ-ctrz-e2e-*`,
  `mcp-writ-kata-*`, `mcp-writ-apple-*`, `mcp-writ-hyperv-*`,
  `mcp-writ-wslc-*` — the Windows
  daemon's tags are reached via `docker.exe` when it answers in Windows
  mode), leaked `apple-e2e-*` units, orphaned test builds, and builder
  cache. See `docs/development.md` → "Disk hygiene for container tests".
- **Windows temp dirs leak on failure/interrupt**: the suites create
  `%TEMP%\mcp-writ-test-*` (~160–220 MB each) and `%TEMP%\mcp_writ_*` dirs that
  are only removed on success. Delete stale ones after runs.
- **WSL2**: this distro's `ext4.vhdx` lives at `D:\wsl\Ubuntu` (registered
  BasePath, moved off C:) and never shrinks on its own. Keep builds/artifacts
  on `/mnt/d`, and if the vhdx balloons, `wsl --shutdown` then compact it
  (`Optimize-VHD` or `diskpart compact vdisk`).
- Keep bulk data (images, caches, extracted rootfs, test workspaces) on D: or
  inside WSL — not under `%TEMP%` or `%USERPROFILE%` on C: — when a choice
  exists.
