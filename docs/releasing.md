# Publishing and releasing

This procedure covers source publication and binary releases. It does not
require publishing the crate to crates.io.

The source repository is [strumbyte/mcp-writ](https://github.com/strumbyte/mcp-writ).
Publish binary releases under this repository.

## Preparing a new repository

1. Copy the reviewed source tree, including dotfiles and `.github/`. Exclude
   `.git/`, `target/`, `.local/`, local environment files, and runtime audit logs.
   Start a fresh Git repository if the development history is not intended for
   publication. Copying the old `.git/` directory would also copy that history.
2. Set the final repository name and URL. Add `repository` and, if applicable,
   `homepage` to Cargo.toml. Use the destination repository for badges and
   releases; documentation inside the tree uses relative links.
3. Review the staged file list and diff. Keep the MIT license text and copyright
   notice. Review third-party license notices for the actual artifacts being
   distributed, including bundled binaries and container images.
4. Enable Actions and run CI, Platform tests, Container tests, Go MCP runtime
   compatibility, Linux tests, and MCP server verification on the intended
   commit. Set branch protection or rulesets for the checks required by the
   project; workflow files alone do not require them before merging.

`.local/` is for private backups and working notes and is ignored by Git and
excluded from Cargo packages. Do not upload a complete workspace ZIP without
checking its contents.

## Verification

Run the checks in [Development](development.md), then verify the package:

```sh
cargo package --locked --list
```

Review the package list for source, fixtures, user documentation, and LICENSE.
Private notes, audit logs, and build outputs must not appear. A cross-target
Clippy run checks compilation; it does not replace execution on Linux,
Windows, or macOS.

## Creating a binary release

1. Choose the release version and update Cargo.toml and Cargo.lock together.
   Write release notes describing user-visible changes and known limitations.
2. Commit the reviewed source and confirm all four verification workflows pass
   for that commit, including Docker and actual Go runtime execution. Dispatch
   the Linux tests workflow on the same commit — it is the only check running
   on real AArch64 hardware — and the MCP server verification workflow, which
   exercises the pinned real MCP servers under the sandbox on all three OSes.
   Both are intentionally manual-only rather than Release workflow
   dependencies, so they must pass before the tag is pushed. Per-test
   ownership of these workflows is listed in the
   [test matrix](test-matrix.md).
3. Push a matching `v<version>` tag when ready to publish. The Release workflow
   runs verification before building the platform binaries and publishing archives.
   Pushing this tag triggers publication; an ordinary branch push does not.
4. Inspect the resulting archives and SHA-256 checksum file. Each archive must
   contain the CLI, a Linux runner for the matching architecture, LICENSE,
   policy.example.kdl, and the public documentation.
5. Exercise the extracted CLI's `--version` and `--help` on the target OS. Test
   the packaged Linux runner with the intended container base image; build
   environment compatibility alone does not establish runtime compatibility.

The repository URL and remote workflow results depend on the destination
repository. Local source checks cannot confirm them.

## Distribution description check

Work through the pre-release checklist in the
[test matrix](test-matrix.md), which splits this check into two steps:

- Before the tag is pushed, compare the planned tag, repository URL,
  release version, and the asset names defined in the Release workflow
  against what README.md, README.ja.md, Cargo.toml, and this document
  describe.
- After the Release workflow publishes, verify the actual release and
  its published assets, and record the confirmation date and result in
  the checklist's record table. If anything is unpublished or
  unconfirmed, record that state rather than describing it as
  published.
