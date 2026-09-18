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
4. Enable Actions and run CI, Platform tests, Container tests, and Go MCP runtime
   compatibility on the intended commit. Set branch protection or rulesets for
   the checks required by the project; workflow files alone do not require them
   before merging.

`.local/` is for private backups and working notes and is ignored by Git and
excluded from Cargo packages. Do not upload a complete workspace ZIP without
checking its contents.

## Verification

Run the checks in [Development](development.md), then verify the package:

```sh
python3 scripts/check_docs.py
cargo package --locked --list
```

On Windows, use `py -3 scripts/check_docs.py`. Review the package list for source,
fixtures, user documentation, and LICENSE. Private notes, audit logs, and build
outputs must not appear. A cross-target Clippy run checks compilation; it does
not replace execution on Linux, Windows, or macOS.

## Creating a binary release

1. Choose the release version and update Cargo.toml and Cargo.lock together.
   Write release notes describing user-visible changes and known limitations.
2. Commit the reviewed source and confirm all four verification workflows pass
   for that commit, including Docker and actual Go runtime execution.
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
