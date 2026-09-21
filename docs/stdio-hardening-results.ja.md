# stdio 運用強化の作業記録

本書は[作業手順書](stdio-hardening-runbook.ja.md)末尾の様式に従い、
各 PR の実施結果を記録する。証拠の原本は `証拠の保存先` に従う。
記録は実施した環境と時点に限り有効であり、他 OS・他環境の合格を意味しない。

## PR0. 着手前の記録

対象コミット / 未コミット差分: HEAD = `7c6d553e92a0f7ffc540180bcbd0985fc810b710`。
  記録時点の `git status --short` は空（クリーン）、`git diff --stat` も空。
  本書と `.local/stdio-hardening/` 配下の記録ファイルは新規または gitignore 対象であり、
  実装差分ではない。基準コミット `ca74b4dfebf6e63a7069096080da9efd56333218` から
  HEAD までの差分は `7c6d553`（`Archive ARM64 docs and add stdio hardening plan and runbook`）
  1 件のみで、変更は `docs/` 7 ファイル（計画書・手順書の新設、ARM64 文書の `docs/archive/`
  移動、`development.md` と `docs/README.md` の各 1 行）。`src/` の実装差分は無いため、
  手順 1 の読み直し対象は発生しなかった。
変更ファイル: なし（PR0 は記録のみ、ソース変更なし）。生成物は `.local/stdio-hardening/`
  （gitignore 対象）と本書、および `docs/README.md` の本書へのリンク 1 行。
設計判断と逸脱: `generate-policy -- python3 …` は手順書の `<system-python>` 規約に従い
  Windows の `py -3` に読み替えた（`python3` は WindowsApps 配下のストアエイリアスで
  実行実体が無い）。それ以外の逸脱なし。
検証コマンドと結果: 後述の「検証コマンドと終了コード」。共通チェックはすべて終了コード 0。
現物サーバ: 未取得（PR2 の範囲）。手順 4 の `scripted_stdio.py` はリポジトリ付属の
  fixture であり、現物サーバではない。
未検証: Linux のサンドボックス付き e2e（`MCP_WRIT_REQUIRE_E2E_TESTS=1` は Linux ホストでの
  確認要件のため本機では未実施）、macOS 経路全般、Docker 依存経路（デーモン停止中）。
残る制約: Docker デーモン未起動、symlink 作成権限なし（開発者モード未設定）、
  UNC 検証共有なし。以降の PR の Windows 上の作業はこの環境で継続可能。
証拠の保存先: `.local/stdio-hardening/`（gitignore 対象の作業領域）。
  ベースラインは `.local/stdio-hardening/baseline/`、ログは同階層。

### 実行環境（PR0-1）

| 項目 | 値 |
|---|---|
| OS / カーネル / CPU | Windows 11（10.0.26200.9457）/ AMD Ryzen 5 9600X（6 コア）/ native x86-64 |
| シェル | WSL2 Ubuntu 上の bash（kernel 5.15.167.4-microsoft-standard-WSL2）。WSL 内にツールチェーンはなく、Windows 側の `cargo.exe` / `py.exe` / `node.exe` を相互運用で実行。git は WSL 側 `/usr/bin/git` を使用 |
| 環境変数の扱い | WSL から Win32 子プロセスへの環境変数は既定で引き継がれないため、必要な変数は `WSLENV` に列挙して伝播した |

バージョン記録（手順 1 のコマンド出力）:

```text
rustc 1.98.1 (48a229cea 2026-09-01)
  binary: rustc / commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985
  commit-date: 2026-09-01 / host: x86_64-pc-windows-msvc / release: 1.98.1
  LLVM version: 22.1.8
cargo 1.98.1 (797e8a9bc 2026-08-05)
node v24.11.1
npm 11.6.2
Python 3.12.10（py -3）
pip 25.0.1 from C:\Users\yuzame.AzureAD\AppData\Local\Programs\Python\Python312\Lib\site-packages\pip (python 3.12)
git version 2.43.0（WSL 側）
```

### テスト件数と skip（PR0-2）

`cargo test --locked` → 終了コード 0。18 スイート合計 1498 件すべて合格、
0 failed、0 ignored。生ログは `.local/stdio-hardening/cargo-test-pr0.log`。

| スイート | 件数 |
|---|---|
| lib（src/lib.rs ユニット） | 1319 |
| container_e2e | 4 |
| containerize_e2e | 14 |
| diagnostics_e2e | 3 |
| go_runtime_policy | 7 |
| inspector_arm64_p4 | 13 |
| inspector_arm64_p5 | 24 |
| inspector_macho_p6 | 28 |
| integration | 12 |
| kdl_policy_e2e | 18 |
| legislator_protocol_versions | 5 |
| path_resolution_e2e | 6 |
| self_test | 4 |
| tool_enforcement_e2e | 25 |
| wrap_image_e2e | 16 |
| bin ユニット（main.rs / mcp-secure-runner.rs）と Doc-tests | 0 + 0 + 0 |

harness 上の skip（`ignored`）は 0 件。内部で条件判定して pass 扱いになる skip が
あり、`--nocapture` で実施した再実行（生ログ `cargo-test-pr0-nocapture.log`）で確認したもの:

- Docker デーモン停止中（`npipe:////./pipe/dockerDesktopLinuxEngine` に接続不可）のため、
  container_e2e 内のコンテナ実行系が `SKIP: no container engine`、
  containerize_e2e の 4 件（`base_image_override`、`custom_tag`、`nodejs_basic`、
  `policy_injection`）と wrap_image_e2e の 12 件が `Docker not available` で内部 skip。
  `test_container_no_engine_skip` は skip 挙動自体を検査するテストで期待どおり pass。
- `path_resolution_e2e::symlink_resolution_and_wait_file_barrier` は
  `symlink creation unavailable (privilege/developer mode)` で内部 skip。
- `windows_verbatim_and_plain_drive_forms` 内の UNC 形検査は
  `NOTE: UNC form skipped (no managed verification share)` で部分 skip。
- Windows のサンドボックス経路（AppContainer）は
  `sandboxed_os_boundary_and_process_shared_access` が実実行で合格。

### ベースライン出力（PR0-3）

`cargo build --locked --release --bin mcp-writ`（終了コード 0、
`target/release/mcp-writ.exe` 4,727,808 bytes）の後、手順どおりの出力を
`.local/stdio-hardening/baseline/` に保存した。PR7 のバイト一致比較に使用する。

| ファイル | 内容 | SHA-256 |
|---|---|---|
| `inspect-x86.{human,json,kdl}` | `x86_64_linux_syscalls.elf` の inspect。Risk 55/100 (High)、syscall サイト 10 件（execve 含む）、URL/path/env 文字列各 1 | `527f446c…` / `a662c92c…` / `93c63744…` |
| `inspect-aarch64.{human,json,kdl}` | `aarch64_linux_syscalls.elf` の inspect | `49114054…` / `5dc4436d…` / `1033b3d9…` |
| `inspect-py.{human,json,kdl}` | `read_file_urlopen.py` の inspect。stderr に `native analysis skipped; source payload = tests/fixtures/py_mcp/read_file_urlopen.py` | `d1e7320d…` / `97f70a90…` / `fd5645fc…` |
| `genpol-py.kdl` | `generate-policy -- py -3 tests/fixtures/py_mcp/read_file_urlopen.py`。Source payload は `.py` に解決、syscalls は `non_native_payload` で allow 行なし、`tool "read_file" side_effect="network"` を生成 | `53e37141…` |
| `genpol-py.stderr.txt` | 上記実行の stderr。`native analysis skipped; source payload = …` と静的解析のみの INFO 行 | （ログ） |
| `genpol-x86.kdl` | `generate-policy -- tests/fixtures/inspector/x86_64_linux_syscalls.elf`。`defaults.syscalls.allow` に 10 名（execve は REVIEW コメントで非許可）、server ブロックなし | `1db2751e…` |
| `genpol-x86.stderr.txt` | 上記実行の stderr。静的解析のみの INFO 行 | （ログ） |
| `cargo-tree.txt` | `cargo tree --locked --edges normal,build`（依存グラフ固定用） | `a7df1099…` |

完全なハッシュ値は `sha256sum .local/stdio-hardening/baseline/*` で再現可能。
`generate-policy` はいずれも静的解析のみ（`--live-discovery` 未指定）で、
stderr は同ディレクトリの `genpol-*.stderr.txt` に保存した。

### tools/list の変更前挙動（PR0-4）

`tool_enforcement_e2e.rs::transfer_b_drops_unknown_vendor_key_from_forwarded_tools_list`
と同じ経路で記録した。`MCP_WRIT_FIXTURE=tools_call_ok` の
`tests/fixtures/mcp_servers/scripted_stdio.py`（応答ツール: `read_file`、
`fail_write`、`fetch_url` の 3 件）に対し、ポリシーには `read_file` と `fetch_url`
だけを載せ `fail_write` を未掲載にした（`.local/stdio-hardening/tools-list-policy.kdl`、
テストの `BASE_POLICY` と同内容）。

実行コマンド（`MCP_WRIT_SKIP_SANDBOX=1` と `MCP_WRIT_FIXTURE=tools_call_ok` を `WSLENV` で伝播）:

```sh
{ printf '%s\n' '{"jsonrpc":"2.0","id":41,"method":"tools/list","params":{}}'; sleep 8; } |
  target/release/mcp-writ.exe run --transport stdio \
    --policy .local/stdio-hardening/tools-list-policy.kdl \
    --audit-log .local/stdio-hardening/tools-list-audit.jsonl \
    -- py -3 tests/fixtures/mcp_servers/scripted_stdio.py
```

終了コード 0。stdout の応答（`.local/stdio-hardening/tools-list-before.stdout.txt`）は
`"result"` を含み、`tools` に `read_file`、`fail_write`、`fetch_url` の 3 件すべてが
含まれる。ポリシー未掲載の `fail_write` がクライアントへ転送される現行挙動を確認した
（PR4 のフィルタ対象となる変更前挙動）。stderr（同 `.stderr.txt`）は
`Policy loaded`、`sandboxing disabled (MCP_WRIT_SKIP_SANDBOX)`、
`No tools-list-hash in policy; allowing tools/list`、`Auditor relay finished` の各 1 行。
監査ログ `tools-list-audit.jsonl` は 0 バイト（拒否・フィルタ対象イベントなし）。

### 検証コマンドと終了コード（PR0 共通チェック）

| コマンド | 終了コード | 要点 |
|---|---|---|
| `cargo fmt --all -- --check` | 0 | 差分なし |
| `cargo clippy --locked --all-targets -- -D warnings` | 0 | 警告なし |
| `cargo test --locked` | 0 | 1498 件全合格（上表） |
| `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` | 0 | `target/doc/mcp_writ/index.html` 生成 |
| `git diff --check` | 0 | 出力なし |
| `git diff --stat -- Cargo.lock` | 0 | 出力空（`Cargo.lock` 差分なし） |
| `py -3 scripts/check_docs.py` | 0 | `Checked 18 Markdown files: encoding and local links OK` |

### 次へ進む条件の確認

- HEAD: `7c6d553e92a0f7ffc540180bcbd0985fc810b710` を記録済み
- 既存差分: `git status --short` / `git diff --stat` ともに空を記録済み
- テスト件数: 1498 件全合格、内部 skip の一覧と理由を記録済み
- fixture 出力: `baseline/` に 12 ファイル（inspect 9 + generate-policy 2 + cargo-tree 1）
  と tools/list 記録一式を保存済み
- 依存グラフ: `baseline/cargo-tree.txt` に保存済み
- ランタイムの版: rustc / cargo / node / npm / Python / pip / git を記録済み

## PR1. 文書チェックの cargo test 化

対象コミット / 未コミット差分: 実施時点の HEAD =
  `7c6d553e92a0f7ffc540180bcbd0985fc810b710`（PR0 時点から変更なし）で、当時の
  `git status --short` は `M` 6 件（2 ワークフロー、development/releasing、
  plan/runbook の日本語文書）、`D` 1 件（`scripts/check_docs.py`）、`??` 1 件
  （`tests/docs_check.rs`）、および本書の更新だった。その後 `2b17f1d`
  （`Migrate documentation checks from Python script to Rust integration test`）
  としてコミット済み。レビュー指摘対応としてさらに未コミット差分が残る:
  `platform-tests.yml` への `--test docs_check` 追加、`Cargo.toml` の `exclude`
  への `/tests/docs_check.rs` 追加、`tests/docs_check.rs` の等価性修正（後述）。
変更ファイル:
- 新設 `tests/docs_check.rs`: `scripts/check_docs.py` の Rust 移植。11 テスト
  （初回 9 テスト＋レビュー指摘対応で `url_split_rejects_python_valueerror_netlocs`、
  `resolve_canonicalizes_the_existing_prefix` を追加。さらに unix 限定で
  `resolve_expands_dangling_symlink_targets` を追加）。
- 削除 `scripts/check_docs.py`: `scripts/` は空になったためディレクトリごと削除。
- 更新 `.github/workflows/ci.yml` / `.github/workflows/linux-tests.yml`:
  `python3 scripts/check_docs.py` の明示ステップを削除し、Integration tests の
  列挙に `--test docs_check` を追加。
- 更新 `.github/workflows/platform-tests.yml`（レビュー指摘対応）: Windows/macOS
  の Integration tests に `--test docs_check` を追加し、Windows 固有パス
  （`norm_key`・`is_relative_to`・`resolve_link` の rooted 分岐）を CI で検証可能にした。
- 更新 `Cargo.toml`（レビュー指摘対応）: `exclude` に `/tests/docs_check.rs` を追加。
  `.github/**` が exclude 済みのため、同梱したままではパッケージ内で `cargo test`
  を実行した際に `.github` へのリンクが「missing local target」で失敗する
  （Python 版はスクリプト自体が非同梱であり、この失敗経路は移植で新設された）。
- 更新 `docs/development.md` / `docs/releasing.md`: 検証コマンド一覧から Python 版の
  実行行を外し、文書チェックが `cargo test` に含まれる旨を記載。
- 更新 `docs/stdio-hardening-plan.ja.md` / `docs/stdio-hardening-runbook.ja.md`:
  削除済みスクリプトへの Markdown リンクをコード表記へ変更（リンク切れ防止）。
  手順・切り戻しの記述自体は手順書の役割上そのまま残す。
設計判断と逸脱:
- `regex-lite` 0.1.9 は `\p{...}` Unicode クラス非対応で `\s` は ASCII のみのため、
  Python の `unicodedata.category(chr)[0] in "LNM"` 相当は Python 3.12.10
  （unicodedata Unicode 15.0.0）から生成した 794 区間の `LNM_RANGES` テーブルで再現した。
  Python `re` の `\s` / `str.isspace()` / `str.splitlines()` の Unicode 境界は
  `PY_WS` 集合と `is_py_space` / `py_lines` で再現。依存追加なし、`Cargo.lock` 差分なし。
- `urlsplit` による外部 URL 判定、`posixpath.normpath` 相当のリンク解決、
  リポジトリ境界検査、重複見出しの `-1` 連番、`Checked N Markdown files: ...` の
  成功出力を維持。指摘の同一性は下記の対称検証で確認した。
- 逸脱: なし（計画どおり標準ライブラリと `regex-lite` のみで実装）。
- レビュー指摘対応（`2b17f1d` 後の未コミット差分）で残存する非等価経路を修正:
  - 文書キーとリンク先の `Path.resolve()` 相当を `resolve()` で実装。最長既存
    プレフィックスを `fs::canonicalize` して欠落尾部を字句正規化で再接続する
    （symlink 解決後に `..` が適用される `os.path.realpath` の意味論に一致）。
    さらに、dangling symlink（リンク先が存在しない）も `read_link` で展開し、
    相対ターゲットはリンクの親基準で解決する（realpath がリンクを字句的に
    展開する挙動に一致。`link -> missing/deep` への `link/../x` は
    `missing/x` に解決される）。Windows の verbatim 接頭辞 `\\?\` /
    `\\?\UNC\` は `strip_verbatim` で `D:\…` / `\\s\p` 形式へ戻す。
  - `urlsplit` が `ValueError` でクラッシュする経路を panic で再現: ブラケット
    不整合（`Invalid IPv6 URL`）、不正な bracketed host（IPvFuture 形式、
    `ipaddress.ip_address` 相当の検査、bracketed IPv4 の拒否、IPv6 `%scope`
    受理 — ただし空または `%` を含む scope は Python 同様拒否）、非 ASCII
    netloc の NFKC 検査（`_checknetloc`）。NFKC は既存依存の
    `unicode-normalization` を使用。
  - ルート直下の `*.md` ディレクトリは `is_file()` フィルタを外して `fs::read`
    の panic に委ねる（Python の `IsADirectoryError` クラッシュ相当）。
    `rglob` 相当の再帰は `entry.file_type()` で判定し、symlink ディレクトリに
    潜らない（`Path.walk(follow_symlinks=False)` 相当）。
  - `normalize` の `..` 退避分岐は絶対パス入力では到達不能のため削除。
  - `sorted()` は `_parts_normcase` の順方向比較であり `parts_key` と等価、
    `urlsplit` の scheme 先頭英字要件は Python 3.12.3 の実機出力で確認済み。
検証コマンドと結果: 下記「検証コマンドと終了コード（PR1 共通チェック）」。
  対称検証（手順 2）は同一作業ツリーで実施し、クリーン時は両実装とも
  `Checked 19 Markdown files: encoding and local links OK` を出力。
  意図的に作った `zz-broken.md`（存在しない `does-not-exist.md` へのリンク）に対し、
  両実装とも `zz-broken.md: missing local target does-not-exist.md` のみを指摘した
  （検証後に当該ファイルを削除）。
現物サーバ: 未取得（PR2 の範囲）。本 PR は文書チェックの移植のみで、
  実行経路の変更はない。
未検証: Python 版の終了コード。WSL→Win32 相互運用では子プロセスの終了コードが
  伝播しない環境癖があり（`sys.exit(7)` でもシェルには 0 と見える）、
  指摘の同一性は出力テキストの照合で代替した。Linux/macOS での `cargo test` は
  本機（Windows）では未実施。symlink 経路は本機に作成権限がなく実機検証できず、
  `resolve()` の意味論は WSL 上の Python 3.12.3 の `os.path.realpath` /
  `urlsplit` / `Path.walk` 出力との照合で設計した。
残る制約: `LNM_RANGES` は Unicode 15.0.0 に固定。Python 側の Unicode 版が上がり
  カテゴリ差異が問題になった場合はテーブルを再生成する。`_checknetloc` の NFKC
  は `unicode-normalization` クレートの同梱 Unicode 版に依存する（Python 3.12 の
  unicodedata 15.0.0 とは版差がありうる）。文書チェックは以後 `cargo test` の
  一部であり、Python 実行環境は不要になった。

### 検証コマンドと終了コード（PR1 共通チェック）

| コマンド | 終了コード | 要点 |
|---|---|---|
| `cargo fmt --all -- --check` | 0 | `cargo fmt --all` で整形後に差分なし |
| `cargo clippy --locked --all-targets -- -D warnings` | 0 | `collapsible_if` を let-chain 化して解消 |
| `cargo test --locked` | 0 | 19 スイート合計 1509 件すべて合格（PR0 の 1498 + `docs_check` 11）、0 failed、0 ignored |
| `cargo test --locked --test docs_check` | 0 | 11 件合格、`Checked 19 Markdown files: encoding and local links OK` を出力 |
| 異常系の対称確認（レビュー指摘対応） | ― | `zz-badurl.md`（`http://[` リンク）と `zz-dir.md`（ルート直下の `*.md` ディレクトリ）で panic、Python の `ValueError` / `IsADirectoryError` クラッシュ相当を確認（検証後に削除） |
| `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` | 0 | `target/doc/mcp_writ/index.html` 生成 |
| `git diff --check` | 0 | 差分エラーなし（既存 fixture の CRLF 通知のみ、本 diff とは無関係） |
| `git diff --stat -- Cargo.lock` | 0 | 出力空（`Cargo.lock` 差分なし） |
| `py -3 scripts/check_docs.py`（削除前の対称検証） | ― | `Checked 19 Markdown files: ...` を出力。終了コードは上記環境癖により未検証 |

### check_docs 残存参照の確認（手順 6）

全層検索の結果、生きた実行指示は残っていない。残存は次のいずれかに限定される:
`docs/archive/` 配下の保管文書（移行対象外）、本 PR の移行自体を記述する
plan/runbook/results 内の記述（いずれもコード表記、Markdown リンクではない）、
`tests/docs_check.rs` 冒頭の由来コメント。

### 次へ進む条件の確認（PR1）

- 文書チェックが `cargo test` に含まれる: `tests/docs_check.rs` 9 件が
  `cargo test --locked` で実行され合格
- Python 版と同じ指摘を出す: クリーン時と壊れたリンク時の両方で出力一致を確認済み
- CI の明示ステップが消えている: `ci.yml` / `linux-tests.yml` から削除済み
- `scripts/` 削除済み、`Cargo.lock` 差分なし

## PR2. 現物 MCP サーバの検証基盤

対象コミット / 未コミット差分: 実施時点の HEAD =
  `cda10cdb93e00f3566b603962b6bb35b1be51c37`（`Merge pull request #11`、PR1 まで
  コミット済み）。PR2 の変更はすべて未コミットの作業ツリー差分として残す
  （`git status --short`: `M` 19 件、`??` 5 件 — 下記「変更ファイル」）。
変更ファイル:
- 新設 `tests/fixtures/real_servers/`: 取得定義のみをコミット対象にする。
  `node/package.json`（`@modelcontextprotocol/server-filesystem` と
  `server-memory` を `2026.8.31` に exact 固定）と `npm ci --ignore-scripts` で
  再現する `node/package-lock.json`、`python/requirements.txt`
  （`mcp-server-time` / `mcp-server-git` を `2026.8.18` に `==` 固定、依存閉包
  `mcp==1.30.0` など全行 `--hash=sha256:` 付き。`pywin32` には
  `sys_platform == "win32"` マーカーを付けて非 Windows での解決失敗を回避）、
  `setup.sh` / `setup.ps1`（引数なし・冪等・同一手順）、Windows 専用の
  `node/win-realpath-stub.cjs`（後述）。`setup.ps1` はさらに MinGit
  `2.55.0.4` を取得する — 公式リリース告知の sha256
  `4e03f94c2ffbf70be337e005cee02661c732dbfc81031a078bda9299b9a7d644` を
  ピンし、取得時に照合してから展開する。
- 新設 `examples/policies/`: `filesystem.kdl` / `memory.kdl` / `time.kdl` /
  `git.kdl` の 4 本（ツール allowlist・`side_effect`・per-tool `filesystem`・
  手順 4 の `tools-list-hash`。`defaults` には `network { deny host="*" }` のみで
  ホスト固有パスを書かない）と、ランタイム基底 `runtime/node.kdl` /
  `runtime/python.kdl`（Linux seccomp 許可リストを `defaults.syscalls` に、
  群ごとの理由コメント付き。ホスト固有パスなし）。
- 新設 `tests/real_servers_e2e.rs`: 4 サーバ × 6 段階。fixture 未導入なら
  `common::skip_server_test` で skip、`MCP_WRIT_REQUIRE_SERVER_TESTS=1` では
  失敗にする。段構成は手順書どおり（discovery / dry-run / sandboxed /
  Auditor 拒否 / OS 層拒否 / 破損 `tools-list-hash` 拒否）。
- 新設 `scripts/check-server.sh` / `scripts/check-server.ps1`: 同一引数・
  同一 3 段（dry-run → sandboxed → 任意の sandboxed `tools/call`）・同一見出し。
  判定は「応答に `"result"` を含み `"error"` を含まない、`--call` 応答は
  `"isError":true` を含まない」に限定。ps1 は `-File` 呼び出しでは `--` を
  束縛できないため `--` なしの残り引数でサーバコマンドを受け取る
  （防御的に先頭の `--` は剥がす）。`ProcessStartInfo.ArgumentList` は
  Windows PowerShell 5.1 に無いため `Arguments` 文字列に手動クォートで組み立て、
  `PositionalBinding=$false` でサーバコマンドが named パラメータに誤束縛
  されるのを防いだ。
- 新設 `.github/workflows/mcp-servers.yml`: `workflow_dispatch` /
  `workflow_call` のみ（push/PR 自動起動なし）。`ubuntu-24.04` /
  `macos-latest` / `windows-latest` matrix、アクションは全て SHA ピン、
  Rust `1.98.1` / Node `24.11.1` / Python `3.12.10` 固定、
  `MCP_WRIT_REQUIRE_SERVER_TESTS=1` で 6 段階 e2e と `check-server` を実行。
  Unix のホストポリシー生成は `/usr` `/lib` `/lib64` `/bin` `/sbin` `/etc`
  `/etc/ssl` `/proc` `/dev` 等の存在パスに read、`/dev/null` に write を付与
  する（後述の実測由来）。Windows 側は Node 起動に
  `--preserve-symlinks-main --preserve-symlinks --require <stub>` を付ける。
- 更新 `.github/workflows/release.yml`: `mcp-servers.yml` は `needs` に加えず
  linux-tests と同じ manual-dispatch 扱いである旨のコメント。
- 更新 `tests/common/mod.rs`: `path_resolution_e2e` から sandboxed spawn /
  policy 補助を移動し、`host_defaults_kdl(argv0)` を新設 — argv0 の与えたままの
  親＋祖先、`resolve_command_path` で解決した実行体の親＋祖先、Windows venv の
  `pyvenv.cfg` から読んだ base interpreter prefix、fixture ツリー、プラット
  フォームのランタイムディレクトリ（Linux は `/usr` `/lib` `/lib64` `/etc`
  `/etc/ssl` `/proc` `/dev` 等、`/dev/null` は write、macOS は SBPL プロファイルと
  同じ固定システムパス）を read 許可に入れる。`defaults.syscalls` は
  `examples/policies/runtime/{node,python}.kdl` を読んで単一ソース化。
- 更新 `tests/path_resolution_e2e.rs`: 共通ヘルパーへの移行で重複削除。
- 更新 `src/runtime/launch.rs`: argv0 がパス形式（`/`・`\` 含有）なら綴りを
  維持し、裸名だけを解決済みパスに置き換える。canonicalize で venv の
  `bin/python` symlink が base interpreter に潰れ venv を喪失する不具合を修正。
- 更新 `src/warden/windows_profile.rs` / `src/warden/windows_sandbox.rs`:
  Windows サンドボックスの既定を LPAC から通常 AppContainer に変更
  （`MCP_WRIT_WINDOWS_LPAC=1` で opt-in 復帰）。fs/read_write/tmpdir の ACL
  grant は失敗を spawn 失敗にせず `tracing::warn` に格下げ（grant 失敗は
  権限を広げないため）。
- 更新 `src/warden/seccomp_impl.rs`: `capget` `io_uring_setup` `io_uring_enter`
  `io_uring_register` `membarrier` のマッピングを追加。従来は実行時に
  「no mapping on this architecture」で静かにスキップされていた。
- 更新 `src/warden/mod.rs` / `src/legislator/self_test.rs`: LPAC 前提の
  記述を AppContainer に合わせたコメント修正。
- 更新 `tests/docs_check.rs`: `collect_markdown` が `node_modules` / `.venv`
  のベンダ README を検査して誤検出するため、これらのディレクトリ名では
  再帰を降りないようにした。
- 更新 `policy.example.kdl`: 19-20 行の `servers/filesystem.kdl` 参照を
  `examples/policies/filesystem.kdl` に変更。
- 更新 `docs/development.md` / `docs/policy-authoring.{md,ja.md}` /
  `docs/guide.{md,ja.md}` / `docs/releasing.md`: 前提条件・実サーバ検証手順・
  ランタイムポリシー作成・`check-server` の使い方・プラットフォーム差異・
  ワークフローの手動 dispatch 要件を日英で追記。ガイド FAQ の LPAC 記述は
  実装変更（既定=通常 AppContainer、`MCP_WRIT_WINDOWS_LPAC=1` で opt-in）に
  合わせて訂正。
- `.gitignore`: `tests/fixtures/real_servers/node/node_modules/`、
  `python/.venv/`、`mingit/` を追加。`Cargo.toml` の `exclude` にも同 3 つ。

設計判断と逸脱:
- Windows の既定を LPAC → 通常 AppContainer に変更。LPAC は
  `ALL_APPLICATION_PACKAGES` を外すため Winsock カタログ等のシステム資源まで
  閉じ、Node が `WSAStartup` で死ぬ。レジストリキーは非管理者が ACL grant
  できず回避不能。通常 AppContainer でもユーザ私物ファイルは package ACE を
  持たず拒否されたままなので隔離目的は維持される。
- Windows の Node サーバは realpath 経路が 2 層で塞がる。(a) モジュール
  ローダーの `realpathSync` がドライブルートまで祖先 lstat を要し、ルートは
  grant 不能 → `--preserve-symlinks-main --preserve-symlinks` で回避。
  (b) `fs.realpath`（libuv = `GetFinalPathNameByHandleW`）は NT 名前空間
  アクセスが必須で AppContainer から恒常 EPERM、サーバ側のフォールバックも
  無い → `tests/fixtures/real_servers/node/win-realpath-stub.cjs` を
  `--require` で preload し `fs.realpath` を恒等写像に置き換える。パス自体の
  DACL 強制は残るため検証目的を損なわない。これは製品仕様の制約として記録し、
  fixture 側でサーバコードは改変しない。
- Windows の git: システム `git.exe`（`D:\Program Files\Git`）は package ACE
  も非管理者 grant も効かずコンテナ内で起動不能。さらに MinGW の
  `mingw_getcwd` が `GetFinalPathNameByHandleW` を呼ぶため、実行できても
  cwd 解決で失敗する。対策として `setup.ps1` で sha256 ピン済み MinGit を
  fixture に置き、`GIT_PYTHON_GIT_EXECUTABLE` に渡す — GitPython の import
  時検証（`git version`）まではコンテナ内で成立し、initialize / tools/list /
  Auditor 層は実検証できる。`git_log` 等の実サブプロセス呼び出しは
  AppContainer では原理的に不可のため段 3・5 は Windows 分岐で「失敗が
  fail-closed に返る」ことをアサートして記録（実装コメント参照）。
- git 段 5 の設計を修正: `mcp-server-git` は `--repository` でスコープ外
  repo_path をサーバ自身が拒否するため、別セッションで `--repository` を
  対象リポジトリに向けて起動し、サーバスコープを通した上で OS 層の到達を
  検証する形にした。
- Linux の syscall 許可リストは推測でなく strace 実測で組み立てた。
  見つかった不足と対応: `uname`（Python/Node とも起動直後に死亡）、
  `socketpair`（asyncio セルフパイプ、起動不能）、`sendto`/`recvfrom`/
  `sendmsg`/`recvmsg`/`shutdown`（セルフパイプ起床が EPERM で `epoll_wait`
  永久ハング — 最も解析に時間が掛かった障害）、`rename`/`mkdirat` 等の
  書き込み系（memory サーバの永続化）、`ioctl`/`statx`/`capget`/`sysinfo`/
  `setpgid`/`io_uring_*`/`membarrier`（Node の probes と libuv）。後者群の
  一部は seccomp_impl のマッピング表に無く静かにスキップされていたため
  実装側も修正した。
- Linux の filesystem grant に `/proc` `/dev` が抜けており `openat("/dev/null")`、
  `/proc/self/maps` 等が EACCES → `host_defaults_kdl` と CI のポリシー生成に
  追加。`/dev/null` は libuv が O_RDWR で開くため write 許可が必要。
- WSL2 カーネル 5.15 は Landlock ABI V1 のみ対応で、全 ruleset は
  `PartiallyEnforced` となり fail-closed で起動拒否される。e2e のホスト
  ポリシー生成にカーネル判定を入れ、6.7 未満では `sandbox allow_degraded=#true`
  を付与する。部分適用での合格であり、完全適用の証拠はカーネル 6.8+ の CI
  に委ねる（後述「未検証」）。
- git サーバは `HOME/.gitconfig` を読みに行き、sandbox で EACCES になると
  `fatal: unknown error` で落ちる。e2e では `GIT_CONFIG_GLOBAL=/dev/null` と
  `GIT_CONFIG_NOSYSTEM=1` を子に渡して回避。
- Windows では `AppContainerSandbox::Drop` が grant 前 DACL を復元するため、
  並行テストで一方の終了が他方の伝播 ACE を消し込む競合があった
  （`ERR_MODULE_NOT_FOUND` 等）。PR2 範囲ではテストを static Mutex で直列化
  して回避し、restore-on-drop 自体の競合は製品レベルの既知制約として残す。
- `check-server.sh`: dry-run 送信直後に stdin を閉じるとガードが先に終了して
  tools/list 応答を取りこぼす競合があったため、送信後に stdin を数秒保持
  する。`--audit-log` の既定は cwd 相対に変更（WSL→Win32 相互運用では
  `/tmp/...` が Win32 側に通じない）。
- `path_resolution_e2e` からのヘルパー移動は挙動不変。`stage2_dry_run` は
  positive call の 3 引数を `PositiveCall` に集約（clippy 対応）。
- 逸脱: venv の混在事故（`/mnt/d` 上の `.venv` が Windows 形式と WSL 側
  作成の混在で壊れた）に伴い、Windows 側は `setup.ps1` で再作成、Linux 検証は
  `/mnt/d`（DrvFS で node_modules 読み込みが遅く discovery 5 秒タイムアウトを
  超過した）ではなく ext4 上のコピー `/home/yuzame/mcp-writ-verify` で実施。
  コピーは検証用で、変更は常に `D:\Projects\mcp-writ` に施してから同期した。
検証コマンドと結果: 下記「検証コマンドと終了コード（PR2）」。
現物サーバ: 取得・検証済み（次節の表）。4 本とも `2025-11-25` を交渉した。
macOS 経路は 2026-09-21 に実機検証済み（末尾「macOS 追検証」節）。
未検証: `mcp-servers.yml` の CI 実行自体（手動 dispatch 前提で未起動）。
  Landlock ABI V4 の完全適用（WSL カーネル 5.15 では ABI V1 の部分適用
  まで）。Windows の LPAC モード（opt-in 実験用）。
残る制約: WSL2 カーネル 5.15 = Landlock ABI V1 のみ（部分適用）。Windows は
  Node の `fs.realpath` が恒等 stub 前提、`git.exe` の cwd 解決不可により
  mcp-server-git の実 git 呼び出しはコンテナ内で動かない（段 3・5 は
  fail-closed 確認に留まる）。runtime ポリシーの syscall 群は実測由来で
  プラットフォーム・版依存。`AppContainerSandbox::Drop` の DACL 復元競合は
  未改修（テストは直列化で回避）。
証拠の保存先: `.local/stdio-hardening/`（gitignore 対象）。起動形分類の
  inspect / generate-policy 出力は `classify/`、live discovery の出力は
  `discover/`、作業用ディレクトリは `work/`。

### 実行環境（PR2）

| 項目 | 値 |
|---|---|
| OS（Windows） | Windows 11（10.0.26200.9457）、native x86-64 |
| OS（Linux） | WSL2 Ubuntu 24.04.2、kernel `5.15.167.4-microsoft-standard-WSL2`（Landlock ABI V1 のみ） |
| CPU | AMD Ryzen 5 9600X |
| ツールチェーン | `rustc`/`cargo` 1.98.1（Windows: x86_64-pc-windows-msvc。WSL: ユーザ空間インストール + musl ターゲット、ビルドスクリプト用リンカのみ zig cc ラッパー）、Node `v24.11.1`、Python `3.12.10`（Windows は `py -3`、WSL は venv 内 `python3.12`）、git `2.43.0`（WSL）/ MinGit `2.55.0.4`（Windows fixture） |

### 起動形の分類（手順 3）

`mcp-writ inspect` / `generate-policy --static-only` を各起動形に実行した
（出力は `.local/stdio-hardening/classify/`）。基準実装どおり:

| 起動形 | payload | 備考 |
|---|---|---|
| `node <…>/dist/index.js`（filesystem / memory） | Source（`non_native_payload`、script が解決される） | `source_tools` 出力あり |
| `<venv-python> <site-packages>/…/__main__.py`（time / git） | Source（同上） | `source_tools` 出力あり |
| `<venv-python> -m mcp_server_time` / `-m mcp_server_git` / `py -3 -m` | Unresolved（`no source file payload` warning） | モジュール名は静的解決されずランタイム側の束縛に委ねる |
| `npx -y @modelcontextprotocol/server-filesystem@2026.8.31` | Unresolved（同上） | 同上 |
| `<venv>/Scripts/mcp-server-time.exe`（entry point exe） | PE 容器は検出されるが `unsupported_format`（PE 解析非対応）、risk_score 10 | Windows venv の exe stub |

### 現物サーバの live discovery（手順 4）

`generate-policy --live-discovery` の結果（出力は
`.local/stdio-hardening/discover/`）。`tools-list-hash` は `examples/policies/`
の各ファイルにピン済みで、`tests/real_servers_e2e.rs` の `expected_hash` と
一致することを段 1・6 で検証している。

| サーバ | 固定版 | 交渉 MCP 版 | ツール数 | tools-list-hash (sha256) |
|---|---|---|---|---|
| `@modelcontextprotocol/server-filesystem` | `2026.8.31` | `2025-11-25` | 14 | `1ef36fd736d82bacdbb5bce1dda540553a2b59e07c625249845296845a335a26` |
| `@modelcontextprotocol/server-memory` | `2026.8.31` | `2025-11-25` | 9 | `0ae46ff5e9dee8192e577615964eb12d3b3b4ddcaee608049c201267842c3fa8` |
| `mcp-server-time` | `2026.8.18` | `2025-11-25` | 2 | `194aba9e881fd6f061b6c80175838c4d82a30ad2f8a53a68e68585f39422bb7c`（`--local-timezone UTC` pin。旧値 `be763b48…` はホスト TZ 依存だった — 末尾「macOS 追検証」参照） |
| `mcp-server-git` | `2026.8.18` | `2025-11-25` | 12 | `6d33f714008a03d44fcb8458e95fa8b5374240837f04e6bd5db86e49ac7e6410` |

### 6 段階 e2e の結果（手順 8・12）

`MCP_WRIT_REQUIRE_SERVER_TESTS=1 cargo test --locked --test real_servers_e2e`
を Windows（ネイティブ、musl ではなく msvc）と WSL2（musl、ext4 コピー）で
実行。両方で `4 passed; 0 failed`（`filesystem_stages` / `memory_stages` /
`time_stages` / `git_stages`）。

| 段 | Windows | WSL2 Linux（ABI V1 部分適用） |
|---|---|---|
| 1 live discovery + hash pin | 4/4 成功 | 4/4 成功 |
| 2 dry-run（initialize・tools/list・許可 call） | 4/4 成功 | 4/4 成功 |
| 3 sandboxed 起動・initialize・許可 call | fs/memory/time 成功。git はサーバ起動・tools/list・Auditor 層まで成立、実 `git` 呼び出しは fail-closed（記録済みの platform 分岐） | 4/4 成功 |
| 4 Auditor 拒否（JSON-RPC error + `tool_call.denied` 監査行） | 4/4 成功 | 4/4 成功 |
| 5 OS 層のみの拒否・到達 | fs/memory/git の期待どおり（git は Windows 分岐で fail-closed 確認） | 4/4 成功（合成 grant で到達する経路も含む） |
| 6 破損 `tools-list-hash` で tools/list 拒否 | 4/4 成功 | 4/4 成功 |

fixture 未導入環境での skip 振る舞い: `MCP_WRIT_REQUIRE_SERVER_TESTS` 未設定
では `common::skip_server_test` で skip、設定時は prerequisite 欠落が失敗に
なる（CI では常時設定）。

### check-server の実機実行（手順 9・12）

- Linux（WSL、mcp-server-time、`get_current_time` call 付き）:
  `check-server.sh` が stage 1 dry-run / stage 2 sandboxed / stage 3 sandboxed
  call を全て PASS。応答は `result` 含有・`error` 非含有・`isError:false`。
  監査ログ末尾に `hash.verified`（tools-list-hash 検証）と
  `tool_call.allowed`（`get_current_time`）を確認。終了出力 `check-server: PASS`。
- Windows（filesystem サーバ、`check-server.ps1`、native PowerShell 実行）:
  全 3 段 PASS。同一サーバに対する `check-server.sh`（WSL bash から Win32
  相互運用）も PASS。両スクリプトの見出しと段構成は一致。

### 検証コマンドと終了コード（PR2 共通チェック）

| コマンド | 終了コード | 要点 |
|---|---|---|
| `cargo fmt --all -- --check` | 0 | `cargo fmt --all` 適用後に差分なし |
| `cargo clippy --locked --all-targets -- -D warnings` | 0 | 初回は `tests/common/mod.rs` の doc リスト字下げ 3 件・`collapsible_if` 1 件、`real_servers_e2e` の `too_many_arguments` 1 件で失敗 → doc 区切り修正・let-chain 化・`PositiveCall` 集約で解消後に警告なし |
| `cargo test --locked` | 0 | 全 20 スイート計 1513 件合格（`real_servers_e2e` 4 件は fixture ありのため本番実行で 43.1s）。初回は `docs_check` が fixture 内のベンダ README を誤検出して失敗 → 除外修正で合格 |
| `MCP_WRIT_REQUIRE_SERVER_TESTS=1 cargo test --locked --test real_servers_e2e` | 0 | Windows msvc / WSL musl の両環境で 4 件合格 |
| `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` | 0 | `target/doc/mcp_writ/index.html` 生成 |
| `git diff --check` | 0 | 出力なし |
| `git diff --stat -- Cargo.lock` | 0 | 出力空（`Cargo.lock` 差分なし） |
| `cargo package --list` | 0 | `node_modules` / `.venv` / `mingit` を含まない。fixture は取得定義（package.json / lock / requirements.txt / setup.* / stub）のみ同梱 |
| `scripts/check-server.sh`（Linux、実 time サーバ） | 0 | 3 段 PASS（上記） |
| `scripts/check-server.ps1`（Windows、実 filesystem サーバ） | 0 | 3 段 PASS（上記） |

### 次へ進む条件の確認（PR2）

- 4 本の現物サーバが Warden 有りで `initialize` から `tools/call` まで動く:
  Windows・WSL2・macOS で確認（git の実呼び出しは Windows では記録済みの
  platform 制約で fail-closed。macOS の結果は末尾「macOS 追検証」節）
- Auditor の拒否・OS 層だけの拒否・`tools-list-hash` の固定: 段 4・5・6 で確認
- 起動形ごとの分類と交渉した MCP 版: 上記 2 表に記録
- 配備先で同じ確認を行える: `setup.sh`/`setup.ps1`（冪等・ハッシュ照合付き）、
  `check-server.sh`/`.ps1`（同一 3 段）、`mcp-servers.yml`（手動 dispatch）を配置
- `cargo package --list` に `node_modules` / `.venv` / `mingit` が無いこと:
  確認済み

### macOS 追検証（2026-09-21）

実施時は「本機に Mac なし」で未検証だった macOS 経路を、macOS 26.6.2
（Darwin 25.6.0、arm64）で実機検証した。ツールチェーン: `rustc`/`cargo`
`1.98.1`、Node `v24.6.0`（Homebrew）、Python `3.14.6`（Homebrew
`python@3.14`、fixture venv は `.venv/bin/python`）、git `2.49.0`。

`tests/fixtures/real_servers/setup.sh` は `npm ci --ignore-scripts`
（104 パッケージ、監査上の脆弱性なし）と `pip install --require-hashes`
（venv 作成を含む）がそのまま完了した。起動形分類と live discovery は
Windows/WSL と同じ結果: `node <path>.js` と `<venv>/python …__main__.py` は
Source payload を取得、`python -m` と `npx` は Unresolved。4 本とも
`2025-11-25` を交渉し、ツール数と `tools-list-hash` はピンと一致した。

発見した macOS 固有の不具合と修正（すべて作業ツリー差分に含む）:

- **venv の interpreter 喪失**: macOS の CPython は install prefix を
  `argv[0]` ではなく `_NSGetExecutablePath`（exec された実体パス）から
  決める。ガードが検証済み実体を exec して綴りを `argv[0]` に残す設計の
  ため、`.venv/bin/python` symlink 経由の venv 認識が壊れ
  `No module named mcp_server_*` で起動不能になった（Windows は
  `Scripts\python.exe` が実ファイルなので未発だった）。`warden` に
  `python_executable_override` を追加し、macOS では綴りパスを
  `PYTHONEXECUTABLE`（getpath が実体パスより先に参照するフック）として
  子に渡す。
- **Homebrew の共有ライブラリ**: `Cellar/node/<ver>/bin/node` は
  `/opt/homebrew/opt/{libuv,simdjson,brotli,…}`（sibling keg）の dylib を
  リンクする。実行体の親＋祖父の許可では届かず、`dyld` が
  `Library not loaded … (blocked by sandbox)` で spawn 失敗した。
  `tests/common` に `exe_read_grant_dirs`（親・prefix・`<prefix>/Cellar`
  の親 = store root）を追加して host ポリシー生成に配線。SBPL 側は dyld
  の mmap に `file-map-executable` が要るため `/usr/lib`・
  `/System/Library` に追加（`file-read*` だけでは dylib の executable
  mapping は許可されない）。
- **祖先コンポーネントの traversal**: deny-default では許可パス本体が
  読めても祖先を `lstat` できず、Node の `realpathSync`（モジュール
  ローダー）と CPython の getpath が `EPERM lstat '/Users'` 等で死亡。
  SBPL 生成が全許可パスの祖先へ `file-read-metadata` を付与するようにした。
- **symlink hop の readlink**: `/tmp` → `private/tmp` のように綴り側に
  symlink を含む許可パスは、canonical 形の祖先メタデータだけでは不足
  （link の readlink は `file-read-data` が要る）。ポリシー許可パスを
  `canonical_grant_path`（最深の既存祖先を canonicalize して残りを
  再接続、write 対象の未存在パスも解決）で canonical 形にして emit し、
  綴り側の祖先が symlink の場合は `file-read*` literal を出すようにした。
  `check-server.sh` の `/tmp/…` データディレクトリで実発した不具合で、
  e2e は `temp_root()` が canonicalize 済みだったため検出されていなかった。
- **`/bin/sh` の shim**: argv0 ≠ 実体パスの経路で使う `exec -a` ラッパーが
  macOS の `/bin/sh` shim 経由で `/private/var/select/sh`（→ `/bin/bash`）
  を開き EPERM ノイズを出した（非致命）。granted path に追加して許可。
- **tools-list hash のホスト依存**: `mcp-server-time` は起動時に検出した
  ローカル TZ を tool schema の description に埋め込む。サンドボックス下で
  `/etc/localtime` が読めず UTC フォールバックになり hash が不一致だった
  （旧 pin `be763b48…` は検証機の `Asia/Tokyo` 検出に依存していた）。
  `--local-timezone UTC` で pin して `sha256:194aba9e…` に更新し、
  `time.kdl`・`real_servers_e2e` の期待値を更新。併せて SBPL 基底に
  `/etc/localtime`・`/private/var/db/timezone` の読み取りを追加
  （TZ 未固定でもホストと同じ TZ を見られるようにする ambient 許可）。
- **`.sh` の実行ビット**: `check-server.sh` / `setup.sh` が `100644` で
  コミットされ Unix 直実行不可（Windows 開発では顕在化しない）。`+x` に修正。
- **`docs_check` の dangling-symlink テスト**: `tempdir()` が macOS では
  `/var/…`（非 canonical）を返し、`resolve()` の既存 prefix canonicalize
  と期待値が不一致になる latent bug。比較側を `canonicalize` して修正。

検証結果:

| 項目 | 結果 |
|---|---|
| `setup.sh` | PASS（`npm ci` 104 件・pinned pip、venv 作成） |
| 起動形分類 | Windows と同じ（`node <path>`・`__main__.py` = Source、`python -m`・`npx` = Unresolved） |
| live discovery | 4/4、`2025-11-25` 交渉、hash・ツール数一致 |
| `MCP_WRIT_REQUIRE_SERVER_TESTS=1 cargo test --locked --test real_servers_e2e` | 0 — 4/4 合格（time の段 5 は I/O 面なしで設計上 skip） |
| `check-server.sh`（filesystem 実サーバ、`/tmp` データ + `read_file` call） | 0 — 3 段 PASS、call 応答に実ファイル内容、`hash.verified`・`tool_call.allowed` 監査行を確認 |
| `check-server.ps1` | 未実施（本機に pwsh なし） |
| `cargo fmt --all -- --check` | 0 |
| `cargo clippy --locked --all-targets -- -D warnings` | 0 |
| `MCP_WRIT_REQUIRE_SERVER_TESTS=1 cargo test --locked` | 0 — 全 20 スイート計 1529 件合格 |
| `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` | 0 |
| `git diff --check` | 0 |
| `git diff --stat -- Cargo.lock` | 出力空（`Cargo.lock` 差分なし） |

macOS 追検証後も残る未検証: `mcp-servers.yml` の手動 dispatch 実行自体、
`check-server.ps1`（本機に pwsh なし）、Landlock ABI V4 の完全適用、
Windows LPAC opt-in。macOS 上の `sandbox allow_degraded` / Landlock 相当の
段 5 部分適用分岐は不要だった（sandbox-exec は常に完全適用）。

## PR3. README と公開面の訂正

対象コミット / 未コミット差分: 実施時点の HEAD =
  `97a473e0b9db72d5ac968d1a9504f55aeee9f648`（`Merge pull request #12`、PR2 まで
  コミット済み）。PR3 の変更はすべて未コミットの作業ツリー差分として残す。

変更ファイル:

- `README.md` / `README.ja.md`:
  - 先頭文を `Cargo.toml` の `description` に揃えた（英:
    "Policy enforcement, OS sandboxing, and JSON-RPC auditing for local stdio
    MCP servers"、日:「ローカル stdio MCP サーバ向けのポリシー執行、OS
    サンドボックス、JSON-RPC 監査」）。
  - 冒頭段落の直後に位置づけ文を追加。ローカル stdio サーバを対象とする
    制御面のポリシー執行点（ツール定義の固定、`tools/call` の許否、
    パス/ホスト引数の制約、起動環境の制御、監査ログ）であり、応答本文
    DLP・HTTP/SSE ゲートウェイ・LLM 判定などのデータ面検査は別レイヤーの
    直列配置を前提とすることを明記。HTTP/SSE 非対応は意図的な範囲外として
    表現を維持。
  - Features の解析対象に Python と JavaScript/TypeScript を明記し、
    その他のスクリプトは shebang とコマンド名から推定する旨を記載。
  - 「Security boundaries」を「What the guard enforces」/「What it does
    not guarantee」（日:「ガードが強制するもの」/「保証しないもの」）の
    2 一覧に再構成（各版 20 行以内）。Linux = Landlock + seccomp・許可
    ツールの filesystem はプロセス全体に統合、macOS = sandbox-exec が
    グローバル filesystem のみ・per-tool は Auditor のみ・syscall 非適用、
    Windows = AppContainer・OS ネットワークは全拒否/無制限の 2 値、
    per-tool 検査は RPC 引数の検査であり OS サンドボックスではない、
    dry-run は OS サンドボックス無しで副作用が起き得る、TOCTOU は
    対象外、DLP/HTTP-SSE/LLM 判定は別レイヤー、を列挙し
    `docs/guide.md#per-os-enforcement-matrix` へリンク。
  - Quick Start を実サーバ固定版かつ最小形に書き換え:
    `cargo install --locked --path . --bin mcp-writ`、
    `npm install -g @modelcontextprotocol/server-filesystem@2026.8.31`、
    `extends "examples/policies/filesystem.kdl"` + `read_file` のみ許可する
    最小 `policy.kdl`、`run --dry-run`（dry-run は OS サンドボックス無しの
    ため `defaults` 不要、実機で応答確認済み）。詳細手順は新設の
    `docs/quickstart.md` / `docs/quickstart.ja.md` へ移動（runbook は
    check-server までを README に載せる想定だったが、簡潔化の指示に
    従いウォークスルーへ分離）。
- `docs/quickstart.md` / `docs/quickstart.ja.md`（新設）: README から
  移した詳細手順 — ホスト固有 `defaults` 付きの完全な `policy.kdl`、
  `generate-policy --live-discovery`（shim 裸名は `Error reading binary`
  で失敗する旨を明記）、dry-run、`check-server.sh`（Windows は
  `check-server.ps1` + `--preserve-symlinks-main --preserve-symlinks` +
  `win-realpath-stub.cjs` プリロードの `node <dist/index.js>` 起動形）、
  期待される監査イベント、Landlock ABI V1 の部分適用注意。
  - 「Client configuration」節を追加。Claude Desktop / Cursor は
    `mcpServers.<name>.{command,args,env}`、VS Code は `servers.<name>`
    （差は 1 行で言及）。`env` は既定で子に継承される旨 1 文を記載。
- `docs/policy-authoring.md` / `docs/policy-authoring.ja.md`: 既定
  deny → 実サーバで拒否応答を読む → 確認済み節だけ足す → 再ピン、の流れに
  再構成。dry-run（転送 + `observed`）と通常起動（遮断 + `denied`）の
  違い、検証チェックリスト、`MCP_WRIT_SKIP_SANDBOX=1` /
  `allow_degraded=#true` は通常保護の証拠にならない旨を明記。
  既存アンカー id（`#editing` `#linux-read-only` `#recipes` `#write-output`
  `#windows-files` `#api-access` `#pathless` `#verification`
  `#troubleshooting` の 9 件）はすべて維持。
- `docs/stdio-hardening-runbook.ja.md` / `docs/stdio-hardening-plan.ja.md`:
  見出し変更で失われた旧アンカー参照を現行アンカーへ修正
  （`#3-edit-runtime-permissions-and-tool-permissions` → `#editing` /
  `#linux-read-only`、`#5-verify-through-an-mcp-client` → `#verification`）。
- `docs/stdio-hardening-results.ja.md`（本節）。
- `.gitignore`: クイックスタートで生成するホスト固有ポリシー
  `/policy.kdl` を ignore に追加（後述のレビュー指摘対応で実追加。
  実行時に使った作業用 `policy.kdl` はホスト絶対パスを含むため削除。
  証拠は `.local/stdio-hardening/pr3/`）。
- レビュー指摘対応（PR3 範囲の追加修正。いずれも未コミット差分）:
  - `docs/quickstart.md` / `docs/quickstart.ja.md`: 手順 3 を実装どおりに
    修正。`generate-policy --live-discovery` は既存ポリシーを読まず、
    検出した `tools-list-hash` を含む独立草案を出力するのみであり、
    ピン値との照合は `run` が `hash.verified` を記録する手順 5 が担う。
    `policy.draft.kdl` をピン値との比較材料とする旨を明記。
    `list_allowed_directories` はパスを取らず上書きなしでも拒否されない
    ため、fail-closed の記述をパスを取るツールに限定。手順 5 に Landlock
    ABI V1 のみのカーネルで `sandbox allow_degraded=#true` が必要になる
    注意（「Caveats」/「注意点」節）への相互参照を追加。
  - `README.md` / `README.ja.md`: 「everything else is denied」/
    「それ以外は拒否」を、パスを取る他ツールへの拒否に限定した表現へ修正
    （`list_allowed_directories` の呼び出しは拒否されない）。
  - `examples/policies/filesystem.kdl`: コメント内の旧節名参照を
    「Add only the confirmed clauses」（`#editing`）へ更新。
  - `docs/README.md`: 索引に quickstart の行を追加。
  - `Cargo.toml`: `description` を README 先頭文と一致させた
    （"…for local stdio MCP servers"）。
  - 本節: 維持したアンカー id の列挙を実在する 9 件へ修正
    （`#drafting` `#platforms` `#shims` `#native-linux` は旧版にも
    存在しない）。

`docs/guide.md` / `docs/guide.ja.md` / `docs/modules.md` は公開面の修正が
不要と判断し未変更。

実サーバのクイックスタート実行（証拠は `.local/stdio-hardening/pr3/`）:

- 固定サーバ: `@modelcontextprotocol/server-filesystem@2026.8.31`、
  交渉 `2025-11-25`、14 ツール、
  `tools-list-hash "sha256:1ef36fd736d82bacdbb5bce1dda540553a2b59e07c625249845296845a335a26"`。
- Windows（Windows 11 26200.9457、x86-64、Node v24.11.1）:
  - `generate-policy` に npm shim の裸名を渡すと
    `Error reading binary 'mcp-server-filesystem': No such file or directory`
    （PATH 解決せずリテラルパスを読む）。`node <dist/index.js>` 形で
    live discovery 成功（14 ツール、上記ハッシュ）。
  - dry-run: initialize / tools/list / 許可パスの `read_file` 成功、
    `.ssh/id_rsa` 相当パスは転送され監査 `tool_call.denied`（`observed`）。
  - 通常起動（AppContainer）: `hash.verified`、marker ファイル
    `tool_call.allowed`、シークレットパスは JSON-RPC 拒否
    `tool_call.denied`。`tools/list` 再検証中の早期 call は
    fail-secure で拒否されることを確認。
  - `check-server.ps1`（powershell.exe 相互運用、stub + preserve-symlinks
    起動形）: 3 段すべて PASS。
  - README 掲載の最小ポリシー（`extends` + `read_file` のみ、`defaults`
    無し）で dry-run を実行: initialize / marker 許可 / `.ssh` パスは
    `observed` 拒否を確認。
  - `cargo install --locked --path . --bin mcp-writ`（msvc）: 成功
    （release 30.85s）。
- WSL2（Ubuntu 24.04、kernel 5.15.167.4、Landlock ABI V1、Node v24.11.1）:
  - `generate-policy` は shim 絶対パスでも `/usr/bin/env node` の解決に
    PATH 上の node が必要。`~/.local/node/bin` を PATH に追加して
    live discovery 成功（同一ハッシュ）。
  - dry-run: 許可パス allowed、シークレットパス `observed`。
  - 通常起動: ABI V1 のみのため seccomp/Landlock が `PartiallyEnforced`
    となり fail-closed で spawn `EACCES`。`sandbox allow_degraded=#true`
    を付けて起動成功（部分適用であることを記録）。
  - `check-server.sh`: 3 段 PASS。
  - `cargo install`（gnu/musl）: `cc` リンカ不在で失敗。Windows 側で
    代替実施済み。
- クライアント設定 JSON: 2026-09-21 に各ベンダ現行ドキュメントと照合
  （Claude Desktop `claude_desktop_config.json` と Cursor `.cursor/mcp.json`
  は `mcpServers`、VS Code `.vscode/mcp.json` は `servers`）。一致確認済み。

検証結果:

| 項目 | 結果 |
|---|---|
| `cargo fmt --all -- --check` | 0 |
| `cargo clippy --locked --all-targets -- -D warnings` | 0 |
| `cargo test --locked --test docs_check` | 初回 FAIL（上記 5 件の旧アンカー参照）→ 参照元修正後 11/11 PASS。レビュー指摘対応後の再実行も 11/11 PASS |
| `MCP_WRIT_REQUIRE_SERVER_TESTS=1 cargo test --locked` | 中断。lib 1322 件と docs_check までの複数スイートは合格、修正後の全量再実行はユーザー指示により中止 |
| `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` | 未実施（同上） |
| `git diff --check` | 0 |
| `git diff --stat -- Cargo.lock` | 出力空（`Cargo.lock` 差分なし） |

残る未検証 / 制約: macOS 実機でのクイックスタート実行（macOS ホスト無し）、
Windows LPAC opt-in、Landlock ABI V4 の完全適用、修正後 `cargo test` 全量と
`cargo doc`。`v*` タグは存在しないためリリース配布物リンクは未掲載。
Git の stage / commit / push は一切実施していない。

## PR4. tools/list の allowlist フィルタ

対象コミット / 未コミット差分: 実施時点の HEAD =
  `35e5fe9c5d83732e52036374baa505978abaa0d5`（`Merge pull request #13`、PR3 まで
  コミット済み）。PR4 の変更はすべて未コミットの作業ツリー差分として残す。

変更ファイル:

- `src/auditor/checker.rs`:
  - 「`policy.tools` に同名があり `allowed` が真」の述語を
    `pub fn tool_is_allowed(policy: &Policy, name: &str) -> bool` として
    切り出し、`check_request` はこの関数を呼ぶ形に変更。`tools/call` の
    許否と `tools/list` の可視性が同一述語で駆動されることを docstring に
    明記。エラーメッセージ（`tool is not allowed` /
    `tool not found in policy (default deny)`）は従来どおり。
- `src/auditor/audit_log.rs`:
  - `EventType::ToolsListFiltered` を追加。`as_str` は
    `tools_list.filtered`、`category` は `policy_enforcement`。
    `test_event_type_as_str` / `test_event_type_category` に対応する
    アサーションを追加。
- `src/auditor/proxy_tools_list.rs`:
  - `verify_and_emit_list` の順序契約を docstring に明記: マニフェスト
    スキャン・`verify_tools_list`・`hash_tools_list`・
    `record_verified_digest` は全件の `tools_to_verify` に対して実行し、
    allowlist フィルタはその後のクライアント向け応答のみに適用する。
  - `record_verified_digest` の直後で `tools_to_verify` を
    `visible` / `hidden` に分割（`checker::tool_is_allowed`）。
    `hidden` が 1 件以上のとき 1 イベントの `tools_list.filtered` を
    記録（`Severity::Info`、`Outcome::Failure`、`details` に隠したツール名を
    列挙、`target_server` は `scan_server`、`request_id` は
    `client_facing_id` の値）。`action` は通常運用で `Denied`、dry-run で
    `Observed`。
  - dry-run ではフィルタせず全件を転送。通常運用は `visible` のみを
    `build_verified_tools_list_response` に渡す。
- `tests/fixtures/mcp_servers/scripted_stdio.py`:
  - `list_changed_ok` の再リスト（`list_count >= 1`）が `call_tools()`
    の 3 ツールセットを返すように変更（再検証後の emit 経路でフィルタが
    実際に働くことを検証するため）。初回リストの内容・0.4s 遅延・
    通知送出のタイミングは不変。既存テスト
    `list_changed_revalidates_then_forwards_and_denies_mid_relist_call`
    （BASE_POLICY: read_file + fetch_url 許可）は全アサーション合格を
    維持。
- `tests/tool_enforcement_e2e.rs`:
  - `spawn_guard_with` を `spawn_guard_at`（監査ログパス指定版）への
    委譲に変更（既存呼び出しは不変）。
  - 新規テスト 5 件（全て pass。Linux / Windows 両環境で確認）:
    - `tools_list_hides_denied_and_unlisted_tools`: `tools_call_ok` の
      3 ツール広告に対し `read_file` のみ返却（`fetch_url` deny・
      `fail_write` 未記載は非表示）。応答に両者の名前が出ないことも確認。
    - `tools_list_dry_run_keeps_all_tools_and_observes`: dry-run は 3 件
      全転送 + `tools_list.filtered` が `action:"observed"` で 1 件だけ
      記録（`fail_write, fetch_url` を列挙）。
    - `tools_list_hash_pins_full_advertised_set_not_filtered_view`:
      fixture を直接起動して得た広告セットのハッシュを計算し
      `tools-list-hash` に pin → 検証通過かつ応答は 1 件のみ。
      逆にフィルタ後の 1 件ハッシュを pin したポリシーは検証失敗
      （fail-closed JSON-RPC エラー）。ハッシュ pin が全件対象であることを
      負のテストで固定。
    - `list_changed_relist_is_filtered`: `list_changed` → 内部再リスト
      （3 ツール広告）→ 通知転送後の `tools/list` も `read_file` 1 件のみ。
    - `tools_list_empty_when_policy_has_no_tools`: ツールを 1 つも書かない
      ポリシーで `tools/list` が正常応答 `{"result":{"tools":[]}}` を返す
      （エラーではない）。
- `tests/real_servers_e2e.rs`:
  - `example_tool_names`（`examples/policies/<name>.kdl` の `tool "…"`
    行を抽出）と `response_tool_names`（応答の `result.tools` 名抽出）を
    追加。
  - 新規テスト `real_filesystem_server_lists_only_allowed_tools`:
    `examples/policies/filesystem.kdl` を extends し `move_file` のみ
    `deny=#true` で上書きしたホストポリシーで実 filesystem サーバを起動。
    `tools/list` 応答のツール名集合が「例の allowlist 14 件 − move_file」に
    一致すること、ピン留めハッシュが全件広告セットで検証成功すること、
    `tools_list.filtered`（`denied`、`details` に `move_file`）が記録される
    ことを確認。
- ドキュメント（日英で同じ内容）:
  - `docs/guide.md` / `docs/guide.ja.md`:
    - 攻撃シナリオ表「不正なツール呼び出し」に `tools/list` からの非表示を
      追記。
    - フェイルセキュア原則に「`tools/list` 応答はポリシー許可ツールのみ、
      検証ハッシュは引き続き全件対象」の不変条件を追加。
    - dry-run FAQ に「`tools/list` は dry-run でフィルタされず全件転送、
      隠されるはずのツールは `tools_list.filtered` / `observed` で記録」
      を追加。
    - 「Audit log schema」（日:「監査ログスキーマ」）節を新設。JSONL の
      全フィールド、`event_type` / `event_category` / `severity` /
      `action` / `outcome` の値一覧を `audit_log.rs` の `as_str` から写して
      掲載。拒否要求のクライアント側 `id` が `request_id` にそのまま保持
      されること（文字列 id は引用符付き、内部 id は echo しない）、
      他ツールが接合する契約であり値の変更は移行ガイドに書く旨を明記。
      `tools_list.filtered` も一覧に掲載。
  - `docs/policy-authoring.md` / `docs/policy-authoring.ja.md`:
    通常起動で確認することの表に `tools/list` 行（許可ツールのみ一覧化）を
    追加し、許可を広げた後はクライアントに `tools/list` の再取得が必要な
    旨を追記。
  - `README.md` / `README.ja.md`: Features の Tool access controls に
    `tools/list` からの非表示を追記。
  - `docs/modules.md`: invariants に「scan/hash/digest は全件対象、
    フィルタは検証済み出力のみ、dry-run はフィルタしない」を追加。

### 実機確認（PR4）

- モック（`scripted_stdio.py`、WSL2、`MCP_WRIT_SKIP_SANDBOX=1`、
  ポリシー `.local/stdio-hardening/tools-list-filter-policy.kdl` =
  read_file 許可 / fetch_url deny / fail_write 未記載）:
  - 通常運用: `tools/list` 応答は `read_file` 1 件のみ
    （`tools-list-filter.stdout.txt`）。
  - 監査 1 件: `event_type:"tools_list.filtered"`、`severity:"info"`、
    `action:"denied"`、`details:"tools hidden from the client:
    fail_write, fetch_url"`、`request_id:"1"`（クライアント側 id 保持）。
  - dry-run: 3 件全転送 + `tools_list.filtered` は `action:"observed"`。
- 実 filesystem サーバ（`@modelcontextprotocol/server-filesystem`
  2026.8.31、WSL2 Node v24.11.1、pin 済み `filesystem.kdl` + `move_file`
  deny 上書き、`MCP_WRIT_SKIP_SANDBOX=1`）:
  - `tools/list` 応答は 13 件（`move_file` のみ非表示）:
    read_file / read_text_file / read_media_file / read_multiple_files /
    write_file / edit_file / create_directory / list_directory /
    list_directory_with_sizes / directory_tree / search_files /
    get_file_info / list_allowed_directories。
  - 監査: `hash.verified`（`allowed`、ピンは全件広告セットで検証成功）+
    `tools_list.filtered`（`denied`、`details` に `move_file`、
    `target_server:"filesystem"`、`request_id:"2"`）。
- 実サーバ e2e（Windows 11、`MCP_WRIT_REQUIRE_SERVER_TESTS=1`）:
  `real_filesystem_server_lists_only_allowed_tools` を含む
  `real_servers_e2e` 5/5 PASS。

### 検証コマンドと終了コード（PR4 共通チェック）

| 項目 | 結果 |
|---|---|
| `cargo fmt --all -- --check` | 0 |
| `cargo clippy --locked --all-targets -- -D warnings` | 0 |
| `cargo test --locked`（WSL2） | 全スイート PASS（lib 1330 件を含む 1534 件、0 失敗） |
| `MCP_WRIT_REQUIRE_E2E_TESTS=1 cargo test --locked`（WSL2） | PASS |
| `MCP_WRIT_REQUIRE_SERVER_TESTS=1 cargo test --locked`（Windows） | `real_servers_e2e` 5/5 PASS を含む全スイート PASS |
| `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` | 0 |
| `git diff --check` | 0 |
| `git diff --stat -- Cargo.lock` | 出力空（`Cargo.lock` 差分なし） |

### 次へ進む条件の確認（PR4）

- 通常運用で未許可ツールが `tools/list` から消える: mock・実サーバともに
  確認済み。
- dry-run では全件が残り `observed` イベントが記録される: 確認済み。
- ハッシュ pin が全件で計算されることが負のテストで固定されている:
  `tools_list_hash_pins_full_advertised_set_not_filtered_view` で固定済み。
- 現物（実 filesystem サーバ）でも確認済み。
- 文書が日英で揃っている: `docs_check` PASS を含め更新済み。

### レビュー指摘対応（PR4 差分レビュー後の修正）

コードレビューで検出された指摘（いずれも非ブロッキング）への対応:

- dry-run の `details` 文言: 全件が実際に転送される dry-run では
  `"tools that would be hidden from the client: …"` と記録するように分岐。
  通常運用は従来どおり `"tools hidden from the client: …"`。
- `target_server` のフォールバック: `tools-list-hash` が無いポリシーでも、
  `declared_servers()` が一意のサーバ識別を返す場合（bind 済みポリシー）は
  その名前を `scan_server` / `event.target_server` に記録する。
  `"default"` フォールバックは監査ログには書かない。
- 監査 API の `Option` 化（追加指摘対応）: `log_manifest_scan` /
  `log_manifest_scan_for` は `Option<&str>` を取り、サーバ未解決時は
  `manifest.finding` の `target_server` を `null`（欠落）として記録する。
  合成名 `"default"` は audit API に到達しない（`verify_tools_list` の
  unpinned 経路は `NoEntry` で早期リターンするため監査イベントを持たず、
  そこに渡す `"default"` はベースライン名空間と tracing のみに留まる）。
- 内部再リストの重複イベント抑止: `record_verified_digest` が digest の
  変更有無を返すようにし、`list_changed` 再検証で digest が不変
  （= 広告セットが同一 = 隠す集合も同一）の場合は `tools_list.filtered` を
  再記録しない。digest が変わる再リストでは従来どおり記録する。
  クライアント起因の一覧は要求ごとに記録する契約を維持。
- `Outcome::Failure` の意味付け: 「要求された一覧全体の表示が拒否された」
  という `tool_call.denied` と同一の規約である旨をコードコメントと
  `guide.md` / `guide.ja.md` の監査スキーマ節に明記。動作変更なし。
- 追加テスト（`proxy_tools_list.rs`、全て pass）:
  `identical_revalidation_does_not_repeat_filtered_event`（同一 digest の
  再リストでは再記録しない）、`changed_revalidation_logs_filtered_event`
  （変化した再リストでは記録する）、
  `dry_run_filtered_event_reports_would_be_hidden_and_declared_server`
  （dry-run の文言と `target_server` フォールバック）、
  `filtered_event_without_declared_server_has_no_target`（サーバ無し →
  `target_server` null）、
  `filtered_event_with_multiple_declared_servers_has_no_target`（複数宣言は
  曖昧 → null）、`verifier::manifest` の
  `unresolved_server_records_no_target_server`（`None` → null、
  `"default"` 非出力）。

## PR5. 起動対象ハッシュの文書化と草案出力

対象コミット / 未コミット差分: 実施時点の HEAD =
  `8eddfeb15cb151909496aed7699bfc75fc98bf72`（`Merge pull request #14`、PR4 まで
  コミット済み）だった。その後 PR5 の変更は `0c2be30`
  （`docs: Document launch-target hash verification, add binary-hash/entrypoint-hash
  to policy schema, and expand draft generation with workload binding`）として
  `stdio-hardening-PR5` ブランチにコミット済み。差分レビュー指摘への対応分は
  作業ツリー差分として残す（後述「レビュー指摘対応」各節）。

変更ファイル:

- `src/legislator/source_bind.rs`:
  - `HashLine`（`target` + `hash_value`）と `WorkloadHashes`
    （`binary` / `entrypoint` / `unbound_reason`）を追加。
  - `workload_hashes(argv, discovery)` を追加。`argv[0]` を PATH 解決して
    `binary-hash` を計算し、`PayloadDiscovery` が実体のあるソースファイルを
    指す場合は `entrypoint-hash` も計算する。束縛できない形式
    （`python -m` 等のモジュール実行、inline eval の `-c` / `-e` /
    `--eval` / `--command`、未解決ペイロード）ではハッシュを捏造せず
    `unbound_reason` に理由を記録する。
  - `discover_from_argv` に `-m` フラグの明示検出を追加。モジュール名が
    たまたま cwd の実ファイルと同名でも誤って `entrypoint-hash` を pin
    しない（理由文も `-m` 由来であることを明示）。
  - 草案に書く `target=` は canonicalize 済みの絶対パスで、Windows の
    `\\?\` verbatim プレフィックスは可読性のため除去（Verifier 側の
    `same_file` も canonicalize して比較するため同一オブジェクトを指す）。
- `src/legislator/policy_generator.rs`:
  - `generate_policy` が `&WorkloadHashes` を受け取るシグネチャに変更。
  - `server` ブロック内に `binary-hash "<sha256>" target="<path>"` /
    `entrypoint-hash "<sha256>" target="<path>"` を出力する
    `emit_workload_hashes` を追加。
  - ハッシュがこのホストの実ファイルを pin する旨・デプロイ先ホストでの
    再計算・サーバ / インタプリタ更新時の再生成・unbound 理由を
    `// REVIEW:` コメントとして草案に出力。
  - ユニットテスト追加: ネイティブの binary-hash 出力、ソース payload の
    entrypoint-hash 出力、生成草案の `load_kdl_policy` parse および
    `HashEntry` 化、unbound 理由コメント出力。
- `src/commands/generate_policy.rs`:
  - `discover_from_argv(&args.command)` の結果から
    `workload_hashes` を計算し `generate_policy` へ渡す。
- `tests/workload_hash_e2e.rs`（新規、3 件・Windows / Linux 両方で pass）:
  - `native_binary_hash_binds_and_tamper_fails`: 生成草案でネイティブ
    サーバを起動 → `initialize` 成功。バイナリ改竄後は
    `Supply chain verification failed` で起動拒否。
  - `interpreted_entrypoint_hash_binds_and_tamper_fails`: インタプリタの
    binary-hash + ソースの entrypoint-hash が bind され、ソース改竄で
    起動拒否。
  - `module_and_inline_eval_emit_reason_not_fabricated_hash`: `python -m` /
    `python -c` で `entrypoint-hash` を出さず `// REVIEW:` 理由コメント
    のみ出力。binary-hash がある草案で inline eval を起動すると実行時にも
    サプライチェーン拒否されることを確認。
- `tests/real_servers_e2e.rs`:
  - stage1 で生成草案を `load_kdl_policy` し、workload hash エントリが
    実際の起動対象（実行ファイル / ソースファイル）と一致することを確認
    （Node・Python の実サーバフィクスチャで検証）。
- `tests/inspector_arm64_p4.rs` / `inspector_arm64_p5.rs` /
  `inspector_macho_p6.rs`: `generate_policy` 呼び出しを新シグネチャ
  （`&WorkloadHashes::default()`）に追従。
- ドキュメント（日英で同じ内容）:
  - `docs/guide.md` / `docs/guide.ja.md`: 起動対象ハッシュ検証の説明、
    Field Reference への `binary-hash` / `entrypoint-hash` 行追加、
    `generate-policy` 草案が起動対象ハッシュを出す旨と束縛不能な起動形の
    扱いを追記。
  - `docs/policy-authoring.md` / `docs/policy-authoring.ja.md`:
    草案に含まれるハッシュがホスト依存であること・デプロイ先での再計算・
    束縛不能形式では理由コメントになることを追記。
  - `README.md` / `README.ja.md`: 機能一覧に起動対象ハッシュ pin を追記。
  - `policy.example.kdl`: `binary-hash` / `entrypoint-hash` の記述例を追加。

### 実機確認（PR5）

- Windows 11:
  - `mcp-writ generate-policy -- py -3 tests/fixtures/mcp_servers/scripted_stdio.py`
    → `binary-hash` = `C:\Users\...\Python\Launcher\py.exe` の sha256、
    `entrypoint-hash` = `D:\...\scripted_stdio.py` の sha256。
  - `py -3 some_uninstalled_module_xyz`（モジュール名が実ファイルでない）
    → `binary-hash` のみ + `// REVIEW: entrypoint-hash not emitted: ...`。
  - `node -e ...` → `binary-hash` + inline eval はハッシュ束縛不可の
    `// REVIEW:` コメント。
  - 生成草案は `load_kdl_policy` で parse 可能、ハッシュ値は
    `sha256:<64 桁小文字 hex>` 形式。

### 検証コマンドと終了コード（PR5 共通チェック）

| 項目 | 結果 |
|---|---|
| `cargo fmt --all -- --check` | 0（Windows / Linux とも） |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | 0（Windows） |
| `cargo test --locked --lib`（Windows） | 1333 件全件 PASS |
| `cargo test --locked --test workload_hash_e2e` | 3/3 PASS（Windows / Linux とも） |
| `MCP_WRIT_REQUIRE_SERVER_TESTS=1 cargo test --locked --test real_servers_e2e`（Windows） | 5/5 PASS |
| `cargo test --locked` 全スイート（Windows） | PASS（`docs_check` 含む） |
| `cargo check` / `cargo test`（Linux、WSL2 検証コピー） | PASS（`~/.local/bin` の zig cc を PATH に追加してリンカ確保） |
| `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` | 0 |
| `git diff --check` | 0 |
| `git diff --stat -- Cargo.lock` | 出力空（`Cargo.lock` 差分なし） |

### Linux での既知の環境依存失敗（PR5 の変更とは無関係）

- `MCP_WRIT_REQUIRE_E2E_TESTS=1` 下の
  `path_resolution_e2e::sandboxed_os_boundary_and_process_shared_access` が
  `Process spawn failed: Permission denied (os error 13)` で失敗する。
- 切り分けの結果、原因は fail-closed 設計そのもの: カーネル 5.15
  （Landlock ABI V1 のみ）で `create_landlock_ruleset` が要求する
  V2/V3/V4 の `handled_access` が landlock crate の `CompatState` を
  `Partial` にし、`restrict_self_fail_closed` が `PartiallyEnforced` を
  検出して EACCES を返す。`/usr/bin/cat` のサンドボックス起動でも同様に
  失敗することを確認（フィクスチャ・PR5 変更とも無関係）。
- 生 syscall プローブで、V1 ruleset の作成・`restrict_self` 強制・許可
  パスへの execve・未許可パス（`/dev/null`）の拒否がすべて正常に動作する
  ことを確認 = カーネルの Landlock 実装自体は健全。
- REQUIRE フラグなしでは同テストは内部で skip して `ok` となる。PR5 の
  `workload_hash_e2e` が Linux で pass するのは `generate-policy` が
  kernel <6.7 では草案に `sandbox allow_degraded=#true` を出すためで、
  本テストの手書きポリシーには `allow_degraded` が無い。
- 本制約は既存記録の「WSL2 カーネル 5.15 = Landlock ABI V1 の部分適用」
  と整合しており、PR5 の変更範囲外（`src/warden/`、`src/runtime/launch.rs`
  に差分なし）。

### 次へ進む条件の確認（PR5）

- `generate-policy` が実際の起動対象を特定し `binary-hash` を出力:
  確認済み。
- 解釈系で実体ソースファイルがある場合 `entrypoint-hash` を出力:
  確認済み。
- 束縛不能な起動形（`python -m` / `npx` / inline eval / 未解決
  ペイロード）でハッシュを捏造せず理由コメントを出力: 確認済み。
- 生成草案が parse 可能でランタイム検証と整合（verify → bind → reverify
  → spawn の順序を維持、`launch.rs` 無変更）: 確認済み。
- ネイティブ / 解釈系の両経路が e2e で固定: 確認済み。
- 実 MCP サーバの草案でハッシュが起動対象と一致: `real_servers_e2e`
  stage1 で確認済み。
- 日英文書が揃っている: `docs_check` PASS を含め確認済み。

### レビュー指摘対応（PR5 差分レビュー後の修正）

指摘: `resolve_command_path` 周辺で、`env` や `py.exe` のような委譲型
ランチャーが選択するインタプリタ / ペイロードまで解決を追い、ランチャー
バイナリだけを完全束縛済みとして扱わないこと。委譲を解決できない場合は
`unbound_reason` を設定し、完全束縛ポリシーの生成を防ぐこと。

検証した結果、指摘は有効:

- `env FOO=1 python3 server.py` は従来 `binary-hash` が `/usr/bin/env`
  のみを pin し、内部コマンドは完全に未束縛なのに草案上「束縛済み」に
  見えた。ランタイム契約上 `binary-hash` は spawn される `argv[0]` 自身と
  一致必須、`entrypoint-hash` は実行ファイルまたは `first_payload_arg`
  （この argv では `FOO=1`）との一致必須のため、内部コマンドの pin は
  現在のハッシュモデルでは表現不能 → 理由コメントが唯一の正しい出力。
- `py -3 server.py` は `binary-hash`=py.exe + `entrypoint-hash`=スクリプト
  で正しく pin されるが、py が実行時に選択する `python.exe` 自体は
  pin されないギャップが黙っていた。
- 加えて `resolve_generate_capability` の Native 分岐が `argv[0]` を
  リテラルパスで読んでおり、裸のコマンド名（`env` 等）は PATH 解決前に
  `Error reading binary` で失敗していた（本指摘とは別の既存バグ）。

修正（`src/legislator/source_bind.rs` / `src/commands/generate_policy.rs` /
`src/legislator/policy_generator.rs`）:

- `delegating_launcher_reason(argv0)` を追加し `env` / `py` / `pyw` /
  `npx` を検出。`workload_hashes` が `unbound_reasons` に理由を積む:
  - `env`: 「ランチャーの pin のみで内部コマンドは未束縛。内部 argv で
    generate-policy を再実行せよ」
  - `py` / `pyw`: 「py が実行時に選択するインタプリタ実行ファイルは
    未 pin。インタプリタを直接起動して束縛せよ」
  - `npx`: 「実行時に解決されるパッケージと node 実行ファイルは未 pin」
- `WorkloadHashes.unbound_reason: Option<String>` を
  `unbound_reasons: Vec<String>` に変更し、理由ごとに独立した
  `// REVIEW:` 行を出力（複数理由の `"; "` 連結で 1 行に潰れる問題も解消）。
- `resolve_generate_capability` の Native 分岐で `argv[0]` を
  `resolve_command_path` 経由で PATH 解決（`--binary-path` 指定時は従来
  どおり）。裸コマンド名で解析対象と pin 対象が同一ファイルになる。
- 内部コマンドへの「解決の追従」は意図的に行わない: ハッシュモデル上
  pin を表現できないため、emit すると実行時 bind が必ず拒否する草案に
  なってしまう。代わりに理由で誘導する。

テスト追加 / 更新:

- `source_bind` ユニット: `delegating_launchers_are_flagged`（env/py/pyw/
  npx の検出と python/node/スクリプトの非検出）、
  `env_launcher_marks_workload_not_fully_bound`（理由が出て entrypoint が
  出ないこと）。
- `workload_hash_e2e`: `module_and_inline_eval_emit_reason_not_fabricated_hash`
  に委譲ランチャーブロックを追加（Windows は `py -3`、Linux は
  `env FOO=1 python3` で草案が caveat を含むことを確認）。
- `policy_generator` ユニットの `unbound_reason` 使用箇所を `Vec` 化に追従。

検証（修正後）:

| 項目 | 結果 |
|---|---|
| `cargo fmt --all -- --check` | 0（Windows / Linux） |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | 0（Windows） |
| `cargo test --locked --lib`（Windows） | 1335 件全件 PASS |
| `cargo test --locked --test workload_hash_e2e` | 3/3 PASS（Windows / Linux） |
| `MCP_WRIT_REQUIRE_SERVER_TESTS=1 cargo test --locked --test real_servers_e2e`（Windows） | 5/5 PASS |
| 実機 `generate-policy -- env FOO=1 python3 server.py`（Linux） | `binary-hash`=/usr/bin/env + REVIEW（内部コマンド未束縛） |
| 実機 `generate-policy -- py -3 scripted_stdio.py`（Windows） | binary + entrypoint + REVIEW（選択インタプリタ未 pin） |

追加の指摘対応（同セッション、2 件）:

- 実行ファイル名の `.exe` 除去が大小文字混在（`.ExE` 等）を取りこぼす
  → `delegating_launcher_reason` と `interpreter_from_command` の正規化を
  「小文字化 → `.exe` 除去」の順に統一。`PY.eXe` / `Node.ExE` /
  `Env.ExE` も正しく検出されることをユニットテストで固定。
- ソースペイロードの shebang 検査: 直接実行形（`argv[0]` がペイロード
  自身、例 `./server.py`）で shebang が `env` 委譲
  （`#!/usr/bin/env python3` 等、`/bin/env`・`#!env` も含む）の場合、
  PATH 経由で選択されるインタプリタは pin されない旨の
  `unbound_reasons` を追加。`python3 server.py` のようなインタプリタ
  直接指定では shebang は不活性（pin 済みインタプリタが使われる）ため
  caveat を出さない — `argv[0] == ペイロードパス` の場合に限定して
  誤検知を防いだ。
- 実機確認（Linux）: `generate-policy -- /tmp/envsrv.py`
  （`#!/usr/bin/env python3`）→ binary + entrypoint がスクリプトを pin
  + REVIEW「env shebang は PATH 経由のインタプリタ選択で未 pin」。
  `generate-policy -- python3 /tmp/envsrv.py` → caveat なし（両要素 pin）。
- 検証: fmt / clippy `-D warnings` / lib 1336 件 / workload_hash_e2e 3/3
  （Windows・Linux ともに PASS）。

### レビュー指摘対応（`0c2be30` 後の差分レビュー修正）

`stdio-hardening-PR5` ブランチの差分レビューで検出された全指摘への対応。
いずれも作業ツリー差分として残す。

- **README の fail-closed 記述を実装に合わせて訂正**: 「`python -m`・`npx`・
  inline eval は fail-closed」としていたが、実行時に拒否されるのは
  inline eval と非束縛ターゲットのみで、`python -m` / `npx` の binary-hash
  のみの草案はそのまま起動する（ペイロード未束縛のまま）。guide と同じ
  「argv から束縛できないペイロードは pin されず REVIEW コメントで記録」
  という表現に修正（`README.md` / `README.ja.md`）。
- **値を取るオプションのオペランドが entrypoint として pin される問題を
  修正**: `first_payload_arg_index`（`src/verifier/hash.rs`）は `-` 始まりを
  すべて値を取らないフラグとして読み飛ばしていたため、
  `node --require stub.cjs index.js` は `stub.cjs` を、`python -W ignore
  server.py` は `ignore` を pin していた（`real_servers_e2e` の Windows
  node argv でも `--require` の stub が pin されていた）。
  `flag_consumes_operand` テーブル（CPython の `-W` / `-X` /
  `--check-hash-based-pycs`、Node の `--require` / `-r` / `--loader` /
  `--import` / `--input-type` / `-C` / `--conditions` 等）を追加し、
  オペランドを読み飛ばす。`--flag=value` / `-Wignore` の接置形は
  オペランド内蔵のため 1 トークンのみスキップ。`-m` と inline eval 系
  フラグは意図的に対象外（それらのオペランド以降はペイロード自身の引数）。
  ランタイムと草案生成が同じ `first_payload_arg` を使うため束縛契約は
  一致を維持する。一覧にない値を取るオプションの残存ギャップは guide
  （日英）に既知制限として記載。`real_servers_e2e` の stage1 で
  entrypoint-hash のターゲットが `dist/index.js` と正規化一致することを
  明示的に固定した。
- **inline eval の理由出力をインタプリタ非依存化**: `workload_hashes`
  は `PayloadKind::InlineEval` のときのみ理由を出していたが、
  `InlineEval` は `interpreter_from_command` が argv0 を認識した場合にしか
  立たず、`sh -c` / `perl -e` / `ruby -e` は理由なしに binary-hash のみの
  草案になっていた（実行時には必ず拒否されるため fail-visible 違反）。
  `argv_contains_inline_eval(argv)` を discovery kind と独立にチェックし、
  理由を `unbound_reasons` に積むようにした。
- **直接実行スクリプトの shebang 検出を拡張**: `discover_from_argv` で
  argv0 の拡張子判定に失敗した場合、`resolve_command_path` で解決した
  実体の shebang を読むようにした（拡張子なしの PATH インストール型
  エントリスクリプト、例 `mcp-server-git` 対応）。env shebang の caveat は
  `argv[0] == ペイロード` 一致から「argv0 の解決結果がペイロードと同一
  ファイル」判定（`direct_script_exec`）に一般化し、PATH 解決された裸名
  起動でも出るようにした。さらに固定 shebang（`#!/usr/bin/python3` 等）の
  直接実行でも、カーネルが選択するインタプリタ実体は pin されない旨の
  caveat を出すようにした（`env_shebang` → `shebang_line` リファクタ）。
- **委譲ランチャー一覧を拡張**: `delegating_launcher_reason` に exec 系
  ラッパー（`nice` / `nohup` / `timeout` / `gtimeout` / `setsid` /
  `stdbuf` / `chrt` / `taskset` / `ionice` / `sudo` / `doas`）、パッケージ
  ランナー（`bunx` / `uvx` / `pipx` / `pnpx`）、サブコマンド選択型
  （`uv` / `poetry` / `pipenv` / `pdm` / `hatch` / `conda` / `npm` /
  `pnpm` / `yarn` / `deno` / `bun` / `docker` / `podman`）を追加。
- **`workload_hash_e2e` のインタプリタ不在時 skip**: `interpreted_*` と
  `module_and_inline_eval_*` は `py` / `python3` 不在環境で binary-hash
  非出力により assert 失敗していた。`interpreter_or_skip` ヘルパで
  `resolve_command_path` による事前確認 + `common::skip_e2e_test` に変更
  （`MCP_WRIT_REQUIRE_E2E_TESTS=1` では失敗扱いのまま）。
- **本書の記述修正**: 「PR5 の変更はすべて未コミット」とあったが
  `0c2be30` としてコミット済みだったため訂正。

テスト追加 / 更新:

- `hash` ユニット `test_first_payload_arg_skips_option_operands`:
  `--require` / `-r` / `--require=` 形 / `-W` / `-Wignore` 形で payload が
  正しく選ばれること、`-m` オペランド以降の `-c` が inline eval 誤検知に
  ならないこと、オペランドスキップ後の `-c` は検知されることを固定。
- `source_bind` ユニット: `option_operands_are_not_the_payload`、
  `inline_eval_reason_without_known_interpreter`、
  `extensionless_shebang_script_is_a_source_payload` を新設。
  `delegating_launchers_are_flagged` に新ランチャー群を追加。
  `env_shebang_marks_direct_exec_unbound` に固定 shebang の caveat を
  確認する検査を追加。
- `real_servers_e2e` stage1: node の entrypoint-hash ターゲットが
  `dist/index.js` と canonicalize 一致することを明示検査。

検証（本修正後、Linux・WSL2 カーネル 5.15）:

| 項目 | 結果 |
|---|---|
| `cargo fmt --all -- --check` | 0 |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | 0 |
| `cargo test --locked --lib` | 1348 件全件 PASS |
| `cargo test --locked --test workload_hash_e2e` | 3/3 PASS |
| `cargo test --locked --test docs_check` | 12/12 PASS |
| `cargo test --locked` 全スイート | PASS |
| `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` | 0 |
| 実機 `generate-policy -- node --require <stub> <dist/index.js>` | `entrypoint-hash` が `dist/index.js` を pin（従来は stub） |
| 実機 `generate-policy -- python3 -W ignore <script>` | `entrypoint-hash` がスクリプトを pin（従来は `ignore`） |
| 実機 `generate-policy -- sh -c 'exec node server.js'` | `binary-hash`(dash) + inline eval の REVIEW |
| 実機 `generate-policy -- /tmp/mcp-server-test`（拡張子なし env shebang） | binary + entrypoint + env shebang REVIEW |
| 実機 `generate-policy -- /tmp/fixed-shebang.py`（`#!/usr/bin/python3`） | binary + entrypoint + shebang インタプリタ未 pin REVIEW |
| 実機 `generate-policy -- nice -n 5 python3 s.py` / `timeout 30 …` | 委譲ランチャー REVIEW |

`real_servers_e2e` は本ホストに node / `.venv` フィクスチャが無く
各テストが stage1 前に skip（終了コードとしては PASS）。stage1 の
entrypoint ターゲット検査はユニットテストと上記実機確認で代替検証済み。

### レビュー指摘対応（shebang コマンドトークン解析・インタプリタ別オペランド）

差分レビューの指摘 2 件を検証し、いずれも有効と判断して修正
（いずれも作業ツリー差分として残す）。

- **shebang の言語判定をコマンドトークン方式へ**（`src/legislator/source_bind.rs`）。
  従来 `shebang_interpreter` は行全体への部分文字列（`contains("python")` /
  `contains("node")`）で判定しており、`#!/opt/python-tools/run.sh` のような
  フックパスや `env -S bash -c 'echo python'` のようなオプション・eval
  文字列中の偶発的な一致で誤分類し得た。修正後は shebang 行を空白トークンに
  分解し、固定形式（`#!/usr/bin/python3 -u`）は先頭トークン、`/usr/bin/env`
  形式は env 自身のオプション（`-S`/`--split-string`、別離オペランドを持つ
  `-u`/`--unset`/`-C`/`--chdir`、その他 `-` 始まり）と `VAR=val` 代入を
  スキップした先のコマンドトークンを `interpreter_from_command` に渡して
  判定する。`env -S python3 -u` 等は正しく解釈され、`bash`/`deno`/フック
  パスは `Native` に落ちる（捏造された source 解析を防ぐ）。`analyze_source`
  経路は同一ヘルパーを使うため自動的に同じ判定となる。
- **inline eval / ペイロード引数解析をインタプリタ対応化**
  （`src/verifier/hash.rs`）。`flag_consumes_operand` に `argv0` を渡し、共有
  テーブルに加えてインタプリタ別の operand フラグを参照する。perl は
  `-I`（インクルードパス）・`-M`/`-m`（モジュール）が別離オペランドを
  取り、ruby は `-I`/`-r` が取る。CPython の `-I`（isolated、オペランド
  なし）と意味が衝突するためグローバル表には置けない。これにより
  `perl -I lib -e 'print 1'` で `lib` がペイロードと誤認されず `-e` が
  走査範囲に入り、生成側 REVIEW と実行時 `bind_launched_workload` の拒否が
  同一ヘルパーで一致する（従来は両方とも検出漏れで fail-open）。添字は
  `first_payload_arg_index` が argv 先頭から自前で argv0 を得るため呼出側の
  変更は不要。

検証（本修正後）:

| 項目 | 結果 |
|---|---|
| `cargo fmt --all -- --check` | PASS（Windows / Linux） |
| `cargo clippy --locked --all-targets -- -D warnings` | 0（両 OS） |
| `cargo test --locked --lib` | 1342 件 PASS（Windows）/ hash 系 26 件 PASS（Linux） |
| `cargo test --locked --test workload_hash_e2e` | 3/3 PASS（両 OS） |
| `cargo test --locked --test real_servers_e2e`（REQUIRE 付き、Windows） | 5/5 PASS |
| 実機 `generate-policy -- perl -I lib -e 'print 1'`（Linux） | binary-hash + inline eval REVIEW（entrypoint 不捏造） |
| 実機 `generate-policy -- /tmp/mcpsrv_s`（`#!/usr/bin/env -S python3 -u`、拡張子なし） | binary + entrypoint + env shebang REVIEW |
| 実機 `generate-policy -- /tmp/notpy`（`env -S bash -c "echo python"`） | binary のみ（誤分類なし） |
| `git diff --check` | PASS |

新規テスト: `verifier::hash::tests::test_interpreter_specific_operand_flags`
（perl `-I lib -e` 回帰、`-M`、ruby `-I`、CPython `-I` はフラグ、
perl `-Ilib` 添字形式）、`source_bind::tests::shebang_interpreter_parses_command_token`
（固定形式・env 各形・フックパス/オプション/eval 文字列での誤分類防止）。

追記レビュー指摘対応: `interpreter_operand_extras` の ruby 判定が
`stem == "ruby"` のみで `ruby3.3` 等のバージョン付き名を拾えず
`-I`/`-r` のオペランド消費が利かなかったため、`ruby` 接頭辞の
非空サフィクスが数字と `.` のみで構成される名も認めるよう拡張
（`rubyfoo` のような非バージョン名は除外）。同テストに
`ruby3.3 -I lib -e` の inline-eval 検出と `rubyfoo` 非一致の回帰を追加。
実機 `generate-policy -- /tmp/ruby3.3 -I lib -e 'puts 1'`（シム経由）
でも binary-hash + inline eval REVIEW の出力を確認。fmt / clippy /
hash 系 26 件 / workload_hash_e2e 3/3 は両 OS で PASS。

## PR6. 子プロセス環境の allowlist

対象コミット / 未コミット差分: 実施時点の HEAD =
  `efadf43981fc9b285f7a5de544617dc1a2e59a9b`（`Merge pull request #15`、PR5 まで
  コミット済み）。PR6 の変更はすべて未コミットの作業ツリー差分として残す
  （ブランチ `stdio-hardening-PR6`）。

変更ファイル:

- `src/policy/mod.rs`: `EnvironmentPolicy { restrict, allowed }`（既定
  `restrict: false` / `allowed: []`）を追加し、`Policy.environment` と
  `default_policy` に接続。`ToolPolicy.environment_explicit` /
  `PolicyLayer.environment_explicit` を追加し、全 struct literal を追従。
- `src/policy/kdl_parse.rs`: `parse_defaults` で `children.get("environment")`
  を読み、`allow "NAME"` の位置引数を `allowed` に集める。ノード存在で
  `restrict = true`。`allow` 以外の子ノード・`environment` 自体の
  引数/属性・`allow` の名前付き属性は `PolicyError::KdlParse`。
  tool / profile / server-defaults / server 直下の `environment` は
  `environment_explicit` に旗を立てる（`environment` はプロセス共通の
  launch 契約であり、server 直下で黙って無視される方が危険なため
  server 直下も拒否対象に含めた）。
- `src/policy/kdl_inherit.rs`: `merge_into_policy` / `apply_overrides_from_doc`
  （`when` 経路）で overlay の `environment` ノードがあれば `restrict = true`、
  `allowed` が非空なら置換（syscalls と同じ規則）。overlay で解除する手段は
  存在しない。`environment_explicit` は tool merge で OR 伝播し、`when` 内の
  tool 直下 `environment` も旗を立てる。
- `src/policy/validator.rs`: `validate_per_tool_environment`（per-tool
  syscalls と同じ文言体系: `tool '<name>' declares per-tool environment,
  which is not enforced; move environment rules to defaults.environment`）と
  `validate_environment_names`（空 / `=` / NUL を含む名前は
  `PolicyError::Validation`）を追加。
- `src/policy/kdl_emit.rs`: `defaults` 内に `environment { allow ... }` を
  `restrict` が真のときだけ出力（空許可リストでも空ブロックを出し
  ラウンドトリップを維持）。`kdl_loader.rs` の `test_full_policy_roundtrip`
  に `environment` を追加し emit → 再解析の同値を確認。
- `src/policy/kdl_canon.rs`: 実装は無変更。`environment` ノードの有無で
  `hash_canonical_kdl` が変わる回帰テストのみ追加。
- `src/warden/mod.rs`: `SpawnOptions.allowed_names` を追加し、
  `spawn_child_async_exe_with` / `spawn_unsandboxed_async_exe_with` の
  `_exe_with` 変種を追加（launch が解決済み exe を渡すため）。self-test と
  live discovery の `SpawnOptions` は `allowed_names: Vec::new()` で据え置き。
- `src/warden/env.rs`: `restricted_base_env` が `allowed_names` の各名前を
  親から複写（親に無い名前は未設定のまま。空 / `=` / NUL を含む名前は
  validator が既に拒否するが、プログラム経由の誤用に備え skip）。
- `src/warden/env.rs`（Windows 修正）: 制限モードのベースラインに
  `LOCALAPPDATA` を追加。**実バグ修正** — カスタム環境ブロックを持つ
  AppContainer 子プロセスの `CreateProcessW` は `LOCALAPPDATA` が無いと
  `ERROR_ENVVAR_NOT_FOUND` (os error 203) で失敗する（コンテナ固有プロファイル
  パスの導出元）。手動二分探索で `LOCALAPPDATA` 単独が必要十分であることを
  確認（`APPDATA` / `TEMP` / `USERPROFILE` では不可）。
- `src/warden/windows_sandbox.rs`: 既存テストの TEMP 期待値を修正。
  `LOCALAPPDATA` が環境ブロックに入ると Windows が `TEMP` をコンテナ固有の
  `Packages\mcp-writ-<name>-<pid>\AC\Temp` にリマップするため、要求した
  tmpdir またはコンテナ `AC\Temp` のどちらでも受理する。
- `src/runtime/launch.rs`: `Policy.environment` から `SpawnOptions` を組み立て、
  `skip_sandbox` の真偽に関わらず sandboxed / unsandboxed の両経路へ渡す。
  `mcp-secure-runner` は同じ `launch` を使うため追加作業なし。
- `tests/fixtures/mcp_servers/scripted_stdio.py`: `env_probe` モード追加。
  `argv[1]` でモード指定できるようにし、制限環境で `MCP_WRIT_FIXTURE` が
  届かなくても動作する。`tools/call env_probe` の `arguments.names` 配列の
  各変数の観測値（または null）を `result.content` の JSON で返す。
- `tests/environment_e2e.rs`（新規、6 件）: 既定継承 / allowlist 制限 /
  dry-run / `MCP_WRIT_SKIP_SANDBOX` / 実サンドボックス（`host_defaults_kdl`
  ベース、`MCP_WRIT_REQUIRE_E2E_TESTS=1` で skip 不可）/ per-tool の
  ロード時拒否。
- `tests/real_servers_e2e.rs`: `inject_environment` と
  `real_memory_server_needs_listed_env` を追加（後述の実機確認を参照）。
- ドキュメント（日英で同じ内容）: `docs/guide.{md,ja.md}` の Field
  Reference と OS 別適用範囲マトリクスに `environment` / 環境変数の行を追加。
  `docs/policy-authoring.{md,ja.md}` に「サーバへ渡す環境変数を絞る」節を追加
  （`MEMORY_FILE_PATH` を例に、クライアント `env` の API キーは列挙しないと
  届かないこと・既定は継承であることを記述）。`README.{md,ja.md}` の保証一覧と
  `env` 継承の記述を更新。`docs/modules.md` に不変条件を追加。
  `policy.example.kdl` にコメントアウト例、`examples/policies/memory.kdl` の
  先頭コメントに `MEMORY_FILE_PATH` の案内を追加。

### 実機確認（PR6）

- Windows 11（build 26200）実機、`mcp-writ run` を手動起動し `env_probe` の
  応答を記録（`MCP_WRIT_TEST_KEEP=keep` / `MCP_WRIT_TEST_DROP=drop` を guard 側に設定）:
  - `MCP_WRIT_SKIP_SANDBOX=1`（非サンドボックス経路）:
    `{"MCP_WRIT_TEST_KEEP": "keep", "MCP_WRIT_TEST_DROP": null, "PATH": "C:\\Program Files\\...", "MCP_WRIT_TEST_MISSING": null}`。
    stderr に `sandboxing disabled (MCP_WRIT_SKIP_SANDBOX)` — OS サンドボックスのみ
    迂回し、環境制限は適用されている。
  - サンドボックス有り（`Warden: Windows sandbox applied (AppContainer)`）:
    同じく `KEEP=keep` / `DROP=null` / `MISSING=null` / `PATH` 生存。
    `TEMP` は `C:\Users\...\AppData\Local\Packages\mcp-writ-python_exe-<pid>\AC\Temp`
    にリマップされていることを確認（上記 `LOCALAPPDATA` 修正の効果で
    AppContainer 正常起動）。
  - 実メモリサーバ（`@modelcontextprotocol/server-memory` 0.6.3、AppContainer 下）:
    - `environment { allow "MEMORY_FILE_PATH" }` + 親に `MEMORY_FILE_PATH` 設定
      → `create_entities` 成功、`MEMORY_FILE_PATH` が指す `manual.json` に
      `{"type":"entity","name":"env-manual",...}` が実際に書き込まれた。
    - 未列挙（`allow "MCP_WRIT_UNRELATED_UNUSED"`）+ 親に `MEMORY_FILE_PATH` 設定
      → 変数は子に届かず、サーバは `dist/memory.jsonl`（読み取り専用付与の
      パッケージ内）へフォールバックし、`create_entities` が
      `isError:true` の `EPERM: operation not permitted, open '...\server-memory\dist\memory.jsonl.<hash>.tmp'`
      を返した。指定ファイルは生成されない。起動自体は成功する（サーバは
      パスを遅延解決する）— e2e はこの実挙動を期待値にしている。
- Linux（WSL2、カーネル 5.15.167.4 = Landlock ABI V1、`sandbox allow_degraded`
  で部分適用を許容した実 spawn）実機、`env_probe` 応答:
  `{"MCP_WRIT_TEST_KEEP": "keep", "MCP_WRIT_TEST_DROP": null, "PATH": "/usr/local/sbin:...",
  "MCP_WRIT_TEST_MISSING": null, "TMPDIR": null}` — `tmpdir` 未設定時に
  TMPDIR が捏造されないことも確認。実メモリサーバテスト
  `real_memory_server_needs_listed_env` も `MCP_WRIT_REQUIRE_SERVER_TESTS=1`
  下で PASS。
- macOS: **未検証**（本ホストに macOS 環境なし）。実装は OS 非依存の
  `apply_spawn_env` / `spawn_env_pairs` 経路を通るため差分はないが、
  `sandbox-exec` 下での実挙動は次の macOS 検証機会に持ち越し。

### 検証コマンドと終了コード（PR6 共通チェック）

| 項目 | 結果 |
|---|---|
| `cargo fmt --all -- --check` | 0（Windows） |
| `cargo check --locked --all-targets` | 0（Windows） |
| `cargo clippy --locked --all-targets -- -D warnings` | 0（Windows） |
| `cargo test --locked --lib` | 1365 件 PASS（Windows）/ 1373 件 PASS（Linux、WSL2 検証コピー） |
| `MCP_WRIT_REQUIRE_E2E_TESTS=1 cargo test --locked --test environment_e2e` | 6/6 PASS（Windows / Linux とも。`environment_applies_under_sandbox` は実サンドボックス経路で実行、skip なし） |
| `MCP_WRIT_REQUIRE_SERVER_TESTS=1 MCP_WRIT_REQUIRE_E2E_TESTS=1 cargo test --locked --test real_servers_e2e real_memory_server_needs_listed_env` | PASS（Windows / Linux とも実行、skip なし） |
| `cargo test --locked --test docs_check` | 11/11 PASS（Windows） |
| `git diff --check` | PASS |

### 次へ進む条件の確認（PR6）

- ノード無しの挙動が不変（親環境をそのまま継承）: `environment_inherits_by_default`・
  env.rs ユニットテスト・emit が `restrict` 偽でブロックを出さないことで確認済み。
- ノード有りで列挙名 + PATH 系だけが子に届く: Windows（AppContainer・skip 両経路）
  と Linux（WSL2、Landlock 部分適用下の実 spawn・skip 両経路）で実機確認済み。
  macOS は未検証として記録。
- per-tool / profile / server-defaults の `environment` はロード時拒否:
  `per_tool_environment_is_rejected_at_load`（終了コード非ゼロ + stderr に
  `per-tool environment`）と validator ユニットテストで確認済み。
- 現物でも確認: メモリサーバで `MEMORY_FILE_PATH` の列挙有無による
  成否を Windows 実機と e2e（Windows / Linux）で確認済み。
- `MCP_WRIT_REQUIRE_E2E_TESTS=1` で skip を失敗化しても全環境 e2e が PASS。
