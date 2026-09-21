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
未検証: macOS 経路全般（本機に Mac なし）。`mcp-servers.yml` の CI 実行自体
  （手動 dispatch 前提で未起動）。Landlock ABI V4 の完全適用（WSL カーネル
  5.15 では ABI V1 の部分適用まで）。Windows の LPAC モード（opt-in 実験用）。
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
| `mcp-server-time` | `2026.8.18` | `2025-11-25` | 2 | `be763b48bfee1ccabf75d095bf48a22b52b504a29ec36c8261fbb4842429017b` |
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
  Windows・WSL2 で確認（git の実呼び出しは Windows では記録済みの platform
  制約で fail-closed、macOS は未実施）
- Auditor の拒否・OS 層だけの拒否・`tools-list-hash` の固定: 段 4・5・6 で確認
- 起動形ごとの分類と交渉した MCP 版: 上記 2 表に記録
- 配備先で同じ確認を行える: `setup.sh`/`setup.ps1`（冪等・ハッシュ照合付き）、
  `check-server.sh`/`.ps1`（同一 3 段）、`mcp-servers.yml`（手動 dispatch）を配置
- `cargo package --list` に `node_modules` / `.venv` / `mingit` が無いこと:
  確認済み
