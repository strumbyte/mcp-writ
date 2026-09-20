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
