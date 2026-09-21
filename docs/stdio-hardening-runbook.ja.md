# stdio 運用強化の作業手順書

- 作成日: 2026-09-20
- 基準コミット: `ca74b4dfebf6e63a7069096080da9efd56333218`

本書は[作業計画](stdio-hardening-plan.ja.md)の PR0〜PR7 を実行するための手順である。
記載した新規モジュール・関数・テスト名は配置案であり、基準コミットには存在しない。
コマンドの掲載は実行済みを意味しない。各 PR の結果を末尾の様式で記録する。

## 共通ルール

- Rust の新規依存を追加しない。`Cargo.lock` に差分が出た時点でその PR は完了条件を満たさない。[開発方針](development.md#dependency-and-ffi-policy)に従う。
- 補助ツール（検査、スクリプト、テストハーネス）は cargo が実行できる Rust で書く。cargo の外から叩く必要があるものだけ sh（Linux/macOS 用）と ps1（Windows 用）にし、それ以外の要件を足さない。補助ツールに Python は使わない。
- MCP サーバの検証は現物で行う。自作の mock はプロトコル異常系にだけ使う。現物で見つかった製品側の制約は記録し、fixture やテストで回避しない。
- テスト用 MCP サーバは補助ツールではない。Python、JS、Go の実物を使い、Rust に書き直さない。
- コミット、ブランチ作成、push、stash、checkout は利用者が行う。エージェントは作業ツリーにファイルとして残し、Git の状態を変えない。
- リポジトリルートで作業する。既存のユーザー変更を保存し、作業対象以外を巻き戻さない。
- 実装変更と、それを説明する日英ドキュメントを同じ PR に含める。ガイドの英語版と日本語版は同じ仕様を説明する。
- テスト用の権限を広げて本来の制限を回避しない。未実施・skip は理由を記録し、実機合格と区別する。
- 「完了」「合格」と書けるのは、共通チェックをすべて実行し、変更した経路を実際に起動して確認した後だけとする。欠けている軸があれば「実装済み・未検証（欠けている軸: X）」と書く。
- 日本語ファイルは UTF-8、BOM なし、LF で保存する。
- Python の呼び方は OS で分ける。システムの Python は Unix で `python3`、Windows で `py -3`。仮想環境は Unix で `.venv/bin/python` と `.venv/bin/pip`、Windows で `.venv\Scripts\python.exe` と `.venv\Scripts\pip.exe`。本書の `<system-python>`、`<venv-python>`、`<venv-pip>` はこの対応で読む。

### 共通チェック

各 PR の最後に次をすべて実行し、終了コードと要点を記録する。

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
git diff --check
git diff --stat -- Cargo.lock
```

最後の 1 行は出力が空であることを確認する。文書チェックは PR1 で `cargo test` に含まれる。
PR0 と PR1 の作業中だけ `python3 scripts/check_docs.py` を併用する。
Linux では加えて `MCP_WRIT_REQUIRE_E2E_TESTS=1 cargo test --locked` を実行し、
サンドボックス付き e2e が skip ではなく実行されたことを確認する。
PR2 以降で現物サーバを取得済みのホストでは `MCP_WRIT_REQUIRE_SERVER_TESTS=1` も付けて実行する。
PowerShell では環境変数付きのコマンドを `$env:NAME = '1'` の設定と `cargo …` の 2 行に分けて実行する。

## PR0. 着手前の記録

対象: 記録のみ。ソースは変更しない。

1. 次を取得し、基準コミットから実装が変わっていれば該当箇所を読み直す。

   ```sh
   git status --short
   git rev-parse HEAD
   git diff --stat
   rustc --version --verbose
   cargo --version
   node --version
   npm --version
   python3 --version            # Windows: py -3 --version
   python3 -m pip --version     # Windows: py -3 -m pip --version
   git --version
   ```

2. `cargo test --locked` を実行し、テストの総数、合格数、skip の理由を記録する。
3. 次の出力を `.local/stdio-hardening/baseline/` に保存する。PR7 のバイト一致比較に使う。

   ```sh
   cargo build --locked --release --bin mcp-writ
   B=target/release/mcp-writ
   for f in human json kdl; do
     $B inspect --format $f tests/fixtures/inspector/x86_64_linux_syscalls.elf   > .local/stdio-hardening/baseline/inspect-x86.$f
     $B inspect --format $f tests/fixtures/inspector/aarch64_linux_syscalls.elf > .local/stdio-hardening/baseline/inspect-aarch64.$f
     $B inspect --format $f tests/fixtures/py_mcp/read_file_urlopen.py         > .local/stdio-hardening/baseline/inspect-py.$f
   done
   $B generate-policy -- python3 tests/fixtures/py_mcp/read_file_urlopen.py     > .local/stdio-hardening/baseline/genpol-py.kdl
   $B generate-policy -- tests/fixtures/inspector/x86_64_linux_syscalls.elf     > .local/stdio-hardening/baseline/genpol-x86.kdl
   cargo tree --locked --edges normal,build > .local/stdio-hardening/baseline/cargo-tree.txt
   ```

4. `tools/list` の変更前挙動を記録する。[tool_enforcement_e2e](../tests/tool_enforcement_e2e.rs) の
   `transfer_b_drops_unknown_vendor_key_from_forwarded_tools_list` を参考に、
   `MCP_WRIT_FIXTURE=tools_call_ok` の [scripted_stdio.py](../tests/fixtures/mcp_servers/scripted_stdio.py) へ
   `tools/list` を送り、ポリシーに無いツールが応答に含まれることを確認した出力を保存する。
5. `docs/stdio-hardening-results.ja.md` を作成し、上記を第 1 節として書く。

**次へ進む条件:** HEAD、既存差分、テスト件数、fixture 出力、依存グラフ、ランタイムの版が保存されている。

## PR1. 文書チェックの cargo test 化

対象: `tests/docs_check.rs`（新設）、`scripts/check_docs.py`、
[ci.yml](../.github/workflows/ci.yml)、[linux-tests.yml](../.github/workflows/linux-tests.yml)、
[development.md](development.md)、[releasing.md](releasing.md)。

1. `tests/docs_check.rs` を新設し、`scripts/check_docs.py` と同じ規則を実装する。
   対象はルート直下、`docs/`、`tests/`、`.github/` の `*.md`。UTF-8 で BOM なし、`\r` を含まない、
   fenced code を除いたローカルリンクの実在、`#` フラグメントの見出しアンカー一致。
   アンカーの生成規則は Python 版の `anchors` と同じにし、同名見出しの連番も同じにする。
   標準ライブラリと既存依存の `regex-lite` だけを使う。
2. Python 版と Rust 版を同じ作業ツリーで 1 度ずつ実行し、指摘が同一であることを記録する。
   意図的に壊したリンクを 1 つ作って両方が検出することも記録する。
3. `scripts/check_docs.py` を削除する。`scripts/` が空になれば削除する。
4. [ci.yml](../.github/workflows/ci.yml) 45 行と [linux-tests.yml](../.github/workflows/linux-tests.yml) 54 行の
   `python3 scripts/check_docs.py` ステップを削除する。
5. [development.md](development.md) の検証コマンド一覧から `python3 scripts/check_docs.py` と Windows の `py -3` 行を外し、
   文書チェックが `cargo test` に含まれることを書く。[releasing.md](releasing.md) の検証節からも同じ行を外す。
6. 全層 grep で `check_docs` の残存を確認する。残ってよいのは保管文書（`docs/archive/`）だけ。
7. 共通チェックを実行する。

**完了条件:** 文書チェックが `cargo test` に含まれ、Python 版と同じ指摘を出す。CI の明示ステップが消えている。

## PR2. 現物 MCP サーバの検証基盤

対象: `tests/fixtures/real_servers/`（新設）、`examples/policies/`（新設）、`tests/real_servers_e2e.rs`（新設）、
`scripts/check-server.sh` と `scripts/check-server.ps1`（新設）、`.github/workflows/mcp-servers.yml`（新設）、
[release.yml](../.github/workflows/release.yml)、[Cargo.toml](../Cargo.toml)、[.gitignore](../.gitignore)、
[tests/common/mod.rs](../tests/common/mod.rs)、[path_resolution_e2e](../tests/path_resolution_e2e.rs)、
[policy.example.kdl](../policy.example.kdl)、[development.md](development.md)、日英ガイド、日英ポリシー作成ガイド。

1. 対象サーバの版を固定する。[modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) の
   公開パッケージから次の 4 本を選び、実装日時点の最新安定版を記録する。

   | サーバ | 取得元 | 実行形 |
   |---|---|---|
   | `@modelcontextprotocol/server-filesystem` | npm | `node <node_modules>/@modelcontextprotocol/server-filesystem/dist/index.js <許可ルート>` |
   | `@modelcontextprotocol/server-memory` | npm | `node <node_modules>/@modelcontextprotocol/server-memory/dist/index.js`、`MEMORY_FILE_PATH` で保存先を指定 |
   | `mcp-server-time` | PyPI | `<venv-python> -m mcp_server_time` と `<venv-python> <site-packages>/mcp_server_time/__main__.py` の両方 |
   | `mcp-server-git` | PyPI | `<venv-python> -m mcp_server_git --repository <一時リポジトリ>` と同上のパス形 |

   `dist/index.js` の実パスはパッケージの `bin` 定義で確認し、記録する。

2. 取得の定義を置く。

   - `tests/fixtures/real_servers/node/package.json` に 2 パッケージを exact 版で書き、`npm install --ignore-scripts` で
     `package-lock.json` を生成してコミット対象にする。以後の取得は `npm ci --ignore-scripts`。
   - `tests/fixtures/real_servers/python/requirements.txt` に 2 パッケージを `==` と `--hash=sha256:…` で書く。
     ハッシュは `pip download` で得た配布物から取り、手で書かない。取得は `<system-python> -m venv .venv` と
     `<venv-pip> install --require-hashes -r requirements.txt`。
   - `tests/fixtures/real_servers/setup.sh` と `setup.ps1` が上記を行う。引数は無し。既に取得済みなら何もしない。
     2 つは同じ手順と同じ出力にする。
   - `.gitignore` に `tests/fixtures/real_servers/node/node_modules/` と `tests/fixtures/real_servers/python/.venv/` を、
     [Cargo.toml](../Cargo.toml) の `exclude` に同じ 2 つを足す。`cargo package --locked --list` に含まれないことを確認する。

3. 起動形の分類を記録する。各サーバの各実行形について `mcp-writ inspect -- <argv>` と
   `mcp-writ generate-policy -- <argv>` を実行し、payload が Source と Unresolved のどちらになるか、
   静的解析で `source_tools` が出るかを記録する。基準コミットの実装では `node <path>.js` と `__main__.py` パス形は
   Source、`python -m` と `npx` は Unresolved になるはずである。結果が違えば実装の差分を読んで理由を書く。
   Unresolved を回避する変更は入れない。

4. 交渉する MCP 版を記録する。各サーバに `generate-policy --live-discovery` を実行し、
   `protocolVersion` とツール数と `tools-list-hash` を記録する。製品が実装する `2025-11-25` と `2026-07-28` 以外しか
   話さないサーバは、失敗の stderr をそのまま記録し、そのサーバのシナリオは「製品側の対応範囲外」として skip 扱いにする。
   fixture 側で版を偽装しない。

5. `examples/policies/` に 4 本の実ポリシーを書く。ファイル名は `filesystem.kdl`、`memory.kdl`、`time.kdl`、`git.kdl`。

   - `server` ブロックにツールの allowlist、`side_effect`、per-tool の `filesystem` と `network`、
     手順 4 で得た `tools-list-hash` を書く。書き込みを伴うツールは書き込み範囲を per-tool で絞る。
   - `defaults` の `filesystem` と `syscalls` は書かない。先頭コメントで、利用者は
     [ポリシー作成ガイド](policy-authoring.md#editing)の手順で
     ホストごとの `defaults` を足すこと、テストは `extends` で同じことをしていることを書く。
   - `network` は `deny host="*"` を `defaults` に書く。Windows で拒否される組み合わせ（allowlist と deny-all の併用）は書かない。
   - [policy.example.kdl](../policy.example.kdl) 19-20 行の `servers/filesystem.kdl` のコメントを `examples/policies/filesystem.kdl` に変える。

6. サンドボックス起動の補助を共通化する。[path_resolution_e2e](../tests/path_resolution_e2e.rs) 894 行の
   `spawn_guard_sandboxed` と 964 行の `sandboxed_policy` を [tests/common/mod.rs](../tests/common/mod.rs) へ移し、
   既存の呼び出しを書き換える。挙動は変えない。

7. ホスト向け `defaults` の生成を書く。`common::host_defaults_kdl(argv0: &str) -> String` を足し、
   次を返す。固定パスを書かない。

   - `argv0` を `resolve_command_path` で解決し、その親と、親の親（インストール prefix）を読み取り許可に入れる。
     `<venv-python>` は symlink 先も解決し、両方を入れる。`node_modules` と `.venv` のディレクトリも読み取り許可に入れる。
   - Linux は `/usr/lib/**`、`/lib/**`、`/lib64/**`、`/usr/local/lib/**`、`/etc/ssl/**` のうち存在するものを入れる。
     macOS は `sandbox-exec` の固定システムパスに加えて解決した prefix を入れる。Windows は解決した prefix に読み取りを付与する。
   - `syscalls` は Linux で観測した定数 `NODE_SYSCALLS` と `PYTHON_SYSCALLS` を使う。初期値は
     [ポリシー作成ガイドの Linux 例](policy-authoring.md#linux-read-only)から取り、
     実行時の stderr の `unknown syscall` と `EPERM`、監査ログから不足分を足す。群（ローダー、スレッド、シグナル、乱数、
     git の `execve`）ごとに理由をコメントする。観測した OS、カーネル、Node、Python の版を作業記録に書く。
   - 観測した `NODE_SYSCALLS` と `PYTHON_SYSCALLS` は、読み取りパスの組み立て規則のコメントとともに
     `examples/policies/runtime/node.kdl` と `python.kdl` に `defaults` として書く。ホスト固有のパスは書かない。
     テストの定数はこのファイルを読んで得る。定数の二重管理をしない。
   - 生成した `host.kdl` は `extends "…/examples/policies/<server>.kdl"` で例を継承し、例は
     `extends "runtime/<node|python>.kdl"` で基底を継承する。`host.kdl` は解決したパスと `logging fail_closed=#false` だけを足す。
     多段の `extends` が既存の loader で成立することを [kdl_policy_e2e](../tests/kdl_policy_e2e.rs) の `test_extends_with_include_combined` と同じ形で確認する。

8. `tests/real_servers_e2e.rs` を新設する。サーバの一覧を 1 か所に持ち、取得済みでなければ
   `common::skip_e2e_test` で抜ける。`MCP_WRIT_REQUIRE_SERVER_TESTS=1` なら失敗させる。
   サーバごとに次の 6 段階を行い、応答と監査ログの行をアサートする。

   | 段 | 内容 | filesystem | memory | time | git |
   |---|---|---|---|---|---|
   | 1 | `generate-policy --live-discovery` が完了する | 同左 | 同左 | 同左 | 同左 |
   | 2 | dry-run で `initialize`、`tools/list`、許可された `tools/call` が成功する | `read_file` で許可ルート内のファイル | `create_entities` で 1 件 | `get_current_time` | 一時リポジトリへの `git_log` |
   | 3 | Warden 有りで段 2 と同じ | 同左 | 同左 | 同左 | 同左 |
   | 4 | Auditor の拒否が JSON-RPC エラーで返る | ルート内に置いた `.ssh/id_rsa` 相当のパスを `read_file`（secret-overlay） | per-tool で未許可のツール名 | 未掲載ツール名 | per-tool の `filesystem` 外のパスを `--repository` 相当の引数に渡す |
   | 5 | OS 層だけの拒否。監査ログに `tool_call.denied` が無く、`result.isError` か JSON-RPC エラーが返る | 許可ルート内だが `defaults` で許可していない下位ディレクトリの `read_file` | `MEMORY_FILE_PATH` を許可外に置いた `create_entities` | 該当なし（I/O 無し）。段 3 で代替 | 許可外ディレクトリのリポジトリへの `git_log` |
   | 6 | 例の `tools-list-hash` が取得した版と一致する | 同左 | 同左 | 同左 | 同左 |

   段 5 の filesystem は、Linux では許可ツールの `filesystem` が Landlock に合成されるため、per-tool の allow は
   ルート全体に、`defaults` の allow は下位の 1 つに限定して差を作る。macOS と Windows では per-tool が Auditor 検査だけなので、
   同じ入力でも拒否層が変わる。どの層で止まったかを監査ログの有無で判定し、OS ごとの期待値を表に書く。

9. `scripts/check-server.sh` と `scripts/check-server.ps1` を書く。

   ```text
   check-server --policy <kdl> [--audit-log <path>] [--call <json params>] [--mcp-writ <path>] -- <server command...>
   ```

   - `mcp-writ` は PATH 上か `--mcp-writ` で指定されたものだけを使う。cargo を呼ばない。
   - 手順は 3 つ。dry-run で `initialize` と `notifications/initialized` と `tools/list` を送ること。
     Warden 有りで同じことを行うこと。`--call` があれば Warden 有りで `tools/call` を 1 回送り、応答をそのまま表示すること。
   - 各応答行の判定は 3 条件。`"result"` を含む、`"error"` を含まない、`--call` の応答は `"isError":true` を含まない。
     ps1 は `ConvertFrom-Json` で構造的に判定し、sh は JSON パーサーを持たないため同じ 3 条件を文字列で判定する。
   - 監査ログの末尾 20 行を表示し、いずれかの段が失敗したら非 0 で終了する。判定はこれ以上増やさない。細かい期待値は cargo 側の e2e に置く。
   - JSON-RPC の行は固定文字列で持つ。`protocolVersion` は `2025-11-25`。
   - 2 つのスクリプトは同じ引数、同じ段、同じ出力の見出しにする。

10. `.github/workflows/mcp-servers.yml` を新設する。[go-runtime.yml](../.github/workflows/go-runtime.yml) と同じ
    `workflow_dispatch` と `workflow_call` で、`ubuntu-24.04`、`macos-latest`、`windows-latest` の matrix。
    `actions/setup-node` と `actions/setup-python` で版を固定し、`setup` スクリプトを OS に応じて実行し、
    `MCP_WRIT_REQUIRE_SERVER_TESTS=1 cargo test --locked --test real_servers_e2e` を回す。
    続けて `check-server` スクリプトを filesystem サーバと `examples/policies/filesystem.kdl` に `host.kdl` を足したもので実行し、
    終了コード 0 を要求する。[release.yml](../.github/workflows/release.yml) の `needs` には加えず、
    Linux tests と同じ扱いでその旨のコメントを足し、[releasing.md](releasing.md) の手順 2 に
    「タグ前に同じコミットで dispatch する」を書く。

11. 文書を更新する。

    - [development.md](development.md) の前提に Node、Python 3、git と、取得のためのネットワークを書く。ワークフロー表に「MCP server compatibility」を足す。Platform sandbox verification の表に現物サーバの段を足す。[releasing.md](releasing.md) の手順 4 のワークフロー一覧にも足す。
    - [policy-authoring.md](policy-authoring.md) の冒頭で `examples/policies/` を実ポリシーの出発点として案内し、`examples/policies/runtime/` の基底を `extends` してから `defaults` にホストのパスを足す手順へ繋ぐ。第 5 節に `check-server` スクリプトの使い方を足す。
    - [guide.md](guide.md) の Deployment Scenarios から `examples/policies/` と `check-server` へリンクする。
    - 日本語版も同じ内容にする。

12. 3 OS で `MCP_WRIT_REQUIRE_SERVER_TESTS=1 cargo test --locked --test real_servers_e2e` を実行し、
    4 本の 6 段階の生の出力を記録する。PowerShell では
    `$env:MCP_WRIT_REQUIRE_SERVER_TESTS = '1'; cargo test --locked --test real_servers_e2e` とする。取得前のホストで同じテストが skip することと、
    変数付きで失敗することも記録する。`check-server` の sh と ps1 を同じサーバに対して実行し、出力を並べて記録する。

13. 共通チェックを実行する。`cargo package --locked --list` に `node_modules` と `.venv` が無いことを確認する。

**完了条件:** 3 OS で 4 本の現物サーバが Warden 有りで `initialize` から `tools/call` まで動く。
Auditor の拒否、OS 層だけの拒否、`tools-list-hash` の固定が確認できる。
起動形ごとの分類と交渉した MCP 版が記録されている。配備先でスクリプトが同じ確認を行える。

## PR3. README と公開面の訂正

対象: [README 英語](../README.md)、[README 日本語](../README.ja.md)、
[ガイド英語](guide.md)、[ガイド日本語](guide.ja.md)、
[ポリシー作成ガイド英語](policy-authoring.md)、[日本語](policy-authoring.ja.md)。

1. 解析範囲の記述は基準コミットで訂正済みである。「Supported targets」節、Features の ELF / Mach-O、
   `inspect` 行、ビルド節の文言が更新されている。残る 1 点だけ直す。Features の「supported scripts」に
   Python と JavaScript/TypeScript を明記し、シェルは shebang とコマンド名からの推定である旨を書く。
   根拠は [guide.md](guide.md) 333 行と [modules.md](modules.md) の Inspector 行。
   日本語 README の「対応スクリプト」も同じにする。ガイド側は変更しない。

2. 位置づけを先頭段落の直後に 1〜2 文で書く。ローカル stdio サーバが対象であること、
   制御面（ツール定義の固定、呼び出しの許可、パスとホスト、起動権限、監査）のポリシー執行点であり、
   データ面（応答本文の DLP、HTTP/SSE ゲートウェイ、LLM による判定）は範囲外で、そうした検査器とは
   直列に接続する分担であること。非目標を欠落ではなく分担として書く。
   既存の「Supported MCP versions」節の「HTTP/SSE transport is not supported」は残し、
   範囲の決定であることが分かる表現に揃える。

3. 「Security boundaries」節を「保証すること」と「保証しないこと」の 2 つの短い一覧に組み替える。
   合計 20 行以内。次を含める。

   - Linux が主対象。Landlock と seccomp。許可ツールの filesystem はプロセス共通の ruleset に合成される。
   - macOS はグローバルの filesystem を `sandbox-exec` で強制し、per-tool の filesystem と network は Auditor 検査のみ。syscalls は未適用。
   - Windows は AppContainer。ネットワークは全拒否か無制限で、宛先単位の OS 制御は無い。
   - per-tool の検査は RPC 引数に対するもので、ツールごとの OS サンドボックスではない。
   - dry-run は OS サンドボックス無しでサーバを実行し、副作用がある。
   - TOCTOU は Auditor 検査の対象外で、OS 層が受け持つ範囲だけ閉じる。

   各行の根拠は [Per-OS enforcement matrix](guide.md#per-os-enforcement-matrix) にあり、
   README からその見出しへリンクする。

4. クイックスタートを現物のサーバで書く。PR2 で固定した filesystem サーバの版と `examples/policies/filesystem.kdl` を使い、次の流れにする。

   ```sh
   cargo install --locked --path . --bin mcp-writ
   npm install -g @modelcontextprotocol/server-filesystem@<PR2 で固定した版>
   # Create policy.kdl: extend the reviewed example and add this host's defaults
   # (interpreter read paths and syscalls; see the policy authoring guide)
   cat > policy.kdl <<'EOF'
   policy version=1
   extends "examples/policies/filesystem.kdl"
   defaults {
       // filesystem and syscalls for this host go here
   }
   EOF
   # Discover the server's tools in a restricted environment and compare with the pinned hash
   mcp-writ generate-policy --live-discovery --output policy.draft.kdl -- mcp-server-filesystem /path/to/allowed/dir
   # Observe the guard in dry-run
   mcp-writ run --dry-run --policy policy.kdl --audit-log ./audit.jsonl -- mcp-server-filesystem /path/to/allowed/dir
   # Check the real server through the installed guard, sandbox on
   scripts/check-server.sh --policy policy.kdl -- mcp-server-filesystem /path/to/allowed/dir
   ```

   `policy.kdl` は例の複写ではなく、`extends` で例を継承してホストの `defaults` を足したものにする。
   README には PR2 で実際に動いた `host.kdl` の `defaults` を載せ、`run` と `check-server` はその `policy.kdl` を読む。
   `npm install -g` が作る実行ファイル名と、`node <path>/dist/index.js` 形との違いは PR2 の記録から書く。
   Linux と macOS でこの流れを実際に実行し、生成された草案、`initialize` と `tools/list` と
   `tools/call read_file`（許可ディレクトリ内に置いた `.ssh/id_rsa` 相当のパスで secret-overlay の拒否を見せる）の応答、
   監査ログの行、`check-server` の出力を記録する。README に載せるのは dry-run と `check-server` までとし、
   ポリシーの `defaults` の書き方は[ポリシー作成ガイド](policy-authoring.md#verification)へ誘導する。
   Windows では `check-server.ps1` に読み替えた行を載せ、実行結果を記録する。実行していない行を README に書かない。

5. クライアント設定の JSON を「Client configuration」節として追加する。
   `mcpServers` 形式の `command` / `args` / `env` を示し、`args` に
   `run --policy … --audit-log … -- <server command>` を入れる。
   載せる形は次のとおり。Claude Desktop の `claude_desktop_config.json` と Cursor の `.cursor/mcp.json` は
   `mcpServers.<name>.{command,args,env}`、VS Code の `.vscode/mcp.json` は `servers.<name>` で同じ 3 項目。
   VS Code の差は 1 行で触れる。この形が各クライアントの現行ドキュメントと一致することを実装時に照合し、
   照合した日付を記録する。一致しない場合は現行ドキュメントに合わせ、差異を作業記録に書く。
   `env` で渡した変数は既定で子に継承されることを 1 文で書く。PR6 完了後にこの文を allowlist の案内へ更新する。
   [ポリシー作成ガイド](policy-authoring.md#verification)の該当節から README のこの節へリンクする。

6. README の先頭文を `Cargo.toml` の `description`（Policy enforcement, OS sandboxing, and JSON-RPC auditing for MCP servers）に揃える。
   日本語版は「MCP サーバ向けのポリシー執行、OS サンドボックス、JSON-RPC 監査」とする。`Cargo.toml` は変えない。

7. リリース配布物へのリンクは、`v*` タグが存在する場合だけ追加する。存在しない場合は追加せず、記録に「タグ未作成のため未掲載」と書く。

8. [policy-authoring.md](policy-authoring.md) の構成を、狭い default-deny で起動し、拒否を監査ログから読み、
   確認した条項だけ足し、差分を pin し直す、の順に組み替える。既存の第 5 節と第 6 節の内容はこの流れの中へ移す。
   `generate-policy` の草案は出発点の 1 つとして位置づけ、草案の allow を読んで削る手順を主経路にしない。
   dry-run が副作用を持つことは、この流れの「拒否を読む」段の注意として書く。日本語版も同じ構成にする。

9. 共通チェックを実行する。文書チェックはリンク先とアンカーを検査するため、
   見出しを変えた場合は参照元も更新する。

**完了条件:** README だけを読んで、対応する形式と ISA、stdio 特化、制御面とデータ面の分担、OS ごとの強制の差、保証しないことが分かる。
クイックスタートの各行は現物のサーバで実行済みで、その出力が作業記録にある。

## PR4. tools/list の allowlist フィルタ

対象: [checker](../src/auditor/checker.rs)、[proxy_tools_list](../src/auditor/proxy_tools_list.rs)、
[audit_log](../src/auditor/audit_log.rs)、[tool_enforcement_e2e](../tests/tool_enforcement_e2e.rs)、
`tests/real_servers_e2e.rs`、[scripted_stdio.py](../tests/fixtures/mcp_servers/scripted_stdio.py)、
日英ガイド、日英ポリシー作成ガイド、日英 README、[modules.md](modules.md)。

1. 判定述語を切り出す。[checker](../src/auditor/checker.rs) 212-223 行の
   「`policy.tools` に同名があり `allowed` が真」を `pub fn tool_is_allowed(policy: &Policy, name: &str) -> bool`
   として定義し、`check_request` はこの関数を呼ぶ形に変える。挙動は変えない。
   既存の `test_denied_tool_blocked` と `test_unknown_tool_blocked`（[integration](../tests/integration.rs)）が
   そのまま通ることを確認する。

2. フィルタを入れる。[verify_and_emit_list](../src/auditor/proxy_tools_list.rs) の
   `record_verified_digest` の後、`build_verified_tools_list_response` の直前で、
   `tools_to_verify` を可視と不可視に分ける。可視だけを応答に渡す。
   scan、`verify_tools_list`、`hash_tools_list`、`record_verified_digest` の引数は
   `tools_to_verify` のままにする。この順序を関数のコメントに明記する。

3. dry-run の分岐を入れる。`shared.dry_run` が真ならフィルタせず全件を渡す。

4. 監査イベントを出す。不可視が 1 件以上のとき 1 イベントを記録する。
   種別は `EventType::ToolsListFiltered` を追加する。`as_str` は `tools_list.filtered`、
   `category` は `policy_enforcement`、`Severity::Info`。`details` に隠した名前を列挙し、
   `Action` は通常運用で `Denied`、dry-run で `Observed`。
   `EventType` を網羅する `match` はコンパイラが検査するが、文字列の一覧を持つ
   [audit_log](../src/auditor/audit_log.rs) のテストは手で更新する。`rg 'EventType::' src tests` で一覧を取る。

5. e2e テストを追加する。異常系は mock で、可視性の現物確認は filesystem サーバで行う。
   mock は `MCP_WRIT_FIXTURE=tools_call_ok` の [scripted_stdio.py](../tests/fixtures/mcp_servers/scripted_stdio.py) が返す
   `read_file`、`fail_write`、`fetch_url` の 3 件を使う。ポリシーは `read_file` を許可、
   `fetch_url` を `deny=#true`、`fail_write` を未掲載にする。期待値は次のとおり。

   | テスト名（案） | 入力 | 期待 |
   |---|---|---|
   | `tools_list_hides_denied_and_unlisted_tools` | 通常運用で `tools/list` | 応答の `tools` は `read_file` の 1 件のみ。`fetch_url` と `fail_write` の文字列が含まれない |
   | `tools_list_dry_run_keeps_all_tools_and_observes` | dry-run で `tools/list` | 3 件すべて含まれる。監査ログに `observed` のイベントが 1 件 |
   | `tools_list_hash_pins_full_advertised_set_not_filtered_view` | 3 件の一覧から計算した `tools-list-hash` をポリシーに書き、通常運用で `tools/list` | 検証が通り、応答は 1 件。1 件の一覧から計算したハッシュを書いた場合は検証失敗 |
   | `list_changed_relist_is_filtered` | `MCP_WRIT_FIXTURE=list_changed_ok` | 再検証後に転送される一覧も 1 件 |
   | `tools_list_empty_when_policy_has_no_tools` | ツールを 1 つも書かないポリシー | `tools: []` の正常応答。エラーではない |
   | `real_filesystem_server_lists_only_allowed_tools`（`real_servers_e2e`） | `examples/policies/filesystem.kdl` で `tools/list` | 応答のツール名の集合が例の allowlist と一致し、例の `tools-list-hash` の検証が通る |

   3 番目のハッシュ値は `verifier::tools_diff::hash_tools_list` をテスト内で呼んで求める。
   値をテストに直書きしない。

6. 文書を更新する。

   - [guide.md](guide.md) の Security Model 表の「Unauthorized tool invocation」行に、tools/list からも除外されることを追記する。Fail-Secure Principle の一覧に 1 行足す。dry-run の説明（FAQ の「How do I use dry-run mode?」）に、dry-run ではフィルタしない旨を足す。
   - [policy-authoring.md](policy-authoring.md) の「What to check in a normal run」に、`tools/list` に許可ツールだけが並ぶことを確認項目として足す。許可を広げた後はクライアントの再取得が必要なことも書く。
   - README の Features「Tool access controls」に 1 句足す。
   - [modules.md](modules.md) の不変条件に「tools/list の scan、ハッシュ、digest は広告された全件に対して行い、allowlist フィルタは検証後の出力にだけ適用する。dry-run はフィルタしない」を足す。
   - [guide.md](guide.md) に「Audit log schema」節を足す。JSONL の各フィールド、`event_type`、`category`、`severity`、`action` の値一覧、拒否した要求のクライアント側 id の保持を、[audit_log](../src/auditor/audit_log.rs) の `as_str` から写して書く。他ツールが接合する契約と位置づけ、値を変える場合は移行ガイドに書く旨を添える。本 PR で足す `tools_list.filtered` も載せる。
   - 日本語版もすべて同じ内容にする。

7. 実際に起動して確認する。PR0 の手順 4 と同じ入力を送り、応答が変わったことを記録する。
   dry-run の同じ入力も記録する。filesystem サーバでも `tools/list` の応答を記録する。

8. 共通チェックを実行する。

**完了条件:** 通常運用で未許可ツールが tools/list から消え、dry-run では残る。
ハッシュ pin が全件で計算されることが負のテストで固定されている。現物でも確認した。文書が日英で揃っている。

## PR5. 起動対象ハッシュの文書化と草案出力

対象: [generate_policy](../src/commands/generate_policy.rs)、[policy_generator](../src/legislator/policy_generator.rs)、
[source_bind](../src/legislator/source_bind.rs)、[hash](../src/verifier/hash.rs)、
[policy.example.kdl](../policy.example.kdl)、`tests/real_servers_e2e.rs`、日英ガイド、日英ポリシー作成ガイド、日英 README。

1. 既存の検査順序を確認する。[launch](../src/runtime/launch.rs) 88-114 行と
   [hash](../src/verifier/hash.rs) の `verify_server_hashes`、`bind_launched_workload`、
   `reverify_immediately_before_spawn` を読み、次を記録する。

   - `binary` は `argv[0]` の実体と `same_file` で照合され、ハッシュが一致しないと `Mismatch`。
   - `entrypoint` は `argv[0]` か最初の payload 引数のどちらかに一致しないと `UnboundWorkload`。
   - `lockfile` と `docker-manifest` だけでは bind できず `UnboundWorkload`。
   - inline eval は `UnboundWorkload`。
   - エントリが無い場合は警告のみで起動する（`NoEntries`）。

   この記録をそのまま文書の根拠にする。実装は変えない。

2. 草案出力を追加する。[generate_policy](../src/commands/generate_policy.rs) で
   `discover_from_argv` の結果から次を求め、`policy_generator::generate_policy` に渡す。

   - `argv[0]` を `resolve_command_path` で解決した絶対パスと `hash_file` の値。
   - payload が Script の場合、その絶対パスと `hash_file` の値。
   - payload が InlineEval または不明の場合は「束縛不能」の理由文字列。

   `generate_policy` は `server "auto-generated" {` の直後、`tools-list-hash` の前に
   `binary-hash` と `entrypoint-hash` の行を出す。書式は
   [kdl_emit](../src/policy/kdl_emit.rs) 173-185 行と同じ `<種別> "<sha256:…>" target="<絶対パス>"`。
   直前に REVIEW コメントを 2 行置く。配備先で再計算すること、サーバ更新時に再生成すること。
   束縛不能の場合はハッシュ行を出さず、理由をコメントで出す。
   ハッシュ情報は `WorkloadHashes { binary: Option<HashLine>, entrypoint: Option<HashLine>, unbound_reason: Option<String> }`
   を `Default` 付きで定義して 1 引数で渡す。`HashLine` は絶対パスと `sha256:` 値の組。
   既存のテスト呼び出し `generate_policy(&result, &cap, None, &[])` は `&WorkloadHashes::default()` を足す形に揃える。

3. ユニットテストを追加する。

   - 生成した KDL が `kdl_loader::parse_kdl_policy` で解析でき、`hash_entries` に `Binary` と `Entrypoint` が 1 件ずつ入る。
   - inline eval ではハッシュ行が無く、理由コメントがある。
   - 既存の `empty_elf_does_not_emit_execve_from_missing_syscalls` など生成器のテストが不変。

4. e2e テストを追加する。`tests/workload_hash_e2e.rs` を新設し、次の 2 経路を行う。

   ネイティブの経路（`binary-hash`）:

   - `common::compiled_open_path_fixture()` の実行ファイルを一時ディレクトリへ複写する。
   - `generate-policy --output <tmp>/policy.kdl -- <tmp>/open_path_server` を CLI で実行し、
     `binary-hash` の `target` が複写先の絶対パスであることを確認する。
   - そのポリシーで `run --dry-run` を起動し、`initialize` に応答することを確認する。
   - 複写した実行ファイルの末尾に 1 バイト追記し、同じポリシーで再起動すると終了コード 1、
     stderr に `Supply chain verification failed`、監査ログに `hash_mismatch` があることを確認する。

   解釈系の経路（`entrypoint-hash`）:

   - [open_path.py](../tests/fixtures/mcp_servers/open_path.py) を一時ディレクトリへ複写する。
   - `generate-policy --output <tmp>/policy.kdl -- <system-python> <tmp>/open_path.py` を実行し、
     `binary-hash` の `target` が起動した `argv[0]`（Unix は `python3`、Windows は `py`）を `resolve_command_path` で
     解決した実体、`entrypoint-hash` の `target` が複写先の絶対パスであることを確認する。
     Windows で束縛されるのはランチャー `py.exe` であり、委譲先の `python.exe` は束縛対象外になる。
     これは製品の仕様として記録し、テスト側で回避しない。
   - `run --dry-run` で `initialize` に応答することを確認し、`.py` の末尾にコメント 1 行を追記して再起動すると
     拒否されることを確認する。

   現物の確認（`real_servers_e2e` に追加）:

   - `node <path>/dist/index.js` 形の filesystem サーバで `generate-policy` を実行し、`binary-hash` と `entrypoint-hash` の両方が出て、そのポリシーで起動できることを確認する。
   - `python -m mcp_server_time` 形では `entrypoint-hash` が出ず、理由コメントが出ることを確認する。`__main__.py` パス形では出ることを確認する。

5. 文書を書く。

   - [guide.md](guide.md) の Field Reference に `server` 配下の 4 種別を 1 行ずつ足す。Policy Reference 配下に「Workload verification」小節を新設し、手順 1 で記録した検査順序と失敗時の挙動、終了コード、監査イベント `hash_verified` / `hash_mismatch` を書く。ハッシュはホスト固有であり別ホストでは再計算が必要なこと、`python -m` と `npx` 形は束縛できないことを書く。
   - [policy-authoring.md](policy-authoring.md) の「Generate a draft」節に、草案にハッシュ行が入ることと確認方法を足す。「Find the setting behind a denial」の表に起動対象ハッシュ不一致の行を足す。
   - [policy.example.kdl](../policy.example.kdl) の `server` ブロックにコメントアウトした `binary-hash` と `entrypoint-hash` の例を足す。
   - README の Features「Tool definition verification」を起動対象の検証を含む表現に広げる。
   - 日本語版も同じ内容にする。

6. 実際に起動して確認する。手順 4 と同じことを Linux か macOS の実機で手動でも行い、
   生成された草案と拒否時の stderr をそのまま記録する。Windows では `py.exe` のパスと、委譲先の `python.exe` が束縛対象外であることを記録する。

7. 共通チェックを実行する。

**完了条件:** ガイドから 4 種別と検査順序が分かる。草案に実在ファイルのハッシュが入り、
改変後の起動が拒否されることを e2e と実機の両方で確認した。現物の起動形ごとの束縛可否が記録されている。

## PR6. 子プロセス環境の allowlist

対象: [policy/mod.rs](../src/policy/mod.rs)、[kdl_parse](../src/policy/kdl_parse.rs)、
[kdl_inherit](../src/policy/kdl_inherit.rs)、[kdl_emit](../src/policy/kdl_emit.rs)、
[validator](../src/policy/validator.rs)、[warden/mod.rs](../src/warden/mod.rs)、
[env.rs](../src/warden/env.rs)、[launch](../src/runtime/launch.rs)、
[scripted_stdio.py](../tests/fixtures/mcp_servers/scripted_stdio.py)、`tests/real_servers_e2e.rs`、
[policy.example.kdl](../policy.example.kdl)、日英ガイド、日英ポリシー作成ガイド、日英 README、[modules.md](modules.md)。

1. 型を足す。`Policy` に `pub environment: EnvironmentPolicy` を追加し、
   `EnvironmentPolicy { pub restrict: bool, pub allowed: Vec<String> }` の既定値は
   `restrict: false`、`allowed: []` とする。`default_policy` も同じ。

2. 解析を足す。[parse_defaults](../src/policy/kdl_parse.rs) 129-190 行で `children.get("environment")` を読み、
   `allow "NAME" ...` の位置引数を `allowed` に集める。ノードがあれば `restrict = true`。
   `allow` 以外の子ノードと名前付き属性はエラーにする。
   tool、profile、server-defaults の子に `environment` があれば `environment_explicit` を立て、
   [validator](../src/policy/validator.rs) 402-408 行の per-tool syscalls と同じ文言で読み込み時に拒否する。

3. 検証を足す。名前が空、`=` を含む、NUL を含む場合は `PolicyError::Validation`。

4. 合成を足す。[merge_into_policy](../src/policy/kdl_inherit.rs) 168-170 行の syscalls と同じく
   overlay の `allowed` が非空なら置換する。`apply_overrides_from_doc` の `when` 経路も同様にする。
   `rematerialize_inherited_defaults` に影響が無いことを確認する。

5. 出力を足す。[kdl_emit](../src/policy/kdl_emit.rs) の `defaults` 内に `environment { allow ... }` を出す。
   `restrict` が偽なら出さない。[kdl_loader](../src/policy/kdl_loader.rs) 491 行の
   `test_full_policy_roundtrip` に `environment` を足し、再解析で同値になることを確認する。
   `kdl_canon` は変更しない。ノードの有無で `hash_canonical_kdl` が変わることをテストで確認する。

6. Warden に渡す。[SpawnOptions](../src/warden/mod.rs) 13-18 行に `pub allowed_names: Vec<String>` を足す。
   [restricted_base_env](../src/warden/env.rs) は `allowed_names` の各名前について親に値があれば複写する。
   `PATH`、Windows のシステム変数、`TMPDIR` 系は現状どおり。
   Windows の [encode_windows_env_block](../src/warden/windows_env.rs) は `spawn_env_pairs` に委譲しており、
   macOS と Linux の spawn も `apply_spawn_env` を通るため、OS 別の変更は無い。

7. 起動経路に繋ぐ。[launch](../src/runtime/launch.rs) で `Policy.environment` から `SpawnOptions` を組み立て、
   `spawn_child_async_with` と `spawn_unsandboxed_async_with` に渡す。`skip_sandbox` の真偽に関わらず渡す。
   `mcp-secure-runner` は同じ `launch` を使うため追加作業は無い。
   [mcp-secure-runner.rs](../src/bin/mcp-secure-runner.rs) 45 行で `MCP_WRIT_SKIP_SANDBOX` を除去した後に
   spawn 時点の親環境を読むため、除去した変数が子へ複写されることは無い。
   live discovery と self-test の `SpawnOptions` は変えない。

8. ユニットテストを足す。[env.rs](../src/warden/env.rs) の既存テストに倣い、
   列挙した名前が複写され、列挙しない親の変数が落ち、`PATH` と `TMPDIR` が残ることを確認する。
   列挙した名前が親に無い場合にエラーにならないことも確認する。

9. e2e テストを足す。mock と現物の両方で行う。
   [scripted_stdio.py](../tests/fixtures/mcp_servers/scripted_stdio.py) に `env_probe` モードを足し、
   `initialize` に応答し、`tools/call env_probe` の `arguments.names` に列挙された環境変数の値を
   `result.content` の JSON として返す。標準出力は JSON-RPC 以外を書かない。
   `tests/environment_e2e.rs` を新設し、次を行う。

   | テスト名（案） | ポリシー | 期待 |
   |---|---|---|
   | `environment_inherits_by_default` | `environment` ノード無し | `MCP_WRIT_TEST_DROP` が子に届く |
   | `environment_allowlist_restricts_child` | `environment { allow "MCP_WRIT_TEST_KEEP" }` | `KEEP` は届き、`DROP` は届かず、`PATH` は届く |
   | `environment_applies_when_sandbox_skipped` | 同上、`MCP_WRIT_SKIP_SANDBOX=1` | 同じ結果 |
   | `environment_applies_under_sandbox` | 同上、サンドボックス有り。`host_defaults_kdl` の Python 向け設定を使う | 同じ結果。`MCP_WRIT_REQUIRE_E2E_TESTS=1` で skip を許さない |
   | `per_tool_environment_is_rejected_at_load` | tool 配下に `environment` | 起動前に終了コード 1 と拒否メッセージ |
   | `real_memory_server_needs_listed_env`（`real_servers_e2e`） | memory サーバに `MEMORY_FILE_PATH` を渡し、allowlist に載せた場合と載せない場合 | 載せた場合は指定先に書き、載せない場合は既定の保存先か失敗になる。どちらになるかはサーバの実装を読んで期待値を決め、記録する |

   guard を起動する側で `MCP_WRIT_TEST_KEEP=keep` と `MCP_WRIT_TEST_DROP=drop` を設定する。

10. 文書を書く。

    - [guide.md](guide.md) の Field Reference に `defaults.environment` の行を足す。Per-OS enforcement matrix に「Environment」行を足し、3 OS とも Warden が起動時に適用すること、dry-run と skip でも適用されることを書く。
    - [policy-authoring.md](policy-authoring.md) に「サーバへ渡す環境変数を絞る」節を足す。クライアントの `env` で渡す API キーは列挙しないと届かないこと、既定は継承であることを、memory サーバの `MEMORY_FILE_PATH` を例に書く。
    - [policy.example.kdl](../policy.example.kdl) の `defaults` にコメントアウトした例を足す。`examples/policies/memory.kdl` の先頭コメントに `MEMORY_FILE_PATH` の案内を足す。
    - README の「保証すること」一覧に 1 行足し、PR3 で書いた「`env` は既定で継承」の文を allowlist の案内へ更新する。
    - [modules.md](modules.md) の不変条件に「環境の制限は起動契約であり、dry-run と skip-sandbox でも適用する。既定は継承」を足す。
    - 日本語版も同じ内容にする。

11. 実際に起動して確認する。Linux、macOS、Windows の 3 OS で、手順 9 のポリシーを使って
    `run` を起動し、fixture と memory サーバの応答をそのまま記録する。実施できない OS は未検証として記録する。

12. 共通チェックを実行する。

**完了条件:** ノード無しの挙動が不変。ノード有りで列挙した名前と PATH 系だけが子に届くことを
3 OS で確認した。per-tool は読み込み時に拒否される。現物でも確認した。

## PR7. 依存の向きの固定

対象: [lib.rs](../src/lib.rs)、[legislator](../src/legislator/mod.rs)、[auditor](../src/auditor/mod.rs)、
[verifier](../src/verifier/mod.rs)、[inspector/profile/format.rs](../src/inspector/profile/format.rs)、
[commands/inspect.rs](../src/commands/inspect.rs)、[warden/windows_sandbox.rs](../src/warden/windows_sandbox.rs)、
[modules.md](modules.md)、`tests/`。

挙動は一切変えない。各手順の後に `cargo check --locked --all-targets` を通してから次へ進む。

1. 現状の参照を列挙し、記録する。

   ```sh
   for m in auditor cli commands container error framing fspriv inspector legislator pathutil policy runtime termutil tool_def verifier warden; do
     if [ -d src/$m ]; then f=src/$m; else f=src/$m.rs; fi
     printf '%s -> ' "$m"; rg -oh 'crate::[a-z_]+' "$f" | sort -u | tr '\n' ' '; echo
   done
   ```

2. `protocol` を葉にする。`src/legislator/protocol.rs` を `src/protocol/mod.rs` へ移し、
   `src/legislator/tools_list_parse.rs` を `src/protocol/tools_list.rs` へ移す。
   `MAX_PAGES` も移す。`tools_list_parse` が使う `ToolsListError` の variant は `ParseError(String)` だけなので、
   `protocol` に `ToolsListParseError(String)` を定義し、`legislator::tools_list::ToolsListError` へ
   `From` で `ParseError` に変換する。
   `lib.rs` に `pub mod protocol;` を足す。参照元は `rg 'legislator::(protocol|tools_list::(parse_tools_list_response|parse_tools_list_response_page|verified_tool_json|MAX_PAGES))'` で列挙して書き換える。

3. baseline を `verifier` へ移す。`src/legislator/tools_list_baseline.rs` を `src/verifier/tools_baseline.rs` へ移し、
   `legislator::tools_list` の再公開と auditor の `load_baseline` 呼び出しを書き換える。
   保存先ディレクトリの決め方は変えない。

4. `audit_log` を葉にする。`src/auditor/audit_log.rs` を `src/audit_log.rs` へ移し、
   `auditor::audit_log` の参照をすべて `crate::audit_log` に書き換える。
   `pub use crate::audit_log` を `auditor` に残さない。

5. `secret_paths` を葉にする。`src/auditor/secret_paths.rs` を `src/secret_paths.rs` へ移す。
   `pathutil` への依存は葉同士なので許容する。

6. `workload` を葉にする。`src/workload.rs` を新設し、[hash](../src/verifier/hash.rs) の
   `resolve_command_path`、`search_path`、`same_file`、`first_payload_arg`、
   `first_payload_arg_index`、`argv_contains_inline_eval` を移す。
   `hash.rs`、`source_bind.rs`、`self_test_warden.rs`、`windows_sandbox.rs` の参照を書き換える。
   [runtime/argv.rs](../src/runtime/argv.rs) の `parse_shell_or_json` はコンテナ起動用の別関心のため移さない。

7. 整形関数を `commands` へ移す。[format.rs](../src/inspector/profile/format.rs) の
   `format_json_with_project`、`format_json_with_extras`、`format_kdl_with_project` と、
   これらだけが使う補助関数およびテスト（1044-1074 行付近）を `src/commands/inspect_format.rs` へ移す。
   `inspector` から `crate::legislator` の参照が消えることを確認する。
   `format_human`、`format_json`、`format_kdl` は残す。

8. `fixture_regression` を統合テストへ移す。`src/verifier/fixture_regression.rs` を
   `tests/manifest_fixtures.rs` へ移し、`mcp_writ::` の公開経路で参照する。
   必要な関数が `pub` でなければ最小限で公開する。

9. レイヤーテストを足す。`tests/module_layering.rs` を新設し、標準ライブラリと既存依存の `regex-lite` で次を行う。

   - `src` 配下の `.rs` を走査し、パスから最上位モジュール名を求める。
   - 各ファイルの `crate::<name>` 参照を集める。`use crate::{auditor, verifier};` の grouped import と
     `use crate::{auditor::checker, verifier::hash};` の入れ子は波括弧を展開して各モジュール名を取り出す。
     `pub use crate::…` も対象にする。この展開をテスト内の単体ケースで固定する。
   - 計画の第 4.6 節の層表をテスト内の定数に持ち、参照先の層が自分の層以下でなければ失敗する。
   - 例外の一覧を定数として持ち、空にする。例外を足す場合は理由をコメントに書く。

10. [modules.md](modules.md) を更新する。層の表と「上位から下位への参照のみ許可」の規則を「依存の向き」節として足す。
    モジュール表に `protocol`、`audit_log`、`secret_paths`、`workload` の行を足し、
    `legislator` と `auditor` と `verifier` の責務説明から移した内容を除く。
    経緯は書かず、現在の設計として書く。

11. 出力の不変を確認する。PR0 の手順 3 と同じコマンドを実行し、`.local/stdio-hardening/baseline/` と
    `diff` して差分が無いことを確認する。`cargo test --locked` の総数が PR0 の記録以上であることを確認する。

12. 3 OS で `cargo clippy --locked --all-targets -- -D warnings` を通す。OS 固有の参照書き換え漏れは
    ホストの `cargo check` では見つからない。

13. 共通チェックを実行する。

**完了条件:** レイヤーテストが例外 0 件で通る。`inspect` と `generate-policy` の出力が PR0 の記録とバイト一致。
テスト件数が減っていない。modules.md が現在の層を説明している。

## 任意 PR の候補

着手条件は[作業計画](stdio-hardening-plan.ja.md)の第 1 節にある。条件を満たしたときに本書へ手順を追記する。

- **現物サーバの追加**: `mcp-server-fetch` は `deny host="*"` の下で外向き接続が OS 層で止まる証拠になる。CI から外部へ到達できることを前提にせず、ローカルの記録で足りるかを先に決める。
- **`python -m` と `npx` の payload 束縛**: PR2 と PR5 で記録した Unresolved の結果を起点に、モジュール名と npm パッケージ名をどう実体に解決するかを設計する。`entrypoint-hash` の意味を変えない範囲で決める。
- **rlimit / Job Object 上限**: Linux は `pre_exec` 内で `setrlimit`、Windows は `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` の `ProcessMemoryLimit` と `ActiveProcessLimit`。macOS は `sandbox-exec` に相当機能が無いため未適用として文書化する。seccomp の許可名に `setrlimit` / `prlimit64` が既にあることを確認する。
- **OWASP MCP Top 10 対応表**: 一次資料の項目名を写し、各項目に対応する層（Auditor / Warden / Verifier / 対象外）と根拠のファイルを書く。番号や名称を推測で埋めない。

## 結果記録と切り戻し

各 PR の完了時に `docs/stdio-hardening-results.ja.md` へ次の様式で追記する。

```
## PRn. <題名>

対象コミット / 未コミット差分: HEAD = <sha>、`git status --short` の要約
変更ファイル: <一覧>
設計判断と逸脱: <計画からの差異とその理由。無ければ「なし」>
検証コマンドと結果: <共通チェックの各コマンドと終了コード、テスト件数、実機で起動した経路と生の出力>
現物サーバ: <版、protocolVersion、ツール数、tools-list-hash、起動形の分類、OS ごとの 6 段階の結果>
未検証: <実施できなかった OS・経路と理由>
残る制約: <次の PR へ持ち越すもの>
```

切り戻しは PR 単位で行う。PR1 は `check_docs.py` と CI ステップの復元。PR2 は新設ディレクトリとワークフローの削除。
PR4 は `verify_and_emit_list` のフィルタ呼び出しを外す。PR5 は草案のハッシュ出力を外す。
PR6 は `environment` ノードの解析を外せば既定の継承に戻る。PR7 はファイル移動を戻す。
いずれも他の PR に影響しない。
