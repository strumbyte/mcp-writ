# stdio 運用強化の作業計画

- 作成日: 2026-09-20
- 調査基準: `ca74b4dfebf6e63a7069096080da9efd56333218`
- 状態: 計画。以下の完了条件は、実装・検証済みであることを示さない。

起点は公開直後に受けた 2 件の外部レビューである。各指摘を実装とドキュメントに
照らして検証した結果を第 2 節に記録し、採用するものだけを作業に落とした。
具体的な編集・検証方法は[作業手順書](stdio-hardening-runbook.ja.md)にまとめる。
着手時に基準コミットとの差分を確認し、変更された実装に合わせて本計画を更新する。

## 1. 目的と決定事項

対象はローカル stdio の強制執行ランタイムとしての mcp-writ である。
Auditor の RPC 検査と Warden のプロセス単位の OS 制限という責務分担、
確定権を Verifier に置く構造、Legislator を草案生成に留める構造は維持する。

### 位置づけ

- HTTP/SSE ゲートウェイ、応答のマスキングや DLP、LLM による判定、観測 UI、コンテナ基盤の取り込みは対象外のままとする。README にはこれを欠点ではなく範囲の決定として書く。
- モジュール名 Inspector / Legislator / Warden / Auditor / Verifier は README、ガイド、診断文言で公開語彙になっている。改名はしない。
- crate 分割はしない。単一 crate の中で依存の向きを固定する。

### 常設ルール: 補助ツールとテスト用サーバ

- 補助ツール（検査、スクリプト、テストハーネス）は cargo が実行できる形の Rust で書く。cargo の外から叩く必要があるものだけスクリプトにし、その場合は sh（Linux/macOS 用）と ps1（Windows 用）の 2 つとする。それ以外の要件を足さない。補助ツールに Python は使わない。
- MCP サーバの検証は現物で行う。公開されている MCP サーバを版を固定して取得し、それを製品で包んで検証する。自作の mock サーバはプロトコルの異常系を作るためのものであり、製品が現物を包めることの証拠にはならない。
- テスト用 MCP サーバは補助ツールではない。Python、JS、Go の実物を使い、Rust に書き直さない。
- `tests/fixtures/py_mcp` と `js_mcp` はサーバ解析機能の入力データであり、実行されない。言語も内容も変えない。
- 製品バイナリは Python にも Node にも依存していない。これらは検証の前提であって、配備先の要件ではない。

### 今回の対応方針

| 対象 | 採用する方針 |
|---|---|
| 現物 MCP サーバの検証 | 公式リファレンスサーバから Node 製 2 本と Python 製 2 本を版固定で取得し、`examples/policies/` の実ポリシーで Warden 有りの起動、Auditor の拒否、OS 層だけの拒否、`tools-list-hash` の固定を確認する。配備先で現物を検査する sh と ps1 のスクリプトを提供する。Node と Python の起動に必要な syscall と読み取りパスの規則は `examples/policies/runtime/` に `extends` 用の基底として公開し、テストも同じファイルを読む |
| テスト支援 | 文書チェックを `cargo test` へ移す。既存の Python mock サーバはプロトコル異常系のために残す |
| README と公開面 | 解析範囲の記述は基準コミットで更新済みなので、対応スクリプトの言語名だけ足す。現物サーバと実ポリシーによるクイックスタート、クライアント設定の JSON、OS 差と保証範囲の短い一覧を先頭側に置く。位置づけは「制御面のポリシー執行点。データ面の検査器とは直列に接続する」と書き、非目標を欠落ではなく分担として示す。ポリシー作成ガイドは「狭い default-deny で起動し、拒否ログから許可を昇格し、差分を pin し直す」ループを主経路にする |
| tools/list | allowlist 外のツールを発見面から消す。first-seen スキャン、ハッシュ、digest は広告された全件に対して行い、フィルタは検証後の出力にだけ適用する。dry-run はフィルタしない |
| 起動対象の同一性 | 既存の `binary-hash` / `entrypoint-hash` 検査を利用者向けに文書化し、`generate-policy` が草案へ出力する。値の捏造はしない |
| 子プロセスの環境変数 | ポリシーで opt-in の allowlist を追加する。ノードが無ければ現状どおり親環境を継承する。既定値は変えない |
| モジュール境界 | 循環している 4 本の依存を葉モジュールの抽出で解き、依存の向きを modules.md とテストで固定する |
| 依存 | 本計画の全 PR で Rust の新規依存を追加しない。[開発方針](development.md#dependency-and-ffi-policy)を適用する。現物サーバの取得は検証の前提であり、製品の依存ではない |

### 見送るもの

| 項目 | 理由 |
|---|---|
| 引数述語の短縮記法（`startsWith` / `regex`） | `args_schema` の JSON Schema `pattern` と per-tool filesystem glob で表現できる。[schema_validator](../src/auditor/schema_validator.rs) |
| モジュールの改名（draft / sandbox / audit / launch / app） | 公開語彙の変更であり、利用者に見える。循環の解消は改名なしで可能 |
| crate 分割、HTTP 対応、応答 DLP、プロジェクト名の変更 | 位置づけの外、または効果に対して変更が大きい |
| Python の mock サーバを Rust に書き直すこと | 現物の検証が入れば mock は異常系専用になる。書き直しは要件を増やすだけで、対象の忠実さを下げる |
| 自作の同型サーバ（open_path の JS 版など）を足すこと | 現物のサーバで同じ証拠が取れる。自作サーバを増やすと現物との差が検証されない |
| `open_path_server.rs` の rustc 直接コンパイルを変えること | 動いている経路であり、今回の目的に寄与しない |

### 任意項目（ゲート付き）

| 項目 | 着手条件 |
|---|---|
| 現物サーバの追加（fetch、github など） | 初期 4 本の検証基盤が動いた後。ネットワークを要するサーバは deny-all の証拠として価値があるが、CI の外部到達性を前提にしない |
| `python -m` と `npx` の payload 束縛 | 現物の検証で Unresolved と記録された後、束縛規則の設計を別 PR で行う。本計画では回避策を入れない |
| ライブ発見の一時サンドボックス化と `--unsafe-unsandboxed-discovery` の改名 | 利用者の承認。self-test の probe ポリシー生成を発見に転用できるかを先に確認する。改名は公開 CLI の変更である |
| 起動時の enforcement 報告と、強制できない条項の明示承認 | 利用者の承認。既定は報告のみとし、起動拒否は opt-in にする案から検討する。macOS と Windows の既存利用者の per-tool 条項を突然の起動失敗にしない |
| 複数サーバの grant 干渉検査 | 利用者の承認。1 ポリシー内の複数 `server` を対象にした読み取り専用の検査として設計する。実行時の挙動は変えない |
| クライアント設定の書き換えコマンド | 利用者の承認。PR3 の JSON 例で足りるかを先に見る |
| rlimit / Job Object のメモリ・プロセス数上限 | Landlock と seccomp で止まらない量的な問題が運用で観測されたとき |
| OWASP MCP Top 10 との対応表 | 公開されている項目名と番号を一次資料で照合できたとき。レビューに書かれた番号を検証なしで採用しない |
| v0.1.0 のリリース公開と README からのリンク | `v*` タグの push は利用者の操作。タグが存在しない間は README に配布物へのリンクを書かない |

## 2. レビュー指摘の検証結果と現状の根拠

| 指摘 | 主な確認先 | 実態 | 計画への反映 |
|---|---|---|---|
| 現物のサーバで検証されていない | [tests/fixtures/mcp_servers/](../tests/fixtures/mcp_servers/)、[go_mcp](../tests/fixtures/go_mcp/)、各 e2e の `MCP_WRIT_SKIP_SANDBOX` | 実行される MCP サーバはすべて自作の mock。公開サーバは 1 本も通していない。Python mock は全件サンドボックス無しで走る。Warden 有りで走るのは Go の自作 fixture と Rust の `open_path_server` だけ | PR2 |
| 起動形の分類 | [source_bind](../src/legislator/source_bind.rs) 103-127 行と 176-187 行、[hash](../src/verifier/hash.rs) 419-438 行 | `node <path>.js` は Source として束縛できる。`python -m <module>` と `npx <package>` は payload がファイルでないため Unresolved になり、静的解析と `entrypoint-hash` の対象外。[ポリシー作成ガイド](policy-authoring.md) 36 行も `python -m` ではソースを特定できない場合があると書いている | PR2 で現物の起動形ごとに記録し、対応は任意項目 |
| 補助ツールの Python | `scripts/check_docs.py`、[ci.yml](../.github/workflows/ci.yml) 45 行 | 補助ツールで Python なのは文書チェックだけ。製品バイナリは Python を使わない | PR1 |
| ライブ発見が OS サンドボックス無し | [tools_list](../src/legislator/tools_list.rs) 424-441 行、[parse_gen_policy](../src/cli/parse_gen_policy.rs) 67-68 行 | 発見の spawn は Warden を通らず、既定は環境変数の制限だけ。`--unsafe-unsandboxed-discovery` の「unsandboxed」は環境変数の継承を指し、名前が実態より強い。self-test には probe ポリシーの生成（[self_test_warden](../src/legislator/self_test_warden.rs) 142 行）があり転用できる | 任意項目（承認待ち） |
| 強制できない条項を起動時に知らせない | [landlock_impl](../src/warden/landlock_impl.rs) 106 行と 128 行 | 起動時の警告は Landlock のパス skip だけ。macOS と Windows で per-tool の filesystem と network が Auditor 検査のみになることは guide の表にあるが、実行時には出ない | 任意項目（承認待ち） |
| 監査ログのスキーマが契約として文書化されていない | [guide.md](guide.md) 279 行、[audit_log](../src/auditor/audit_log.rs) 13-43 行 | JSONL であることと診断の読み方はあるが、フィールドと種別の値一覧が無い。他ツールが接合する継ぎ目として固定されていない | PR4 で文書化 |
| 複数サーバの grant 干渉を見ない | [policy/mod.rs](../src/policy/mod.rs) 603-630 行 | `bind_to_server` は 1 サーバに束縛し、他サーバの grant を借りない。同時接続するサーバ集合の重複や共有書き込み先の検査は無い | 任意項目（承認待ち） |
| ARM 解析が未完了 | [modules.md](modules.md)、[作業記録](archive/arm64-security-results.ja.md)、[decoder](../src/inspector/decoder/aarch64.rs)、[macho_parser](../src/inspector/macho_parser.rs) | Linux AArch64 ELF と macOS ARM64 Mach-O は解析済み。Linux AArch64 の Warden 強制も GitHub Actions の ARM ランナーで検証済み。未検証は Windows ARM64 の実機のみ。PE と arm64e は `unsupported` として出力される | README も基準コミットで更新済み。作業不要 |
| README の重心が x86 ELF | [README](../README.md) 5-8 行と 47-61 行、[README.ja](../README.ja.md) | 基準コミットで訂正済み。「Supported targets」節が形式・ISA・ABI ごとの結果を表にしている。残るのは「supported scripts」に言語名が無い点だけ | PR3 で言語名だけ足す |
| 動くポリシー例が無い | [policy.example.kdl](../policy.example.kdl) 19-20 行 | コメントが `servers/filesystem.kdl` を示唆するだけで実体が無い | PR2 の `examples/policies/` |
| tools/list から未許可ツールを落とす | [proxy_tools_list](../src/auditor/proxy_tools_list.rs) 502-517 行、[proxy_wire](../src/auditor/proxy_wire.rs) 358-385 行 | 検証後の再構成は全ツールを出力し、`policy.tools` を参照しない。可視性を検査するテストも無い | PR4 |
| 起動対象の digest が無い | [launch](../src/runtime/launch.rs) 88-114 行、[hash](../src/verifier/hash.rs) 307-400 行、[kdl_parse](../src/policy/kdl_parse.rs) 1154-1190 行 | 4 種別のハッシュを受け付け、spawn 前に verify、bind、reverify の順で検査する。entrypoint は最初の payload 引数に束縛し、inline eval は拒否する。ただしガイド、ポリシー作成ガイド、README に記述が無く、`generate-policy` も出力しない | PR5 |
| spawn 時の env allowlist | [warden/mod.rs](../src/warden/mod.rs) 13-18 行と 158-160 行、[env.rs](../src/warden/env.rs) 31-59 行 | `SpawnOptions.restrict_environment` は live discovery と self-test 専用。`run` は既定値のまま全 OS で親環境を継承する | PR6 |
| クライアント設定のスニペット | [guide.md](guide.md) 156 行 | 散文のみ。JSON 例は無い | PR3 |
| Partial 解析を許可集合に変えない | [policy_generator](../src/legislator/policy_generator.rs) 400-416 行、[score](../src/inspector/profile/score.rs) 27-32 行、[P4 テスト](../tests/inspector_arm64_p4.rs) 311 行と 470 行 | 非 `analyzed` では REVIEW コメントを出し、Linux ABI 以外では allow 行を出さない。スコアには加点する。テストで固定済み | 作業不要 |
| dry-run のヘルプと文書の整合 | [parse_run](../src/cli/parse_run.rs) 60-65 行 | 整合済み | 作業不要 |
| sandbox が KDL 生データを持たない | [warden](../src/warden/) 配下の `use crate::policy` | 型付きの `Policy` のみを受け取る | 作業不要 |
| verify を純粋判定に保つ | [hash](../src/verifier/hash.rs) 8 行、[manifest](../src/verifier/manifest.rs) 12 行、[tools_diff](../src/verifier/tools_diff.rs) 5 行 | 判定は純粋だが、監査イベントの出力で auditor を import している | PR7 で `audit_log` を葉へ移す |
| 依存の向きを厳しくする | 第 4.6 節の一覧 | auditor と legislator、auditor と verifier、inspector と legislator が相互参照。warden が verifier のパス解決関数を借用 | PR7 |
| `PathRule` と `HostPath` の分離 | [landlock_impl](../src/warden/landlock_impl.rs)、[guide.md](guide.md#per-os-enforcement-matrix) | 型は存在せず文字列。glob の縮約規則が OS ごとに違う（Linux は警告、Windows は無言で skip） | 今回は見送り。OS 差を揃える必要が出た時点で型の導入を検討する |
| 事前ビルド配布 | [release.yml](../.github/workflows/release.yml)、[releasing.md](releasing.md) | 6 系統の CLI と 2 系統の runner をタグで build する。タグは未作成 | 任意項目。利用者の操作 |

維持する条件:

- [modules.md の不変条件](modules.md#invariants-to-preserve)をすべて維持する。
- 現物サーバの版は lockfile とハッシュで固定する。版を上げるときは `tools-list-hash` の再固定と差分の記録を伴う。
- 現物の起動形で Unresolved や束縛不能になる場合は、そのまま記録する。テストや fixture 側で回避しない。
- tools/list の scan、ハッシュ、digest は広告された全件に対して行う。フィルタで `tools-list-hash` の意味と `last_verified` が変わらない。
- dry-run の意味論を変えない。違反した `tools/call` は転送され、ツール定義の遮断検査は残る。
- 子プロセスの既定の環境は継承のまま。制限はポリシーの opt-in だけで有効になる。
- 起動対象ハッシュの検査順序 verify、bind、reverify と、失敗時の `exit 1` を変えない。
- stdout は JSON-RPC フレームのみ。監査ログの既存フィールドと `as_str` の値を変えない。イベント種別を追加する場合は `as_str`、カテゴリ、列挙テストを同じ PR で更新する。
- 既存の Python mock サーバとそれを使う e2e の期待値は変えない。
- `py_mcp` と `js_mcp` の解析入力 fixture は実行されないデータであり、言語も内容も変えない。
- 日英ドキュメントを同じ変更単位で更新する。
- Rust の新規依存を追加しない。`Cargo.lock` の差分は無しを期待値とする。

## 3. 作業分割・順序・完了条件

各 PR を独立してレビュー・差し戻しできる変更単位にする。
コミット、ブランチ作成、push は利用者が行う。エージェントは作業ツリーにファイルとして残す。

| ID | 作業・成果物 | 前提 | 完了条件 |
|---|---|---|---|
| PR0 | 基準状態の記録。HEAD、既存テストの結果、fixture の `inspect` / `generate-policy` 出力、依存グラフ、利用できる Node と Python と git の版 | なし | 変更前の出力と件数が `.local/` に残り、PR7 のバイト一致比較に使える |
| PR1 | 文書チェックの `cargo test` 化。`tests/docs_check.rs`、`check_docs.py` の削除、CI と文書の更新 | PR0 | 文書チェックが `cargo test` に含まれ、Python 版と同じ指摘を出す。CI の明示ステップが消えている |
| PR2 | 現物 MCP サーバの検証基盤。版固定の取得、`examples/policies/`、`tests/real_servers_e2e.rs`、`setup` と `check-server` の sh と ps1、ワークフロー、文書 | PR0 | 3 OS で 4 本の現物サーバが Warden 有りで `initialize` から `tools/call` まで動く。Auditor の拒否、OS 層だけの拒否、`tools-list-hash` の固定が確認できる。配備先でスクリプトが同じ確認を行える |
| PR3 | README と公開面の訂正。解析範囲、位置づけ、OS 差、保証範囲、現物サーバによるクイックスタート、クライアント設定 | PR2 | README だけを読んで、対応する形式と ISA、stdio 特化、OS ごとの強制の差、保証しないことが分かる。クイックスタートの各コマンドを実行して結果を記録した |
| PR4 | tools/list の allowlist フィルタ。監査イベント、日英文書、e2e テスト | PR2 | 通常運用で未許可ツールが tools/list から消え、dry-run では残る。ハッシュ pin が全件で計算されることが負のテストで固定されている。現物サーバでも確認した |
| PR5 | 起動対象ハッシュの文書化と草案出力 | PR2 | ガイドから 4 種別と検査順序が分かる。`generate-policy` の草案に実在ファイルのハッシュが入り、改変後の起動が拒否されることを e2e で確認した。現物の起動形ごとの束縛可否を記録した |
| PR6 | 子プロセス環境の allowlist。ポリシーノード、Warden の適用、日英文書 | PR2 | ノード無しの挙動が不変。ノード有りで列挙した名前と PATH 系だけが子に届くことを 3 OS で確認した。現物サーバの環境変数で確認した |
| PR7 | 依存の向きの固定。葉モジュールの抽出、modules.md、レイヤーテスト | PR4、PR5、PR6 | 循環が 0 本。`inspect` と `generate-policy` の出力が PR0 の記録とバイト一致。テスト件数が減っていない |

基本の着手順は PR0 → PR1 → PR2 → PR3 → PR4 → PR5 → PR6 → PR7 とする。
PR2 を先に置くのは、PR3 のクイックスタートと PR4 以降の現物確認が PR2 の取得基盤と実ポリシーを使うためである。
PR1 は独立しており、いつでも入れられる。PR3 と PR4 は触るファイルが分かれるため並行できる。
PR7 はファイル移動を含むため最後に置き、先行 PR の差分と衝突させない。

## 4. 設計上の確定事項

### 4.1 文書チェック

文書チェックは `tests/docs_check.rs` に移す。`scripts/check_docs.py` と同じ規則
（UTF-8 で BOM なし、LF、ローカルリンクの実在、見出しアンカーの一致）を標準ライブラリと
既存依存の `regex-lite` で実装する。対象ディレクトリも同じにする。CI の明示ステップは
`cargo test` に含まれるため削除する。

### 4.2 現物 MCP サーバの検証基盤

**対象サーバ。** 公式の [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) から、
Node 製 2 本と Python 製 2 本を初期セットとする。

| サーバ | 言語 | 選ぶ理由 | 検証で使う性質 |
|---|---|---|---|
| `@modelcontextprotocol/server-filesystem` | Node | 最も使われるサーバで、ルート引数とパス引数を持つ | Auditor のパス検査、secret-overlay、per-tool の書き込み範囲 |
| `@modelcontextprotocol/server-memory` | Node | 引数に現れないパス（`MEMORY_FILE_PATH` の環境変数）へ自分で書く | Auditor に見えない I/O が OS 層でだけ止まることの証拠。PR6 の環境変数 allowlist の現物 |
| `mcp-server-time` | Python | I/O を持たない最小の Python サーバ | Python ランタイムが Warden 有りで動くことの基準 |
| `mcp-server-git` | Python | 子プロセスとして `git` を実行する | `execve` の許可とリポジトリ外への OS 拒否 |

版は実装時に固定し、作業記録に書く。版を上げるときは `tools-list-hash` を再固定し、ツールの差分を記録する。

**取得。** `tests/fixtures/real_servers/node/` に `package.json` と `package-lock.json` を置き、
`npm ci --ignore-scripts` で取得する。`tests/fixtures/real_servers/python/` に `==` と `--hash` 付きの
`requirements.txt` を置き、`.venv` へ `pip install --require-hashes` で取得する。
取得は cargo の外の操作なので、同じディレクトリの `setup.sh`（Linux/macOS）と `setup.ps1`（Windows）が行う。
`node_modules` と `.venv` は `.gitignore` と `Cargo.toml` の `exclude` に加える。
取得にはネットワークが要る。取得済みでなければ e2e は `common::skip_e2e_test` で抜け、
`MCP_WRIT_REQUIRE_SERVER_TESTS=1` では失敗する。コンテナテストの `MCP_WRIT_REQUIRE_CONTAINER_TESTS` と同じ形である。

**起動形。** Node は `node <node_modules>/<package>/dist/index.js …` を基本にする。`argv[0]` が `node`、
payload がファイルなので、静的解析と `entrypoint-hash` の対象になる。`npx` 形は分類の記録にだけ使う。
Python は `.venv` の `python` で `-m <module>` 形と `<site-packages>/<module>/__main__.py` のパス形の両方を試し、
分類の結果を記録する。基準コミットでは `python -m` と `npx` の payload は Unresolved になる。これは仕様どおりの
挙動であり、PR2 では回避も修正もしない。対応は任意項目とする。

**ポリシー。** `examples/policies/<server>.kdl` に、ツールの allowlist、`side_effect`、per-tool の filesystem と
network、`secret-overlay`、固定した版の `tools-list-hash` を書く。`defaults` の filesystem と syscalls は
ホストごとに違うため例には書かず、テストが解決したインタープリタの位置と観測した syscall から
`host.kdl` を生成し、`extends` で例を継承する。利用者向けには[ポリシー作成ガイド](policy-authoring.md)の
手順で `defaults` を足すよう案内する。例のポリシーはテストが読むため、文書だけの例より腐りにくい。

**シナリオ。** `tests/real_servers_e2e.rs` はサーバごとに次を行う。

1. `generate-policy --live-discovery` が完了し、交渉した `protocolVersion` とツール数を記録する。製品が実装する `2025-11-25` と `2026-07-28` 以外しか話さないサーバは、失敗をそのまま記録する。
2. `run --dry-run` で `initialize`、`tools/list`、許可された `tools/call` が成功する。
3. Warden 有りの `run` で同じ 3 段階が成功する。
4. Auditor の拒否。per-tool の範囲外のパス、または secret-overlay に当たるパスへの `tools/call` が JSON-RPC エラーになる。
5. OS 層だけの拒否。Auditor に見えない I/O が失敗する。memory は `MEMORY_FILE_PATH` を許可外に置いた書き込み、git は許可外のリポジトリ、filesystem はルート内だが `defaults` で許可していない下位ディレクトリの読み取り。結果は `result.isError` か JSON-RPC エラーで返り、監査ログには `tool_call.denied` が無い。
6. `examples/policies/` の `tools-list-hash` が取得した版の `tools/list` と一致する。一致しなければ版か例のどちらかが古い。

3 OS で実施する。Linux は Landlock と seccomp、macOS は `sandbox-exec`、Windows は AppContainer。
インタープリタ向けの読み取りパスは解決した位置から組み立て、固定パスを書かない。
syscall の一覧は Linux で観測して定数に記録し、群ごとに理由をコメントする。

**ランタイム基底。** 観測した syscall 一覧と、読み取りパスの組み立て規則のコメントを
`examples/policies/runtime/node.kdl` と `python.kdl` に `defaults` として置く。ホスト固有のパスは書かない。
テストの `host.kdl` はこの基底を `extends` し、解決したパスだけを足す。利用者も同じ基底を `extends` する。
定数をテストの中に閉じ込めず、利用者が Node と Python のサーバを起動する最初の壁をここで下げる。

**配備先で使うスクリプト。** `scripts/check-server.sh` と `scripts/check-server.ps1` を提供する。
インストール済みの `mcp-writ` だけを使い、`--policy <kdl> [--audit-log <path>] [--call <json>] -- <server command…>` を受けて、
dry-run と Warden 有りの両方で `initialize` と `tools/list` を送り、`--call` があれば 1 回の `tools/call` を送り、
応答と監査ログの末尾を表示して、失敗なら非 0 で終了する。判定は「`result` を含む応答行があるか」と終了コードに留め、
細かい期待値は cargo 側の e2e に置く。2 つのスクリプトは同じ引数と同じ出力形式にする。
ワークフローがこのスクリプトを filesystem サーバに対して実行し、腐らないようにする。

**ワークフロー。** `.github/workflows/mcp-servers.yml` を `go-runtime.yml` と同じ形（`workflow_dispatch` と `workflow_call`）で足し、
`ubuntu-24.04`、`macos-latest`、`windows-latest` で Node と Python を版固定で用意し、`setup` スクリプトを実行し、
`MCP_WRIT_REQUIRE_SERVER_TESTS=1` で e2e を回す。Release の `needs` には加えず、Linux tests と同じく
「タグ前に同じコミットで dispatch する」を releasing.md に書く。Actions の利用方針で重いワークフローを
手動実行に限る既存の判断に合わせる。

### 4.3 tools/list の allowlist フィルタ

適用位置は [verify_and_emit_list](../src/auditor/proxy_tools_list.rs) の digest 記録後、
`build_verified_tools_list_response` の直前とする。
scan、ハッシュ検証、`hash_tools_list`、`record_verified_digest` はすべて全件に対して行う。

可視の判定は `tools/call` と同じ述語を使う。[checker](../src/auditor/checker.rs) 212-223 行の
「`policy.tools` に名前があり `allowed` が真」を関数として切り出し、call 側と list 側で共有する。
ポリシーに無い名前は不可視とする。default-deny と同じ扱いである。
可視ツールが 0 件でも `tools: []` を返し、エラーにしない。

dry-run ではフィルタしない。違反 `tools/call` を転送する dry-run の意味論と揃える。
その代わり隠す対象を監査ログへ `observed` で記録する。
通常運用では隠した名前を 1 イベントで `denied` として記録する。
イベント種別は `EventType::ToolsListFiltered` を追加する。`as_str` は `tools_list.filtered`、
カテゴリは `policy_enforcement`、重大度は `Info`。既存の `ToolsListChanged` は供給網の変化を表す
種別であり、ポリシー執行の結果を相乗りさせない。
`as_str`、カテゴリ、[audit_log](../src/auditor/audit_log.rs) の列挙テストを同じ PR で更新する。

`notifications/tools/list_changed` の再検証も同じ関数を通るため自動的に適用されるが、
再検証後に転送される一覧がフィルタされていることをテストで確認する。

フィルタを無効にする opt-out は設けない。default-deny の一貫性を優先する。
必要になった場合にポリシーノード 1 つで足せるよう、判定関数は `Policy` だけを引数に取る。

この変更は利用者に見える。クライアントが未許可ツールを一覧で見なくなる。
本計画の承認をこの変更の承認とみなす。

### 4.4 起動対象ハッシュ

既存の実装をそのまま使う。4 種別は `binary-hash`、`lockfile-hash`、`entrypoint-hash`、
`docker-manifest-hash`。起動前に verify、bind、reverify の順で検査し、
`binary` か `entrypoint` が無いと bind できず拒否する。
inline eval（`-c` / `-e` / `--eval` / `--command`）は束縛不能として拒否する。

`generate-policy` は `server` ブロックの先頭、`tools-list-hash` の隣に次を出力する。

- `binary-hash`: 解決済みの `argv[0]` の絶対パスとその SHA-256。
- `entrypoint-hash`: 解釈系の場合、payload スクリプトの絶対パスとその SHA-256。
- REVIEW コメント: 配備先で再計算すること、サーバ更新時に再生成すること。

inline eval や payload 不明の場合はハッシュ行を出さず、理由をコメントで残す。
`--binary` で解析対象を別に指定した場合も、ハッシュは起動する `argv[0]` から取る。
`lockfile-hash` は bind に寄与しないため自動出力しない。文書で任意項目として案内する。
生成器へはハッシュ情報を `WorkloadHashes { binary, entrypoint, unbound_reason }` の 1 引数で渡し、
既存のテスト呼び出しは既定値を渡す形に揃える。

文書化する内容: ノードの構文、4 種別の意味、検査順序、entrypoint の束縛規則、
inline eval の扱い、`NoEntries` 警告、失敗時の終了コードと監査イベント、
現物の起動形（`node <path>.js` は束縛可、`python -m` と `npx` は不可）の記録。

### 4.5 子プロセス環境の allowlist

KDL は `defaults` の子ノードとする。

```kdl
defaults {
    environment {
        allow "HOME" "LANG" "LC_ALL"
    }
}
```

ノードが存在すれば制限モードになる。子に渡すのは `PATH`、Windows のシステム変数、
`TMPDIR` 系、列挙した名前だけで、値は親から複写する。列挙した名前が親に無い場合は
設定しない。ノードが無ければ現状どおり継承する。

型は `Policy` に `EnvironmentPolicy { restrict: bool, allowed: Vec<String> }` を追加し、
[SpawnOptions](../src/warden/mod.rs) に列挙名を追加する。
[launch](../src/runtime/launch.rs) が `Policy` から `SpawnOptions` を組み立て、
`spawn_child_async_with` と `spawn_unsandboxed_async_with` に渡す。
`mcp-secure-runner` も同じ経路を使う。

dry-run と `MCP_WRIT_SKIP_SANDBOX` でも環境制限は適用する。
環境は OS サンドボックスではなく起動契約であり、検証モードで親の秘密を子へ漏らす理由が無い。

検証は名前が空でないこと、`=` と NUL を含まないこと。
per-tool、profile、server-defaults の `environment` は per-tool syscalls と同じく読み込み時に拒否する。
`extends` / `include` / `when` の合成は syscalls と同じ「overlay が非空なら置換」とする。
`kdl_canon` は汎用処理のため変更不要だが、ノード有無で正規化ハッシュが変わることをテストで確認する。

live discovery と self-test はポリシー生成前に動くため現状維持とする。
現物では memory サーバの `MEMORY_FILE_PATH` を allowlist に載せた場合と載せない場合で挙動を確認する。

### 4.6 依存の向き

目標とする層を上から下へ定める。各モジュールは自分より下の層だけを参照できる。

| 層 | モジュール |
|---|---|
| 8 | `main.rs`、`bin/mcp-secure-runner.rs` |
| 7 | `commands` |
| 6 | `cli` |
| 5 | `runtime`、`container` |
| 4 | `legislator` |
| 3 | `auditor`、`warden` |
| 2 | `verifier`、`inspector` |
| 1 | `policy` |
| 0 | `error`、`termutil`、`pathutil`、`fspriv`、`tool_def`、`framing`、`protocol`（新）、`audit_log`（移動）、`secret_paths`（移動）、`workload`（新） |

同じ層のモジュール同士は参照しない。基準コミットで同層の相互参照は無い。
`commands` は `cli` の引数型を使うため `cli` より上に置く。

基準コミットで層に反する参照は次のとおり。

| 参照 | 箇所 | 解消方法 |
|---|---|---|
| auditor → legislator | [checker](../src/auditor/checker.rs) 3 行、[proxy_s2c](../src/auditor/proxy_s2c.rs) 70 行、[proxy_list_state](../src/auditor/proxy_list_state.rs) 8 行、[proxy_tools_list](../src/auditor/proxy_tools_list.rs) 286 行と 392 行と 409 行、[proxy_wire](../src/auditor/proxy_wire.rs) 45 行と 312 行と 375 行 | `legislator::protocol` と `tools_list_parse` を葉の `protocol` へ。baseline の読み書きを `verifier` へ |
| verifier → auditor | [hash](../src/verifier/hash.rs) 8 行、[manifest](../src/verifier/manifest.rs) 12 行、[tools_diff](../src/verifier/tools_diff.rs) 5 行、[manifest_rules](../src/verifier/manifest_rules.rs) 13 行 | `auditor::audit_log` と `auditor::secret_paths` を葉へ。`fixture_regression` は `tests/` へ |
| inspector → legislator | [format](../src/inspector/profile/format.rs) 8 行、288 行、296 行、320 行、627 行 | project hint を伴う整形関数を `commands` へ |
| warden → verifier | [windows_sandbox](../src/warden/windows_sandbox.rs) 100 行 | `resolve_command_path` と payload 引数の補助関数を葉の `workload` へ |

`tool_def` と `framing` を `protocol` の下へ移す案は、差分を増やすため今回は行わない。
`policy → termutil` は葉への参照であり許容する。

固定方法: modules.md に層の表と規則を書き、`tests/` に標準ライブラリと既存依存の `regex-lite` で書いた
レイヤーテストを置く。grouped import と入れ子の `use` も展開して検査する。`src` 配下の `crate::<module>` 参照を列挙し、
参照先の層が自分の層以下であることを検査する。例外一覧は空を目標とする。

### 4.7 実行結果で決まる事項

設計としては確定しており、実行して初めて内容が埋まるものは次のとおり。

- PR2 で固定する 4 本のサーバの版、各サーバが交渉する `protocolVersion`、ツール数、`tools-list-hash` の値。
- PR2 のインタープリタ向け `host.kdl` の syscall 一覧と読み取りパス。Linux で観測して定数に記録する。
- PR2 で記録する起動形ごとの分類結果（`node <path>.js`、`npx`、`python -m`、`__main__.py` パス）。
- PR3 のクイックスタートに載せる実出力。README には dry-run までを載せ、Warden 有りの起動は[ポリシー作成ガイド](policy-authoring.md#verification)と `check-server` スクリプトへ誘導する。実行前に文面を確定しない。
- リリース配布物へのリンク。`v*` タグが存在する場合だけ載せる。

## 5. 検証環境と採否条件

| PR | 必要な環境 | 実機で確認する項目 |
|---|---|---|
| PR1 | 任意の 1 OS | Python 版と Rust 版の指摘が同一であること |
| PR2 | Linux、macOS、Windows の 3 OS。Node、Python 3、git、取得のためのネットワーク | 4 本のサーバが 6 段階を通ること。取得前は skip し、`MCP_WRIT_REQUIRE_SERVER_TESTS=1` では失敗すること。`check-server` の sh と ps1 が同じ結果を出すこと |
| PR3 | Linux または macOS。Windows は読み替え行の確認 | クイックスタートの各コマンドの実出力 |
| PR4 | 任意の 1 OS。現物は filesystem サーバ | e2e は OS に依存しない。現物で `tools/list` が絞られること |
| PR5 | 任意の 1 OS | 草案のハッシュが `resolve_command_path` の結果と一致すること。改変後の起動拒否。現物の起動形ごとの束縛可否 |
| PR6 | Linux、macOS、Windows の 3 OS | 継承モードの不変、制限モードでの到達変数。サンドボックス有りと無し。memory サーバの `MEMORY_FILE_PATH` |
| PR7 | 任意の 1 OS でバイト一致。3 OS で `cargo clippy --all-targets` | 出力不変、テスト件数不変 |

採否条件は各 PR に共通で、[開発手順の検証コマンド](development.md#verification)がすべて終了コード 0、
`Cargo.lock` に差分が無いこと、変更した経路を実際に起動して確認したこと。
未実施の環境は未検証として記録し、合格と区別する。

## 6. 対象外・リスク・切り戻し

- PR2 の現物サーバは版を固定しても、Node と Python の版とインストール場所に依存する。読み取りパスは解決した位置から組み立て、固定パスを書かない。失敗時は差分の syscall とパスを記録して定数を更新する。
- PR2 で現物が製品の実装する MCP 版を話さない場合、それは製品側の対応範囲の問題として記録する。fixture 側で版を偽装しない。
- PR2 の取得はネットワークを要する。ローカルで取得していない場合は skip し、CI のワークフローだけが必須にする。
- PR2 の `check-server` スクリプトは薄い包みに留める。判定を増やしたくなったら cargo 側の e2e に足す。
- PR4 はクライアントの見え方を変える。ツール一覧をキャッシュするクライアントは、許可を広げた後に再取得が必要になる。これは既存の `list_changed` 経路と同じ制約であり、文書に書く。
- PR4 のイベント追加は監査ログの消費者に新しい種別を見せる。既存種別の意味は変えない。
- PR5 の草案ハッシュはホスト固有である。別ホストへ持ち出す場合は再計算が必要であることを文書に書く。
- PR6 で allowlist を使うと、クライアントが `env` で渡す API キーは列挙しない限り届かない。既定を制限モードにしない理由はこれである。
- PR7 は挙動を変えない。切り戻しはファイル移動を戻すだけで済む。
- 各 PR は単独で戻せる。PR1 は `check_docs.py` と CI ステップの復元、PR2 は新設ディレクトリとワークフローの削除、PR4 は判定呼び出しの削除、PR5 は出力の削除、PR6 はノード解析の削除で無効化できる。

## 7. 完了時に残すもの

- 各 PR の変更ファイル、設計判断と逸脱、検証コマンドの生の結果、残る制約を `stdio-hardening-results.ja.md` に記録する。
- 4 本の現物サーバについて、版、`protocolVersion`、ツール一覧、`tools-list-hash`、起動形の分類、3 OS の結果の記録。
- `examples/policies/` の実ポリシーと、それを読む e2e。
- modules.md は現在形の設計として更新し、経緯は本計画と作業記録に残す。
- README、ガイド、ポリシー作成ガイド、開発手順の日英が同じ仕様を説明している。
- 任意項目の着手条件が満たされたかを再評価した記録。

## 8. 一次資料

- [MCP 仕様 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers)
- [モジュールガイド](modules.md)
- [ユーザーガイド](guide.md)
- [ポリシー作成ガイド](policy-authoring.md)
- [開発手順](development.md)
- [ARM64 作業記録](archive/arm64-security-results.ja.md)
