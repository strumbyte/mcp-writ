# mcp-writ 改善計画 PR別実装手順書（2026-10-27、2026-11-04 更新）

作成日: 2026-10-27
更新日: 2026-11-04（基準コミットを `f00e28a` に更新 — 後述の「基準以降の変化」参照）

状態: **計画のみ**。各PRの実装・環境更新・コミット・ブランチ作成・push・GitHub PR作成は、別途指示があるまで行いません。以下の共通手順にある実装・PR操作は、将来の実装着手時の手順です。

[改善計画（評価レポート対応版）](improvement-plan-2026-11.ja.md)を目的・範囲・ロードマップの正とし、本書をPR単位の作業順序の正とします。基準コミットは `f00e28a`（`main` の先端、v0.5.1 公開後の検証記録）。対象箇所が基準から変わった場合は、本書の事実・依存・試験を更新します。行番号は `f00e28a` のコード読解で照合しました（ビルド・テスト未実行。性能値はレポート側の Linux 実機計測に依る）。

## 基準以降の変化（`2f87236` → `f00e28a`）と各PRへの影響

計画時の基準 `2f87236`（merge #92）から、v0.5.1 リリースを挟んで #93〜#97 と後続の修正が入りました。各PRの前提への影響は次のとおりです（詳細は各PR節）。

| 基準以降の変更 | 影響するPR |
|---|---|
| **探索（`--live-discovery`）が既定で Warden サンドボックス内に**。`tools_list.rs` の `DiscoveryOptions.restrict_environment` は「Warden 経路（deny-all egress・コマンドツリー＋インタプリタprefixのfs・専用TMPDIR・制限環境・secret overlay）か、文書化された ambient ダウングレードか」を選ぶ意味に変わり、`spawn_server_sandboxed`（同 `1345`）が fail-closed で組み込みポリシー下の spawn を行う。`--unsafe-unsandboxed-discovery` は ambient 継承のダウングレード、`MCP_WRIT_SKIP_SANDBOX` は制限環境のみの plain spawn（`1441`・警告あり） | **E-08 は実装済み**（警告文は「runs inside the Warden sandbox (restricted environment, deny-all egress, private TMPDIR)」に更新済み）。**B-06・PR-09 の中核は実装済み**で、PR-09 は残件（文書・フラグ名の結論記録）のみに縮小 |
| `policy-authoring.md:154`・`policy-authoring.ja.md:120` が「discovery は OS サンドボックス内で動かない」と記述したまま — **実装が先行したため新たな実装との乖離（過少記述）**。README・quickstart の「制限した環境で実行」も実態より弱い記述に | PR-01（E-04 の修正方向が反転＋対象追加） |
| `sandbox require_lifetime_boundary`（既定 `#true`）— カーネル強制の子孫 teardown が取れない経路での supervised launch を拒否（security-fix #93）。`ci.yml`・`linux-tests.yml`・`mcp-servers.yml` に cgroup v2 委譲ステップ追加（`platform-tests.yml` は `workflow_call` の再利用ワークフローとして区別） | PR-07（ワークフロー変更点）、PR-11（調査入力の追加） |
| 信頼ソースの強制：ポリシー読込と、payload-bound entrypoint の native Unix 起動で `fspriv::require_trusted_source_file`（pin.rs `1174`）— 低い信頼の主体が置換できるパス・祖先を持つスクリプトの起動は fail-closed。**guide/policy-authoring/README に未記載の新しい起動拒否** | PR-01（新規 E-10）、PR-02（前提に追加） |
| 監査スキーマ `"2.0"`：`session_id` を全レコードに付与、`policy.loaded` の `source=` を percent-encode、`tools_list.filtered` の outcome を `success` に変更（docs/archive/migration.{md,ja.md} に移行注記） | PR-04（details 追加時の規約） |
| 起動レポートに `correction_candidates`（未呼出ツール・根拠付き拒否ターゲット）とセッション呼出 tally、replaceable-paths opt-out の記録 | PR-04（隣接機能として注記）、PR-08（B-07 関連） |
| `select.rs` に `masked_fs_root`（覆われる木の下の fs **許可**を方式選択時の違反として報告）— 基準時点で既存だが前提の記述を補強。`masked_namespace_root` は相変わらず pin 済み entrypoint のみ（`select.rs:772`、launch.rs `152`、namespaced_run.rs `575`）。`err_stage_hint`（spawn.rs `164`）に exec ENOENT の masked-tree ヒントはまだ無い | PR-05（前提の更新。fs 許可は既に選択時検査済み、ワークロード側は未対応のまま） |
| `verify_server_hashes`（hash.rs `172`）・`bind_launched_workload`（pin.rs `164`）・`reverify_immediately_before_spawn`（同 `1064`）・`snapshot_object`（同 `728`/`764`）の多段読み直しは継続。保持ハンドル＋stamp の機構（`open_pinned`・`record_stamp`・`stamp_unchanged`・`same_open_object`）は既に整っている | PR-02（前提の更新） |
| ワークフローに `schedule` トリガーは依然無し。`test-matrix.md` に Workflow inventory 表（`8`〜）が整備済み。`releasing.md` に release-gate（タグは default branch 到達可能＋maintainer 権限＋`release` 環境の承認） | PR-07（前提の更新） |
| `guide.md`/`guide.ja.md`/`policy-authoring` が更新され、スクリプトの実パス起動と `exe_exec=path`（Windows）の説明は記載済み。Windows 実行ファイル側の「share-mode で保持したハンドルを exec」と読める表現が残る（guide.md `429`・`3362`、guide.ja.md `354`・`1882`、policy-authoring.md `168` ほか） | PR-01（E-06 の範囲を縮小） |
| `docs/modules.md`・`examples/policies/*.kdl`・README 英日・quickstart 英日は無変更。E-01・E-02・E-03・E-05・E-09 は前提どおり残存 | PR-01 |
| v0.5.1 を公開済み（`Cargo.toml` version=0.5.1、公開後検証を test-matrix.md に記録） | リリース節（次版は引き続き v0.6 想定） |
| 結合試験の分割：`tests/plan_report_e2e/`・`tests/dns_gate_e2e/`・`tests/mcp_wire_e2e/`・`tests/wslc_container_e2e/` がディレクトリ形式のターゲットに（`--test` 名は不変） | 検証セットの実行方法は不変 |

本書のPR番号は本計画内の番号です。前身の手順書 [archive/improvement-pr-guide-2026-10.ja.md](archive/improvement-pr-guide-2026-10.ja.md) の PR-01〜36 とは無関係で、前身の PR を指すときは「前身の PR-xx」と書きます。

ロードマップ対応: P0 の PR-01 は次版（v0.6 想定）のタグ前に必須、P1 の PR-02〜05・PR-07 は含める範囲をリリース時に判断、P2 の PR-06・PR-08・PR-10・PR-11 は次版以降です。PR-09 は基準以降に中核が実装済み（探索が既定で Warden 内）で、D-2 の結論も記録済み — 残件は PR-01 の文書に織り込み済みです。バージョンを上げる条件と手順は、作業の流れの中のリリース節（[次版](#release-next)）に記載します — その時点で確認するものなので、先読みは不要です。

## 共通手順

作業開始・実装中の共通条件・Linux の方式選択・PRを閉じるときの規則は、前身の手順書の [共通手順](archive/improvement-pr-guide-2026-10.ja.md) をそのまま適用します。本書で追加する規則は次の 2 点です。

- PRを閉じるとき、実行した試験の件数（pass／fail／skip）を記録する（PR-07 で前身の手順書にも明記する）。
- 性能に関わるPR（PR-02・PR-03）は、修正前の計測値を同じ環境で先に取り、修正後の値と並べて記録する。計測スクリプトはリポジトリに入れず、手順と値だけを残す。

### 検証セット

前身の手順書と同じ ID を使います。

| ID | 内容・コマンド | 実行条件 |
|---|---|---|
| T-BASE | `cargo fmt --all -- --check`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo test --locked --lib --bins`、`cargo doc --locked --no-deps`、`cargo test --locked --doc` | Rustコード変更時。OS固有コードは該当OSでも実行 |
| T-DOC | `cargo test --locked --test docs_check` | 文書・リンク・文字コードの確認 |
| T-LAYER | `cargo test --locked --test module_layering` | モジュール・依存関係変更時 |
| T-POLICY | `cargo test --locked --test kdl_policy_e2e --test environment_e2e --test go_runtime_policy` | ポリシー形式・継承・生成・export の契約変更時 |
| T-NATIVE | `cargo test --locked --test diagnostics_e2e --test path_resolution_e2e --test environment_e2e --test self_test` | 各 OS の該当環境 |
| T-PROTOCOL | `cargo test --locked --test protocol_versions --test tool_enforcement_e2e --test integration --test manifest_fixtures` | MCP 規則・監査イベント変更時 |
| T-IDENTITY | `cargo test --locked --test workload_hash_e2e --test path_resolution_e2e` | 実行対象・検証時点の変更時 |
| T-CONTAINER | `cargo test --locked --test container_e2e --test wrap_image_e2e --test containerize_e2e` | コンテナ経路の変更時 |
| T-VM | 当該方式の実機試験 | 環境情報・実行件数・隔離確認・結果の証拠が必須 |

## 作業の流れ（PR とリリース）

- [PR-01 文書・例の即時修正（環境変数の既定、fetch.kdl、探索の実態、スクリプト起動の表記）](#pr-01)
- [PR-02 ハッシュ固定の起動コスト — 読取回数の削減](#pr-02)
- [PR-03 引数分類の計算量削減](#pr-03)
- [PR-04 ツール単位の自由記述欄の宣言](#pr-04)
- [PR-05 namespaced 経路で覆われる木にあるワークロードの起動前判定](#pr-05)
- [PR-06 草案の `policy version=3` 出力と、ツール単位 deny ワイルドカードの警告](#pr-06)
- [PR-07 CI の定期実行と検証記録の件数](#pr-07)
- [PR-08 運用文書 — ドライバ配置、版の追加手順、直列構成、SECURITY.md](#pr-08)
- [PR-09 探索の OS サンドボックス適用 — 実装済み・結論記録済み（残件は文書のみ、PR-01 内）](#pr-09)
- [PR-10 ファジング基盤と PoC 昇格基準](#pr-10)
- [PR-11 後継機構・新 ABI の評価（調査のみ）](#pr-11)
- [リリース: 次版（v0.6 想定）— PR-01 の完了後（PR-02〜05・07 は含める範囲を判断）](#release-next)

依存と順序は次のとおりです。

| PR | 優先度 | 依存・順序 | 主な変更先 |
|---|---|---|---|
| PR-01 | P0 | 最初に実施（文書・例・コメント・試験コードのみ。境界の過大表示と権限拡大を誘う不変条件を先に正す） | `docs/modules.md`、`examples/policies/{fetch,filesystem}.kdl`、README 英日、quickstart 英日、guide 英日、policy-authoring 英日、`src/runtime/launch.rs`（コメント）、`tests/docs_check.rs`、`tests/kdl_policy_e2e.rs` |
| PR-02 | P1 | なし。D-6 の判断で残すハッシュ段を確定する | `src/verifier/hash.rs`、`src/verifier/hash/pin.rs`、`src/runtime/launch.rs`（スナップショット）、`tests/workload_hash_e2e.rs` |
| PR-03 | P1 | なし。D-4 の判断で削減手段を確定する。PR-04 と `targets.rs` が重なるため PR-04 より先にマージ | `src/auditor/checker/targets.rs`、`src/secret_paths.rs`、`src/pathutil.rs` |
| PR-04 | P1 | PR-03 の後（`targets.rs`・`sub_policy.rs` が重なる）。D-5 の判断で宣言の形を確定する | `src/policy/kdl_parse`、`src/policy/mod.rs`、`src/policy/validator.rs`、`src/auditor/checker/sub_policy.rs`、`src/legislator/policy_generator.rs`、policy-authoring 英日 |
| PR-05 | P1 | なし。D-8 の判断で `auto` の扱いを確定する | `src/warden/select.rs`、`src/warden/namespaced/{launch,init}.rs`、`src/warden/plan/mod.rs`、`src/commands/namespaced_run.rs`、guide 英日、`tests/linux_mechanism_e2e.rs` |
| PR-06 | P2 | PR-04 の後（`kdl_parse`・`policy_generator.rs` が重なる）。D-1・D-3 の判断で着手を決める | `src/legislator/policy_generator.rs`、`src/policy/kdl_parse/leaves.rs`、`src/policy/validator.rs`、`src/commands/check.rs`、policy-authoring 英日 |
| PR-07 | P1 | なし。D-10 の判断で頻度を確定する | `.github/workflows/ci.yml`、`.github/workflows/linux-tests.yml`、`.github/workflows/mcp-servers.yml`、`docs/test-matrix.md`、前身の手順書「PRを閉じるとき」 |
| PR-08 | P2 | PR-01 の後（README・guide が重なる）。D-7 の判断で SECURITY.md を決める | guide 英日、README 英日、`SECURITY.md`（新規）、`docs/releasing.md` |
| PR-09 | —（実装済み） | 中核は v0.5.1 で実装済み。D-2 の結論は改善計画 §5 に記録済み。文書の残件は PR-01 に織り込み済み（E-04・E-10） | （文書は PR-01 の対象と同じ） |
| PR-10 | P2 | なし | `fuzz/`（新規）、`src/framing.rs`・`src/warden/namespaced` の入力境界、guide 英日、`docs/test-matrix.md` |
| PR-11 | P2 | なし。調査のみでコード変更を含まない | `docs/validation/`（調査記録）、改善計画 |

PR-01 を先に実施します。PR-02・PR-03・PR-05・PR-07 は変更先が分かれているので並行できます。PR-04 は PR-03 の後、PR-06 は PR-04 の後、PR-08 は PR-01 の後に着手します。PR-10・PR-11 は他と重なりません。PR-09 は実装・D-2 の結論記録とも済みのため着手対象外です（残る文書追従は PR-01）。

<a id="pr-01"></a>

### PR-01 文書・例の即時修正（環境変数の既定、fetch.kdl、探索の実態、スクリプト起動の表記）

対応論点: 改善計画 §1 E-01〜E-09（E-08 は実装済み）、§3 R-04、新規 E-10。直接依存: なし。着手・公開条件: P0 — 次版のタグ前に必須。最初に実施する。

**目的:** 実装と食い違う記述のうち、保守者を権限拡大へ誘導するもの（E-01）、写すと動かない例（E-03）、境界を実装と違って見せるもの（E-05・E-06・E-04・E-10）を正す。E-04 は v0.5.1 で探索が既定で Warden 内になったため、修正方向が「サンドボックスの外で動くと警告する」から「既定で Warden 内で動くことと、ambient ダウングレードの注意」を書くに変わった。あわせて、同じ乖離が再発したら `docs_check` と例ファイルの読込試験で止まるようにする。コードの挙動は変えない。

**主な変更先:** [modules.md](modules.md)、[examples/policies/fetch.kdl](../examples/policies/fetch.kdl)、[examples/policies/filesystem.kdl](../examples/policies/filesystem.kdl)、README 英日、quickstart 英日、guide 英日、policy-authoring 英日、[runtime/launch.rs](../src/runtime/launch.rs)（コメント）、[tests/docs_check.rs](../tests/docs_check.rs)、[tests/kdl_policy_e2e.rs](../tests/kdl_policy_e2e.rs)

**タスク**

- [x] E-01: modules.md L88–94 を実装に合わせる — `EnvironmentPolicy::default()` は `restrict: true`（[policy/mod.rs](../src/policy/mod.rs) `135-141`）、`runtime/launch.rs` がそれを `SpawnOptions.restrict_environment` に写し、`spawn_env_pairs` は `restrict_environment` のとき制限済みブロックを返す。親環境がそのまま届くのは `inherit-parent #true` を宣言したときだけ。文面はレポート §4.3 の置き換え案を基に、[warden/env.rs](../src/warden/env.rs) の実装と突き合わせて確定する — **済**: `restrict: true` 既定（ノード未宣言でも制限済みブロック）と `inherit-parent #true` による明示的降格の説明に書き換え。同種の残存コメント（src/warden/mod.rs L26-27）も併せて修正
- [x] E-02: filesystem.kdl L44–51 と fetch.kdl L62–67 のコメントを「ノードを省略しても起動契約が同じ制限を適用する。空ノードは意図の明示。親環境が戻るのは `inherit-parent #true` のときだけ」に改める — **済**: 両ファイルとも指示どおりの記述に改訂
- [x] E-03: fetch.kdl の本文 L94–97 からツール単位の `deny host="*"` を外し、`allow host="<FETCH_HOST>"` だけの閉じた許可リストにする。直前のコメントに「ツール単位では `host="*"` は姿勢ではなく通常の規則で、同じブロックの allow より先に評価される」を書く。冒頭コメント L37–44 の例も同様に 1 行にする。policy-authoring 英日の tool `network` の節に同じ規則を明記する（D-1 の警告は PR-06） — **済**: 本文・冒頭例とも `allow` 単独行に改め、deny-first 規則のコメントを追加。policy-authoring.md L520・policy-authoring.ja.md L487 に同規則を明記
- [x] E-03 の試験: `tests/kdl_policy_e2e.rs` に、`examples/policies/*.kdl` を全件読み込み、各ツール単位 `network` の allow 先が同じブロックの deny に覆われていないことを固定する試験を足す（`denied_hosts` に `*` があり `allowed_hosts` が非空なら失敗）。fetch.kdl の `<FETCH_HOST>` は試験側で置換して読み込む — **済**: `example_policies_tool_network_allows_are_reachable` を追加（スクラッチツリーへコピーして `<FETCH_HOST>` 置換、Linux-native 固定ターゲットで読込。`allowed_cidrs`・`egress_rules` も allow 側として判定）。`cargo test --locked --test kdl_policy_e2e` 40/40 PASS。**追記（レビュー指摘対応）**: allow 側の判定を `!egress_rules.is_empty()` から `allow_specified`（宣言の存証）に修正 — deny ルールも同じリストに入るため非空判定では allow 無しの `deny host="*"` 単体で誤発火し得たうえ、合成時の deny-wins プルーニングで遮蔽された allow はロード後のリストから既に消えているため、生存ルールを見ても遮蔽を検出できなかった。あわせて検出範囲を拡張: 「宣言済み allow 側が空 × host/cidr deny 非空」のシグネチャで、ワイルドカードに限らない部分遮蔽（`deny host="*.x"` + `allow host="a.x"` 等）や `deny` + `allow none` の冗長綴りも捕捉し、`deny cidr` の全宛先覆い（`0.0.0.0/0`・`::/0`、生存する allow 側が全て IP リテラル・cidr のとき）は別条件で検査する。一部の allow が生存する混合遮蔽（遮蔽済み＋到達可能が同居）はロード後に原理上区別不能なため対象外
- [x] E-04（修正方向が反転）: README.md L133–135、README.ja.md L117–119、quickstart.md L83–85、quickstart.ja.md L85–87 に、探索が**既定で Warden サンドボックス内で動く**ことを書く — 制限環境（`PATH`、Windows は `SYSTEMROOT`・`WINDIR`・`PATHEXT` も、専用の一時ディレクトリ）、deny-all egress、コマンドツリー＋インタプリタprefixの fs 表面、secret overlay。あわせて `MCP_WRIT_SKIP_SANDBOX`（制限環境のみ）と `--unsafe-unsandboxed-discovery`（ambient 継承）の 2 つのダウングレードを区別し、ambient 側だけに「審査前のサーバーは使い捨ての VM かコンテナの中で」の注意を残す。実装との照合は [tools_list.rs](../src/legislator/tools_list.rs) `243-263`・`528-566`・`1345-1459` を正とする — **済**: 4 文書すべて記述。あわせて guide 英日の `--live-discovery` / `--unsafe-unsandboxed-discovery` オプション表・`check -- <command>` の spawn 説明、`src/commands/check.rs`・`src/cli/parse_check.rs` のコメントも同旨に修正。**追記（レビュー指摘対応）**: `src/cli/mod.rs` の `CheckArgs::command` コメントに同じ古い記述（`restricted environment, no OS sandbox`）が残存していたため同旨に修正
- [x] E-04 の新規乖離: policy-authoring.md L154（`does not run discovery inside an OS sandbox`）と policy-authoring.ja.md L120（同旨）は実装と逆になったため最優先で正す — 既定は Warden 内、`--unsafe-unsandboxed-discovery` が ambient のダウングレード。L155 の `inherit-parent #true` の説明は実装どおりなので触らない — **済**: 既定 Warden 内（制限環境・deny-all egress・private TMPDIR・fs 表面・secret overlay・fail-closed）と 2 ダウングレードの区別、ambient 側への使い捨て VM/コンテナ注意を記述。L155 は未変更
- [ ] ~~E-08（警告文）~~: **実装済み**。`generate_policy.rs` L33–38 の WARNING は「the server runs inside the Warden sandbox (restricted environment, deny-all egress, private TMPDIR)」に更新され、L26–30 の static-only の案内も実態どおり。対象外とする（残る文書更新は E-04）。フラグ名の結論は D-2 に記録する
- [x] E-05: README.md L412–426、README.ja.md L384–397 を、実行ファイル（pin 済みオブジェクトから起動。Windows は share-mode pin を保持したまま実パス）と entrypoint スクリプト（実パスで起動。隙間が閉じるのは Linux namespaced と Windows のみ）を書き分けた文に改める。guide §8.2 の記述と語を揃える。あわせて native Unix の信頼ソースゲート（E-10）への参照を入れる — **済**: 実行ファイル（fd/staged/実パス＋保持中 share-mode ピン）と entrypoint スクリプト（実パス起動＋native Unix 信頼ソースゲート）を書き分け、配置指針も追加
- [x] E-06: guide.md L429・L3358–3373、guide.ja.md L354・L1882、policy-authoring.md L168（および ja 対応箇所）の Windows 実行ファイル側の表記を「share-mode pin を保持したまま実パスで起動」に改める。スクリプト側の実パス起動と `exe_exec=fd|staged|path` の記述は更新済みなので触らない。差し替え防止の効果の記述は変えない — **済**: 計 6 箇所を「share-mode ピンを保持した実パス」表記に修正。スクリプト側記述と差し替え防止の効果説明は未変更
- [x] E-07: `runtime/launch.rs` L176–184 の関数コメントを、pin あり実行ファイル／pin なし実行ファイル／entrypoint スクリプトの 3 通りで書き分ける（レポート §4.3 の置き換え案を基にし、`548-559`・`649-657`・`955-972` の既存コメントと矛盾しないようにする） — **済**: 「splits three ways」で 3 通りに書き分け（pin なし実行ファイルは `resolved_exe` 実パス — `fd_exec_plan` の `None` 分岐と照合済み）
- [x] E-09: guide.md L72・guide.ja.md L72 の構成図 Layer 3 のラベルを「Confused Deputy (deputy role + extraction rules)」相当に改める。本文の攻撃表（L87 付近）は更新済みなので触らない — **済**: 英 `deputy role + extraction rules`・日 `deputy ロール + 抽出規則` に変更。攻撃表は未変更
- [x] E-10（新規、実装先行の未記載）: payload-bound entrypoint の native Unix 起動が `fspriv::require_trusted_source_file`（pin.rs `1172-1181`）を要求することを guide 英日 §8.2・policy-authoring 英日・README 英日の pin の節に書く — 要件（スクリプトとその祖先が低い信頼の主体による置換を拒否すること）、満たさない場合の fail-closed 拒否、namespaced 経路が init の verified mount で例外になること、を明記する。低い信頼の別主体が置換・書込できる場所にスクリプトを置くと起動できないため、配置の指針も添える。ポリシー読込側の同ゲート（policy/loader.rs）は別経路の要件であり、本項目の文書化対象には含めない — **済**: 6 ファイル（guide 英日 §8.2・policy-authoring 英日・README 英日）に要件・fail-closed・namespaced 例外・配置指針（所有者制限ツリー、`MCP_WRIT_ALLOW_REPLACEABLE_PATHS` opt-out）を記述。ポリシー読込側のゲートは未記述のまま
- [x] 再発防止: `tests/docs_check.rs` に「実装と矛盾する既知の文」の不在を固定する否定語句の一覧を足す。最低限、`inherits the full parent environment`／`inherits the whole parent environment`（E-01・E-02。ただし `inherit-parent #true` の説明文は除外できる書き方にする）、`share-mode-held handle on Windows`（E-06）、`in a restricted environment, and records`（E-04）、`does not run discovery inside an OS sandbox` と `OS サンドボックス内での探索では`（E-04 新規乖離）を登録する。一覧は本PRで直した文に限り、一般的な語句は登録しない — **済**: `FORBIDDEN_PHRASES` に指定語句＋`OS サンドボックス内での検出では` 変体を登録。行単位の `inherit-parent` 免除、`improvement-`/`security_report` パス免除、`examples/**/*.kdl` 走査も追加。`cargo test --locked --test docs_check` 11/11 PASS

**検証:** T-DOC、T-POLICY（例ファイルの読込試験）、T-BASE（`launch.rs` のコメント変更があるため）。警告文を固定する既存試験は無い（`tests/` 内に該当文字列の固定は存在しない — `f00e28a` 照合）。

**完了条件:** E-01〜E-07・E-09・E-10 の各箇所が実装と一致し、`docs_check` の否定語句一覧と例ファイルの読込試験が通る。コードの挙動（解析結果・判定・監査）は変わらない。

**移行・戻し方:** 文書・例・コメントの変更のみ。fetch.kdl を継承している利用者は、ツール単位の `deny host="*"` を外すと許可先が通るようになる（従来は全拒否だった）。これは例の修正であり、ポリシー言語の意味は変えない。E-04・E-10 は実装先行でドキュメントが遅れているものの訂正であり、利用者の既存ポリシーには影響しない。

<a id="pr-02"></a>

### PR-02 ハッシュ固定の起動コスト — 読取回数の削減

対応論点: 改善計画 §2 B-05。直接依存: なし。着手・公開条件: P1 — 次版。D-6 の判断で残すハッシュ段を確定する。

**目的:** `binary-hash`／`entrypoint-hash` を宣言した起動で、同じファイルを段階ごとに全読みしている箇所を減らし、保証に必要な「exec する保持オブジェクトから計算したダイジェストが pin と一致する」を 1 回の読取で満たす。検証の順序（verify → bind → reverify → spawn）と fail-closed の判定は変えない。

**前提（HEAD `f00e28a`）:** `verify_server_hashes`（[hash.rs](../src/verifier/hash.rs) `172`、エントリごとに `hash_file` で全読み、`BUFFER_SIZE` 8 KiB）、`bind_launched_workload`（[pin.rs](../src/verifier/hash/pin.rs) `164` — exe を `198`、payload を `281` でそれぞれパス名から全読み）、`reverify_immediately_before_spawn`（同 `1064` — `1071` で bind を丸ごと再実行 = exe+payload の再ハッシュ、さらに保持ハンドルの再ハッシュ `1096`・payload `1205`）、`immutable_snapshot`→`snapshot_object`（`700-723`・`728`/`764` — `io::copy` で複製しながら `hash_open_file` で照合）が、同じ内容を段階ごとに全読みする。基準以降に payload-bound entrypoint の `require_trusted_source_file` ゲート（`1172-1181`）が加わった（判定はするが読み直しはしない）。保持ハンドル＋stamp の機構（`open_pinned`・`record_stamp`・`stamp_unchanged`・`same_open_object` `54`）は既に整っているため、作業はパス名からの冗長な再ハッシュの削減に絞れる。レポートの計測では Python 31 MB を 6 回（178 MiB）、Node.js 119 MiB を 6 回（715 MiB）読み、起動から `initialize` 応答までが 0.86 s／3.3 s（SHA 拡張命令の無い CPU）。payload-bound の解釈型起動では現状その回数を上回る。

**主な変更先:** [verifier/hash.rs](../src/verifier/hash.rs)、[verifier/hash/pin.rs](../src/verifier/hash/pin.rs)、[runtime/launch.rs](../src/runtime/launch.rs)（スナップショット生成）、[tests/workload_hash_e2e.rs](../tests/workload_hash_e2e.rs)、guide 英日 §8.2（起動コストの目安）

**タスク**

- [x] 修正前の計測を記録する: Linux 実機で、ハッシュ固定あり／なしの起動から `initialize` 応答までの時間と、`strace -e read` または `/proc/<pid>/io` の `rchar` で読取量を取る。対象は Python と Node.js の実在サーバー（`tests/real_servers_e2e.rs` の fixture を使う）。SHA 拡張命令の有無（`/proc/cpuinfo` の `sha_ni`）を記録する
- [x] `verify_server_hashes` の段階で、pin 対象の実行ファイルと entrypoint を保持ハンドル（`open_pinned`）で開き、stamp を記録してからハッシュし、ハンドルと stamp・ダイジェストを `VerifiedWorkload`（名称は担当PRで確定）として後段に渡す。`hash.verified`／`hash.mismatch` の監査イベントはこの 1 回で出す
- [x] `bind_launched_workload` と `reverify_immediately_before_spawn` は、パス名から開き直してハッシュする代わりに、保持ハンドルの同一性（`same_open_object`）と stamp の不変を確認する。stamp が変わっていれば内容を再ハッシュして判定する（stamp だけで内容検証を代替しない — D-6）。保持ハンドルを持たない経路（`run-image` など）は従来どおり。`require_trusted_source_file` ゲート（E-10 の対象）は読み直しの対象外として残し、順序（信頼判定 → ハッシュ）を変えない
- [x] スナップショット（`snapshot_object`）は保持ハンドルから複製しながらダイジェストを計算し、複製後の別読みをなくす。複製したバイト列のダイジェストが pin と一致しなければ fail-closed
- [x] `code_identity` の報告（どの検査点を通ったか）は従来どおりの項目を出す。読取回数が減っても「検証した検査点」の表現は変えない
- [x] 修正後の計測を同じ条件で取り、guide 英日 §8.2 に「起動コストの目安（ファイルサイズ・CPU・回数）」として載せる。目標は読取回数 6 → 2、Node.js 119 MiB で 3.3 s → 1.2 s 以下（SHA 拡張命令なし）

**検証:** T-BASE、T-IDENTITY（`workload_hash_e2e` の既存試験 — 差し替え検出・inline eval 拒否・`python -m` 非固定 — が全て通ること）。加えて、hash 中の書き換えを `stamp_unchanged` が検出する既存試験と、保持ハンドルを持たない経路の回帰を対で固定する。デバッグビルドで 30 秒を超えていた Node.js の試験（レポート「評価の前提」）が単独実行で短縮されることを記録する。

**完了条件:** 固定あり起動の読取回数が 2 回以下になり、既存の fail-closed 試験が全て通る。計測値が guide に載る。

**移行・戻し方:** ポリシー・監査スキーマ・CLI は変えない。保持ハンドル方式は前身の PR-16 以降の `exec` 経路と同じ契約で、戻す場合は段階ごとの再ハッシュに戻すだけで判定は同じ。

<a id="pr-03"></a>

### PR-03 引数分類の計算量削減

対応論点: 改善計画 §2 B-03。直接依存: なし（PR-04 より先にマージ）。着手・公開条件: P1 — 次版。D-4 の判断で削減手段を確定する。

**目的:** `tools/call` の引数が大きいときの検査コストを、検査の省略ではなく計算量の削減で下げる。「秘密パスの予約綴りはどの欄名でも検査する」「語彙外の欄の資源らしい文字列は制限契約のあるツールで拒否する」の 2 つの規則は変えない。

**前提（HEAD `f00e28a`）:** [checker/targets.rs](../src/auditor/checker/targets.rs) `328-416` の `classify_target_string` は、全文字列に `normalize_fs_argument` を掛け、`is_secret_path`（[secret_paths.rs](../src/secret_paths.rs) `242-255`）が内部で再度 `normalize_fs_argument` と `reserved_after_normalize`（NFKC 2 回・`resolve_for_authorization` `229`）を実行する。`is_known_payload_field_name`（`409`）はその後。構造は基準時点と不変。レポートの callgrind では 1 MiB の要求 1 回あたり約 24 億命令、`is_secret_path` が約 64%（NFKC 約 48%）、`normalize_fs_argument` が約 49%。

**主な変更先:** [checker/targets.rs](../src/auditor/checker/targets.rs)、[secret_paths.rs](../src/secret_paths.rs)、[pathutil.rs](../src/pathutil.rs)

**タスク**

- [ ] 修正前の計測を記録する: レポートと同じ形（64 B／64 KiB／1 MiB の引数、直結との差分、`MCP_WRIT_SKIP_SANDBOX=1`）で Linux 実機の値を取り、`callgrind` または `perf` で内訳を残す
- [ ] ASCII のみの値では NFKC を省く（NFKC は ASCII に対して恒等。`is_ascii()` の判定は線形 1 回で済む）。非 ASCII を含む値は従来どおり NFKC を 2 回とも行う
- [ ] `classify_target_string` が計算した `normalized` を `is_secret_path` に渡す入口（例: `is_secret_path_normalized(raw, normalized)`）を設け、二重の `normalize_fs_argument` をなくす。`Err(_) => true`（不安定なパーセントエンコードは予約扱い）の fail-closed は維持する
- [ ] `selector_plausible` が偽になる値（区切り・sigil・ドットを含まない）について、正規化の前に判定できる条件を特定し、該当する値では正規化と秘密パス判定を省けるかを検討する。省けるのは「`looks_like_path`・`looks_like_network_target`・`looks_like_host_or_socket`・`is_secret_path` のいずれも真になり得ない」ことを証明できる場合に限る。証明できなければ省かない（D-4）
- [ ] 1 MiB 級の単一文字列で `resolve_for_authorization`（`secret_paths.rs` `229`）がファイルシステムに触れる回数を測り、`matches_reserved_form` の字句判定が偽のときに解決を省けるかを確認する（既存の順序が「字句で真なら即 true、偽なら解決して再判定」なので、解決は省けない可能性が高い — 結果を記録する）
- [ ] 修正後の計測を同じ条件で取り、guide 英日の性能の節（§8 付近）に「引数サイズ別の増分の目安」として載せる。目標は 1 MiB で増分を半減

**検証:** T-BASE（`targets.rs`・`secret_paths.rs`・`pathutil.rs` の既存単体試験 — 特に `%66ile:///`・NUL・不可視 Unicode・NFKC 同形の秘密パスを検出する試験 — が全て通ること）、T-PROTOCOL（`tool_enforcement_e2e`）。非 ASCII の秘密パス（全角・結合文字）が引き続き拒否されることを対で固定する。

**完了条件:** 既存の分類結果（許可・拒否・分類先）が全入力で不変で、1 MiB の引数の増分が修正前の半分以下になる。

**移行・戻し方:** 分類結果は変えない。計算経路の変更のみ。

<a id="pr-04"></a>

### PR-04 ツール単位の自由記述欄の宣言

対応論点: 改善計画 §2 B-04。直接依存: PR-03（`targets.rs`・`sub_policy.rs` が重なる）。着手・公開条件: P1 — 次版。D-5 の判断で宣言の形を確定する。

**目的:** 名前や文章を独自のキーで受け取るサーバー（記憶・課題管理など）で、正当な呼び出しが「宣言されていない資源の指定かもしれない」として拒否される問題に、ポリシー側で「この欄は資源を指さない」と宣言する手段を設ける。宣言は「語彙外の欄の拒否」だけを免除し、秘密パスの予約綴りと明確な資源形（`scheme://`、IP リテラル、`host:port`）の分類は宣言があっても従来どおり行う。

**前提（HEAD `f00e28a`）:** [sub_policy.rs](../src/auditor/checker/sub_policy.rs) `130-171`（拒否自体は `158-171`）は、制限契約（fs 規則・tool `network`・`read_only`・全体の outbound 規則）のあるツールで、`extracted.unclassified` のうち `selector_plausible` な値を拒否する。既知の payload 欄は [pathutil.rs](../src/pathutil.rs) `1118`〜（`is_known_payload_field_name` `1137`）の固定一覧で、ポリシーから足せない。`ToolPolicy`（[policy/mod.rs](../src/policy/mod.rs) `319-357`）に宣言用の欄は無い。回避策の `deputy extract` は資源を束縛する側で、自由記述の宣言には使えない。基準以降に起動レポートの `correction_candidates`（[enforcement/model.rs](../src/enforcement/model.rs) `682-711` — 未呼出ツールと根拠付き拒否ターゲットをセッション終了時に出す）が加わったが、これはレビュー補助であって宣言手段ではなく、B-04 の解にはならない。

**主な変更先:** [policy/kdl_parse](../src/policy/kdl_parse)、[policy/mod.rs](../src/policy/mod.rs)（`ToolPolicy`）、[policy/validator.rs](../src/policy/validator.rs)、[policy/kdl_inherit](../src/policy/kdl_inherit)（継承・v3 の合成）、[checker/sub_policy.rs](../src/auditor/checker/sub_policy.rs)、[checker/targets.rs](../src/auditor/checker/targets.rs)、[legislator/policy_generator.rs](../src/legislator/policy_generator.rs)、policy-authoring 英日、guide 英日 §4

**タスク**

- [ ] 修正前に失敗する再現試験を書く: 制限契約のあるツールに `{"name": "Acme Corp.", "observations": ["Joined in 2021.", "contact alice@example.com"]}` を渡すと拒否され、同じ入力で `.ssh/id_rsa` や `https://evil.example/` を含む値は宣言後も拒否されることを対で固定する
- [ ] ツール単位の宣言を追加する（名称は担当PRで確定。候補: `tool "x" { arguments { opaque "name" "observations" } }`）。`policy version=2` 以上の未知属性拒否に正規登録し、v1 では読込エラーにする。欄名は `params.arguments` の最上位キーと、JSON Pointer（`deputy extract` と同じ記法）の両方を受ける。継承は和集合（v3 の規則と同じ）、v2 でも和集合とする（狭める意味の属性ではないため）
- [ ] 分類側: 宣言された欄の文字列は `TargetSlot::Unclassified` に入れない。ただし `is_secret_path` が真の値、`starts_with_file_scheme`・`looks_like_network_target`・`looks_like_host_or_socket` が真の値は従来どおり分類する（宣言は語彙外の拒否だけを免除する）。`read_only` の URL 拒否も従来どおり
- [ ] `check`／`plan` の表示: 宣言された欄の一覧をツールごとに出し、「この欄は資源らしい文字列でも転送される」ことを運用者に見せる。監査の `tool_call.allowed` の details に宣言で通した欄の件数を残す（値は残さない）。details の追加は監査スキーマ `"2.0"`（`session_id` 全レコード付与・`policy.loaded` `source=` percent-encode 済み）の規約に従い、schema の変更が要る形なら版を上げる判断を記録する
- [ ] `generate-policy`: `args_schema` で `type: string`（配列要素を含む）かつ `format` の無い欄を、コメントアウトした候補（`// arguments { opaque "name" }` と `// REVIEW: opaque: enable only for fields that never carry a path, host or URL`）として出す。有効な KDL としては投入しない。REVIEW の種別台帳（前身の PR-31 の `MarkerKind`）に `opaque-candidate` を足す
- [ ] 文書: policy-authoring 英日の冒頭近く（ポリシーを書き始める前の節）に「引数はどう分類され、何が拒否されるか」と「自由記述の欄の宣言」「`deputy extract` との違い」を移す。guide §4 の該当段落（`guide.md:2311`）から参照する
- [ ] `tests/real_servers_e2e.rs` の memory 系サーバーの試験に、点・`@`・空白を含む正当な値（"Acme Corp."、"contact alice@example.com"）を宣言ありで通し、宣言なしで拒否される対を足す

**検証:** T-BASE、T-POLICY（`kdl_policy_e2e` に新属性の v1 拒否・v2 受理・継承の和集合）、T-PROTOCOL（`tool_enforcement_e2e`）、`tests/real_servers_e2e.rs`。

**完了条件:** 宣言した欄で正当な自由記述が通り、宣言した欄でも秘密パスと明確な資源形は拒否される。宣言の無いポリシーの判定は不変。

**移行・戻し方:** 属性の追加のみ。宣言を書かなければ従来の判定と同じ。旧版バイナリは未知属性として読込を拒否する（黙って無視しない）。

<a id="pr-05"></a>

### PR-05 namespaced 経路で覆われる木にあるワークロードの起動前判定

対応論点: 改善計画 §2 B-08。直接依存: なし。着手・公開条件: P1 — 次版。D-8 の判断で `auto` の扱いを確定する。

**目的:** namespaced 経路の init が私的 tmpfs で覆う木（`/run` は常に、`/tmp` は resolv.conf の bind 元が必要なとき）の下に実行ファイル・ペイロードがあるとき、exec の `ENOENT` ではなく起動前に理由付きで判定する。`auto` は方式選択の設計表どおり native（要求を満たす場合）へ回り、理由を plan／report／監査に残す。

**前提（HEAD `f00e28a`）:** [select.rs](../src/warden/select.rs) `772` の `masked_namespace_root` は、[namespaced/launch.rs](../src/warden/namespaced/launch.rs) `152-164` と [namespaced_run.rs](../src/commands/namespaced_run.rs) `568-598` で pin 済み entrypoint にだけ適用される。実行ファイル本体、pin なしのペイロード、`plan` は検査しない — `SelectionInput`（select.rs `51-87`）にワークロードのパスを渡す欄自体が無い。一方で fs **許可**については `masked_fs_root`（select.rs `697`、glob-aware の表記走査）が `namespaced_policy_violations`（`596-630`）で選択時の違反として既に報告する（基準時点で既存。「ワークロードの可視性」を追加する際の直近の先例）。`/tmp` を覆う理由は [namespaced/init.rs](../src/warden/namespaced/init.rs) の `redirect_resolv_conf`（`294-321`、呼出 `961`、文書 `38-45`）— memfd は `mount(2)` の source にできないため、bind 元を `/tmp` 上の私的 tmpfs に置く。`tmp_mask_planned()` は select.rs `681` に実在する（resolv.conf を canonicalize して判定。試験注入点は未設置）。`err_stage_hint`（namespaced/spawn.rs `164-190`）は proc-mount／unshare／idmap の EPERM にだけヒントを持ち、`exec errno=2` 向けは無い。

**主な変更先:** [warden/select.rs](../src/warden/select.rs)（`decide` の入力）、[warden/namespaced/launch.rs](../src/warden/namespaced/launch.rs)、[warden/namespaced/init.rs](../src/warden/namespaced/init.rs)、[warden/plan/mod.rs](../src/warden/plan/mod.rs)、[commands/namespaced_run.rs](../src/commands/namespaced_run.rs)、guide 英日（Linux の方式選択・§7 切り分け表）、[tests/linux_mechanism_e2e.rs](../tests/linux_mechanism_e2e.rs)

**タスク**

- [ ] 修正前に失敗する再現試験を書く: `/tmp` 配下に置いた pin なしの実行ファイルを `--linux-mechanism namespaced` で起動すると `ERR exec errno=2` になることを fixture で固定し（resolv.conf が `/run` の外にある環境でのみ再現するので、`tmp_mask_planned()` を試験側で強制できる注入点を設ける）、修正後は起動前の理由付き判定になることを対にする
- [ ] `/tmp` を覆う必要性を調べる: bind 元のファイルを、既に私的 tmpfs で覆っている `/run` の下（例: `/run/mcp-writ/resolv.conf`）に置けないかを init の手順で確認する。置けるなら `/tmp` の覆いを外し、「ワークロードの `/tmp` スクラッチをホストから隔離する」効果が要るかを別の判断事項として記録する（本PRでは既定を変えない）。置けない理由があればコメントに書く
- [ ] 方式選択の入力に「ワークロードの可視性」を加える: 解決済み実行ファイル、第 1 ペイロード引数（pin の有無を問わない）、pin 済み entrypoint の 3 つについて `masked_namespace_root` を評価し、該当があれば namespaced を「このワークロードでは利用不可」として `decide` に渡す。`missing` 相当のトークン（例: `workload_masked:/tmp`）を plan の `mechanism` に出す
- [ ] `auto`: namespaced が利用不可として native（要求を満たす場合）を選び、理由を plan／report／`server.connected` の details に残す。native でも要求を満たせなければ従来どおり起動拒否。`namespaced` 明示指定は理由付きで拒否（D-8）
- [ ] 実行時の保険: init の exec 失敗 `ERR exec errno=2` に、前身の PR-35 の `err_stage_hint` と同じ形式で「覆われる木の下にある可能性」のヒントを付ける（起動前判定をすり抜けた経路 — 相対パスや cwd 依存 — 向け）
- [ ] guide 英日: Linux の方式選択の表に「ワークロードが覆われる木の下にある」行を足し、§7 の切り分け表に `workload_masked` の行を足す

**検証:** T-BASE、`tests/linux_mechanism_e2e.rs`（WSL2 実機で既存レグが通ること。`/tmp` 配下の fixture は注入点で `tmp_mask_planned` を強制して固定する）、T-NATIVE、`cargo test --locked --test plan_report_e2e`（`mechanism` の新トークンの契約を固定する。T-NATIVE には含まれないため個別に実行する）。

**完了条件:** `/tmp`／`/run` 配下のワークロードで、`auto` が理由付きで native を選ぶか、`namespaced` 明示指定が理由付きで拒否される。exec の `ENOENT` で終わらない。

**移行・戻し方:** 方式選択の入力の追加。従来「起動時に exec 失敗していた」組み合わせが「選択時に判定される」ようになる。それ以外の選択結果は不変（前身の D-10 と同じ性質）。

<a id="pr-06"></a>

### PR-06 草案の `policy version=3` 出力と、ツール単位 deny ワイルドカードの警告

対応論点: 改善計画 §2 B-02、§1 E-03 の後続（D-1・D-3）。直接依存: PR-04（`kdl_parse`・`policy_generator.rs` が重なる）。着手・公開条件: P2 — 次版以降。

**目的:** (1) `generate-policy` が v3 の草案を出せるようにし、`check` の移行プレビューが生成テンプレート起因で「v3 で失敗」と報告する状態をなくす。(2) ツール単位 `network` の `deny host="*"` が同じブロックの allow を全て覆うことを、読込時と `check` が知らせる。どちらも既定の出力・判定は変えない。

**主な変更先:** [legislator/policy_generator.rs](../src/legislator/policy_generator.rs)、[cli/parse_gen_policy.rs](../src/cli/parse_gen_policy.rs)、[policy/kdl_parse/leaves.rs](../src/policy/kdl_parse/leaves.rs)、[policy/validator.rs](../src/policy/validator.rs)、[commands/check.rs](../src/commands/check.rs)、policy-authoring 英日

**タスク**

- [ ] B-02 の原因を特定する: レポートの事象（v2 草案を v3 で読むと「`require-path #false` には明示的に空の許可リストが要る」で失敗）を、生成テンプレートの fixture で再現する試験を書く
- [ ] `--policy-version 2|3` を `generate-policy` に追加する。既定は 2 で出力不変（前身の PR-32 の snapshot 試験で固定）。3 では `policy version=3` を出し、`require-path #false` のブロックに明示的な空の許可リストを添える（または v3 の検証規則側で「`require-path #false` 単独」を受理すべきかを判断し、受理する場合は検証規則の変更として前身の PR-28 の不変条件 — 子で足した許可が親の許可を含む — に反しないことを確認する）
- [ ] v3 で出した草案を `check` に掛け、`migration` が `null`（v3 のため対象外）になること、v2 で出した草案の `migration.status` が `fields_differ` または `unchanged` になり `simulation_failed` にならないことを固定する
- [ ] D-1: ツール単位 `network` に `deny host="*"` と allow（host／cidr／egress rule）が同居するとき、読込時の警告（前身の PR-24 の継承警告と同じ経路）と `check` の `warnings[]` に「tool-level `deny host="*"` is an ordinary wildcard rule evaluated before every allow in this block — the allow list is already closed; remove the deny」を出す。エラーにはしない。既存ポリシーの判定は不変
- [ ] policy-authoring 英日: `--policy-version` の説明と、ツール単位 `network` の規則（PR-01 で書いた文）への警告の参照を足す

**検証:** T-BASE、T-POLICY、`tests/policy_check_e2e.rs`、`tests/self_test.rs`（v3 草案で enforced run が起動すること）。

**完了条件:** v3 の草案が `check` と `run` を通り、v2 草案の移行プレビューが生成テンプレート起因で失敗しない。ツール単位の deny ワイルドカードが警告される。既定の出力と判定は不変。

**移行・戻し方:** オプション・警告の追加のみ。

<a id="pr-07"></a>

### PR-07 CI の定期実行と検証記録の件数

対応論点: 改善計画 §3 R-06、§2 B-01（公式サーバー試験の定期実行）。直接依存: なし。着手・公開条件: P1 — 次版。D-10 の判断で頻度を確定する。

**目的:** 重い結合テストを含むワークフローを `main` に対して定期実行し、未リリースの先端に対する実行証跡を残す。手動 dispatch と pr-checks.yml（前身の D-1）は変えない。

**前提（HEAD `f00e28a`）:** [ci.yml](../.github/workflows/ci.yml)・[linux-tests.yml](../.github/workflows/linux-tests.yml)・[platform-tests.yml](../.github/workflows/platform-tests.yml)・[mcp-servers.yml](../.github/workflows/mcp-servers.yml) に `schedule` トリガーは依然無い。基準以降、ci.yml・linux-tests.yml・mcp-servers.yml に `require_lifetime_boundary` の実測のため cgroup v2 ルート委譲ステップが加わり、mcp-servers.yml には check-server の replaceable-paths waiver 宣言が入った — 定期実行を足す際はこれらのステップを壊さない。test-matrix.md には Workflow inventory 表（`8`〜、`Trigger` 列で dispatch／call を集約）が既に整っている。レポートは `66e08c9` に対する CI 実行が Actions 一覧に無かったこと、前身の PR-31〜36 の記録に実行件数が無いことを指摘している。

**主な変更先:** `.github/workflows/ci.yml`、`.github/workflows/linux-tests.yml`、`.github/workflows/mcp-servers.yml`、[docs/test-matrix.md](test-matrix.md)、前身の手順書「PRを閉じるとき」

**タスク**

- [ ] `ci.yml` と `linux-tests.yml` に `schedule`（週 1 回、`main`）を加える。`platform-tests.yml` は対象外とする — `workflow_call` で release.yml から呼ばれる再利用ワークフローであり、定期実行を足すと release 経路と二重に走るため（理由を test-matrix.md に書く）。`mcp-servers.yml` は公式サーバーの版更新で壊れやすいので、同じ頻度で加えるか手動のままにするかを担当PRで決め、理由を test-matrix.md に書く。実 AArch64 のレグは self-hosted／有料ランナーの有無で判断する
- [ ] `schedule` 実行の失敗を見落とさない手段を決める（Actions の通知、または README のバッジ）。issue の自動起票はしない（D-10）
- [ ] [test-matrix.md](test-matrix.md) の Workflow inventory（`8`〜）の `Trigger` 列を `schedule` の頻度まで拡張するか `schedule` 列を足し、各ワークフローの頻度と対象ブランチを書く
- [ ] 前身の手順書「PRを閉じるとき」に「実行した試験の件数（pass／fail／skip）を記録する」を明記する。前身の PR-31〜36 の検証欄に、次に実行したときの件数を追記する（遡っての再実行は求めない）
- [ ] [docs/releasing.md](releasing.md) の手順 2（6 ワークフローの成功確認）に「直近の `schedule` 実行が当該コミットかその祖先で成功していること」を足す（release-gate の手順は既に記載済み — 触らない）

**検証:** ワークフローの構文（`actionlint` があれば）、`workflow_dispatch` での試走 1 回。T-DOC。

**完了条件:** `main` の先端に対する結合テストの実行結果が、手動操作なしに週 1 回 Actions に残る。`platform-tests.yml` を含め対象外としたワークフローの除外理由が test-matrix.md に記録されている。

**移行・戻し方:** トリガーの追加のみ。pr-checks.yml と手動 dispatch は不変。

<a id="pr-08"></a>

### PR-08 運用文書 — ドライバ配置、版の追加手順、直列構成、SECURITY.md

対応論点: 改善計画 §2 B-01・B-07、§3 R-01・R-06。直接依存: PR-01（README・guide が重なる）。着手・公開条件: P2 — 次版以降。D-7 の判断で SECURITY.md を決める。

**目的:** 評価レポートが「対策の方向」として挙げた運用面の文書を揃える。コードは変えない。

**主な変更先:** guide 英日、README 英日、`SECURITY.md`（新規）、[docs/releasing.md](releasing.md)、[docs/modules.md](modules.md)

**タスク**

- [ ] B-07: guide 英日の `--isolation` の節に、OS ごとにエンジン（docker／podman／buildah／Apple container）を管理者所有の場所に置く手順を書く — Linux はパッケージ管理の `/usr/bin`、macOS は Homebrew の `/opt/homebrew/bin` が利用者所有になる事情と `MCP_WRIT_*_EXE` の個別指定、Windows は `Program Files` 配下。`MCP_WRIT_ALLOW_REPLACEABLE_DRIVERS=1` は本番で使わないことを再掲する（基準以降に opt-out が起動レポートに記録されるようになった — その記録先の説明も足す）。判定規則自体は guide.md `313-334` に既記載なので、そこから参照する形で運用手順に絞る
- [ ] B-01: MCP の版を追加するときの手順を modules.md または guide の保守者向け節に書く — [protocol/mod.rs](../src/protocol/mod.rs) の版一覧、[policy/mcp.rs](../src/policy/mcp.rs) の通過規則（版・方向・種別・メソッド）、`server/discover`／`initialize` の交渉経路、`tests/protocol_versions.rs`、capability matrix、guide の対応版の記述、の各更新点を列挙する。前身の D-4 の「版の追加は閉じた台帳への追加として別途判断する」を手順の入口にする
- [ ] R-01: guide 英日に、リモート MCP ゲートウェイ製品と直列に置く構成（クライアント → ゲートウェイ → `mcp-writ run` → ローカルサーバー）の例と、どちらが何を担うかの境界を書く。製品名は挙げず、役割（認証・集中管理・応答検査はゲートウェイ、ローカルの隔離・引数検査・監査は mcp-writ）で書く
- [ ] D-7: `SECURITY.md` を置く — 報告窓口（GitHub の private vulnerability reporting）、受付確認と初回評価の目安日数、対象の版（最新リリースと `main`）、PoC 経路（`unotify-run`・`ebpf-run`・`macos-proxy-run`）は対象外、公開までの調整方針。README 英日からリンクする
- [ ] D-9: guide 英日の監査ログの節に「Windows では回転の契機が無く、計画的なセッション再起動で切り替える」を運用手順として補う

**検証:** T-DOC。

**完了条件:** 各手順が文書から読め、SECURITY.md が README から辿れる。

**移行・戻し方:** 文書の追加のみ。

<a id="pr-09"></a>

### PR-09 探索への OS サンドボックス適用 — 実装済み・結論記録済み（残件は文書のみ、PR-01 内）

対応論点: 改善計画 §1 E-08、§2 B-06（D-2 の第 2 段）。状態: **基準 `2f87236` 以降に実装され、v0.5.1 に含まれる**。実装は計画の「opt-in（`--discovery-sandbox`）」とは違う形を取った — 既定で Warden 内、ambient 継承は明示的なダウングレードのみ。より強い既定挙動なので、計画の中核目的は達成済みと判断する。

**実装済みの内容（HEAD `f00e28a` 照合）:**

- 探索の子プロセスは既定で Warden 経由（`tools_list.rs` `spawn_server_sandboxed` `1345-1459`・`discovery_policy` `243-263`・`528-566`）。組み込みプロファイル: deny-all egress、fs は解決済み実行ファイルの prefix／コマンドツリー／インタプリタprefix（`node_modules`・PATH helper・引数の親を含む実行時導出）、書込は専用 TMPDIR のみ、制限環境、secret overlay 有効
- ポリシー構築は blocking pool 上で失敗時 fail-closed、子プロセスは `RunningChild` で子孫まで所有。`MCP_WRIT_SKIP_SANDBOX` は OS サンドボックスと子孫プロセスの寿命管理を外し、制限環境と専用 TMPDIR は維持、`--unsafe-unsandboxed-discovery` が ambient 継承のフルダウングレード
- 警告文・static-only 案内は実態どおりに更新済み（E-08 解消）
- 層の規則: 実装は `tools_list.rs` が `Warden::spawn_child_async_exe_with` を直接呼ぶ形。計画の「commands 層から stdio を渡す」分離は取らなかった — T-LAYER で許容されていることを確認し、判断を記録する

**残件（コード変更・記録作業とも無し）:**

- D-2 の結論は改善計画 §5 に記録済み: 「既定で Warden 内、`--unsafe-unsandboxed-discovery` が唯一の ambient ダウングレード」で着地し、`--inherit-ambient-environment` への改名は「OS サンドボックスまで外す実態を過小表示する」として不採用
- 文書の追従は PR-01 の E-04・E-10 に織り込み済み（本項目では触らない）

**検証:** 実装済み部分は v0.5.1 の検証記録で確認済み。

**完了条件:** 充足済み — 実装は v0.5.1 に含まれ、D-2 の結論は改善計画 §5 に記録済み。文書の追従（E-04・E-10）は PR-01 の完了条件に含まれる。

**移行・戻し方:** 実装は既にリリース済み。本項目は記録のみ。

<a id="pr-10"></a>

### PR-10 ファジング基盤と PoC 昇格基準

対応論点: 改善計画 §3 R-07。直接依存: なし。着手・公開条件: P2 — 次版以降。

**目的:** 攻撃者の入力を最初に扱う境界コード（フレーミング、JSON-RPC の解釈、namespaced プロキシのパケット解析、DNS ゲートの応答解析）にファジングの入口を設け、PoC 経路を「採用済み」に上げる基準を文書化する。

**主な変更先:** `fuzz/`（新規、`cargo-fuzz`。ワークスペースには含めず `Cargo.toml` の `exclude` に置く）、[framing.rs](../src/framing.rs)、[protocol](../src/protocol)、[warden/namespaced](../src/warden/namespaced)（ユーザー空間 TCP スタックの入力境界）、[dnsgate](../src/dnsgate)、guide 英日 §8、[docs/test-matrix.md](test-matrix.md)

**タスク**

- [ ] ファジング対象を列挙し、純粋関数として切り出せる入口（バイト列 → 解析結果）を特定する。OS 資源に触れる経路は対象外にする
- [ ] `fuzz/fuzz_targets/` に、フレーミング（`--max-frame-bytes` 境界を含む）、JSON-RPC の解釈（`protocol`）、namespaced プロキシの TCP／UDP／DNS パケット解析、DNS ゲートの応答解析の各ターゲットを置く。ワークフローは手動 dispatch（`fuzz.yml`）で、時間上限を設けて走らせ、クラッシュ入力は artifact に残す
- [ ] 見つかった不具合は本PRでは直さず、再現 fixture を単体試験に移して別PRで直す（本PRは基盤のみ）
- [ ] guide 英日 §8 に「PoC 経路を採用済みに上げる基準」を書く — 実機記録のある OS／カーネルの範囲、ファジングの実施、拒否監査の網羅、`plan`／`report`／JSONL の一致、文書の限界開示、の各条件と、現時点の各 PoC（`unotify-run`・`ebpf-run`・`macos-proxy-run`）の充足状況
- [ ] test-matrix.md に `fuzz.yml` を登録する

**検証:** ファジングの各ターゲットが短時間（CI で 5 分程度）走り切ること。T-DOC。

**完了条件:** 境界コードのファジングが手動 dispatch で実行でき、PoC の昇格基準が文書から読める。

**移行・戻し方:** 製品コードの変更は入口の切り出し（純粋関数化）に限り、挙動は変えない。

<a id="pr-11"></a>

### PR-11 後継機構・新 ABI の評価（調査のみ）

対応論点: 改善計画 §3 R-02。直接依存: なし。着手・公開条件: P2 — 次版以降。コード変更を含まない。

**目的:** OS 間の機能差を埋める方針のもとで、評価レポートが挙げた後継機構と新しい ABI が、既存の OS サンドボックスを維持したまま差を縮める手段になるかを調べ、採否と着手条件を記録する。結果は microVM 隔離強化の別計画の入力にもなる。

**調査対象:**

- Windows: Microsoft Execution Containers（2026-10-07 GA）。AppContainer が持たない宛先単位の通信制御、PSEC の preview-documented な属性への依存を減らせるか、非特権で使えるか、Windows の版要件
- macOS: Endpoint Security の `es_new_descendants_client`（macOS 27 以降、`com.apple.developer.endpoint-security.client` entitlement）。sandbox-exec の非推奨に対する代替になり得るか、entitlement の取得・配布の条件、ツール単位の規則や syscall 制限をどこまで表現できるか
- Linux: Landlock ABI v10（Linux 7.2、UDP の制限）・v11（7.3）。`landlock` クレートの対応版の公開状況、`deny_all_others` 時の UDP socket 拒否（seccomp）を Landlock に置き換えられるか、capability matrix への反映
- Ubuntu 24.04 以降の非特権 user namespace 制限（AppArmor）に対する、`auto` の実機挙動と文書の案内（`plan` で判定し、強い境界が要るなら VM 隔離経路）の妥当性

**タスク**

- [ ] 各機構の一次ソース（公式文書・ヘッダ・カーネルの `syscalls.c`・クレートの CHANGELOG）を読み、表現できる制御を capability matrix の項目（fs・network 宛先・syscall・IPC・process）に対応付ける
- [ ] 実機で試せるもの（Linux の新 ABI、Windows の GA 機能）は最小の試作で確認し、環境・結果を `docs/validation/` に記録する。試せないもの（macOS 27 の entitlement）は未確認と記す
- [ ] 採否と着手条件（OS の版・配布要件・特権要否・既存経路との共存）を改善計画に追記する。採用する場合は新しい PR として起票し、本PRでは実装しない

**検証:** 調査記録の T-DOC のみ。

**完了条件:** 調査対象ごとに「採用／見送り／保留と解除条件」が記録され、改善計画のロードマップに反映される。

**移行・戻し方:** コード変更なし。

<a id="release-next"></a>

### リリース: 次版（v0.6 想定）— PR-01 の完了後（PR-02〜05・07 は含める範囲を判断）

実装PRではなく、ここに到達した時点で確認する条件と手順です。バージョン更新・タグ付け・リリース実行は git／リリース操作のため、実施は別途指示を受けてから行います。

**現状（`f00e28a` 時点）:** `0.5.1` がリリース・検証済み（`3530b5a` で版更新、`f00e28a` で post-publication verification 記録）。v0.5.1 には PR-09 の中核（探索の既定 Warden 化）・E-08・監査スキーマ 2.0・`require_lifetime_boundary`・信頼ソースゲート・`correction_candidates` 等が既に含まれる。次版の起点はこの v0.5.1 以降のコミット。

**到達条件 — 全て満たしたらバージョンを上げる**

- [ ] PR-01（P0）がマージ済み
- [ ] PR-02〜05・PR-07（P1）のうち当該リリースに含める範囲を決め、マージ済み
- [ ] 前身の手順書の PR-30〜36（次版の範囲）がマージ済み — `2f87236` 時点で全てマージ済み
- [x] PR-09 の残件（D-2 の結論記録）が反映済み — 実装は v0.5.1 に含まれ、結論は改善計画 §5 に記録済み
- [ ] 判断事項 D-1〜D-10（改善計画 §5）のうち、含める PR に関わるものの結論が記録されている
- [ ] 含める項目が確定した時点で版番号を決めた
- [ ] PR-01 で改めた境界の記述（スクリプト起動・探索の実態・環境変数の既定）が、当該コミットの実装と照合済み
- [ ] PR-07 を含める場合、直近の `schedule` 実行が当該コミットかその祖先で成功している

**バージョン更新の手順**

- [ ] [Cargo.toml](../Cargo.toml) の `version` を確定した版に更新し、`Cargo.lock` を再生成する
- [ ] 最新コミットで T-BASE・T-DOC・該当する実機記録を再確認し、実行件数を記録する
- [ ] タグ `vX.Y.Z` を付ける — push 前に当該コミットで 4 検証ワークフロー＋手動 dispatch の linux-tests・MCP server verification の成功が前提（[releasing.md](releasing.md) 手順 2）
- [ ] リリースノートに「この版で保証する制御」と「残る限界」（改善計画 §3 の対応状況）を明記する。PR-01 の README 修正（スクリプト起動の隙間・探索の実態）は「記述の訂正」として明示する

## 実装結果として残す記録

前身の手順書と同じ項目を残します。調査だけで終えたPR（PR-11）にも、未確認事項と後続PRの開始条件を記録してください。

| 項目 | 記載内容 |
|---|---|
| 対象 | 実装コミット、前提PR、改善計画の節番号 |
| 環境 | CLIホスト、実行基盤、対象OS／arch、カーネル、エンジン、イメージの版 |
| 実行 | 再現コマンド、必要条件、対象試験と実行件数（pass／fail／skip） |
| 結果 | 成功・拒否・失敗・スキップ・未確認を区別 |
| 制御 | 適用予定、観測、取得根拠、残る制約、制御の配置 |
| 監査 | emit されたイベント、details の内容、観測不能な経路の扱い |
| 互換性 | 既存利用者への変更、ポリシー移行、旧版との組み合わせ |
| 資源 | 必要な測定の結果と基準。性能PRは修正前後の値を並べる。未測定は未測定と記載 |
| 後始末 | 子・孫プロセス、一時領域、ハンドル、変更した設定 |
| 次の判断 | 完了、後続可、条件付き、保留。保留の解除に必要な具体的条件 |

手順書を更新した場合は、[改善計画](improvement-plan-2026-11.ja.md)のロードマップ（§6）との整合も合わせます。実装済みかどうかは本書の存在から判断せず、該当PRの実装と試験記録で判断してください。
