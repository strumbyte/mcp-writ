# 改善計画 — 評価レポート (2026-10-27) 対応版

対象: `main` の先端 `2f87236`（merge #92、2026-10-27）。多角的評価レポート
（`mcp-writ-evaluation-2026-10-27.md`。評価対象は PR-36 ブランチの先端 `66e08c9`）の
§4.1〜§4.3 と、`116a111` 評価（[assessment-116a111.ja.md](assessment-116a111.ja.md)）の
残件を、コード読解で突き合わせて計画化したもの。`2f87236` は `66e08c9` を含み、
以降のソース差分は無い。

PR 単位の作業順序は [improvement-pr-guide-2026-11.ja.md](improvement-pr-guide-2026-11.ja.md) を参照。

前身の計画は [archive/improvement-plan-2026-10.ja.md](archive/improvement-plan-2026-10.ja.md)（2026-10-07 評価メモ対応、§8 外部レビュー対応、§9 実運用検証フィードバック対応）。本書はそれを置き換えず、`2f87236` 以降の作業だけを扱う。前身の計画の PR-01〜36 はすべてマージ済み。

方針（2026-10-27 確認）: 既存の各 OS サンドボックスは維持し、OS 間の機能差を埋めて使いやすくする。microVM 隔離の強化は既存の `--isolation` バックエンドの延長として別途計画し、本書には含めない。本書で「使いやすくする」変更（自由記述欄の宣言、探索の警告、起動前判定）は、fail-closed の原則を崩さない範囲に限る。

設計原則（前身の計画と同じ）:

- 通信の**中身は見ない**。制御するのは**宛先**だけ（制御面の延長）
- 宛先制御は **ドメイン層 + IP 層** の 2 層。片方しか効かない経路を「ドメイン制御あり」と表示しない
- 非保証・限界は隠さず仕様として開示する
- 監査に残らない挙動（バイパス・スキップ・ダイヤル低下）は「無かったこと」にしない

---

## 0. 照合の前提

| 略称 | 内容 |
|---|---|
| レポート | 多角的評価レポート（2026-10-27、`66e08c9`）。§1 概要、§2 他製品比較、§3 アーキテクチャ、§4 課題・リスク（4.1 ボトルネック、4.2 リスク、4.3 文書修正提案） |
| `116a111` 評価 | [assessment-116a111.ja.md](assessment-116a111.ja.md) の A1〜A5・B1・B2・C1・C2 |

- レポートの §1〜§3 は、技術的な指摘に当たる部分（文書の乖離、CI の範囲、報告窓口、Landlock ABI の追従）だけを扱う。市場・比較・開発者数そのものは扱わない。
- 照合はコード読解による（Windows ホスト、ビルド・テスト未実行）。レポートの実測（引数 1 MiB で +221〜255 ms、ハッシュ固定で Python 0.86 s / Node.js 3.3 s、fetch.kdl の拒否再現）は、レポート側の Linux 実機結果に依る。このため性能系 PR の最初のタスクを「修正前の計測値を手元で再現し記録する」にする。
- `116a111` 評価の 9 項目は、`2f87236` の静的照合で A1・A2・A3・A5・B1・B2 が実装着地、A4・C2 が一部、C1 が保留と判定した。残件のうち本書で扱うのは、構成図の Layer 3 ラベル（E-09）だけ。README の「配布済み」の記述は、Releases に v0.2.0〜v0.5.0 が公開されていることをレポートの公開状況で確認したため、乖離なしとして閉じる。
- 照合の過程で見つかった、レポートに無い問題は「新規」と記す。

### 0.1 優先度の基準

前身の計画 §8.1 と同じ基準を、次版（v0.6 想定）に読み替える。

| 優先度 | 基準 | リリースとの関係 |
|---|---|---|
| P0 | 境界の過大表示、権限の拡大、一般的な公式サーバーが既定で動かない、検証基盤が失敗を隠す | 次版のタグ前に必須 |
| P1 | 誤操作を誘う仕様、診断不足、試験の網羅漏れ、運用上の明確なコスト | 次版に含めるのが望ましいが、タグは止めない |
| P2 | 運用改善、保守性、調査 | 次版以降 |

## 1. 文書・例の乖離（レポート §4.3、`116a111` 残件）

| ID | 指摘（出典） | HEAD での判定 | 優先度 | PR |
|---|---|---|---|---|
| E-01 | [modules.md](modules.md) L91–94 の不変条件が「`environment` ノードが無ければ親環境を全部継承し、`spawn_env_pairs` は `None` を返し続けなければならない」と、実装（`EnvironmentPolicy::default()` の `restrict: true`、PR-12 以降の既定制限）の逆を書いている（§4.3） | **確認**。[policy/mod.rs](../src/policy/mod.rs) `113-122` は `restrict: true` を既定にし、[runtime/launch.rs](../src/runtime/launch.rs) がそれを `SpawnOptions` に写す。保守者がこの文に従って直すと権限の拡大になる | P0 | PR-01 |
| E-02 | [examples/policies/filesystem.kdl](../examples/policies/filesystem.kdl) L45–49 と [fetch.kdl](../examples/policies/fetch.kdl) L63–64 のコメントが「ノードを省略すると親環境を全部継承する」と書く（§4.3） | **確認**。filesystem.kdl は既定制限（`baac817`）より前の文が残存、fetch.kdl は後から同じ誤りで新規に書かれた | P1 | PR-01 |
| E-03 | fetch.kdl のツール単位 `network` が `deny host="*"` と `allow host="<FETCH_HOST>"` を並べており、写すと許可先も拒否される（§4.3） | **確認（コード読解）**。[kdl_parse/leaves.rs](../src/policy/kdl_parse/leaves.rs) `683-689` はツール単位の `host="*"` を姿勢ではなく通常のワイルドカード規則として `denied_hosts` に入れ、[checker/sub_policy.rs](../src/auditor/checker/sub_policy.rs) `352-361` が deny を先に評価する。`tests/real_servers_e2e.rs` のツール単位は `allow` だけで、例ファイル自体を読み込む試験は無い | P0 | PR-01（例の修正・例ファイルの読込試験）、PR-06（ローダ警告 — D-1） |
| E-04 | README.md L134–135、README.ja.md L118–119、quickstart.md L83–84、quickstart.ja.md L85–86 が探索を「制限した環境で実行」とだけ書き、OS サンドボックスの外で動くことを伝えていない（§4.3・§4.1） | **確認**。[legislator/tools_list.rs](../src/legislator/tools_list.rs) `430-506` は `tokio::process::Command` に `env_clear` と専用 TMPDIR を与えるだけで Warden を通さない | P1 | PR-01 |
| E-05 | README.md L412–421、README.ja.md L389–391 が、ハッシュ固定したスクリプトも pin 済みオブジェクトから起動すると読める（§4.3・§4.2） | **確認**。`9ecee0e`（2026-10-24）以降、entrypoint スクリプトは実パスで起動する。guide 英日・policy-authoring は更新済み、README 英日だけが未更新。境界の過大表示に当たる | P0 | PR-01 |
| E-06 | guide.md L429・L3298、guide.ja.md L354・L1875、policy-authoring.md L167 が Windows でも「share-mode で保持したハンドル」を exec すると読める。実装は share-mode pin を保持したまま実パスで起動（§4.3） | **確認**。差し替え防止の効果は同じで、表記の精度の問題 | P2 | PR-01 |
| E-07 | [runtime/launch.rs](../src/runtime/launch.rs) L170–177 の関数コメントが、実行ファイルとスクリプトの起動方法の違いを書き分けていない（§4.3） | **確認** | P2 | PR-01 |
| E-08 | [commands/generate_policy.rs](../src/commands/generate_policy.rs) L33–38 の警告が環境の制限だけを伝え、OS サンドボックスの外で動くことを伝えない。フラグ名 `--unsafe-unsandboxed-discovery` は既定がサンドボックス内と読める（§4.3・§4.1） | **確認**。フラグが切り替えるのは `restrict_environment` のみ（同 L40） | P1（警告文）／P2（フラグ名・探索へのサンドボックス適用 — D-2） | PR-01、PR-09 |
| E-09 | guide 英日の構成図 Layer 3 が「Confused Deputy (fixed tool names)」のまま（`116a111` 評価 A4 の残件） | **確認**。guide.md L72・guide.ja.md L72。`deputy role=` と抽出規則（schema v2）で役割は設定可能になっており、本文の攻撃表は更新済み | P2 | PR-01 |

## 2. 本番運用のボトルネック（レポート §4.1）

| ID | 指摘（出典） | HEAD での判定 | 優先度 | PR |
|---|---|---|---|---|
| B-01 | 対応する MCP の版が 2 つだけで、改訂のたびに台帳とプロトコル処理の改修が要る | **設計どおり**（閉じた台帳。前身の計画 N-11・D-4 で決定済み）。版を追加する手順は文書化されていない。公式サーバーとの組み合わせ試験は [mcp-servers.yml](../.github/workflows/mcp-servers.yml) にあるが手動起動 | P2 | PR-08（手順の文書化）、PR-07（定期実行） |
| B-02 | ポリシーの作成と維持の手間。`generate-policy` の草案は `version=2` のまま（[policy_generator.rs](../src/legislator/policy_generator.rs) L133）。`check` の移行プレビューが v3 で読込失敗を報告する例（`require-path #false` に明示的な空の許可リストが要る） | **確認**。前身の PR-28・PR-36 で v3 と移行プレビューは揃ったが、草案を v3 で出す選択肢が無い。プレビューの失敗理由は、生成テンプレートの `require-path #false` が v3 の検証規則と噛み合わないため（**新規**） | P2 | PR-06（D-3） |
| B-03 | 大きな引数の検査コスト。1 MiB で +221〜255 ms、処理命令の約 97% が `walk_json_targets` 配下、うち `is_secret_path`（NFKC 約 48%）と `normalize_fs_argument` が主 | **確認（コード読解）**。[checker/targets.rs](../src/auditor/checker/targets.rs) `328-416` は全文字列に `normalize_fs_argument` を掛け、`is_secret_path` が内部で再度 `normalize_fs_argument` と NFKC を実行する（[secret_paths.rs](../src/secret_paths.rs) `220-254`）。欄の種類（`is_known_payload_field_name`）を見るのは秘密パス判定の後（`404-411`）。秘密パスを「どの欄名でも」検査するのは F66/F11/F12 対策の仕様で、省略できない | P1 | PR-03（D-4） |
| B-04 | 正当な引数の拒否。独自キーの "Acme Corp."、"Joined in 2021."、"contact alice@example.com" が「宣言されていない資源の指定かもしれない」として拒否される。回避策は per-tool `deputy extract` か欄名の変更で、他者のサーバーの欄名は変えられない | **確認（設計どおり）**。[sub_policy.rs](../src/auditor/checker/sub_policy.rs) `130-171` は、制限契約（fs 規則・tool `network`・`read_only`・全体の outbound 規則）があるツールで、語彙外の欄にある `selector_plausible` な文字列を拒否する。全体で `deny host="*"` を書くと全ツールが対象になる。「資源を指さない自由記述の欄」をツール単位で宣言する手段は無い（`deputy extract` は逆に資源を束縛する側） | P1 | PR-04（D-5） |
| B-05 | ハッシュ固定の起動コスト。Python 31 MB で 0.86 s、Node.js 119 MiB で 3.3 s。起動までにインタプリタを 6 回読み直す | **確認（コード読解）**。`verify_hashes`（[hash.rs](../src/verifier/hash.rs) `95`・`195`）→ `bind_launched_workload`（[pin.rs](../src/verifier/hash/pin.rs) `198`・`281`）→ `reverify_immediately_before_spawn` が bind を再実行（同 `1057`）→ 保持ハンドルの再ハッシュ（`1081`・`1161`）→ スナップショットの照合（`708`）と、同じ内容を段階ごとに全読みする。保証に必要なのは「exec する保持オブジェクトから計算したダイジェストが pin と一致すること」で、パス名から開き直す途中段のハッシュは冗長 | P1 | PR-02（D-6） |
| B-06 | ポリシー生成時のサーバー実行が OS サンドボックスの外で動く。dry-run には隔離環境で実行する注意があるが探索には無い | **確認**（E-04・E-08 と同根） | P1（警告・文書）／P2（探索への Warden 適用） | PR-01、PR-09 |
| B-07 | 隔離用ドライバの解決規則（管理者所有の場所からのみ解決、#85）。Homebrew や `~/.local/bin` のエンジンは既定で使えず、全体を緩める回避策を本番に持ち込む恐れ | **設計どおり**（security-fix）。OS ごとにエンジンを管理者所有の場所に置く手順が文書に無い | P2 | PR-08 |
| B-08 | namespaced 経路で `/etc/resolv.conf` が `/run` の外にあると `/tmp` を専用 tmpfs で覆う。`/tmp` 配下の固定していない実行ファイルは `ERR exec errno=2` で失敗する | **確認**。[select.rs](../src/warden/select.rs) `700-712` の `masked_namespace_root` は、[namespaced/launch.rs](../src/warden/namespaced/launch.rs) `152-163` と `namespaced_run.rs` `555` で pin 済み entrypoint にだけ適用され、実行ファイル本体・pin なしのペイロード・`plan` では検査されない（**新規**） | P1 | PR-05（D-8） |

## 3. 拡張・長期運用のリスク（レポート §4.2）

| ID | 指摘（出典） | HEAD での判定 | 優先度 | PR |
|---|---|---|---|---|
| R-01 | stdio 限定。リモート MCP と集中管理はカバーしない | **非目標**（§7）。ゲートウェイ製品と直列に置く構成例は無い | P2 | PR-08（構成例のみ） |
| R-02 | OS ごとの保証差（macOS の sandbox-exec は非推奨、Windows AppContainer は宛先制御不可、Ubuntu 24.04 は非特権 userns を既定で制限）。後継機構として Microsoft Execution Containers（2026-10-07 GA）と macOS Endpoint Security の `es_new_descendants_client`（macOS 27 以降）を挙げる | **設計どおり開示済み**（capability matrix・guide の OS 別表）。後継機構の評価は未着手。Landlock も ABI v9 までで、v10（UDP 制限、Linux 7.2）はクレート 0.4.7 に未収録 | P2 | PR-11（調査のみ） |
| R-03 | ツール単位の OS 隔離は構造的に不可能 | **設計どおり開示済み**（README L430–438、guide §8.1、前身の D-6）。対応しない | — | — |
| R-04 | ハッシュ固定したスクリプトは実パスで起動し、隙間が閉じるのは namespaced と Windows のみ | **設計どおり開示済み**（guide §8.2）。README 英日の未更新は E-05 | — | PR-01 |
| R-05 | 監査ログの運用。Windows に再オープンの契機が無い。容量枯渇は fail-closed で復帰しない | **設計どおり**（前身の PR-27 の決定）。Windows の再オープン契機は判断事項として記録する | P2 | —（D-9） |
| R-06 | 体制と成熟度。SECURITY.md が無い。26 の結合テストを含む CI は手動起動で、PR ごとは fmt・clippy・単体＋4 結合のみ。前身の PR-31〜36 の記録に実行件数が無い | **確認**。リポジトリに `SECURITY.md` は無い。[ci.yml](../.github/workflows/ci.yml)・[linux-tests.yml](../.github/workflows/linux-tests.yml) に `schedule` トリガーは無い。`66e08c9` に対する CI 実行は Actions 一覧に無かった（レポート） | P1（定期実行）／P2（窓口） | PR-07（D-10）、PR-08（D-7） |
| R-07 | PoC 経路（`unotify-run`・`ebpf-run`・`macos-proxy-run`）と境界コード。ユーザー空間 TCP スタックのファジングは未実施と開示。PoC を採用済みに上げる基準が無い | **設計どおり開示済み**（guide L3480–3497）。ファジング基盤と昇格基準は未整備 | P2 | PR-10 |

## 4. レポートの対策案との差分

- B-03 は検査の省略ではなく計算量の削減で対応する。秘密パスの「どの欄名でも検査する」規則と、語彙外の欄の fail-closed は変えない（D-4）。
- B-04 は「自由記述の欄」をポリシーで宣言できるようにするが、宣言した欄でも秘密パスの予約綴りの検査は残す（D-5）。
- B-05 は「1 回のハッシュ計算を使い回す」のうち、exec する保持オブジェクトからの計算を最後に残し、パス名から開き直す途中段のハッシュを減らす。stamp（inode・サイズ・mtime）だけで内容検証を代替しない（D-6）。
- B-08 は `plan` での検査表示に加えて、`auto` の方式選択に反映する（D-8）。
- E-08 のフラグ名は、既存名を互換のため残したうえで実態に合う名前を追加する（D-2）。

## 5. 判断事項

| ID | 論点 | 推奨 | 代替 |
|---|---|---|---|
| D-1 | ツール単位 `network` で `deny host="*"` と `allow host=` が同居するとき、ローダや `check` が知らせるか | `check` と読込時の警告にする（エラーにしない）。「ツール単位の `host="*"` は姿勢ではなく通常の規則で、同じブロックの allow を全て覆う」と文面で説明し、policy-authoring 英日に規則を明記する。既存ポリシーの意味は変えない | ツール単位の `deny host="*"` を `defaults` と同じ姿勢として解釈する — 意味の変更になり、v1〜v3 の全版に影響するため採らない |
| D-2 | 探索（`generate-policy --live-discovery`）に OS サンドボックスを適用するか。フラグ名 `--unsafe-unsandboxed-discovery` をどうするか | 2 段階にする。第 1 段（PR-01）は警告文と README・quickstart の修正。第 2 段（PR-09）は opt-in `--discovery-sandbox` で、ポリシー不要の組み込みプロファイル（network 全拒否、fs は実行ファイルの prefix と cwd の読取＋専用 TMPDIR の書込、`defaults.environment` 既定）を Warden に渡す。フラグは `--inherit-ambient-environment` を正式名にし、旧名は非推奨の別名として残す（前身の PR-30 の「既存のフラグ名を変えない」に従う） | 探索を常にサンドボックス内で行う — ポリシーが無い段階で拒否が出ると草案が作れず、導線を壊す |
| D-3 | `generate-policy` の草案を `policy version=3` で出すか | `--policy-version 2\|3` を追加し、既定は 2 のまま（出力不変）。3 を選んだときはテンプレートの `require-path #false` に明示的な空の許可リストを添えて v3 の検証を通す。`check` の移行プレビューが「v3 で失敗」と報告する原因（B-02）を生成側で解消する | 既定を 3 に変える — 前身の PR-32 の snapshot 試験と利用者の既存運用を同時に変えることになるため、運用実績を見てから判断する |
| D-4 | 引数分類で、欄名が既知の payload 欄なら秘密パス判定を省くか | 省かない。秘密パスの「どの欄名でも」検査は F66/F11/F12 対策の仕様。代わりに (a) ASCII のみの値は NFKC を省く（NFKC は ASCII に対して恒等）、(b) `classify_target_string` が計算した正規化結果を `is_secret_path` に渡して二重計算をなくす、(c) 区切り・sigil・ドットを含まない長い値は `selector_plausible` が偽になるので、その判定を正規化より前に置く、の 3 点で削る。目標はレポートの 1 MiB 計測で増分を半減 | 長さ上限を超える値は分類せず拒否する — 既存の `--max-frame-bytes` と二重になり、正当な長文を落とす |
| D-5 | ツールごとに「資源を指さない自由記述の欄」を宣言できるようにするか | 宣言できるようにする。`tool "x" { arguments { opaque "name" "observations" } }`（名称は担当PRで確定）を `policy version=2` 以上に正規登録し、宣言した欄の文字列は `unclassified` の拒否対象から外す。秘密パスの予約綴りと、`scheme://`・IP リテラルなど明確な資源形は宣言があっても従来どおり分類する（宣言は「語彙外の拒否」だけを免除する）。`generate-policy` は `args_schema` で `string` かつ `format` の無い欄をコメントアウトした候補として出す。分類規則と回避策を policy-authoring 英日の冒頭に移す | `args_schema` に `type: string` と書かれた欄を自動で自由記述扱いにする — スキーマは利用者が書き換えられる値で、契約の根拠として弱い |
| D-6 | ハッシュ固定の起動コストを下げるために、どの段階のハッシュを残すか | 残すのは (1) 起動前検証の `hash.verified`／`hash.mismatch`（1 回）と (2) exec する保持オブジェクトからの再ハッシュ（1 回）。bind は保持ハンドルの同一性（`same_open_object`）と stamp で確認し、内容の再ハッシュをしない。スナップショットは保持ハンドルから複製しながらダイジェストを取り、別読みをなくす。目標は読取回数 6 → 2。stamp だけで内容検証を代替しない（保持 fd は Unix で書込を阻まない） | SHA-256 の実装を変える（`sha2` の asm 機能や並列化） — 読取回数を減らす方が効果が大きく、依存の増加を伴わない |
| D-7 | 脆弱性の報告窓口（SECURITY.md）を置くか | 置く。GitHub の private vulnerability reporting を窓口とし、対応の目安（受付確認・初回評価の日数）、対象となる版（最新リリースと main）、PoC 経路は対象外である旨を書く。README 英日からリンクする | 置かない — 利用者が報告先を見つけられず、公開 issue に脆弱性が書かれる |
| D-8 | namespaced 経路で実行ファイル・ペイロードが覆われる木（`/run`、`/tmp`）の下にあるとき、`auto` をどうするか | 方式選択（`select.rs` の `decide`）に「ワークロードの可視性」を入力として加え、覆われる木の下なら namespaced を「このワークロードでは利用不可」とする。`auto` は native で要求を満たせれば native へ回り、理由（`workload_masked: /tmp`）を plan / report / 監査に残す。`namespaced` 明示指定は拒否。前身の D-10（`proc_mount`）と同じ扱い。あわせて、`/tmp` を覆う必要性（resolv.conf の bind 元を `/run` の私的 tmpfs に置けないか）を担当PRで調べ、置けるなら `/tmp` の覆いを外す | 常に拒否する — 設計表の「namespaced が利用不可なら native」と整合せず、`/tmp` に置いた開発用サーバーで `auto` が使えなくなる |
| D-9 | Windows で監査ログを開き直す契機を設けるか | 今回は設けない。guide 英日に「Windows では回転の契機が無く、セッション再起動で切り替える」を明記する（既に L2989–2991 にある記述を運用手順として補う） | 名前付きイベントで `audit.reopened` を起こす — 契機の認証（誰が送れるか）の設計が要る |
| D-10 | 重い結合テストを含む CI を定期実行するか | `ci.yml` と `linux-tests.yml` に `schedule`（週 1 回、`main`）を加える。手動 dispatch は維持し、PR トリガーは pr-checks.yml のまま（前身の D-1 の決定を変えない）。失敗は issue を自動起票せず、Actions の通知に任せる。あわせて「PRを閉じるとき」の記録に実行件数を必須と明記する | リリース前だけ手動で回す（現状） — 評価レポートの指摘どおり、`66e08c9` のような未リリースの先端に対する実行証跡が残らない |

## 6. ロードマップ案

| 版 | 内容 |
|---|---|
| **次版（v0.6 想定）** | P0 の PR-01（文書・例の即時修正）はタグ前に必須。P1 の PR-02〜05・PR-07（起動コスト・引数分類・自由記述欄・namespaced の起動前判定・CI 定期実行）は含める範囲をリリース時に判断 |
| **次版以降** | P2 の PR-06・PR-08〜11（v3 草案と警告、運用文書、探索のサンドボックス、ファジング基盤、後継機構の調査） |
| **別計画** | microVM 隔離の強化（既存の `--isolation` バックエンドの延長）。PR-11 の調査結果を入力にする |

## 7. 非目標（継続）

前身の計画と同じ: Remote MCP ゲートウェイ、応答ボディの DLP/DPI、LLM による中身判定、「FQDN を書けば絶対安全」の宣伝。レポート §2 が「劣る点」として挙げた応答の中身の検査・集中管理・SSO/RBAC もここに含める。
