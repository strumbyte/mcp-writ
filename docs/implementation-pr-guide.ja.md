# mcp-writ PR別実装手順書

作成日: 2026-09-22

状態: 実装中。完了したチェック項目は各PRの節に記録しています。

[全体計画](implementation-plan.ja.md)を目的・範囲・採用条件の正とし、本書をPR単位の作業順序の正とします。根拠は[分析資料](assessment-116a111.ja.md)と `116a111028b39767ec69cb3fbe8e1a885f732571` のソースです。分析資料のSHA-256は `ca23ed7eff62cb698abbe335b7307357a94fea981afabf4f3986d5e448aa611a` です（リンク相対化・環境依存パス除去の改訂後。初回記録時は `c3096f5eb71a21b703366f49f3c1b0a8b3b7a316f05939293ba4a7f45fd0e3da`）。

この手順書を作成した時点で、製品テスト・性能測定・VM実機検証は行っていません。記載するコマンドは今後の実装時の検証手順であり、成功済みの記録ではありません。

PR-01〜13は主計画と既存論点の必須作業です。PR-14は一般化を行う場合の追加作業です。PR-15〜25はVM拡張で、Kataは計画対象、Apple・Windows方式の組み込みは検証結果による条件付きです。PR-26で全体の対応状況を整合させます。番号は計画内の番号です。

## 共通手順

### 作業開始

1. 対象ブランチのHEAD、作業ツリー、適用済みの前提PRを確認する。基準コミットから対象箇所が変わった場合は、本書の事実・依存・試験を更新する。
2. 当該PRの目的と受入条件をPR本文へ転記する。VM方式の製品組み込みでは、先行する試作の実測記録を添付する。
3. 分岐が必要なら `codex/` 接頭辞を使う。後続PRを積む場合は依存先を本文に記録し、取り込み後に差分を見直す。
4. 既存の利用者変更を保持する。日本語ファイルの文字コード問題が疑われる場合は、編集前にバックアップする。原文を確認できない本文を再生成で置き換えない。
5. 新しいファイル・型・オプション名は提案である。既存APIと取り違えず、担当PRで確定し、影響する後続PRへ反映する。

### 実装中の共通条件

- 各OSのネイティブサンドボックス経路を維持する。OSごとの適用処理を共通化の都合で削らない。
- 読み取り・書き込み・ネットワーク等をツールごとにカーネル分離できると表示しない。
- 既存のハッシュ照合、tools/list定義検証・再検証、環境制御、監査のfail-closedを残す。
- 起動報告とMCPフレームを別経路にする。子プロセスの自由なstdout／stderrを信頼できる制御の証明として解析しない。
- 同階層モジュールの相互依存を追加しない。共通の値型を下位に置き、実行・表示・OS制御の所有者を保つ。
- 新しい試験は、拒否されるべき動作と維持すべき正規動作を対にする。実装の写しだけの試験を増やさない。
- 文書修正だけのPRに不要な製品テストを新設しない。関連する既存試験を使う。

### PRを閉じるとき

- 対象コミット、OS・arch・カーネル／ビルド、実行方式、コマンド、結果を記録する。
- 成功・失敗・スキップ・環境未確保を分ける。実行していない試験を「通過」と書かない。
- 追加・変更したテストがどの手動ワークフローに含まれるか確認する。PR-01の一覧ができるまでは、対象テスト・担当ワークフロー・結果・未実施理由を各PR本文に記録する。PR-01で先行PRの行を回収し、一覧作成後は各PRから更新する。公開前には一覧への統合を必須にする。
- 表示した権限・制御が、実際のルール構築と同じ情報から得られるか確認する。
- UTF-8、BOMなし、LF、リンク、差分を確認する。PowerShellで日本語を書く場合はUTF-8を明示する。
- 主計画の公開条件と、各VM方式の採用ゲートを混同しない。未検証方式は未対応のままにする。

主計画の公開前には、公開担当がREADME等の配布記述と実際の公開URL・版・資産を照合し、確認日と結果をPR-01で整える公開チェックリストへ記録する。この照合はPR-25／26を待たない。

### 検証セット

作業ディレクトリはリポジトリルート（`mcp-writ`）とし、文中のパス表記は `mcp-writ/` をルートとします。文書内のローカルリンクは各文書からの相対パスとし、T-DOCで参照先とアンカーを検査します。以下は基準コミットに存在するターゲットです。追加ターゲットは担当PRで明示的に追加し、そのPRのワークフローにも組み込みます。

| ID | 内容・コマンド | 実行条件 |
|---|---|---|
| T-BASE | `cargo fmt --all -- --check`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo test --locked --lib --bins`、`cargo doc --locked --no-deps`、`cargo test --locked --doc` | Rustコード変更時。OS固有コードは該当OSでも実行 |
| T-DOC | `cargo test --locked --test docs_check` | 文書・リンク・文字コードの確認 |
| T-LAYER | `cargo test --locked --test module_layering` | モジュール・依存関係変更時 |
| T-POLICY | `cargo test --locked --test kdl_policy_e2e --test environment_e2e --test go_runtime_policy` | ロード・継承・生成・環境制御・ランタイム用権限とRPC制約の契約 |
| T-NATIVE | `cargo test --locked --test diagnostics_e2e --test path_resolution_e2e --test environment_e2e --test self_test` | Linux／macOS／Windowsの該当環境。OS適用の実試験を含む |
| T-PROTOCOL | `cargo test --locked --test protocol_versions --test tool_enforcement_e2e --test integration --test manifest_fixtures` | MCP規則、定義検査、監査。Python等のfixture前提を確認 |
| T-IDENTITY | `cargo test --locked --test workload_hash_e2e --test path_resolution_e2e` | 実行対象と検証時点 |
| T-CONTAINER | `cargo test --locked --test container_e2e --test wrap_image_e2e --test containerize_e2e` | Linuxの検証用エンジン等、各試験の前提を満たす環境 |
| T-REAL | `cargo test --locked --test real_servers_e2e` | 固定した実サーバーfixture・ランタイムを用意した環境 |
| T-VM | 当該方式の試作・組み込みPRで追加する実機試験 | 環境情報、実行件数、隔離確認、結果の証拠が必須 |

既存の `MCP_WRIT_REQUIRE_E2E_TESTS=1`、`MCP_WRIT_REQUIRE_CONTAINER_TESTS=1`、`MCP_WRIT_REQUIRE_SERVER_TESTS=1` は該当する受入ジョブで使います。これらで全試験のスキップを検知できるとは仮定せず、新規VM試験にも「必須ジョブでは未実施を失敗にする」仕組みを設けます。`MCP_WRIT_SKIP_SANDBOX` でOS適用試験を通したことにはしません。

受入環境でRust・依存・fixtureを準備したうえで `--locked` を使用します。ローカルの準備不足と実装の失敗は区別しますが、必須試験が未実施なら受入完了にはしません。

## PR別の作業

- [PR-01 既存テストの実行担当と検証記録を整える](#pr-01)
- [PR-02 実行対象OSを明示したポリシー検証](#pr-02)
- [PR-03 制御計画・観測結果・プロセス権限の共通モデル](#pr-03)
- [PR-04 Linuxの適用状態を子プロセスから回収](#pr-04)
- [PR-05 macOSの適用根拠と未確認状態を報告](#pr-05)
- [PR-06 Windowsの適用根拠と後始末を報告](#pr-06)
- [PR-07 起動前診断・起動結果・導入手順を統合](#pr-07)
- [PR-08 既存コンテナ経路の対象識別とゲスト報告](#pr-08)
- [PR-09 MCP通過規則のポリシー形式と判定モデル](#pr-09)
- [PR-10 双方向RPC・応答・通知の制御](#pr-10)
- [PR-11 MRTR追加要求の制御と安全な既定値への移行](#pr-11)
- [PR-12 コード同一性の範囲と検証時点を明示](#pr-12)
- [PR-13 Confused Deputyの説明と既存動作を整合](#pr-13)
- [PR-14 Confused Deputyの役割・パス抽出規則](#pr-14)
- [PR-15 追加隔離の選択・状態・ライフサイクル契約](#pr-15)
- [PR-16 Linux Kataの実機検証](#pr-16)
- [PR-17 Linux Kataバックエンドの製品組み込み](#pr-17)
- [PR-18 Apple containerの実機検証](#pr-18)
- [PR-19 Apple containerバックエンドの製品組み込み](#pr-19)
- [PR-20 Windows Hyper-V分離コンテナの実機検証](#pr-20)
- [PR-21 Windowsゲスト用ランナー・配布物・イメージ](#pr-21)
- [PR-22 Hyper-V分離Windowsコンテナの製品組み込み](#pr-22)
- [PR-23 Windows Sandboxのstdio中継と成立性検証](#pr-23)
- [PR-24 Windows Sandboxバックエンドの製品組み込み](#pr-24)
- [PR-25 採用VM方式の手動CIと証跡収集](#pr-25)
- [PR-26 対応表・導入文書・配布記述の最終整合](#pr-26)

<a id="pr-01"></a>

### PR-01 既存テストの実行担当と検証記録を整える

対応論点: C2。直接依存: なし。着手・公開条件: 常設。

**目的:** 手動CIを維持し、テストが存在することと実際に実行対象であることを揃える。

**主な変更先:** [.github/workflows](../.github/workflows)、[tests/common/mod.rs](../tests/common/mod.rs)、[docs/modules.md](modules.md)、[docs/releasing.md](releasing.md)。実行担当一覧は新規 `mcp-writ/docs/test-matrix.md` を候補とする。

**タスク**

- [x] 現行ワークフローの直接実行・workflow_call・releaseからの呼び出しを調べ、OSとテストターゲットの対応を一覧にする。
- [x] `workload_hash_e2e`、`environment_e2e`、`module_layering`、`manifest_fixtures` に実行担当を割り当てる。
- [x] inspectorの3試験がci／platform-testsとlinux-testsで異なる点を整理し、必要な実行先へ追加するか、重複を避ける担当分担を明記する。
- [x] 以後の新規試験を一覧へ登録する手順と、未実施・失敗を区別する証跡様式を追加する。一覧作成より先に進んだPRの担当行をPR本文から回収する。
- [x] 主計画の公開前チェックリストへ配布記述の照合を追加する。公開担当がREADME等に記したURL・版・資産を読み取り確認し、確認日と結果を残す。未公開・未確認ならその状態を記述し、PR-25／26まで確認を先送りしない。
- [x] 手動起動を自動PRトリガーへ変えない。実サーバーの版固定を維持する。releaseが呼ぶci／platform-tests／container-tests／go-runtimeを維持し、linux-tests／mcp-serversは従来どおり公開対象コミットで別途手動実行する。

**検証:** 追加した4ターゲットを対応OSで実行し、既存の手動ジョブで選択されることを確認する。T-DOCと、変更したfixtureがあればT-BASE。すべてのジョブへ同じ試験を重複追加する必要はない。

**完了条件:** リポジトリ内の全結合テストについて実行担当または意図した除外理由が読める。代表ジョブの実行記録があり、必須試験のスキップが成功扱いにならない。主計画公開前の配布照合について、担当・確認項目・記録先が決まっている。

**移行・戻し方:** トリガーの変更は行わない。ジョブの分割は戻せるが、未実施を成功とする変更で失敗を隠さない。

<a id="pr-02"></a>

### PR-02 実行対象OSを明示したポリシー検証

対応論点: B1。直接依存: なし。着手・公開条件: 常設。

**目的:** ホストのビルドOSではなく、ワークロードの実行対象でポリシーの適用可能性を検査する。

**主な変更先:** [policy/loader.rs](../src/policy/loader.rs)、[kdl_loader.rs](../src/policy/kdl_loader.rs)、[kdl_inherit.rs](../src/policy/kdl_inherit.rs)、[validator.rs](../src/policy/validator.rs)、[policy_export.rs](../src/container/policy_export.rs)、[main.rs](../src/main.rs)、[mcp-secure-runner.rs](../src/bin/mcp-secure-runner.rs)。

**タスク**

- [x] ホスト・実行基盤・対象OS／archを表す小さい値型を定義する。新規 `mcp-writ/src/execution.rs` 等の下位モジュールを候補とし、policyやruntimeに依存させない。
- [x] 共通値型は層0に置く。エンジンの識別も葉の値型とし、container::EngineKindとの変換はcontainer側に置く。新規モジュールとLAYERSの登録をdocs/modules.mdとtests/module_layering.rsで同時に更新する。
- [x] 構文・型・重複・一般的な整合性と、対象OSで表現できる制約の検査を分離する。`cfg!(windows)` で対象を決める箇所を明示コンテキストへ移す。
- [x] validatorのnormalize_fs_pattern／path_seg_eq等について、区切り文字・ドライブ表記・大文字小文字の扱いを対象OSで決める。pathutilの呼出経路も棚卸しし、対象側パスをホストの解決処理へ渡す経路だけを分離する。workloadのPATH／PATHEXT検索等、実際にそのプロセス上で行う実行ファイル解決は実行環境のOSに従わせる。
- [x] load／parse／include／extends／when／bind／exportの呼び出しを棚卸しし、途中でホスト条件へ戻らないようにする。制御ノードを失うシリアライズも防ぐ。
- [x] ネイティブ呼び出しの互換ラッパーはホストOSを対象とする。コンテナ側は既存のLinux実行契約を明示し、将来のWindows対象を表現できるようにする。
- [x] ホストで存在確認するポリシーファイル・マウント元と、対象側の許可パスを区別する。LinuxパスをWindowsのパスAPIで勝手に正規化しない。
- [x] ゲスト内ランナーでも実OSに対して再検証する。ホストが指定した対象名だけで異なるOSの検査を通さない。

**検証:** T-BASE、T-LAYER、T-POLICY。対象Windowsでは宛先別ネットワーク許可を現行同様に拒否し、同じ条件を対象Linuxにした場合はWindows固有理由で拒否しない。明示した対象OSコンテキストの単体試験で、パスの大小文字・区切り文字・ドライブ表記、未知の対象、マウント元不在、継承後の制約、対象OS不一致を確認する。PR-02の受入はこの契約と各ホスト上の試験で閉じ、Windowsホスト→実Linuxコンテナの往復確認はPR-08で行う。

**完了条件:** 同じ対象の受理判定がホストビルドに依存しない。ホスト側の必要なパス検査とゲスト側の再検証が残る。

**移行・戻し方:** 既存ポリシーの構文はこのPRでは変えない。問題のある追加対象は未対応として止め、Windowsの検査を削除して回避しない。

<a id="pr-03"></a>

### PR-03 制御計画・観測結果・プロセス権限の共通モデル

対応論点: A1 / B2。直接依存: PR-02。着手・公開条件: 常設。

**目的:** 「書かれた設定」「構築した制御」「適用の観測」を別の値として扱い、プロセス権限の由来を追えるようにする。

**主な変更先:** [warden/mod.rs](../src/warden/mod.rs)、[landlock_impl.rs](../src/warden/landlock_impl.rs)、[macos_sandbox.rs](../src/warden/macos_sandbox.rs)、[windows_sandbox.rs](../src/warden/windows_sandbox.rs)、[runtime/launch.rs](../src/runtime/launch.rs)、[audit_log.rs](../src/audit_log.rs)。PR-02の共通値型を利用する。

**タスク**

- [x] 全体計画のEnforcementPlan／Observation／LaunchReportを具体化し、起動ID・対象・制御層・時点・根拠・状態・理由・スキーマ版を定義する。
- [x] 共通型の定義はPR-02のexecution等の層0に置き、Policyやcontainer::EngineKindをフィールド型に含めない。policy・Warden・containerが葉の値へ変換し、runtimeは報告を組み立てる。新しい葉を追加する場合はdocs/modules.mdとtests/module_layering.rsのLAYERSを同じPRで更新する。
- [x] 状態は少なくとも「予定」「確認済み」「部分適用」「未適用」「意図して省略」「未確認」「失敗」を区別する。OSで無関係な項目は適用不要とし、unknownや成功と混ぜない。
- [x] 実際のルール構築に使う正規化データから権限表を生成する。既定、ランタイムに必要な追加、許可ツール、OS実装由来を識別する。
- [x] ツール別の拒否・secret overlay等のRPC制御と、OSで許可した範囲を別欄にする。OSの全権限を観測できない場合は範囲を限定する。
- [x] 欠落パス、ホスト名ネットワーク規則の非適用、dry-run、環境変数によるsandbox省略、trajectory／Confused Deputyの任意機能を表現する。
- [x] 成功を先に出す既存ログを整理するための接続口を作る。既存監査の相関ID・policy hashと関連付け、秘密値や応答本文を追加収集しない。
- [x] 報告の共通型とOS実装の依存方向を検査する。既存nojson等で実現できる範囲を確認し、表示のためだけに大きい依存を追加しない。

**検証:** T-BASE、T-LAYER。読み取りツールと書き込みツールの同居、deny済みツール、既定権限、パス欠落、OSで表現不能な規則を入力し、ルール構築結果と報告が対応することを検証する。allow_degradedの設定だけで状態を決めないケースも含む。

**完了条件:** 一つの計画データをOS適用と報告で共有でき、表示専用の別計算が実装と乖離しない。まだ観測を実装していない制御はunknownである。

**移行・戻し方:** 型・報告追加の段階では従来の実行許可を広げない。表示不具合は報告層を修正し、制御を無効にして合わせない。

<a id="pr-04"></a>

### PR-04 Linuxの適用状態を子プロセスから回収

対応論点: B2。直接依存: PR-03。着手・公開条件: 常設。

**目的:** Linuxのfork後に適用した結果を、親側で信頼できる範囲に限って報告する。

**主な変更先:** [linux_spawn.rs](../src/warden/linux_spawn.rs)、[landlock_impl.rs](../src/warden/landlock_impl.rs)、[seccomp_impl.rs](../src/warden/seccomp_impl.rs)、[child.rs](../src/warden/child.rs)。

**タスク**

- [x] LandlockのFullyEnforced／PartiallyEnforced／NotEnforcedと、no_new_privs・seccompの適用結果を返せる形にする。allow_degradedによる続行判断は別に残す。
- [x] 親で用意した固定長の共有状態等を使い、exec前の結果を親へ回収する方式を選ぶ。fork後にヒープ確保、フォーマット、tracing、通常のロック操作を追加しない。
- [x] `no_new_privs → Landlock → seccomp` の順序を維持する。報告のためにwrite等のsyscall許可を広げない。採用した回収方式がこの条件を満たす根拠をPR本文に記す。
- [x] 状態をexec後のワークロードが偽造できないようにし、exec失敗、途中失敗、記録途切れを確認済みにしない。
- [x] pre-forkで省略したルールと、カーネルが受理したルールセットの状態を別々に残す。

**実施記録（回収方式の根拠と検証）:** 回収方式は「親がfork前に `mmap(MAP_SHARED|MAP_ANONYMOUS)` で確保した固定長ページへ、子の `pre_exec` が atomic store で段階結果を書き、親が `spawn()` 復帰後に読む」構成（`ApplyRecordPage` / `SharedApplyRecord` / `ApplySnapshot`）。この方式を選んだ根拠:

- `pre_exec` 内の書き込みは単一 atomic store であり、ヒープ確保・フォーマット・tracing・ロック・syscall を一切伴わない。seccomp適用後の最終段階の記録もフィルタに通す必要がなく、報告のために syscall 許可を広げていない。
- `execve` は旧アドレス空間のマッピングを全て破棄し、無名共有ページには fd も名前もないため、exec後のワークロードはレコードを偽造できない。書き込み主体は exec 前の子に限られる。
- `spawn()` が返る時点で子の記録は確定している（exec成功なら全段階の store が先行、エラー経路なら `failed_stage`/`errno` の store が `Err` 返却に先行）。段階 store は Release、親の読み取りは Acquire で出版する。
- 途中失敗・記録途切れ・フィールド不整合（成功結果と `failed_stage` の同居等）は `Unknown` / `Failed` に写像し、確認済みへ読み替えない。

観測と判断の分離は `landlock_impl::restrict_self_observed`（`RestrictionStatus` を返す）と `enforcement_gate`（`allow_degraded` による続行可否のみ判定）に分解して実現した。pre-fork のルール省略は従来どおり grants の `Skipped`/`Failed` として残り、カーネル受理後のルールセット状態は `ApplySnapshot.landlock`/`landlock_abi` として別欄で報告される。

検証実行記録: WSL2 x86_64・kernel `5.15.167.4-microsoft-standard-WSL2`（Landlock ABI v1・seccomp BPF 利用可）、Rust 1.98.1。`cargo fmt --check`、`cargo check`（`x86_64-unknown-linux-gnu` / `x86_64-pc-windows-msvc`、all-targets）、`cargo clippy --all-targets`、`cargo test --lib`（1423件）、`--bins`、`--doc`、`--test module_layering`、`--test docs_check` を全てパス。実機spawnで `ApplySnapshot { stage: 3, landlock: PARTIAL, landlock_abi: 1, failed_stage: 0 }`（劣化許容あり・`/bin/true`）と `{ stage: 1, landlock: PARTIAL, landlock_abi: 1, failed_stage: LANDLOCK, errno: EACCES }` → spawn失敗（劣化許容なし）を確認し、exec失敗（ENOENT）時に全段階完了が残ることも確認した。部分適用はこのカーネルで実機発生したため、状態変換試験（`plan::tests::linux_observations`）と実機確認を併記した。親プロセス自身は制限を受けない（同一テストプロセスが後続spawnを正常実行）。ホスト名規則の非適用や各種 reject 経路は既存試験が維持。未実施: 実ファイル拒否・ネットワーク制御の実機確認、`go_runtime_policy` を含むE2Eワークフロー（手動ジョブ、別途実施が必要）。

**完了条件:** 子の適用結果と親の報告が対応し、劣化許容trueでも完全適用なら完全適用と表示する。回収不能はunknownまたは起動失敗であり、適用済みへ読み替えない。

**移行・戻し方:** 失敗時の拒否は従来より弱めない。観測機能だけを戻す場合も、既知でなくなった項目はunknownに戻す。

<a id="pr-05"></a>

### PR-05 macOSの適用根拠と未確認状態を報告

対応論点: B2。直接依存: PR-03。着手・公開条件: 常設。

**目的:** macOSで実際に確認できる事実を報告し、sandbox-execの起動成功を完全適用の証明にしない。

**主な変更先:** [macos_sandbox.rs](../src/warden/macos_sandbox.rs)、[warden/mod.rs](../src/warden/mod.rs)、[guide.md](guide.md)。

**タスク**

- [x] SBPL生成、sandbox-exec起動、子の実行・終了、私有一時ディレクトリの状態を観測イベントへ対応付ける。
- [x] 観測可能な根拠と推定を分ける。公開された安定した照会手段で確認できない項目はunknownとして残す。
- [x] SBPL構文失敗、sandbox-exec不在、起動直後の終了を扱う。ログをspawn前の適用成功表示にしない。
- [x] 私有一時ディレクトリ、Python起動パスの扱い、プロセスグループと停止処理を維持する。
- [x] sandbox-exec／SBPLのサポート上の注意と、現行ネイティブ経路の維持を文書へ反映する。

**実施記録（観測方式の根拠と検証）:** `sandbox-exec` はプロファイル受理を照会する公開・安定した手段を持たないため、観測は「構築の事実」と「起動の事実」に限定する構成とした。`os.sandbox`（mechanism `sandbox-exec`）を新設し、Build フェーズで SBPL 生成＋私有一時ディレクトリ作成を `Verified`（basis `verification_run`）、Spawn フェーズで spawn 成否と初期終了チェックを記録する。`initial_exit_check` は spawn 後に最大 150 ms・10 ms 間隔で `try_wait` をポーリングする。`sandbox-exec` はプロファイルを自身へ適用してから workload を exec するため、プロファイル拒否・exec 不能は数 ms 以内の exit として現れる（実機で不正 SBPL が status 65・約 9 ms で exit することを確認）。窓内 exit は終了コードを子の終了状態として記録するが、サンドボックス適用の失敗を直接示す根拠がないため `os.sandbox` は `Unknown`（basis `spawn_result`）を維持する — 短命の正常 workload も同じ形で終了するため、exit だけでは mechanism 失敗と断定できない。窓を越えて生存した場合は `Verified`（basis `spawn_result`）とする。ドメイン別コントロール（`os.fs` / `os.net.outbound` / `os.net.inbound` / `os.process`）はどちらの場合も `Unknown` を維持する — 早期終了は「プロセスが終わった」事実でありカーネル受理の証明ではないため、推定で成功へ読み替えない。spawn エラー（`sandbox-exec` 不在等）は mechanism が走っていないため全 Planned OS コントロールを `Failed` とする。私有一時ディレクトリは作成済みが `PrivateTmpdir` grant の `Verified` として報告される。早期終了は spawn 結果を `Err` に変えない（self-test の短命プローブを壊さない）— 呼び出し側は従来どおり EOF で失敗を知り、報告が Failed/Unknown を保持する。子の stderr は workload 自身のチャネルとして扱い、証拠として解析しない。

検証実行記録: macOS 26.6.2（Darwin 25.6.0）arm64、Rust 1.98.1。`cargo fmt --all -- --check`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo test --locked --lib --bins`（1417件）、`cargo doc --locked --no-deps`、`cargo test --locked --doc`、`cargo test --locked --test docs_check`、`--test module_layering`、T-NATIVE（`diagnostics_e2e` 4件・`environment_e2e` 5件・`path_resolution_e2e` 4件・`self_test` 4件）、T-IDENTITY（`workload_hash_e2e`・`path_resolution_e2e`）を全てパス。`cargo check --locked --all-targets --target x86_64-unknown-linux-gnu` もパス（変更は macOS の cfg 範囲に限定）。実機 spawn で `/bin/sh -c 'sleep 30'` が `os.sandbox` = Verified（Build＋Spawn 2件）・各ドメイン Unknown を、`/bin/sh -c 'exit 3'` が `os.sandbox` = Unknown（`exit status: 3` を理由に保持 — 早期終了はサンドボックス拒否と短命の正常終了を区別できない）・各ドメイン Unknown を確認（`warden::tests` の `#[tokio::test]` 経由）。既存の実機拒否試験（許可外パスへの書き込み拒否・私有一時 TMPDIR・loopback 拒否）は維持。追加した試験は `src/warden` のユニット試験であり、担当ワークフローは platform-tests（macos-latest の `cargo test --locked --lib --bins`）— 新規 `tests/*.rs` ターゲットは追加していないため test-matrix.md の行追加は不要。未実施: Windows ターゲットのコンパイル確認（Windows 経路は無変更）、手動 E2E ワークフロー全体（platform-tests の実ジョブ実行は別途）。

**完了条件:** ネイティブ経路が維持され、確認できない状態が誤って成功にならない。必要な保護に関する確認可能範囲が文書と出力で一致する。

**移行・戻し方:** Apple containerへの置き換えは行わない。観測追加に不具合があれば既存実行経路を保ち、観測の保証を限定する。

<a id="pr-06"></a>

### PR-06 Windowsの適用根拠と後始末を報告

対応論点: B2。直接依存: PR-03。着手・公開条件: 常設。

**目的:** WindowsのAppContainer・Job・DACL等について、適用処理の完了と失敗を報告する。

**主な変更先:** [windows_sandbox.rs](../src/warden/windows_sandbox.rs)、[windows_profile.rs](../src/warden/windows_profile.rs)、[windows_proc.rs](../src/warden/windows_proc.rs)、[child.rs](../src/warden/child.rs)。

**タスク**

- [x] AppContainer作成、capability設定、パスへのDACL付与、プロセス作成、Job割当、実行開始を報告へ対応付ける。
- [x] API呼び出し成功の根拠と、アクセスを実際に拒否できたという試験結果を区別する。
- [x] 実行開始前に必要な制御が失敗した場合は起動を止め、作成済みのプロセス・プロファイル・ハンドル等を既存責務で後始末する。
- [x] パス別に付与した権利と、Windowsでは表現できない宛先別ネットワーク制御を表示する。
- [x] sandbox成功ログの時点を見直し、失敗時にもステージと理由を残す。

**実施記録（観測方式の根拠と検証）:** Windows の適用パイプラインは親側の連続した Win32 呼び出しであり、各段の成否がそれぞれのメカニズム結果になる。`spawn_sandboxed` は最初に失敗した必須ステージで中断し、`WinSpawnError { stage, source }` でどの段で死んだかを返す。ステージ語彙は `profile-creation`（CreateAppContainerProfile）、`grant-application`（ケイパビリティ SID と HTTP ループバック免除 — パス別 DACL 書き込みはこのステージ内でベストエフォート）、`process-setup`（パイプ・属性リスト）、`create-process`（CreateProcessW そのもの）、`job-setup`（Job 生成と kill-on-close 設定）、`job-assignment`（`AssignProcessToJobObject`）、`execution-start`（ResumeThread）。呼び出し側へ伝播する `WardenError` の文言にもこのステージラベルを残し、`grant-application` 中断時は未到達 intent を `Skipped` として全列挙する（レビュー指摘対応）。観測写像: CreateProcessW 前のステージ失敗はコンテナプロセスが存在しないため全 Planned OS コントロールを `Failed`、CreateProcessW 失敗は属性・イメージ融合で判定不能のため `Unknown`（basis `spawn_result`）、Job/実行開始失敗はコンテナ内実プロセスが存在したため `os.process` を `Failed` とし、適用済みが証明された他コントロールは結果を維持して理由に中断を併記する（Linux の exec 失敗経路と同じ約定）。成功時は `os.process`=`Verified`（CreateProcessW がコンテナトークンの権威）、`os.fs` は policy 起因 DACL 付与の失敗数で `Verified`/`PartiallyApplied`（runtime 起因の付与失敗は policy fs を partial にしない）、`os.net.outbound`/`os.net.inbound` はトークン内ケイパビリティ SID を根拠に `Verified`。HTTP トランスポートでは `os.net.loopback` コントロールを新設し、CheckNetIsolation の `Ok(true)`/`Ok(false)`/起動失敗を `Verified`/`Unknown`/中止に対応付ける（未確認を成功にしない）。宛先別ネットワークエントリは OS で表現不能のため `net_destination` grant を `Skipped` として記録する（拒否ではなく、RPC 層のみで強制）。`kill()` は `TerminateJobObject` 後の `TerminateProcess` が既終了プロセスへ ACCESS_DENIED を返し Job 経路で実質必ず失敗する既存バグを修正した（Job 経路では `TerminateJobObject` のみを呼ぶ）。`WindowsChild::try_wait` と `RunningChild::try_wait` の Windows 配線を追加し、自然終了と強制終了を区別できるようにした。`os_limitations` には「`verified` ACL 付与は SetNamedSecurityInfoW の API 結果のみ」「ケイパビリティは all-or-none で宛先別は RPC 層」を追記した。

実機で判明した環境事実: この起動構成ではコンテナ内からの子プロセス起動が拒否される（`cmd /c cmd /c echo` で子出力なし・非ゼロ終了を実測）。ただし機序は「コンテナ外トークンの子」説ではない — AppContainer の子は通常コンテナトークンを継承し、`KILL_ON_JOB_CLOSE` は生成を妨げず、`PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY`/`PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` も設定していない。観測された拒否は起動条件（コンテナの付与範囲外の作業ディレクトリ継承・コンソールなし・stdio のみのハンドル継承）由来の性質であり、ポリシーによる子プロセス制限ではない（追加プローブ: コンテナは bypass-traverse 権を持たず、許可パス自身への ACL 付与だけでは祖先を辿れないため `cd` はどこへも効かない）。したがって Job の子孫終了は実機上では「作れない子孫」への防御であり、試験はこの起動条件での観測拒否として固定した（`sandboxed_workload_cannot_spawn_children`）。同様に `cmd /c` 内の `\"` 引用符は argv エスケープ後に cmd が解釈できず、従来の deny 試験はコマンド未実行で事実上空成功していた — リダイレクト先を引用符なしの絶対パスに直して実書き込みを試行する形へ修正した。ACL 実測では `read_write` 付与（`FILE_DATA_WRITE`）はディレクトリ内のファイル作成を許可するが `cd` は許可しないため、テストは `cd` ではなくフルパス直書きで検証する（`acl_grant_allows_write_and_drop_restores_denial`: 付与→書き込み可→drop→別コンテナで拒否、同一プロファイル名＝同一 SID で ACL 復元を確認）。DACL fixture は `std::env::temp_dir()` 配下のテスト専用ディレクトリに閉じる。

**検証実行記録:** Windows 11（ローカル、x86_64）、Rust 1.98.1（cargo 1.98.1）、PowerShell 経由。`cargo check --locked --all-targets`、`cargo fmt --all -- --check`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo test --locked --lib --bins`（1435件）、`cargo test --locked --doc`（doc test なし）、`cargo test --locked --test docs_check`（T-DOC、11件）、`--test module_layering`（T-LAYER、16件）は全てパス。`MCP_WRIT_REQUIRE_E2E_TESTS=1` で T-NATIVE（`diagnostics_e2e` 3件・`environment_e2e` 5件・`path_resolution_e2e` 5/6件・`self_test` 4件）、T-IDENTITY（`workload_hash_e2e` 3件・`path_resolution_e2e` 同上）、T-POLICY（`go_runtime_policy`・`kdl_policy_e2e`、いずれも失敗0）、T-PROTOCOL（`integration`・`protocol_versions` 5件・`tool_enforcement_e2e` 30件、いずれも失敗0）を実施し、`go_runtime_policy` 側で起動に必要な OS 権限と RPC 側制約の分離を確認。`path_resolution_e2e::symlink_resolution_and_wait_file_barrier` はシンボリックリンク作成の特権／開発者モード不足で環境前提未充足（実装不具合ではなく skip 相当、他5件はパス）。追加試験は `src/warden` ユニット試験（plan ステージ写像5件＋実機 spawn 3件）と既存試験の実効化修正であり、新規 `tests/*.rs` ターゲットは追加していないため test-matrix.md の行追加は不要。

未実施: `manifest_fixtures`（T-PROTOCOL）。手動 E2E ワークフロー全体の実行（platform-tests の実ジョブ実行は別途）。Linux/macOS でのリグレッション確認（Windows ホストの `cargo check` は他 OS の `cfg` コードをコンパイルしない。本変更は Windows cfg 範囲と共有の `RunningChild::try_wait` Windows 分岐に限定しており、他 OS 側の振る舞いを変える差分はない）。`--report` の CLI 出力経路（PR-07 範囲）。

**完了条件:** AppContainer・Job・DACLの状態が一つの曖昧なsandbox成功へ潰れず、ネイティブ経路の既存拒否と後始末が維持される。

**移行・戻し方:** JobやAppContainerを省略して起動成功に変えない。追加観測だけを戻す場合は確認できなくなった範囲を出力へ反映する。

<a id="pr-07"></a>

### PR-07 起動前診断・起動結果・導入手順を統合

対応論点: A1 / B1 / B2。直接依存: PR-04、PR-05、PR-06。着手・公開条件: 常設。

**目的:** 利用者が起動前に必要条件を確認し、起動後に実効状態を一か所で把握できるようにする。

**主な変更先:** [cli](../src/cli)、[commands](../src/commands)、[runtime/launch.rs](../src/runtime/launch.rs)、[main.rs](../src/main.rs)、[audit_log.rs](../src/audit_log.rs)、[docs](.)。

**タスク**

- [x] `plan` のCLIを確定する。ネイティブは `mcp-writ plan --policy <path> -- <command>`、イメージは `mcp-writ plan --engine <engine> --image <digest> --policy <path>` を基本案とする。
- [x] planはワークロード・live discoveryを起動しない。イメージ取得、管理者設定、デーモン設定変更を暗黙に行わず、足りない前提を結果にする。
- [x] planの結果と終了コードを下表で固定する。計画を算出できても必須前提が欠ける場合はreadyにしない。機械可読なstatus・reasonと人向けの修正手順を揃える。
- [x] `run` と `run-image` の `--report <path>` を確定し、同じスキーマで予定・観測・最終結果を記録する。未対応の実行経路は成功相当の空結果を返さない。
- [x] 報告はMCPのstdoutへ出さない。人向け要約はstderr、JSONは指定先へ出す。既存ファイルの扱い、途中失敗時の保存、報告書き込み失敗の終了状態を決める。
- [x] 起動IDで監査と報告を結び付ける。コマンドの秘密引数・環境変数の値・応答本文を無条件に保存しない。
- [x] OS判定、必要な機能・権限・エンジンの診断と、修正する具体的な次の手順を示す。
- [x] dry-runは実行を伴う既存モードとして維持し、planと区別する。任意機能と制御省略は要約に残す。
- [x] ネイティブ3 OSの短い導入例と診断例を更新する。報告形式の版と互換性方針を記録する。

**実施記録（方式の根拠と検証）:** `plan` は `commands/plan.rs` に独立実装し、ワークロード・live discovery・イメージ取得を一切行わない。ネイティブ経路はポリシー load/bind・`resolve_command_path`・`MCP_WRIT_SKIP_SANDBOX`・`logging.fail_closed`・ハッシュpin有無・`Warden::enforcement_plan`（spawn と同一ビルダーで Failed コントロールが起動失敗と一致）を `checks` に落とし、最初の Fail で ready→blocked に降格、check id から安定 `reason.code`（`command_not_found` 等）を引く。CLI 入力エラーは `PlanArgs.invalid_input` に保持して status `invalid`（exit 2）の機械可読結果にする（usage エラーと区別）。イメージ経路は digest pin・engine 解決・ローカル inspect・runner ENTRYPOINT・`docker-manifest-hash` 照合・ゲスト契約 `skipped` を診断し、pull/daemon 変更なし — ゲスト側計画は mcp-secure-runner の領域として `skipped`/`limitations` に残す（PR-08 の接続点）。`--report` は `run`/`run-image`/`plan` に共通追加し、保存先を起動前に open/truncate 検証して「要求された報告が保存できないのに成功終了」を構造的に排除 — `LaunchReport::write_to` は全上書き（各起動が前回を置き換え）、書き込み失敗は終了コード 1 相当の失敗にする。`LaunchReport` に `result`（`running`/`exited`/`failed`/`interrupted` + detail + exit_code、`LaunchOutcome`）を追加し、`wait_for_shutdown` の `Option<ReportTarget>` が全終了経路で最終結果を書く。`LaunchError` 全バリアントが `report` を持ち、pre-spawn 失敗（解決・検証・バインド・再検証・spawn・stdio捕捉）でも計画＋`failed` 結果を出し、対応する `server.error` 監査イベントを発行 — 起動失敗が空の成功報告にならない。`launch_id`（UUIDv7）はレポートと監査イベント `correlation_id` で一致し、`run-image` はホスト経由 `MCP_WRIT_LAUNCH_ID` でゲスト監査と相関する。`plan` の JSON は stdout 専有（`--report` 時はファイル）、`run`/`run-image` のレポート JSON は MCP stdout に出さず要約は stderr。検証: `tests/plan_report_e2e.rs` が 4 状態の終了コード・無起動マーカー・stdout分離・`run --report` dry-run セッションの `exited` 0・launch_id↔server.connected/server.error 相関・`failed` 失敗報告・書込不可 `--report` の spawn 前失敗を網羅（T-BASE/T-NATIVE ローカル pass）。文書: guide.md/guide.ja.md に 4.7 plan・4.8 レポート共通仕様（スキーマ版 "1"、互換性方針、stdout 分離、上書き規則、失敗=非成功）と `run`/`run-image` の `--report` 行・FAQ を追加、quickstart.md/quickstart.ja.md に plan→dry-run→report の導線（Windows 形を含む）を追加、test-matrix.md に `plan_report_e2e` の所有ワークフロー（CI/Platform/Linux）と証跡を登録、3 ワークフローのターゲットリストへ追加済み。dry-run は実行モードとして維持し、文書で plan と明確に区別した。レビュー対応（2026-09-26）: `audit.config` は `run`/`run-image` の実行時フラグを `plan` が検証不能なため Fail→Warn に降格（Fail のままでは `fail_closed` 既定の全ポリシーで `ready` 未到達となる恒常 blocked の解消）、イメージ経路にも同チェックを追加（`--log-dir` 前提を Warn 表示）、`resolve_command_path` はパス指定かつ非存在を NotFound で失敗させて `command.resolve` の偽陽性を解消、`container_run_args` が `MCP_WRIT_LAUNCH_ID` を空でクリアしてイメージ焼き付け値による相関 ID 偽装を防止、`image.digest_match` 失敗を `launch.image` コントロールの Failed に写像、`run-image` の `--report` 事前検証を create+truncate に統一（クラッシュ時に古い成功レポートを残さない）、`run` はポリシー load/bind・`--audit-log` 必須等の launch 前段失敗でも最小 `failed` レポートを書いて空ファイルを残さない、`LaunchError` 全バリアントで stderr に `launch report:` を出力（`mcp-secure-runner` と同一）、`HostRunRec.exit_code` の dead field を削除し `observe()` に phase を明示。e2e は 12 件（パス指定で非存在コマンド→`command_not_found`、既定 `fail_closed`→`audit.config` warn＋`ready` を追加）。

| planの状態 | 終了コード | 結果 |
|---|---|---|
| ready | 0 | 予定を算出でき、検査対象の必須前提を満たす。実際の制御適用は未観測 |
| blocked | 1 | 前提不足・非対応・必須条件を確認不能。reasonと不足内容を返す |
| invalid | 2 | CLI入力・ポリシーの構文や意味が不正。修正箇所を返す |
| error | 1 | 診断処理や結果の保存に失敗。blockedとはstatus・reasonで区別する |

**検証:** T-BASE、T-DOC、T-NATIVE。planの無起動と4状態の終了コードをfixtureで確認し、通常起動のstdoutがJSON-RPCのみであること、起動失敗・報告先不正・unknownを検証する。`--report` を明示して保存できない場合に成功終了で済ませない。

**完了条件:** 一つの結果から対象、プロセス権限、制御層、予定／観測、スキップ理由、未確認が読める。3 OSの導入手順にplan→実行→結果確認がある。

**移行・戻し方:** 新オプションを使わない既存CLIを維持する。報告スキーマの変更は版で扱い、stdoutへ退避しない。

<a id="pr-08"></a>

### PR-08 既存コンテナ経路の対象識別とゲスト報告

対応論点: B1 / B2。直接依存: PR-07。着手・公開条件: 常設。

**目的:** 既存コンテナでも対象OS・パス・ゲスト側の観測を正しく扱い、VM拡張が再利用できる接続点を作る。

**主な変更先:** [container/runner.rs](../src/container/runner.rs)、[engine.rs](../src/container/engine.rs)、[inspect.rs](../src/container/inspect.rs)、[policy_export.rs](../src/container/policy_export.rs)、[common.rs](../src/container/common.rs)、[mcp-secure-runner.rs](../src/bin/mcp-secure-runner.rs)。

**タスク**

- [x] CLIホスト、エンジン実行先、イメージのOS／arch、ゲスト内ランナーを区別して記録する。Windows対象の未対応イメージはこの段階では明示拒否する。
- [x] wrap-image／containerize／run-imageのポリシー受理・bind・自己完結化・ゲスト再検証を対象OSで一貫させる。
- [x] ホストのポリシー実体とゲスト側の読み取り専用パス、ログ・報告の受け渡し領域を分ける。リモートデーモンや共有不能なパスは事前に診断する。
- [x] ゲストの観測をホストのLaunchReportへ結び付ける経路を設計する。制限した専用チャネルまたは専用出力領域を使い、サーバーの自由なstderr解析で代用しない。
- [x] 報告は起動ID・ランナー版・サイズ・期限・形式を検査し、不在や不一致はunknown／失敗にする。ゲスト由来の情報をホスト独立の証明に格上げしない。
- [x] ランナーの古い版に報告機能がない場合の診断を用意する。必要な報告を取得できないのにVM対応等を主張しない。
- [x] 下表の互換性をコマンド・報告指定・ランナー能力で固定する。既知の旧版の機能不足と、対応版での報告欠落・不一致を区別し、後者を旧構成扱いへ自動で落とさない。
- [x] EOF、起動失敗、中断時のrelay・一時ファイル・コンテナ後始末を確認する。既存のイメージダイジェスト要求とsandbox省略環境変数の処理を維持する。

| 操作・条件 | 報告非対応の旧ランナーの扱い |
|---|---|
| wrap-image | 既存ポリシーを扱える場合は生成を許可し、成果物にランナー版と報告能力の有無を記録する。生成成功を適用観測としない |
| containerize | 同上。自動選択したランナーの版・能力も記録し、報告対応イメージを生成したという誤表示を防ぐ |
| run-image、--reportなし、通常コンテナ | 既知の旧版は従来相当として許可し、ゲスト観測を未確認と表示する。必須制御やポリシー形式の互換性検査は維持する |
| run-image、--reportあり | 必要なゲスト報告を取得できない旧版は起動前に拒否する。対応版でも報告の欠落・不正・保存失敗を成功扱いにしない |
| 後続PRのVM隔離経路 | --reportの有無にかかわらず必要な報告能力を必須とし、旧版を拒否する |

`--output-dockerfile` だけの場合も生成物の契約を示し、実行や観測の成功を報告しない。上表の生成許可は、未知のポリシー制御を旧ランナーへ渡す許可ではない。

**検証:** T-BASE、T-DOC、T-CONTAINER、T-POLICY。Windowsホスト→実Linuxコンテナで、PR-02の対象OS判定からポリシー受け渡し・ゲスト再検証までを確認する。上表の旧版互換性、偽のstdout報告、欠落・過大・別起動IDの報告、ゲスト再検証失敗、停止時の資源を確認する。Docker／Podmanは利用可能な対象でそれぞれ検証する。

**完了条件:** 既存の3つのコンテナ操作が維持され、ホストとゲストの結果を一つの起動で把握できる。受け渡しのためにワークロードへホスト管理ソケットを公開しない。

**移行・戻し方:** 旧ランナーの受理は上表に従う。--report指定時とVM隔離では必要な報告を必須とし、既存の通常コンテナで許可する旧構成は従来相当・未確認と表示する。対応版の報告障害を互換動作で隠さない。

**実施記録（対象識別とゲスト報告経路の根拠・検証）:** 対象識別は `ExecutionTarget`（`host_os` / `substrate_os` / `workload_os` / `workload_arch` / `substrate` / `engine`）で分離し、`inspect.rs` がイメージの `Os`／`Architecture`／`Config.Env` を抽出、`engine.rs` の `info()` がエンジン実行先（基盤OS・リモートendpointヒント）を取る。`TargetArch::Other` を String 保持にしてイメージarch名をレポートへ残す。非 Linux イメージは `guest_report::check_guest_image_os` で `wrap-image`／`containerize`（`--output-dockerfile` も）／`run-image` の起動前ゲートとして拒否する。ポリシーの受け渡しはホスト実体を bind せず、`inline_policy_to_kdl` で Linux ゲスト対象の自己完結 KDL を私有一時ディレクトリへ export して `/etc/mcp-secure/policy.kdl:ro` に載せ、ゲスト内ランナーが実環境で load/bind し直す。ゲスト報告は stdout/stderr 解析を使わず、ホスト側私有一時ディレクトリを `/run/mcp-secure/report` へ bind し `MCP_WRIT_REPORT_OUT` で指す専用チャネルとした。ランナー能力はバイナリ埋め込みマーカー `MCP_WRIT_RUNNER_CAPS:{"v":…,"caps":["guest-report-1"]}` をスキャンし、生成イメージには ENV `MCP_WRIT_RUNNER_CAPS` で記録する — `wrap-image`/`containerize` は能力なしでも生成を許可するが版・能力を stderr に記録し、`run-image --report` では能力なしを起動前拒否、`--report` なしでは従来相当の起動を許可してゲスト観測未確認を stderr に表示する。報告検証は起動ID一致・ランナー版一致・JSON形式・schema_version・8 MiB上限を `read_guest_report` が行い、欠落／不正は `Missing`／`Invalid`（保存失敗は実行自体の失敗）として成功にしない。期限は「コンテナ終了後の出現待ち」として適用する（`GUEST_REPORT_WAIT` = 3秒、50msポーリング。ゲストプロセスは既に終了しているため、遅れ得るのはマウント伝播のみ）— 超過は `Missing` として fail-closed。レポート内容の有効期限（`created_at` の鮮度）は別途検査しない: 報告dirは起動ごとの新規 private temp dir で過去起動のファイルは存在し得ず、別起動の報告は `launch_id` 不一致で既に拒否されるため、鮮度検査の追加は防御を増やさない。境界値の試験: 期限超過→`Missing`（`read_missing_after_deadline`）、窓内出現→受理（`read_picks_up_late_arriving_report`）、symlink/非regular拒否・サイズ上限の4件を `read_guest_report` に追加し、テストでは期限を 250ms に短縮している。`LaunchReport` には `guest_runner`（`GuestRunnerIdentity`＝`version` と `capabilities` のみ。ゲスト側レポートが自身を宣言する欄で、ホストのレポートでは `None`）と `guest`（`GuestReportLink`: `state`／`detail`／`runner`＝イメージ記録の同一identity／`report`＝検証済みの逐語JSON）を追加し、ゲスト由来の観測は `observations` に混入しない。`plan` は `engine.locality`（リモートデーモン＝共有可能性未検証で warn）、`image.os`（非 Linux で fail → `unsupported_guest_os`）、`runner.caps`（報告能力 warn）を新チェックとして出す — 新 reason.code は `remote_daemon`／`unsupported_guest_os`／`runner_incapable`。後始末は `TempLaunchDir`（policy/report/cidfile を集約）の Drop で政策・報告・cidfile 一時領域を一括削除し、EOF・起動失敗・Ctrl-C の各経路で cidfile 経由のコンテナ cleanup を維持する。hardening 環境変数除去は `MCP_WRIT_REPORT_OUT` を新たにクリア対象へ加え、従来の `MCP_WRIT_ENV`/`MCP_WRIT_SKIP_SANDBOX`/`MCP_WRIT_SERVER`/`MCP_WRIT_LAUNCH_ID` を維持。リモートデーモン・非Linuxイメージ・報告能力不足・ゲスト報告の欠落/不正の各拒否は `run_image_inner` の `Err` として返り、ドライバが `--report` に result `failed`（`result.detail` に失敗段階）を書く。検証: `cargo fmt --check`、`clippy -D warnings` クリーン。lib/bins 1484 テスト全 pass。`plan_report_e2e` の3件の失敗（`syscalls.allowed` への execve 不足）は変更前 HEAD でも同じ診断で失敗し、既存問題と確認した（Docker デーモン非利用環境のためコンテナ実機 E2E は Container tests ワークフロー担当）。

<a id="pr-09"></a>

### PR-09 MCP通過規則のポリシー形式と判定モデル

対応論点: A2。直接依存: なし。着手・公開条件: 常設・PR-11まで単独公開しない。

**目的:** MCPの通過規則を、ツール許可から独立した小さい判定モデルとして定義する。

**主な変更先:** [policy/mod.rs](../src/policy/mod.rs)、[kdl_parse.rs](../src/policy/kdl_parse.rs)、[kdl_inherit.rs](../src/policy/kdl_inherit.rs)、[kdl_emit.rs](../src/policy/kdl_emit.rs)、[validator.rs](../src/policy/validator.rs)、[protocol/mod.rs](../src/protocol/mod.rs)。

**タスク**

- [ ] 規則キーを対応版・方向・メッセージ種別・method／追加要求methodとし、判定理由を安定したコードで返す。
- [ ] 2025年版はinitialize／initializedの段階と交換したcapabilityを追跡する。2026年版には初期化待ちを設けず、各要求の_meta内のprotocolVersion／clientCapabilitiesを毎回検査する。server/discoverは先行必須にせず、clientInfo／serverInfoの省略を拒否理由や権限判定に使わない。
- [ ] 以下の既定表を仕様化し、双方の正式仕様と既存fixtureへ照合する。「4メソッドだけ許可」で済ませない。
- [ ] serverに結び付く通信規則のKDL v2構文を定義する。未知キー・未知版・不正な方向・重複や矛盾を拒否する。
- [ ] v2ではtool内の未知プロパティ・未知子ノードもロード時に拒否する。継承・include・when・profile経由でも未知の制御を黙って無視せず、PR-11の初回v2公開にこの拒否を含める。
- [ ] 継承・include・when・server選択・KDL再出力で規則を保持する。deny優先と、許可を広げる明示操作の扱いをテストで固定する。
- [ ] v1では追加規則なしの安全な既定プロファイルへ移行する案を、移行文書と一緒に確定する。旧バイナリがv2を拒否することも確認する。
- [ ] 2026年版の購読要求・承認通知・変更通知の規則を定義する。subscriptionIdはsubscriptions/listenのJSON-RPC IDと型・値が一致するものとする。要求・承認フィルター、購読ID、承認待ち／有効／終了を判定入力に含める。resourceSubscriptionsはURI文字列の配列として扱い、初期の許可範囲はURI完全一致の一覧とする。URIをホストのファイルパスとして正規化しない。未知フィルター、不許可の通知種別のtrue、不許可URIを含む要求は全体を拒否する。
- [ ] Policyを参照する純粋な判定処理はpolicyへ置き、protocolには版・フレーム等の葉の値型と解析を置く。protocolからpolicyへ依存させない。通信状態・要求表・購読状態はAuditorが所有し、判定に必要な値を渡す。
- [ ] 版別の応答形式も検査する。2026の通常結果はresultType=completeを必須とし、input_requiredはPR-11の条件へ分岐する。未知のresultTypeは拒否する。2026のCacheableResultにはttlMsとcacheScopeを要求し、型・値を対応版のスキーマへ照合する。tools/listの検証済み応答を再構成する経路でもこれらを維持する — ただしポリシーが結果を変える再構成（フィルタ済み tools/list 等）はフィルタ前の応答とは別物であり、サーバーの cacheScope を引き継いだ公開キャッシュへ残してはならない。その場合は `cacheScope=private` とするかキャッシュを無効化し、ポリシーが結果を変えない場合だけサーバーの cacheScope と ttlMs を維持する。2025ではresultTypeの省略をcompleteとして扱い、2026専用の必須フィールドを要求しない。
- [ ] v2の実行・生成はPR-11まで有効化しない。構文だけの中間状態を利用者向けに公開しない。

stdioクライアントの版交渉と旧版フォールバックの責務は、PR-09/10ではなく既存の呼び出し側が担う: Legislator の stdio tools/list クライアント `src/legislator/tools_list.rs`（generate-policy・inspect の discovery が使用）が交渉・再試行・フォールバックを所有する。PR-09は `src/protocol/mod.rs` の版別値とプローブ分類（`classify_probe_line` / `classification_to_outcome` / `VersionProbeOutcome`）だけを定義し、PR-10の Auditor プロキシは交渉済みの版を判定入力として扱う。既存呼び出し側との契約は次の通り:

- discover-first: 本セッションの子プロセスへ pre-`initialize` トラフィックを残さないため、使い捨ての sibling プロセスへ `2026-07-28` `_meta` 付き `server/discover` を送る（probe timeout は min(要求timeout, 2s)）。
- 版選択と再試行: `UnsupportedProtocolVersion`（-32022）応答の `data.supported` と discover 結果の `supportedVersions` から版を選ぶ。`2026-07-28` を明示的に含む場合のみ `UseMcp2026July28` — その場合は新しい子プロセスへ `_meta` 付き `tools/list` を送る。-32022 の `data.supported` が `2025-11-25` を含むなら `UseMcp2025November25`（選択された版として新しい子で `2025-11-25` の initialize を実行 — 推測ではない）。-32022 で supported が空・欠落・既知版を含まないなら `Unsupported` とし、推測での旧版フォールバックは行わない（-32022 自体が版交渉の応答であり、選択材料が無いのに initialize を試すのは fail-closed に反する）。discover 結果側で `2025-11-25` を含む・空・欠落なら `TryMcp2025November25`。既知の2版をどちらも含まない列挙は `Unsupported` とし、将来日付を暗黙対応しない。
- 旧版 initialize へ移る条件: プローブの spawn 後 IO 失敗・タイムアウト・応答の解析失敗・空出力、`-32601` 等の MCP 予約外エラー、`-32022` 以外の MCP 予約エラー（その `data.supported` は版交渉の根拠にしない）。これらはいずれも新しい子プロセスで `initialize` → `notifications/initialized` → `tools/list`（`2025-11-25`）を試し、同じ子プロセスへ継続送信しない。
- 対応する検証項目: discover 成功（`supportedVersions` に `2026-07-28`）、`-32022`＋各 supported 列挙（`2026-07-28`／`2025-11-25`／未知のみ／空）、`-32601` と `-32022` 以外の予約コード、不正・空のプローブ出力、タイムアウト・プロセス失敗からの旧版移行。`src/protocol/mod.rs` の単体試験と `tests/protocol_versions.rs` で確認する。

以下は通常実行の既定値です。dry-runで実際に転送した要求もPR-10の要求表で追跡し、通常時の許可／拒否判定とは区別します。

| 版 | 方向・種別／method | 通常時の扱い |
|---|---|---|
| 2025 | C2S initialize／notifications/initialized | 初期化の順序・capability・要求／通知の形を検査して許可 |
| 2025 | 双方向のping要求 | 初期化中を含め許可し、応答は方向付き要求表で相関させる |
| 両版 | C2S tools/list、tools/call | 許可。2025は初期化後、2026は各要求のメタデータを検査する。既存のツール定義・許可・引数検査も必須 |
| 両版 | C2S resources/list、resources/templates/list、resources/read、prompts/list、prompts/get、completion/complete | method・対象・必要capabilityに対応する明示規則がなければ拒否 |
| 2025 | C2S resources/subscribe、resources/unsubscribe | 明示規則とresourcesのsubscribe能力を要求し、URIの許可範囲・購読状態を照合 |
| 2025 | C2S logging/setLevel、S2C notifications/message | 明示規則とlogging能力、ログレベルの形式・設定を検査。未知通知扱いで一律破棄する実装にしない |
| 2025 | S2C sampling/createMessage、roots/list、elicitation/create | 明示規則と必要なclient capabilityが揃う場合だけ許可 |
| 2025 | C2S notifications/roots/list_changed、S2C notifications/elicitation/complete | 対応する機能の明示規則・capability・版固有の相関条件が揃う場合だけ許可 |
| 2025 | S2C notifications/tools/list_changed | 初期化時のtools.listChanged能力を照合して許可し、既存の定義再検証へ接続 |
| 2025 | S2C notifications/resources/list_changed、notifications/prompts/list_changed、notifications/resources/updated | 明示規則と必要capabilityを要求。resources/updatedは許可済み購読URIと一致する場合だけ許可 |
| 2025 | 双方向のnotifications/cancelled、notifications/progress | 取消は送信者が開始した追跡中の要求ID、進捗は元要求のprogressTokenへ対応付ける |
| 2026 | C2S server/discover | 各要求の版・メタデータ・形式を検査して許可。過去のdiscoverの成功を後続要求の前提にしない |
| 2026 | C2S subscriptions/listen | toolsListChangedのみの購読は既定で許可。promptsListChanged・resourcesListChanged・resourceSubscriptionsには通知種別とURI範囲の明示規則が必要 |
| 2026 | S2C notifications/subscriptions/acknowledged | 購読要求IDと一致するsubscriptionIdの最初の通知で、承認フィルターが要求・許可範囲の部分集合なら許可。購読要求は完了させない |
| 2026 | S2C notifications/tools/list_changed、notifications/prompts/list_changed、notifications/resources/list_changed、notifications/resources/updated | 有効な購読のsubscriptionIdと承認フィルターへ照合。resources/updatedは承認済みURIにも一致させる。tools/list_changedは既存の再検証へ接続 |
| 2026 | S2C notifications/progress | 購読通知として扱わず、進行中の元要求のprogressTokenと照合する。未要求・完了後・不一致の通知は破棄して監査 |
| 2026 | S2C notifications/message | 明示規則、元要求の_meta内のio.modelcontextprotocol/logLevel、要求したレベル以上であること、元要求との相関が確認できる場合だけ許可。購読通知として扱わない |
| 2026 | 双方向のnotifications/cancelled | C2S取消は追跡中のC2S要求IDへ対応付け、長寿命の購読もこの取消で終了する。S2C取消はsubscriptions/listenの終了時に限り、有効な購読要求IDを参照する場合だけ許可する。対応する有効な購読IDのないS2C取消は拒否する |
| 2026 | initialize、notifications/initialized、ping、logging/setLevel、resources/subscribe、resources/unsubscribe、notifications/roots/list_changed、notifications/elicitation/complete | この版では削除済み。要求は拒否し、通知は破棄して監査。明示規則でも復活させない |
| 2026 | S2Cトップレベル要求、C2Sトップレベル応答 | 版に反する通信として拒否。サーバーからの追加要求とその返答はMRTR内で扱う |
| 2026 | 応答内inputRequests | tools/call・resources/read・prompts/getの追跡済み元要求、版、capability、明示規則を満たす場合だけ許可。他の元要求へのinput_requiredは拒否 |
| 両版 | methodを持たない応答 | 2025は両方向、2026はS2Cのみ。反対方向へ送った追跡済み要求と版別の結果／エラー形式を照合。通常時の許可／拒否とdry-runによる転送を区別 |
| 両版 | 未知の要求／追加要求・未対応拡張 | 拒否。実験的tasksや拡張resultTypeは初期対応に含めず、対応追加時に判定表とfixtureを追加する |
| 両版 | 未知・不許可・相関不能の通知 | 破棄して監査。通知にJSON-RPC応答は返さない |

2026の要求メタデータのキーは `io.modelcontextprotocol/protocolVersion` と `io.modelcontextprotocol/clientCapabilities` を必須とする。progressTokenとlogLevelを購読IDへ読み替えない。stdioは全要求が同じチャネルを使うため、HTTPの応答ストリームを相関根拠に使わない。特にログ通知から元要求を特定できない場合は、その通知だけを破棄して理由を監査し、独自の必須フィールドを正式仕様の要件として追加しない。この制限も移行例に含める。

移行例では、従来通過していたresources/list・resources/templates/list・resources/read・resources/subscribe・resources/unsubscribe・prompts/list・prompts/get・completion/complete・logging/setLevelとサーバー起点機能を列挙し、2025で明示許可する例、2026の購読・要求単位logLevelへ移す例、未対応拡張の扱いを示す。

**検証:** T-BASE、T-LAYER、T-POLICY。表の各行について版・方向・種別・許可／拒否の純粋試験を作り、v2の継承・往復・bind・exportも確認する。2026の削除メソッド、必須メタデータ、resultType・キャッシュ情報、MRTR対象外の元要求、購読IDの型と値、URI範囲外、要求単位通知の相関不能を試す。tool内の未知プロパティ・未知子ノードは継承等を経由しても拒否されることを確認する。MCPの日付とKDLのversionを混同しない。

**完了条件:** 実装者が方向・版・種別別の判定を一意に実装できる。どの通信が制御対象か、互換性が変わる範囲、移行例がレビュー可能である。

**移行・戻し方:** 単独公開しない。構文を変える場合はPR-10／11とfixtureを同時に更新し、未知の制御を黙って捨てる読み込みへ戻さない。

**仕様の参照先:** [2025-11-25 lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)、[2026-07-28変更履歴](https://modelcontextprotocol.io/specification/2026-07-28/changelog)、[base protocol](https://modelcontextprotocol.io/specification/2026-07-28/basic/index)、[versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)、[subscriptions](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions)、[progress](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/progress)、[logging](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/logging)、[stdio](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)。実装時に参照版を固定する。

<a id="pr-10"></a>

### PR-10 双方向RPC・応答・通知の制御

対応論点: A2。直接依存: PR-09。着手・公開条件: 常設・PR-11まで単独公開しない。

**目的:** C2SとS2Cの両方で、要求・応答・通知を転送前に判定する。

**主な変更先:** [proxy_c2s.rs](../src/auditor/proxy_c2s.rs)、[proxy_s2c.rs](../src/auditor/proxy_s2c.rs)、[proxy_state.rs](../src/auditor/proxy_state.rs)、[proxy_wire.rs](../src/auditor/proxy_wire.rs)、[proxy_tools_list.rs](../src/auditor/proxy_tools_list.rs)、[checker.rs](../src/auditor/checker.rs)、[audit_log.rs](../src/audit_log.rs)。

**タスク**

- [ ] 既存のフレームサイズ上限を維持し、要求・応答・通知として構造検査する。通過判定を全転送経路の前へ置く。
- [ ] 方向とRpcIdを組にした有限の要求表を作る。既存tools/listの128件制限を参考に全体上限を確定し、重複・上限時に未応答要求を勝手に捨てない。
- [ ] 同じIDの逆方向要求、型の異なるID、無関係な応答、内部tools/list用IDとの衝突を区別する。内部再検証も所有者を明示して追跡する。
- [ ] 実際に転送する要求を登録し、通常時の許可／拒否判定とdry-runによる転送を別々に保持する。dry-runで転送した違反要求も追跡し、未転送の拒否要求は登録しない。応答・取消・EOF・切断時に状態を処理し、送信失敗時は登録を取り消す。
- [ ] 通知に応答を返さず、応答が許される要求の拒否は要求元へ版に合うエラーを返す。2026の不正なS2C要求には禁止されたC2S応答を生成せず、転送を止めて監査する。破損応答や孤立応答の扱いを定義し、別要求の成功に使わせない。
- [ ] 2026年版の購読を長寿命の要求として追跡する。購読ごとの最初の承認通知、承認済みフィルター、通知の `params._meta["io.modelcontextprotocol/subscriptionId"]` を検査する。別購読のメッセージが交錯しても混同せず、承認通知では要求を完了させない。取消・正常終了応答・EOF・切断で解放し、購読数と保持データにも上限を設ける。
- [ ] 購読とは別に、各要求の版・capability・progressToken・logLevelと、2025のURI購読・通知に必要な状態を保持する。通知はPR-09の相関条件で判定し、終了した要求の通知を別の進行中要求へ付け替えない。
- [ ] tools/listの検証・ページング・list_changed中の遮断、ツール定義の整合確認を維持する。
- [ ] 許可／拒否／破棄／dry-run上の判定と、実際に転送したかを監査に残す。dry-runの転送を通常の強制適用と表示しない。
- [ ] 監査失敗・要求表上限・低速相手へのバックプレッシャーが、無制限メモリや無監査通過につながらないようにする。

**検証:** T-BASE、T-PROTOCOL。両方向の要求、同ID、通知、取消、進捗、未知method、不正JSON-RPC、応答の二重送信、上限、監査障害をfixtureで確認する。2025の正常初期化と2026の正規フレームを通す。`generate-policy` のdiscoveryは既存の新旧判定・別プロセスでの再試行を維持する。

2026版では購読開始→承認→tools/list_changed→定義再検証の経路と、未承認・不一致ID・範囲外URI／通知・複数購読の交錯・取消・正常終了・上限時の動作を確認する。progressとmessageを購読通知へ混ぜず、未要求・元要求不明・完了後の通知を試す。tools/listの受信・再出力でresultTypeとキャッシュ情報を維持し、2025の正常結果へ新しい必須項目を要求しないことも確認する。dry-runでは違反要求の転送から正常なJSON-RPC応答の返却までを試し、孤立応答と誤認しないこと、未転送要求や無関係な応答を追跡済みとして扱わないことを確認する。要求をそのままechoする既存fixtureだけで往復の検証を代用しない。

**完了条件:** methodの有無だけで無条件転送する経路が残らない。まだMRTRを制御しない中間状態を、A2対応済みとして公開しない。

**移行・戻し方:** PR-09〜11を一体の公開単位にする。部分的に戻して片方向だけ制御する状態を新しい保証で公開しない。

<a id="pr-11"></a>

### PR-11 MRTR追加要求の制御と安全な既定値への移行

対応論点: A2 / C1。直接依存: PR-10。着手・公開条件: 常設。

**目的:** MRTRの追加要求をクライアントの処理前に制御し、MCP通過制御を移行可能な形で公開する。

**主な変更先:** [proxy_s2c.rs](../src/auditor/proxy_s2c.rs)、[proxy_c2s.rs](../src/auditor/proxy_c2s.rs)、[proxy_wire.rs](../src/auditor/proxy_wire.rs)、[session.rs](../src/auditor/session.rs)、[policy_generator.rs](../src/legislator/policy_generator.rs)、[MRTR fixtures](../tests/fixtures/mrtr)、[protocol_versions.rs](../tests/protocol_versions.rs)。

**タスク**

- [ ] `input_required` を、対応する転送済み・追跡済みの元要求に結び付ける。通常実行では元要求が許可済みであることも確認し、dry-runによる転送とは区別する。tools/callに加え、明示許可したresources/read・prompts/getでも規則を適用する。
- [ ] InputRequiredResultを返せる元要求をtools/call・resources/read・prompts/getに限定する。tools/list・server/discover・subscriptions/listen等へのinput_requiredは、追加要求の明示許可があっても仕様違反として拒否する。
- [ ] `inputRequests` の仕様上の形、method、capability、許可規則を調べ、未知・不許可があればクライアントへ渡す前に止める。
- [ ] 複数の追加要求の一つが不許可なら、初期実装では応答全体を拒否し、元の要求に対するエラーを返す。部分書き換えで継続状態の意味を壊さない。
- [ ] `requestState` の内容を解析・改変・権限判定に使わない。`inputRequests` がなくrequestStateだけの正規応答も扱う。
- [ ] input_requiredは元RPCへの応答として完了させるが、ツールの成功履歴へ入れない。再試行は別IDの独立要求として、ツール許可・引数・input_responses・trajectory等を再判定する。
- [ ] 既存の `input_responses=auto/deny/allow/inspect` と、新しい追加要求の通過許可を別の制御として説明・試験する。Autoはhas_security_contractがtrueならDeny、falseならAllowとする。Inspectは通過させて存在を監査へ記録し、内容検査を保証するモードへ読み替えない。
- [ ] v2の実行・生成をここで有効化する。新生成ポリシー、例、自己完結export、CLI、ランナーを揃える。PR-09のtool内未知制御の拒否を初回v2公開に含め、v1の移行後既定値と追加許可の書き方を文書化する。
- [ ] 応答内容のDLPを追加しない。監査には判断と理由を残し、sampling本文や入力値の収集を増やさない。
- [ ] 対応版の正常例と拒否例で実クライアント互換性を確認し、PR-09〜11を公開可能にする。

**検証:** T-BASE、T-POLICY、T-PROTOCOL、T-REAL。sampling／roots／elicitationの許可・拒否、不正追加要求、複数混在、別IDでの再試行、未知版、capability不足、元要求違い・対象外メソッドを確認する。再試行のinputResponsesは4値すべてとAutoの契約あり／なし、Inspectの監査記録を別の試験として維持する。dry-runで転送した違反要求へのinput_requiredも相関を維持し、追加要求の通過判定と区別する。拒否時にクライアント側の実行カウンターが増えないことをfixtureで検証する。

**完了条件:** 追加要求が転送された後にinputResponsesだけを拒否する経路で代用していない。v1移行・v2生成・旧バイナリ拒否の記録がある。既存の定義検証とツール別制御が維持される。

**移行・戻し方:** 通信互換性変更をリリースノートに記す。戻す際にv2をv1へ自動変換したり、無制限通過へ自動移行したりしない。既存版へ戻す場合の保証低下を明記する。

**仕様の参照先:** [2026-07-28 MRTR](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr)。再試行は別IDの独立した要求であり、requestStateは不透明な値として扱う。

<a id="pr-12"></a>

### PR-12 コード同一性の範囲と検証時点を明示

対応論点: A3。直接依存: PR-08。着手・公開条件: 常設。

**目的:** 実行コード全体の同一性を保証しているという誤認を、報告と文書・コメントの整合で解消する。

**主な変更先:** [verifier/hash.rs](../src/verifier/hash.rs)、[runtime/launch.rs](../src/runtime/launch.rs)、[workload.rs](../src/workload.rs)、[container/runner.rs](../src/container/runner.rs)、[policy_generator.rs](../src/legislator/policy_generator.rs)、[guide.md](guide.md)。

**タスク**

- [ ] LaunchReportへ対象種別・解決した実行ファイル・ハッシュ照合範囲・照合時点・依存範囲・可変部分を追加する。
- [ ] ネイティブファイル、別スクリプト、ランチャー／モジュール実行、イメージダイジェストを区別する。
- [ ] binary-hash／entrypoint-hash／lockfile-hash／docker-manifest-hashの役割を区別し、lockfileだけで実行対象が固定されたと表示しない。
- [ ] 初回内容照合、起動直前の実行ファイル再照合、スクリプトのパス対応確認を分ける。別スクリプト内容の直前再照合と不変保持がない現状を残す。
- [ ] イメージ内の依存先はその固定範囲に含め、追加マウント・書き込み層・起動後取得・ゲストカーネル等は別に記録する。
- [ ] 「再検証でTOCTOUを閉じる」等の過大なコメントを直す。解析未対応と検出ゼロを混ぜず、スキャナの網羅性拡大は本PRに入れない。
- [ ] 完全な依存閉包固定、fdベース実行、不変スナップショット、スクリプト直前再ハッシュは別の保証拡張として残し、このPRで解決済みとしない。

**検証:** T-BASE、T-IDENTITY、T-CONTAINERの該当ケース。Python仮想環境・symlink経由の実行、native、script、module／launcher、インライン評価拒否、可変タグ明示許容の報告を確認する。競合をsleepで再現させる不安定な試験は避け、検証時点を制御できるfixtureを使う。

**完了条件:** コード・報告・文書で保証の範囲と残る変更可能性が一致する。既存の拒否条件は弱まらず、スクリプトやネイティブ起動形を削除しない。

**移行・戻し方:** このPRは保証の明確化を主目的とする。報告形式は版で管理し、未実装の不変性を示す表現へ戻さない。

<a id="pr-13"></a>

### PR-13 Confused Deputyの説明と既存動作を整合

対応論点: A4。直接依存: なし。着手・公開条件: 常設。

**目的:** Confused Deputyの機能範囲を図・攻撃表・本文で一致させる。

**主な変更先:** [guide.md](guide.md)、[README.md](../README.md)、対応する翻訳、[proxy_c2s.rs](../src/auditor/proxy_c2s.rs)、[session.rs](../src/auditor/session.rs)の説明コメント。

**タスク**

- [ ] 既定オフ、名前固定の3操作、プロセス単位のknown_paths共有を図・表・本文へ揃える。
- [ ] 「それ以外のツールでは当該機能の検査を行わない」と書き、他のポリシー検査までないように読ませない。
- [ ] side_effectだけでは発見／利用を区別できないことを、一般化計画の前提にする。
- [ ] 1クライアント／1子プロセスの推奨と、共有時の境界を維持する。VM追加で状態分離が生じたとは書かない。

**検証:** T-DOC。対象実装と記述を突き合わせる。説明だけの修正なら新しい製品試験は作らない。

**完了条件:** 任意の限定機能が常設の一般的保護に見えない。PR-14を実施しなくてもこの説明修正は完了する。

**移行・戻し方:** 既定値・動作は変更しない。翻訳の原文対応を保ち、文字コード問題があればバックアップ後に最小差分で修正する。

<a id="pr-14"></a>

### PR-14 Confused Deputyの役割・パス抽出規則

対応論点: A4。直接依存: PR-11、PR-13。着手・公開条件: 一般化を実施する場合。

**目的:** 一般化を行う場合に、ツール名ではなく明示した役割とパス抽出規則で機能を動かす。

**主な変更先:** [policy/mod.rs](../src/policy/mod.rs)、[kdl_parse.rs](../src/policy/kdl_parse.rs)、[kdl_emit.rs](../src/policy/kdl_emit.rs)、[proxy_c2s.rs](../src/auditor/proxy_c2s.rs)、[proxy_s2c.rs](../src/auditor/proxy_s2c.rs)、[session.rs](../src/auditor/session.rs)。

**タスク**

- [ ] v2のtool設定へ、パス発見／利用の役割と、引数・応答のどこからパスを取るかを定義する。実行コードや任意評価式は許可しない。
- [ ] PR-09で定めた未知制御の拒否がPR-11時点のv2対応バイナリに含まれることを確認する。同じversion=2であることだけを旧版拒否の根拠にしない。先行v2が新設定を無視して受理する場合は、ポリシー形式の版を更新してから公開する。
- [ ] 初期の抽出規則を限定したJSON Pointerと既知の構造に絞り、配列数・サイズ・深さ・不正値・抽出失敗時の扱いを定義する。
- [ ] 既存の3つの名前は互換用の明示マッピングとして保持し、新方式との優先順位と移行方法を定める。
- [ ] 発見結果は相関の合う正常終了からだけ記録する。MRTR中間応答、失敗、無関係な応答でknown_pathsを増やさない。
- [ ] 利用役割を明示したツールの抽出失敗を、検査なしの許可にしない。
- [ ] 既定オフ、状態上限、パス正規化、プロセス共有を維持する。役割追加でセッション分離できたとは報告しない。

**検証:** T-BASE、T-POLICY、T-PROTOCOL。異なるツール名、同じread_onlyでも異なる役割、抽出失敗、失敗応答、MRTR、正規化、上限を試験する。旧設定の3名称の挙動と既定オフを維持する。新設定はv1専用バイナリだけでなくPR-11時点のv2対応バイナリでも拒否されることを確認する。既存3名称以外の利用役割ツールを使い、継承・include・when・profile経由でも設定だけが失われて許可されないことを検証する。

**完了条件:** 名前に依存しない設定が可能で、一般化後の限界が文書と一致する。新設定を理解しない先行v2を含む旧バイナリが、制御を省略して起動しない。一般化を選ばない場合は本PRを見送りと記録し、A4の説明修正まで未完了にしない。

**移行・戻し方:** 新設定を旧形式へ自動変換しない。PR-11時点のv2対応バイナリでは未知制御として拒否させ、それを保証できない場合は更新した形式の版で旧版を拒否する。状態分離等の追加仕様は本PRに混ぜない。

<a id="pr-15"></a>

### PR-15 追加隔離の選択・状態・ライフサイクル契約

対応論点: A5 / B2。直接依存: PR-08。着手・公開条件: 拡張の共通部分。

**目的:** OS固有方式をそのまま実装できる、追加隔離の最小限の接続契約を作る。

**主な変更先:** [container/engine.rs](../src/container/engine.rs)、[options.rs](../src/container/options.rs)、[runner.rs](../src/container/runner.rs)、[cli](../src/cli)、PR-02／03の共通値型。新規アダプターは `mcp-writ/src/container/backends/` 等を候補とする。

**タスク**

- [ ] エンジンと隔離方式を別に選択するCLI／値型を定義する。`--isolation` 等の明示選択を基本とし、既存runのnative・run-imageの通常コンテナという既定を維持する。
- [ ] バックエンドが実行可能なOS、イメージ／コマンド、stdio、停止、共有、資源、観測手段を宣言する。能力は実際の適用成功とは別にする。
- [ ] バックエンドは実行ハンドルと、起動・観測・終了・後始末を提供する。Windows SandboxへOCI buildを要求する等の過剰な共通インターフェースを作らない。
- [ ] 型付きの起動条件から引数を組み立てる。未対応の組み合わせを拒否し、Linux用entrypointをWindowsへ流用しない。
- [ ] 設定された隔離、実行エンジンが確認した隔離、ゲスト報告を別々に記録する。起動ID・コンテナ／VM識別子・分離単位を関連付ける。
- [ ] 不足する隔離を通常実行へ切り替えない。必要な確認が欠ける場合の開始拒否・停止を定義する。
- [ ] stdin EOF、終了コード、キャンセル、中断、部分起動失敗で資源を解放する共通の契約試験を作る。バックエンド固有の実装は保持する。
- [ ] Docker／Podman／Buildahの既存能力差を維持し、エンジン全体の書き換えを避ける。

**検証:** T-BASE、T-LAYER、T-CONTAINER。実VMを要求しない契約試験で、非対応、起動途中失敗、停止、重複終了、要求と観測の不一致を確認する。fakeの成功だけで実バックエンド対応済みとはしない。

**完了条件:** 既存方式が退行せず、後続の各方式を独立に組み込める。CLI上は未実装方式を選択可能な成功経路として露出させない。

**移行・戻し方:** 必要なら新方式の選択だけを無効にできる。既存経路への自動フォールバックは実装しない。

<a id="pr-16"></a>

### PR-16 Linux Kataの実機検証

対応論点: A5。直接依存: PR-08。着手・公開条件: 計画対象・実機必須。

**目的:** LinuxのKataで、既存のLinux WardenとMCP実行が同時に成立することを実機で確かめる。

**主な成果物:** 再現手順・結果の新規文書 `mcp-writ/docs/validation/kata.md`、必要なfixtureと試作コード。製品の通常経路へ未検証コードを有効化しない。

**タスク**

- [ ] Linuxホスト・arch・仮想化機能・Docker・Kata・QEMU・ゲストカーネルの版と設定を固定して記録する。最初はDocker＋Kata＋QEMUの1構成に絞る。
- [ ] 登録したKata runtimeの実体と設定、エンジン側の起動情報、ゲスト側の情報を合わせてVM実行を確認する。ゲストのunameだけで証明を完了しない。
- [ ] 既存ランナーを含むダイジェスト固定イメージでstdio MCPを起動する。Landlock／seccompのゲスト側対応と実際の許可・拒否を調べる。
- [ ] 必須制御が欠ける場合は、必要なゲスト構成変更と維持費を記録する。allow_degradedやsandbox省略を使って対応済みにしない。
- [ ] ポリシーの読み取り専用共有、監査・報告の回収、EOF・中断・強制停止、VMの掃除を試す。
- [ ] 通常コンテナと同じfixtureでcold／warm起動、最初の応答、メモリ、停止を測る。製品組み込み時の許容値を記録する。
- [ ] Podman等の別エンジンをこの結果から対応済みと推定しない。

**検証:** T-VMのKata版を作る。許可・拒否のファイル操作、ゲスト内の制御状態、未知MCP要求の拒否、stdio混入なし、必要機能欠落時の失敗を記録する。試作コードは既定のCLIへ接続しない。PR-11の通信制御やPR-15の実行契約が未完成なら該当項目を未完了と記録し、PR-17で通信制御・PR-08の報告・PR-15の実行契約を再検証する。

**完了条件:** 実行コマンド、版、結果、未確認、採用判断、性能許容値が残る。環境未確保なら調査状態を記録できるが、Kata対応完了にはしない。

**戻し方:** 所有する試作VM・コンテナ・設定だけを戻す。利用者の他のVMやエンジン設定をまとめて消さない。

<a id="pr-17"></a>

### PR-17 Linux Kataバックエンドの製品組み込み

対応論点: A5。直接依存: PR-11、PR-12、PR-15、PR-16。着手・公開条件: PR-16の受入条件成立。

**目的:** 検証したKata構成を、明示選択できる追加隔離として製品へ組み込む。

**主な変更先:** [container/engine.rs](../src/container/engine.rs)、[options.rs](../src/container/options.rs)、[runner.rs](../src/container/runner.rs)、[cli](../src/cli)。新規バックエンドは `mcp-writ/src/container/backends/kata.rs` 等を候補とする。

**タスク**

- [ ] PR-16で確認した構成だけを初期対応にする。エンジン名・runtimeの識別子・必要条件を検査し、明示的なKata選択を起動引数へ結び付ける。
- [ ] 実行先とイメージのLinux／archを確認する。Kataの導入がない、runtimeが違う、必要な観測がない場合に起動を完了扱いにしない。
- [ ] 1サーバー／1VMを初期の分離単位とし、使い回しによる共有を黙って導入しない。
- [ ] PR-08のゲスト報告とPR-15の実行契約へ接続する。ゲスト内Auditor・Wardenの位置、イメージとゲストカーネルの固定範囲を表示する。
- [ ] 通常コンテナへのフォールバックを禁止し、中断・部分失敗・終了コード・後始末を実装する。
- [ ] 既存Linuxネイティブ・Docker／Podman経路を回帰確認し、Kata専用導入手順を追加する。

**検証:** T-BASE、T-CONTAINER、T-PROTOCOL、T-VMのKata版。指定runtime不在、別runtimeでの起動、ゲスト機能不足、ポリシー不一致、取消、ログ回収失敗を含む。PR-16の測定と比較し、決めた予算内か確認する。

**完了条件:** 明示指定と実行実績が一致し、通常実行の必須制御を維持したKata起動が再現可能。対応OS／版／archの範囲を記載する。

**移行・戻し方:** 任意選択として提供する。問題のあるKata経路だけを未対応へ戻し、自動で通常コンテナを実行しない。

<a id="pr-18"></a>

### PR-18 Apple containerの実機検証

対応論点: A5。直接依存: PR-08。着手・公開条件: 候補検証・実機必須。

**目的:** Apple公式のcontainerを使う追加方式で、Linuxゲスト内の既存制御が成立するか確認する。

**主な成果物:** 新規 `mcp-writ/docs/validation/apple-container.md` と試作fixture。macOSネイティブ実装は変更しない。

**タスク**

- [ ] 対応Apple silicon・macOS・containerの版と、利用するLinuxゲストカーネル・arm64イメージを固定する。
- [ ] 初期はインストール済みの公式container CLIを利用する案を検証する。Rustから独自VMMやSwift管理層を作ることを前提にしない。
- [ ] containerの起動、非TTYの双方向stdio、イメージのinspect／digest、マウント、終了処理を調べ、PR-15の能力契約へ対応付ける。
- [ ] ゲストのLandlock／seccompを実動作で確認する。標準ゲストで不足する場合、必要な構成変更と更新方法を調査する。
- [ ] ホスト側のネイティブサンドボックス経路と、ゲスト側Linux制御の位置を図と報告で区別する。
- [ ] 共有パス、ネットワーク、ポリシー、監査・報告、異常終了後のVMを確認し、cold／warmの性能・資源を測る。
- [ ] 公式CLIで満たせない条件は明記し、ライブラリ直接利用が必要なら規模と追加の維持費を採用判断へ含める。

**検証:** 実macOSでT-VMのApple版とT-NATIVE。古いmacOS／非対応archは明示拒否を検証する。Linuxゲストの機能確認をmacOSネイティブ試験の代替にしない。試作コードは既定のCLIへ接続せず、未完成の通信制御・実行契約は未完了と記録する。PR-19でPR-11の通信制御・PR-08の報告・PR-15の実行契約を再検証する。

**完了条件:** 必須条件を満たす構成、または採用を保留する具体的理由がある。PR-19へ進む場合はstdio・制御・観測・性能の許容値が定まっている。

**戻し方:** 試作で作成した資源を停止・削除し、macOSネイティブ実行を保つ。未成立の機能を通常実行へ自動切替しない。

<a id="pr-19"></a>

### PR-19 Apple containerバックエンドの製品組み込み

対応論点: A5。直接依存: PR-11、PR-12、PR-15、PR-18。着手・公開条件: PR-18で採用可能と判断。

**目的:** 成立したApple containerの構成を、macOSの任意の追加隔離として提供する。

**主な変更先:** [container](../src/container)、[cli](../src/cli)、[docs](.)。新規 `mcp-writ/src/container/backends/apple.rs` 等を候補とする。

**タスク**

- [ ] Apple container CLIの版・実行先・能力を確認するアダプターを実装する。Docker互換引数をそのまま渡さない。
- [ ] Linuxイメージとarm64ランナーの整合を確認し、digest検査・ポリシー受け渡し・非TTY stdio・終了を接続する。
- [ ] wrap／buildまで扱う場合は公式CLIの対応を確認する。初回は対応済みOCIイメージのrunに絞ることを許容し、未対応buildを明示する。
- [ ] VM選択とゲストの制御結果をLaunchReportへ統合する。ホストはmacOS、ワークロードはLinuxと表示する。
- [ ] macOSネイティブ経路を維持し、未対応OS・arch・ゲスト機能不足の拒否を実装する。
- [ ] 必要条件と導入手順、共有・ネットワーク・資源設定の意味を文書化する。

**検証:** T-BASE、T-PROTOCOL、Apple版T-VM、macOSのT-NATIVE。CLI不在・未対応版・起動途中失敗・報告不一致・取消・再起動・終了後の資源を確認する。

**完了条件:** PR-18の採用条件と性能予算を満たす実行が製品経路で再現できる。未実装のOCI操作を対応済みと表示しない。

**移行・戻し方:** 追加方式を無効化してもネイティブは使える。通常コンテナや非隔離起動への暗黙切替は行わない。

<a id="pr-20"></a>

### PR-20 Windows Hyper-V分離コンテナの実機検証

対応論点: A5。直接依存: PR-06。着手・公開条件: 優先候補検証・実機必須。

**目的:** Hyper-V分離Windowsコンテナの内側で、Windows版Wardenが機能するかを先に確認する。

**主な成果物:** 新規 `mcp-writ/docs/validation/windows-hyperv.md`、試作Dockerfile・fixture。製品用WindowsイメージはPR-21で整える。

**タスク**

- [ ] ホストのWindows版・edition・arch・仮想化条件、エンジンのWindowsモード、対応するWindowsベースイメージを確認し固定する。
- [ ] 最初は必要APIを備えた構成でWindows版mcp-writを起動する。Nano Serverへの軽量化を成立条件にしない。
- [ ] `--isolation=hyperv` の指定と、エンジンが報告する実際の分離を照合する。process isolationで代用しない。
- [ ] ゲストでAppContainer作成、必要なcapability、DACL、Job割当と子孫終了が使えるかを個別に確認する。
- [ ] Windowsのパス・環境・コマンドライン、双方向stdio、ポリシー受け渡し、ログ保存、ホスト共有の権限を試す。
- [ ] ゲスト内の権限不足やJobの制約を記録する。AppContainerを省略しないと動かない構成は、現在の受入条件を満たさない。
- [ ] cold／warm、イメージサイズ、初回取得・更新、メモリ、終了を測り、適合するベースイメージと許容値を記録する。

**検証:** 実WindowsのHyper-V分離環境でT-VM。許可／拒否パス、Jobによる子孫終了、ネットワークの既存Windows制約、ゲスト報告、停止後の資源を確認する。試作コードは既定のCLIへ接続せず、PR-11の通信制御・PR-08／21のゲスト報告・PR-15の実行契約が未完成なら該当項目を未完了と記録する。PR-22でこれらを再検証し、試作の併用可否だけで製品対応済みとしない。

**完了条件:** Windows版Wardenとの併用可否を証拠付きで判断できる。併用不可ならPR-22を開始せず、必要な追加調査を残す。

**戻し方:** 所有する試作コンテナとイメージだけを整理する。ホスト全体の仮想化設定を無断で切り替える手順にしない。

<a id="pr-21"></a>

### PR-21 Windowsゲスト用ランナー・配布物・イメージ

対応論点: A5 / A3。直接依存: PR-06、PR-12、PR-15。着手・公開条件: PR-20またはPR-23で採用可能と判断。

**目的:** 採用可能なWindows方式向けに、Windowsゲストで動くランナーと起動物を用意する。

**主な変更先:** [mcp-secure-runner.rs](../src/bin/mcp-secure-runner.rs)、[runner_resolve.rs](../src/container/runner_resolve.rs)、[dockerfile.rs](../src/container/dockerfile.rs)、[containerize_dockerfile.rs](../src/container/containerize_dockerfile.rs)、[release.yml](../.github/workflows/release.yml)の配布物生成箇所。

**タスク**

- [ ] 固定されたLinux用policy／audit／runnerの配置を、ゲスト対象別の起動契約へ分ける。Linuxの既定パスは維持する。
- [ ] Windows用ポリシーパス・ログ先・一時領域・実行ファイルのパスを定義し、ホストが選んだ信頼できる起動設定として渡す。
- [ ] 元コマンドの引数・Unicode・空白・環境・server bindを維持し、シェル文字列を組み立てて起動しない。
- [ ] Windows版バイナリのarch・形式を検査する。ELFをWindowsへ、WindowsバイナリをLinuxへコピーしない。
- [ ] Hyper-Vを採用する場合はPR-20で適合したWindowsベースイメージを使う。Sandboxを採用する場合は同じランナー契約を使うゲスト配置物を用意する。
- [ ] バイナリ・イメージの固定範囲、版、チェックサムを記録し、PR-12の報告へ接続する。
- [ ] releaseの既存Linuxランナー資産を維持し、Windows用を追加できる生成・パッケージ工程を整える。実際の公開作業はこの実装PRと区別する。

**検証:** T-BASE、T-IDENTITY、T-POLICYを実Windowsで実行する。パス・空白・日本語・環境値・失敗終了・監査先不正を検証する。Hyper-V用イメージはdigest固定で実際に起動し、Sandbox用配置物は採用時にPR-24で接続試験する。

**完了条件:** 少なくとも採用する一方のWindows方式のゲストにランナーを再現可能に配置できる。Linuxの既存配布・配置契約を壊さない。

**移行・戻し方:** PR-20またはPR-23が採用可能と判断されるまで着手しない。既存Linux資産と別の識別子で追加し、旧イメージをWindows用として再解釈しない。

<a id="pr-22"></a>

### PR-22 Hyper-V分離Windowsコンテナの製品組み込み

対応論点: A5。直接依存: PR-11、PR-20、PR-21。着手・公開条件: PR-20の受入条件成立。

**目的:** Windows Hyper-V分離コンテナを、追加隔離として明示選択できるようにする。

**主な変更先:** [container](../src/container)、[cli](../src/cli)、[docs](.)。新規 `mcp-writ/src/container/backends/hyperv.rs` 等を候補とする。

**タスク**

- [ ] ホスト・エンジンモード・イメージOSとarch・Hyper-V前提を検証する。
- [ ] Hyper-V分離を明示指定し、実行後のエンジン情報と照合する。process isolationなら続行しない。
- [ ] Windows用entrypoint・ポリシー・ログのマウントを、PR-21の契約で設定する。
- [ ] ゲストのWindows Warden観測をPR-15の結果へ統合する。VMの分離とAppContainer等を別項目で表示する。
- [ ] EOF・キャンセル・異常終了・起動途中の掃除を実装し、割り当てたコンテナ以外を停止しない。
- [ ] Windowsネイティブおよび既存Linuxコンテナ利用時の対象判定を回帰確認する。

**検証:** T-BASE、T-PROTOCOL、WindowsのT-NATIVEとHyper-V版T-VM。隔離指定の不一致、ゲスト制御の失敗、報告欠落、ログ共有の不備、停止・再実行を確認する。PR-20の資源予算を検証する。

**完了条件:** 製品経路から1サーバー／1VMが成立し、Windowsの必須制御を維持する。対応ホストとイメージの組み合わせが明記される。

**移行・戻し方:** 当該方式だけを無効化できる。Windowsネイティブ、process isolation、Linux VMへ暗黙に置き換えない。

<a id="pr-23"></a>

### PR-23 Windows Sandboxのstdio中継と成立性検証

対応論点: A5。直接依存: PR-06。着手・公開条件: 候補検証・実機必須。

**目的:** Windows Sandboxで、双方向stdioを含む運用が成立するかを判断する。

**主な成果物:** 新規 `mcp-writ/docs/validation/windows-sandbox.md` と中継の試作。標準 `wsb exec` はプロセスI/Oを提供しないという前提で着手する。

**タスク**

- [ ] 対応Windows版・機能・起動セッション要件、同時起動や既存Sandboxとの共存を調べる。
- [ ] 利用できるIPC／専用通信経路を選び、host stdin→guest child stdinと逆方向を実装する試作を作る。単発のコマンド終了コードだけで完了にしない。
- [ ] 中継の接続元・起動ID・通信相手を検証し、ワークロードへホストの任意コマンド実行権限を渡さない。中継用の共有・通信も許可範囲として記録する。
- [ ] 大きいフレーム、低速相手、EOF、取消、子のクラッシュ、Sandbox停止でバックプレッシャーと終了を確認する。
- [ ] 中継のフレームサイズ・キュー・期限の上限を記録する。製品組み込みではPR-10のフレーム上限・バックプレッシャーとPR-15の停止契約へ揃え、中継だけに無制限のバッファを残さない。
- [ ] ゲストでWindows版Wardenを使い、OS制御・監査・報告の配置を試す。
- [ ] 所有するSandboxを識別して停止できるかを確認する。利用者の既存Sandboxの停止や共有を前提にしない。
- [ ] 対話UI・セッション要件がOSSの実行経路として受容できるか、起動・メモリ・中継遅延と一緒に判断する。

**検証:** 実機のT-VM。双方からの通信、フレーム混入、接続先なりすまし、制御適用失敗、監査保存、所有資源だけの停止を確認する。試作中継は既定のCLIへ接続せず、未完成の通信制御・報告・実行契約は未完了と記録する。PR-24でPR-10／11の通信制御と上限・PR-08／21の報告・PR-15の実行契約を再検証する。

**完了条件:** 中継を含む再現可能な運用方式と必要条件が示される。成立しなければPR-24を保留し、Hyper-V候補とネイティブ経路を維持する。

**戻し方:** 試作中継・作成資源だけを除去する。MXC／Nanvix／Hyperlightの実験機能を、必須の保護の代替として導入しない。

<a id="pr-24"></a>

### PR-24 Windows Sandboxバックエンドの製品組み込み

対応論点: A5。直接依存: PR-11、PR-21、PR-23。着手・公開条件: PR-23で採用可能と判断。

**目的:** 採用条件を満たしたWindows Sandbox方式だけを、製品の任意実行経路として提供する。

**主な変更先:** [cli](../src/cli)、[container](../src/container)、PR-21のランナー契約。新規 `mcp-writ/src/container/backends/windows_sandbox.rs` と中継コンポーネントを候補とする。既存 `mcp-writ/src/warden/windows_sandbox.rs` はAppContainerの実装であり、同一機能として置き換えない。

**タスク**

- [ ] PR-23で採用した中継を、対象OS・セッション条件・接続認証・上限・期限を持つ製品コンポーネントにする。
- [ ] コマンド／配置物をゲストの固定したパスへ渡す。OCIイメージ専用の契約へ無理に押し込めない。
- [ ] Sandboxの識別子・分離単位・所有者を管理し、同時実行できない構成なら起動前に拒否する。
- [ ] ゲスト内のWarden・Auditorと、その外側の中継・報告を結ぶ。中継やSandbox起動だけを制御適用の証拠にしない。
- [ ] EOF・取消・終了コード・異常終了・後始末をPR-15の契約へ接続する。別のSandboxを終了しない。
- [ ] 導入・更新・必要なユーザーセッション・非対応条件を診断と文書へ反映する。

**検証:** T-BASE、T-PROTOCOL、WindowsのT-NATIVE、Sandbox版T-VM。中継障害、セッション不成立、誤ったID、同時起動、停止後の資源と再実行を確認する。PR-23の遅延・資源予算を満たす。

**完了条件:** 採用した環境で双方向MCPが安定し、必須制御・監査・状態報告が維持される。CLIのみで成立しない制約を隠さない。

**移行・戻し方:** 明示的な追加方式として提供し、不具合時は選択を拒否する。nativeやHyper-Vへ自動切替しない。

<a id="pr-25"></a>

### PR-25 採用VM方式の手動CIと証跡収集

対応論点: A5 / C2。直接依存: PR-01、PR-15。着手・公開条件: 採用するPR-17 / 19 / 22 / 24を方式別に追加依存。

**目的:** 採用方式ごとに、再現可能な手動検証と実行証拠を保つ。

**主な変更先:** [.github/workflows](../.github/workflows)、[tests/common/mod.rs](../tests/common/mod.rs)、新規VM結合試験・実機検証文書。

**タスク**

- [ ] 採用したPR-17／19／22／24を方式ごとの前提に加え、OS・arch・仮想化・ゲストの条件を明記した手動ジョブを作る。
- [ ] hosted runnerで必要機能が使えると仮定しない。専用環境を使う場合は実行対象コミットと環境を固定し、検証資源を分離する。
- [ ] 必須VMジョブでは環境不成立や全件スキップを成功にしない。native・通常コンテナ・VMの結果を別々に集計する。
- [ ] コミット、エンジン・runtime・OS・ゲスト・イメージ版、起動報告、実試験件数、性能、後始末結果をartifactに残す。資格情報やRPCの任意本文を追加保存しない。
- [ ] 既存のnative 3 OS・Docker／Podman・実サーバーの手動ジョブを維持する。
- [ ] 各方式の専用検証から主計画の回帰検証へ辿れるようにし、PR-01の担当一覧を更新する。

**検証:** 採用方式ごとのT-VMと、該当T-NATIVE／T-CONTAINERを手動起動する。実行対象がゼロ、必要機能欠落、報告未保存の失敗ケースも確認する。

**完了条件:** 対応済みとするすべてのVM方式に、実際に走った成功・拒否・停止の証拠がある。保留方式は別行に残り、対応済みの件数へ入らない。

**移行・戻し方:** 方式ごとのジョブは独立に停止できる。実機環境が失われた場合は最新検証時点と未確認範囲を明示し、自動実行へ方針転換しない。

<a id="pr-26"></a>

### PR-26 対応表・導入文書・配布記述の最終整合

対応論点: 全項目。直接依存: PR-08、PR-11、PR-12、PR-13、PR-25。着手・公開条件: 条件付きPRは採否・未対応理由を記録。

**目的:** 実装・検証・説明・配布記述を、利用者が選択できる実行方式の単位で揃える。

**主な変更先:** [README.md](../README.md)、[guide.md](guide.md)、[docs](.)のquickstart・翻訳・構成図・攻撃表、[release.yml](../.github/workflows/release.yml)の記述に対応する資料。

**タスク**

- [ ] host／target／backend／native sandbox／追加VM／対応操作／対応版を一覧にし、採用・候補・保留・非対応を区別する。
- [ ] native 3 OSと採用した追加方式の短い導入例を揃える。OS差を省略して誤解させず、診断→起動→結果確認へ繋ぐ。
- [ ] v1→v2の通信規則移行、応答内追加要求、未知要求の拒否理由を説明する。
- [ ] 権限共有、ハッシュの範囲・検証時点、Confused Deputyの任意性、DLP／HTTP-SSEの対象外を一致させる。
- [ ] PR-01で整えたチェックリストにある主計画公開時の配布照合記録を引き継ぎ、VM拡張で追加・変更する配布も実際の公開URL・版・資産と照合する。確認日付きで配布記述へ反映し、未確認の配布を完了済みと書かない。
- [ ] PR-14と候補方式を見送った場合は、その理由と将来再開の条件を残す。Kataが未成立なら拡張全体は未完了と記録する。
- [ ] 主計画の公開条件とVM方式ごとの公開条件の達成状況をまとめる。公開操作そのものはこの文書整合PRに混ぜない。

**検証:** T-DOC。PR-01／25の実行記録と対応表を照合し、導入例を該当環境で再現する。既存の成功証拠を再利用し、文書修正だけで全性能試験を繰り返さない。動作を変えた例は必要な範囲を再確認する。

**完了条件:** 利用者が、自分のOSで維持される保護と追加可能な隔離、必要条件、未確認事項を判断できる。対応済みの主張に対応する実機証拠がある。

**移行・戻し方:** 配布が取り消された場合は記述も合わせる。説明を戻して既定オフや残る境界を隠さない。

## 実装結果として残す記録

各PRの本文または実機検証文書には、次の項目を残します。調査だけで終えたPRにも、未確認事項と後続PRの開始条件を記録してください。

| 項目 | 記載内容 |
|---|---|
| 対象 | 実装コミット、前提PR、元の論点名 |
| 環境 | CLIホスト、実行基盤、対象OS／arch、カーネル、エンジン、ゲスト、イメージの版 |
| 実行 | 再現コマンド、必要条件、対象試験と実行件数 |
| 結果 | 成功・拒否・失敗・スキップ・未確認を区別 |
| 制御 | 適用予定、観測、取得根拠、残る制約、制御の配置 |
| 互換性 | 既存利用者への変更、ポリシー移行、旧版との組み合わせ |
| 資源 | 必要な測定の結果と基準。未測定は未測定と記載 |
| 後始末 | 子・孫プロセス、コンテナ／VM、一時領域、ハンドル、変更した設定 |
| 次の判断 | 完了、後続可、条件付き、保留。保留の解除に必要な具体的条件 |

常に信頼する基盤の範囲を明示します。初期VM対応ではホストOS・選択した管理エンジンと起動前の信頼できるランナーを前提にし、管理者権限の奪取検出やリモートアテステーションまで保証しません。ゲスト内の報告を取得した事実と、ゲスト侵害後も正しい情報であることは区別します。

手順書を更新した場合は、全体計画のPR一覧・対応論点・依存・採用条件も合わせます。実装済みかどうかは本書の存在から判断せず、該当PRの実装と試験記録で判断してください。
