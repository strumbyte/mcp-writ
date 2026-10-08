# mcp-writ 改善計画 PR別実装手順書（2026-10）

作成日: 2026-10-07

状態: **計画のみ**。各PRの実装・環境更新・コミット・ブランチ作成・push・GitHub PR作成は、別途指示があるまで行いません。以下の共通手順にある実装・PR操作は、将来の実装着手時の手順です。

[改善計画](improvement-plan-2026-10.ja.md)を目的・範囲・ロードマップの正とし、本書をPR単位の作業順序の正とします。基準コミットは `562ea185`（v0.2.0 tip）。対象箇所が基準から変わった場合は、本書の事実・依存・試験を更新します。

本書のPR番号は本計画内の番号です。旧手順書 [archive/implementation-pr-guide.ja.md](archive/implementation-pr-guide.ja.md) のPR-01〜32とは無関係です。

ロードマップ対応: PR-01〜08 が v0.3（§2 全部＋§1.1／§1.2／§1.3(a)／§1.6／§2.5）、PR-09〜13 が v0.4（§1.3(c)／§1.3(b)／§1.5／§3.3 Windows／§3.1）、PR-14〜16 が v0.5+（§5.1-5.2／netns 本番化／§1.7 継続評価）に対応します。各リリースでバージョンを上げる条件と手順は、作業の流れの中のリリース節（[v0.3.0](#release-v0-3)／[v0.4.0](#release-v0-4)／[v0.5+](#release-v0-5)）に記載します — その時点で確認するものなので、先読みは不要です。

## 共通手順

### 作業開始

1. 対象ブランチのHEAD、作業ツリー、適用済みの前提PRを確認する。基準コミット `562ea185` から対象箇所が変わった場合は、本書の事実・依存・試験を更新する。
2. 当該PRの目的と受入条件をPR本文へ転記する。PoC・実機検証を含むPRでは、先行する試作の実測記録を添付する。
3. 新しいファイル・型・オプション名は提案である。既存APIと取り違えず、担当PRで確定し、影響する後続PRへ反映する。
4. 新規モジュールを作るPRは、`docs/modules.md` の依存方向説明と `tests/module_layering.rs` の LAYERS 登録を同じPRで行う。
5. 既存の利用者変更を保持する。日本語ファイルの文字コード問題が疑われる場合は、編集前にバックアップする。

### 実装中の共通条件

- 通信の**中身は見ない**。制御するのは宛先だけ（制御面の延長）。TLS 内部・HTTP ボディ・RPC 応答本文の検査機能を追加しない。
- 宛先制御は**ドメイン層（DNS ゲート/名前ポリシー）＋ IP 層（接続時強制）の 2 層モデル**。片方しか効かない経路を「ドメイン制御あり」と表示しない — 「plain spawn = IP 層のみ、namespaced = 2 層」の能力差を正直に明記する。
- 監査に残らない挙動（バイパス・スキップ・ダイヤル低下・観測不能な拒否）は「無かったこと」にしない。残せない場合は限界として仕様化・文書化する。
- 非保証・限界は隠さず仕様として開示する。シナリオ B（IP 直打ち流出）が効かない経路で「宛先制御済み」と見せない。
- 非特権 CLI を既定に保つ。特権が要る機構（cgroup eBPF 等）は opt-in とし、既定経路を特権前提にしない。
- 既存の fail-closed 監査、channel drop カウンタ、hash pin / re-verify、6 系統の隔離経路（OCI/Kata/Apple Container/Hyper-V/Windows Sandbox/WSLc）、deny 既定を維持する。
- ポリシー形式の拡張は旧版バイナリが黙って無視しないことを確認する。`policy version=2` の未知属性拒否に新属性を正規登録する。
- 新しい試験は、拒否されるべき動作と維持すべき正規動作を対にする。「観測不能であること」を仕様として固定する試験は、emit 失敗の検出ではなく仕様の表明として書く。
- 文書修正だけのPRに不要な製品テストを新設しない。関連する既存試験を使う。

### PRを閉じるとき

- 対象コミット、OS・arch・カーネル／ビルド、実行方式、コマンド、結果を記録する。
- 成功・失敗・スキップ・環境未確保を分ける。実行していない試験を「通過」と書かない。
- 追加・変更したテストがどの手動ワークフローに含まれるか確認し、[test-matrix.md](test-matrix.md) の担当一覧へ登録する。
- 表示した権限・制御が、実際のルール構築と同じ情報から得られるか確認する。`--report` と JSONL 監査で同じ事実を指すか照合する。
- UTF-8、BOMなし、LF、リンク、差分を確認する。PowerShellで日本語を書く場合はUTF-8を明示する。
- 「拒否した」ことを示す証拠と「観測できない」ことを区別する。カーネル内拒否（Landlock/seccomp/Job）は通知が来ないため emit 不可であり、観測経路のある経路（supervisor/proxy/DNS ゲート）のみ emit できる。

### 検証セット

作業ディレクトリはリポジトリルート（`mcp-writ`）とし、文中のパス表記は `mcp-writ/` をルートとします。以下は基準コミットに存在するターゲットです。追加ターゲットは担当PRで明示的に追加し、そのPRのワークフローにも組み込みます。

| ID | 内容・コマンド | 実行条件 |
|---|---|---|
| T-BASE | `cargo fmt --all -- --check`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo test --locked --lib --bins`、`cargo doc --locked --no-deps`、`cargo test --locked --doc` | Rustコード変更時。OS固有コードは該当OSでも実行 |
| T-DOC | `cargo test --locked --test docs_check` | 文書・リンク・文字コードの確認 |
| T-LAYER | `cargo test --locked --test module_layering` | モジュール・依存関係変更時。新規モジュールは LAYERS 登録と同じPRで |
| T-POLICY | `cargo test --locked --test kdl_policy_e2e --test environment_e2e --test go_runtime_policy` | ポリシー形式・継承・生成・export の契約変更時 |
| T-NATIVE | `cargo test --locked --test diagnostics_e2e --test path_resolution_e2e --test environment_e2e --test self_test` | 各 OS の該当環境。OS 適用の実試験を含む |
| T-PROTOCOL | `cargo test --locked --test protocol_versions --test tool_enforcement_e2e --test integration --test manifest_fixtures` | MCP 規則・監査イベント変更時 |
| T-IDENTITY | `cargo test --locked --test workload_hash_e2e --test path_resolution_e2e` | 実行対象・検証時点の変更時 |
| T-CONTAINER | `cargo test --locked --test container_e2e --test wrap_image_e2e --test containerize_e2e` | コンテナ経路の変更時 |
| T-VM | 当該方式の実機試験 | PR-09・PR-11・PR-12 の実機確認。環境情報・実行件数・隔離確認・結果の証拠が必須 |

新規コンポーネント（DNS ゲート・unotify supervisor・netns プロキシ）の結合試験ターゲット名は担当PRで確定して本表へ追加します。既存の `MCP_WRIT_REQUIRE_*_TESTS=1` 系の必須モード規則を新規試験にも適用し、全件スキップを成功扱いしない仕組みを設けます。

## 作業の流れ（PR とリリース）

- [PR-01 監査イベントの棚卸しとライフサイクル・設定イベントの実装](#pr-01)
- [PR-02 バイパス・ダイヤル低下・dry-run の監査記録](#pr-02)
- [PR-03 `server.connected` の enforcement 状態と PSEC 状態の JSONL](#pr-03)
- [PR-04 監査バッファの SIGKILL 耐性と外部転送](#pr-04)
- [PR-05 egress ポリシースキーマ — `allow cidr` と 2 層評価モデル](#pr-05)
- [PR-06 DNS ゲート — ポリシー評価リゾルバ](#pr-06)
- [PR-07 Linux IP 層 — seccomp user notification PoC](#pr-07)
- [PR-08 拒否監査の仕様確定とシナリオ回帰 e2e](#pr-08)
- [リリース: v0.3.0 — PR-01〜08 完了後](#release-v0-3)
- [PR-09 netns/userns/mountns ＋ユーザ空間プロキシ PoC](#pr-09)
- [PR-10 cgroup eBPF（INET4/6_CONNECT）opt-in](#pr-10)
- [PR-11 macOS loopback CONNECT プロキシ経路](#pr-11)
- [PR-12 Windows PSEC — 既定化検討・ARM64・FQDN 限界の明記](#pr-12)
- [PR-13 機能マトリクスの機械可読化と OS 位置づけ](#pr-13)
- [リリース: v0.4.0 — PR-09〜13 完了後](#release-v0-4)
- [PR-14 ポリシー運用 — REVIEW strict とドリフト検出 `mcp-writ check`](#pr-14)
- [PR-15 構造的限界と残存リスクの開示](#pr-15)
- [PR-16 netns プロキシの本番化と UDP/QUIC 方針](#pr-16)
- [リリース: v0.5+ — PR-14〜16 のうち含める範囲の完了後](#release-v0-5)

<a id="pr-01"></a>

### PR-01 監査イベントの棚卸しとライフサイクル・設定イベントの実装

対応論点: §2.3（§0 の死に定義棚卸しを含む）。直接依存: なし。着手・公開条件: 常設。

**目的:** 起動・終了・ポリシー読込・セッションの監査イベントを実際に emit し、emit 経路の無いイベント定義の去留を項目ごとに決める。

**主な変更先:** [audit_log.rs](../src/audit_log.rs)、[launch.rs](../src/runtime/launch.rs)、[wait.rs](../src/runtime/wait.rs)、[main.rs](../src/main.rs)、[proxy.rs](../src/auditor/proxy.rs)、英日ガイドの監査スキーマ節。

**タスク**

- [x] `EventType` 全バリアントの emit 有無を棚卸しする。改善計画が挙げる `sandbox.*_denied`・`session.*` に加え、基準コミットでは `guard.*`・`policy.*`・`server.disconnected`・`validation.*` にも emit 箇所が無いことを実測で確かめ、一覧を PR 本文に残す。
- [x] `session.started`/`session.ended` を起動・終了パスで emit する。IR でセッションを再構成できるよう `session_id`・起動ID（`launch_id`）の相関を揃える。
- [x] `guard.started`/`guard.stopped` を emit する。`guard.stopped` には終了理由（正常終了・中断・子死亡等）を含める。
- [x] `policy.loaded`/`policy.error`（必要なら `policy.reloaded`）を emit し、details にポリシー版・hash・`fail_on` 値を含める — `fail_on` 記録は PR-02 のバイパス記録と整合させる。
- [x] `server.disconnected` を emit する。
- [x] `sandbox.file_denied`/`sandbox.process_denied` は項目ごとに「emit 経路を足す」か「schema から削る」かを決める。カーネル内拒否（Landlock/seccomp/Job）はユーザ空間への通知が来ないため、観測経路が実装されるまで emit できない実情を記録する — §1.6 の「supervisor/proxy 経路のみ emit 可」仕様と整合させる。
- [x] `validation.path_traversal`/`validation.argument_invalid` の去留も同じ基準で決める。
- [x] スキーマから削る場合は `EventType`・`as_str`・category・`schema_version` の扱いと、過去ログの読み手への影響を記録する。削除は breaking なので版の扱いを決める。
- [x] emit されたイベントが「拒否が実行された保証」ではなく「判定された事実」である点を、イベントの semantics として定義する。

**検証:** T-BASE、T-DOC、T-NATIVE。emit された各イベントが JSONL に出ること、セッション相関、終了経路（EOF・中断・強制終了）での記録を確認する。

**完了条件:** emit しないイベントが定義に残る場合は「観測経路なし・将来実装」または「削除」のいずれかとして文書化され、利用者が「イベントが無い＝発生しなかった」と誤読しない形になる。

**移行・戻し方:** イベント追加は後方互換だが削除はスキーマ破壊。削除する場合は版の扱いを明示し、読み手側の互換方針を残す。

<a id="pr-02"></a>

### PR-02 バイパス・ダイヤル低下・dry-run の監査記録

対応論点: §2.1。直接依存: PR-01。着手・公開条件: 常設。

**目的:** サンドボックス省略・判定緩和・dry-run の実行を監査ログへ残し、「証拠が無い」状態を無くす。

**主な変更先:** [main.rs](../src/main.rs)、[plan.rs](../src/commands/plan.rs)、[launch.rs](../src/runtime/launch.rs)、[fail_on.rs](../src/verifier/fail_on.rs)、[audit_log.rs](../src/audit_log.rs)。

**タスク**

- [x] `MCP_WRIT_SKIP_SANDBOX` 検出時に `guard.started` details または新規 `config.override` イベントへ `sandbox=skipped via MCP_WRIT_SKIP_SANDBOX` を必ず記録する。stderr 警告は維持する。
- [x] `FAIL_ON=none` を起動時に記録する — `policy.loaded` details に `fail_on` 値を含める方式が候補（PR-01 の details 設計と整合）。finding 0 件でも痕跡が残ること。
- [x] `--dry-run` を `guard.started` details の `dry_run=true`、または全イベントへの伝播で記録する。`LaunchReport.dry_run`（[launch.rs](../src/runtime/launch.rs) 既存）との対応を取る。
- [x] `allow_degraded` による部分適用や `MCP_WRIT_PROBE_LANDLOCK_ABI` 等の診断用環境変数も、実実行に影響するものは同じ基準で記録対象とするか判断する。判断: `sandbox allow_degraded=#true` は許容した弱化なので `policy.loaded` の `allow_degraded=true` と `server.connected` の `os.*=<state>` トークン（`partially_applied`/`not_applied`/`failed`）で記録する。`MCP_WRIT_PROBE_LANDLOCK_ABI` はプローブ応答のため `main` 先頭で即終了し起動・監査経路へ一切到達しない（実行を弱める経路ではない）ため監査対象外とする。
- [x] `plan` サブコマンドのチェック出力（[plan.rs](../src/commands/plan.rs) の SKIP_SANDBOX 警告等）と監査記録の対応を揃える。`env.fail_on` チェックを追加し、`run` が `policy.loaded` に記録する解決済みダイヤルと同じ値を plan 側でも診断する。

**検証:** T-BASE、T-NATIVE。SKIP_SANDBOX 設定下・FAIL_ON=none・dry-run の各起動で JSONL に証拠が残ることを fixture で確認する。

**完了条件:** 制御を弱める経路が全て監査に残る。記録が無い起動は「フル制御下で実行された」ことを意味する。

**移行・戻し方:** 記録追加のみで判定挙動は変えない。環境変数の意味を変えない。

<a id="pr-03"></a>

### PR-03 `server.connected` の enforcement 状態と PSEC 状態の JSONL

対応論点: §2.2、§2.5（§1.4 と同一項目）。直接依存: PR-01。着手・公開条件: 常設。

**目的:** 起動時点の実効制御状態を JSONL に残し、`--report` と監査で同じ事実を読めるようにする。

**主な変更先:** [launch.rs](../src/runtime/launch.rs)（`server.connected` emit 箇所）、[enforcement.rs](../src/enforcement.rs)、[windows_psec.rs](../src/warden/windows_psec.rs)、[plan 配下](../src/warden/plan/mod.rs)、英日ガイドの監査スキーマ節。

**タスク**

- [x] `server.connected` details を `spawned <exe>` から拡張し、sandbox backend（landlock/seccomp、appcontainer、psec、sandbox-exec、none）、`RestrictionStatus`（FullyEnforced/PartiallyEnforced/NotEnforced）、適用 controls 数、スキップした grant の要約を構造化して載せる。実装: `details` は `spawned <exe> backend=<name>`、構造化は `enforcement` メンバ（`backend`/`restriction`/`controls_applied`/`controls`/`grants`/`skipped_grants`）。
- [x] PSEC の mechanism 選択（`--windows-mechanism`）、schema 版、egress 規則の受理結果を `server.connected` details または専用イベントで emit する。`--report` の `plan`/`observations` と同じ情報源から生成し、表示専用の別計算を作らない。実装: `enforcement.backend=psec` + `enforcement.psec.{schema_version,egress_default_deny,egress_allow_rules,egress_rules_refused}` を `EnforcementSummary::build(&report.plan, &report.observations, …)` で生成。
- [x] details が肥大化する場合は `sandbox.applied` 等の専用イベントに分けるか判断する — details 文字列と構造化フィールドの使い分けをスキーマとして定義する。判断: 専用イベントは追加せず、平坦な `details`（人間向け）と `enforcement` メンバ（機械向け）の併記をスキーマとして英日ガイドに定義 — 肥大化した場合は専用イベントへ昇格させる方針を明記。
- [x] `dry_run`/`skip_sandbox` 時の `server.connected` が enforcement 無しを示すことを PR-02 と整合させる。実装: `backend=none` + `dry_run=true`、os.* 制御は `verified`/`partially_applied` にならないことを `plan_report_e2e` で固定。

**検証:** T-BASE、T-NATIVE（3 OS）。Windows での PSEC emit e2e（§5.4 の一部、PR-08 でも回帰）。report の `plan`/`observations` と JSONL details が同一実を指すことを照合する。

**完了条件:** JSONL だけから「どの mechanism で何が効いていたか」が読める。`--report` だけに存在する enforcement 情報が残らない。

**移行・戻し方:** details の構造化は既存の文字列 details との併記で行い、読み手を壊さない。

<a id="pr-04"></a>

### PR-04 監査バッファの SIGKILL 耐性と外部転送

対応論点: §2.4、§5.3。直接依存: PR-01（`guard.stopped` の emit）。着手・公開条件: 常設。

**目的:** 強制終了時の末尾欠損を小さくし、残った損失の大きさを監査側が知れる形にする。

**主な変更先:** [audit_log.rs](../src/audit_log.rs)、[cli](../src/cli)、[main.rs](../src/main.rs)、英日ガイド。

**タスク**

- [x] High 以上の severity でも即時 flush+fsync する（現行は Critical のみ即時 flush — [audit_log.rs](../src/audit_log.rs) の writer task）。性能影響を計測し、判定閾値を設定可能にするか決める。 → `IMMEDIATE_SYNC_SEVERITY`（High 固定・非設定化 — 弱化できない契約として明示）で即時 flush+fsync。性能影響は `audit_durability_e2e` の drain 計測で両モードを比較できる形にした。
- [x] `--audit-sync`（仮）オプションで逐次 fsync する経路を追加する。性能との引き換えを明記する。 → `AuditSyncMode::EveryEvent` として実装（`--audit-sync`、`--audit-log` 必須、windows-sandbox では拒否）。引き換えは英日ガイドの「Audit durability, sync modes, and external forwarding」節に明記。
- [x] `guard.stopped` details に `dropped` カウンタ（channel 満杯で捨てた件数、既存 `dropped` フィールド）と `writer_failed` を記録する。 → `dropped=<n>` / `writer_failed=<bool>` を常時記録。
- [x] stdout audit モード（既存の `to_tracing` 経路との関係を整理）または tail → SIEM の外部転送の運用例をガイドに追加する。起動側が SIGKILL されても転送先が生きていれば末尾が残る構成を示す。 → tail → SIEM（別プロセス）例を英日ガイドに追加。stderr/tracing は耐久性契約を持たず fail-closed はファイルシンク必須、という整理も明記。
- [x] バッファ条件（64KB BufWriter・1s/100件 flush・5s fsync — [audit_log.rs](../src/audit_log.rs) の定数）の現行値を明文化し、変更時の互換性方針を決める。 → 英日ガイドに明文化（定数は再調整可・順序保証は維持の方針）。SIGKILL 損失上限も bound として記述。

**検証:** T-BASE。SIGKILL 末尾欠損の計測（§5.4）— 親強制終了で失われるイベント数の実測値と、`--audit-sync` でのゼロ確認を fixture で行う（PR-08 で回帰固定）。

**完了条件:** 強制終了で監査が失われる限界が「無かったこと」ではなく、失われた範囲の情報と共に仕様として残る。

**移行・戻し方:** 既定の flush/fsync 周期を変えても既存挙動の契約（Critical 即時）は維持する。`--audit-sync` を外しても通常経路は退化しない。

<a id="pr-05"></a>

### PR-05 egress ポリシースキーマ — `allow cidr` と 2 層評価モデル

対応論点: §1.1。直接依存: なし。着手・公開条件: 常設。

**目的:** ドメイン層（名前ポリシー）と IP 層（接続時強制）の 2 層を、ポリシー形式のレベルで分離・共存させる。

**主な変更先:** [leaves.rs](../src/policy/kdl_parse/leaves.rs)（`parse_network_rules`）、[mod.rs](../src/policy/mod.rs)（`OutboundPolicy`/`ToolNetworkPolicy`）、[host.rs](../src/policy/host.rs)、[kdl_emit.rs](../src/policy/kdl_emit.rs)、[kdl_inherit](../src/policy/kdl_inherit)、[validator](../src/policy/validator.rs)、[policy_export.rs](../src/container/policy_export.rs)、[plan.rs](../src/commands/plan.rs)、英日ガイド・[policy.example.kdl](../policy.example.kdl)。

**タスク**

- [ ] `network` の `allow` に `cidr="…"` 属性を新設する。IPv4/IPv6 CIDR の受理・正規化・重複統合を定義し、`host` とは別フィールド（`OutboundPolicy` の新規フィールド、名称は担当PRで確定）に保持する。
- [ ] `deny` 側の IP 層規則の要否を決める（`deny cidr` の追加か、`denied_hosts` の IP リテラル項を IP 層で評価するか）。
- [ ] `denied_hosts` を両層で評価するモデルを確定する: 名前拒否は DNS ゲートで解決時点 fail、IP リテラルの拒否は接続時点 fail。Auditor 側の `denied_hosts` 引数検査（[checker.rs](../src/auditor/checker.rs)）は維持する。
- [ ] port 修飾の扱いを確定する — メカニズム別 expressibility（PSEC は port 非表現として既に拒否、[validator/psec.rs](../src/policy/validator/psec.rs)）に落とし、暗黙の全ポート拡大をしない。`allowed_port_qualified` の既存の履歴管理と整合させる。
- [ ] 継承・include・when・profile・`kdl_emit` 往復・ゲスト用 policy export で新フィールドを保持する。`policy version=2` の未知属性拒否に `cidr` を正規属性として登録する。
- [ ] `mcp-writ plan` 出力に「host 規則（名前層）と CIDR 規則（IP 層）の対応表」を含める — どの機構がどちらの層を担うか、ホストエントリが IP 層に届かない OS での表示を決める。
- [ ] IP リテラル宛の `allow host=` 指定が IP 層の静的規則としても効くかの挙動を定義する（現行 `analyze_policy_host` は IP を正規化する — [host.rs](../src/policy/host.rs)）。

**検証:** T-BASE、T-POLICY、T-LAYER（新フィールドの層位置）。継承・export・再出力での保存、未知/不正 CIDR の拒否、PSEC 経路での表現不能拒否を単体試験で確認する。

**完了条件:** ドメイン名と CIDR が別の層の規則として型上も出力上も区別され、どちらの層にも届かない経路（Auditor のみ等）が plan で可視化される。

**移行・戻し方:** 既存の `allow host=`/`deny host=` の意味を変えない。スキーマ追加は v1/v2 両形式での扱いを決め、旧版バイナリが新属性を黙って捨てないことを確認する。

<a id="pr-06"></a>

### PR-06 DNS ゲート — ポリシー評価リゾルバ

対応論点: §1.2、§1.6（名前層 emit）。直接依存: PR-01（イベント emit）、PR-05（スキーマ）。着手・公開条件: 常設。v0.3 では「設定ベースで先行利用可能な単体」として提供し、netns 組み込みは PR-09 の範囲。

**目的:** 名前解決の時点でポリシーを評価し、許可名だけを解決する。拒否名の流出を監査に残す。

**主な成果物:** 新規ゲートコンポーネント（`src/dnsgate/` 等を候補 — 層の登録を `docs/modules.md` と `tests/module_layering.rs` で同じPRに行う）、設定・運用のガイド節。

**タスク**

- [ ] UDP/TCP の DNS リゾルバーを実装する。上流リゾルバへの転送はクエリを中継する形とし、通信の中身（応答ペイロードの意味解釈）はしない — 宛先制御の範囲に留める。
- [ ] クエリ名を [host.rs](../src/policy/host.rs) の UTS-46 正規化（`normalize_policy_host`、`idna` crate 導入済み）に通してから名前ポリシー（`allowed`/`denied_hosts`、ワイルドカードは `host_matches` 相当）を評価する。Unicode 変種（全角ドット等）による拒否回避は既対策を再利用する。
- [ ] 拒否名は NXDOMAIN/REFUSED を返し、`sandbox.network_denied` を `name`/`qtype`/`session_id` 付きで emit する — 解決時点で止まった流出が監査に乗る（§1.6 名前層の最初の実装）。
- [ ] CNAME は最終名まで追跡するが、allow/deny の評価はクエリ名のみに対称適用する（§1.2 の根拠 — チェーンはワークロードが制御しない）。応答のチェーン全体は監査 details に記録し、観測はするが強制はしない。
- [ ] 応答 IP を TTL スコープ（チェーン最小 TTL）で IP 層の動的 allowlist に登録するインターフェースを定義する — PR-07 の supervisor / PR-09 のプロキシが読む共有表。TTL 失効・再上書き・同一 IP の複数名共有を扱う。
- [ ] 起動形態を決める: 単体プロセス（新サブコマンドまたは `run` の内蔵コンポーネント）、listen アドレス、上流リゾルバの設定、ゲート自身の失敗時挙動（上流 unreachable → fail-closed 側へ倒すかの約定）。
- [ ] キャッシュ・同時問合せ・応答サイズに上限を設ける。DoH 迂回（853/443 への直行）は IP 層の既定拒否で塞ぐ前提であることを明記する — ゲート自体はそれを防がない。
- [ ] `allow host=` 規則が「Auditor の引数検査に加えて DNS ゲートの名前ポリシーにも効く」ことを plan 出力とガイドに反映する。

**検証:** T-BASE、新規ゲート試験ターゲット（担当PRで追加・ワークフロー登録）。許可名/拒否名/ワイルドカード/CNAME 追跡/TTL 失効/不正クエリ/上限到達を単体・結合試験で確認し、拒否時の `sandbox.network_denied` emit を JSONL で検証する。

**完了条件:** 設定ベースで単体利用でき、拒否した名前が監査に残る。動的 allowlist の形式が PR-07/PR-09 の入力契約として確定している。

**移行・戻し方:** ゲートを無効にしても従来の Auditor 名検査は維持する。ゲート不在で名前解決が通る経路がある場合の表示を「名前層なし」として正直に残す。

<a id="pr-07"></a>

### PR-07 Linux IP 層 — seccomp user notification PoC

対応論点: §1.3(a)、§1.6（IP 層 emit）。直接依存: PR-05（`cidr` スキーマ）、PR-06（動的 allowlist の入力契約）。着手・公開条件: PoC — 製品既定経路には接続しない。

**目的:** `connect()` 時点で宛先 IP を検査し、静的 CIDR と DNS ゲートの動的許可の両方で判定する。

**主な変更先:** [seccomp_impl.rs](../src/warden/seccomp_impl.rs)、[linux_spawn.rs](../src/warden/linux_spawn.rs)、[child.rs](../src/warden/child.rs)、新規 supervisor モジュール（`src/warden/` 配下を候補）、`docs/validation/` の新規検証文書。

**タスク**

- [ ] `SECCOMP_USER_NOTIF`（`SECCOMP_FILTER_FLAG_NEW_LISTENER`）で `connect` を通知対象にするフィルタを追加し、リスナ fd を supervisor 側へ渡す経路を作る — 現行の pre_exec 自己適用モデル（[linux_spawn.rs](../src/warden/linux_spawn.rs) の `no_new_privs → Landlock → seccomp`）と supervisor 常駐モデルの共存形を決める。
- [ ] supervisor は子の `sockaddr` を `process_vm_readv`/`/proc/pid/mem` で読み、静的 CIDR 規則と動的 allowlist（PR-06 の TTL スコープ表）に照合する。「引数検査〜実使用の隙間」（読み取り後に子が sockaddr を書き換えうる）を限界として記録する。
- [ ] 許可側は `SECCOMP_USER_NOTIF_FLAG_CONTINUE`（kernel 5.5+）でオーバーヘッドを抑える。カーネル未対応時は起動前診断で拒否する。
- [ ] 拒否時は `sandbox.network_denied` を `dest`/`port`/`proto`/`session_id` で emit する — IP 層 emit 経路の最初の実装。
- [ ] v0.3 の範囲は TCP `connect` のみ。UDP/RAW socket・`sendmsg`/`sendto` は別途設計として残し、黙って素通しする経路があれば診断で示す。
- [ ] supervisor の死亡・監視断の扱いを決める — 通知への応答が無いまま子が進む経路を fail-closed 側へ倒す。
- [ ] 「supervisor/proxy が介在する経路で弾いたもののみ emit 可能」（§1.6）の仕様をここで確定する — Landlock/seccomp のカーネル内拒否には通知が来ないため、観測可能な経路と不能な経路を分けて文書化する。
- [ ] 「plain spawn = IP 層のみ、namespaced = 2 層」という能力差を plan/--report/ガイドで表現する。

**検証:** T-BASE、実 Linux（kernel 5.5+）での PoC 動作確認、新規結合試験（担当PRで追加）。許可/拒否/動的 allowlist 反映/TTL 失効後の再接続拒否/supervisor 死亡時を確認し、`/proc` 読み取りの権限・races を含む限界を検証文書に記録する。

**完了条件:** IP 直打ちの egress（シナリオ B）が PoC 経路で止まり、拒否が JSONL に残る。観測経路を持つ最初の IP 層として、能力と限界が明記される。

**移行・戻し方:** PoC は opt-in フラグか試験経路に留め、既定の plain spawn を変えない。不具合時は unotify フィルタを外して従来 seccomp のみに戻す。

<a id="pr-08"></a>

### PR-08 拒否監査の仕様確定とシナリオ回帰 e2e

対応論点: §1.6（仕様面）、§5.4。直接依存: PR-03、PR-04、PR-06、PR-07。着手・公開条件: v0.3 統合の締め。

**目的:** 「拒否された通信が監査に残る」ことをエンドツーエンドで固定し、観測できない経路を仕様として区別する。

**主な変更先:** 新規 `tests/` ターゲット、[test-matrix.md](test-matrix.md)、[development.md](development.md)、英日ガイド。

**タスク**

- [ ] シナリオ A（注入 → 拒否 → JSONL 確認）を e2e 化する — RPC 層の拒否が `tool_call.denied`/`mcp_message.denied` として残る経路を fixture で固定する。
- [ ] シナリオ B（443 直出し）を再現し、PR-07 の IP 層で拒否されること・拒否イベントが残ることを回帰テストにする。
- [ ] 名前拒否（PR-06）→ NXDOMAIN/REFUSED + `sandbox.network_denied` の e2e。
- [ ] SIGKILL 末尾欠損の計測（PR-04 のバッファ改善の効果測定）を実装し、失われうる範囲を数値で記録する。
- [ ] PSEC 状態の JSONL emit（PR-03）の e2e を Windows で実施する。
- [ ] Landlock 単独経路の FS/ネットワーク拒否が監査に残らないことを「観測不能」として試験と文書に固定する — emit されないことを検知するテストではなく、「残らないことが仕様」であることを表明するテストにする。
- [ ] 新規試験を [test-matrix.md](test-matrix.md) の担当一覧と手動ワークフローへ登録する。

**検証:** 上記シナリオが全て実行され、成功・拒否・環境未確保が区別されて記録される。

**完了条件:** v0.3 の監査完全性の主張（バイパス記録・enforcement 状態・拒否 emit・SIGKILL 耐性）が全て再現可能な試験か記録された限界として残る。

**移行・戻し方:** 試験追加のみ。製品経路の既定は変えない。

<a id="release-v0-3"></a>

### リリース: v0.3.0 — PR-01〜08 の完了後

実装PRではなく、ここに到達した時点で確認する条件と手順です。バージョン更新・タグ付け・リリース実行は git／リリース操作のため、実施は別途指示を受けてから行います。

**到達条件 — 全て満たしたらバージョンを上げる**

- [ ] PR-01〜08 が全てマージ済み
- [ ] §5.4 の検証記録（シナリオ A/B・PSEC JSONL・SIGKILL 計測）が残っている
- [ ] 「観測不能」の残存経路が仕様として文書化されている

**バージョン更新の手順**

- [ ] [Cargo.toml](../Cargo.toml) の `version` を `0.3.0` に更新し、`Cargo.lock` を再生成する
- [ ] 最新コミットで T-BASE・T-DOC・該当する実機記録を再確認する
- [ ] タグ `v0.3.0` を付ける — タグ push が [release.yml](../.github/workflows/release.yml) の起点（ci・platform-tests・container-tests・go-runtime の verify を通る）
- [ ] リリースノートに「この版で保証する制御」と「残る限界」（§1.7・§5.2 の対応状況）を明記する

<a id="pr-09"></a>

### PR-09 netns/userns/mountns ＋ユーザ空間プロキシ PoC

対応論点: §1.3(c)。直接依存: PR-06（ゲートを resolv.conf 経路で内蔵）、PR-07（deny/allowlist の配管）。着手・公開条件: PoC — v0.4 の FQDN 実効強制の主経路。

**目的:** 非特権のまま「resolv.conf 支配＋DNS ゲート＋全 TCP を宛先チェック付きプロキシ経由」を組み、FQDN の実効強制を実証する。

**主な成果物:** 新規 namespaced spawn 経路（`src/warden/` 配下または新モジュール — 層登録を同PRで）、`docs/validation/` の新規検証文書。

**タスク**

- [ ] userns+netns+mountns で子を分離する（bubblewrap 型の非特権ルート）。権限不要であることを起動条件として検査する。
- [ ] mountns 内で `resolv.conf` を自前 mount で差し替え、名前解決が必ずゲート（PR-06）を通る形にする。ゲートを使わないハードコードリゾルバは fail-closed（「動かなくなる」が正しい挙動、§1.7）。
- [ ] netns 内の通信を全てユーザ空間プロキシ経由にする — tun + smoltcp 相当のユーザ空間スタック（依存選定はこのPRで確定: 最小フットプリント・外部デーモン非依存）。
- [ ] プロキシの宛先判定は名前/IP の両方を扱い、静的 CIDR＋動的 allowlist＋名前規則を評価する。拒否は `sandbox.network_denied` 経路（PR-07 と共用できるか確認）へ。
- [ ] QUIC 等の非 DNS UDP は既定拒否（ポリシー化）。
- [ ] プロキシ自体の信頼性（§1.7）— ユーザ空間スタックの実装バグがそのまま境界の穴になる点を記録し、最小実装＋e2e で担保する方針を決める。
- [ ] 性能: cold/warm 起動・初回応答・メモリを既存の基準経路（native spawn）と同じ fixture で測る。

**検証:** T-BASE、実 Linux での PoC 動作、ゲート経由名解決の強制・プロキシ経由 TCP の宛先判定・UDP 既定拒否・resolv.conf 差し替えの確認。検証文書に証跡を残す。

**完了条件:** FQDN 規則だけのポリシーで実 egress が制御されることを実機で確認し、「namespaced = 2 層」の表示が実装と一致する。

**移行・戻し方:** PoC は既定経路にしない。失敗時は namespaced 経路を選択不可に戻す。

<a id="pr-10"></a>

### PR-10 cgroup eBPF（INET4/6_CONNECT）opt-in

対応論点: §1.3(b)。直接依存: PR-07（deny emit・allowlist の配管）。着手・公開条件: 権限あり環境の opt-in 強化として。

**目的:** 特権の使える環境で、IP 層をカーネル内強制＋deny イベント観測に寄せる。

**主な変更先:** 新規 eBPF 経路（`src/warden/` 配下または新モジュール）、[seccomp_impl.rs](../src/warden/seccomp_impl.rs)・[linux_spawn.rs](../src/warden/linux_spawn.rs) との併用整理、英日ガイド。

**タスク**

- [ ] cgroup eBPF で `BPF_CGROUP_INET4_CONNECT`/`INET6_CONNECT` をフックし、静的 CIDR＋動的 allowlist で判定する。crate 選定（aya 等）・BPF object の同梱形態をこのPRで確定する。
- [ ] CAP_BPF/CAP_SYS_ADMIN 等の権限前提を起動前診断で検査し、不足時は opt-in 経路だけを拒否する — 既定経路を特権前提にしない（§1.3 表の評価を維持）。
- [ ] ring buffer 等で deny イベントを観測し、`sandbox.network_denied`（`dest`/`port`/`proto`）を emit する — カーネル内拒否でも観測可能な経路。
- [ ] cgroup の割り当て・detach・後始末を実装し、他プロセスの cgroup を巻き込まない。

**検証:** T-BASE＋権限のある実 Linux 環境での動作確認。非特権環境では起動前拒否が出ることを確認。

**完了条件:** opt-in として明示選択した場合のみ有効で、既定の非特権経路を変えない。deny が観測・emit される。

**移行・戻し方:** eBPF 経路だけを無効化できる。unotify 経路への暗黙フォールバックはしない（観測経路の違いを混同しない）。

<a id="pr-11"></a>

### PR-11 macOS loopback CONNECT プロキシ経路

対応論点: §1.5。直接依存: PR-05（スキーマ）。着手・公開条件: 常設。sandbox-exec は deprecated のため投資をこの範囲に限定する。

**目的:** `localhost:port` 許可だけが書ける SBPL の制約を、loopback 上の宛先判定プロキシでドメイン制御に変換する。

**主な変更先:** [macos_sandbox.rs](../src/warden/macos_sandbox.rs)、新規プロキシコンポーネント（PR-09 の宛先判定コアと共有できるか検討）、英日ガイド。

**タスク**

- [ ] `sandbox-exec` の `(allow network-outbound (remote tcp "localhost:port"))` でプロキシだけに出られる構成を作る。プロキシが CONNECT/宛先情報から名前・IP を判定して外向き dial する — 中身は見ない。
- [ ] SBPL の `(remote ip "…")` で IP リテラル egress も試行し、使える範囲を実機で確かめる。
- [ ] プロキシの listen・宛先判定・拒否時の `sandbox.network_denied` emit を実装する。macOS 側の拒否は SBPL が loopback 外を止める構成であり、「プロキシが宛先を判定した」ことが emit の根拠。
- [ ] 強い境界が要る場合は Apple Container バックエンドの NAT/ホスト側にゲートを置く経路を guide に明記する（実装はそのバックエンド側の話として切り分ける）。
- [ ] deprecated API への投資はこの範囲に限定し、sandbox-exec 自体の拡張はしない。

**検証:** 実 macOS でプロキシ経由の egress 制御と拒否 emit を確認。ネイティブ経路（sandbox-exec 単体）の既存挙動に回帰が無いこと。

**完了条件:** ネイティブ経路でも loopback プロキシ経由なら宛先制御が効き、制限（deprecated API・プロキシ信頼性）は文書化される。

**移行・戻し方:** プロキシ経路は明示選択。不具合時は従来の sandbox-exec 単体経路（host エントリは RPC 層のみ）に戻す。

<a id="pr-12"></a>

### PR-12 Windows PSEC — 既定化検討・ARM64・FQDN 限界の明記

対応論点: §1.4、§3.3（Windows 項）。直接依存: PR-03（PSEC JSONL）。着手・公開条件: 常設。

**目的:** 唯一の宛先 egress 実装である PSEC を、実測に基づいて既定化の可否まで進める。

**主な変更先:** [windows_psec.rs](../src/warden/windows_psec.rs)、[psec_spec.rs](../src/warden/psec_spec.rs)、[validator/psec.rs](../src/policy/validator/psec.rs)、[cli](../src/cli)、英日ガイド。

**タスク**

- [ ] ARM64 対応を実機で確かめる — PSEC の arch サポート範囲を runtime probe で確認し、対応できるなら対象を拡大、無理なら拒否条件として明記する。
- [ ] opt-in（`--windows-mechanism psec`）から既定化への可否を検討する — capability probe の信頼性・表現不能ポリシーの拒否カバレッジ・AppContainer 既定との差分を評価軸にし、既定化する/しないの判断と条件を記録する。
- [ ] FQDN はネイティブでは不可能（PSEC v1.0 は loopback 免除なし → ローカルプロキシ/ゲートにも届かない）をガイド・plan 診断で明文化する。FQDN が要るワークロードは network broker 前置または Windows Sandbox/WSLc のゲストネットワーク経路を案内する（現行 validator メッセージと同じ指針）。
- [ ] AppContainer 経路は宛先制御を持たない → 現行のロード時拒否を維持する。
- [ ] WFP は管理者権限が必要で CLI 常駐モデルと合わない → 補助枠としてのみ記録し、実装は保留とする判断を残す。
- [ ] egress の port 修飾・IPv6 等、v1.0 契約の限界で拒否している項目が PR-05 の新スキーマでも正しく拒否されることを確認する。

**検証:** T-BASE、Windows の実機 T-NATIVE と既存の `windows_isolation_e2e`。ARM64 は実機がある場合のみ実施し、無ければ未検証として記録する。

**完了条件:** PSEC の opt-in/既定の位置づけが実測に基づいて記録され、FQDN 不可の限界が利用者へ届く。ARM64 の可否が「検証済み/未対応」のどちらかで明記される。

**移行・戻し方:** 既定化する場合は opt-out を残す。PSEC を既定にして AppContainer の制御を落とさない。

<a id="pr-13"></a>

### PR-13 機能マトリクスの機械可読化と OS 位置づけ

対応論点: §3.1、§3.2、§3.3（Linux 項）。直接依存: PR-03（report の enforcement 情報）。着手・公開条件: 常設。

**目的:** 「何がどの OS で効くか」を EnforcementPlan のデータから機械可読に出し、文書との乖離を CI で検出する。

**主な変更先:** [enforcement.rs](../src/enforcement.rs)、[plan.rs](../src/commands/plan.rs)、[test-matrix.md](test-matrix.md)、英日 [guide.md](guide.md)、[README.md](../README.md)、CI 検査。

**タスク**

- [ ] `PlannedControl`/`ProcessGrant`/`EnforcementPlan` の既存モデルから OS 横断の capability 出力を統一する — `mcp-writ plan`/`--report` が同じ情報源を使う形にする。
- [ ] 出力と [test-matrix.md](test-matrix.md)（または新規の機械可読対応表）との整合を CI 試験で検査する — 実装と対応表が乖離したら fail する。
- [ ] 「native warden は Linux が本命、他 OS で強い境界が要る場合は `--isolation`（Kata/Apple Container/Hyper-V/Windows Sandbox/WSLc/OCI）経路を推奨」という階層設計を README/guide に明記する — OS 差評価を言い訳でなく設計として説明する。
- [ ] Landlock ABI 追従（probe 機構 `MCP_WRIT_PROBE_LANDLOCK_ABI` 済み）の現状と、新 ABI への追従方針を記録する。

**検証:** T-BASE、T-DOC。matrix 生成と既存出力の差分照合、CI 検査の fail 経路を確認する。

**完了条件:** OS 差が「実装データから生成された対応表」として一貫し、手書き文書とのずれが検出できる。

**移行・戻し方:** 出力形式は版管理し、既存の plan/report 読み手を壊さない。

<a id="release-v0-4"></a>

### リリース: v0.4.0 — PR-09〜13 の完了後

実装PRではなく、ここに到達した時点で確認する条件と手順です。バージョン更新・タグ付け・リリース実行は git／リリース操作のため、実施は別途指示を受けてから行います。

**到達条件 — 全て満たしたらバージョンを上げる**

- [ ] PR-09〜13 が全てマージ済み
- [ ] PR-09/10/11 の PoC 検証文書が残っている
- [ ] PR-12 の既定化判断（する/しないとその条件）が記録されている

**バージョン更新の手順**

- [ ] [Cargo.toml](../Cargo.toml) の `version` を `0.4.0` に更新し、`Cargo.lock` を再生成する
- [ ] 最新コミットで T-BASE・T-DOC・該当する実機記録を再確認する
- [ ] タグ `v0.4.0` を付ける — タグ push が [release.yml](../.github/workflows/release.yml) の起点（ci・platform-tests・container-tests・go-runtime の verify を通る）
- [ ] リリースノートに「この版で保証する制御」と「残る限界」（§1.7・§5.2 の対応状況）を明記する

<a id="pr-14"></a>

### PR-14 ポリシー運用 — REVIEW strict とドリフト検出 `mcp-writ check`

対応論点: §5.1。直接依存: なし。着手・公開条件: v0.5+。

**目的:** 生成ポリシーの未レビュー項目とハッシュドリフトを運用で検出できるようにする。

**主な変更先:** [policy_generator.rs](../src/legislator/policy_generator.rs)、[loader.rs](../src/policy/loader.rs)、[verifier](../src/verifier)、新規 `check` コマンド（[commands](../src/commands)、[cli](../src/cli)）。

**タスク**

- [ ] legislator が生成する `// REVIEW` コメントの未解消をロード時に warn/refuse する strict モードを作る — 既定は warn か、opt-in strict かを決める。
- [ ] `mcp-writ check`（仮）で現行ポリシーと実ファイルを再照合する — tools-list-hash/binary-hash/entrypoint-hash/lockfile-hash/docker-manifest-hash の再検証を既存 verifier の機構で実行し、CI で使える終了コードと出力を定義する。
- [ ] ドリフト検出時の運用手順（再生成・pin 更新・差分レビュー）をガイドに追加する。

**検証:** T-BASE、T-POLICY、T-IDENTITY。REVIEW 残りの warn/refuse、各 hash の一致/不一致、`check` の終了コードを fixture で確認する。

**完了条件:** ポリシーの生成→レビュー→検出の運用サイクルが閉じ、`check` が CI に置ける。

**移行・戻し方:** strict は opt-in とし、既定のロード挙動を変えない。

<a id="pr-15"></a>

### PR-15 構造的限界と残存リスクの開示

対応論点: §5.2、§1.7。直接依存: PR-06、PR-07、PR-09、PR-11（実装に即した開示のため）。着手・公開条件: v0.5+。ただし各 egress PR の節に暫定記述を入れることは可。

**目的:** 実装で残る限界を、設計上の境界・残存リスクとして利用者が読める形に固定する。

**主な変更先:** 英日 [guide.md](guide.md)、[README.md](../README.md)、[policy-authoring.md](policy-authoring.md) 系、必要なら `docs/validation/` の記録。

**タスク**

- [ ] TOCTOU（RPC 引数検査とサーバ内部動作の乖離）を設計上の境界として docs に固定する — FS は Landlock が `open()` 時点で強制するため実効的に緩和済み、という切り分けも書く。
- [ ] `npx` 系は entrypoint-hash＋インタプリタ同時ピンのガイドを強化する。
- [ ] §1.7 の残存リスクを項目ごとに「現状・緩和・残存」を揃えて書く: DoH 回避（IP 層既定拒否で塞ぐが許可済み宛先兼リゾルバは残る）/ ECH（SNI 判定が効かない宛先）/ ハードコードリゾルバ（fail-closed 仕様）/ TTL レース / CNAME 委譲（対称評価の限界）/ 共有 IP（名前層の保証は解決名の範囲）/ プロキシ自体の信頼性。
- [ ] 各リスクについて「検知できること」（監査のチェーン記録等）と「止められること」を分けて記述する。

**検証:** T-DOC。文書の記述が実装の挙動と一致することを当該PRの検証記録と照合する。

**完了条件:** 限界が全て「無かったこと」でなく仕様として公開され、利用者が自分の脅威モデルに照合できる。

**移行・戻し方:** 開示を弱める変更はしない。実装が限界を解消したら該当記述を「解消済み」に更新する。

<a id="pr-16"></a>

### PR-16 netns プロキシの本番化と UDP/QUIC 方針

対応論点: §1.3(c) の本番化、§1.7 の継続評価。直接依存: PR-09（PoC）。着手・公開条件: v0.5+、PR-09 の PoC が採用可能と判断された場合。

**目的:** namespaced 経路を明示選択できる製品経路にする。

**主な変更先:** PR-09 の成果物、[cli](../src/cli)、[launch.rs](../src/runtime/launch.rs)、[enforcement.rs](../src/enforcement.rs)、英日ガイド・[quickstart.md](quickstart.md)。

**タスク**

- [ ] PR-09 の PoC を製品経路へ — 明示選択の形（`--isolation` 系か native 経路のモード選択かをこのPRで確定）、launch/report/監査への統合、起動前診断。
- [ ] UDP/QUIC の方針を確定する — 既定拒否のままか、ポリシー化して許可経路を作るか。
- [ ] 中断・部分失敗・後始末のライフサイクル契約を PR-09 PoC の制約から製品契約へ引き上げる。
- [ ] 手動 CI/証跡収集へ登録する。
- [ ] §1.7 残存リスクの継続評価を本番化の受入条件に含める — プロキシ信頼性・DoH/ECH/共有 IP の残存を当該版で再評価して記録する。

**検証:** T-BASE、T-NATIVE、namespaced 経路の実機 e2e、性能基準。

**完了条件:** namespaced 経路が「2 層 egress」として明示選択・再現可能・限界が明記された製品機能になる。

**移行・戻し方:** 当該経路だけを無効化できる。native plain spawn への暗黙フォールバックはしない。

<a id="release-v0-5"></a>

### リリース: v0.5+ — PR-14〜16 のうち含める範囲の完了後

実装PRではなく、ここに到達した時点で確認する条件と手順です。バージョン更新・タグ付け・リリース実行は git／リリース操作のため、実施は別途指示を受けてから行います。

**到達条件 — 全て満たしたらバージョンを上げる**

- [ ] PR-14〜16 のうち当該リリースに含める範囲がマージ済み
- [ ] 含める項目が確定した時点で版番号（`0.5.0` かそれ以降か）を決めた
- [ ] PR-15 の限界開示を含める場合、その記述が実装挙動と照合済み

**バージョン更新の手順**

- [ ] [Cargo.toml](../Cargo.toml) の `version` を確定した版に更新し、`Cargo.lock` を再生成する
- [ ] 最新コミットで T-BASE・T-DOC・該当する実機記録を再確認する
- [ ] タグ `vX.Y.Z` を付ける — タグ push が [release.yml](../.github/workflows/release.yml) の起点（ci・platform-tests・container-tests・go-runtime の verify を通る）
- [ ] リリースノートに「この版で保証する制御」と「残る限界」（§1.7・§5.2 の対応状況）を明記する

## 実装結果として残す記録

各PRの本文または実機検証文書には、次の項目を残します。調査だけで終えたPRにも、未確認事項と後続PRの開始条件を記録してください。

| 項目 | 記載内容 |
|---|---|
| 対象 | 実装コミット、前提PR、改善計画の節番号 |
| 環境 | CLIホスト、実行基盤、対象OS／arch、カーネル、エンジン、イメージの版 |
| 実行 | 再現コマンド、必要条件、対象試験と実行件数 |
| 結果 | 成功・拒否・失敗・スキップ・未確認を区別 |
| 制御 | 適用予定、観測、取得根拠、残る制約、制御の配置（ドメイン層/IP層のどちらで効くか） |
| 監査 | emit されたイベント、details の内容、観測不能な経路の扱い |
| 互換性 | 既存利用者への変更、ポリシー移行、旧版との組み合わせ |
| 資源 | 必要な測定の結果と基準。未測定は未測定と記載 |
| 後始末 | 子・孫プロセス、一時領域、ハンドル、変更した設定 |
| 次の判断 | 完了、後続可、条件付き、保留。保留の解除に必要な具体的条件 |

手順書を更新した場合は、[改善計画](improvement-plan-2026-10.ja.md)のロードマップ（§6）・§1.7 残存リスクとの整合も合わせます。実装済みかどうかは本書の存在から判断せず、該当PRの実装と試験記録で判断してください。
