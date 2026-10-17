# mcp-writ 改善計画 PR別実装手順書（2026-10）

作成日: 2026-10-07

方針更新: 2026-10-10 — Linux は名前空間＋プロキシを優先し、要求を満たせる場合に限り既存の Landlock＋seccomp 経路を使用する。UDP の宛先別制御を PR-09 の PoC に含める。

方針更新: 2026-10-16 — 外部レビュー対応（改善計画 §8）として PR-17〜29 を追加する。PR-17〜22 を v0.5+ の到達条件に加える。PR-17 以降の事実・行番号は `9203e2c` のコード読解で照合した（ビルド・テストは未実行）。

状態: **計画のみ**。各PRの実装・環境更新・コミット・ブランチ作成・push・GitHub PR作成は、別途指示があるまで行いません。以下の共通手順にある実装・PR操作は、将来の実装着手時の手順です。

[改善計画](improvement-plan-2026-10.ja.md)を目的・範囲・ロードマップの正とし、本書をPR単位の作業順序の正とします。基準コミットは `562ea185`（v0.2.0 tip）。対象箇所が基準から変わった場合は、本書の事実・依存・試験を更新します。

本書のPR番号は本計画内の番号です。旧手順書 [archive/implementation-pr-guide.ja.md](archive/implementation-pr-guide.ja.md) のPR-01〜32とは無関係です。

ロードマップ対応: PR-01〜08 が v0.3（§2 全部＋§1.1／§1.2／§1.3(a)／§1.6／§2.5）、PR-09〜13 が v0.4（§1.3(c)／§1.3(b)／§1.5／§3.3 Windows／§3.1）、PR-14〜16 が v0.5+（§5.1-5.2／netns 本番化／§1.7 継続評価）に対応します。PR-17〜29 は外部レビュー対応（§8）で、P0 の PR-17〜22 は v0.5+ に必須、P1 の PR-23〜26 は v0.5+ に含める範囲をリリース時に判断、P2 の PR-27〜29 は次版以降です。各リリースでバージョンを上げる条件と手順は、作業の流れの中のリリース節（[v0.3.0](#release-v0-3)／[v0.4.0](#release-v0-4)／[v0.5+](#release-v0-5)）に記載します — その時点で確認するものなので、先読みは不要です。

## 共通手順

### 作業開始

1. 対象ブランチのHEAD、作業ツリー、適用済みの前提PRを確認する。基準コミット `562ea185` から対象箇所が変わった場合は、本書の事実・依存・試験を更新する。
2. 当該PRの目的と受入条件をPR本文へ転記する。PoC・実機検証を含むPRでは、先行する試作の実測記録を添付する。
3. 新しいファイル・型・オプション名は提案である。既存APIと取り違えず、担当PRで確定し、影響する後続PRへ反映する。
4. 新規モジュールを作るPRは、`docs/modules.md` の依存方向説明と `tests/module_layering.rs` の LAYERS 登録を同じPRで行う。
5. 既存の利用者変更を保持する。日本語ファイルの文字コード問題が疑われる場合は、編集前にバックアップする。

### 実装中の共通条件

- 通信の**中身は見ない**。制御するのは宛先だけ（制御面の延長）。TLS 内部・HTTP ボディ・RPC 応答本文の検査機能を追加しない。
- 宛先制御は**ドメイン層（DNS ゲート/名前ポリシー）＋ IP 層（TCP 接続・UDP 送信時の強制）の 2 層モデル**。片方しか効かない経路を「ドメイン制御あり」と表示しない。既存 native の Landlock TCP ポート制限、opt-in の unotify による IP 判定、namespaced の 2 層制御を区別し、共有 IP 等の限界（改善計画 §1.7）も併記する。
- 監査に残らない挙動（バイパス・スキップ・ダイヤル低下・観測不能な拒否）は「無かったこと」にしない。残せない場合は限界として仕様化・文書化する。
- 非保証・限界は隠さず仕様として開示する。シナリオ B（IP 直打ち流出）が効かない経路で「宛先制御済み」と見せない。
- 非特権 CLI を既定に保つ。特権が要る機構（cgroup eBPF 等）は opt-in とし、既定経路を特権前提にしない。
- 既存の fail-closed 監査、channel drop カウンタ、hash pin / re-verify、6 系統の隔離経路（OCI/Kata/Apple Container/Hyper-V/Windows Sandbox/WSLc）、deny 既定を維持する。
- ポリシー形式の拡張は旧版バイナリが黙って無視しないことを確認する。`policy version=2` の未知属性拒否に新属性を正規登録する。
- 新しい試験は、拒否されるべき動作と維持すべき正規動作を対にする。「観測不能であること」を仕様として固定する試験は、emit 失敗の検出ではなく仕様の表明として書く。
- 文書修正だけのPRに不要な製品テストを新設しない。関連する既存試験を使う。

<a id="linux-egress-selection"></a>

### Linux の方式選択（2026-10-10 決定）

製品化時は、起動前の能力検査で userns/netns/mountns・TUN・必要な制御が利用可能なら namespaced を優先する。ネットワーク通信が可能でも、新しい名前空間の作成や TUN の利用が許可されているとは限らない。どちらの方式でも表現・強制できない要求は、名前空間が利用可能な環境でも起動前に拒否する。以下の `auto` / `namespaced` / `native` は設計上の呼称で、要求能力の表現を PR-09、製品の選択インターフェースを PR-16 で確定する。PR-09 の PoC は引き続き opt-in とする。

| 選択・条件 | 起動時の扱い |
|---|---|
| `auto`、namespaced で要求を満たせる | 名前空間＋プロキシを選択し、TCP/UDP の宛先 IP・ポートを制御する |
| `auto`、namespaced が利用不可、native で要求を満たせる | 既存の Landlock＋seccomp 経路を選択し、理由と適用範囲を表示・監査する |
| `auto`、namespaced が利用不可、native では要求を満たせない | 起動拒否。UDP の宛先別許可や、既存方式で強制できない実通信の IP・名前制御を省略しない |
| `namespaced` を明示指定したが利用不可、または要求を満たせない | 起動拒否。native へ切り替えない |
| `native` を明示指定 | 要求と能力を照合してから起動する。満たせない要求があれば拒否する |
| 設定不正、初期化途中の失敗、稼働中のプロキシ/DNS ゲート/必須監査の障害 | 起動拒否または対象ワークロードを停止する。障害を理由に弱い方式へ切り替えない |

native の現行ネットワーク制御は Landlock ABI V4 の TCP ポート制限と seccomp の組合せであり、Landlock 単体は宛先 IP/CIDR を制御しない。`deny_all_others` 時の UDP socket 拒否を維持し、`allow host="*"` で開放して代用しない。unotify は connect-only を残す PoC（sockaddr TOCTOU は connect エミュレーションで解消済み）、eBPF は特権を伴う opt-in として扱い、どちらも自動の代替経路にはしない。

Landlock のファイル制限と seccomp は namespaced でも併用する。要求能力と実際の適用能力を分離して判定し、選択理由・不足能力・拒否理由を `plan` / `--report` / JSONL で一致させる。`allow_degraded` によって新設する必須ネットワーク制御を省略しない。従来ポリシーの互換解釈は PR-09 で明文化し、既存の Auditor 限定の規則を OS 強制済みとは表示しない。

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
- [PR-09 netns/userns/mountns ＋ TCP/UDP プロキシ PoC](#pr-09)
- [PR-10 cgroup eBPF（INET4/6_CONNECT）opt-in](#pr-10)
- [PR-11 macOS loopback CONNECT プロキシ経路](#pr-11)
- [PR-12 Windows PSEC — 既定化検討・ARM64・FQDN 限界の明記](#pr-12)
- [PR-13 機能マトリクスの機械可読化と OS 位置づけ](#pr-13)
- [リリース: v0.4.0 — PR-09〜13 完了後](#release-v0-4)
- [PR-14 ポリシー運用 — REVIEW strict とドリフト検出 `mcp-writ check`](#pr-14)
- [PR-15 構造的限界と残存リスクの開示](#pr-15)
- [PR-16 netns プロキシの本番化と能力に応じた方式選択](#pr-16)
- [PR-17 検証基盤の是正と文書の即時修正](#pr-17)
- [PR-18 Linux ネイティブ経路の AF_UNIX・シグナル封じ込めと適用表示の是正](#pr-18)
- [PR-19 KDL 継承マージの不具合修正](#pr-19)
- [PR-20 Auditor のフレーム上限の設定化と要求単位の失敗処理](#pr-20)
- [PR-21 `args_schema` の対応拡充と生成ドラフトの整合](#pr-21)
- [PR-22 マニフェスト規則の誤検知是正と公開サーバーの回帰コーパス](#pr-22)
- [PR-23 未対応プロトコル版の診断](#pr-23)
- [PR-24 合成ポリシーの可視化と、継承規則の警告・スキーマ厳格化](#pr-24)
- [PR-25 実サーバーの通し試験](#pr-25)
- [PR-26 PR-16 の残作業](#pr-26)
- [リリース: v0.5+ — PR-14〜16 と PR-17〜22 の完了後（PR-23〜26 は含める範囲を判断）](#release-v0-5)
- [PR-27 監査ログの再オープンと、容量が尽きたときの扱い](#pr-27)
- [PR-28 ポリシー v3 — 既定は追加、置換は明示、複数 profile](#pr-28)
- [PR-29 unsafe の Safety 注記と lint](#pr-29)

外部レビュー対応（PR-17〜29）の依存と順序は次のとおりです。

| PR | 優先度 | 依存・順序 | 主な変更先 |
|---|---|---|---|
| PR-17 | P0 | 最初に実施 | `tests/common`、`tests/real_servers_e2e.rs`、workflows、`src/cli` の試験、README、guide |
| PR-18 | P0 | PR-17 の後。policy 属性の追加は PR-19 の後にマージ | `src/warden`、`src/enforcement/capability.rs`、`src/policy`（属性追加） |
| PR-19 | P0 | なし | `src/policy/kdl_inherit` |
| PR-20 | P0 | なし | `src/framing.rs`、`src/auditor/proxy_*` |
| PR-21 | P0 | なし | `src/auditor/schema_validator.rs`、`checker.rs`、`src/legislator`、`src/policy/validator.rs` |
| PR-22 | P0 | なし | `src/verifier`、`tests/fixtures` |
| PR-23 | P1 | PR-20 の後（`proxy_s2c.rs` が重なる） | `src/auditor/proxy_s2c.rs`、`proxy_rpc.rs` |
| PR-24 | P1 | PR-19 の後 | `src/policy`、新規コマンド |
| PR-25 | P1 | PR-17・PR-21・PR-22 の後 | `tests/real_servers_e2e.rs`、fixtures |
| PR-26 | P1 | PR-18 の後（`select.rs` が重なる） | `src/warden/select.rs`、`src/bin/mcp-secure-runner.rs`、tests |
| PR-27 | P2 | なし | `src/audit_log*` |
| PR-28 | P2 | PR-19（祖先の版の検証）と PR-24 の後 | `src/policy` |
| PR-29 | P2 | PR-18・PR-26 の後 | `src/warden` |

PR-17 を最初に実施し、後続 PR の検証結果を信頼できるものにします。PR-18〜22 は変更先が分かれているので並行できます。ただし PR-18 で追加する UNIX ソケットの opt-in 属性は `overlay.rs` で PR-19 と重なるため、PR-19 を先にマージします。

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

- [x] `network` の `allow` に `cidr="…"` 属性を新設する。IPv4/IPv6 CIDR の受理・正規化・重複統合を定義し、`host` とは別フィールド（`OutboundPolicy` の新規フィールド、名称は担当PRで確定）に保持する。→ `allowed_cidrs`/`denied_cidrs`（`addr/prefix` 正規形、host ビット masked、IPv4-mapped fold、port 修飾は `allowed_*_port_qualified` に provenance 保持）
- [x] `deny` 側の IP 層規則の要否を決める（`deny cidr` の追加か、`denied_hosts` の IP リテラル項を IP 層で評価するか）。→ 両方採用: `deny cidr=` 新設 + `denied_hosts` の IP リテラルは `ip_layer_denies()` で IP 層にも射影
- [x] `denied_hosts` を両層で評価するモデルを確定する: 名前拒否は DNS ゲートで解決時点 fail、IP リテラルの拒否は接続時点 fail。Auditor 側の `denied_hosts` 引数検査（[checker.rs](../src/auditor/checker.rs)）は維持する。→ モデル確定済み（`OutboundPolicy` doc: "evaluated at both layers"）。DNS ゲート実装自体は PR-06
- [x] port 修飾の扱いを確定する — メカニズム別 expressibility（PSEC は port 非表現として既に拒否、[validator/psec.rs](../src/policy/validator/psec.rs)）に落とし、暗黙の全ポート拡大をしない。`allowed_port_qualified` の既存の履歴管理と整合させる。→ `allowed_cidrs_port_qualified` も同契約、deny 側は parse 時拒否
- [x] 継承・include・when・profile・`kdl_emit` 往復・ゲスト用 policy export で新フィールドを保持する。`policy version=2` の未知属性拒否に `cidr` を正規属性として登録する。→ overlay/when/profile 保持、`to_kdl` round-trip・guest export とも対応済み（v1/v2 共通の property 検査に `cidr` 登録 — 旧バイナリは unknown property として load error で落とすため silent drop にならない）
- [x] `mcp-writ plan` 出力に「host 規則（名前層）と CIDR 規則（IP 層）の対応表」を含める — どの機構がどちらの層を担うか、ホストエントリが IP 層に届かない OS での表示を決める。→ `plan.egress_layers`（rules 対応表 + 層別 disposition、sandbox-skip/guest 変種あり、additive `null`/object）
- [x] IP リテラル宛の `allow host=` 指定が IP 層の静的規則としても効くかの挙動を定義する（現行 `analyze_policy_host` は IP を正規化する — [host.rs](../src/policy/host.rs)）。→ リテラルは `/32`/`/128` 静的規則として IP 層に射影（`ip_layer_allows()`）— name 層エントリと併存

**検証:** T-BASE、T-POLICY、T-LAYER（新フィールドの層位置）。継承・export・再出力での保存、未知/不正 CIDR の拒否、PSEC 経路での表現不能拒否を単体試験で確認する。

**完了条件:** ドメイン名と CIDR が別の層の規則として型上も出力上も区別され、どちらの層にも届かない経路（Auditor のみ等）が plan で可視化される。

**移行・戻し方:** 既存の `allow host=`/`deny host=` の意味を変えない。スキーマ追加は v1/v2 両形式での扱いを決め、旧版バイナリが新属性を黙って捨てないことを確認する。

<a id="pr-06"></a>

### PR-06 DNS ゲート — ポリシー評価リゾルバ

対応論点: §1.2、§1.6（名前層 emit）。直接依存: PR-01（イベント emit）、PR-05（スキーマ）。着手・公開条件: 常設。v0.3 では「設定ベースで先行利用可能な単体」として提供し、netns 組み込みは PR-09 の範囲。

**目的:** 名前解決の時点でポリシーを評価し、許可名だけを解決する。拒否名の流出を監査に残す。

**主な成果物:** 新規ゲートコンポーネント（`src/dnsgate/` 等を候補 — 層の登録を `docs/modules.md` と `tests/module_layering.rs` で同じPRに行う）、設定・運用のガイド節。

**タスク**

- [x] UDP/TCP の DNS リゾルバーを実装する。上流リゾルバへの転送はクエリを中継する形とし、通信の中身（応答ペイロードの意味解釈）はしない — 宛先制御の範囲に留める。→ `src/dnsgate/`（`wire` 最小コーデック / `upstream` UDP→TCP 中継 / `server` UDP+TCP リスナ）。応答から読むのは CNAME チェーン・A/AAAA・TTL の制御面のみで、応答本体は verbatim 中継
- [x] クエリ名を [host.rs](../src/policy/host.rs) の UTS-46 正規化（`normalize_policy_host`、`idna` crate 導入済み）に通してから名前ポリシー（`allowed`/`denied_hosts`、ワイルドカードは `host_matches` 相当）を評価する。Unicode 変種（全角ドット等）による拒否回避は既対策を再利用する。→ `name_policy::evaluate` が `normalize_policy_host`+`canonicalize_policy_host` 経由で判定。`host_matches` は `policy::host` へ共有化し Auditor は委譲 — 同一意味論。IP リテラルのクエリ名は `cidr` 規則にも照合
- [x] 拒否名は NXDOMAIN/REFUSED を返し、`sandbox.network_denied` を `name`/`qtype`/`session_id` 付きで emit する — 解決時点で止まった流出が監査に乗る（§1.6 名前層の最初の実装）。→ `--refuse-rcode nxdomain|refused` で選択。`details` に `layer=name`/`name`/`qtype`/`decision`/`rule`/`rcode`/`client`/`session_id`。fail-closed 時は応答前に `log_committed` で耐久化
- [x] CNAME は最終名まで追跡するが、allow/deny の評価はクエリ名のみに対称適用する（§1.2 の根拠 — チェーンはワークロードが制御しない）。応答のチェーン全体は監査 details に記録し、観測はするが強制はしない。→ `wire::parse_response` が深さ16・ループ検出付きで追跡し `chain=a>b>c`/`chain_truncated` を記録。許可側には `sandbox.network_resolved` を新設
- [x] 応答 IP を TTL スコープ（チェーン最小 TTL）で IP 層の動的 allowlist に登録するインターフェースを定義する — PR-07 の supervisor / PR-09 のプロキシが読む共有表。TTL 失効・再上書き・同一 IP の複数名共有を扱う。→ `DynamicAllowList`（`register`/`is_allowed`/`names_for`/`live_len` + `snapshot_json`/`export_to` の JSON スナップショット契約 `{"schema_version","generated_at_unix_secs","entries":[{name,addr,expires_at_unix_secs}]}`。`--allowlist-export` でバッチごとに原子書き出し。grant はクエリ名に紐付き、TTL はチェーン最小
- [x] 起動形態を決める: 単体プロセス（新サブコマンドまたは `run` の内蔵コンポーネント）、listen アドレス、上流リゾルバの設定、ゲート自身の失敗時挙動（上流 unreachable → fail-closed 側へ倒すかの約定）。→ 新サブコマンド `mcp-writ dns-gate`（`--policy`/`--upstream` 必須、`--listen` 既定 `127.0.0.1:1053`、`--server`/`--refuse-rcode`/`--allowlist-export`/`--audit-log`/`--audit-sync`）。上流 unreachable/timeout → `SERVFAIL`、fail-closed 監査シンク死亡 → 許可クエリを `SERVFAIL`（未監査で解決しない）。SIGINT/SIGTERM で正常停止。ポリシー読込は `load_policy_or_default_for_resolver` — 文書検証のみでワークロード OS 強制可能性チェック（AppContainer/PSEC/Landlock additive）は起動側の責務。ゲートは起動しない + 名前層はゲート自身が強制するため、Windows の `run` が拒否する `host=` 許可リストでも読み込める
- [x] キャッシュ・同時問合せ・応答サイズに上限を設ける。DoH 迂回（853/443 への直行）は IP 層の既定拒否で塞ぐ前提であることを明記する — ゲート自体はそれを防がない。→ キャッシュ無し（毎クエリ再解決）、同時処理 256・TCP 接続 64・アイドル 60s・応答 ≤65535・grant 16384 の固定上限。DoH/ハードコードリゾルバ/IP 直行は名前層を迂回し IP 層の仕事とガイドに明記
- [x] `allow host=` 規則が「Auditor の引数検査に加えて DNS ゲートの名前ポリシーにも効く」ことを plan 出力とガイドに反映する。→ `plan.egress_layers` の名前層 note に dns-gate の存在と非組み込みを明記（linux/macos/windows）。guide.md/guide.ja.md に §4.9 と監査スキーマ記述、policy-authoring 英日に注記、`dns_gate_e2e` を test-matrix と CI/Platform/Linux ワークフローへ登録

**検証:** T-BASE、新規ゲート試験ターゲット（担当PRで追加・ワークフロー登録）。許可名/拒否名/ワイルドカード/CNAME 追跡/TTL 失効/不正クエリ/上限到達を単体・結合試験で確認し、拒否時の `sandbox.network_denied` emit を JSONL で検証する。

**完了条件:** 設定ベースで単体利用でき、拒否した名前が監査に残る。動的 allowlist の形式が PR-07/PR-09 の入力契約として確定している。

**移行・戻し方:** ゲートを無効にしても従来の Auditor 名検査は維持する。ゲート不在で名前解決が通る経路がある場合の表示を「名前層なし」として正直に残す。

<a id="pr-07"></a>

### PR-07 Linux IP 層 — seccomp user notification PoC

対応論点: §1.3(a)、§1.6（IP 層 emit）。直接依存: PR-05（`cidr` スキーマ）、PR-06（動的 allowlist の入力契約）。着手・公開条件: PoC — 製品既定経路には接続しない。

**目的:** `connect()` 時点で宛先 IP を検査し、静的 CIDR と DNS ゲートの動的許可の両方で判定する。

**主な変更先:** [seccomp_impl.rs](../src/warden/seccomp_impl.rs)、[linux_spawn.rs](../src/warden/linux_spawn.rs)、[child.rs](../src/warden/child.rs)、新規 supervisor モジュール（`src/warden/` 配下を候補）、`docs/validation/` の新規検証文書。

**タスク**

- [x] `SECCOMP_USER_NOTIF`（`SECCOMP_FILTER_FLAG_NEW_LISTENER`）で `connect` を通知対象にするフィルタを追加し、リスナ fd を supervisor 側へ渡す経路を作る — 現行の pre_exec 自己適用モデル（[linux_spawn.rs](../src/warden/linux_spawn.rs) の `no_new_privs → Landlock → seccomp`）と supervisor 常駐モデルの共存形を決める。→ `warden::unotify` 新設 + opt-in サブコマンド `unotify-run`。共存形: 子の pre_exec で `Landlock` 後・ポリシー seccomp 前に通知フィルタを装着（`stage::UNOTIFY`）し、SCM_RIGHTS の Unix socketpair でリスナ fd を親へ handoff — supervisor は `unotify-run` プロセス内に常駐し、子の存続中 `NOTIF_RECV`/`NOTIF_SEND` を回す
- [x] supervisor は子の `sockaddr` を `process_vm_readv`/`/proc/pid/mem` で読み、静的 CIDR 規則と動的 allowlist（PR-06 の TTL スコープ表）に照合する。「引数検査〜実使用の隙間」（読み取り後に子が sockaddr を書き換えうる）を限界として記録する。→ `process_vm_readv` で `AF_INET`/`AF_INET6` を復号（v4-mapped は正規化）。評価は `OutboundPolicy::ip_layer_allows/denies` の静的射影 + `--allowlist` スナップショットの live grant（TTL は接続ごとに再評価、陳腐ファイルは空集合 fail-closed）。TOCTOU は `LIMITATIONS` と検証文書に明記（後のセキュリティスキャン対応で、許可 connect は `pidfd_getfd` で複製したソケット fd に pin 済み sockaddr で `connect(2)` を代行するエミュレーションへ置換 — CONTINUE は非 INET/未知 syscall のみに限定され、検査後の書き換えはカーネルへ届かなくなった）
- [x] 許可側は `SECCOMP_USER_NOTIF_FLAG_CONTINUE`（kernel 5.5+）でオーバーヘッドを抑える。カーネル未対応時は起動前診断で拒否する。→ 起動時に `SECCOMP_GET_NOTIF_SIZES` + 実際の fork→通知→`CONTINUE` ラウンドトリップで検査し、未対応は exit 2 で拒否（`allow_degraded` で緩めない）
- [x] 拒否時は `sandbox.network_denied` を `dest`/`port`/`proto`/`session_id` で emit する — IP 層 emit 経路の最初の実装。→ `details` に `layer=ip`/`proto`（`pidfd_getfd`+`SO_TYPE`、失敗時 `unknown`）/`dest`/`port`/`pid`/`decision`/`rule`/`session_id`。fail-closed 監査では応答前に `log_committed`、シンク死亡時は許可判定も拒否化し子を kill
- [x] v0.3 の範囲は TCP `connect` のみ。UDP/RAW socket・`sendmsg`/`sendto` は別途設計として残し、黙って素通しする経路があれば診断で示す。→ `sendto`/`sendmsg`（`connect` を介さない `MSG_FASTOPEN` の TCP 確立を含む）・io_uring `IORING_OP_CONNECT`・非ソケット経路は `LIMITATIONS` と `--report.limitations` に明記。`AF_INET`/`AF_INET6` 以外の `connect` は無監視 CONTINUE として同じく記録（UDP `connect` は宛先確定なので監視対象）
- [x] supervisor の死亡・監視断の扱いを決める — 通知への応答が無いまま子が進む経路を fail-closed 側へ倒す。→ リスナ fd 解放でカーネルが保留/将来の `connect` に `ENOSYS` を返す（`dropped_listener_makes_connects_enosys` で実証）。コマンド側は監視対象プロセスグループへ SIGKILL も送る。`NOTIF_SEND` 前に `ID_VALID` で id を再検証し pid 再利用 race を閉じる
- [x] 「supervisor/proxy が介在する経路で弾いたもののみ emit 可能」（§1.6）の仕様をここで確定する — Landlock/seccomp のカーネル内拒否には通知が来ないため、観測可能な経路と不能な経路を分けて文書化する。→ ガイド英日の監査節で `sandbox.network_denied` を name 層（dns-gate）/ip 層（unotify-run）に層別記述し、カーネル内拒否は引き続き無記録と明記。ポリシー seccomp が `connect` を ERRNO で落とす場合は通知自体が発火しない点も `LIMITATIONS` に記録
- [x] 「plain spawn = IP 層のみ、namespaced = 2 層」という能力差を plan/--report/ガイドで表現する。→ PoC は `unotify-run` 専用で既定 `run`/`plan` は不変（`plan` は IP 層を Auditor 限定のまま正直に報告）。能力差は `unotify-run --report` の `capability`/`egress` 2 層 disposition + `limitations` で表現し、`plan` 側は IP 層 note で PoC の存在を参照するに留める
- [x] レビュー指摘の是正（PR-07 ブランチ内フォローアップ）: (a) `defaults.environment` と `binary-hash`/`entrypoint-hash` pin が `unotify-run` に未適用だった — `env::apply_spawn_env_sync` 新設 + `resolve_command_path`/verify→bind→reverify チェーンを `unotify_run` に配線し、spawn 直前に `SpawnPin::verify_spawn_path` で再検。(b) 許可 connect に監査が無かった — `sandbox.network_allowed`（info/buffered、dns-gate `network_resolved` と同型）を新設。(c) `parse_sockaddr` が `to_ipv4()`（compatible も fold）だった — `to_ipv4_mapped()` に揃え compatible 表記は v6 のまま。(d) `recv_listener` に `MSG_CTRUNC`/`cmsg_len` 検査を追加。(e) 名前形 `deny host=`・grant 供給なしの `allow host=` は起動時警告で可視化。(f) SIGHUP/SIGQUIT も転送（129/131）

**検証:** T-BASE、実 Linux（kernel 5.5+）での PoC 動作確認、新規結合試験（担当PRで追加）。許可/拒否/動的 allowlist 反映/TTL 失効後の再接続拒否/supervisor 死亡時を確認し、`/proc` 読み取りの権限・races を含む限界を検証文書に記録する。

**完了条件:** IP 直打ちの egress（シナリオ B）が PoC 経路で止まり、拒否が JSONL に残る。観測経路を持つ最初の IP 層として、能力と限界が明記される。

**移行・戻し方:** PoC は opt-in フラグか試験経路に留め、既定の plain spawn を変えない。不具合時は unotify フィルタを外して従来 seccomp のみに戻す。

<a id="pr-08"></a>

### PR-08 拒否監査の仕様確定とシナリオ回帰 e2e

対応論点: §1.6（仕様面）、§5.4。直接依存: PR-03、PR-04、PR-06、PR-07。着手・公開条件: v0.3 統合の締め。

**目的:** 「拒否された通信が監査に残る」ことをエンドツーエンドで固定し、観測できない経路を仕様として区別する。

**主な変更先:** 新規 `tests/` ターゲット、[test-matrix.md](test-matrix.md)、[development.md](development.md)、英日ガイド。

**タスク**

- [x] シナリオ A（注入 → 拒否 → JSONL 確認）を e2e 化する — RPC 層の拒否が `tool_call.denied`/`mcp_message.denied` として残る経路を fixture で固定する。→ `tests/denial_audit_e2e.rs::scenario_a_denied_rpc_requests_are_audited` — `scripted_stdio` fixture 上の実 `run` で、ポリシー未収載の `tools/call exec_shell` が `tool_call.denied`（`request_id`/`severity=high`/`action=denied`）、`mcp` 規則の無い `resources/read` が `mcp_message.denied`（`reason=no-rule`/`forwarded=false`）としてクライアントへの拒否応答と共に残ることを固定。`guard.started`/`stopped` のライフサイクルブラケットも検証。RPC 層の計測であり `MCP_WRIT_SKIP_SANDBOX` 経路である点は検証文書に明記
- [x] シナリオ B（443 直出し）を再現し、PR-07 の IP 層で拒否されること・拒否イベントが残ることを回帰テストにする。→ `scenario_b_direct_443_egress_denied_and_audited`（Linux のみ）— 実 `unotify-run`＋`connect_probe` fixture で `192.0.2.1:443`（TEST-NET-1）への connect が supervisor 拒否（EACCES/exit 10）し、`sandbox.network_denied` `layer=ip`/`dest`/`port`/`decision=deny-cidr` が JSONL に残ることを固定。`check_support` 非対応ホストは `MCP_WRIT_REQUIRE_E2E_TESTS` 経路の skip。初実測で unotify の潜伏不具合 3 件（probe の引数違い・`NOTIF_ID_VALID` の値渡し・POLLHUP race）を発見・修正し、bare-port 正規化の未修正不具合は PR-09 へ繰越 — [denial-audit.md](validation/denial-audit.md)「Latent defects」
- [x] 名前拒否（PR-06）→ NXDOMAIN/REFUSED + `sandbox.network_denied` の e2e。→ `dns_gate_denied_names_are_refused_and_audited` — 実 `dns-gate` バイナリを既定（REFUSED）と `--refuse-rcode nxdomain`（NXDOMAIN）の 2 脚で起動し、`deny host=`・未許可名それぞれで `sandbox.network_denied` `layer=name`（`decision=deny-host`/`not-allowed`・`rcode`）を検証。許可名の `sandbox.network_resolved` を対として確認し、`--audit-sync`＋`log_committed` で拒否レコードの応答前耐久化も固定
- [x] SIGKILL 末尾欠損の計測（PR-04 のバッファ改善の効果測定）を実装し、失われうる範囲を数値で記録する。→ 計測器は `tests/audit_durability_e2e.rs`（PR-04 で実装）、PR-08 で再実行して [denial-audit.md](validation/denial-audit.md) に数値記録 — 参照ホスト（WSL2 kernel 6.18.40.1・debug）で buffered は 53 emit/3 生存/`lost_info=50`（`high`+ は全件即時 fsync で生存）、`--audit-sync` は 54/54・損失 0、drain は buffered 13ms vs sync 167ms。単一ホストの計測値で契約は順序保証のみ — `MEASURE` 行で毎回再記録
- [x] PSEC 状態の JSONL emit（PR-03）の e2e を Windows で実施する。→ `winiso_live_product_run`（tests/windows_isolation_e2e.rs）に `assert_audit_enforcement` を実装 — `server.connected` の `enforcement.backend` が要求 mechanism と一致、PSEC 起動で `psec.schema_version="1.0"`＋egress 状態、AppContainer 起動で `psec` が null、拒否された PSEC 起動が `appcontainer` を名乗る `server.connected` を残さないことを検証。**Windows 実機実行は未実施** — windows-msvc ターゲットへのコンパイル確認まで。denial-audit.md に `not run` と記録し、実行は windows-isolation ジョブ（`MCP_WRIT_REQUIRE_WINISO_TESTS`）の責務として merge コミットでの再記録を残す
- [x] Landlock 単独経路の FS/ネットワーク拒否が監査に残らないことを「観測不能」として試験と文書に固定する — emit されないことを検知するテストではなく、「残らないことが仕様」であることを表明するテストにする。→ `landlock_fs_denial_is_unobservable_by_spec`/`seccomp_connect_denial_is_unobservable_by_spec`＋`tests/fixtures/denial_audit/kernel_deny_probe.rs` — プローブ自身の EACCES/EPERM 報告（KDP stderr マーカー＋exit 10）が「拒否は起きた」証人、`enforcement.backend=landlock+seccomp` が拒否主体の証拠、`sandbox.*_denied` 不在は仕様の表明として検査する構成。プローブ未実行時は unavailable 報告で pass-by-absence にしない。ガイド英日の監査節に「Regression coverage」を追加
- [x] 新規試験を [test-matrix.md](test-matrix.md) の担当一覧と手動ワークフローへ登録する。→ `denial_audit_e2e` 行を追加（脚別内容・要件・証拠リンク）し `MCP_WRIT_REQUIRE_E2E_TESTS` の対象一覧へ追記。CI/Platform tests/Linux tests ワークフローへ `--test denial_audit_e2e` を登録、development.md に実行手順と脚の説明を追加。PSEC JSONL 脚は `windows_isolation_e2e` 行を更新し windows-isolation ジョブの責務として登録

**検証:** 上記シナリオが全て実行され、成功・拒否・環境未確保が区別されて記録される。

**完了条件:** v0.3 の監査完全性の主張（バイパス記録・enforcement 状態・拒否 emit・SIGKILL 耐性）が全て再現可能な試験か記録された限界として残る。

**移行・戻し方:** 試験追加のみ。製品経路の既定は変えない。

<a id="release-v0-3"></a>

### リリース: v0.3.0 — PR-01〜08 の完了後

実装PRではなく、ここに到達した時点で確認する条件と手順です。バージョン更新・タグ付け・リリース実行は git／リリース操作のため、実施は別途指示を受けてから行います。

**到達条件 — 全て満たしたらバージョンを上げる**

- [x] PR-01〜08 が全てマージ済み — `main` で merge #52〜#59（`2ba1c6d`〜`753a492`）を確認（2026-10-10）
- [x] §5.4 の検証記録（シナリオ A/B・PSEC JSONL・SIGKILL 計測）が残っている — [denial-audit.md](validation/denial-audit.md) に記録。**ただし** PSEC JSONL 脚は Windows 実機未実施の `not run` 記録であり、`windows-isolation` ジョブが merge コミットで再記録する責務が残る — タグ前に実施するか「記録済みの限界」として受理するかはリリース判断
- [x] 「観測不能」の残存経路が仕様として文書化されている — `sandbox.file_denied`/`sandbox.process_denied` の予約済み仕様（英日ガイド監査節）、[denial-audit.md](validation/denial-audit.md) の kernel-internal 節、`denial_audit_e2e` の仕様表明脚で固定

**バージョン更新の手順**

- [x] [Cargo.toml](../Cargo.toml) の `version` を `0.3.0` に更新し、`Cargo.lock` を再生成する — 作業ツリーに反映済み・未コミット。`--locked` ビルドで lock 整合を確認
- [x] 最新コミットで T-BASE・T-DOC・該当する実機記録を再確認する — merge コミット＋バージョン更新のツリーで T-BASE/T-DOC を実施（2026-10-10・WSL2 kernel 6.18.40.1・x86-64・rustc 1.99.0）: fmt / clippy `-D warnings` / lib+bins 1954 件 / doc / doc-test 0 件 / docs_check 12 件 全 pass。`cargo doc` に private-item link の警告 7 件（既存）。`cargo package --locked --list` で同梱物確認（478 件、`.local/`・`target/`・監査ログの混入なし）。実機記録: denial-audit.md は当該ホストで 2026-10-09 実測済み、PSEC JSONL 脚の Windows 再記録は未実施。OS 固有コードの T-BASE は platform-tests 等の当該 OS ワークフローの責務
- [x] タグ `v0.3.0` を付ける — タグ push が [release.yml](../.github/workflows/release.yml) の起点（ci・platform-tests・container-tests・go-runtime の verify を通る）。push 前に当該コミットで 4 検証ワークフロー＋手動 dispatch の linux-tests（実 AArch64）・MCP server verification の成功が前提（[releasing.md](releasing.md) 手順 2）
- [x] リリースノートに「この版で保証する制御」と「残る限界」（§1.7・§5.2 の対応状況）を明記する — 下書きはセッション出力を参照

<a id="pr-09"></a>

### PR-09 netns/userns/mountns ＋ TCP/UDP プロキシ PoC

対応論点: §1.1、§1.3(c)。直接依存: PR-05（スキーマ・2 層評価）、PR-06（ゲートを resolv.conf 経路で内蔵）、PR-07（deny/allowlist の配管）。着手・公開条件: opt-in PoC — v0.4 の TCP/UDP 宛先制御と DNS ゲート強制の主経路。

**目的:** 非特権のまま「resolv.conf 支配＋DNS ゲート＋TCP/UDP を宛先チェック付きプロキシ経由」を組み、UDP を明示許可できる構成を実証する。名前層は DNS の問い合わせ名、IP 層は実際の宛先 IP・プロトコル・ポートを制御し、共有 IP 上の別ドメインまで識別する保証はしない（§1.7）。

**主な成果物:** 新規 namespaced spawn 経路（`src/warden/` 配下または新モジュール — 層登録を同PRで）、ポリシーのプロトコル・ポート・要求能力の表現、再現可能な実機 fixture と `docs/validation/` の新規検証文書。

**タスク**

- [x] 先に能力検査を実装する。一般ユーザー・ホスト側の追加 capability なしで userns/netns/mountns 作成、TUN 作成・FD 引き渡し、経路設定、私有 mount が可能かを実操作で確認する。作成禁止、TUN 不在・アクセス拒否、カーネル機能不足を区別して報告し、失敗したプローブの資源を回収する。→ `namespaced::probe`（tokio 起動前 dispatch の `namespaced-probe` re-exec）が実操作で unshare/idmap/tun/loopback/route を stage 別に報告し、init handshake の `ERR <stage>`（`unshare`/`idmap`/`tun`/`net`/`pidns-fork`/`proc-mount`/`sandbox`/`exec`）も区別する。実機確認: [linux-namespaced-proxy.md](validation/linux-namespaced-proxy.md) の capability gate
- [x] プロトコル（TCP/UDP）・宛先ポート・必須の実通信制御を表すスキーマを定義し、要求能力と backend 能力の照合を実装する。旧規則を暗黙に UDP 許可へ広げず、未表現の規則は起動前に拒否する。load/validate/継承/生成/export/emit と全 backend の対応をそろえる。PR-08 の bare-port 正規化不具合（[denial-audit.md](validation/denial-audit.md)）も解消し、数値 `host` とポートを混同しない。→ `EgressRule`/`EgressProto`/`EgressDest` で `proto=`/`port=` qualifier を保持し、parse（`kdl_parse`）→ emit（`kdl_emit`）→ memfd 再 parse の往復が成立（scoped `allow host="*"` は posture を汚染しない）。表現不能な backend（PSEC）は qualifier を拒否して widen しない。bare-port は `host::bare_port_spelling` で `allow host="443"`→port 規則に解消済み（deny の proto/port 修飾・all-digits host は parse 拒否で fail-closed）
- [x] userns+netns+mountns で子を分離し、信頼する起動処理だけが初期設定を行う。不要な capability とその再取得経路を閉じ、`no_new_privs` を設定してから MCP サーバーを exec する。子・孫にも隔離を継承させる。→ `namespaced::init` — `CLONE_NEWUSER|NEWNET|NEWNS|NEWPID` を1 `unshare`、init 親が `/proc/<pid>/{setgroups,uid_map,gid_map}` を書込（WSL2 で唯一の非特権経路）、pidns init＋`/proc` 再 mount、`no_new_privs`→Landlock→seccomp→exec、3段 `PR_SET_PDEATHSIG` カスケード。実機で `uid=0` in userns・`Pid: 1` を確認
- [x] mountns 内で `resolv.conf` を自前 mount で差し替え、DNS をゲート（PR-06）経由に制限する。外向き経路の判定も併用し、ファイル差し替えだけで強制済みとしない。ゲート外のハードコードリゾルバは拒否し、許可済み宛先を使う DoH 等は §1.7 の限界として残す。→ 私有 `/run` tmpfs でホスト AF_UNIX を遮蔽後、解決先が `/run` 配下なら tmpfs 内へ再生成、それ以外は私有 `/tmp` tmpfs から bind-mount（memfd パスは mount EINVAL）。`nameserver 10.250.0.1`（GATEWAY）で埋め込みゲートを指し、生の外部リゾルバは port-53 intercept（UDP/TCP 両対応）が捕捉して bypass 不可。ホスト側ファイル不変・DoT/DoH 限界は limitations に記録
- [x] netns 内の外向き IP 経路を TUN 経由に限定し、その FD をホスト側の非特権プロキシへ渡す。プロキシは判定済みの宛先だけに自身の socket で中継する。tun + smoltcp 相当の依存選定はこのPRで確定し、最小フットプリント・外部デーモン非依存を維持する。→ `stack.rs` — `/dev/net/tun` 一本化（`IFF_NO_PI`）＋ smoltcp DNAT splice、親保持の TUN fd が唯一の egress で proxy 死→fd close→fail-closed が構造的に成立。依存は `smoltcp` crate のみ・外部デーモンなし
- [x] プロキシの宛先判定に静的 CIDR＋動的 allowlist＋名前規則を接続し、deny 優先・IPv4/IPv6・セッション分離を維持する。DNS の許可情報は応答を子へ返す前に反映する。拒否は `sandbox.network_denied` へ記録し、TCP/UDP と宛先 IP・ポート、判定根拠を残す。→ `eval.rs` `FlowGate` — `IpLayerEvaluator`（静的 CIDR＋`egress_rules` quals）＋ `DynamicAllowList` の quals 付き grant＋deny 優先＋ audit sink 死亡で deny（fail-closed）。grant は answer を返す前に mint される。`sandbox.network_denied`/`allowed` は `layer=ip proto dest port`＋decision/basis を保持
- [x] UDP 中継を実装する。非 DNS UDP は既定拒否を維持し、明示した規則の宛先だけ許可する。`connect` 済みでも各データグラムの実宛先を検査し、DNS 由来の動的許可は有効期限も確認する。`sendto`/`sendmsg`/`sendmmsg` による別宛先への送信も同じ判定の対象にする。QUIC は UDP の宛先制御として扱い、暗号化された内容の検査は追加しない。→ `udp_task` — per-datagram verdict（TTL 失効は次のデータグラムで即時反映）、`connect()` で peer を pin し spoofed reply を排除、flow cap＋idle reaper、監査は方向別 dedup＋ emission budget で上限化。実機 `sendto` 往復・deny drop を確認。`sendmmsg` 混在と実 QUIC クライアントの fixture は未実施として検証文書に記録
- [x] namespaced の制御経路が確立した起動だけ、ポリシーで許可した UDP に必要な seccomp の socket 制限を緩める。family/type/protocol を区別し、native の `deny_all_others` 時の制約を維持する。Landlock のファイル制限を併用し、TCP ポート規則もプロキシの許可と矛盾しないよう構築する。→ `prepare_linux_child_sandbox_namespaced` ＋ `namespaced_netport_plan` — namespaced 経路のみ socket-family 緩和（netns 内ではどんな socket も TUN に行き詰まるため成立）、`ConnectTcp` は「deny-all posture かつ全 TCP allow が port-qualified」の時だけ維持し、それ以外は widen せず proxy に委譲。レビューで検出した open posture の deny-all 化不具合は修正済み（回帰テスト追加）
- [x] 迂回経路を閉じる。隔離前の通信 socket の継承、SCM_RIGHTS/pidfd 等による外部 FD の取得、ホストの pathname UNIX socket 等を使った代理通信、監視プロセスへの干渉、`setns` や経路変更を制限する。TUN・設定用 FD は子に残さない。必要な IPC は経路を限定して明示許可する。→ handshake socketpair・policy memfd・TUN fd は全て子に残らず fd>2 を全 close＋`MCP_WRIT_NS_*` scrub（policy env 経由の注入も spawn で遮断）、`/run` tmpfs で dbus/docker.sock 等のホスト AF_UNIX 代理経路を遮蔽（実機 FileNotFound）、pidns＋proc remount で監視プロセス不可視・signal 不能、`setns`/nested `unshare` は EPERM
- [x] 対応外のプロトコル・アドレスファミリーは既定拒否とする。断片化、IPv6 拡張ヘッダー、ICMP/ICMPv6 の制御通信、MTU の扱いを定義し、解釈・検査できないパケットを素通ししない。`io_uring` は既存の危険 syscall 制限を維持し、許可する構成でも宛先制御を迂回できないことを検証する。→ classifier が v6/fragment（MF・offset 両捕捉）/未知 proto/malformed を全 drop＋netns 内でも `disable_ipv6`、MTU 1500 固定。`io_uring_setup` は workload の syscall policy 未許可で実機 −1 を確認（proxy が終端しないプロトコルに egress は存在しない）
- [x] プロキシ・DNS ゲート・必須監査の障害、中断、初期化途中の失敗では起動拒否またはワークロード停止とし、直接通信へ戻さない。通常終了・強制終了とも子孫、FD、名前空間、一時 mount を回収する。→ init `ERR <stage>`→起動拒否、`RunExit::ProxyLost`/`AuditFailed`→group kill＋reap、audit sink 死亡→verdict deny（fail-closed）。supervisor 死亡は3段 pdeathsig で subtree 全滅（実機 `ps` に leak なし）、exit status は init 親→grandchild→pidns の経路で signal 再送出込み転送
- [x] プロキシ自体の信頼性（§1.7）— ユーザ空間スタックの実装バグが境界に影響する点を記録する。プロキシ自身の制限、パケット長・再構成バッファ・フロー数・待ち時間の上限を定め、最小実装と異常入力試験で検証する。→ `report::LIMITATIONS` で自己申告し、task 間の全 queue を bounded 化（満杯は drop でメモリ増殖しない）＋`LISTEN_POOL`/`UDP_FLOW_CAP`/`CONN_PENDING_CAP`/`GATE_INFLIGHT`/audit budget で上限を定義。検証は malformed drop 計上までで、異常入力 fuzzing は検証文書の未確認一覧に記録
- [x] 性能: cold/warm 起動・初回応答・メモリを既存の基準経路（native spawn）と同じ fixture で測る。→ 実機 `namespaced-run -- true` warm×3 = 0.22s・約16MiB maxrss（baseline `mcp-writ --version` 0.04s — overhead ≈180ms＋16MiB）。native spawn と同一 fixture での対測定は未実施として記録

**検証:** T-BASE、T-POLICY、T-DOC と実 Linux の PoC 試験。先行する小規模試作の成功を製品の完全な経路検証と扱わず、既存の起動・ポリシー・DNS・監査と結合した fixture をリポジトリに残す。

| 検証対象 | 受入条件 |
|---|---|
| 非特権・能力不足 | ホストの UID/capability を記録して正常起動。名前空間作成禁止・TUN 利用不可では明示拒否し、ホスト設定を変更しない |
| TCP/UDP の正常系・拒否系 | IPv4/IPv6 の許可宛先との往復と、拒否 IP・ポートへの未到達を受信側で確認。既定拒否と deny 優先も確認 |
| UDP の送信方法 | 未接続送信、接続済み送信、別宛先指定、`sendmmsg` 内の宛先混在を検証。QUIC の実クライアントでも許可先の正常通信と拒否先の遮断を確認 |
| DNS と時限許可 | ゲート経由の A/AAAA、ゲート外 DNS の拒否、TTL 失効後の UDP 送信拒否、別セッションの grant が流用されないことを確認。既存 TCP 接続の TTL 失効時の扱いも仕様化・検証 |
| 迂回・異常入力 | 継承/受け渡し FD、ホスト IPC、子孫、名前空間・経路変更、許可時の io_uring、断片化・拡張ヘッダーを検証。対応外は拒否し、未実行は未確認として記録 |
| 障害・後始末 | プロキシ/ゲートの強制終了、必須監査失敗、部分初期化失敗で外部送信が継続しないこと、子孫・FD・一時設定が残らないことを確認 |

**完了条件:** 名前層と TCP/UDP の宛先制御、上記の正常系・拒否系・迂回・障害試験が実機で確認され、実装と `plan` / `--report` / 監査の能力表示が一致する。必要な検証が未確認なら採用判定を保留し、PR-16 の製品化へ進めない。

**移行・戻し方:** PoC は既定経路にしない。無効化した場合も namespaced 必須の起動は拒否する。製品化時の既存経路への切り替えは [Linux の方式選択](#linux-egress-selection) に従う。

<a id="pr-10"></a>

### PR-10 cgroup eBPF（INET4/6_CONNECT）opt-in

対応論点: §1.3(b)。直接依存: PR-07（deny emit・allowlist の配管）。着手・公開条件: 権限あり環境の opt-in 強化として。

**目的:** 特権の使える環境で、IP 層をカーネル内強制＋deny イベント観測に寄せる。

**主な変更先:** 新規 eBPF 経路（`src/warden/` 配下または新モジュール）、[seccomp_impl.rs](../src/warden/seccomp_impl.rs)・[linux_spawn.rs](../src/warden/linux_spawn.rs) との併用整理、英日ガイド。

**タスク**

- [x] cgroup eBPF で `BPF_CGROUP_INET4_CONNECT`/`INET6_CONNECT` をフックし、静的 CIDR＋動的 allowlist で判定する。crate 選定（aya 等）・BPF object の同梱形態をこのPRで確定する。→ 外部 crate なしの生 insn 生成＋`bpf(2)` 直接呼出しに確定（[src/warden/ebpf/](../src/warden/ebpf/mod.rs)）。静的規則は deny 優先の ARRAY map＋生成 straight-line プログラム、動的 grant は別 map＋TTL をカーネル側で評価。grant map の書き換えは dead-expiry フェーズ＋専用 seq マップの seqlock で囲まれ、torn read は判定を既定へ倒す（deny-all 下では拒否: fail-closed）
- [x] CAP_BPF/CAP_SYS_ADMIN 等の権限前提を起動前診断で検査し、不足時は opt-in 経路だけを拒否する — 既定経路を特権前提にしない（§1.3 表の評価を維持）。→ `check_support` が stage 名つきで拒否（`--report` では `state: "unsupported"`、exit 2）。`allow_degraded` は本チェックを覆さず、unotify/通常経路へのフォールバックもしない
- [x] ring buffer 等で deny イベントを観測し、`sandbox.network_denied`（`dest`/`port`/`proto`）を emit する — カーネル内拒否でも観測可能な経路。→ `BPF_MAP_TYPE_RINGBUF`＋drain スレッドが commit 済み `sandbox.network_denied`（`layer=ip`・`decision`・`rule`・`session_id` 込み）を emit。ring 飽和は判定を弱めず `denied_dropped` で計数し、判定数そのものはカーネル側カウンタを drain 終了時に回収して `kernel_denied` として報告
- [x] cgroup の割り当て・detach・後始末を実装し、他プロセスの cgroup を巻き込まない。→ 私有 cgroup（`/sys/fs/cgroup/mcp-writ-ebpf-<pid>-<nonce>`）を子の `pre_exec` で `cgroup.procs` へ書き込んで join。退避時は残存メンバーを先に kill（`cgroup.kill`、無ければ freeze＋pid sweep）してから detach＋rmdir — デーモン化した子孫が強制を残したまま残留しない
- [x] 本PRの connect フックだけでは UDP の全送信経路を制御できないことを能力表示に反映する。PR-09 の TCP/UDP 制御の自動代替にはしない。→ `--report.limitations`・英日ガイドに connect-only・UDP `sendto`/`sendmsg`・`SCM_RIGHTS`・supervisor 死亡時の残滓を明記。`plan` の既定経路評価は不変更

**検証:** T-BASE＋権限のある実 Linux 環境での動作確認。非特権環境では起動前拒否が出ることを確認。

**完了条件:** opt-in として明示選択した場合のみ有効で、既定の非特権経路を変えない。deny が観測・emit される。

**移行・戻し方:** eBPF 経路だけを無効化できる。unotify 経路への暗黙フォールバックはしない（観測経路の違いを混同しない）。

<a id="pr-11"></a>

### PR-11 macOS loopback CONNECT プロキシ経路

対応論点: §1.5。直接依存: PR-05（スキーマ）。着手・公開条件: 常設。sandbox-exec は deprecated のため投資をこの範囲に限定する。

**目的:** `localhost:port` 許可だけが書ける SBPL の制約を、loopback 上の宛先判定プロキシでドメイン制御に変換する。

**主な変更先:** [macos_sandbox.rs](../src/warden/macos_sandbox.rs)、新規プロキシコンポーネント（PR-09 の宛先判定コアと共有できるか検討）、英日ガイド。

**タスク**

- [x] `sandbox-exec` の `(allow network-outbound (remote tcp "localhost:port"))` でプロキシだけに出られる構成を作る。プロキシが CONNECT/宛先情報から名前・IP を判定して外向き dial する — 中身は見ない。→ `EgressProfile::ConnectProxy { proxy_port }`（[macos_sandbox.rs](../src/warden/macos_sandbox.rs)）が `remote tcp "localhost:<proxy_port>"` のみ許可し、プロセス内 `ConnectProxy`（[macos_proxy/proxy.rs](../src/warden/macos_proxy/proxy.rs)）が CONNECT authority を名前/IP 規則で判定してから dial — `200` 後はバイトを splice するだけで内容は見ない
- [x] SBPL の `(remote ip "…")` で IP リテラル egress も試行し、使える範囲を実機で確かめる。→ macOS 26.6.2 で実測: `(remote ip)` と IP リテラルの `remote tcp` はプロファイルロード時に拒否（"host must be * or localhost"）。使えるのは `localhost` と `*` のみ — プロキシ経路が必須であることを裏付け、結果は [docs/validation/macos-connect-proxy.md](validation/macos-connect-proxy.md) に記録
- [x] プロキシの listen・宛先判定・拒否時の `sandbox.network_denied` emit を実装する。macOS 側の拒否は SBPL が loopback 外を止める構成であり、「プロキシが宛先を判定した」ことが emit の根拠。→ `ConnectProxy` が判定・dial・emit を担い、判定コアは PR-09 と共有（`warden::flow_gate`/`warden::ip_eval` へ OS 非依存として移動）。拒否は commit 済み `sandbox.network_denied`（`layer=name|ip`）、成立フローは `sandbox.network_allowed`。カーネル側 SBPL 拒否は観測不能として文書化
- [x] 強い境界が要る場合は Apple Container バックエンドの NAT/ホスト側にゲートを置く経路を guide に明記する（実装はそのバックエンド側の話として切り分ける）。→ 英日 guide §4.13 と `--report.limitations` に「プロキシはランチャー内の信頼コードであり、supervisor を信頼しない境界には Apple Container の VM/NAT 隔離が文書化された強い経路」と明記 — 実装は本 PR 範囲外
- [x] deprecated API への投資はこの範囲に限定し、sandbox-exec 自体の拡張はしない。→ 変更は SBPL 生成の egress モード分岐と新規プロキシコンポーネントのみ。ネイティブ経路・プロファイル生成の他規則は無変更（既存テストで固定）

**検証:** 実 macOS でプロキシ経由の egress 制御と拒否 emit を確認。ネイティブ経路（sandbox-exec 単体）の既存挙動に回帰が無いこと。→ `macos_proxy_e2e` 15/15（macOS 26.6.2 arm64、シリアルおよび通常の並列実行）: CONNECT 許可経路 splice＋`network_allowed`、`deny cidr=`→403＋`network_denied layer=ip`、`deny host=`→`layer=name`、SSRF 保護宛先拒否、407、workload 直接/loopback egress カーネル拒否、UDP＋サンドボックス内 `getaddrinfo` 拒否、pipelined バイト中継、oversized head→431、`--listen` ポート報告、名前解決失敗の `decision=resolve-error` レコード、名許可後に拒否されたフローが `network_allowed` を残さないこと（同イベントは「確立」のみ）、WHATWG 数値 authority が畳み込み先 IP リテラルとして判定されること、SIGTERM がサンドボックス内 workload まで転送されること、ネイティブ `run` 非回帰。レビュー後の強化（移行スキーム宛先正規化、grant 容量拒否の可観測化、`proxy_stats.active` 出力、シグナルハンドラの spawn 前登録＋転送後の境界付き猶予）に加え、2回目レビュー指摘の是正 — `sandbox.network_allowed` をフロー確立後の記録点のみに限定（名層 Allow 時点の早期 emit を除去、成立しないフローが許可として記録される不具合）・名前解決を `{canonical}.` の絶対問い合わせに変更（ホストリゾルバの検索ドメインがポリシー未判定の別名を展開する経路を閉塞、IP リテラルへ畳まれた名は問い合わせせずリテラルとして判定）— も同ツリーで実施済み。シグナルテストの flake 解消: `proxy_sigterm_reaches_the_sandboxed_workload` が高並列負荷時に稀に `GOT_TERM` エコーを欠く件を調査した結果、supervisor の転送は常に正しく（`sleep` の SIGTERM 死と `kill(-pgid)` 成功を計測で確認）、原因はテスト側の `sh` workload — `wait` 中の子が同じグループシグナルで死ぬ局面では `sh` の TERM trap dispatch が保証されず、pending trap が EOF 経路で捨てられる（`sh` が exit 0 で echo なし）か無期限に遅延される（5 秒猶予を超えて SIGKILL まで生存）シェルセマンティクスの競合だった。workload を単一プロセスの Rust コンパイル fixture（`tests/fixtures/macos_proxy/sigterm_probe.rs` — `open_path_server.rs` と同じテスト時 `rustc -O` 方式、SIGTERM ハンドラが `write(2)` で `GOT_TERM` を出力）に差し替えて決定論的にした — 変更後の並列スイート 9 連続 15/15・直接再現ハーネス 90/90。証拠: [docs/validation/macos-connect-proxy.md](validation/macos-connect-proxy.md)

**完了条件:** ネイティブ経路でも loopback プロキシ経由なら宛先制御が効き、制限（deprecated API・プロキシ信頼性）は文書化される。

**移行・戻し方:** プロキシ経路は明示選択（`mcp-writ macos-proxy-run` 専用サブコマンド）。不具合時は従来の sandbox-exec 単体経路（host エントリは RPC 層のみ）に戻す — `run` 経路は一切変更していない。

<a id="pr-12"></a>

### PR-12 Windows PSEC — 既定化検討・ARM64・FQDN 限界の明記

対応論点: §1.4、§3.3（Windows 項）。直接依存: PR-03（PSEC JSONL）。着手・公開条件: 常設。

**目的:** 唯一の宛先 egress 実装である PSEC を、実測に基づいて既定化の可否まで進める。

**主な変更先:** [windows_psec.rs](../src/warden/windows_psec.rs)、[psec_spec.rs](../src/warden/psec_spec.rs)、[validator/psec.rs](../src/policy/validator/psec.rs)、[cli](../src/cli)、英日ガイド。

**タスク**

- [x] ARM64 対応を実機で確かめる — PSEC の arch サポート範囲を runtime probe で確認し、対応できるなら対象を拡大、無理なら拒否条件として明記する。→ 実機なしのため未検証＝拒否として実装: `capability_probe` 先頭で `GetNativeSystemInfo`（*マシン* arch、エミュレーション下でも正しく ARM64 と読まれる）を見て `AMD64` 以外を `capability-probe` ステージで拒否。記録: `windows-isolation.md` PR-12 節。
- [x] opt-in（`--windows-mechanism psec`）から既定化への可否を検討する — capability probe の信頼性・表現不能ポリシーの拒否カバレッジ・AppContainer 既定との差分を評価軸にし、既定化する/しないの判断と条件を記録する。→ **既定化しない**と判断（単一ビルド実測・preview 契約・環境非継承・ループバック免除なし・ARM64 未検証）。記録: `src/execution.rs` `WindowsNativeMechanism` ドキュメント + `windows-isolation.md`。
- [x] FQDN はネイティブでは不可能（PSEC v1.0 は loopback 免除なし → ローカルプロキシ/ゲートにも届かない）をガイド・plan 診断で明文化する。FQDN が要るワークロードは network broker 前置または Windows Sandbox/WSLc のゲストネットワーク経路を案内する（現行 validator メッセージと同じ指針）。
- [x] AppContainer 経路は宛先制御を持たない → 現行のロード時拒否を維持する。→ 維持（`validator/psec.rs` の AppContainer 分岐は不変、名前付き拒否メッセージは `NAME_LAYER_GUIDANCE` に集約）。
- [x] WFP は管理者権限が必要で CLI 常駐モデルと合わない → 補助枠としてのみ記録し、実装は保留とする判断を残す。→ `improvement-plan` § に補助枠として記録済み、`windows-isolation.md` PR-12 節に保留判断を追記。実装・フォールバックともに導入しない。
- [x] egress の port 修飾・IPv6 等、v1.0 契約の限界で拒否している項目が PR-05 の新スキーマでも正しく拒否されることを確認する。→ structured provenance で `host:port`/`proto`/`port` 修飾を修飾付きのまま拒否（素のホストへ拡大しない）。validator と spec ビルドが同一の expressibility ヘルパを共有し、unit テストで拒否を固定。

**検証:** T-BASE、Windows の実機 T-NATIVE と既存の `windows_isolation_e2e`。ARM64 は実機がある場合のみ実施し、無ければ未検証として記録する。

**完了条件:** PSEC の opt-in/既定の位置づけが実測に基づいて記録され、FQDN 不可の限界が利用者へ届く。ARM64 の可否が「検証済み/未対応」のどちらかで明記される。

**移行・戻し方:** 既定化する場合は opt-out を残す。PSEC を既定にして AppContainer の制御を落とさない。

<a id="pr-13"></a>

### PR-13 機能マトリクスの機械可読化と OS 位置づけ

対応論点: §3.1、§3.2、§3.3（Linux 項）。直接依存: PR-03（report の enforcement 情報）。着手・公開条件: 常設。

**目的:** 「何がどの OS で効くか」を EnforcementPlan のデータから機械可読に出し、文書との乖離を CI で検出する。

**主な変更先:** [enforcement.rs](../src/enforcement.rs)、[capability.rs](../src/enforcement/capability.rs)、[test-matrix.md](test-matrix.md)、英日 [guide.md](guide.md)、[README.md](../README.md)、CI 検査。

**タスク**

- [x] `PlannedControl`/`ProcessGrant`/`EnforcementPlan` の既存モデルから OS 横断の capability 出力を統一する — `mcp-writ plan`/`--report` が同じ情報源を使う形にする。実装: `enforcement::capability`（葉モジュール）に `MechanismCapability`/`LayerCapability`/`Requirement`/`UnmetRequirement` の共通モデルと 9 行の機構カタログを追加。各 OS の `os_egress_layer_status`（linux/macos/windows/fallback）と PoC レポート（unotify/namespaced/ebpf/macos-proxy）はカタログ行の `LayerCapability` から `EgressLayerStatus` を生成する — 文字列は起動経路と対応表で共有され、plan/report JSON の `target.sandbox_mechanism` と PoC `capability.capability_id`/`capability.missing` が同じ id を指す。
- [x] 出力と [test-matrix.md](test-matrix.md)（または新規の機械可読対応表）との整合を CI 試験で検査する — 実装と対応表が乖離したら fail する。実装: `mcp-writ capability-matrix` が `capability_matrix_json()`（`schema_version: "1"`）を出力。`docs/capability-matrix.json` はそのコミット済み写しで、`tests/capability_matrix.rs` がバイト比較・機構行の形状・`os: null` 層の Auditor 帰属・`mechanism_for` の全対象カバー・ホスト plan の `egress_layers` とカタログ行の一致を検査する。ci.yml / platform-tests.yml の Integration tests に登録済み。
- [x] 「native warden は Linux が本命、他 OS で強い境界が要る場合は `--isolation`（Kata/Apple Container/Hyper-V/Windows Sandbox/WSLc/OCI）経路を推奨」という階層設計を README/guide に明記する — OS 差評価を言い訳でなく設計として説明する。実装: マトリクス JSON の `positioning` ブロック（`native_warden`/`stronger_boundaries`/`honesty`）に加え、README「Security boundaries」と guide/guide.ja「実行方式と対応状況」に同じ位置づけを明記。
- [x] Landlock ABI 追従（probe 機構 `MCP_WRIT_PROBE_LANDLOCK_ABI` 済み）の現状と、新 ABI への追従方針を記録する。実装: カタログの `linux-native` 行は ABI 4 を optional 条件 `landlock-abi-v4` として持ち、追従方針（optional 条件として採用・記録レベルは正直に・`verified` へ昇格しない）を guide/guide.ja の OS 別適用範囲節に記録。
- [x] Linux の native / unotify / namespaced / eBPF を区別し、TCP/UDP、ポート/IP/名前の粒度、要求能力、不足能力、選択・拒否理由を共通モデルへ載せる。PR-09 の PoC 表示と PR-16 の方式選択に同じ判定を使う。実装: 4 行の Linux 機構は `transports`/`granularity`（fqdn/cidr/literal-ip/port/proto）/`requires`/`optional`/`deficiencies`/`select`/`refuse` を持ち、unotify・ebpf の `check_support` は `UnmetRequirement`（カタログ `requires` id）を返し `missing` メンバへ投影、namespaced の `ProbeReport::missing()` は同じ id を列挙する（`capable()` は `missing().is_empty()` と同値 — 1 つの判定を両者が使う）。`auto_candidate` フラグが PR-16 の選択候補を先行記録する。
- [x] 先行ブランチ由来のテスト追従修正を同梱する（本題と直接関係しないためここで明記する）: PR-12 で導入された子プロセス環境の既定制限に伴い `tests/{real_servers_e2e,tool_enforcement_e2e,path_resolution_e2e}.rs` のポリシーへ環境変数の明示許可を追加、`path_resolution_e2e` では AppContainer が拒否を `EACCES`/`ENOENT` どちらで返すかの差を許容、`tests/mcp_wire_e2e/deputy.rs` は文字通りの traversal と非正規形パスの診断メッセージを区別、`tests/wrap_image_e2e.rs` は Docker 不在環境で skip するガードを追加。

**検証:** T-BASE、T-DOC。matrix 生成と既存出力の差分照合、CI 検査の fail 経路を確認する。

**完了条件:** OS 差が「実装データから生成された対応表」として一貫し、手書き文書とのずれが検出できる。

**移行・戻し方:** 出力形式は版管理し、既存の plan/report 読み手を壊さない。

<a id="release-v0-4"></a>

### リリース: v0.4.0 — PR-09〜13 の完了後

実装PRではなく、ここに到達した時点で確認する条件と手順です。バージョン更新・タグ付け・リリース実行は git／リリース操作のため、実施は別途指示を受けてから行います。

**到達条件 — 全て満たしたらバージョンを上げる**

- [x] PR-09〜13 が全てマージ済み — `main` で merge #60〜#64（`4633fcc`〜`cb68e87`）を確認（2026-10-15）
- [x] PR-09/10/11 の PoC 検証文書が残っている — PR-09: [linux-namespaced-proxy.md](validation/linux-namespaced-proxy.md)、PR-11: [macos-connect-proxy.md](validation/macos-connect-proxy.md)。**ただし** PR-10 は `docs/validation/` の専用文書がなく、検証記録は [test-matrix.md](test-matrix.md) `ebpf_e2e` 行（WSL2 kernel 6.18・特権コンテナ 9/9）とガイド §4.12 の記載に留まる — 専用文書を要するかはリリース判断
- [x] PR-09 の TCP/UDP・DNS・迂回・障害試験に未確認の必須項目がなく、PoC の範囲と native との差が明記されている — 必須脚（capability probe・TCP/UDP 許可・拒否・監査・DNS ゲート・TTL grant・迂回経路遮断・supervisor SIGKILL teardown）は同検証文書で実機確認済み、opt-in PoC と native 経路不変も明記済み。**ただし** spec 検証表にあった `sendmmsg` 宛先混在・実 QUIC クライアント・TCP 接続中の TTL 失効・セッション間 grant 分離・v6 拡張ヘッダー細工・通信中の proxy/gate 強制終了は同文書 "not yet exercised" 節の未確認一覧に記録 — これらを必須項目とみなすかはリリース判断
- [x] PR-12 の既定化判断（する/しないとその条件）が記録されている — **既定化しない**（単一ビルド実測・preview 契約・環境非継承・ループバック免除なし・ARM64 未検証→拒否。再検討条件: 追加ビルド/エディション/arch の probe 脚実績と v1.0 契約の安定性確約）。記録: [windows-isolation.md](validation/windows-isolation.md) "PR-12 hardening record" 節 + `src/execution.rs` `WindowsNativeMechanism` ドキュメント

**バージョン更新の手順**

- [x] [Cargo.toml](../Cargo.toml) の `version` を `0.4.0` に更新し、`Cargo.lock` を再生成する — 作業ツリーに反映済み・未コミット（2026-10-15）。`Cargo.lock` は `mcp-writ` の version 欄のみの 1 行差分、`--locked` ビルドで lock 整合を確認
- [x] 最新コミットで T-BASE・T-DOC・該当する実機記録を再確認する — merge コミット（`cb68e87`）＋ lint 修正・バージョン更新の未コミットツリーで T-BASE/T-DOC を実施（2026-10-15・WSL2 kernel 6.18.54.1・x86-64・rustc 1.99.0）: fmt / clippy `-D warnings` / lib+bins 2195 件 / doc / doc-test 0 件 / docs_check 12 件 / capability_matrix 6 件 全 pass。`cargo doc` に private-item link の警告 15 件（既存クラス）。`cargo package --locked --list` で同梱物確認（525 件、`.local/`・`target/`・監査ログの混入なし）。**ただし** HEAD（`cb68e87`）自体は pinned 1.99.0 で fmt 4 箇所・clippy 27 件が失敗（PR-09〜13 系コミット由来）— 修正は作業ツリーに未コミットのため、コミット後の実ツリーで CI による再確認が前提。実機記録: 各 validation 文書の記録どおり（PR-10 は test-matrix `ebpf_e2e` 行・特権コンテナ 9/9）。OS 固有コードの T-BASE は platform-tests 等の当該 OS ワークフローの責務
- [x] タグ `v0.4.0` を付ける — タグ push が [release.yml](../.github/workflows/release.yml) の起点（ci・platform-tests・container-tests・go-runtime の verify を通る）。push 前に当該コミットで 4 検証ワークフロー＋手動 dispatch の linux-tests（実 AArch64）・MCP server verification の成功が前提（[releasing.md](releasing.md) 手順 2）
- [x] リリースノートに「この版で保証する制御」と「残る限界」（§1.7・§5.2 の対応状況）を明記する — 下書きはセッション出力を参照

<a id="pr-14"></a>

### PR-14 ポリシー運用 — REVIEW strict とドリフト検出 `mcp-writ check`

対応論点: §5.1。直接依存: なし。着手・公開条件: v0.5+。

**目的:** 生成ポリシーの未レビュー項目とハッシュドリフトを運用で検出できるようにする。

**主な変更先:** [policy_generator.rs](../src/legislator/policy_generator.rs)、[loader.rs](../src/policy/loader.rs)、[verifier](../src/verifier)、新規 `check` コマンド（[commands](../src/commands)、[cli](../src/cli)）。

**タスク**

- [x] legislator が生成する `// REVIEW` コメントの未解消をロード時に warn/refuse する strict モードを作る — 既定は warn か、opt-in strict かを決める。→ `policy::review` のコメント走査（行/ブロック/ネスト、`//` と `/* */`、文字列・raw 文字列内は除外、extends/include の祖先も収集）+ `MCP_WRIT_REVIEW_MODE`（`warn` 既定/`refuse`(`strict`) は `PolicyError::Validation` でロード失敗/`off` で黙止/未知値は fail-close で refuse）。既定は warn、strict は opt-in
- [x] `mcp-writ check`（仮）で現行ポリシーと実ファイルを再照合する — tools-list-hash/binary-hash/entrypoint-hash/lockfile-hash/docker-manifest-hash の再検証を既存 verifier の機構で実行し、CI で使える終了コードと出力を定義する。→ サブコマンド `check`（`--policy`/`--server`/`--engine`/`--report`/`-- <command>`）を新設。束縛済みポリシーの全 pin を `hash_file`/`inspect_image`/`hash_tools_list` で再照合し、pin 単位に `verified`/`mismatch`/`unreadable`/`unverified` を出す。`-- <command>` は起動 argv としても使い、`bind_launched_workload` のパス対応規則で identity pin（binary/entrypoint）の束縛を再検査する。`docker-manifest-hash` の `target=` がファイルを指す場合はネイティブ `run` と同じくファイルハッシュで照合する。REVIEW マーカーは帯域内 drift（`check` は REVIEW_MODE を強制しない）。終了コードは `plan` 規約（clean 0 / drifted 1 / invalid 2 / error 1）、JSON は stdout・要約は stderr
- [x] ドリフト検出時の運用手順（再生成・pin 更新・差分レビュー）をガイドに追加する。→ guide §4.15（英日）に終了コード・JSON スキーマ・drift 運用手順を記述。policy-authoring 英日にロード時ゲートと check の段落、README 英日のサブコマンド表、`policy_check_e2e` を CI/Platform/Linux ワークフローと test-matrix に登録

**検証:** T-BASE、T-POLICY、T-IDENTITY。REVIEW 残りの warn/refuse、各 hash の一致/不一致、`check` の終了コードを fixture で確認する。

**完了条件:** ポリシーの生成→レビュー→検出の運用サイクルが閉じ、`check` が CI に置ける。

**移行・戻し方:** strict は opt-in とし、既定のロード挙動を変えない。

<a id="pr-15"></a>

### PR-15 構造的限界と残存リスクの開示

対応論点: §5.2、§1.7。直接依存: PR-06、PR-07、PR-09、PR-11（実装に即した開示のため）。着手・公開条件: v0.5+。ただし各 egress PR の節に暫定記述を入れることは可。

**目的:** 実装で残る限界を、設計上の境界・残存リスクとして利用者が読める形に固定する。

**主な変更先:** 英日 [guide.md](guide.md)、[README.md](../README.md)、[policy-authoring.md](policy-authoring.md) 系、必要なら `docs/validation/` の記録。

**タスク**

- [x] TOCTOU（RPC 引数検査とサーバ内部動作の乖離）を設計上の境界として docs に固定する — FS は Landlock が `open()` 時点で強制するため実効的に緩和済み、という切り分けも書く。→ 英日ガイド §8.1 に固定。「検査→使用の形を閉じる経路」（Landlock/SBPL/AppContainer の open 時点強制・pin 済みオブジェクトの exec・unotify の connect エミュレート）と「検査時点に留まるもの」（非 FS 引数・OS 規則外オブジェクト・許可権限内のサーバー動作）を分離して記述。グローバル FS リストのみ OS 下限を持ち、ツール別 `filesystem` が macOS/Windows で Auditor-only である差も明記
- [x] `npx` 系は entrypoint-hash＋インタプリタ同時ピンのガイドを強化する。→ 英日ガイド §8.2 に `launcher_or_module` の pin 境界（argv からはランチャー `argv[0]` のみ pin 可能・ペイロードは `code_identity.mutable` 行・entrypoint target は第 1 ペイロード引数か実行ファイルに限るためパッケージ名では束縛失敗する）を記述し、直起動＋`binary-hash`/`entrypoint-hash` 両 pin の例を KDL で提示。policy-authoring 英日の「Executing through a launcher」節を強化。実装照合: [identity.rs](../src/verifier/identity.rs) の kind 分類、[pin.rs](../src/verifier/hash/pin.rs) の snapshot/staging、[launch.rs](../src/runtime/launch.rs) の verify→bind→re-verify
- [x] §1.7 の残存リスクを項目ごとに「現状・緩和・残存」を揃えて書く: DoH 回避（IP 層既定拒否で塞ぐが許可済み宛先兼リゾルバは残る）/ ECH（SNI 判定が効かない宛先）/ ハードコードリゾルバ（fail-closed 仕様）/ TTL レース / CNAME 委譲（対称評価の限界）/ 共有 IP（名前層の保証は解決名の範囲）/ プロキシ自体の信頼性。→ 英日ガイド §8.3 に 7 項目を「止められること／検知に留まること／残るもの」構造で記述。実装照合: `namespaced-run` の port-53 TCP/UDP インターセプト（[nat.rs](../src/warden/namespaced/nat.rs)・[stack.rs](../src/warden/namespaced/stack.rs)）、macOS CONNECT プロキシの 5 分固定 TTL キャップ（[macos_proxy/mod.rs](../src/warden/macos_proxy/mod.rs)）、SNI 非検査の警告（[ip_eval.rs](../src/warden/ip_eval.rs)）。※素のネイティブ `run` では名・IP 層は Auditor-only である前提を冒頭に明記
- [x] 各リスクについて「検知できること」（監査のチェーン記録等）と「止められること」を分けて記述する。→ §8.3 の各項目で `sandbox.network_denied`/`sandbox.network_resolved` の `ttl_min`/`chain`/`grants_refused`/`protected_refused`/`basis=allowlist-grant`/`proxy_stats` を検知側に、deny/既定拒否・SERVFAIL・chain 再評価・grant 失効を停止側に分離して記述。合わせて JA §4.9 の陳腐化した記述（CNAME 末端未解決で grant 不発行→実装は全 chain-target 再評価＋拒否/未カバー/切詰で fail-closed）を [server.rs](../src/dnsgate/server.rs) と整合修正、EN §4.1 のハッシュ検証記述を pin.rs/launch.rs の現実装（Unix は fd/ステージ exec・Windows は share-mode ハンドル保持、遅延ロード名解決は live）に整合修正

**検証:** T-DOC。文書の記述が実装の挙動と一致することを当該PRの検証記録と照合する。

**完了条件:** 限界が全て「無かったこと」でなく仕様として公開され、利用者が自分の脅威モデルに照合できる。

**移行・戻し方:** 開示を弱める変更はしない。実装が限界を解消したら該当記述を「解消済み」に更新する。

<a id="pr-16"></a>

### PR-16 netns プロキシの本番化と能力に応じた方式選択

対応論点: §1.3(c) の本番化、§1.7 の継続評価。直接依存: PR-09（TCP/UDP PoC・要求能力の契約）、PR-13（能力表示）。着手・公開条件: v0.5+、PR-09 の受入条件を満たして採用可能と判断された場合。

**目的:** namespaced を優先し、利用不可なら要求を満たせる範囲で既存 Landlock＋seccomp を使う製品経路にする。UDP の明示許可と、制御できない要求を起動前に拒否する契約を維持する。

**主な変更先:** PR-09 の成果物、[cli](../src/cli)、[launch.rs](../src/runtime/launch.rs)、[enforcement.rs](../src/enforcement.rs)、英日ガイド・[quickstart.md](quickstart.md)。

**タスク**

状態は 2026-10-16 に、merge #67（`330c394`・`7f28243`）のコードと記録から照合しました。未完の分は PR-26 へ繰り越します。

- [x] PR-09 の PoC を製品経路へ統合し、[Linux の方式選択](#linux-egress-selection) の自動選択と明示選択を実装する。CLI/ポリシーの指定方法・優先順位・従来設定の移行を確定し、既定の非特権起動で namespaced を優先する。→ `run`/`plan` に `--linux-mechanism auto|namespaced|native`（既定 `auto`、`src/execution.rs`・`src/cli/parse_run.rs`・`parse_plan.rs`）、選択は `warden::select`（`select_linux_mechanism`/`decide`）。指定は CLI のみで、ポリシー側の指定は設けていない。**残:** Linux `run` の既定が `auto` に変わったことの移行注記と、ポリシー側の指定の要否判断 → PR-26
- [x] 起動前に要求能力と実機の能力を照合する。native で満たせる場合の切り替え、UDP/IP 制御等の不足による起動拒否、明示 namespaced の失敗を区別する。起動前診断と実際のセットアップの結果を照合し、必須制御を `allow_degraded` で省略しない。→ `select.rs` の `native_policy_violations` が要求と能力を照合し、明示 `native` はプローブを省略（`7f28243`）。**残:** `allow_degraded` が選択時の Landlock ABI 検査を緩める点と、ABI 1〜3 で `auto` が native を選び起動時に EACCES になる点 → PR-18（§8.3 F-12）
- [x] 選択方式・利用不可理由・適用するプロトコルと宛先粒度・残る制約を `plan` / `--report` / JSONL に同じ情報源から出力する。native の Landlock ポート制限を IP/CIDR 強制や UDP 対応として表示しない。→ `enforcement/json.rs`・`warden/plan/linux.rs` が同じ選択結果から出力し、拒否時は `linux_selection_refused` を立てる。一致の記録は [linux-namespaced-proxy.md](validation/linux-namespaced-proxy.md) の *PR-16 product integration*。ただし native の AF_UNIX・シグナルについての過大表示は別件 → PR-18（§8.2 F-01）
- [ ] PR-09 の UDP 明示許可を製品のポリシー・継承・生成・export と各実行経路へ反映する。未対応 backend は要求を拒否し、UDP/QUIC を全開放する回避策を作らない。→ **未完。** `proto="udp"` の構文と namespaced の UDP 中継は PR-09 のもの。`generate-policy` は UDP 規則を出さず、ゲスト内 `mcp-secure-runner` は方式選択の無い従来経路（native）のまま → PR-26 へ繰越
- [x] 中断・部分失敗・後始末のライフサイクル契約を製品化し、稼働中の制御喪失時はワークロードを停止する。障害時の native 再起動や直接通信への切り替えを行わない。→ 監査を閉じる前に proxy を停止し、稼働中の proxy 喪失は `SupervisionLost` でワークロードを停止（`src/runtime/wait.rs`）。**未確認:** 通信中の proxy 強制終了は検証文書の未確認一覧に記録 → PR-26 の e2e に含める
- [ ] 手動 CI/証跡収集へ登録する。→ **未完。** 選択の検証は `warden::select` の単体試験と手動脚のみで、`cargo test` のターゲットもワークフロー登録も無い（[test-matrix.md](test-matrix.md) の PR-16 行） → PR-26 へ繰越
- [x] §1.7 残存リスクの継続評価を本番化の受入条件に含める — プロキシ信頼性・DoH/ECH/共有 IP の残存を当該版で再評価して記録する。→ [linux-namespaced-proxy.md](validation/linux-namespaced-proxy.md) の *§1.7 residual-risk re-evaluation (PR-16 acceptance)* に記録

**検証:** T-BASE、T-POLICY、T-NATIVE、T-DOC、PR-09 の実機 e2e と性能基準。選択表の全行を試験し、特に「能力不足でも native で要求を満たす場合の起動」と「UDP 等の必須要求があり拒否する場合」を対にする。正常な既存 MCP ワークロード、起動中の障害、表示・監査の一致、後始末も確認する。

**完了条件:** namespaced 優先・native 条件付き使用・要求不足時の起動拒否が再現可能な製品機能となり、利用者が適用方式と制御範囲を確認できる。共有 IP/DoH 等の限界を開示し、全環境・全通信方式の無条件保証とは表示しない。

**移行・戻し方:** 当該経路だけを無効化できる。native を使う場合も選択表の要求照合・表示・監査を省略しない。namespaced や UDP 宛先別制御が必須の設定は、無効化後も起動拒否とする。

<a id="pr-17"></a>

### PR-17 検証基盤の是正と文書の即時修正

対応論点: §8.3 F-10（文書）、§8.5 F-19・F-20・F-23・F-24、§8.6 F-25・F-27、§8.8 N-01（再発防止）。直接依存: なし。着手・公開条件: P0 — v0.5+ に必須。外部レビュー対応の最初に実施する。

**目的:** 既存の試験が失敗を隠さない状態に戻し、利用者の判断を誤らせる文書を直す。後続 PR の検証の前提になる。

**主な変更先:**

- 試験: `tests/common/mod.rs`、`tests/real_servers_e2e.rs`、`tests/tool_enforcement_e2e.rs`、`tests/diagnostics_e2e.rs`、`src/cli/tests_parse.rs`、`src/fspriv.rs`、`src/dnsgate/allowlist.rs`
- ワークフロー: `.github/workflows/linux-tests.yml`（D-1 の結論によっては新しいワークフローも）
- 文書: README 英日、guide 英日、quickstart 英日

**タスク**

- [x] `real_servers_e2e` のスキップを、前提不足の検査点に限定する。前提不足とは、サーバー・git・mingit が見つからない場合を指す。
  - stage 2/3 の応答欠落と起動失敗は、テストの失敗として扱う。
  - memory/git の stage 5 が「起動失敗を記録として受理」している扱いを見直す。
  - 全段がスキップになった場合も失敗とする。
- [x] CLI の全サブコマンドを、引数なしで parse する単体試験を追加する。`capability-matrix` が「最後に登録する」ことに依存している点を試験で固定する。可能であれば `finish()` への依存をやめる。
- [x] `linux-tests.yml` に、`ci.yml` との差分の試験を登録する。対象は `capability_matrix`・`module_layering`・`manifest_fixtures`・`inspector_*`。`ebpf_e2e` の担当（特権ランナーか手動か）を [test-matrix.md](test-matrix.md) に明記する。
- [x] D-1（改善計画 §8.9）の結論に従い、PR トリガーの最小ジョブか、マージ前の検査スクリプトを追加する。
- [x] root で実行すると失敗する 3 件を、`running_as_root()` で skip する。e2e の 1 件は `skip_e2e_test` を通し、REQUIRE モードでは失敗するようにする。
- [x] `tool_enforcement_e2e` の汚染 tools/list ヘルパーで、応答 id を照合する。
- [x] README と README.ja の `environment` の説明を、既定で制限する現在の実装に合わせる。
- [x] guide 英日の Case C 表を、`deny=#true` に `// REVIEW` を付けた形に直す。ディスパッチャ型（`@server.call_tool()`、`setRequestHandler`）では全ツールが Case C になることを追記する。
- [x] quickstart 英日の symlink 解決ループを、README と同じ `readlink -f` と生成フローにそろえる。

**検証:** T-BASE、T-DOC、`capability_matrix`。サーバーを導入済みの環境で、`MCP_WRIT_REQUIRE_SERVER_TESTS=1` を付けて `real_servers_e2e` を実行する。

**完了条件:** 前提不足以外の理由で「ok」と表示される e2e が無く、CLI の退行を単体試験で検出できる。

**移行・戻し方:** 試験と文書の変更だけで、製品の挙動は変えない。

<a id="pr-18"></a>

### PR-18 Linux ネイティブ経路の AF_UNIX・シグナル封じ込めと適用表示の是正

対応論点: §8.2 F-01、§8.3 F-12、§8.5 F-22、§8.6 F-26、§8.7 F-29、§1.7（ネイティブ経路の IPC 迂回）。直接依存: PR-17。policy 属性の追加は PR-19 の後にマージする。着手・公開条件: P0 — v0.5+ に必須。

**目的:** ネイティブ経路で IPC を使った迂回を閉じ、閉じられない部分を「適用済み」と表示しないようにする。

**主な変更先:**

- warden: `src/warden/landlock_impl.rs`、`seccomp_impl.rs`、`linux_spawn.rs`、`plan/linux.rs`、`select.rs`
- 能力表: `src/enforcement/capability.rs`、`docs/capability-matrix.json`
- policy（opt-in 属性）: `kdl_parse/leaves.rs`、`mod.rs`、`kdl_emit.rs`、`kdl_inherit`
- 試験: `tests/denial_audit_e2e.rs`、`tests/fixtures/denial_audit/kernel_deny_probe.rs`
- 文書: guide 英日、`docs/validation/linux-namespaced-proxy.md`

**タスク**

- [x] 先に脱出試験を書く。
  - `kernel_deny_probe` に、`unix-connect <path>`、`abstract-connect <name>`、`dgram-sendto <path>`、`kill <pid>` の 4 モードを追加する。→ 実装済み（`KDP <mode>=ok`/`errno=<n>` を stderr に出力、EACCES/EPERM で exit 10）。
  - `--linux-mechanism native` を固定して実行し、修正前に 4 種が成立することを再現の証拠として記録する。→ 修正後は `pr18_native_ipc_escape_legs` が 4 脚とも exit 10（カーネル拒否）を確認。修正前の成立は fixture の非 sandbox 実走（ライブ listener への connect 成功経路）で確認。
  - 既存の `denial_audit_e2e` も `native` に固定する。→ `run_kernel_probe`/`run_pr18_probe` が `--linux-mechanism native` を渡す。
- [x] Landlock の対応を追加する。
  - 計測した ABI が 6 以上なら `Scope::AbstractUnixSocket | Scope::Signal` を付ける。BestEffort のまま、要求した権利と適用できた権利を記録する。→ `landlock_impl.rs` が `kernel_abi()` で計測し ABI≥6 で scope を要求、`LandlockBuild.requested_rights`（`fs=… net=… scope=…`）を報告に載せる。`unix="*"` opt-in 時は `AbstractUnixSocket` を意図的に外し、grant 記録で開示。
  - ABI 5 の `IoctlDev` を扱うかを判断する。→ **判断: 扱わない。** `deny` すると許可済み fs ツリー内の `/dev/tty`・ptmx ioctl を失い端末系ワークロードが壊れるため。capability matrix の deficiency と guide §8.4 に記録。
  - ABI 9 以上の `ResolveUnix` の使い方は、D-2 の結論に従う。→ パス指定 `unix=` がある場合のみ `ResolveUnix` を handle し、ソケットの親ディレクトリへ `path_beneath` 規則を追加（ソケット inode は open 不能のため親ディレクトリ粒度と明記）。ABI<9 では選択時に拒否（ファミリを黙って開かない）。
- [x] ネイティブの seccomp を強化する。
  - egress を制限する構成では、`socket()` の family を AF_INET/AF_INET6 に固定し、既存の type 条件と組み合わせる。→ deny-all 下で `stream(AF_INET)+stream(AF_INET6)` 規則に固定。open posture では無ピン（従来通り）。`unix="*"` はファミリ全体、パス指定は AF_UNIX stream のみを再許可。
  - `socketpair` の AF_UNIX+SOCK_DGRAM の遮断を、namespaced と共有する。→ ピン条件下の両経路で共有。`unix="*"` 時は opt-in と矛盾しないよう解放。
  - `kill`・`tgkill`・`pidfd_send_signal` は Landlock のスコープに任せる。ABI が 6 未満の環境では限界として表示する。→ `os.ipc.signal` が ABI<6 で `not_applied` を報告。
- [x] 正当に UNIX ソケットを使うサーバー（docker.sock、PostgreSQL など）のために、opt-in をポリシーに追加する（D-2）。
  - `policy version=2` の属性として登録する。→ `EgressDest::Unix`（`src/policy/mod.rs`）、`kdl_parse/leaves.rs` で `unix=` 受理、`validator.rs::validate_unix_optins` が version=2 未満を拒否。
  - emit の往復、継承、export を通す。→ `kdl_emit.rs` に `unix` arm、継承（`kdl_inherit/overlay.rs`）は `egress_rules` の汎用マージで透過。
  - PSEC・macOS・Windows のように表現できない経路では、起動前に拒否する。→ `validate_unix_optins` が非 Linux ターゲットを読み込み時に拒否、namespaced 経路は `namespaced_policy_violations` で選択時に拒否。
- [x] 表示を是正する。
  - FullyEnforced の理由文を、要求した権利の一覧に変える。→ `requested_rights` を `LinuxSandboxBits`/`ApplySnapshot` 経由で観測へ渡し、`restrict_self reported FullyEnforced …; requested: fs=v1..v3 net=connect_tcp+bind_tcp scope=…` を出力。
  - ABI 6 未満でスコープが付かない場合は、該当する制御を `not_applied` と表示する。→ `os.ipc.unix`/`os.ipc.signal` が ABI<6 で `not_applied`+理由を報告し、`os_limitations` にも同文を出力。
  - `LINUX_NATIVE.deficiencies` に AF_UNIX・抽象ソケット・シグナル・ioctl を追加し、`capability-matrix.json` を再生成する。→ `landlock-abi-v6`/`landlock-abi-v9` optional 要件と deficiency 4 件を追加し JSON 再生成（`capability_matrix` 試験と一致）。
  - `capability.rs:216` の、ネイティブを `run` の既定とする古い注記を直す。→ `auto` が namespaced 利用不可時のみ native を選ぶ旨に修正済み。
- [x] `select.rs` を、起動時の判定とそろえる。
  - 選択時の ABI 検査を、起動時の gate と一致させる。→ ABI 0 → 拒否（`allow_degraded` は宣言済み制御が残る限り救済しない）、ABI 1〜3 → `!allow_degraded` で拒否・`allow_degraded` でも TCP 許可面があれば拒否（必須制御の欠落は容認しない）。
  - `allow_degraded` が選択時の必須制御の検査を緩めている件を、PR-16 の「必須制御を省略しない」方針に合わせて整理する。→ fs/TCP サーフェスの有無で判定する形に整理済み（上記）。
- [x] `compile_post_exec_filter` とその単体試験を削除し、`seccomp_impl.rs` の誤った doc comment（37-40、58-60、66-68 行）を直す。→ 関数と試験を削除し、spawn フィルタの execve 保持実態を正しく記述。
- [x] 文書を直す。
  - guide 英日と検証文書の AF_UNIX の記述を、「Landlock は ABI 9 未満では AF_UNIX の connect を仲介しない」に改める。→ `linux-namespaced-proxy.md` と guide 英日の関連節を修正。
  - guide §8 に、ネイティブ経路の IPC の限界を加える。→ §8.4「Native-route IPC containment（英）/ ネイティブ経路の IPC 封じ込め（日）」を追加。`policy-authoring` 英日にも `unix=` の注記を追加（移行注記を兼ねる）。
- [x] 影響する既存試験を更新する。対象は、`seccomp_impl.rs:996-1010`・`:1034-1045`・`:1066-1072` と、`enforcement` と `plan` の理由文の assertion。→ seccomp の socket/socketpair 試験を新仕様へ更新、select の ABI 試験と plan 観測試験を更新、`plan_report_e2e` の backend 語彙に `namespaced` を追加（namespaced 対応ホストでの環境依存失敗を修正）。

**検証結果（2026-10-16、WSL2 kernel 6.18 / Landlock ABI v7）:** `cargo test --lib` 2251 件、`denial_audit_e2e` 6 件（4 脱出脚 + TCP 陽性対照 + ABI 分岐 kill 脚）、`capability_matrix` 6 件、`plan_report_e2e` 24 件、`real_servers_e2e` 6 件、fmt/clippy クリーン。実機では `unix="/path"` が ABI v9 未満で選択拒否、`unix="*"` が起動後 `KDP unix-connect=ok` を確認。

- 実機は ABI 6 以上と ABI 6 未満の両方が望ましい。片方しか用意できない場合は、もう片方を未確認として記録する。→ **未確認: ABI<6 カーネル。** 本ホストは ABI v7 のため、ABI<6 の `not_applied` 開示はコード経路と単体試験で確認済みだが実機未検証。
- 修正後は 4 種の脱出が拒否されることを確認する。対として、正規の TCP 通信と既存の実サーバーが動くことも確認する。→ 4 脚とも拒否（exit 10）、TCP 陽性対照と real_servers_e2e 通過。
- 脱出試験は root と非 root の両方で実行する。→ 非 root（uid 1000）で実施。**未確認: 実 root**（passwordless sudo 不可）— `unshare -Ur` の user-namespace root で代替確認済み。

**完了条件:** ネイティブ経路で 4 種の脱出が止まる。止まらない条件（ABI 6 未満でのシグナルなど）がある場合は、plan・`--report`・JSONL・capability matrix のすべてで同じ表現で開示される。

**移行・戻し方:**

- UNIX ソケットを使うサーバーは、opt-in の指定が必要になる。リリースノートと guide に移行の注記を書く。
- スコープと family の固定は、それぞれ単独で外せる構造にする。

<a id="pr-19"></a>

### PR-19 KDL 継承マージの不具合修正

対応論点: §8.2 F-02・F-03・F-04、§8.4 F-18。直接依存: なし。着手・公開条件: P0 — v0.5+ に必須。

**目的:** 継承で黙って権限が広がる経路と、設定が落ちる経路を閉じる。継承規則の意味（追加か置換か）は変えず、不具合だけを直す。

**主な変更先:** `src/policy/kdl_inherit/overlay.rs`、`src/policy/kdl_inherit.rs`、`src/policy/kdl_inherit/tests.rs`、`policy.example.kdl`

**タスク**

- [x] 先に回帰試験を書く。 → 新規 `src/policy/kdl_inherit/tests/merge.rs` に 11 件。修正前コードで 9 件が失敗（(a) の許可リスト消失、(b) の defaults への拡大、posture/inbound リセット、include での transport・trajectory rules 消失、`when` の secret-overlay・posture 消失、祖先 version 不検証）することを確認してから実装した。
  - (a) 親で `network { allow host="a" }` を持つツールを、子が `side_effect` だけで再宣言しても、親の許可リストが残る。 → `test_extends_redecl_keeps_tool_network_allowlist`
  - (b) `allow none=#true` を持つツールを、`defaults.filesystem` を持つ子が再宣言しても、defaults のパスまで広がらない。 → `test_extends_redecl_keeps_tool_fs_none`
  - (c) README の quickstart の合成結果を固定する。この例は `filesystem.kdl` を extends して `read_file` を上書きする。 → `test_readme_quickstart_merge_result`（`read_file` は宣言通り `/srv/mcp-data/**`、兄弟ツールは継承の `allow none=#true` を保持）
- [x] ツールの fs/network のマージを、`fs_explicit`/`network_explicit` が真のときだけ行う。`when` の経路と同じ扱いにする。 → `merge_into_policy` のツール fs/network アームを `tool.fs_explicit`/`tool.network_explicit` でゲート。このフラグは tool/profile/server-defaults の宣言時のみ立ち、グローバル `defaults` のマテリアライズでは立たないため「宣言されたか」の判別にそのまま使える。
- [x] `when` で `secret-overlay` を反映する。 → `apply_overrides_from_doc` が `defaults.filesystem` 宣言を含むマッチ時に `policy.fs.secret_overlay` を適用（省略時は既定の `#true` — fail-secure）。`test_when_secret_overlay_applies` で固定。
- [x] include で、取り込むファイルの祖先や `when` に由来する値が失われる件を直す。「そのファイルにノードがあるか」ではなく、合成済みの値で判断する。 → `OverlayDecl` を新設し、再帰ローダ（`load_kdl_policy_recursive_with_decl`）が `(Policy, OverlayDecl)` を返す。decl は extends 祖先・include・自ファイル・マッチした `when`（`apply_when_overrides` が decl を返す）の宣言を集約し、include 側のマージ判定はその集約で行う — transport/sandbox/logging/`confused_deputy_protection`/trajectory(+rules)/`defaults.filesystem`(secret-overlay)/`defaults.network`(posture/inbound)。`test_include_propagates_ancestor_declared_fields`・`test_include_propagates_when_derived_fields` で固定。
- [x] extends で、子が `defaults.network` を宣言しただけで posture と inbound がリセットされる件を直す。
  - 子が明示したときだけ変更する。 → posture は裸の `allow host="*"`/`deny host="*"` 宣言時のみ（`declares_network_posture` — `proto=`/`port=` 付きは scoped rule で posture ではない、パーサの判定と同条件）、inbound は `inbound` 子ノード宣言時のみ。`test_extends_network_posture_and_inbound_{inherit,override}`・`test_when_network_posture_only_moves_when_declared` で固定。
  - inbound を継承するようにすると、許可が広がる方向の変更になる。警告を出すか版で切り替えるかを判断し、PR 本文に記録する。 → **警告を採用**。版ゲートは v1/v2 が同一 grammar を共有しており切り分け不能のため。`defaults.network` を再宣言しつつ `inbound` を書かない側が、継承中の `inbound allow=#true` を保持する場合、ロード時にファイル名入りの stderr 警告を出す（`warn_inherited_inbound`。extends・include・マッチした `when` の 3 経路）。
- [x] 祖先ファイルの `policy version` を検証し、未知の版は拒否する。これは PR-28 の前提になる。 → `load_kdl_policy_recursive_with_decl` が各ファイルの parse 直後に `MIN_SUPPORTED_VERSION..=MAX_SUPPORTED_VERSION` を検査し、ファイル名入りで拒否（`unsupported policy version 99, expected 1..=2 in 'base.kdl'`）。`test_extends_rejects_unknown_ancestor_version`・`test_include_rejects_unknown_included_version` で固定。
- [x] `overlay.rs:35-36` の冒頭コメントを実装に合わせる。`policy.example.kdl:101-108` の壊れた例を直す。 → `merge_into_policy` の doc コメントを宣言ベース判定と posture/inbound ゲート込みの記述に書き換え。example の `protocol="https"`（文法に存在しないプロパティ）は `proto="tcp" port=443` に修正。
- [x] レビュー指摘対応（設計意図「include は subtree の実効宣言をそのまま取り込む」を確認のうえ、弱化方向は警告で可視化）。 → 各マージ適用前に `SecurityPosture::capture` で fail-secure 設定をスナップショットし、弱化があれば `(path, WeakenedPosture)` を遅延記録。対象は `confused_deputy_protection` 解除・`trajectory` 解除/ルール欠落・既定以外に選んだ `logging level` の変更・`fail_closed` 解除・`sandbox allow_degraded` 許可・`secret-overlay` 解除・外向き posture 開放・`inbound` リスナ許可・`environment` 制限解除/allow 拡大。警告はファイル処理末尾で最終状態に再評価して発火 — 後続の宣言が復帰・閉鎖した場合は出さない（inbound 警告も同じ遅延枠組みに移し、従来の「include が自ファイル doc より先に処理される」順序依存の偽陽性を解消）。tool `syscalls` マージは `syscalls_explicit` でゲート（fs/network と同型 — 非宣言ツールの materialized defaults がベースの値を置換しえた）。`defaults { network }`（子なし）で `decl.network` が立たないよう `absorb_shared` を children 必須に修正。`?` 早期 return で `visited` に残る問題は、再帰を `load_kdl_policy_recursive_with_decl`（visited 管理）/ `load_kdl_policy_subtree`（本体）に分離して修正。`test_merge_tool_syscalls_gated_on_explicit`・`test_security_posture_*` 4 件を追加（計 15 件）。

**検証:** T-BASE、T-POLICY。 → 実施済み。`cargo fmt --all -- --check` パス、`cargo clippy --locked --all-targets -- -D warnings` パス、`cargo test --locked --lib --bins` 2269/2269、`cargo test --locked --doc` 0 件、`kdl_inherit` 107/107（新規 15 件含む）。T-POLICY: `environment_e2e` 6/6、`go_runtime_policy` 7/7、`kdl_policy_e2e` 19/19。

**完了条件:** 継承の結果が、親で明示したツールのスコープより広がらない。祖先や `when` の値が include で失われない。

**移行・戻し方:** 不具合の修正だが、合成結果が変わるポリシーはありうる（特にツールを再宣言する子ファイル）。変化の例を PR 本文に示す。

<a id="pr-20"></a>

### PR-20 Auditor のフレーム上限の設定化と要求単位の失敗処理

対応論点: §8.3 F-05、§8.7 F-31。直接依存: なし。着手・公開条件: P0 — v0.5+ に必須。

**目的:** 大きな正常応答でセッションが落ちないようにし、上限を超えた場合も、失敗をその要求だけに留める。

**主な変更先:**

- フレーム処理: `src/framing.rs`、`src/auditor/proxy_wire.rs`・`proxy_s2c.rs`・`proxy_c2s.rs`・`proxy.rs`
- 設定の受け渡し: `src/cli/parse_run.rs`、`src/bin/mcp-secure-runner.rs`（コンテナやサンドボックスへの受け渡しを含む）
- 文書: guide 英日

**タスク**

- [x] 上限を設定できるようにする（`--max-frame-bytes`）。
  - `ProxyShared` を通して読み取り処理に渡す。既定値は D-3 の結論に従う。
    → `RunArgs`/`RunImageArgs` に `Option<usize>` として追加（0・非数値・値なしは拒否）。`LaunchConfig.max_frame_bytes` → `Auditor::with_max_frame_bytes` → `run_proxy` → `ProxyShared.max_frame_bytes` で両方向の読み取りへ渡る。既定値は `framing::DEFAULT_MAX_FRAME_BYTES = 10 MiB`（D-3 / TS SDK と同値）。`run --isolation windows-sandbox` は `SandboxRunOptions` → `MCP_WRIT_MAX_FRAME_BYTES` → relay-config `max_frame_bytes=` → WSB agent が runner 環境へ設定。`run-image` は `RunImageOptions` → `spec.env` の同変数で runner へ。イメージに焼き込まれた `MCP_WRIT_MAX_FRAME_BYTES` は各バックエンドのクリアリスト（engine/oci/apple/dockerfile `CHANNEL_CLEAR_ENVS`）と runner 冒頭の `remove_var` で消し、ホスト指定値だけが効く。runner 側は値を検証し、不正値は既定へ黙って戻さず起動失敗とする
  - 他の上限との関係を整理する。対象は tools/list の 8 MiB、監査のフィールド上限、WSB relay のチャンク。
    → 整理を英日ガイドの Auditor 節に明記: フレーム上限は 1 行のバイト数のみを縛り、tools/list の帳簿上限（クライアント元要求の保持 8 MiB `MAX_ORIGINAL_TOOLS_LIST_BYTES`、組み立てページ合計 16 MiB `MAX_LIST_PAGE_BYTES`）、監査フィールドの 1 KiB 切り詰め、WSB relay の 1 MiB チャンク分割（伝送上の分割でありメッセージ上限ではない — 1 行が複数チャンクに跨る）とは独立。上限を上げると上限内フレームは全体をバッファするため 1 フレームあたりのメモリ上限も上がる旨も記載
- [x] framing に、上限を超えた行を次の改行まで読み捨てて継続できる API を用意する。`TooLarge` の文言も直す。
  → `read_frame_bounded` / `BoundedFrame::{Line, Oversize}` / `OversizeFrame{head, tail, bytes, terminated}` を新設。超過フレームは改行（または EOF）まで境界を保ったままドレインし、先頭・末尾各 8 KiB のウィンドウと総バイト数のみ保持するため次フレームは正常に読める。`TooLarge` は `JSON-RPC frame exceeds the {limit}-byte limit ({bytes} bytes)` に修正（`read_line_bounded` は従来どおり致命的扱いにする互換ラッパ）
- [x] サーバー→クライアントで上限を超えた応答を処理する。
  - 先頭と末尾の有界バッファから id を回収する。TS SDK は id を末尾に置く。
    → `recover_id_candidates`（応答は末尾優先、要求は先頭優先）と `recover_method` を `proxy_wire` に追加。候補は `WireState` の追跡表に照合してから信頼する（ネストした `result.id` 等は in-flight 要求に解決しない限り無視）
  - 回収した id 宛てに JSON-RPC エラーを返し、追跡エントリを解放する。
    → 解決した id は `wire.take` で消費し、tools/call なら trajectory pending + Confused Deputy pending を解放、tools/list なら pending/original/collection/busy ゲートを巻き戻してからクライアントへ `-32001` エラーを返す。途中の内部 pagination 要求の wire 登録も退役させる
  - id を回収できない場合の扱い（セッションを終了するか、`id:null` で返すか）を決める。
    → `id: null` のエラーを返してセッション継続（JSON-RPC の「要求を名指せないエラー」慣習）。method が回収できた場合はサーバー要求/通知として扱い、2025 はサーバーへエラーを返し、2026（S2C 要求は版違反）はドロップ。唯一セッションを終了するのは Auditor 自身の内部 `tools/list`（pagination / list_changed 再検証）への超過応答 — 検証済みリストを生成できないため他の内部応答拒否と同じく abort し、理由は監査に残る
- [x] クライアント→サーバーで上限を超えた要求には、クライアントへエラーを返し、サーバーへは送らない。
  → `c2s_oversize`: 回収 method/id で要求なら回収 id 宛てに `-32001`、通知なら応答なしでドロップ、応答（method 無し）なら追跡済み S2C 要求のエントリを解放してサーバーへエラー（2026 では応答生成しない）。`--dry-run` でも転送しない — フレーム本体はドレインで捨てられ手元に残らないため
- [x] 超過を監査に記録する（例: `mcp_message.denied`、`reason=frame-too-large`）。`--report` と stderr の内容とそろえる。
  → `DenyReason::FrameTooLarge`（`"frame-too-large"`）を追加し、両方向とも `audit_decision` で `forwarded=false` の `mcp_message.denied` を記録。`details` に `frame_bytes=<n>`・`frame_limit=<n>`（EOF 終了なら `unterminated` も）を含める。監査不可は既存どおり fail-closed。レポート/stderr には別経路を増やさず、診断表の行で「stdout フレーム＋監査ログ」として記載
- [x] クライアント→サーバーの読み取りを、サーバー→クライアントと同じ peek 方式にそろえる。`fail_watch` が発火しても、読みかけの行が失われないようにする。
  → 両ループとも `tokio::select!` で `fill_buf` のみ待ち、バッファに入力があればフレーム読み取り（超過ドレインを含む）を中断不能で完走する形に統一 — watch の変化が読みかけの行を失わせない
- [x] guide 英日に、上限・設定方法・超過時の挙動を書き、診断表に行を追加する。
  → `run`/`run-image` のオプション表に `--max-frame-bytes`、Auditor 節にフレーム上限の箇条書き（挙動・dry-run・内部応答の例外・他上限との関係・メモリ）、`mcp_message.denied` の理由列挙に `frame-too-large`、診断表に超過拒否行を追加（英日双方）

**検証:** T-BASE、T-PROTOCOL。次の 4 点を確認する。

- 2 MiB 程度の正常応答が通る。
- 上限を超えた応答では、エラーが返ってセッションが続く。
- 上限を超えた要求が拒否される。
- id が末尾にある JSON から id を回収できる。

**検証で発見・修正した既存不具合（PR-20 以前から存在）:**

- 内部 `tools/list`（`initialize` 直後のプローブ、`list_changed` 再検証）が検証失敗や拒否で abort する際、その裏に同居していたクライアント要求が `id:null` のエラーか無回答で落ちる輸送中レースがあった。`internal_list_failure`（S2C が理由を記録）+ C2S abort ドレイン（held スロットとパイプ内の輸送中 `tools/list` を走査して元の id で拒否を返す。要求が無ければ `id:null` で abort を可視化）で決定的に解消。`run_proxy` は S2C 失敗後に C2S を bounded（250ms）で駆動してドレインを完了させる。内部 listing に対応する abort 経路（検証失敗・登録拒否・応答拒否・oversize・S2C EOF）で同じ記録を立てる
- Windows での `integration`/`tool_enforcement_e2e`/`manifest_fixtures` の失敗: テストポリシーの POSIX パス atom（`/home/*/.ssh/**`、`/workspace/**`）が `D:\` に drive-qualify され、broad-replace ACL のルートに対する意図どおりの fail-closed 拒否で落ちていた。パス強化を緩めず、テストハーネス側に `MCP_WRIT_ALLOW_REPLACEABLE_PATHS=1` を設定してホスト ACL 非依存にした（拒否判定自体の網羅は fspriv/pathutil の単体テストに残る）

**完了条件:** 上限の超過でセッションが終了しない。終了させる設計を選んだ場合でも、終了理由が監査に残る。

**移行・戻し方:** 既定値を上げる場合は、1 フレームあたりのメモリ使用の上限が変わることを明記する。

<a id="pr-21"></a>

### PR-21 `args_schema` の対応拡充と生成ドラフトの整合

対応論点: §8.3 F-06・F-10（ドラフト）。直接依存: なし。着手・公開条件: P0 — v0.5+ に必須。

**目的:** 公式サーバーのスキーマを写したドラフトを、そのまま使えるようにする。使えない場合は、呼び出し時ではなくロード時に分かるようにする。

**主な変更先:**

- 検証: `src/auditor/schema_validator.rs`、`src/auditor/checker.rs`、`src/policy/validator.rs`
- 生成: `src/legislator/policy_generator.rs`
- 文書: policy-authoring 英日、guide 英日

**タスク**

- [x] validator にキーワードを追加する。
  - 対象: `anyOf`・`oneOf`・`allOf`・`const`・`minItems`・`maxItems`・`uniqueItems`・`multipleOf`、配列形式の `type`。真偽値スキーマ（`true`/`false`）も受理。
  - `format` は、2020-12 の既定どおり注釈として扱い、検証しない。
  - 同一文書内（`$defs`）の `$ref` をどう扱うかを決める — `#` / `#/…` の同一文書参照のみ解決し（`$defs`・`definitions` を含む JSON ポインタ歩行）、外部参照は拒否。循環は深さ上限で停止する。
  - 深さと組み合わせ評価に上限を設ける。Auditor のパース処理のバグは、そのまま迂回経路になる（review1）— `MAX_SCHEMA_DEPTH=64`（`src/schema_spec.rs` で共有）と `MAX_BRANCH_EVALS`（分岐評価回数）、`multipleOf` の筆算コスト上限を設けた。
- [x] ロード時に全ツールの `args_schema` を走査し、非対応のキーワードを検出する。v2 では拒否し、v1 では警告にする — 判断: v2 は対応サブセットを保証する版付き契約なのでロード拒否、v1 は評価器の呼び出し時ガードが fail-closed で拒否するため警告付きロード継続とした（`validate_args_schemas`、policy-authoring/guide 英日に記録）。層制約のため走査は層0の `src/schema_spec.rs` に置く。
- [x] `tools/call` で `arguments` が省略された場合は、`{}` とみなす（MCP 仕様どおり）。
- [x] 生成ドラフトを整える。
  - 非対応のキーワードが残るスキーマは、`args_schema` を省略して `// REVIEW` を付ける。
  - 全ツールが Case C になったドラフトの先頭には、「N/N のツールに根拠がない」と注記し、例示ポリシーを案内する — 能力根拠（判定）のないエントリのみで構成されるドラフトに `// NOTE: N/N tools ... carry no capability grounding` を出力し、`examples/policies/` を案内する。Case B の deny は判定済みとして対象外。
- [x] 試験を更新する。
  - `test_f15_unsupported_keywords_rejected` の対象を、引き続き非対応のキーワードに差し替える — `patternProperties` を検査する形に変更。
  - 実サーバーのスキーマ（git の pydantic `anyOf`、filesystem の `minItems`、fetch の `format`）を fixture にして単体試験を書く — `test_real_git_server_schema`・`test_real_filesystem_server_schema`・`test_real_fetch_server_schema`。
- [x] 対応するキーワードの一覧と、`format` の扱いを文書に書く — policy-authoring 英日の「引数の形式を制限する」節と guide 英日の `args_schema` 行に記載。生成ドラフトの省略 + REVIEW・全 Case C 注記も policy-authoring の草案チェック節に記録。

**実施記録（2026-10-17・Windows ホスト・WSL2・x86-64・rustc 1.99.0）:** T-BASE（fmt / clippy `-D warnings` / lib+bins 2175 件 / doc / doc-test 0 件）・T-LAYER（16 件）・T-DOC（11 件）・T-POLICY（kdl_policy_e2e 19・environment_e2e 6・go_runtime_policy 7）・T-PROTOCOL（integration 12・manifest_fixtures 7・protocol_versions 5・tool_enforcement_e2e 30）全 pass。`cargo doc` は既存クラスの private-item link 警告 4 件。kdl_policy_e2e の POSIX パス経路試験は当該 Windows ホストの `D:\` ルートが replaceable-component 検査に触れるため `MCP_WRIT_ALLOW_REPLACEABLE_PATHS=1`（WSLENV 経由）で実施 — 環境依存で PR-21 とは無関係。

**検証:** T-BASE、T-POLICY、T-PROTOCOL。

**完了条件:** 公式 4 サーバーと fetch のスキーマを写したドラフトで、正当な呼び出しが schema で拒否されない。省略可能な引数を渡す呼び出しも含む。

**移行・戻し方:** v2 でロード時の検査が拒否するようになるポリシーには、エラーメッセージで該当するツールとキーワードを示す。

<a id="pr-22"></a>

### PR-22 マニフェスト規則の誤検知是正と公開サーバーの回帰コーパス

対応論点: §8.3 F-07・F-08。直接依存: なし。着手・公開条件: P0 — v0.5+ に必須。

**目的:** 公式サーバーが既定の設定のままでも中断されない状態にし、規則を変えたときに、公開サーバーの実データで回帰を確かめられるようにする。

**主な変更先:**

- 規則と試験: `src/verifier/manifest_rules.rs`、`src/verifier/manifest/tests.rs`、`tests/manifest_fixtures.rs`
- 新規: `tests/fixtures/` のコーパス、`scripts/` の取得スクリプト
- 文書: guide 英日

**タスク**

- [x] CC-011 を直す。
  - `openWorldHint` が明示的に `true` のときは、ネットワーク系のキーを矛盾として扱わない。
  - 型が不正な場合は、従来どおり fail-closed にする。
  - `manifest/tests.rs:516-522` を、`openWorldHint` がある場合とない場合の対にする。
- [x] 公開サーバーの tools/list スナップショットを集めたコーパスを作る。
  - 対象は公式の reference servers（filesystem・memory・time・git・fetch・everything・sequential-thinking など）と、利用の多いサーバー数件。
  - 取得スクリプトと、取得日・版を記録する。
  - ツール説明文は各プロジェクトの著作物なので、ライセンスを確認する。
- [x] コーパスに全 CC 規則をかけ、High 以上が出ないことを `manifest_fixtures` で回帰させる。
  - High 以上が出たものは個別に妥当性を判断し、妥当なものは期待値として固定する。
  - CC-003・005・007・009・010 で誤検知が出た場合は、規則ごとに直す。
- [x] 拒否したツールの説明文でもセッション全体が止まる現在の挙動を、文書に書く。ツール単位の免除を設けるかは D-6 で判断する。
- [x] guide に、CC-011 が見るキーの一覧と `openWorldHint` の扱いを書く。

**実施記録（2026-10-17・Windows ホスト・WSL2・x86-64・rustc 1.99.0）:** T-BASE（fmt / clippy `-D warnings` / lib+bins 2349 件 / doc / doc-test 0 件）・T-PROTOCOL（integration 12・manifest_fixtures 8・protocol_versions 6・tool_enforcement_e2e 30）・T-DOC（12 件）全 pass。`cargo doc` は既存クラスの private-item link 警告 4 件。コーパスは公式 7 件 + playwright / chrome-devtools の計 9 サーバー・109 ツールで全 CC 規則クリーン（`expected-findings.json` 全件空）。旧 CC-011 判定への一時巻き戻しで fetch に CC-011 High が出て回帰試験が落ちることを確認済み（F-07 再現 → 修正で消滅）。`mcp-server-fetch` は `openWorldHint=True` を持つ 2026.10.10 を取得。

**検証:** T-BASE、T-PROTOCOL。

**完了条件:** コーパスの全件で、High 以上の検出が「期待値として説明できるもの」だけになる。

**移行・戻し方:** 判定を緩める方向の変更（CC-011）で、tools-list-hash は変わらない。

<a id="pr-23"></a>

### PR-23 未対応プロトコル版の診断

対応論点: §8.3 F-09。直接依存: PR-20（`proxy_s2c.rs` が重なるため）。着手・公開条件: P1 — v0.5+ に含める範囲をリリース時に判断。

**目的:** 未対応のプロトコル版で失敗したときに、原因が利用者に伝わるようにする。

**主な変更先:** `src/auditor/proxy_s2c.rs`、`proxy_rpc.rs`、`tests/fixtures/mcp_servers/scripted_stdio.py`、guide 英日（理由コード）

**タスク**

- [ ] クライアントへのエラー文に、交渉された版と対応している版を含める。stderr にも 1 行出す。
- [ ] 監査の details に、サーバーが返した `protocolVersion` を記録する。誤解を招く `version=` の表記も直す。
- [ ] 失敗後にセッションを続けるか終了するかを決める。`DenyReason` を追加する場合は、理由コードの文書も更新する。
- [ ] scripted fixture に版を指定するモードを足し、`run` 側の e2e を 2 通り書く。1 つはサーバーが古い版で応答する場合、もう 1 つはクライアントが古い版を要求する場合。
- [ ] 古い版（`2025-06-18`）に対応するかどうかは、D-4 の判断として記録する。

**検証:** T-BASE、T-PROTOCOL。

**完了条件:** 未対応の版で失敗したとき、クライアントのエラー・stderr・監査ログの 3 つで、原因（交渉された版と対応版）が同じように読める。

**移行・戻し方:** 診断の追加だけで、判定は変えない。

<a id="pr-24"></a>

### PR-24 合成ポリシーの可視化と、継承規則の警告・スキーマ厳格化

対応論点: §8.4 F-13〜F-17。直接依存: PR-19。着手・公開条件: P1 — v0.5+ に含める範囲をリリース時に判断。

**目的:** 最終的に効くポリシーと、各行の出所を確認できるようにする。置換や無視が起きたときは、読み込み時に知らせる。既存の継承規則の意味は変えない。

**主な変更先:**

- コマンド: `src/cli`、`src/commands`（新規）
- ポリシー: `src/policy/kdl_inherit`、`src/policy/merge.rs`、`src/policy/kdl_parse.rs`、`kdl_parse/servers.rs`、`src/policy/review.rs`（診断の出し口）
- plan の検査: `src/warden/plan/linux.rs`
- 文書と例: policy-authoring 英日、`examples/policies/runtime/*.kdl`

**タスク**

- [ ] `mcp-writ policy resolve`（仮称）を追加する。
  - 合成後の KDL を、既存の `to_kdl` で出力する。
  - 出所の記録器（ファイル、ノード位置、操作の種類 set/union/replace/prune）を、継承ローダ・merge・overlay・`parse_servers` に通す。
  - `--env`・`--server` の指定と、JSON 出力に対応する。
- [ ] 置換が起きたら警告する。
  - 対象: syscalls、network の allow、ツールの fs/network、profile の上書き。
  - 形式は「base.kdl の N 件を child.kdl が置換」。plan と check の JSON にも載せる。
  - REVIEW と同じく warn/refuse/off で切り替えられるようにするかを検討する。
- [ ] execve が不足したときのエラーに、置き換えたファイルを示す。plan でも同じ検査を行い、「plan は通るのに run で落ちる」食い違いをなくす。
- [ ] `profile`/`profiles` に複数の引数・非文字列・属性を書いた場合、v2 では拒否し、v1 では警告する。構文を文書化する。
- [ ] 未知のノードや重複したノードを、v2 では拒否し、v1 では警告する。
  - `defaults` の子、top-level、`profile`/`server-defaults` の子
  - `when` の属性、`extends`/`include` の余分な引数、2 つ目の `extends`
  - 未知の transport
- [ ] policy-authoring 英日に、フィールドごとのマージ規則表を追加する。改善計画 §8 の照合で作った表を下書きにする。
- [ ] `runtime/node.kdl`・`python.kdl` の「Extend it from runtime evidence」を、置換の規則が分かる文に改める。

**検証:** T-BASE、T-POLICY、T-DOC。

**完了条件:** 合成結果と出所を 1 つのコマンドで確認でき、置換や無視が黙って起きない。

**移行・戻し方:** v2 では、誤記のあるポリシーが読み込めなくなる場合がある。誤記をエラーで知らせることがこの変更の目的なので、メッセージで該当箇所を示す。

<a id="pr-25"></a>

### PR-25 実サーバーの通し試験（生成→run、省略可能な引数、fetch）

対応論点: §8.5 F-21、§8.8 N-13。直接依存: PR-17、PR-21、PR-22。着手・公開条件: P1 — v0.5+ に含める範囲をリリース時に判断。

**目的:** 生成→レビュー→`run` という利用者の流れを、実サーバーで通しで試験する。

**主な変更先:** `tests/real_servers_e2e.rs`、`tests/fixtures/real_servers/`、`requirements.txt`、`examples/policies/`（fetch を追加）、`.github/workflows/mcp-servers.yml`

**タスク**

- [ ] `generate-policy --live-discovery` で作ったドラフトに、ホスト側の許可を足して `run` する（dry-run と本実行の両方）。レビュー工程は、指定したツールの deny を外す操作で模擬する。
- [ ] 省略可能な引数を含めて呼び出す。
  - git: `git_log` に `max_count` とタイムスタンプを渡し、他の git ツールも呼ぶ。
  - filesystem: `read_multiple_files` と、PR-20 の上限付近の大きなファイルを試す。
- [ ] fetch を試験対象に加える。fetch は外部へ通信するので、ローカルの HTTP サーバー宛てにする。
- [ ] 固定版を更新し、npm で非推奨になっていないか確認する。

**検証:** `MCP_WRIT_REQUIRE_SERVER_TESTS=1` を付け、`mcp-servers.yml` の 3 OS で実行する。

**完了条件:** 生成→レビュー→`run` の流れが、公式 4 サーバーと fetch で通る。

**移行・戻し方:** 試験の追加だけで、製品の挙動は変えない。

<a id="pr-26"></a>

### PR-26 PR-16 の残作業

対応論点: §8.6 F-28（PR-16 タスク 4・6 の繰越）。直接依存: PR-18（`select.rs` が重なるため）。着手・公開条件: P1 — v0.5+ に含める範囲をリリース時に判断。ただし PR-16 を v0.5+ に含める場合、本 PR のタスク 4・6 は PR-16 の完了条件に属する。

**目的:** PR-16 の未完タスクを終え、PR-16 の完了条件を満たす。

**主な変更先:** `src/legislator`、`src/container/policy_export.rs`、`src/bin/mcp-secure-runner.rs`、`tests/`（新規）、`.github/workflows/linux-tests.yml`、guide 英日、quickstart 英日、本書の PR-16 節

**タスク**

- [ ] PR-16 タスク 4: UDP の許可を、生成・export・コンテナ経路に反映する。ゲスト内の runner は方式選択の無い従来経路（native）で動くため、UDP の許可を拒否するかを決める。
- [ ] PR-16 タスク 6: `tests/linux_mechanism_e2e.rs`（`MCP_WRIT_REQUIRE_E2E_TESTS` 対象）を作り、`linux-tests.yml` と [test-matrix.md](test-matrix.md) に登録する。検証文書の未確認一覧にある「通信中の proxy 強制終了」もこの e2e に含める。
- [ ] Linux の `run` の既定が `auto` に変わったことについて、移行の注記を guide と quickstart に書く。方式をポリシー側でも指定できるようにするかを判断する。
- [ ] 完了したら、本書の PR-16 節のタスク 4・6 にチェックを付ける。
- [ ] 任意: capability matrix に成熟度（stable / opt-in PoC）を加える（review1 の「安定版の境界を絞る」提案）。

**検証:** T-BASE、T-DOC と、Linux 実機での `linux_mechanism_e2e`。

**完了条件:** PR-16 の全タスクにチェックが付き、PR-16 の完了条件を満たす。

**移行・戻し方:** 試験・文書・記録が中心。UDP の扱いで判定が変わる場合は、PR 本文に記録する。

<a id="release-v0-5"></a>

### リリース: v0.5+ — PR-14〜16 と PR-17〜22 の完了後（PR-23〜26 は含める範囲を判断）

実装PRではなく、ここに到達した時点で確認する条件と手順です。バージョン更新・タグ付け・リリース実行は git／リリース操作のため、実施は別途指示を受けてから行います。

**到達条件 — 全て満たしたらバージョンを上げる**

- [ ] PR-14〜16 のうち当該リリースに含める範囲がマージ済み
- [ ] PR-17〜22（改善計画 §8 の P0）が全てマージ済み
- [ ] PR-23〜26（§8 の P1）のうち当該リリースに含める範囲を決め、マージ済み。PR-16 を含める場合は PR-26 のタスク 4・6 も完了している
- [ ] 判断事項 D-1〜D-6（§8.9）のうち、含める PR に関わるものの結論が記録されている
- [ ] 含める項目が確定した時点で版番号（`0.5.0` かそれ以降か）を決めた
- [ ] PR-15 の限界開示を含める場合、その記述が実装挙動と照合済み。PR-18 の IPC 限界の開示も同様

**バージョン更新の手順**

- [ ] [Cargo.toml](../Cargo.toml) の `version` を確定した版に更新し、`Cargo.lock` を再生成する
- [ ] 最新コミットで T-BASE・T-DOC・該当する実機記録を再確認する
- [ ] タグ `vX.Y.Z` を付ける — タグ push が [release.yml](../.github/workflows/release.yml) の起点（ci・platform-tests・container-tests・go-runtime の verify を通る）
- [ ] リリースノートに「この版で保証する制御」と「残る限界」（§1.7・§5.2 の対応状況）を明記する

<a id="pr-27"></a>

### PR-27 監査ログの再オープンと、容量が尽きたときの扱い

対応論点: §8.3 F-11。直接依存: なし。着手・公開条件: P2 — 次版以降。

**目的:** 外部のローテーションと共存できるようにし、容量が尽きたときの挙動を仕様として明示する。

**主な変更先:** `src/audit_log.rs`、`src/audit_log/sink_open.rs`、`src/runtime/wait.rs`（シグナルの扱い）、guide 英日

**タスク**

- [ ] シグナルで監査ログを開き直し、`audit.reopened` を記録する。
  - SIGHUP は PoC 系コマンドで終了扱い（129）なので、使うシグナルと `run` 側の扱いを整理する。
  - 開き直す前に flush と fsync を行う。
- [ ] 起動時に空き容量を検査するか、`logging max_size=` を設けるかを判断する。
- [ ] 容量が尽きたときの挙動を guide に書く。fail-closed で中断する、空きを作っても復帰しない、行が途中で切れることがある、の 3 点。あわせて `copytruncate` を推奨し、別の uid で作り直すと次の起動を拒否することも書く。

**検証:** T-BASE。開き直したあとの記録が新しいファイルへ続くことと、容量が尽きたときの中断を fixture で確認する。

**完了条件:** logrotate と共存でき、容量が尽きたときの挙動が文書から読める。

**移行・戻し方:** 開き直しの経路を足すだけで、既存の記録経路と fail-closed の契約は変えない。

<a id="pr-28"></a>

### PR-28 ポリシー v3 — 既定は追加、置換は明示、複数 profile

対応論点: §8.4 F-13・F-14・F-15 の根本対策（review2 の改善方向 2・3）。直接依存: PR-19（祖先の版の検証）、PR-24（`policy resolve` で差分を確認できること）。着手・公開条件: P2 — 次版以降。D-5 の判断で着手を決める。

**目的:** 継承の規則を「既定は追加、置換は明示」にそろえる。既存ポリシーの意味が変わるため、`policy version=3` で切り替える。

**主な変更先:** `src/policy/kdl_inherit`、`src/policy/merge.rs`、`src/policy/kdl_parse`、`src/policy/validator.rs`、policy-authoring 英日

**タスク**

- [ ] `policy version=3` で、syscalls・network も和集合にし、置き換えたいときだけ `replace=#true` を書く形にする。
- [ ] syscalls を和集合にすると、狭める手段が無くなる。defaults の階層に `deny` を設ける。
- [ ] 複数の profile を、和集合として合成する。profile とツール自身の記述も足し算にする。
- [ ] v2 から v3 への変換で合成結果が変わる箇所を、`policy resolve` の差分で示す。

**検証:** T-BASE、T-POLICY、T-DOC。同じポリシーを v2 と v3 で読み、差が仕様どおりであることを確かめる。

**完了条件:** v3 では、子で足した許可が親の許可を含む（review3 の不変条件）。

**移行・戻し方:** v2 の意味は変えない。v3 を読めない旧版のバイナリは、PR-19 の祖先の版の検証で拒否するため、黙って v2 の規則で読むことはない。

<a id="pr-29"></a>

### PR-29 unsafe の Safety 注記と lint

対応論点: §8.7 F-30。直接依存: PR-18、PR-26。着手・公開条件: P2 — 次版以降。

**目的:** unsafe ブロックの前提を注記で読めるようにし、新しい unsafe に注記が無ければ lint で止める。

**主な変更先:** `src/warden`（まず `namespaced`）、lint の設定

**タスク**

- [ ] `clippy::undocumented_unsafe_blocks` を、境界のモジュール（`warden::namespaced` など）から順に deny にする。
- [ ] 不足している Safety の注記を足す。

**検証:** T-BASE。

**完了条件:** lint の対象にしたモジュールで、注記の無い unsafe ブロックが無い。

**移行・戻し方:** 挙動は変えない。

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
