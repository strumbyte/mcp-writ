# 改善計画 — 評価メモ (2026-10-07) 対応版

対象: v0.2.0 / tip `562ea185`。評価メモ (`mcp-writ-eval-2026-10-07.html`) の
指摘と今後提言を、コード実測と突き合わせて計画化したもの。

PR 単位の作業順序は [improvement-pr-guide-2026-10.ja.md](improvement-pr-guide-2026-10.ja.md) を参照。

方針更新: 2026-10-10 — Linux は名前空間＋プロキシを優先し、要求を満たせる場合に限り既存の Landlock＋seccomp 経路を使用する（§1.3）。

方針更新: 2026-10-16 — 外部レビュー 5 件への対応を §8 として追加し、その P0 を v0.5+ の範囲に含める（§6）。

設計原則（レポートと同じ）:

- 通信の**中身は見ない**。制御するのは**宛先**だけ（制御面の延長）
- 宛先制御は **ドメイン層（DNS ゲート/名前ポリシー）+ IP 層（TCP 接続・UDP 送信時の強制）**
  の 2 層。CIDR だけでも FQDN だけでも成立しない
- 非保証・限界は隠さず仕様として開示する
- 監査に残らない挙動（バイパス・スキップ・ダイヤル低下）は「無かったこと」
  にしない

---

## 0. 現状の突き合わせ（コード確認済み）

| 指摘 | 実態 | 根拠 |
|---|---|---|
| `sandbox.*_denied` が死に定義 | `SandboxFileDenied`/`SandboxNetworkDenied`/`SandboxProcessDenied` は enum 定義のみ、emit 箇所なし | `src/audit_log.rs:62-64`（src/tests 全体に emit なし） |
| `session.*` が死に定義 | `SessionStarted`/`SessionEnded` も未使用 | 同上 |
| `MCP_WRIT_SKIP_SANDBOX` が JSONL に残らない | stderr/`--report` には出るが監査イベントなし | `src/commands/plan.rs:136-139`、`src/main.rs` |
| `FAIL_ON=none` が証拠にならない | stderr 警告のみ（finding 0 件なら JSONL に痕跡なし） | `src/verifier/fail_on.rs:12` `NONE_STARTUP_WARNING` |
| `server.connected` に enforcement 状態なし | details は `spawned <exe>` のみ | `src/runtime/launch.rs:448-461` |
| Landlock は TCP ポート粒度 | `ConnectTcp` のみ。host エントリは「Auditor-only」として skip | `src/warden/landlock_impl.rs:395-440` |
| Windows PSEC は --report のみ | JSONL 非搭載。egress は IPv4 subnet のみ表現可 | `src/warden/psec_spec.rs`、`src/warden/windows_psec.rs` |
| macOS が弱い | sandbox-exec（deprecated）。remote host は拒否、`localhost:port` のみ許可 | `src/warden/macos_sandbox.rs:52-57, 526-553` |
| 監査バッファ × SIGKILL | `BufWriter` 64KB・flush 1s/100件・fsync 5s。Critical は即時 flush あり | `src/audit_log.rs:249-251, 468-533` |
| `--dry-run` が本番と誤認されうる | `LaunchReport.dry_run` あり、ただし JSONL 各イベントに伝播なし | `src/runtime/launch.rs:428` |

補足（プラス材料）:

- **Windows PSEC が唯一の宛先 egress 実装**（IPv4 subnet、deny-all 既定）。
  opt-in・x86-64 限定・v1.0 契約の限界（ingress 不可・env 非継承・loopback
  免除なし）はロード時拒否で誠実に処理済み（`src/policy/validator/psec.rs`）
- コンテナ隔離経路は既に 6 系統（OCI/Kata/Apple Container/Hyper-V/
  Windows Sandbox/WSLc）。「強い境界が要る OS」への逃げ道は存在する
- `fail_closed` 監査モード、channel drop カウンタ、hash pin / re-verify
  等、土台の実装密度は高い

---

## 1. 通信先制御 — egress destination enforcement（最重要）

宛先制御は **ドメイン層 + IP 層の 2 層モデル** として扱う。
どちらか片方だけでは成立しない:

- **ドメイン層（FQDN）**: 名前解決の時点でポリシー評価する **DNS ゲート**
  と、必要に応じて CONNECT プロキシ。`allow api.example.com` という
  現実のポリシー形状はここでしか表せない
- **IP 層（CIDR / リテラル IP）**: TCP 接続・UDP データグラムの実宛先を強制。
  IP 直打ちの流出（シナリオ B）を塞ぎ、ドメインの意図を実フローに結びつける

片方だけでは破綻することが両方向に示せる:

- **CIDR だけでは現実の宛先を表せない**: CDN や LB 配下の名前は短 TTL で
  回転する共有 IP 群であり、静的 CIDR で書けば実質「半インターネット許可」
  になる。`github.com` を allow するためだけに GitHub の全 IP 帯を焼く
  運用は崩壊する
- **FQDN だけでは接続を止められない**: 名前を介さない IP リテラル接続、
  ゲート外リゾルバ（DoH/自前スタブ）は名前層の外を通る

したがって **解決結果で両層を結合** する: DNS ゲートが許可した名前の
応答 IP を TTL スコープで IP 層の動的 allowlist に流し込む。
（ポリシー生成時の静的 resolve では CDN 回転で死ぬ — **実行時 resolve が必須**）

### 1.1 ポリシースキーマ（全 OS 共通）

- `allow host="…"`（現行）: ドメイン名。**Auditor の引数検査に加えて
  DNS ゲートの名前ポリシー評価にも効く** — 「Auditor 補助」に格下げしない
- `allow cidr="…"`（新設案）: IP 層の静的規則。port 修飾はメカニズム別
  expressibility に落とす（PSEC は port 非表現として既に拒否）
- `denied_hosts` は両層で評価: 名前拒否は解決時点で fail、
  IP 拒否は接続・送信時点で fail
- PR-09 でプロトコル・宛先ポート・必須の実通信制御を表す形式を確定する。
  既存規則を暗黙に UDP 許可へ広げず、未対応 backend は要求を起動前に拒否する。
  旧版・継承・生成・export の互換性と、数値 host／ポートの区別も検証する。

### 1.2 DNS ゲート（新コンポーネント）

- ポリシー評価つき DNS リゾルバー。許可名のみ応答、拒否名は
  NXDOMAIN/REFUSED + `sandbox.network_denied` を **名前粒度** で emit
  （`name`/`qtype`/`session_id` — 解決時点で止まる流出も監査に乗る）
- CNAME は最終名まで追跡。ポリシー評価は **対称**: allow/deny ともに
  **クエリ名のみ**評価する（CNAME 先のインフラ名はポリシー対象外）
  - 根拠: CNAME チェーンはワークロードが制御できず（宛先側の運用者が
    決める）、チェーン評価が塞げるのは「許可済みドメインの運用者が
    拒否名へ委譲した」限界事例のみ。一方で共有 IP の穴（許可名の解決先が
    別テナントと IP を共有）はどのみち残るため、名前空間だけ閉じても
    実効上の追加安全性は薄い
  - 単純な意味論に留める: 「allow/deny はワークロードが問い合わせた
    名前に効く。解決先はその名前が指すもの」。非対称評価は運用の
    認知負債になるため採用しない
  - 応答のチェーン全体は監査 details に記録（観測は行うが強制はしない）。
    動的 IP 許可の TTL はチェーン最小 TTL に揃える
- 応答 IP を TTL スコープで IP 層の動的 allowlist に登録
- 既存の UTS-46 正規化（`src/policy/host.rs` の `normalize_policy_host`、
  `idna` crate 導入済み）をそのまま名前マッチに利用 — Unicode 変種
  （全角ドット等）による名前拒否回避は既に対策済み
- 「host 規則（名前層）と CIDR 規則（IP 層）の対応表」を `mcp-writ plan`
  出力に含め、運用時の齟齬を可視化

### 1.3 データプレーン（Linux）— 採用方針と方式選択

Landlock（V4）は宛先をバインドできずポート粒度が上限。宛先制御には別機構が
必要。非特権の名前空間＋プロキシを優先し、既存方式は要求を満たす場合に使用する。
関連する 3 方式の役割と能力は次のとおり:

| 案 | 特権 | IP 層 | ドメイン層 | 評価 |
|---|---|---|---|---|
| **a. seccomp user notification** | 非特権 | connect sockaddr 検査（TOCTOU あり） | △ 53/853 をゲート宛先に限定する拒否は可、DNS 応答の収集は不可 | connect-only の opt-in PoC。UDP 対応や完全な境界の代替にはしない |
| **b. cgroup eBPF** `INET4/6_CONNECT` | 要特権（CAP_BPF 等） | ○ + deny イベント観測可 | △ 同左（DNS ゲートと組合せれば両立） | 権限あり環境の opt-in 強化。「非特権 CLI」モデルと衝突 |
| **c. userns+netns+mountns + ユーザ空間プロキシ** | 非特権（機能・作成権限の検査が必要） | TCP/UDP の宛先 IP・ポート判定 | resolv.conf 支配 + DNS ゲート内蔵（共有 IP 等の限界は §1.7） | **採用する優先方式**。tun + smoltcp 相当を内蔵し、外部デーモンに依存しない |

- (c) は bubblewrap 型の完全非特権ルート: 子を userns+netns+mountns に
  入れ、`resolv.conf` を自前 mount で差し替え、DNS はゲート宛て固定、
  TCP/UDP は宛先チェック付きユーザ空間プロキシのみ経由する。非 DNS UDP は
  既定拒否を維持し、明示した規則の宛先だけ許可する。QUIC は UDP として
  宛先制御し、通信内容の検査は追加しない
- 外向き IP 経路を TUN に限定し、プロキシが実宛先を検査して自身の socket で
  中継する。UDP は接続済みでも各送信を検査し、DNS 由来の動的許可は
  有効期限も確認する。期限切れの許可を使って中継しない。
  外部 socket の継承・受け渡し、ホスト IPC による代理通信、経路変更等の
  迂回を閉じる。対応外の通信は既定拒否、断片化・MTU・IPv6 制御通信も検証する
- Landlock のファイル制限と seccomp は (c) でも併用する。必要な UDP socket の
  許可は制御経路の確立後だけ行い、既存 native の制約を一律に緩めない
- namespaced が利用できない場合は、既存 Landlock＋seccomp で要求を満たすかを
  起動前に判定する。native の Landlock ABI V4 は TCP ポート粒度であり、
  宛先 IP/CIDR を強制しない。`deny_all_others` 時は UDP socket 拒否を維持する。
  UDP 宛先別許可や未対応の実通信制御が必須なら、起動を拒否する
- 製品化時は namespaced 優先の自動選択と明示選択を用意する。利用不可による
  起動前の方式選択と、設定不正・部分初期化失敗・稼働中の障害を区別し、
  障害時は拒否・停止する。選択理由・不足能力・適用範囲を plan/report/監査に
  残し、必須制御を `allow_degraded` で省略しない。詳しい判定は
  [実装手順書の選択表](improvement-pr-guide-2026-10.ja.md#linux-egress-selection) に従う
- (a) は既存 plain spawn とは別の IP 層 PoC として存続する。既存 native の
  Auditor 限定の IP 規則と混同しない。(b) は引き続き特権環境の opt-in とし、
  (a)/(b) への自動切り替えはしない
- 推奨順序: v0.3 で (a) IP 層 PoC + **DNS ゲート単体**（設定ベースで先行
  利用可能）→ v0.4 で (c) TCP/UDP・DNS ゲート強制の PoC、(b) eBPF opt-in
  → v0.5+ で PoC の受入条件を満たした (c) と能力に応じた方式選択を製品化する

(a) の既知の論点:

- supervisor は子プロセスメモリの sockaddr を読む（process_vm_readv /
  `/proc/pid/mem`）。deny 判定は通知時点で閉じるため実害は限定的だが、
  「引数検査〜実使用の隙間」と同型の限界として docs に明記する
- `SECCOMP_USER_NOTIF_FLAG_CONTINUE`（kernel 5.5+）で許可側のオーバーヘッドを
  最小化できる
- v0.3 は connect-only。UDP の宛先別制御は (c) で実装し、(a) の socket
  制限を緩めるだけでは対応しない。UDP `connect` 後も `sendto` 等で別宛先へ
  送信できるため、接続時の検査だけで全送信を制御したとは扱わない

### 1.4 Windows egress

- **PSEC egress（IPv4 subnet）は実装済み** → IP 層は既に最強
  1. opt-in (`--windows-mechanism psec`) → 既定化の可否を検討
  2. ARM64 対応（現 x86-64 のみ）
  3. 適用状態・grant 結果を `--report` だけでなく **JSONL に emit**（§2.5）
- **FQDN はネイティブでは不可能と明記**: PSEC v1.0 は loopback 免除が
  ないためローカルプロキシ/ゲートにすら届かない。FQDN が要るワークロードは
  network broker 前置（現行 validator メッセージと同じ指針）または
  Windows Sandbox / WSLc のゲストネットワーク経路でゲートを挟む
- AppContainer 経路は宛先制御を持たない → 現行のロード時拒否を維持
- WFP は管理者権限が必要で CLI 常駐モデルと合わない → 補助枠としてのみ
  記録し、実装は保留

### 1.5 macOS egress

- sandbox-exec は deprecated だが `localhost:port` 許可が可能 →
  **ネイティブでも loopback CONNECT プロキシ経路が組める**（Windows PSEC と
  非対称）。プロキシが宛先（名前/IP）を判定して外向き dial する形なら
  中身を見ずにドメイン制御が実現できる
- SBPL の `(remote ip "…")` で IP literal egress も試行（deprecated API への
  投資はこの範囲に限定）
- 強い境界は Apple Container バックエンドの NAT/ホスト側にゲートを置く経路

### 1.6 `sandbox.network_denied` の実装

- **名前層**: DNS ゲートの拒否応答時に emit（`name`/`qtype`/`session_id`）
- **IP 層**: unotify supervisor / eBPF ring buffer / プロキシ deny 時に emit
  （`dest`/`port`/`proto`/`session_id`）
- Landlock/seccomp の通常パスはカーネル内で拒否するだけでユーザ空間に
  通知が来ない → 「supervisor/proxy が介在する経路で弾いたもののみ emit
  可能」として仕様化。FS 拒否の観測不能は docs 明記 or auditd 連携を別途検討

### 1.7 残存リスク（誠実に開示）

- **DoH 回避**: ゲート外リゾルバへの 853/443 は IP 層の既定拒否で塞ぐ。
  ただし許可済み CIDR/FQDN の先がリゾルバを兼ねる場合は残る → 文書化
- **ECH**: SNI 暗号化で SNI ベース判定が効かない宛先がある
  （CONNECT プロキシは宛先明示なので影響なし）
- **ハードコードリゾルバ**: ゲートを使わないワークロードは名前解決ごと
  fail → fail-closed として仕様化（「動かなくなる」のが正しい挙動）
- **TTL レース**: 短 TTL 名が応答直後に別 IP を引く。TTL スコープの
  動的 allowlist が緩和するが完全には閉じない → 文書化
- **CNAME 委譲**: 許可名の解決チェーンが拒否名・未知のインフラ名を経由
  しても、名前ポリシーはクエリ名のみ評価（対称評価）。宛先側の委譲は
  監査のチェーン記録で追跡可能だが遮断はしない → 文書化
- **共有 IP**: 許可名が共有 CDN/LB の IP を返すと、その IP 上の別テナント
  も（中身を見ない設計上）到達可能。名前層の保証は解決名の範囲に限る
  → 文書化
- **プロキシ自体の信頼性**: ユーザ空間ネットワークスタックの実装バグは
  そのまま境界の穴。最小フットプリント（外部デーモン非依存）+ e2e で担保
- **ネイティブ経路の IPC 迂回**: native の Landlock＋seccomp は AF_UNIX
  （パス名・抽象）とシグナルを制限しておらず、ホスト上のソケットを介した
  代理通信が宛先制御を迂回しうる → §8.2 F-01 で是正（閉じられない条件は開示）

---

## 2. 監査完全性 — 指摘ポイント対応

小粒だが「監査の土台」の信頼性に直結。全て v0.3 候補。

### 2.1 バイパス・ダイヤル低下の記録

- `MCP_WRIT_SKIP_SANDBOX` 検出時に `guard.started`（または新規
  `config.override`）イベントを必ず emit。details に
  `sandbox=skipped via MCP_WRIT_SKIP_SANDBOX`
- `FAIL_ON=none` を起動時に記録（finding 0 件でも残る）。
  `policy.loaded` details に `fail_on` 値を含める形でも可
- `--dry-run` 時に全イベント or `guard.started` details へ `dry_run=true`
  を伝播（report 側には既にある — `launch.rs:428`）

### 2.2 `server.connected` に enforcement 状態

details に sandbox backend、RestrictionStatus（FullyEnforced/
PartiallyEnforced/NotEnforced）、適用 controls 数、スキップした grant を
要約して載せる。`--report` の `plan`/`observations` との対応を取る

### 2.3 死に定義の解消（実装 or 仕様削除の二者択一）

- `session.started`/`session.ended`: emit は容易（起動/終了パスに hook 済み）。
  実装して IR のセッション再構成に使えるようにする
- `sandbox.file_denied`/`sandbox.process_denied`: OS 層の拒否は観測経路が
  ない限り emit 不可。**「emit できないイベントは schema から削る」か
  「観測経路を足す」かを項目ごとに決める**（§1.6 参照）

### 2.4 監査バッファの SIGKILL 耐性

- 現状: 64KB BufWriter / flush 1s or 100 件 or Critical / fsync 5s
- 改善案:
  - High 以上も即時 flush+fsync（Critical だけでなく）
  - `--audit-sync` オプションで逐次 fsync（性能と引き換えの明示）
  - `guard.stopped` に dropped 数・writer_failed を記録
  - 外部転送（stdout audit モード or tail → SIEM）の運用例を docs に追加

### 2.5 PSEC 状態の JSONL 搭載

`--report` でしか見えない PSEC mechanism/状態を `server.connected` details
または専用イベントで JSONL に emit（§1.4 と同一項目）

---

## 3. OS 差の解消

### 3.1 機能マトリクスの機械可読化

- `PlannedControl`/`ProcessGrant`/`EnforcementPlan`（`src/enforcement.rs`）で
  「何が効くか」は既にモデル化済み → `mcp-writ plan`/`--report` の出力を
  OS 横断で統一し、`docs/test-matrix.md` との整合を CI で検査する

### 3.2 位置づけの明文化

- native warden は **Linux が本命**、他 OS で強い境界が要る場合は
  `--isolation`（Kata/Apple Container/Hyper-V/Windows Sandbox/WSLc/OCI）
  経路を推奨 — という設計判断を README/guide に明記。レポートの
  「Linux B+ / Win C〜C+ / macOS 弱い」を言い訳でなく階層設計として説明する

### 3.3 各 OS 個別

- **Linux**: Landlock ABI 追従（probe 機構 `MCP_WRIT_PROBE_LANDLOCK_ABI`
  済み）+ §1.3 egress 2 層
- **Windows**: PSEC ARM64・既定化検討・mechanism 選択ガイド。
  FQDN はネイティブ不可を明記（§1.4）
- **macOS**: sandbox-exec は最小維持（§1.5）、強化はプロキシ経路と
  Apple Container 経路へ

---

## 4. 最新技術導入

| 技術 | 用途 | 優先度 |
|---|---|---|
| seccomp user notification | Linux IP 層 egress（非特権） | v0.3 PoC |
| DNS ゲート（ポリシー評価リゾルバ） | ドメイン層の中核・名前粒度の拒否監査 | v0.3 |
| userns+netns+mountns + ユーザ空間プロキシ | DNS ゲート強制＋TCP/UDP の宛先制御 | v0.4 PoC、v0.5+ 製品化・方式選択 |
| cgroup eBPF (`INET4/6_CONNECT`) | Linux IP 層強化・deny イベント観測 | v0.4+ opt-in |
| Landlock 新 ABI | 将来の IP/socket 拡張へ追従 | 継続 |
| Windows PSEC schema 追従 | v1.0 契約の拡張（ingress/IPv6 等が来たら） | 継続 |
| Apple Containerization.framework | macOS の強い隔離経路 | 実装済み・拡充 |
| WFP / Endpoint Security | 補助（要権限/entitlement） | 評価のみ・実装保留 |
| MCP spec 新版 | 2025-11-25/2026-07-28 済み。Streamable HTTP 等 transport の監査 IF を検討 | 追従 |

---

## 5. その他

### 5.1 ポリシー運用コスト（レポート §4）

- `legislator` が生成する `// REVIEW` コメント（`src/legislator/
  policy_generator.rs`）の未解消をロード時に warn/refuse する strict モード
- `tools-list-hash`/`binary-hash` のドリフト検出: 現行ポリシーと実ファイルを
  再照合する `mcp-writ check`（仮）で CI 化

### 5.2 構造的限界の明文化

- TOCTOU（RPC 引数検査とサーバ内部動作の乖離）は設計上の境界として docs 固定
  - FS は Landlock が open() 時点で強制するため実効的に緩和済み、との切り分けも
- `npx` 系は entrypoint-hash + インタプリタ同時ピンのガイド強化

### 5.3 監査ログ外部転送

- stdout モード / tail → SIEM の運用例を guide に追加（§2.4 とセット）

### 5.4 テスト・検証

- シナリオ A（注入 → 拒否 → JSONL 確認）を e2e 化
- シナリオ B（443 直出し）を egress 実装後に再現し、効く側に変わったことを
  検証する回帰テスト
- SIGKILL 末尾欠損の計測テスト、PSEC 状態 JSONL emit の e2e

---

## 6. ロードマップ案

| 版 | 内容 |
|---|---|
| **v0.3** | §2 全部（監査完全性）+ §1.1 スキーマ + §1.2 DNS ゲート単体 + §1.3(a) IP 層 PoC + §1.6 emit 経路 + §2.5 PSEC JSONL |
| **v0.4** | §1.3(c) netns プロキシ PoC（TCP/UDP 宛先制御・DNS ゲート強制・迂回/障害試験）+ §1.3(b) eBPF opt-in + §1.5 macOS プロキシ経路 + §3.3 Windows 既定化/ARM64 + §3.1 capability matrix |
| **v0.5+** | §5.1-5.2 ポリシー運用 + netns プロキシの本番化・能力に応じた方式選択（native は要求を満たす場合のみ）+ §1.7 残存リスクの継続評価 + §8 の P0（必須）・P1（含める範囲はリリース時に判断） |
| **次版以降** | §8 の P2（監査ログの再オープン・ポリシー v3・unsafe 注記）+ §9 実運用検証フィードバック（PR-30〜36。v0.5.0 のタグは止めない） |

## 7. 非目標（継続）

レポート同様、以下はスコープ外を維持: Remote MCP ゲートウェイ、応答
ボディの DLP/DPI、LLM による中身判定、「FQDN を書けば絶対安全」の宣伝。

---

## 8. 外部レビュー対応（2026-10-16 追加）

2026-10 に受け取った外部レビュー 5 件の指摘を、HEAD `9203e2c`（PR-16 の
merge #67）のコードと照合して計画化したもの。PR 単位の作業は
[PR別実装手順書](improvement-pr-guide-2026-10.ja.md) の PR-17〜29。

| 略称 | 内容 |
|---|---|
| review1 | 4 観点の評価と Linux 実機での再現（`fd3892e` 時点） |
| review2 | KDL の継承・再利用の実験 |
| review3 | 見逃した問題ごとのテスト照合 |
| argon1 | 市場・技術の評価 |
| argon2 | README の評価 |

- 対象は技術的な指摘に限る。argon1・argon2 のうち、名称・市場・ローンチ経路・
  リポジトリ公開状態など技術以外の指摘は扱わない。
- review1 は PR-16 より前の `fd3892e` 時点の評価。PR-16 が変更したのは
  warden・runtime・cli・enforcement・docs で、`src/auditor`・`src/verifier`・
  `src/policy`・`src/framing.rs` は変わっていないため、これらの指摘は HEAD でも
  そのまま当てはまる。
- 照合はコード読解による。ビルドもテストも実行していない（D: 28 GiB・C: 22 GiB
  の空きで、AGENTS.md の 40 GiB 基準を下回っていたため）。実行による再現は
  review1 の Linux 実機結果に依る。このため各 PR の最初のタスクを「修正前に
  失敗する再現試験を書く」にする。
- 照合の過程で見つかった、レビューに無い問題は「新規」と記す。

### 8.1 優先度の基準

| 優先度 | 基準 | リリースとの関係 |
|---|---|---|
| P0 | 境界の過大表示、権限の拡大、一般的な公式サーバーが既定で動かない、検証基盤が失敗を隠す | v0.5+ のタグ前に必須 |
| P1 | 誤操作を誘う仕様、診断不足、試験の網羅漏れ | v0.5+ に含めるのが望ましいが、タグは止めない |
| P2 | 運用改善、保守性 | 次版以降 |

### 8.2 境界・権限

| ID | 指摘（出典） | HEAD での判定 | 優先度 | PR |
|---|---|---|---|---|
| F-01 | ネイティブ Linux 経路で AF_UNIX（パス名・抽象）とシグナルが素通りし、表示は FullyEnforced（review1、review3、argon1） | **確認**。詳細は表の下 | P0 | PR-18 |
| F-02 | 継承したツールを子ファイルで再宣言すると、親で明示したツールの fs/network スコープが置き換わる（**新規**） | **ほぼ確実**。詳細は表の下 | P0 | PR-19 |
| F-03 | 継承で設定が黙って落ちる（**新規**） | **確認**。詳細は表の下 | P0 | PR-19 |
| F-04 | 祖先ファイルの `policy version` を検証しない。親に `version=99` と書いても、子の版で読み込まれる（**新規**） | **確認** | P1 | PR-19 |

**F-01 の詳細**

- Landlock のスコープ（ABI 6）を使っていない。固定中の `landlock` 0.4.7 は
  `Scope` に対応している。
- ネイティブの seccomp は `socket()` の type だけを絞り、family は絞っていない
  （`src/warden/seccomp_impl.rs:269-291`）。
- 同梱の `examples/policies/runtime/python.kdl` は `socketpair`・`sendto`・
  `sendmsg`・`kill` を許可している。この組み合わせだけで、`/dev/log` などへの
  DGRAM 送信や `kill(getppid())` が成立する。影響範囲はレビューの記述より広い。
- PR-16 の後も、次の場合はネイティブ経路が使われる。
  - namespaced のプローブが失敗する環境
  - `/run` 配下を許可するポリシー
  - `--linux-mechanism native` を明示した場合
  - ゲスト内の `mcp-secure-runner`
  - `unotify-run`・`ebpf-run`

**F-02 の詳細**

- `src/policy/kdl_inherit/overlay.rs:211-221`（fs）と `:263-278`（network）は、
  `fs_explicit`/`network_explicit` を見ずに置き換える。`when` の経路は正しく扱う。
- 次の 2 つで、範囲が広がるか許可リストが消える。
  - 例示ポリシーの `allow none=#true` を持つツールを、`defaults.filesystem` を
    持つ子が再宣言する
  - network の許可リストを持つツールを、子が `side_effect` だけで再宣言する

**F-03 の詳細**

- `when` が `secret-overlay` を落とす。オーバーレイを有効にする方向で失われる
  ため、fail-open。
- include では、取り込むファイルの祖先や `when` に由来する値が失われる。対象は
  transport、sandbox、`logging.fail_closed`、network posture/inbound、
  `secret-overlay`、trajectory rules。
- extends では、子が `defaults.network` を宣言しただけで、親の posture と
  `inbound` がリセットされる。

### 8.3 可用性・正しさ

| ID | 指摘（出典） | HEAD での判定 | 優先度 | PR |
|---|---|---|---|---|
| F-05 | 1 MiB を超えるフレームで、ガードごと終了する（review1、review3） | **確認**。詳細は表の下 | P0 | PR-20 |
| F-06 | `args_schema` が `anyOf`・`minItems`・`format` などを拒否し、生成ドラフトがサーバーのスキーマをそのまま写す（review1、review3） | **確認**。詳細は表の下 | P0 | PR-21 |
| F-07 | CC-011 の誤検知で、公式 fetch サーバーが既定設定では使えない（review1、review3） | **確認**。詳細は表の下 | P0 | PR-22 |
| F-08 | 他の CC 規則（003/005/007/009/010）にも語句ヒューリスティックによる誤検知の余地がある。例: 「Return the next page token」が CC-010（Critical）に当たる | **未計測**。公開サーバーで試していない | P1 | PR-22 |
| F-09 | `2025-06-18` で応答するサーバーが拒否され、理由が `response rejected (shape)` としか出ない（review1、review3） | **確認**。詳細は表の下 | P1 | PR-23 |
| F-10 | ディスパッチャ型サーバーの生成ドラフトは全ツール拒否になる（review1） | **設計どおり**（CWE-862 の是正）。ただし guide の Case C 表（`docs/guide.md:580-582`、`guide.ja.md:542`）は、まだ「allowed with review note」と書いていて実装と矛盾する | P1 | PR-17（文書）、PR-21（ドラフト注記） |
| F-11 | 監査ログにローテーションも再オープンもなく、容量が尽きると停止する（review1） | **確認**。fail-closed としては正しく、許可した呼び出しが未監査で通ることはない。ただし空きを作っても復帰しない | P2 | PR-27 |
| F-12 | `auto` が Landlock ABI 1〜3 でネイティブを選び、起動時に EACCES で失敗する。また `allow_degraded` が選択時の ABI 検査を緩めており、PR-16 の「必須制御を省略しない」と食い違う（**新規**） | **確認**（`src/warden/select.rs:644-663`） | P1 | PR-18 |

**F-05 の詳細**

- サーバーからクライアント、クライアントからサーバーの両方向で起きる
  （`src/framing.rs:9`）。
- 上限は設定で変えられない。クライアントには応答もエラーも返らず、終了理由は
  監査ログにも残らない。上限はガイドにも書かれていない。
- filesystem サーバーは本文を 2 回載せるため、約 512 KiB のテキストで上限に
  達する。TS SDK の上限は 10 MiB。

**F-06 の詳細**

- 判定は呼び出し時に、該当するプロパティを渡したときだけ行われる。ロード時には
  検査していない。
- このため filesystem の `read_multiple_files` は毎回拒否される。git は省略可能な
  引数を渡したときに拒否される。
- **新規**: `args_schema` を持つツールでは、`arguments` を省略した `tools/call`
  も拒否する。MCP 仕様では省略してかまわない。

**F-07 の詳細**

- 判定は `readOnlyHint=true` と `url` 系キーの組み合わせだけで決まり、
  `openWorldHint` を読んでいない。
- 該当ツールに `deny=#true` を付けても回避できず、`--fail-on` を全体で緩める
  しかない。
- fetch が実際に持っている注釈は、リポジトリ内では確認していない。

**F-09 の詳細**

- 監査ログの `version=2025-11-25` という表記は誤解を招く。stderr には何も出ない。
- 古い版を要求するクライアントでも、同じように失敗する。

### 8.4 KDL の継承規則（review2）

| ID | 指摘 | HEAD での判定 | 優先度 | PR |
|---|---|---|---|---|
| F-13 | extends で `defaults.syscalls` が親を丸ごと置き換える | **確認**。詳細は表の下 | P1 | PR-24（警告・文書）、PR-28（v3） |
| F-14 | extends で network の allow が置換になり、filesystem の和集合と逆の規則になっている | **確認** | P1 | PR-24、PR-28 |
| F-15 | `profiles "a" "b"` の第 2 引数以降を黙って無視し、profile の構文が文書にない | **確認**（`kdl_parse/servers.rs:174-177`） | P1 | PR-24 |
| F-16 | 未知のノードや重複したノードを黙って無視する（**新規**、範囲が広い） | **確認**。詳細は表の下 | P1 | PR-24 |
| F-17 | 最終的に効いているポリシーを、出所つきで確認する手段がない | **確認**。`to_kdl` は既にあるが、出所の記録はない | P1 | PR-24 |
| F-18 | `overlay.rs:35-36` の冒頭コメントが実装と食い違う。`policy.example.kdl:101-108` のコメント例が、`protocol=` とツール単位の `deny host="*"` のせいで壊れている | **確認** | P2 | PR-19 |

**F-13 の詳細**

- 置換されても警告は出ず、エラーは「execve が必要」だけ。
- `plan` はこの検査をしないため、`plan` は通るのに `run` で失敗する。
- `runtime/*.kdl` の「Extend it from runtime evidence」という注記が、この誤りを
  誘う。

**F-16 の詳細**

- 黙って無視される例は次のとおり。
  - `defaults` の子の綴り誤り（`filesytem` など）
  - top-level の未知ノード
  - `profile`/`server-defaults` の子
  - 2 つ目の `extends`
  - 未知の transport（stdio として扱われる）
- v2 で厳格なのは `tool` ノードだけ。

### 8.5 試験・検証基盤（review3）

| ID | 指摘 | HEAD での判定 | 優先度 | PR |
|---|---|---|---|---|
| F-19 | `real_servers_e2e` が前提不足のときに黙ってスキップし、「ok」と表示する | **確認**。詳細は表の下 | P0 | PR-17 |
| F-20 | CI が手動起動のみで、capability-matrix の退行がマージを通過した | **確認**。詳細は表の下 | P0（D-1 の判断を含む） | PR-17 |
| F-21 | 生成したドラフトを `run` に渡す通し試験がない。省略可能な引数、fetch、大きな応答もない | **確認**。stage 1 はドラフトを読み込むだけで、`run` は手書きの例示ポリシーで実行している | P1 | PR-25 |
| F-22 | ネイティブ経路で「抜けられないこと」を試す試験がない | **確認**。詳細は表の下 | P0 | PR-18 |
| F-23 | root で実行すると 3 件失敗する | **確認**（`src/fspriv.rs:1350`、`src/dnsgate/allowlist.rs:740`、`tests/diagnostics_e2e.rs:358`） | P2 | PR-17 |
| F-24 | `ebpf_e2e` がどのワークフローにも無い。`tool_enforcement_e2e` の汚染 tools/list ヘルパーが応答 id を照合していない（**新規**） | **確認** | P2 | PR-17 |

**F-19 の詳細**

- 前提不足だけでなく、stage 2/3 の応答欠落（実際の故障）もスキップとして扱われる。
- `MCP_WRIT_REQUIRE_SERVER_TESTS=1` を設定するワークフローは `mcp-servers.yml`
  だけで、手動起動のみ。

**F-20 の詳細**

- 退行そのものは PR-16（`330c394`）で修正済み。
- ただし再発を防ぐ仕組みはない。
  - 登録順に依存していることは、コメントで示しているだけ。
  - 引数なしのサブコマンドを parse する試験がない。
  - `linux-tests.yml` に `capability_matrix` が入っていない。

**F-22 の詳細**

- 既存の拒否試験は、ファイル読み取りと TCP connect の 2 種類だけ。
- **新規**: `denial_audit_e2e` は `--linux-mechanism native` を固定していない。
  PR-16 の後は、ホストによって namespaced が選ばれ、`landlock+seccomp` の検査が
  崩れる。

### 8.6 文書

| ID | 指摘 | HEAD での判定 | 優先度 | PR |
|---|---|---|---|---|
| F-25 | README の `environment` の説明が実装と逆になっている（**新規**） | **確認**。詳細は表の下 | P0 | PR-17 |
| F-26 | 「`/run` の外にある AF_UNIX は fs ポリシーに依る」という記述が誤り（**新規**） | **確認**（`docs/guide.md:1290`、`docs/validation/linux-namespaced-proxy.md:109-111`）。Landlock は ABI 9 未満では AF_UNIX の connect を仲介しない | P0 | PR-18 |
| F-27 | argon2 ①が指摘した symlink 解決ループが `docs/quickstart.md:29-36`（ja も）に残っている。inspect の出力例は汎用の Python だけ | **一部確認**。README 本体では解消済み | P2 | PR-17 |
| F-28 | PR-16 の手順書のチェックボックスが未更新。タスク 4 とタスク 6 が未完で、Linux `run` の既定変更（`auto`）について移行の注記もない | **確認**。チェックは 2026-10-16 に更新し、未完分は PR-26 へ繰り越した | P1 | PR-26 |

**F-25 の詳細**

- README と README.ja は、`environment` ノードを省略すると親の環境を全継承すると
  書いている（README.md:188-193、:405-408、README.ja.md:174、:380）。
- 実装は PR-12 から既定で制限しており、記述と逆。利用者が安全性を判断する際に
  誤らせる。

### 8.7 保守性

| ID | 指摘 | HEAD での判定 | 優先度 | PR |
|---|---|---|---|---|
| F-29 | `compile_post_exec_filter` がどこからも呼ばれず、説明も誤っている（review1） | **確認**（`seccomp_impl.rs:65-77`）。呼び出しは自身の単体試験だけ | P2 | PR-18 |
| F-30 | unsafe に Safety の注記が少ない（review1） | **確認**。src/warden では unsafe ブロック約 410 に対して注記約 99。`namespaced/init.rs` は unsafe 44 に対して注記 0 | P2 | PR-29 |
| F-31 | クライアント→サーバーの読み取り中に `fail_watch` が発火すると、読みかけの行が失われる（best-effort 時）。`TooLarge` の文言が誤解を招く（**新規**） | **確認**。影響は小さい | P2 | PR-20 |

### 8.8 対応しない・対応済みの指摘

| ID | 指摘（出典） | 判断 |
|---|---|---|
| N-01 | `capability-matrix` が "command is not specified" で失敗する（review1） | PR-16 で修正済み。再発防止は PR-17 |
| N-02 | README の Quick Start が手書きの deny 13 行と symlink ループを強いる。バイナリ導入、MSRV、和集合の理由、migration の行（argon2 ①②③⑤） | `b1b5c99`・`c4d0581` で解消済み。レビューは古い README を読んでいる。残っている分は F-27 |
| N-03 | 子プロセスの環境変数を消去する（argon1） | PR-12 で既定化済み |
| N-04 | stdout に JSON-RPC 以外が混入する（argon1） | `run` は混入しない。`tests/diagnostics_e2e.rs:129-147` で固定済み |
| N-05 | Sampling・Roots・Elicitation などサーバー起点の要求（argon1） | 閉じたメソッド台帳で判定済み |
| N-06 | 応答本文の検査・DLP（argon1） | 非目標（§7）。維持する |
| N-07 | ツール呼び出し単位の OS 隔離（argon1、argon2 ③、review1） | 無改造のサーバーを外側から包む設計上の構造的限界。README:427-435 と guide §8 で開示済み |
| N-08 | unotify の TOCTOU（argon1） | PR-07 の connect エミュレーション（`pidfd_getfd`）で解消済み |
| N-09 | DNS リバインディング（argon1） | dns-gate の grant と IP 層の判定（PR-06/09）で対応。素のネイティブ経路が Auditor-only であることは開示済み |
| N-10 | 巨大なファイル、`ProxyShared` の共有状態、自前実装の多さ（review1） | 欠陥ではない。各 PR で触る範囲の分割に留め、単独のリファクタ PR は作らない |
| N-11 | 閉じたメソッド台帳の保守コスト（review1） | 安全側の設計として維持する |
| N-12 | 性能の定量化（argon1） | review1 の実測では上乗せ約 0.6 ms で、問題ない。計測記録を残すのは任意 |
| N-13 | `server-memory@2026.8.31` が npm で非推奨（review1） | リポジトリからは確認できない。PR-25 で固定版を更新する際に確認する |

### 8.9 判断事項

| ID | 論点 | 推奨 | 代替 |
|---|---|---|---|
| D-1 | CI のトリガー。手動 CI は [assessment-116a111.ja.md](assessment-116a111.ja.md) の「必ず維持する前提」だが、そのせいで退行がマージを通過した | `pull_request` で Linux の 1 ジョブだけ常設する。内容は fmt・clippy・lib/bins と、`capability_matrix`・`docs_check`・`module_layering`・`manifest_fixtures`・CLI parse。path filter を付け、目安は約 10 分。重い e2e は手動のまま | 手動を維持し、`scripts/pre-merge-check.sh` の実行ログを PR 本文に必須とする |
| D-2 | ネイティブ経路で正当に UNIX ソケットを使うサーバーの扱い | `network { allow unix="/path" }` を新設する。ABI 9 以上では `ResolveUnix` でパスを限定する。ABI 9 未満では `allow unix="*"` を明示した場合だけ family を開放し、plan に「パス未限定」と表示する | ABI 9 未満では起動を拒否する |
| D-3 | フレーム上限の既定値 | 10 MiB（TypeScript SDK と同じ値）とし、設定で変えられるようにする | 1 MiB のまま設定化だけ行う |
| D-4 | `2025-06-18` に対応するか | 今回は診断の改善だけにする。版の追加は、閉じたメソッド台帳への追加として別途判断する | 台帳に `2025-06-18` を加える |
| D-5 | マージ規則を統一するか（v3） | PR-24 の警告と `policy resolve` を運用し、結果を見てから着手する | PR-24 と同時に設計する |
| D-6 | CC 規則をツール単位で免除できるようにするか（tools-list-hash に紐づける） | PR-22 のコーパスの結果を見て判断する | 実装しない（`--fail-on` の全体設定のみ） |

#### 決定記録（v0.5 到達条件・2026-10-20 確認）

- D-1: **推奨案を採用**。PR-17 で `pull_request` トリガーの最小ジョブ（[pr-checks.yml](../.github/workflows/pr-checks.yml)）を導入済み。重い e2e は従来どおり手動 dispatch。
- D-2: **推奨案を採用**。PR-18 で `network { allow unix="<path>" }` を新設。ABI v9 以上は `ResolveUnix` でソケットの親ディレクトリ粒度に限定し、ABI v9 未満のパス指定は選択時に拒否（ファミリを黙って開かない）。`allow unix="*"` は全カーネルで family 全開放の明示 opt-in として受理。
- D-3: **推奨案を採用**。PR-20 でフレーム上限の既定を 10 MiB（TypeScript SDK と同値、`framing::DEFAULT_MAX_FRAME_BYTES`）とし、`--max-frame-bytes` で変更可能にした。
- D-4: **推奨案を採用**。PR-23 で `2025-06-18` は非対応のまま診断のみを改善（`unsupported-version` で fail-closed、3 面の診断に交渉版と対応版を記録）。版の追加は閉じたメソッド台帳への追加として別途判断する。
- D-5: **推奨案を採用**。PR-24 の継承警告と `policy resolve` を運用し、その結果を見てから PR-28（`policy version=3`）の着手を判断する。v0.5 では着手しない。
- D-6: **代替案を採用**。PR-22 のコーパス（公式 7 件 + playwright / chrome-devtools の計 9 サーバー・109 ツール）で全 CC 規則がクリーンだったため、ツール単位の免除は実装しない（`--fail-on` の全体設定のみ）。将来ツール単位の扱いを導入する場合は、ボルトオン型の免除ではなくツール単位の許可モデルへの再設計として検討する（リリースオーナー判断）。

## 9. 実運用検証フィードバック対応（2026-10-26 追加）

2026-10-26 に受け取った実運用検証レポートの改善案 6 件を、HEAD `41d23e3`（PR-82〜85 のマージ後、0.5.0）のコードと照合して計画化したもの。レポートの検証範囲は、`41d23e3` からビルドした 0.5.0 を Node.js 製の実在 MCP サーバー（複数ファイルの ESM 構成、ツール 12 件）に対して、ポリシー生成 → dry-run → Landlock＋seccomp の enforced run → 許可ツール 1 件の実呼び出しまで通したもの。PR 単位の作業は [PR別実装手順書](improvement-pr-guide-2026-10.ja.md) の PR-30〜36。

- 照合はコード読解と、Windows ホストでの `cargo build --locked` ＋ `mcp-writ run --help` / `mcp-writ generate-policy --help` の実行による。実行で再現したのは改善案 1 のみで、テストは未実行。
- namespaced 経路はレポート側でも未検証（検証環境が入れ子のユーザー名前空間の中にあった）。本節は namespaced 経路のデータプレーンの実装変更を含まない。ただし改善案 5 の環境制約ヒントに付随して、起動前プローブの検査項目追加（D-10）を判断事項として挙げる。
- fail-closed の原則（決めていないことは通さない、失敗時は安全側に倒れる）を利便性のために崩す変更は含めない。各 PR の「移行・戻し方」で、その PR が計画する変更の範囲外では既定の出力・判定が変わらないことを完了条件に含める。計画された変更自体（help 出力・`launch.env` の観測・outcome 値・方式選択など）は、その PR の完了条件に照らして検証する。
- 優先度は §8.1 の基準に従う。いずれも v0.5.0 のタグ前には必須としない（§6 の「次版以降」）。

### 9.1 照合結果

| ID | 改善案（レポート） | HEAD での判定 | 優先度 | PR |
|---|---|---|---|---|
| V-1 | サブコマンドの `--help` が、そのサブコマンドのオプションではなく兄弟サブコマンドの一覧を示す（改善案 1） | **確認（再現済み）**。原因は [cli/mod.rs](../src/cli/mod.rs) `608-690` 行が 15 個の `noargs::cmd(..).take()` を dispatch の前に無条件で実行していること。noargs は一致した cmd より後にログに残った `Cmd` を「Commands:」として描画し、Usage も `mcp-writ ... run [OPTIONS] <COMMAND>` になる。当該サブコマンドのオプション自体は Commands の後ろに出ている（`tests_parse.rs:155` の `--fail-on` 検査が通る理由）が、`-- <command>` の位置引数は Usage にも Arguments にも出ない | P1 | PR-30 |
| V-2a | ランタイム別の雛形を生成ドラフトの選択肢として同梱する（改善案 2-1） | **一部実装済み**。`examples/policies/runtime/{node,python}.kdl` が雛形で、PR-21 以降の `generate-policy` は検出したインタプリタの seccomp ベースラインを同ファイルから自動投入する（[policy_generator.rs](../src/legislator/policy_generator.rs) `511-535`・`668-700`）。残る空白は、インタプリタ実行に必要なファイル読み取り（解決済みの interpreter prefix・パッケージツリー）と、環境変数の許可リストの雛形。ネットワーク宛先は推定しない（設計） | P2 | PR-32 |
| V-2b | `check` の未解決 REVIEW 項目に「判断が必要な理由」と「代表的な解消方法」を付ける（改善案 2-2） | **確認**。`check` は `review_markers[]` に file/line/text を列挙し、remediation は全体で 1 行（[check.rs](../src/commands/check.rs) `644-650`）。マーカー文は `policy_generator.rs` の固定テンプレート（約 15 種）から出るので、種別の分類と案内文の対応表を生成側と check 側で共有できる | P1 | PR-31 |
| V-2c | ディスパッチャ型サーバーの説明をドラフト冒頭で具体化する（改善案 2-3） | **一部実装済み**。全件 deny のときの NOTE（`policy_generator.rs:83-88`）はあるが、静的に結び付けられない理由と、運用者が引き受ける確認事項（`tools-list-hash` pin を整合性の拠り所にする、live discovery の再実行、ツール単位の許可判断）は書いていない。部分的に根拠なしのドラフトでは件数も出ない | P1 | PR-31 |
| V-3 | 許可リストの環境変数の実在を起動時に診断する（改善案 3） | **確認**。[warden/env.rs](../src/warden/env.rs) `188-200` は親環境に無い名前を黙ってスキップし、plan の `launch.env` は件数のみ（[warden/plan/mod.rs](../src/warden/plan/mod.rs) `255-279`）、`server.connected` の details は `env=inherit-parent` の有無のみ（[runtime/launch.rs](../src/runtime/launch.rs) `861-865`）。欠落した名前はどこにも残らない | P1 | PR-33 |
| V-4 | `tools_list.filtered` の outcome が `failure` で記録される（改善案 4） | **確認（設計どおり）**。[proxy_tools_list.rs](../src/auditor/proxy_tools_list.rs) `862-871` が `tool_call.denied` と同じ規約で `Outcome::Failure` を付け、guide 英日（`guide.md:2586-2597`、`guide.ja.md:1589`）がその理由を明記している。ただし `tool_call.denied` が要求自体をエラーで拒むのに対し、`tools_list.filtered` は `tools/list` 要求が成功して整形済みの応答が届いている点で事情が異なり、監視側が failure を異常に数えるという指摘は妥当 | P1 | PR-34 |
| V-5a | init-order 拒否の理由文に期待する順序を含める（改善案 5-1） | **確認**。クライアントには `request denied (init-order)` だけが返る（[proxy_c2s/forward.rs](../src/auditor/proxy_c2s/forward.rs) `238`・`775`）。期待順序（initialize → initialized 通知 → 通常要求）は guide の障害切り分け表にも無い | P1 | PR-35 |
| V-5b | namespaced 初期化の `/proc` マウント EPERM に環境制約のヒントを付ける（改善案 5-2） | **確認**。[namespaced/init.rs](../src/warden/namespaced/init.rs) `1006-1026` は `ERR proc-mount errno=1` を返し、[spawn.rs](../src/warden/namespaced/spawn.rs) `121-122` がそれを `init post-GO failure: ERR proc-mount errno=1` として伝えるだけ。起動前プローブ（[probe.rs](../src/warden/namespaced/probe.rs) `160-205`）は `unshare` と TUN までしか検査せず proc の再マウント可否を見ないため、`auto` は namespaced を選んだ後に起動拒否になり native へ回らない（**新規**。方式選択の設計表では「namespaced が利用不可なら native」） | P1 | PR-35 |
| V-6 | version 2 ポリシーの移行判断材料を `check` が出す（改善案 6） | **確認**。PR-28 の `policy resolve --version-diff`（[policy_resolve.rs](../src/commands/policy_resolve.rs) `279-330`）が同じ計算を持つが、`check` からは呼ばれない。`check` は `policy.version` を audit context として JSON に載せるだけ | P2 | PR-36 |

レポートの受け入れ条件との差分:

- V-2a は「雛形の明示指定」ではなく、起動 argv から解決した事実（インタプリタの prefix・パッケージツリー）に根拠を持つ読み取り許可だけを投入し、環境変数はコメントアウトした候補に留める（D-7）。宛先・値を推定しない点は同じ。
- V-3 の「欠落を失敗にするオプション」は今回設けない（D-8）。
- V-4 は新しい outcome 値（`enforced`）を足さず、`tools_list.filtered` の outcome を `success` に改めて値域と割当を文書化する（D-9）。
- V-5b は表示の改善に加えて、起動前プローブに proc 再マウント可否を加える（D-10）。これは `auto` の選択結果を変える（従来は起動時に失敗していた環境で native を選ぶ）ため、判断事項として分ける。

### 9.2 判断事項

| ID | 論点 | 推奨 | 代替 |
|---|---|---|---|
| D-7 | ドラフトへのインタプリタ用ファイル読み取り許可の自動投入をフラグで gate するか | gate しない。解決済みの interpreter prefix とパッケージツリーは起動 argv から得た事実で、PR-21 が無条件で投入する syscall ベースラインと同じ根拠を持つ。投入した行には由来コメントと REVIEW を付け、運用者が削れるようにする | `--runtime-baseline <node\|python>` の明示指定時のみ投入し、未指定時の出力は現状と同一に保つ |
| D-8 | 許可リストの環境変数が親環境に無いときに起動を失敗させるオプションを設けるか | 今回は設けない。欠落は plan・report・監査に名前で残し、値は残さない。厳格運用が必要なら CI で `plan` の `launch.env` を検査する。必要になった時点で `environment { require "NAME" }` のようなポリシー属性として別途設計する | `run --strict-env` を追加する |
| D-9 | `tools_list.filtered` の outcome | `success` に改める（action は `denied` / dry-run は `observed` のまま）。`tools/list` 要求は成功して応答が届いているので、「outcome は要求された操作の結果」という現行の規約と整合する。要求をエラーで拒む `tool_call.denied`・`mcp_message.denied` と、`hash.mismatch`・`tools_list.verified` の blocked は `failure` のまま。outcome の値域と各イベントの割当を guide に表で固定し、「拒否の検出は `action=denied` で行う」を監視側の指針として書く | (a) 新値 `enforced` を追加する — 値域が広がり、`failure` で拒否を数えていた消費者の移行コストは同じ。(b) 全拒否イベントの outcome を「執行の成否」に再定義する — OCSF の status に近いが、`tool_call.denied` など複数イベントの破壊的変更になる |
| D-10 | namespaced の起動前プローブに proc 再マウント可否を加えるか | 加える。プローブは新しい mountns の中で init と同じ手順で `mount("proc", ...)` を試し、失敗を `missing: ["proc_mount"]` として報告する。`auto` は方式選択の設計表どおり native（要求を満たす場合）へ回り、理由が plan / report に残る。`namespaced` 明示指定は従来どおり拒否 | プローブは変えず、起動失敗時のヒントだけを出す |
