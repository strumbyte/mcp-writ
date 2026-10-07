# 改善計画 — 評価メモ (2026-10-07) 対応版

対象: v0.2.0 / tip `562ea185`。評価メモ (`mcp-writ-eval-2026-10-07.html`) の
指摘と今後提言を、コード実測と突き合わせて計画化したもの。

PR 単位の作業順序は [improvement-pr-guide-2026-10.ja.md](improvement-pr-guide-2026-10.ja.md) を参照。

設計原則（レポートと同じ）:

- 通信の**中身は見ない**。制御するのは**宛先**だけ（制御面の延長）
- 宛先制御は **ドメイン層（DNS ゲート/名前ポリシー）+ IP 層（接続時強制）**
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
- **IP 層（CIDR / リテラル IP）**: `connect()` 時点の強制。
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
  IP 拒否は接続時点で fail

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

### 1.3 データプレーン（Linux）— 実装選択肢の再評価

Landlock（V4）は宛先をバインドできずポート粒度が上限。宛先制御には別機構が
必要。3 案 — **ドメイン層を届けられるか** が最大の分かれ目:

| 案 | 特権 | IP 層 | ドメイン層 | 評価 |
|---|---|---|---|---|
| **a. seccomp user notification** | 非特権 | ○ connect sockaddr 検査 | △ 53/853 をゲート宛先に限定する拒否は可、DNS 応答の収集は不可 | **IP 層の本命候補**。既存 seccomp 基盤の延長。単体では FQDN を届けられない |
| **b. cgroup eBPF** `INET4/6_CONNECT` | 要特権（CAP_BPF 等） | ○ + deny イベント観測可 | △ 同左（DNS ゲートと組合せれば両立） | 権限あり環境の opt-in 強化。「非特権 CLI」モデルと衝突 |
| **c. userns+netns+mountns + ユーザ空間プロキシ** | 非特権 | ○ | **◎ resolv.conf 支配 + DNS ゲート内蔵 + 全 TCP 経由** | **ドメイン制御の本命**。実装量は最大（tun + smoltcp 相当） |

- (c) は bubblewrap 型の完全非特権ルート: 子を userns+netns+mountns に
  入れ、`resolv.conf` を自前 mount で差し替え、DNS はゲート宛て固定、
  TCP は宛先チェック付きユーザ空間プロキシのみ経由。QUIC 等
  非 DNS UDP は既定拒否（ポリシー化）
- (a) は plain spawn モードの IP 層として存続価値あり: mountns が無いと
  resolv.conf を差し替えられないため、名前解決がゲートを通る保証がない点は
  能力差として正直に明記（「plain spawn = IP 層のみ、namespaced = 2 層」）
- 推奨順序: v0.3 で (a) IP 層 PoC + **DNS ゲート単体**（設定ベースで先行
  利用可能）→ v0.4 で (c) netns プロキシ PoC = FQDN の実効強制、
  (b) eBPF opt-in

(a) の既知の論点:

- supervisor は子プロセスメモリの sockaddr を読む（process_vm_readv /
  `/proc/pid/mem`）。deny 判定は通知時点で閉じるため実害は限定的だが、
  「引数検査〜実使用の隙間」と同型の限界として docs に明記する
- `SECCOMP_USER_NOTIF_FLAG_CONTINUE`（kernel 5.5+）で許可側のオーバーヘッドを
  最小化できる
- UDP/RAW socket・`sendmsg`/`sendto` の扱いは別途設計（v0.3 は TCP connect のみ）

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
| userns+netns+mountns + ユーザ空間プロキシ | FQDN の実効強制（resolv.conf 支配＋全 TCP 経由） | v0.4 PoC |
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
| **v0.4** | §1.3(c) netns プロキシ PoC（FQDN 実効強制）+ §1.3(b) eBPF opt-in + §1.5 macOS プロキシ経路 + §3.3 Windows 既定化/ARM64 + §3.1 capability matrix |
| **v0.5+** | §5.1-5.2 ポリシー運用 + netns プロキシの本番化・UDP/QUIC 方針 + §1.7 残存リスクの継続評価 |

## 7. 非目標（継続）

レポート同様、以下はスコープ外を維持: Remote MCP ゲートウェイ、応答
ボディの DLP/DPI、LLM による中身判定、「FQDN を書けば絶対安全」の宣伝。
