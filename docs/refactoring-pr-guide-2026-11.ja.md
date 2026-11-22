# mcp-writ リファクタリング PR別実装手順書

策定日: 2026-11-16。照合基準: `23d8e82764d3428e5f4bf719b3eba822c582cba1`、v0.5.2。

本書は[リファクタリング計画](refactoring-plan-2026-11.ja.md)を実装するエージェント向けの手順書である。計画書は目的・優先順位・依存関係・採否の判断を、本書は変更箇所・作業順・回帰検証・性能測定・完了記録を扱う。RF番号は両書で共通とし、既存のPR番号とは区別する。

構成は[過去の実装手順書](archive/improvement-pr-guide-2026-11.ja.md)に合わせた。ただし、過去資料の完了チェック、PR番号、性能値、OS検証結果を今回の作業の実施証跡として転記しない。本書のチェックリストは策定時点ではすべて未着手である。予定する型名・target名・分割先は案であり、既存APIや実行済みコマンドを意味しない。

## 0 実装担当エージェントの開始手順

### 0.1 読む資料と現在地の確認

1. 適用される`AGENTS.md`とユーザーの指示を確認する。[計画書](refactoring-plan-2026-11.ja.md)、[modules](modules.md)、[development](development.md)、[test matrix](test-matrix.md)を読み、担当RFの依存と保証を確認する。
2. リポジトリルートで次を実行し、HEAD、作業中の変更、toolchainを記録する。行番号は移動するため、本書のファイルとシンボルを`rg`で再検索する。

   ```text
   git status --short
   git rev-parse HEAD
   rustc -Vv
   cargo -V
   ```

3. 担当RFに必要な先行作業が、どのcommit・テスト結果で完了したか確認する。基準HEAD以降に実装が変わっていれば、当該節の現状説明と差分を先に記録する。既存のユーザー変更を上書き・巻き戻ししない。独立checkoutを使う場合は、未commit差分を比較対象に含めるか明示する。
4. 変更範囲、依存、確認する入力・出力・不変条件、必要なOS、計測IDをPR単位で確定する。無関係な型整理や依存更新を同じPRへ混ぜない。共有ファイルの並行編集は避け、先行PRのAPIが確定してから後続作業を始める。
5. 関連する既存テストと基準計測を行う。失敗・skip・0件・環境不足は修正前の状態として区別する。実行できないOS経路は未検証として残し、その経路を含む移行の完了条件を下げない。

基準時点の証拠は次の範囲に限る。前回レビューのWindows実行では計2,681件が成功し、`audit_reopen_e2e`は0件だった。別途の既定featureの一覧取得ではlib 2,513件＋integration 740件＝3,253件が登録されていた。後者は`--list`の結果であり実行成功ではない。監査分類とDNS重複予約は現行ライブラリで再現済み。監査の分岐飢餓は同じTokio版の最小モデルで確認した段階のため、RF03では製品writerで再現を固定する。

### 0.2 PRを進める単位

- 挙動の修正、性能改善、テストの移動・削除を別PRにする。RF00／RF-T00の関連基準が取れれば、RF01〜RF03は残りの全測定やテスト整理を待たず着手できる。
- RF05bの前にRF-T01のschema検証、RF09の前にRF-T02、RF10のInspector変更の前にRF-T03のInspector移行を完了する。各節の直接依存も満たす。
- 新しいケースが必要なのは、未検証の保証、新しい失敗経路、今回修正する不具合を捉える場合である。実装の形を写すだけのテストや、全ケースへ同じ故障注入を追加しない。削除時は旧assertionと残存assertionの対応を残す。
- 追加する型・helper・cacheは担当モジュール内に閉じ、テスト都合で公開APIを拡張しない。標準ライブラリと既存依存を優先し、新規依存やFFIが必要なら[開発方針](development.md)に従って根拠を記録する。
- 日本語文書はUTF-8・BOMなし・LFで扱う。文字コード問題が疑われるファイルは編集前にバイト単位のバックアップを作り、原文確認なしに本文を再生成しない。PowerShellでの読書きは文字コードを明示し、保存する差分と保存後のencodingを確認する。

### 0.3 担当作業への入口

| 系列 | 手順 |
|---|---|
| 基準取得 | [RF00](#rf00)・[RF-T00](#rf-t00) |
| 正しさの修正 | [RF01 拒否分類](#rf01)・[RF02 DNS予約](#rf02)・[RF03 監査順序](#rf03) |
| 要求とpolicy | [RF04 解析共有](#rf04)・[RF05a policy準備](#rf05a)・[RF05b schema再利用](#rf05b) |
| 監査とDNS | [RF06 writer](#rf06)・[RF07 DNS索引](#rf07) |
| 構造整理・追加改善 | [RF08 観測](#rf08)・[RF09 起動責務](#rf09)・[RF10 個別改善](#rf10) |
| テストの整理と修正 | [RF-T01 重複](#rf-t01)・[RF-T02 成功判定](#rf-t02)・[RF-T03 target統合](#rf-t03) |
| テスト・CI性能 | [RF-T04 fixture](#rf-t04)・[RF-T05a 実行0件](#rf-t05a)・[RF-T05b CI集約](#rf-t05b) |

## 1 共通の保証・検証・測定

### 1.1 維持する条件

| 対象 | 維持する契約 |
|---|---|
| 認可 | deny優先、server binding、未指定と明示的な空allowの区別、既存の許可・拒否結果 |
| MCP | raw ID、数値IDの精度、重複キー拒否、対応version、MRTR、内部IDの秘匿、stdoutの用途 |
| tools/list | advertised全体を検証してから表示を絞る。再検証中の拒否と、転送直前の世代確認を残す |
| セッション | confused deputy、trajectory、キャンセル後の未確定実行状態、件数・バイト上限 |
| 実行対象 | 開いた対象と実行する対象の同一性、spawn直前の確認、必要期間のpin保持、環境変数制限 |
| 監査 | 永続化成功前に保護対象を転送・公開しない。失敗ラッチ、ファイルと名前の一致、親ディレクトリ同期、回転順序 |
| DNS権限 | 名前別TTL、protocol・port、TTL短縮、commit前の不可視性、トークン別rollback、資源上限 |
| OS管理 | cgroup・Job・PID namespace等の子孫管理、ACL復元、ハンドル回収、OS別shutdown動作 |
| 観測と解析 | intentとobservation、Unknownと成功、Partialと完全解析を区別する |

変更前後で比較するのは正常応答だけではない。拒否理由、監査分類、終了コード、失敗する段階、イベント順序、ファイル・子プロセス・権限の残存も含める。時刻やUUIDは比較時に対応付けるが、親子IDやreportとの相関関係は検査する。

### 1.2 回帰テスト群と必要環境

| 群 | 既存targetと追加する検査 | 必要環境 |
|---|---|---|
| T-BASE | `cargo fmt --all -- --check`、`cargo clippy --locked --all-targets -- -D warnings`、fuzz packageの`cargo clippy`、`cargo test --locked --lib --bins --features fuzzing`、`module_layering`、`docs_check`、`capability_matrix`、`manifest_fixtures`、警告をエラーとする`cargo doc --locked --no-deps`。[pr-checks.yml](../.github/workflows/pr-checks.yml)の検査を包含する | 変更対象OS。汎用処理は対応OSで確認 |
| T-DOC | `cargo test --locked --test docs_check`。文字コード・リンク・anchorを確認 | 文書だけの変更でも実行 |
| T-PROTOCOL | `mcp_wire_e2e`、`tool_enforcement_e2e`、`protocol_versions`、`manifest_fixtures`、checker・session・schemaのlib tests。ID／重複キー／MRTR／世代競合の差分試験を追加 | Linux・Windows・macOS、固定Python fixture |
| T-POLICY | `kdl_policy_e2e`、`policy_check_e2e`、`manifest_fixtures`、policyのlib tests。KDL再出力・hash・binding・provenanceの差分 | 対応OS、必要なPython fixture |
| T-AUDIT | `audit_durability_e2e`、`audit_reopen_e2e`、`denial_audit_e2e`、audit lib tests。飽和・回転・disk full・writer終了・ACKの試験を追加 | 共通試験は対応OS。reopen E2EはLinux／macOSで実行 |
| T-DNS | `dns_gate_e2e`、allowlist lib tests。予約上限と参照モデル試験。利用箇所変更時は`unotify_e2e`、`ebpf_e2e`、`linux_mechanism_e2e`、`macos_proxy_e2e` | mock DNSは各OS。kernel連携は該当する実機と権限 |
| T-REPORT | `plan_report_e2e`、`capability_matrix`、`diagnostics_e2e`、`policy_check_e2e` | 対応OS。観測生成側の実行環境も必要 |
| T-LAUNCH | `workload_hash_e2e`、`environment_e2e`、`path_resolution_e2e`、`integration`、`self_test`、Warden lib tests。対象のcontainer／VM／Windows isolation suites | nativeはLinux x86-64／AArch64・Windows・macOS。backendはテストmatrixの実機 |
| T-FUZZ | 既存の`framing`、`jsonrpc`、`dnsgate_wire`、`namespaced_packet`。変更した入力境界のseed再現と既存coverage gate | Linux。namespaced packetはLinux固有 |
| T-INSPECT | 現行は`inspector_arm64_p4`、`inspector_arm64_p5`、`inspector_macho_p6`とinspector lib tests。RF-T03後は同じケースを移した`inspector_contracts`とlib tests | fixture解析はhost非依存 |

対象ごとの短い確認を開発中に行い、PRの最後にT-BASEと影響群を実行する。広い結合や共通起動処理を変更したPRとリリース候補では、`cargo test --locked`を含む既存の全検証手順を実施する。性能比較をdebugテストの所要時間で代用しない。

例えばRF04のローカル確認は、T-BASEに加えて次を実行する。これは既存targetだけで実行できる。

```text
cargo test --locked --test mcp_wire_e2e --test tool_enforcement_e2e --test protocol_versions --test manifest_fixtures
```

RF03・RF06は次を実行し、Windowsの結果だけでreopen完了とはしない。

```text
cargo test --locked --test audit_durability_e2e --test audit_reopen_e2e --test denial_audit_e2e --test dns_gate_e2e
```

最終受け入れでは必要なfixtureと権限を用意し、`MCP_WRIT_REQUIRE_E2E_TESTS=1`、container用の`MCP_WRIT_REQUIRE_CONTAINER_TESTS=1`、実サーバー用の`MCP_WRIT_REQUIRE_SERVER_TESTS=1`、VM／Windows機構用の個別ゲートを、[test matrix](test-matrix.md)の対象に従って使う。環境変数は実行プロセスの範囲だけに設定する。

0件、skip、unavailable、ignoredを成功件数に加算しない。ゲートの有効化だけでは`cfg`で消えたtargetを検出できないため、OS・target別に期待する実行有無も確認する。必要環境がない場合は未検証として残し、その経路の変更を完了扱いにしない。通すためにsandboxを弱めない。

既存のPR checks・手動workflow・release検証を利用する。計測用の手動実行や記録は追加できるが、無関係なworkflowのscheduleや自動起動条件は変更しない。RF09の共有起動変更ではcontainer、Windows Sandbox、WSLC、Kata、Apple container、Hyper-V等の実際に変更された利用経路を網羅し、Go fixtureの互換性確認も維持する。

### 1.3 コマンドの実行と結果の扱い

コマンドはリポジトリルートで実行し、各コマンドの終了コードを確認する。並べて実行して最後の成功だけを記録しない。T-BASEの基本コマンドは次のとおり。

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --manifest-path fuzz/Cargo.toml -- -D warnings
cargo test --locked --lib --bins --features fuzzing
cargo test --locked --test module_layering --test docs_check --test capability_matrix --test manifest_fixtures
```

T-BASEは[pr-checks.yml](../.github/workflows/pr-checks.yml)の検査を包含させる。fuzz packageは`default-members`外にあり、通常のclippyでは検査されない。fuzz façadeの単体テストは`fuzzing` featureを有効にしたときだけ登録される。PRゲートの構成を変えた場合は本節も合わせる。

T-DOCは`cargo test --locked --test docs_check`。文書だけを変更するPRではこれと文字コード・差分確認を行い、製品の全テストは要求しない。T-BASEのrustdoc警告検査は、Bashでは次を実行する。

```sh
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
```

PowerShellでは既存の環境変数を保存し、実行後に戻す。

```powershell
$rfPreviousRustdocFlags = $env:RUSTDOCFLAGS
try {
    $env:RUSTDOCFLAGS = '-D warnings'
    cargo doc --locked --no-deps
    if ($LASTEXITCODE -ne 0) { throw 'rustdoc check failed' }
} finally {
    if ($null -eq $rfPreviousRustdocFlags) {
        Remove-Item Env:RUSTDOCFLAGS -ErrorAction SilentlyContinue
    } else {
        $env:RUSTDOCFLAGS = $rfPreviousRustdocFlags
    }
}
```

最終受け入れのE2Eでは、[test matrix](test-matrix.md)の前提を満たした対象環境で必須ゲートを有効にする。例えばT-PROTOCOLの次の呼出しは、Bashではその子プロセスだけへゲートを渡せる。

```sh
MCP_WRIT_REQUIRE_E2E_TESTS=1 cargo test --locked --test mcp_wire_e2e --test tool_enforcement_e2e --test protocol_versions --test manifest_fixtures -- --nocapture
```

PowerShellの同等例は次のとおり。他のゲートも同様に元の値を戻し、永続的なユーザー／マシン環境変数を書き換えない。

```powershell
$rfPreviousE2eGate = $env:MCP_WRIT_REQUIRE_E2E_TESTS
try {
    $env:MCP_WRIT_REQUIRE_E2E_TESTS = '1'
    cargo test --locked --test mcp_wire_e2e --test tool_enforcement_e2e --test protocol_versions --test manifest_fixtures -- --nocapture
    if ($LASTEXITCODE -ne 0) { throw 'protocol E2E failed' }
} finally {
    if ($null -eq $rfPreviousE2eGate) {
        Remove-Item Env:MCP_WRIT_REQUIRE_E2E_TESTS -ErrorAction SilentlyContinue
    } else {
        $env:MCP_WRIT_REQUIRE_E2E_TESTS = $rfPreviousE2eGate
    }
}
```

filter付き実行は事前に同じfilterで`-- --list`を確認し、期待する名前が登録され、実行時も0件でないことを確かめる。`--exact`を使う場合は完全修飾名を指定する。一覧の取得を回帰試験の代わりにしない。`cfg`による対象外と関数内skipは別に数える。RF-T02以前のWindowsの早期return等はゲートだけでは捕捉できないため、probeの実行証跡を確認する。

T-FUZZは[fuzz manifest](../fuzz/Cargo.toml)と[fuzz workflow](../.github/workflows/fuzz.yml)の現行コマンドを確認し、変更した境界の既存seed・再現入力を実行する。架空のベンチtargetや未導入のツールを実行済みとして記録しない。RF00で計測targetを導入した時点で、その実在する名前とコマンドを記録する。

例えばLinuxでRF04のJSON-RPC境界を確認する場合は、現在のnoprop方式を使う。nightlyやcargo-fuzzへの移行は前提にしない。

```sh
cargo build --release --locked --manifest-path fuzz/Cargo.toml
mkdir -p .local/refactoring/RF04/fuzz-artifacts
timeout 120 ./target/release/jsonrpc --cases 50000 --seed 0x20261116 --crash-dir .local/refactoring/RF04/fuzz-artifacts
```

seedは再現可能な例であり、これ1本を全保証の根拠にはしない。既存の失敗入力は`--replay <実在する入力file>`で再現する。対象のcoverage gate、処理件数、終了コード、失敗・timeoutとartifactを保存し、timeoutを成功に読み替えない。`namespaced_packet`等の予算はworkflowの対象別設定に合わせる。

### 1.4 性能測定の実行手順

#### 比較方法

比較は同一host・CPU条件・OS・Rust toolchain・Cargo.lock・release profileで行う。M項目ごとの基準hostはRF00で固定し、あるhostで取得できない経路の値を別hostの値で代用しない。初期基準`23d8e82`と、各PRの直前親commitの両方を保存し、累積改善と当該PRの効果を区別する。既知の誤動作に依存した高速さを目標にせず、RF03後の監査改善はRF03を含む版を同じ永続化条件で比較する。

親版Aと候補版Bを別のcheckout・build出力先に用意し、予熱2回と測定10組を初期設定として、A→BとB→Aの実行順を交互にする。計測中にビルドや他の負荷試験を並行させない。短い処理は十分な回数をまとめて測り、空ループ・fixture生成・計測器のコストを分ける。要求単位のtail latencyを出す場合は到着時刻も記録し、待ち行列や拒否を測定から落とさない。

通常のRPC計測は各runで少なくとも10,000要求を目安にする。大きい入力やプロセス起動は処理量に合わせた標本数を事前に決め、少数標本からp99を主張しない。成功数、拒否数、タイムアウト数、監査drop数、投入負荷と完了負荷を併記する。セキュリティ検査や監査の無効化で得た値を製品の改善値にしない。

coldとwarmを区別する。OSのキャッシュを制御していない測定は「初回」またはwarmとして記録し、coldと呼ばない。DNS・サーバーは原則ローカルの固定fixtureを使い、外部サービスの揺れを混ぜない。実サーバーと実sandboxの測定は補完として別集計にする。

#### 計測IDと固定する入力

| ID | 固定する入力条件 | 主な指標 |
|---|---|---|
| M1 要求解析 | 1 KiB・64 KiB・1 MiB・既定上限10 MiB近傍。ASCII／日本語、深いobject、不正JSON、重複キー。session機能off／on、並行度1・16・64 | CPU時間、要求p50／p95／p99、throughput、allocation件数・bytes、ピークメモリ |
| M2 ポリシー準備 | tool数1・100・1,000。schemaなし／小規模／配列pattern／local ref／分岐、opaque有無。許可・拒否双方 | 準備時間、初回要求、定常要求、常駐・ピークメモリ、schema parse・regex構築回数 |
| M3 監査 | Buffered／EveryEvent、best-effort／fail-closed、Info／High／commit待ち。通常／飽和、回転・終了、遅いsink | RPCと独立heartbeatのtail latency、同期開始遅延・完了遅延、回転待ち、drain時間、drop、キューbytes |
| M4 DNS権限 | live件数0・100・1,000・16,384、期限切れ率0・50・100%、IP分散／集中、同一キーの並行予約、TTL更新 | 登録・lookup・commit時間、走査件数、lock保持時間、メモリ、期限管理の保持量 |
| M5 起動 | help／version／同期CLI、native run、guest runner。pinなし／あり、実行形式とpayload別、初回／warm | プロセス開始から最初の応答、spawn前準備、終了時間、ピークメモリ、残存プロセス・資源 |
| M6 inspector | 固定したELF／Mach-O、x86-64／AArch64、通常／文字列密集／syscall密集／打切りを起こす入力 | 解析時間、ELF parse回数、allocation、ピークメモリ、解析出力の差分 |
| M7 buildと配布 | 対応target別、同じsymbols条件。clean buildと一ファイル変更後build、各配布binary | build時間、実行file・配布archiveサイズ、起動と代表RPCの性能 |
| M8 テストとCI | 同じOS・Rust・feature・並列度・必須ゲート。整理前後で同じ保証集合。依存の取得条件とcache状態を固定 | test compile／link時間、warm実行時間、fixtureのrustc起動回数、CPU時間・ピークメモリ、CI総実行時間と完了までの時間 |

全条件の直積は実行せず、通常・高負荷・境界の代表ケースをRF00で固定する。allocation計測は利用可能なprofilerやテスト用計数器で時間計測と分離し、計測のためのunsafe実装追加を前提にしない。取得できない指標は未測定と記録する。RSS／working setは同じOS・同じ方式同士で比較し、OS間の数値を直接比較しない。M6の大入力はメモリに合わせて段階的に増やす。M7は他のPRの測定にrelease設定変更を混在させない。

M8は製品性能M1〜M7と別集計にする。空の専用`CARGO_TARGET_DIR`での`cargo test --locked --tests --no-run`と、一度ビルドした後の実行を分ける。fixtureの生成時間はtest buildに含まれるとは限らないため、実行中のコンパイルも数える。対応するOSで影響targetを単独・通常並列の双方で動かし、target統合による共有状態の干渉を確認する。RF-T02による実際の検証の追加コストは別記し、後続の高速化は同じ成功判定を備えた版同士で比較する。CIではqueue待ち、runner上の実行時間、重複jobの合計時間を分け、runner差だけによる改善を主張しない。登録数の削減率を速度向上率に読み替えない。

#### 採否と証跡

1. 機能・セキュリティの一致が先決であり、速度で失敗を相殺しない。RF01〜RF03の意図した修正だけは変更一覧に記録する。
2. RF00で同じ親版同士を比較するA/A測定を行い、指標別の揺れを記録する。暫定的に「3%とA/Aの絶対相対差の最大値の大きい方」を調査開始の帯域とする。初期設定の10組では95パーセンタイルが最大値と区別できないためである。A/Aを20組以上取った場合は、最大値の代わりに95パーセンタイルを使える。これは許容する性能劣化率ではない。帯域が10%を超える環境は安定化して取り直す。
3. 性能PRでは主指標を測定前に一つ以上指定する。親候補のペア差と95%信頼区間、絶対差と相対差を保存し、改善が誤差と区別できることを確認する。信頼区間は独立に反復したA/Bのrunペアを単位に計算し、同じrun内の各要求を独立な反復と数えない。主要ケースで5%以上の改善を調査目標にできるが、達成を約束した値や全処理共通の合否条件にはしない。
4. 小入力、拒否経路、メモリ、起動、終了も確認する。再現する後退があれば、保持方法・共有方法・実装を見直す。差が不明確なら、性能改善を達成した扱いにせず追加計測または保留にする。
5. 正しさの修正は必要な動作を満たすことが受け入れ条件となる。定期fsyncを実際に行うことで生じるI/O等は修正のコストとして記録し、後続の性能PRを同じ保証の版同士で比べる。保守性PRには速度向上を要求せず、検証済みの非後退と責務の明確化を求める。

測定結果はローカルでは`.local/refactoring/<RF番号>/<run>/`等に保存する。A/B用の別checkoutにはgitignore済みの`.local/`と`AGENTS.md`が存在しない。証跡は主checkoutの`.local/refactoring/`へ絶対パスで保存し、適用規則も主checkoutのものを確認する。commit、実際の差分、環境、build引数、fixture hash、seed、負荷・標本数、元の時間列、集計、失敗・skip理由を残す。比較用の元データを残したうえで、共有する集計をPRに添付する。CIの証跡はartifactとして保持する。

### 1.5 入出力と仕様変更の管理

| 項目 | 本計画での扱い |
|---|---|
| 内部関数 | 検証済みview、実行用policy、型付き拒否・観測情報への変更を許容 |
| MCP原文とID | 維持。JSON-RPCを別形式へ変換しない |
| KDLとpolicy hash | 維持。準備済み索引やhash mapの順序を出力・digestに混ぜない |
| 監査JSONLとreport | schema・フィールド・秘匿を維持。RF01の分類修正とRF03の正しい処理順序は修正として記録 |
| DNS予約 | RF02で従来誤って拒否した同一キー予約を受理する。TTL・scope・監査条件は維持 |
| schemaの早期拒否 | 本計画の最初の移行では行わない。必要なら挙動差を列挙した別PR |
| protobuf・依存置換・panic方式 | 今回の必須範囲に含めない。別の根拠と測定がある場合に評価 |

外部のエラー文、終了コード、オプション、ポリシー意味を変更する必要が出た場合は、対象と実例をPRに列挙し、英語・日本語の利用文書を同時に更新する。機能維持の条件に反する変更を、内部リファクタリングとして混ぜない。

## 2 製品実装手順

各項目は未実施の作業として記す。ソース参照は策定時の入口であり、着手時には先行PR後の呼出元を再検索する。新しい型・targetの名称は案であり、既存のAPIとして扱わない。T群・M項目・共通完了条件は第1節と第4節に従う。

<a id="rf00"></a>

### RF00 基準取得と比較手順

直接依存: なし。優先度: 最初。RF-T00を同時に実施する。全M項目の完了をRF01〜RF03の着手条件にせず、各修正に必要な入力と観測を先に固定する。

**目的:** 製品の挙動を変えず、同じ入力・保証・環境で親版と候補版を比較できる状態を作る。

**現状・主な変更先:** [Cargo.toml](../Cargo.toml)、[tests/fixtures](../tests/fixtures)、[test matrix](test-matrix.md)、[開発方針](development.md)。包括的な比較ベンチは未整備である。既存fixtureを優先し、計測targetと記録様式を必要な範囲に追加する。

**タスク**

- [x] `git status`・HEAD・toolchain・Cargo.lock・OS・CPU・features・build引数を記録し、ユーザーの既存差分と今回の変更を分離する。初期基準`23d8e82764d3428e5f4bf719b3eba822c582cba1`と、着手PRの親commitの両方を特定する。 → `.local/refactoring/RF00/run-2026-11-17-01/env.md`（着手時 `git status` は空、`23d8e82` と親 `05f10bf` を特定）
- [x] 第1節のM1〜M8から当該PRの主指標と代表入力を選ぶ。正常・拒否・上限近傍を含め、入力hash、乱数seed、並列度、成功／拒否／timeout／dropの集計方法を固定する。 → `aggregation.md`（主指標 = M1 verdict・内部計数、M3、M4、M5；入力hash・seed `0x5eed_0001`・集計ルールを固定）
- [x] M項目ごとに基準hostを固定して記録する。Unix専用のreopen（M3）、kernel連携を含む経路（M4）、OS別の起動（M5）はWindows機だけでは取得できないため、対象OSのhostを指定する。hostを用意できないM項目は未測定として残し、別hostの値で代用しない。 → `env.md` の host 表、`aggregation.md` の未測定項目
- [x] 安定版Rustで動く`harness = false`の計測target等を用意する。`[[test]]`として登録すると[開発方針](development.md)の標準検証`cargo test --locked`で毎回実行されるため、`[[bench]]`にするか、fuzz packageと同様に`default-members`外のworkspace memberにする。まず`std::time::Instant`、`std::hint::black_box`と既存依存で構成し、必要になった計測ライブラリだけ追加評価する。計測のためだけに製品の公開APIを広げたりunsafeを追加したりしない。 → `bench/` package（default-members 外・`[[bin]]`×5・既存依存のみ）
- [x] 内部計数（parse・重複キー検査・regex構築の回数、走査件数、lock保持時間、同期開始遅延等）の取得手段を、計測targetの実装前に決めて記録する。候補は、`cfg(test)`に限定した計数器と、既存の`fuzzing` featureと同じ形で非default featureの背後に置く計測用façadeである。どちらの場合も既定buildの公開API・挙動・性能を変えず、`module_layering`を満たす。取得手段を決められない指標は未測定として残す。 → 非default feature `measure` + `src/measure.rs` façade を選択し `env.md` に記録
- [x] 第1節のA/A・A/B手順に従い、親候補別のcheckoutとbuild出力先で実行する。実際に追加して動かしたコマンドを文書化し、存在しないbench名を既存手順として記載しない。 → `commands.md`（親 checkout `.local/refactoring/RF00/parent/`・分離 target dir）
- [x] RF01の監査分類、RF02の容量1の重複予約、RF03の継続負荷について再現入力を保管する。RF03は最小モデルだけでなく製品writerの経路を対象にする。恒常的に失敗するテストをRF00へ入れず、製品回帰テストと修正は各RFの同じPRに含める。 → `tests/fixtures/refactoring/rf01|rf02|rf03/`
- [x] RF-T00のtarget・登録名・実行条件・保証対応表を作り、M8のcompile／link・warm実行・fixtureビルド回数を取得する。`--list`を実行成功として数えない。 → `.local/refactoring/RF-T00/run-2026-11-17-01/inventory.md`
- [x] `.local/refactoring/<RF番号>/<run>/`等に元データ、環境、fixture、集計、比較判定、失敗・skip理由を保存する。共有する証跡の置き場とCI artifactの保持方法を決める。 → 本 run dir；共有証跡は PR 添付用の集計（`aggregation.md` 抜粋）と CI artifact は workflow の `*-evidence` upload 慣行に従う

**検証・計測:** T-BASEと追加した計測target。M1〜M8は対象PRに必要な項目から取得する。前回レビューのWindows 2,681件成功、一覧取得の3,253登録、過去資料の測定値は今回の基準値に転用しない。

**完了条件:** 別エージェントが記録したコマンドとfixtureから同じ比較を再実行でき、未測定項目が識別できる。新しいtargetは実行済みで、製品の許可・拒否・出力に差分がない。

**移行・戻し方:** 製品の形式変更はない。計測コードを戻す場合も、後続PRで使うfixtureと測定証跡は保持する。

<a id="rf01"></a>

### RF01 拒否理由の型付け

直接依存: RF00の関連fixture。優先度: A。

**目的:** 拒否文に含まれるユーザー入力によって監査分類やcorrection candidateの対象が変わる状態をなくす。認可結果とクライアント向け秘匿は維持する。

**現状・主な変更先:** [checker.rs](../src/auditor/checker.rs)の`PolicyViolation`、`validation_kind`、`client_reason`、`is_authorization_denial`、`is_denied_target`、[sub_policy.rs](../src/auditor/checker/sub_policy.rs)、[forward.rs](../src/auditor/proxy_c2s/forward.rs)。`validation_kind`は`reason.contains("path traversal")`等で分類し、他の判定もreasonの一致・接頭辞・接尾辞に依存する。

**タスク**

- [x] `PolicyViolation`の全構築箇所と4つの判定メソッドの全利用箇所を`rg`で列挙する。認可、入力検証、対象資源、セッション状態のどこで拒否が決まるかと、既存のwire・監査・reportへの反映を表にする。
- [x] 通常の許可範囲外パスに`path traversal`、引用符、既存の拒否理由と同じ末尾を含める再現ケースを作る。通常の資源拒否と本物のtraversalを別ケースにし、修正前の誤った分類を固定する。
- [x] `PolicyViolation`へ構造化した拒否種別と必要な対象情報を持たせる。生成側が意味を決め、分類側がreasonを再解析しない形にする。型名とvariantは棚卸しした拒否集合に合わせ、全エラー体系の刷新を同じPRへ広げない。
- [x] 表示用reasonを生成する処理と、wireへ出してよい情報を選ぶ処理を分ける。未知toolと非許可toolのクライアント向け理由は同じ文言に保ち、監査側の区別は維持する。
- [x] 監査イベント種別、認可拒否判定、correction candidateの選別を型情報へ移す。対象の綴りの不正、schema不一致、session拒否を、権限拡張で解消できる対象拒否へ混入させない。
- [x] 全構築元を更新後、reasonに対する意味判定が残っていないか再検索する。通常の表示・ログ文言を変更した箇所があれば、意図した監査分類の修正と分けて差分を説明する。

**維持する条件:** deny優先と既存の許可・拒否、未知／非許可toolのwire秘匿、表示文、report schemaを維持する。型付けに伴う公開JSONの追加や全エラー型の置換は含めない。

**検証・計測:** T-BASE、T-PROTOCOL、T-REPORT、`denial_audit_e2e`。通常のパス拒否、本物のtraversal、schema不一致、未知tool、非許可tool、trajectory／deputy拒否を比較する。M1の拒否経路で非後退を確認する。

**完了条件:** ユーザー入力の綴りで分類が変わらず、意図した外部差分が監査の誤分類修正だけである。認可結果・wire応答・correction candidateの除外規則を差分試験で説明できる。

**移行・戻し方:** データ形式の移行は不要。後続RF04の切り戻し時も本修正を保持する。本修正に回帰があれば、文字列分類へ機械的に戻さず、正しい分類を維持する最小修正を優先する。

<a id="rf02"></a>

### RF02 DNS重複予約の修正

直接依存: RF00の関連fixture。優先度: A。

**目的:** grant容量が埋まっていても、別トークンが既に予約している同一キーへの予約を新規キーとして拒否しない。

**現状・主な変更先:** [allowlist.rs](../src/dnsgate/allowlist.rs)の`register_staged_at`、`commit_staged`、`drop_staged`と同ファイルのtests。現在はlive grantとstagedのユニークキー数から容量を判断するが、今回追加するキーが別トークンの予約集合へ既に含まれる場合の扱いが不足する。データ構造の索引化はRF07へ分離する。

**タスク**

- [x] `max_grants = 1`、同じ名前・IP、異なる2トークンで`register_staged_at`を呼ぶ回帰試験を追加する。両方の予約成功と、commit前にliveへ出ないことを検査する。 → `allowlist::tests::staged_same_key_two_tokens_at_capacity`／`staged_same_key_two_tokens_one_live`
- [x] 現在の`GrantKey`の同一性に従って「既存live」「同じトークン」「別トークンに予約済み」「完全な新規キー」を区別し、新規容量の消費が必要な場合だけ上限判定する。protocol・portやTTLの更新意味は変えない。 → `register_staged_at`：live含有・同token inplace refresh・`staged_new` に既出のキーは上限判定を skip、新規キーのみ `live + staged_new >= max` で拒否
- [x] 片方をdropして他方をcommitする順序、逆順commit、既存liveキーへの更新、予約後の期限切れを検査する。あるトークンの取消しが他方の予約やliveを消さないことを確認する。 → `staged_same_key_drop_then_commit_and_reverse_commit`、`staged_refresh_of_live_key_at_capacity`、`staged_entry_expiring_before_commit`
- [x] 同じIPでも名前が異なるキーは別容量として扱い、新規キーの容量超過を拒否する。`is_allowed`、`snapshot_json`、`export_to`のいずれにも未commit予約が見えないことを確認する。 → `staged_distinct_key_at_capacity_refused`、`staged_grants_absent_from_export`
- [x] 呼出側が維持する同時問い合わせ・予約保持量の上限も確認し、ユニークキーだけを数える修正で無制限の予約保持を許さない。 → staged呼出元は`dnsgate::server::process_query`のみ、in-flightは`MAX_INFLIGHT_QUERIES=256`のsemaphore（namespaced経路は`GATE_INFLIGHT=64`）で上限、1tokenあたりのentry数は1応答のaddr数で有界、ユニーク非liveキーは`max_grants`以下を維持。`begin_staging` docに記録
- [x] 非stagedの`register_at`は容量判定でstagedを数えない。直接の`register`とstaged予約が同じ`DynamicAllowList`で混在しないことを呼出元の棚卸しで確認し、前提として記録する。混在する経路があれば、容量判定の扱いを本PRで決める。 → 棚卸し: 直接`register`はmacos_proxy専用リストのみ（`proxy.rs`）、stagedはgateのリストのみで混在経路なし。`register` docと`register_ignores_staged_capacity`に前提を記録

**検証・計測:** T-BASE、T-DNS。RF00で再現した容量1のケースが修正後に成功し、別キーの容量超過は失敗すること。M4の小規模登録経路で修正コストを記録するが、性能向上を採用条件にはしない。

**完了条件:** 同一キーの複数予約、各tokenのcommit／rollback、TTL・scope・不可視性・上限が両立する。意図した仕様差は従来誤って拒否した予約の受理のみ。

**移行・戻し方:** 保存形式の変更はない。RF07を戻す場合は本修正を含む構造へ戻す。本修正の回帰は保証を保つ最小パッチで対処する。

<a id="rf03"></a>

### RF03 監査の順序と公平性

直接依存: RF00の監査基準。優先度: A。

**目的:** 継続投入下でも定期flush／fsyncを開始でき、回転・終了要求が受付順に沿って処理されるようにする。

**現状・主な変更先:** [audit_log.rs](../src/audit_log.rs)の`log`、`log_ordered`、`log_committed`、`reopen`、`shutdown`、[writer.rs](../src/audit_log/writer.rs)の`file_writer_task`・`reopen_sink`。現在はイベントとreopenが別channelで、writerの`biased`な`select!`ではイベント受信が先に評価される。分岐飢餓は最小モデルで確認済みだが、製品writerによる回帰試験を本PRで成立させる。

**タスク**

- [x] 現行の受付・enqueue・永続化ACK・reopen・shutdownの順序を整理し、「受理済みイベント」と容量待ち／dropされたイベントを区別する。回転要求がどこまでの受理済みイベントを待つかを先に定義する。 → 受理=queue投入成功のみ（`log`はcounted drop、`log_ordered`/`log_committed`はbackpressure）と定義し、reopenは自アイテムのqueue位置より前に受理された全記録を旧sinkへ確定する。
- [x] イベントと回転・終了要求の受付順を一箇所で確定し、回転位置を順序上のbarrierとして表す。有界の制御容量を確保して、イベント容量が埋まっても制御要求を永久に投入待ちにしない。待機中のcancelや送信失敗で処理不能な順序の穴を作らず、queue容量・byte permitの解放を確認する。 → 単一`WriterItem`キュー、`event_slots`(4096)と`control_slots`(4)の独立枠。アイテムはsend完了時のみ存在し、permitはdequeue時(byte)／処理完了時(slot)に解放。
- [x] writerが一定件数を処理した時点または期限到達時に時計を確認するようにする。受信queueが空になることを同期開始の条件にしない。処理区切りの上限とflush／fsync期限の扱いをコードとテストで明確にする。 → `CLOCK_CHECK_RECORDS=32`件ごとの境界確認＋アイドル時のみ`sleep_until`起床。M3で継続投入下の同期開始遅延max 14.9µs（busy=12s変種max 6.5µs）を確認。
- [x] successful reopenはbarrier前の記録を旧sinkへ確定し、新sinkのmarkerと後続イベントの順序を保つ。reopen失敗・marker書込失敗・新旧sinkの同期失敗を区別し、既存のエラー優先順位と失敗ラッチを保つ。 → `FileSink::reopen`が旧世代flush+fsync+dir fsync→交換→新世代entry fsyncを一括実施。ErrBeforeSwap／ErrAfterSwap／marker失敗を`result.and(marker_result)`で区別（reopen側優先）。
- [x] テスト用の時計・sinkで連続投入、飽和、複数回転、回転中shutdownを決定的に再現する。時計とsinkの注入はランタイム非依存にし、`tokio::time`の一時停止等に依存させない。RF06で専用スレッドへ移した後も同じ回帰試験を使うためである。現行writerは`BufWriter<File>`と`tokio::time::interval`に直結し、`sink_entry_visible`はファイルと名前の一致を検査する。テスト用sinkで扱う範囲と、実ファイルのケースへ委ねる範囲を先に決める。単なるsleep後の件数検査ではなく、同期開始、barrier位置、marker、ACK、制御受付を観測する。 → `AuditClock`/`AuditSink` trait注入（製品=`TokioClock`+`FileSink`、試験=`ManualClock`+`FakeSink`）。`tests/fairness.rs` 17件でop列・世代・ACK・制御枠を決定的に観測。
- [x] 実ファイルの回転、disk full、書込失敗、名前差替え、親ディレクトリ同期、終了時drainを確認する。永続化ACKは書込・必要な同期・可視性確認のすべてが成功した後にだけ返す。 → `audit_reopen_e2e`（WSL、SIGUSR1・rename差替え・dir fsync）3/3、`audit_durability_e2e`（disk full latch・drain）4/4、sink/logger lib試験で実ファイル回転を確認。

**維持する条件:** 件数・byte上限、best-effort／fail-closed、Buffered／EveryEvent、High記録、失敗ラッチ、ファイルと名前の一致を維持する。受入条件は「期限到達後、次の有限な処理区切りで同期を開始する」であり、OS I/O停止中も5秒以内に同期が完了する保証ではない。workerの専用スレッド化や同期回数削減は本PRへ混ぜない。

**検証・計測:** T-BASE、T-AUDIT、T-DNS。Unix上の`audit_reopen_e2e`実行を必須とする。M3で同期開始遅延と完了遅延、制御待ち、queue bytes、drop、drainを別々に記録する。

**完了条件:** 継続負荷で同期開始が飢餓せず、reopen／shutdown順序と耐久ACKを製品経路で検証できる。正しく同期するために増えたI/Oは修正コストとして記録する。

**移行・戻し方:** 監査schemaは維持する。RF06以降の性能変更を戻すときも本修正を含む版へ戻す。順序やACKに回帰があればリリースせず、保証を維持する最小修正を行う。

<a id="rf04"></a>

### RF04 要求解析の共有

直接依存: RF01。優先度: B。

**目的:** C2S入口で検証したJSONの解析結果を後段へ渡し、同じ要求のparseと重複キー検査の繰返しを減らす。

**現状・主な変更先:** [proxy_c2s.rs](../src/auditor/proxy_c2s.rs)、[forward.rs](../src/auditor/proxy_c2s/forward.rs)、[proxy_wire.rs](../src/auditor/proxy_wire.rs)、[checker.rs](../src/auditor/checker.rs)、[checker/targets.rs](../src/auditor/checker/targets.rs)、[session.rs](../src/auditor/session.rs)と直接の抽出処理。C2S入口、`check_request`、`check_trajectory`、wire抽出関数等に`RawJson::parse`が分散する。

**タスク**

- [x] 通常要求、通知、MRTR、応答、壊れたframeの各経路を追い、parse・duplicate検査・ID抽出・method／tool抽出の呼出回数を基準化する。壊れた入力のID回復用scanを正常要求の解析と混同しない。 → 変更前のroute別`RawJson::parse`回数: 通知・C2S応答=1（gateのみ）。非tools/call許可要求=2（gate＋`request_state_over_cap`）。tools/call許可はsession無しで3（gate＋`extract_tool_name_from_line`(forward_allowed)＋`check_request`）、session有りで＋`extract_tool_name_from_line`(apply_session_gates)=4、trajectory有効で＋`check_trajectory`とその内部の`request_has_host_or_url`=6、`DeputyBinding::Use`該当で＋`extract_deputy_use_targets_rc`=最大7（trajectory成功・deputy-use通過で転送される場合も7）。tools/call拒否はさらに`extract_raw_id`（常時）と`request_state_over_cap`（dry-run時）の再parseを加算。dupkey拒否=gate parse＋`extract_raw_id`再parse、envelope不正（Malformed）=同様に最大2。S2C応答（追跡tools/call）=境界parse＋`RpcId::from_line`で2。route別回数は入力行のparseのみを数える——args_schema検証の`schema.parse`・regex構築・省略されたargumentsに充てる合成`{}`の`RawJson::parse`は、どのrouteの合計にも`json.parse.calls`計測にも含めない別計数とする。壊れたframeのID回復scan（`recover_id_candidates`・`rpc_id_from_raw_id`の合成`{"id":raw}`・oversize窓scan）と`answer_inflight_client_list`のdrain parseは回復処理として正常要求とは別に計上。変更後は構造検査へ到達する全routeでgateの1 parse＋1 dupkey走査を共有する。構文失敗（`FrameReject::Parse`）はdupkey走査へ進まず1 parse・0 scanで、dupkey拒否（`FrameReject::Checked`）とenvelope不正（`WireFrame::Malformed`）はどちらも構造検査を通った側で1 parse＋1 scanに含まれ、保持した`RawJson`からのID抽出のみで再parseなし。壊れたframeのID回復scanは従来どおり回復処理として別計上（下記measure試験はsession有りtools/call経路を実測）。
- [x] 原文frameを保持したまま参照できる検証済みviewを定義する。構築入口を構文・重複キー・深さ等の検証が完了した経路に限定し、未検証値を同じ型へ直接構築できない可視性にする。envelope objectであることの検査はconstructorの保証とは分け、view構築後の`classify_frame`側で実施する設計とする。 → `checker::VerifiedFrame<'text>`（`frame: &'text str`＋`json: RawJson<'text>`、両フィールドprivate）。唯一の構築入口`parse_and_verify`は1回の`RawJson::parse`＋`check_duplicate_keys_recursively`（深さ上限を含む）を通した値のみ生成し、拒否は`FrameReject::{Parse,Checked{json,reason}}`で返す（`Checked`はID回復用にparse済indexを保持）。envelope object判定は`classify_frame`/`check_request_verified`がview上で実施——つまり`[]`や文字列などの非object JSONは構築を通過し得る。`VerifiedFrame`が保証するのは「構文・重複キー・深さの検証済み」までで、envelope objectであることは保証しない。
- [x] method、raw ID、tool、arguments等の必要な参照をchecker・trajectory・deputyへ渡す。所有権と借用がasync境界を越えられる範囲を決め、借用維持のためにsession lockの保持期間を延長しない。 → `WireFrame<'a>`が`method: Cow<'a,str>`・`raw_id: &'a str`を借用し`classify_frame`で共有。`check_request_verified`・`check_trajectory_json`・`request_state_over_cap_json`・`extract_deputy_use_targets_rc`・`extract_tool_name_from_json`/`extract_raw_id_json`は全て`&RawJson`/`&VerifiedFrame`受取。`apply_session_gates`は`view.json()`をlock内の同期検査へ借用渡しするだけで、lock保持は検査区間のみ（`apply_response_session_updates`は分類済`&RpcId`を受け`RpcId::from_line`再parseを廃止）。
- [x] `check_request(line, policy)`等の既存単体検査入口が必要なら、parseして新入口へ渡す薄いwrapperとして残す。製品の正常経路では検証済みviewを使い、wrapperへ戻って二重解析しない。 → `check_request`/`check_trajectory`/`extract_deputy_use_targets`/`request_has_host_or_url`はparseして`*_json`/`*_inner`へ渡すwrapperとして`pub`維持（bench・legislator等のstandalone入口）。`request_state_over_cap`・`extract_tool_name_from_line`・`extract_raw_id`は`#[cfg(test)]`化。製品経路は`check_request_verified(view)`＋`check_trajectory_json`等のみでline wrapperへ戻らない。
- [x] 原文転送とraw ID表現を保ち、浮動小数化や再シリアライズで数値・エスケープを変えない。エラー経路・監査用文字列・内部ID秘匿も比較する。 → 転送はC2S passthrough経路で`view.frame()`（原文行をそのままwrite）。S2Cは別系統で、dispatcherが行をparseして各handlerへ渡し、応答系routeは受領行をそのままwriteするが、`tools/list`結果は検証後にフィルタ済みの内容で送出する。raw IDは`RawJsonValue::as_raw_str()`の原文スライスで`RpcId`正規化は相関用のみ、監査・応答組立はraw表現を維持。`mcp_wire_e2e`65件・`tool_enforcement_e2e`41件・lib 2559件・`module_layering`16件が全緑でwire出力・拒否文言・内部ID秘匿は不変。
- [x] tools/listの全advertised検証、再検証中の拒否、転送直前の世代確認を保持する。可変sessionの許可状態をviewへ固定して後続の確認を省略しない。 → `forward_allowed`のbusy gate（`list_verification_required`/`list_busy`）、`check_pass`後のadvertised検証、`arm_tools_list`・`register_and_forward_impl`内の転送直前の確認は不変——ただし責務は分かれる: `arm_tools_list`は`list_busy`ゲートをCASで取得するのみで世代は照合せず、tools/list転送は`expected_list_gen`を持たない。世代確認（`expected_list_gen`と`verified_tools.generation`の照合）は`register_and_forward_impl`が`list_epoch`保持下でtools/call転送の直前に行う。advertised検証でも`verified_tools`の同一ロック取得下で`generation==expected`と`names`所属を併せて評価するため、世代とメンバ集合は同一スナップショットから読まれ、片方ずつの読取りに跨がらない。atomicな`list_generation`ミラーは転送可否を制御しない。`apply_session_gates`は引き続き可変`SessionState`をlockしてtrajectory・deputy・pending登録を実施し、viewは検査への入力であって許可状態の固定には使わない。
- [x] 移行後に製品経路のparse呼出しを再計測し、不要になった中間Stringや二重検証を除く。S2C全体の刷新やRPCの形式変更へ範囲を広げない。 → `measure`試験`allowed_tools_call_runs_one_parse_and_one_dupkey_scan`が、`VerifiedFrame::parse_and_verify`構築＋`forward_allowed`（session有り・trajectory有効でsession gateも実施）の区間でparse1・dupkey1・childへの原文転送を、スレッドローカルの`CountWindow`で隔離して固定。計測対象はC2S入口`parse_and_verify`と`forward_allowed`までで、`classify_frame`と`c2s_*`ディスパッチは上流側（同一`RawJson`を共有する設計どおり）だが本試験はC2Sエントリポイント自体を通さず、全route実測ではない。`WireFrame`借用化で`method`/`raw_id`の中間`String`割当を撤去、`Malformed`経路の`extract_raw_id`再parseと`or_else`再parse、S2C `apply_response_session_updates`の`RpcId::from_line`再parseを除去。S2Cは最小修正に留め、wire形式・RPC形式は不変。M1のstandalone API計数（3 parse/行）はwrapper契約として基準維持。

**検証・計測:** T-BASE、T-PROTOCOL、T-FUZZの`jsonrpc`。重複キー（エスケープされた同名キーを含む）、深さ上限、数値／文字列ID、巨大整数、MRTR、欠落arguments、dry-run、list_changedと転送の競合、キャンセル後の未確定状態を差分比較する。M1でparse／duplicate検査回数、大小frameのCPU・allocation・tailを確認する。

**完了条件:** 解析回数が減り、既存の認可・session・wire・監査結果を維持する。改善が測定誤差と区別でき、保持frameの長寿命化によるメモリ後退がない。

**移行・戻し方:** 外部形式は不変。入口の共有をPR単位で戻せる構成にし、RF01の型付き拒否は維持する。比較用の旧実装を恒久的な製品分岐として残さない。

<a id="rf05a"></a>

### RF05a 実行用ポリシーの準備

直接依存: RF04。優先度: B。

**目的:** 同じセッションで不変のツール検索・opaque宣言の構築を要求ごとに繰り返さない。

**現状・主な変更先:** [policy/mod.rs](../src/policy/mod.rs)、[opaque.rs](../src/policy/opaque.rs)の`OpaqueMatcher`、[auditor/mod.rs](../src/auditor/mod.rs)の`Auditor::new`、[checker.rs](../src/auditor/checker.rs)、[sub_policy.rs](../src/auditor/checker/sub_policy.rs)、[checker/targets.rs](../src/auditor/checker/targets.rs)。checkerはtool配列の`any`／`find`を複数箇所で行う。`OpaqueMatcher::build`の呼出しは`sub_policy.rs`と`targets.rs`にある。準備済み表現は新設する内部構造であり、既存の型名を前提にしない。

**タスク**

- [x] load・検証・server bindingとAuditor生成の呼出順を追い、ツール集合が確定する地点を特定する。ポリシー生成・KDL出力・hash計算の利用側も一覧化する。 → 確定地点は`Auditor::new`（`src/auditor/mod.rs`で`PreparedPolicy::new`を一度だけ実行）。KDL出力・hash・provenanceの利用側は`document()`／`Deref`経由で不変の`Policy`を読む
- [x] 確定したポリシーから実行用表現を一度だけ準備する。ツール名から元定義を参照できる索引と、ツールごとのopaque matcherを構築する。可変OS状態やrequest／session状態は含めない。 → `src/policy/prepared.rs`新設：`PreparedPolicy`（文書所有＋`HashMap<Box<str>,ToolSlot>`索引＋`Vec<PreparedTool>`：opaque matcher・解析済み`side_effect`・解決済み`input_responses`）
- [x] 同じ文字列・ツール定義の多重保持を避け、共有が必要な箇所だけ`Arc`等を使う。索引の寿命を元定義の寿命に結び付け、policyの更新・再生成がある経路では古い準備結果を再利用しない。 → 複製は索引キーの`Box<str>`のみ（HashMapがVecから借用不可のため）。`Arc<PreparedPolicy>`をC2S／S2C・tools/listが共有。文書所有のため寿命は一致、swapは`set_policy`で全体再準備
- [x] checkerとtools/listの認可・可視性判定を同じ準備済み規則へ接続する。deny優先、未指定と明示的空allowの意味、server binding後の重複名処理を保存する。 → 両経路とも`ToolIndex`（`tool_is_allowed(&shared.policy)`等）。`ToolSlot{first,first_allowed}`がfind先頭一致とany(allowed)の非対称を保存。線形走査との判定一致は`auditor::checker::tests::prepared`・`policy::prepared::tests`で差分検証
- [x] 元文書、provenance、KDL出力、policy hashの生成は既存の意味と順序を維持する。hash mapの列挙順を外部の配列・文書・digestへ漏らさない。 → 索引は`.get()`参照のみで列挙しない。`policy::prepared::tests::document_forms_are_untouched`が`document()`・`to_kdl()`・`declared_servers()`の一致を検証
- [x] tool数1・100・1,000で準備回数と要求中の再構築回数を観測し、準備時間・常駐量と要求時間を対で測る。 → `bench`に`[[bin]] m2_policy`追加。`policy.prepare.calls`=iterations+1、`policy.opaque.matcher.builds`は準備フェーズのみ（`measure_requests`不変＝要求時再構築0）。release計測: prep p50 0.4µs/5.7µs/159µs、`estimated_resident_bytes` 839B/16.8KB/195.4KB、要求p50約128µsでtool数に依らず一定

検証結果: `cargo test --lib` 2,585件・`--features measure` 2,587件・統合テスト全pass（重複名・opaque重複／階層・資源形拒否・空allow・inherit／include／when・複数サーバーは既存スイートで確認）。`windows_sandbox_vm_e2e` 3件は`wsb`バイナリ未導入の環境不足で未検証として残す。RF04の解析共有（`VerifiedFrame`経路）は不変。

**検証・計測:** T-BASE、T-POLICY、T-PROTOCOL。複数サーバー、binding後のtool名、inherit／include／when、空allow、opaque宣言の重複・階層・既知資源形の拒否を検査する。M2で起動・初回・定常要求・常駐メモリを比較する。

**完了条件:** 実行中に不変な索引・matcherが一度だけ構築され、許可結果と文書・hashに差がない。要求処理の改善が起動・メモリの後退で相殺されていない。

**移行・戻し方:** 外部policy形式は変更しない。準備済み表現の内部利用を戻せる単位にし、RF04の解析共有は保持する。schema構築と起動全体の所有権変更は後続へ分離する。

<a id="rf05b"></a>

### RF05b スキーマの再利用

直接依存: RF05a、RF-T01のschema assertion確認。優先度: B。

**目的:** 解決済みschema・参照先・patternを再利用し、評価の意味と資源上限を変えずに要求ごとの構築を減らす。

**現状・主な変更先:** [schema_validator.rs](../src/auditor/schema_validator.rs)の`resolve_schema`、`validate_arguments`、`validate_value`、[schema_spec.rs](../src/schema_spec.rs)、実行用ポリシー準備処理。現状は`validate_arguments`ごとにschemaをparseし、到達したpatternを評価時にコンパイルする。branch・node・depth・数値計算のbudgetと、Fatal／通常不一致の区別がある。

**タスク**

- [x] 現行評価器の順序とエラーを固定入力で採取する。RF-T01で`additionalProperties`のどのキーを拒否したかを検査できる状態にし、弱いassertionを同等性の根拠にしない。
- [x] 通常KDL経路のロード済みschemaと、直接APIの`@file`経路を区別する。後者のCWD内制限、symlink差替え防止、サイズ上限、更新時の再読込意味を記録し、ファイルパスだけによる無期限cacheを導入しない。
- [x] 不変schemaを再利用可能な表現へ変換する。local `$ref`は参照先の索引で扱い、循環を再帰展開して保持量を増やさない。patternは同じschemaの同じ定義を再利用する。
- [x] 構築処理の入力bytes・ノード数・保持メモリの境界を定める。従来受理したschemaを新しい準備上限で拒否しないよう、必要なら意味を保つ遅延構築を使う。同等性を保てない上限変更はこのPRから分離する。
- [x] 評価順序、最初のエラー、Fatalと通常不一致、エラー発生段階を維持する。従来到達しない分岐の不正pattern等を起動時に一括拒否せず、評価時に同じ結果となる不正ノード表現等を用いる。
- [x] branch・node・depth・`multipleOf`等の計算budgetは要求ごとに初期化し、cache済み構造を通っても必要な消費を行う。評価済み結果を入力間で無条件に再利用しない。
- [x] `anyOf`／`oneOf`／`allOf`、循環・不正参照、未知keyword、`uniqueItems`、数値同値、`multipleOf`、欠落argumentsの空object扱い、入力上限を旧評価器と比較する。旧評価器は比較用のテスト範囲に一時保持し、製品の二重実装を解消する。
- [x] schema parse・regex構築回数、準備コスト、初回要求、定常要求、メモリを比較する。遅延構築する場合は同時初回要求の重複構築や同期待ちも測る。 → prepared側の常駐量は`estimated_resident_bytes`の値で、lazy memo充填前の構造的推定（コンパイル済みregexプログラムとマッチ用スクラッチ領域は含まない）。warm済み常駐メモリの実測値としては扱わない

**維持する条件:** JSON Schemaの対応範囲、`format`等のannotation扱い、既存のエラー文・順序・タイミング、MRTRの`inputResponses`をarguments schemaへ混ぜない条件を保つ。起動時一括拒否やファイル更新意味の変更を最適化として混入させない。

**検証・計測:** T-BASE、T-POLICY、T-PROTOCOL、schema単体テスト。M2でschemaなし・小規模・配列pattern・local ref・分岐・不正schemaを比較する。

**完了条件:** 固定入力の判定・最初のエラー・budget境界が一致し、構築回数と主指標が改善する。起動・初回・常駐量に説明できない後退がない。

**移行・戻し方:** 準備済みpolicyのschema部分を独立して戻せるようにする。RF05aの索引とRF-T01の正しいassertionは維持する。外部schemaのmigrationは発生させない。

<a id="rf06"></a>

### RF06 監査writerの専用スレッド化

直接依存: RF03。優先度: B。

**目的:** 同期ファイルI/Oが非同期workerを占有する状態を避け、監査と無関係なタスクの遅延を減らす。

**現状・主な変更先:** [audit_log.rs](../src/audit_log.rs)、[writer.rs](../src/audit_log/writer.rs)、sinkハンドル、shutdown待機部分。現行file writerは`tokio::spawn`されたasync task内で同期書込・`sync_all`を行う。tracing sinkは別経路なので、durable file sinkと同じ保証だと扱わない。

**タスク**

- [x] RF03後の受付順、制御barrier、byte permit、ACK、失敗ラッチ、停止手順を基準にする。writer所有物とasync側が必要とする結果を列挙する。 → `WriterEnd`（`audit_log.rs`）：file sink=`Thread(FileWriterSpawn{join,ticker,done})`、tracing=`Task(JoinHandle)`。writer所有物はsink・BufWriter・deadlineを`WriterCore`内に閉じ、async側の結果は完了oneshot・reply/ack・`writer_failed`ラッチのみ
- [x] file sink・writer buffer・同期I/Oの所有権を一つの専用スレッドへ移す。イベントごとにスレッドやblocking taskを生成せず、loggerの寿命とwriterの寿命を対応付ける。 → `spawn_file_writer`＋`file_writer_thread`：`std::thread`を1本/logger（`mcp-writ-audit`名）で生成し`rx.blocking_recv()`でdrain。`WriterCore`は無改変で順序・耐久判定を共有
- [x] async側は有界受付と完了通知を使い、writer終了待ちの同期joinで実行workerをブロックしない。既存のbackpressureとpermit解放を維持する。 → `FileWriterSpawn.done`（oneshot）を`shutdown()`が`(&mut spawn.done).await`で待機。`JoinHandle`はdetachのみで同期joinなし。queue・permit会計は非改変のためbackpressure・permit解放は同一セマンティクス
- [x] 受付停止 → 受理済みqueueのdrain → 最終同期・可視性確認 → ハンドル解放 → 終了結果通知の順を明示する。送信者がすべて切断した場合と明示shutdownの双方を扱う。 → `file_writer_thread`：channel close→`drain_finish`（最終flush+fsync+必要時dir sync+`entry_visible`）→`drop(core)`/`drop(rx)`→`done_tx.send`の順。明示shutdownは`tx`のtake、自然終了は全sender切断。`AuditLoggerInner::drop`も同じclose経路
- [x] writerの異常終了、未完了ACK、回転中shutdown、低速sink、送信者cancelを検査する。失敗が全待機者へ伝わり、未同期ACKが成功にならないことを確認する。 → `WriterFaultGuard`（panic unwind中に`FailureFlag::set`→`failure_watch`全購読者へ伝播）＋新規試験`test_writer_abnormal_exit_reports_failure`・`test_shutdown_waits_out_in_flight_io`・`test_cancelled_shutdown_resumes_the_wait`・`GateSink`/`write_gate`/`sync_gate`による低速sink。未完了ACKはcoreと共にdropされwaiterはfail-closedで`AuditUnavailable`
- [x] 実行中のOS I/Oは任意に中断できない前提で停止遅延を報告する。timeoutで失敗ラッチを解除したり、未完了drainを成功にしたりしない。 → `AUDIT_DRAIN_NS`（`rx.is_closed()`初検出→`drain_finish`→ハンドル解放→`done`までの全窓）。`shutdown()`のdone待ちはtimeoutを持たず、未完了drainを成功として報告しない
- [x] RF03の順序・公平性回帰を、RF03で導入した時計・sinkの注入を変えずに新worker上で実行し、非監査heartbeat／RPCと監査同期・終了を別々に測定する。 → fairness試験を同一`ManualClock`/`FakeSink`で`spawn_file_writer`上に移植し24/24 pass。`m3_audit`へ`heartbeat_delay_ns`・`spin_delay_ns`・`--workers`追加、workers=1 every_eventでparent spin p50 35,096µs→cand 1µs。`audit.drain.ns`と非監査遅延は別集計 → `.local/refactoring/RF06/evidence.md`

**維持する条件:** 耐久ACK、親ディレクトリ同期、sink identity、失敗ラッチ、回転順序、drop／backpressure、全件drainを維持する。group commitや`--audit-sync`の同期頻度変更は含めない。

**検証・計測:** T-BASE、T-AUDIT、T-DNS、T-PROTOCOL。M3の通常・飽和・遅いsinkで非監査p95／p99、同期完了、drain時間を比較する。Unix reopen E2Eを省略しない。

**完了条件:** 同期I/Oがasync workerから分離され、同じ保証で非監査遅延が改善する。ACK・終了・回転・メモリの回帰がなく、異常終了を成功と報告しない。

**移行・戻し方:** RF03後のasync writerへ戻せる単位にする。永続形式や同期頻度は変更しない。稼働中writerの所有権を差し替えず、セッション停止とdrain後に切り替える。

<a id="rf07"></a>

### RF07 DNS権限の索引化

直接依存: RF02。優先度: B。

**目的:** IP判定時の全集合走査とstaging時の集合再構築を減らし、判定と監査情報を同じ状態から取得する。

**現状・主な変更先:** [allowlist.rs](../src/dnsgate/allowlist.rs)、[flow_gate.rs](../src/warden/flow_gate.rs)とgrantの直接利用箇所。allowlistは名前・IPのgrant集合を走査し、`FlowGate::verdict`は`names_for`と`is_allowed`を別々に取得する。stagingの容量確認も予約集合を構築する。

**タスク**

- [x] `register`・staging・commit・drop・revoke・expiry・snapshot・exportと全利用箇所を列挙し、ロック境界と名前・IP・qualifierの意味を記録する。 → op×lock×意味の一覧表と全consumer（gate staging系・FlowGate・unotify・namespaced stack・macOS proxy・ebpf snapshot・bench）を棚卸し → `.local/refactoring/RF07/run-2026-11-22-01/inventory.md`
- [x] IPから名前別grantへ到達できる索引を導入する。元のキー同一性と名前別TTLを保ち、同じIPの別名を一つのTTLへ潰さない。 → `Inner.by_addr: HashMap<IpAddr, HashMap<String, GrantEntry>>`（allowlist.rs）：キー同一性は (addr,name) のまま、各 `GrantEntry.expires` が名前別TTLを保持。`same_addr_names_expire_independently` が同一IPの独立失効を確認
- [x] 判定に使うcovered状態と監査用の名前集合を同じロック内のsnapshotから返す内部入口を用意し、FlowGate等の利用側を更新する。既存の名前の出力順・protocol／port・DNS64のjudged endpoint・literal IP専用拒否の意味を変えない。 → `grant_view`/`grant_view_at`→`GrantView{names,covered}`を単一ロック下で算出（`grant_view_of`）。`names`は`names_for`と同じソート順、`covered`は`is_allowed`と同じ答え（差分テストが両者一致を確認）。利用側更新：`FlowGate::verdict`、`unotify::Grants::view`、`supervisor`。`judged_endpoint`・`verdict_literal`（macOS）は非改変。全lookupの基準時刻をロック取得後に統一
- [x] stagingにはキーごとの予約数を持たせる。token別rollbackとliveへの昇格に合わせて計数し、RF02の同一キー予約を維持する。commit前はlookup・snapshot・exportから不可視にする。 → `staged_counts: HashMap<GrantKey, usize>`（キー毎のhold参照数）＋`staged_new`（非live予約の逐次カウンタ）で旧`staged_new`集合のper-call再構築を置き換え。`note_live_inserted`/`note_live_removed`/`release_staged_hold`が stage/commit/drop/reap/revoke の各遷移で計数を整合。RF02テスト（`staged_same_key_*`・`staged_distinct_key_at_capacity_refused`・`staged_entry_expiring_before_commit`）全てパス、commit前の不可視性も`staged_grants_are_invisible_until_commit`/`staged_grants_absent_from_export`で維持
- [x] IP索引と予約計数を先に独立コミットにし、その後、期限キュー等の期限管理案を測定して選ぶ。期限キューを使う場合は世代を照合し、古い期限で更新済みgrantを削除しない。 → git非操作方針により単一コミット `07e3978` だが、索引＋予約計数と期限管理は論理分割可能として戻し方を明記（notes.md「コミット分離」節：期限ヒープ除去は`reap_expired`→`retain`復帰で索引側を維持したまま可能）。期限キューは世代スタンプ付き`DeadlineHeap`（`push_deadline`発行、`reap_expired`が世代不一致popをstale skip）。`stale_deadline_never_reaps_refreshed_grant`がTTL短縮・延長双方で古い期限による誤削除がないことを確認
- [x] 古い期限要素の保持が更新回数に比例して増えないよう、有界化または再構築条件を入れる。lookupでも現在時刻とexpiryを判定し、掃除の遅れを権限延長にしない。 → `compact_deadlines`：`deadlines.len() > max(2*live_total, DEADLINE_REBUILD_FLOOR)` で世代一致要素のみへ再構築。新gauge`DNS_DEADLINE_ENTRIES`で保持量を計測可能化。lookup・snapshotは`expires > now`を都度判定し、基準時刻は全てロック取得後。`deadline_heap_stays_bounded_under_update_churn`（600更新でbound+1以下）・`deadline_heap_compacts_on_commit_and_revoke`・`grant_expires_at_its_exact_deadline`が確認
- [x] 単純な参照モデルとseed固定のregister／stage／commit／drop／expire列を比較する。参照モデルは製品へ入れず、同時キー更新、期限ちょうど、TTL短縮、capacity回復を検査する。 → 旧フラット実装を再現したtest-only`RefList`に対し、`indexed_state_matches_flat_reference_model`がseed`0x9E37_79B9_7F4A_7C15`・600ステップのop列を両者へ適用。各ステップ後に`assert_bookkeeping`で`live_total`/`staged_new`/`staged_counts`/deadlineカバレッジを検査し、全addr×(proto,port)グリッドで`grant_view_at`と参照`view_at`を比較（期限ちょうど・TTL短縮・同時キー更新・capacity回復を含む）
- [x] live件数0・100・1,000・16,384、IP分散／集中、期限切れ率、反復更新でCPU・走査数・lock時間・保持量を測る。IP集中時のコストはそのIPの名前数に依存すると明記する。 → `m4_allowlist`の`SCENARIOS`行列（live_0/100/1k/16k・concentrated_16k names_per_ip=64・expired_half/most・churn_1k/16k・staged_same_key）＋`fill_measure`/`lookup_measure`（`is_allowed`プローブ）/`lookup_view_measure`（呼出側と同じ`grant_view`複合プローブ、names収集・ソート込み）/`churn_measure`＋retained/peak bytes。期限切れシナリオはstagedミントでfill中のreapに触れず、保持数=要求数を`live_len`/受理件数のassertで検証。実測（is_allowed側）：live_16kでも~0.5 scan/lookup・p50 532µs（親版は4000×16384≈65.5M scan・全体wall p50比で≈68×）、集中時は当該IPの名前数(64)に依存、churn_16kでdeadline heap 32,764≤2×16,384の有界を確認 → `.local/refactoring/RF07/run-2026-11-22-01/notes.md`・`m4_candidate.json`

**検証・計測:** T-BASE、T-DNS。RF02の全ケース、同一IPの複数名、protocol／port、snapshot／exportを比較する。該当するLinux・macOSのflow利用経路も実機で確認する。M4を用いる。

**完了条件:** 同じ状態遷移に対する許可・拒否・監査用名前が一致し、検索とstagingの主指標が改善する。更新を繰り返しても保持量が無制限に増えない。

**移行・戻し方:** 索引・予約計数と期限管理を分けて戻せるようにする。RF02の修正は維持し、外部snapshot／export形式は変えない。

<a id="rf08"></a>

### RF08 観測事実の型付け

直接依存: RF00の関連基準。優先度: C。RF01とはコード上の依存がなく（RF01は`auditor/checker`系、本作業は`enforcement`と`warden/plan`）、並行できる。T-REPORTを比較する親版は揃える。RF09と同じファイルを並行編集せず、マージ済みのAPIを基準にする。

**目的:** 説明文を読み取って機械向けreportを決める処理を、型付きの観測事実からの生成へ置き換える。

**現状・主な変更先:** [model.rs](../src/enforcement/model.rs)、[summary.rs](../src/enforcement/summary.rs)、[warden/plan](../src/warden/plan/mod.rs)と実際の観測生成元。summaryにはLandlock適用状態を文字列prefixで分ける処理がある。

**タスク**

- [x] summaryがreason等の表示文字列を意味判定に使う箇所と、その生成側を一覧化する。まず該当項目だけに範囲を限定する。 → 意味判定は`EnforcementSummary::build`の`restriction`導出1箇所のみ（`reason.find(RESTRICT_SELF_REPORTED)`+prefix判定）。生成側は`warden/plan/linux.rs`のLandlock backed control observation。`weakened_os_tokens`等他箇所は`ControlState`参照で範囲外と確認
- [x] Landlockの完全適用・部分適用・未適用等の事実と、未観測／Unknown・失敗を表せる内部型を決める。OSから得ていない値をintentから補って成功としない。 → `enforcement::RestrictionLevel`（`FullyEnforced`/`PartiallyEnforced`/`NotEnforced`）＋`EnforcementObservation.restriction: Option<RestrictionLevel>`。`None`が未観測・`NO_RULESET`・`NOT_RUN`・不明コード・非Landlock機構をカバーし、`landlock_fact()`は`ApplySnapshot.landlock`の実測値のみ変換——plan intentからの補完経路は存在しない
- [x] 生成側で観測事実を持たせ、machine reportとhuman reasonをそこから別々に生成する。説明文の変更が機械結果に影響しないようにする。 → `linux_stage_outcome`が`(state, fact, reason)`を返し、factは`landlock_fact`、reasonは`RestrictionLevel::reason_marker()`が従来文言をそのままレンダリング。`enforcement::tests::summary_restriction_ignores_reason_text`で文言変更時の機械結果同一、marker風文字列のみではnullになることを固定
- [x] 既存のreportフィールド、値、順序が契約化されている出力、Unknown、降格、未適用、失敗を固定fixtureで比較する。時刻・UUIDは対応付け、親子IDやauditとの相関は検査する。 → `summary_to_json_shape`が`enforcement`memberのJSON形状・値・順序を固定。Linux観測側は`warden::plan::tests::linux_observations`の`restriction_of`でFULL→Verified+fact、PARTIAL→降格+fact、NOT_ENFORCED→NotApplied+fact、失敗stage→Failed+fact、`NO_RULESET`/`NOT_RUN`/record欠落・不整合→Unknown+fact無しを固定。reportとauditは同一`plan`/`observations`からの生成で相関は既存構造のまま。lib 2606件・`pr03_corpus_matches_reference`等の既存fixture全緑
- [x] 文字列分類を削除し、型未設定の分岐がUnknownまたは既存の失敗へ安全に落ちることを確認する。全control IDやJSON schemaの同時刷新はしない。 → `RESTRICT_SELF_REPORTED`/`LANDLOCK_*_ENFORCED`定数ごと削除しrgで残存0を確認。`landlock_fact`の`_`アームとrecord欠落・不整合の早いreturnは`None`→`restriction: null`。control ID・外部JSON・`enforcement.backend`値は不変

**検証・計測:** T-BASE、T-REPORT、生成側OSのT-LAUNCH。表示文だけを変えた入力で機械結果が同じことを検査する。変更箇所のreport生成とM5で性能非後退を確認する。

**完了条件:** 対象の機械分類が説明文から独立し、全既存report区分が維持される。未知状態を成功へ寄せるdefaultがない。

**移行・戻し方:** 外部JSONは変更しない。型付き事実とrendererを一緒に戻せる単位にする。RF01〜RF03の修正には影響させない。

<a id="rf09"></a>

### RF09 起動処理の責務分離

直接依存: RF05b・RF06・RF08・RF-T02。優先度: C。RF-T02でWindowsの起動失敗・ACL復元・子孫回収の検証が成立してから着手する。

**目的:** 準備済みpolicy、検証済みworkload、spawn結果、稼働sessionの責任と所有者を明確にし、共通の失敗処理を集約する。

**現状・主な変更先:** [runtime/launch.rs](../src/runtime/launch.rs)、[runtime/wait.rs](../src/runtime/wait.rs)、[runtime/lifecycle.rs](../src/runtime/lifecycle.rs)、[main.rs](../src/main.rs)、[mcp-secure-runner.rs](../src/bin/mcp-secure-runner.rs)、[container/runner.rs](../src/container/runner.rs)、必要なWarden呼出境界。共有`launch`はhostとguestから呼ばれ、resolve → verify → bind → reverify → spawnの順を持つ。既に`hash::VerifiedWorkload`があるため、同名の状態を重ねて追加しない。

**タスク**

- [x] `LaunchConfig`・`LaunchError`・launch結果の全呼出元を一覧化する。host、guest、選択されたnative機構、container／VM adapterのどこまでが同じ経路を使うかを図または表で示す。
- [x] resolve、verify、bind、直前reverify、sandbox準備、spawn、stdio取得、auditor開始、report公開、待機・終了の各段階を表にする。各失敗で子が起動したか、stdio公開済みか、audit／report、pin・ACL・子孫・一時物の所有者と回収者を記録する。
- [x] 最初のコミットは段階ごとの関数抽出に限定し、順序と入出力を保つ。次に準備済みpolicy・既存VerifiedWorkload・spawn後リソース・sessionの所有権を移す。差分が大きければPRを分けるが、各PRでhost／guest全呼出元をビルド・検証可能にする。
- [x] spawn境界の直前再検証とpin保持を実行経路へ結び付ける。型名で検証済みと呼ぶだけで確認を省略せず、Windowsではspawn後も必要な期間pinを保持する。
- [x] 共通の失敗report生成とcleanupを集約する。監査失敗、report書込失敗、stdio取得失敗のときに、既に起動した子を成功状態で残したり、二重にwait／releaseしたりしない。
- [x] Linux内部helperがruntimeのworker生成前に単一スレッドで起動する順序、hostとcontainer PID1のsignal処理差、ACL復元・Job／cgroup・ハンドル寿命を維持する。プロセス管理方式とsandbox選択アルゴリズムは変更しない。
- [x] 段階表の失敗箇所を代表ケースで発生させ、旧新で外部結果と残存物を比較する。RF-T02の有効なprobeと子孫回収検証を使い、単にcargoの成功件数で保証しない。
- [ ] 共通経路を使う変更対象backendの実機結果を揃える。未検証backendを残したまま共有経路の移行完了としない。変更対象はcontainer、Windows Sandbox、WSLC、Kata、Apple container、Hyper-V等のtest matrixで確認する。（検証状況: Hyper-V 17/17・WSLC capability map・container_e2e 16/16（Docker Desktop Linux engine・実Landlock経路）・windows_isolation_e2e/windows_probe_e2e 各22/22・Windows Sandbox mswsb/AppContainer legは実機済み。Windows Sandbox VM tierは昇格下でも`wsb start`が0x80070002を返しDisposableClientVM payload未展開・修復経路なしで本機検証不能。Kata・Apple container・native Linux/macOSは対応ホストなしで未検証のまま残存）

**検証・計測:** T-BASE、T-LAUNCH、T-REPORT、T-AUDIT、T-PROTOCOL。native Linux x86-64／AArch64、Windows、macOSと変更対象backend、Go fixtureの互換性を確認する。M5で準備・初回応答・停止・残存リソースを比較する。

**完了条件:** 呼出側の前提と重複した失敗処理が減り、各資源の所有者と回収経路が説明できる。全変更経路の機能・セキュリティを維持し、性能が後退しない。速度向上自体は採用条件にしない。失敗段階表の各行は、本PRの検証範囲で自然に誘発できるものを実行して結果を記録する。auditor relay起動失敗とstdio取得失敗は安全に誘発する手段がないため「未検証（レビュー確認のみ）」と明記し、検証済み件数には数えない——この2件の実行検証はRF-T06の完了条件に引き継ぐ。

**移行・戻し方:** 抽出・所有権移管の順に独立コミットとし、依存順の逆順で戻す。稼働sessionの途中で所有者を差し替えず、停止・drain・子孫回収後に切り替える。RF01〜RF03およびRF-T02の修正は保持する。

<a id="rf10"></a>

### RF10 小規模な追加改善

直接依存: 各対象のRF00基準。InspectorはRF-T03のケース移行完了後。優先度: D。以下は対象ごとに別PRで扱い、実測効果が不明確なら採用しない。

**RF10-CLI: 同期コマンドのruntime構築回避**

主な変更先: [main.rs](../src/main.rs)、[cli/mod.rs](../src/cli/mod.rs)、同期commandの入口。現在の`real_main`は`#[tokio::main]`で、引数解析と同期dispatchもruntime構築後に行う。

- [ ] help／version／inspect／capability matrixと引数エラーのstdout・stderr・終了コードを固定する。同期とasyncのcommandを現行呼出先で分類する。
- [ ] 引数解析と同期dispatchをruntime構築前へ移し、asyncが必要な経路でだけruntimeを構築する。Linux内部`namespaced-init`／`namespaced-probe`の最優先dispatchは現在どおりworker生成前に保つ。
- [ ] normal run、内部helper、引数エラー、同期コマンドを対で確認し、M5のCLI起動で改善を測る。T-BASE、T-REPORT、影響するCLI／T-LAUNCH試験を実行する。

完了条件・戻し方: 外部出力とLinux helperの単一スレッド要件が一致し、対象CLIの起動が改善する。dispatch変更だけを戻せる単位にする。

**RF10-FRAME: 所有bufferの再利用**

主な変更先: [framing.rs](../src/framing.rs)の`read_frame_bounded`・`read_line_bounded`と直接呼出側。

- [ ] frame読込後のbytes→String変換とallocationを観測し、正常UTF-8で所有bufferを再利用できる地点を特定する。
- [ ] 正常系を再利用へ変更し、不正UTF-8の従来動作を同じエラー／変換規則で維持する。既定10 MiBと設定上限のbytes判定を文字数判定に変えない。
- [ ] 改行、EOF、Content-Length、空入力、途中終了、上限ちょうど／超過、不正UTF-8をT-PROTOCOLと`framing` fuzzで検証する。M1のframing単独でallocationと時間を比較する。

完了条件・戻し方: bytes上限と入力挙動を維持してコピーが減り、大小frameで後退しない。buffer変換の変更だけを戻せる単位にする。

**RF10-INSPECT: ELF解析結果と文字列走査の共有**

主な変更先: [elf_parser.rs](../src/inspector/elf_parser.rs)、[strings.rs](../src/inspector/strings.rs)、[text_section.rs](../src/inspector/text_section.rs)、[inspector/mod.rs](../src/inspector/mod.rs)、[profile/mod.rs](../src/inspector/profile/mod.rs)と解析の呼出側。ELF解析はsymbolとstring抽出等の入口に分散し、`Elf::parse`の呼出しは`elf_parser.rs`・`strings.rs`・`profile/mod.rs`にある。

- [ ] RF-T03後のT-INSPECTで72ケースの移行とfixture配置が保持されていることを確認する。解析入口からELF parse回数と中間の文字列配列保持量を測る。
- [ ] ELF parse結果共有を先に実装する。bytesの寿命と各viewの借用を合わせ、Mach-OやUnsupportedの判定へELF前提を漏らさない。
- [ ] 次の独立コミットで文字列の抽出・分類を逐次化する。出力順、重複排除、URLとpathの分類優先順位、文字列／件数上限、切詰め時のPartial、UTF-8境界を維持する。
- [ ] T-BASE、T-INSPECTとM6でELF／Mach-O、x86-64／AArch64、通常・文字列密集・syscall密集・打切り入力を比較する。大入力はメモリに合わせ段階的に増やす。

完了条件・戻し方: 解析出力とPartial／完全解析の区別が一致し、parse回数・保持量・主指標が改善する。parse共有と逐次分類は別々に戻せるようにする。

**RF10-BUILD: release設定の調整**

主な変更先: [Cargo.toml](../Cargo.toml)と既存の配布build手順。

- [ ] 対応targetと現在のrelease profile・symbols条件・archive条件を記録する。配布対象を減らすことを軽量化として数えない。
- [ ] LTO、codegen units、stripを一因子ずつ比較し、他RFの測定と混ぜない。panic方式や依存削除は別の根拠と検証が必要な変更として分離する。
- [ ] 全配布targetでM7のclean／差分build、binary／archiveサイズ、起動、代表RPCを比較する。必要なT-BASEと既存release検証を行う。

完了条件・戻し方: サイズ・build・実行性能の効果と費用を示せる設定だけ採用する。profile差分を独立して戻せるようにし、測定に使った配布artifactを保持する。

## 3 テスト整理の実装手順

この系列では、テストの件数ではなく、入力・境界条件・失敗検出・OS上の実動作を保証の単位とする。認可、監査永続化、世代競合、数値ID、Unicode、symlink、OS隔離、ACL復元、子孫回収の検査を削減目標から逆算して消さない。対応済みMCP revisionと非対応versionの拒否、単体ロジックとwire／OS経路はそれぞれ維持する。製品コードを変えるRFとテストを移動・削除するRF-Tは別PRとし、共通の完了手順に従う。

<a id="rf-t00"></a>

### RF-T00 棚卸し・保証対応表・テスト時間の基準取得

**目的・依存:** RF00の一部として最初に行う。以降の削除判断とM8の比較に使う一覧を作る。全OSの一覧取得を待たず、必要な環境の基準が揃った作業から進められる。

**現状:** レビュー時のWindows既定featureではlib 2,513件、integration 740件、計3,253件が登録され、`common::kdl::tests`の9ケースが25 targetに入り225登録となっていた。これは`--list`の結果であり、実行成功数ではない。別の範囲で取得した前回レビューの2,681件の成功数とは増減を比較しない。

**調査先:** [Cargo.toml](../Cargo.toml)、[src/testutil.rs](../src/testutil.rs)、[tests/common](../tests/common/mod.rs)、[workflows](../.github/workflows)、[test matrix](test-matrix.md)、各テストの`cfg`と関数内のskip条件。

**タスク**

- [ ] 実装開始時のHEAD、dirty diff、Rust／Cargo版、target triple、OS／architecture、features、必須ゲート、runner、fixture依存を記録する。未コミットの変更を含めて計測する場合はその差分も証跡に含める。
- [ ] 下記コマンドでtarget一覧と登録名を取得する。既定featureとCIで使う`fuzzing`を区別し、該当OSごとに保存する。`cargo metadata`のtest targetとworkflowの明示的な`--test`列挙を突き合わせる。
- [ ] 削除・移動候補について、入力、事前条件、assertion、失敗する経路を読んで保証対応表を埋める。名前が似ているだけのケースを重複としない。`cfg`、関数内の早期return、`ignored`、必要な権限・サービスも記録する。
- [ ] 必要な環境で影響targetを実行し、登録数、実行数、pass、fail、skip、0件、タイムアウトを分ける。関数内returnはRustのharness上でpassとなり得るため、`SKIP:`等の診断とコード読解で未実行を区別する。
- [ ] M8に従い、空の専用`CARGO_TARGET_DIR`でのtest compile／link、一度ビルドした後の実行、実行中のfixtureコンパイル、CI実行時間を分けて取得する。測定用ディレクトリを他作業と共有しない。clean比較のために既存のユーザー用`target`を削除しない。
- [ ] `.local/refactoring/RF-T00/<run>/`等に生ログと対応表を保存し、PRの証跡artifactへ必要な記録を添付する。記録に存在しないOSの結果を補完して書かない。

**既存の棚卸しコマンド**

```text
cargo metadata --locked --no-deps --format-version 1
cargo test --locked --tests -- --list
cargo test --locked --tests --features fuzzing -- --list
rg -n '#\[ignore|skip_unless_required|skip_e2e_test|skipping|SKIP:' src tests
rg -n -- '--test|--features|MCP_WRIT_REQUIRE_' .github/workflows
```

`--list`はテストを実行しない。M8のビルド測定用コマンドは`cargo test --locked --tests --no-run`であり、使用したfeatures等を一覧取得時と揃える。環境変数は共通手順に従い実行プロセスの範囲に限定する。

**保証対応表の必須列**

| 旧target・テスト名 | OS／feature／前提 | 固有の入力・境界・assertion | 残存先／移行先と維持するassertion | 処置と根拠 | 実行selector・証跡 |
|---|---|---|---|---|---|
| 実在する名前を記入 | `cfg`と必須ゲートも記入 | 許可・拒否、順序、資源回収等を区別 | 予定の名前は予定と明示 | 削除／統合／修正／保持／保留 | commit、環境、pass／fail／skip／0件、ログ |

**検証・完了条件:** 削除候補のすべてに対応先または保留理由があり、CIで実行する責任者・targetが特定できる。M8の測定手順を再実行できる。基準取得だけで製品保証が証明された扱いにしない。

**戻し方:** 計測と記録の追加だけに留め、製品動作・テスト判定は変更しない。手順に誤りがあれば基準値を再取得し、古い値を不採用として残す。

<a id="rf-t01"></a>

### RF-T01 重複削除とassertion整理

**目的・依存:** RF-T00後に、固有の検査を失わず登録重複と意味の弱いassertionを整理する。schema部分はRF05bの前に完了する。完全重複の削除とschemaの判断は別コミットにする。

**主な変更先:** [tests/common/kdl.rs](../tests/common/kdl.rs)、[tests/common/mod.rs](../tests/common/mod.rs)、[trajectory_cidr.rs](../src/auditor/checker/tests/trajectory_cidr.rs)、[warden/tests.rs](../src/warden/tests.rs)、[schema_validator/tests.rs](../src/auditor/schema_validator/tests.rs)、新規予定の`tests/common_kdl.rs`、関連workflowとtest matrix。

**タスク**

- [ ] common KDLの9ケースを、入力とassertionを変えず、新規予定の単独integration target `common_kdl`へ移す準備をする。対象は`block_open_finds_line_initial_node`、`block_open_rejects_name_inside_longer_identifier`、`block_open_rejects_mid_line_name`、`block_open_skips_comments_and_strings`、`block_open_allows_trivia_between_name_and_brace`、`block_open_requires_a_brace`、`block_open_from_offset_stays_in_enclosing_block`、`matching_brace_skips_braces_in_comments_and_strings`、`named_insert_pos_lands_on_closing_line`。
- [ ] 新targetは既存helperを必要な範囲で取り込み、テストのために製品の公開APIを増やさない。既存helperの`#[cfg(test)] mod tests`を取り込んだまま別の9ケースを追加して、再び二重登録する構造にしない。
- [ ] 新targetをCI・Platform tests・Linux testsの該当する明示列挙とtest matrixへ登録する。9ケースは現在`manifest_fixtures`経由で[pr-checks.yml](../.github/workflows/pr-checks.yml)のGuard-rail testsでも実行されている。同workflowへ`--test common_kdl`を追加し、冒頭のCoverage記述も更新する。PRゲートから外す場合は、その判断と根拠を保証対応表に記録する。新targetの9ケースを実行してから共通helper内の旧テストmoduleを除去し、helperの関数本体は変えない。
- [ ] `test_trajectory_omitted_leaves_behavior_unchanged`と`test_trajectory_off_allows_read_only_then_network`の本体・fixture・assertionが同一であることを再確認し、前者を削除する。[kdl_loader tests](../src/policy/kdl_loader/tests.rs)の`test_trajectory_omitted_defaults_off`は実際のKDL省略を検査するため保持する。
- [ ] `test_apply_sandbox_noop_on_non_linux`の契約が`test_apply_sandbox_is_noop`に包含されることを確認し、前者を削除する。後者の「成功・反復成功・`sandbox_applied`がfalse」を維持し、現存する公開no-op API自体はこのPRで廃止しない。
- [x] schemaの`required_with_additional_properties_false_no_properties_rejects_extra`を確認する。現在は先頭の`name`の拒否で終了し、`extra`を検査していない。`additional_properties_rejected`と`required_with_additional_properties_false_no_properties_rejects_required_keys`等への保証の包含を確認して統合するか、`name`を許可したschemaにして`extra`の拒否位置を特定するケースへ修正する。採用した方針を対応表へ記録する。 → RF05b commit(`df2b962`)で「`name`を許可したschemaにして`extra`の拒否位置を特定する」方を採用。`required_with_additional_properties_false_rejects_the_extra_key`へ改名し、`properties:{"name":true}`の下で`at 'extra': additional property not allowed`を断言
- [x] schemaの「propertiesなし・requiredあり」の拒否は保持する。文言の一般的な部分一致だけで済ませず、移行先が意図する余分なキーを許可した場合に失敗することを確認する。製品validatorの評価順序・意味をテスト削減に合わせて変更しない。 → RF05b commitで`required_with_additional_properties_false_no_properties_rejects_required_keys`が`at 'name': additional property not allowed`を断言する形へ強化。削除・統合はせず拒否を保持
- [ ] 全targetの登録名を取り直し、消えた名前と移行先をすべて説明する。新targetの9ケースが1箇所だけに登録されることと、helperを使う既存targetの動作を確認する。

**既存の対象別確認コマンド**

```text
cargo test --locked --lib trajectory_
cargo test --locked --lib test_apply_sandbox
cargo test --locked --lib additional_properties
cargo test --locked --test kdl_policy_e2e --test policy_check_e2e --test manifest_fixtures
```

移行後に追加するコマンドは`cargo test --locked --test common_kdl`。このtargetは現時点では未作成であり、追加後の登録確認と実行に使う。filter付きコマンドは`--list`も確認し、0件を成功としない。

**検証・完了条件:** T-BASE、T-POLICY、該当lib testsを実行する。no-opの残存ケースはLinux・非Linux双方、KDL helperは対応OSで確認する。レビュー時のWindowsではKDLの225登録を9登録にし、trajectoryとwardenの各1登録と合わせて218登録を減らせる見込みだが、追加試験を含む最終件数の目標ではない。helper自体の各binaryへのコンパイルは残り得るため、削減率を高速化率としない。

**戻し方:** target移行を戻す場合は旧moduleとCI selectorを同時に戻す。schemaの誤ったassertionへ戻して成功件数を回復しない。対象ごとに戻せる差分にする。

<a id="rf-t02"></a>

### RF-T02 成功判定とWindows・symlink実機検証の修正

**目的・依存:** RF-T00後、RF-T01と並行可能。起動失敗・未実行を成功とする経路を直し、RF09の前提を整える。製品不具合が露見した場合は別の修正PRで解消し、該当保証の未検証を残したままRF09を完了しない。

**主な変更先:** [windows_sandbox.rs](../src/warden/windows_sandbox.rs)のtests、[testutil.rs](../src/testutil.rs)、[tools_list.rs](../src/legislator/tools_list.rs)のtests、[container/runner/tests.rs](../src/container/runner/tests.rs)、[development.md](development.md)のPlatform sandbox verificationと前提不足の説明。必要なprobe fixtureはテスト用途に限定する。

| Windowsの対象テスト | 修正する判定と維持する検査 |
|---|---|
| `test_spawn_sandboxed_with_default_policy` | 起動エラーを見逃さず、正常終了を確認 |
| `test_sandbox_blocks_write_outside_allowed` | probe成立とアクセス拒否を確認。ファイル不存在だけに依存しない |
| `restricted_env_does_not_inherit_sentinel_and_uses_private_tmp` | 応答の取得成功を確認してsentinel非継承とprivate tmpを判定 |
| `acl_grant_allows_write_and_drop_restores_denial` | 許可時の対照と復元後のprobeを成立させ、ACL復元を確認 |
| `sandboxed_workload_cannot_spawn_children` | 偶発的な子起動失敗から、子孫の隔離・回収を検査する代替へ置換 |
| `try_wait_reports_running_and_natural_exit` | 起動成功、稼働中の`None`、自然終了の実exit codeを確認 |

**タスク**

- [x] 各テストのspawn／wait／read失敗と早期returnを一覧化する。OS機能、権限、fixture、TEMPの空白などの前提をspawn前に検査し、既知の前提不足だけを`skip_unless_required`等へ渡す。任意のspawnエラーをskipへ変換する修正にはしない。 → `.local/refactoring/RF09/run-2026-11-22-01/inventory.md`（RF09コミットで実施）、`require_appcontainer()` が `AppContainerSandbox::new` を1回probeし前提不足のみ `skip_unless_required` へ（`windows_sandbox.rs`）
- [x] `MCP_WRIT_REQUIRE_E2E_TESTS=1`では前提不足を失敗とする。前提を満たした後の起動失敗、応答不正、read／wait失敗、タイムアウトはゲートの有無にかかわらず失敗とする。fixtureの引用・cwdの不備をアクセス拒否と取り違えない。 → `skip_unless_required` はゲート下で panic（`testutil.rs`）、`require_appcontainer` は生 `CreateAppContainerProfile` の HRESULT を分類し既知の前提不足（E_ACCESSDENIED/PRIVILEGE_NOT_HELD/NOT_SUPPORTED）のみ skip・予期しないエラーは panic、probe通過後の spawn/wait/read は全て `expect`／`panic`
- [x] 否定probeは、同じ操作が許可された条件では成功する対照を持たせる。拒否側ではfixtureが操作まで到達した証拠、操作のエラー、プロセスの終了状態を確認する。表示言語依存のstderr部分一致だけを唯一の根拠にせず、必要ならprobeで安定した結果を返す。 → `test_sandbox_blocks_write_outside_allowed` に read_write 付与の陽性対照を追加（成功確認後に `drop(control)` で deny probe 評価）
- [x] ACL復元テストの第2段階の`if let Ok(child)`を除き、起動と応答を必須にする。第1段階の成功、grant記録、第2段階のアクセス拒否、元のACLへの復元、残存資源を確認する。共有ディレクトリへ恒久的なgrantを残さない。 → `acl_grant_allows_write_and_drop_restores_denial` で phase1/2 spawn 必須化、grant 記録と `!leaked` の復元確認、fixture cleanup を実装
- [x] 子プロセス禁止を前提にした旧ケースを置換する前に、許可cwd・適切なstdioで子を確実に起動するfixtureを用意する。子の作成成功を確認したうえで、同じtoken・Jobの隔離制約、禁止ファイルと通信へのアクセス拒否を実動作で検査する。通信の対照には動作確認済みのローカルendpoint等を用い、相手不在による失敗を拒否の証拠にしない。 → hyperv leg-9 `tool_spawn_child`（`tests/fixtures/hyperv/hyperv_probe_server.rs`）が子 spawn 成功を確認後に 3 経路で containment 継承を検証: denied-write の `child_txt=false`・子自身の token/Job を `GetTokenInformation(TokenIsAppContainer)`/`IsProcessInJob` で直接照合（`child_token_ac=true`/`child_job=true`）に加え workload 自身の Job の PID リストで `child_warden_job=true` を検証（Job 固有・BREAKAWAY 不可の担保）、通信経路（親の listen 済み loopback endpoint への子 connect は親の `comm_control` と同一 verdict を要求、outbound connect は `child_net_out=denied:10013` = WSAEACCES capability 拒否を必須 — error code が pre-route 拒否を示すため endpoint 未到達の失敗とは区別される）。`hyperv_vm_stdio_session` 実機 pass
- [ ] 親終了時の製品cleanupとJob解放で子孫が回収されることを確認する。親が先に終了して子だけが継続するfixtureを含め、子の自然終了では通らない条件にする。PID等で存続と消滅を追跡し、テスト自身が失敗した場合も作成したプロセス・ACL・一時物を回収する。 （残存: `run_image_hyperv_external_kill_cleans_up` は unit kill → 製品 teardown を検証済みだが、「親終了後も子孫が継続する」orphan fixture は未追加）
- [x] 代替の実機ケースが通ってから`sandboxed_workload_cannot_spawn_children`を置換する。golden reportの`gc_killed`だけで代替しない。AppContainer／Jobの子作成と、Hyper-V等の別backendのprocess limit契約を混同しない。 → 代替実機ケース（hyperv leg-9 containment 継承検証）が 17/17 pass 後に、unit test は「本 launch 条件下での観測拒否」へ doc 明確化し spawn/read/wait を必須化 — 保証過剰主張を除去
- [x] tools-listの`carve_root_symlink_resolves_to_real_tree`、`carve_skips_symlink_entries`、`carve_unresolvable_reparse_root_fails_closed`、`carve_dir_refuses_reparse_root`のsymlink作成失敗returnを共通の前提判定に寄せる。既存のgrant／秘密パス／fail-closedのassertionは保持する。 → 4件とも `skip_unless_required` へ統一（`tools_list.rs`）
- [x] container runnerの`log_share_refuses_artifact_through_plain_spelled_share_link`も同じ方針へ直す。このケースはWindows専用である。tools-listは対応するLinux・macOS・Windows、runnerはWindowsで実行し、Unix側の別形状の既存ケースも残す。テストを通す目的で自動昇格やsandbox緩和を加えない。 → `container/runner/tests.rs` の symlink skip を `skip_unless_required` へ統一
- [x] 変更した判定経路ごとに代表的な前提不足・起動失敗・応答不正・タイムアウトを制御して与え、必須ゲート下で失敗することを確認する。全live testに同じ故障の直積を追加せず、共通判定と固有のprobe経路を必要な範囲で検査する。 → 空白入り `TEMP` で前提不足を制御付与: `MCP_WRIT_REQUIRE_E2E_TESTS=1` で `test prerequisite failed` FAILED、無ゲートで `SKIP`+pass を実行確認済み。probe 通過後の spawn/wait/read 失敗経路は `expect`/`panic` 構造でゲート無関係に失敗（log-and-pass 経路は残存なし）
- [x] 修正したコードと同じPRで、development.mdの「Windows spawn失敗をログに出してpassする」という現状説明を更新する。既知の前提不足のみ明示skip、必須ゲート下では失敗、前提成立後の予期しないspawn／probe失敗は常に失敗、という区別を記す。検証済みOSの範囲と前提権限も維持し、skipされた経路を保証済みと記載しない。 → `development.md` の記述を前提 probe + 必須ゲートの説明へ更新済み

**確認コマンド:** 必須前提を用意し、対象プロセスに`MCP_WRIT_REQUIRE_E2E_TESTS=1`を設定して実行する。

```text
cargo test --locked --lib warden::windows_sandbox::tests -- --nocapture
cargo test --locked --lib carve_ -- --nocapture
cargo test --locked --lib log_share_refuses_artifact_through_plain_spelled_share_link -- --nocapture
```

Windows以外ではWindows専用filterの0件を実行済みとしない。修正したケースを単独と通常並列で動かす。必要なプロセス環境lockは維持し、直列実行だけで並列時の干渉を隠さない。

**検証・完了条件:** T-BASE、T-LAUNCH、対象のpolicy／report検査を実行する。正常probeの成立、実際の拒否、ACL復元、子孫回収の証跡が揃い、必須環境で対象ケースにskipがない。修正で増える実行時間は検証の回復コストとして記録し、M8の高速化と分ける。

**戻し方:** fixtureやhelperの変更は個別に戻せるようにするが、起動失敗の黙殺やファイル不存在だけの判定へ戻さない。製品不具合を直すまで該当作業は未完了とし、旧テストのgreenを完了根拠にしない。

<a id="rf-t03"></a>

### RF-T03 Inspector target・fixtureと純粋なself-test判定の統合

**目的・依存:** RF-T01後に実施する。Inspector部分はRF10の解析変更前に完了する。target移動、fixture共通化、ケース自体の統合は段階を分け、失敗原因を切り分けられる状態を保つ。

**主な変更先:** [inspector_arm64_p4.rs](../tests/inspector_arm64_p4.rs)、[inspector_arm64_p5.rs](../tests/inspector_arm64_p5.rs)、[inspector_macho_p6.rs](../tests/inspector_macho_p6.rs)、新規予定の`tests/inspector_contracts/`、[tests/self_test.rs](../tests/self_test.rs)、[self_test_warden.rs](../src/legislator/self_test_warden.rs)、[self_test_auditor.rs](../src/legislator/self_test_auditor.rs)、CI／Platform tests／Linux testsとtest matrix。

**タスク**

- [ ] Inspectorの現行13・24・35件、計72ケースの名前と入力条件を保存する。環境変数、CWD、静的変数、lock、`OnceLock`等を確認し、同じtest processに置いても独立性が成立することを確認する。
- [ ] 新規予定の`tests/inspector_contracts/main.rs`を入口とする単一targetへ、72ケースを入力・assertion不変で移す。解析状態、Linux AArch64、Mach-O、fixture supportのmoduleへ分ける。OS機構を実行するE2Eまで全て一つのbinaryへ集約しない。
- [ ] 新targetで旧新のケース対応を確認し、通常並列と単独実行を行う。失敗時にケース名と入力条件が分かる診断を残す。この段階では類似ケースを削除しない。
- [ ] P4／P5の`elf64_with_section`の共通化を別段階で行う。`.shstrtab`位置が`0x180`と`0x1b0`で異なる理由を確認し、長い後方探索に必要な容量・section配置を引数または明示計算で保持する。単に片方の定数へ統一しない。
- [ ] 生成bytes、または同等性を説明できるsection配置・命令列を旧fixtureと比較する。解析結果の順序、重複排除、切詰め、Partial、境界を再実行してから旧builderを除去する。P4冒頭のAArch64をUnsupportedとする古い説明は現状に合わせ、対応済み挙動の試験は残す。
- [ ] self-testの`jsonrpc_policy_error_is_never_warden_pass`とlib側の`jsonrpc_policy_error_is_not_warden_pass`、`success_result_with_permission_denied_text_is_not_warden_pass`と`success_result_mentioning_permission_denied_is_not_warden_pass`の入力差を比較する。分類結果だけでなく`is_policy_jsonrpc_error`等のassertionも対応付け、固有の入力をlib側へ移してからintegration側を削除する。
- [ ] `deny_tool_probe_does_not_need_a_child`と`deny_tool_is_auditor_pass`はchecker label等の差を確認して採否を決める。差を移行できない場合は保持する。spawn、`run_self_test`、実際の拒否、report出力を通すE2Eは維持する。
- [ ] 3つの旧Inspector targetを新targetへ置き換え、workflowのmodule filter、test matrix、開発コマンドを更新する。新targetがCIで実際に実行されることを確認後、旧rootファイルを除く。旧selectorの検索結果は歴史文書と現在の実行設定を区別して確認する。

**移行前の確認コマンド**

```text
cargo test --locked --test inspector_arm64_p4 --test inspector_arm64_p5 --test inspector_macho_p6
cargo test --locked --test self_test
cargo test --locked --lib self_test
rg -n 'inspector_arm64_p4|inspector_arm64_p5|inspector_macho_p6' .github docs Cargo.toml
```

移行後のInspector確認は`cargo test --locked --test inspector_contracts`へ変える。新targetは予定であり、作成前の既存コマンドとして扱わない。`--list`で移行名を確認し、機械的な総件数だけで入力バリエーションの維持を判定しない。

**検証・完了条件:** T-BASE、T-INSPECT、self-testに関係するT-LAUNCHとT-REPORT。Inspectorの移動直後は72ケースを維持する。その後の統合は保証対応表で根拠を示す。M8でcompile／link、warm実行、共有状態の影響を記録する。

**戻し方:** 新targetから旧3 targetへ戻す際はworkflowとtest matrixも同時に戻す。fixture配置が変わった場合はbuilderだけを戻せるよう、移動と共通化を分ける。self-testの固有入力を欠落させない。

<a id="rf-t04"></a>

### RF-T04 open-path fixtureビルド共有（測定後に採否決定）

**目的・依存:** RF-T00のM8で重複ビルドの寄与を確認した後に採否を決める。RF-T02の「前提不足とコンパイル・実行失敗を分ける」方針に従う。高速化が不明確、または共有管理の複雑さに見合わなければ保留する。

**現状・主な変更先:** [common/binaries.rs](../tests/common/binaries.rs)の`compiled_open_path_fixture`はtest binaryごとの`OnceLock`で、`diagnostics_e2e`、`path_resolution_e2e`、`workload_hash_e2e`間のビルドは共有しない。[tests/self_test.rs](../tests/self_test.rs)のLinux専用`compile_open_path_server`は別実装である。fixture本体は[open_path_server.rs](../tests/fixtures/mcp_servers/open_path_server.rs)。

**タスク**

- [ ] 各呼出側のsource、compiler引数、生成先、起動前のpin、ACL変更、cleanupを列挙し、同一成果物を利用できる組合せを確定する。M8でrustcの起動回数と寄与時間を測る。
- [ ] 共有を採用する場合は、テスト実行単位のビルド成果物を先に生成する方法と、各targetからの自動生成fallbackを設計する。新しい環境変数やhelperはこのPRで定義・文書化し、存在しない起動方法を前提にしない。
- [ ] source hash、compiler version、target、flagsを識別情報に含める。run専用の信頼できるディレクトリへ一時生成し、完了した成果物のみ原子的に公開する。並列初回buildや中断で部分的な実行fileを取得しない。
- [ ] 所有者・権限・パスと成果物の同一性を確認する。存在確認だけで任意の実行fileをcache hitとしない。検証から実行までの差替えを避け、既存のworkload pinやpath安全性検査を省かない。
- [ ] 共有元を読み取り専用のビルド成果物に限定する。ACLや内容を変更する試験は専有ディレクトリへのコピーを使い、共有artifactのDACLを変更しない。データ、sandbox、session、grantは各テストが所有する。
- [ ] cache miss、source／toolchain／flags変更、並列生成、中断、破損・差替えを代表ケースで確認する。異常時は誤ったartifactを実行せず、失敗または信頼できる場所への再構築となるようにする。
- [ ] `cargo test --test <target>`単独でも自己完結させる。fixtureのコンパイル失敗をskipによる成功へ変えない。cleanupはそのrunが所有するパスに限定し、利用中の他targetの成果物を消さない。
- [ ] 単独target・通常並列の双方で機能を確認し、M8を同じ保証・cache状態で比較する。shared cacheの初回／hitと従来方式の比較を区別し、hit値だけで改善を主張しない。

**既存の影響target確認**

```text
cargo test --locked --test diagnostics_e2e --test path_resolution_e2e --test workload_hash_e2e --test self_test
```

各targetの単独実行も行う。Linux専用self-testビルドとWindowsのACL操作は、それぞれ該当OSで確認する。

**検証・完了条件:** T-BASE、T-LAUNCH、M8。安全な成果物利用、単独fallback、並列実行、cleanupを維持し、時間短縮が実測で確認できる。採用しない場合も根拠を記録すれば調査は完了とし、実装完了とは区別する。

**戻し方:** 呼出側を従来のtarget内ビルドへ戻せる境界にする。戻す場合もRF-T02に従うコンパイル失敗の判定は維持する。run外のcacheを一括削除しない。

<a id="rf-t05a"></a>

### RF-T05a Linux専用テストのWindows実行0件を整理

**目的・依存:** RF-T00後、他のテスト移動と独立して進められる。0件になる呼出しを除き、OSごとの実行責任を明示する。

**現状・主な変更先:** [go-runtime.yml](../.github/workflows/go-runtime.yml)の「Test policy and syscall contracts」は両OSで2つのCargoコマンドを実行する。[seccomp_impl/tests.rs](../src/warden/seccomp_impl/tests.rs)の`go_runtime_syscalls_are_mapped_but_not_implicitly_allowed`はLinux専用moduleにあり、Windowsでは登録されない。[test matrix](test-matrix.md)のCoverage notesはこのlib testに触れている。

**タスク**

- [ ] 共通の`go_runtime_policy`とLinux専用のlib testを別stepへ分け、後者にLinuxの実行条件を付ける。共通step全体をLinux専用にしない。test matrixのCoverage notesに、このlib testをLinuxだけで実行することを反映する。
- [ ] Linuxではlib filterが該当1件を実行すること、Windowsでは該当stepだけが対象外となることを確認する。filterのtypoによる0件を見逃さない。
- [ ] 両OSの`go_runtime_policy`、Go fixture自身のtest／vet／build、直接実行とsandbox経由のprobe、対応protocolごとの比較、失敗時artifactを保持する。
- [ ] workflowの単独実行とreleaseからの呼出しで、失敗の伝播と必要な証跡が残ることを確認する。テストを実行しなかったWindows stepを成功件数へ加算しない。

**既存コマンド**

```text
cargo test --locked --test go_runtime_policy
cargo test --locked --lib go_runtime_syscalls_are_mapped_but_not_implicitly_allowed
```

後者はLinuxで実行する。Go fixtureの実コマンドはworkflowの現行定義を用い、shell、実行file suffix、環境設定を保持する。

**検証・完了条件:** Linuxの対象lib testと両OSのGo契約・実動作が実行済み。Windowsの0件呼出しだけが無くなり、必要な検証が減っていない。

**戻し方:** step分割だけを戻せる変更にする。0件だった呼出しの復活は検証増加と数えない。

<a id="rf-t05b"></a>

### RF-T05b CI重複実行の統合（実行責任を確定してから採用）

**目的・依存:** RF-T01〜RF-T03後のtarget構成を基準にする。同じ条件の検証をまとめ、独立実行時の保証を維持する。単にreusable workflow化して二つのworkflowから毎回呼ぶだけでは時間削減にならない。

**現状・主な変更先:** [ci.yml](../.github/workflows/ci.yml)と[linux-tests.yml](../.github/workflows/linux-tests.yml)は、fuzzing feature付きlib／binsと26 integration targetの実行が重なる。両者のtriggerは`workflow_dispatch`・`workflow_call`・同じcronの週次`schedule`で、PRでは起動しない。PRで起動するのは[pr-checks.yml](../.github/workflows/pr-checks.yml)だけである。Releaseは`ci.yml`を呼び、`linux-tests.yml`は呼ばない。`linux-tests.yml`はリリース対象commitに対して手動dispatchする運用である。実際に重複するのは、週次scheduleと、同じcommitに両方を実行した場合である。fuzz packageのclippyは`ci.yml`と`pr-checks.yml`にあり、`linux-tests.yml`にはない。Linux testsにはAArch64と、x86-64専用の`linux_mechanism_e2e`もある。関連する[platform-tests.yml](../.github/workflows/platform-tests.yml)、[test matrix](test-matrix.md)、[releasing.md](releasing.md)も実行責任の確認対象に含める。

**タスク**

- [ ] workflowのtrigger、呼出元、対象SHA、runner／architecture、Rust版、features、ゲート、target一覧、前提設定、artifact、required status、release依存を表にする。重複して見えても条件が違う組を別に扱う。RF-T01・RF-T03で新設・改名したtargetを反映する。
- [ ] 同じworkflow実行内で共通jobへ集約できる範囲を先に確定する。scheduleの重複を統合する場合も検証頻度と必要な環境を維持する。無関係なworkflowの起動条件を変更しない。
- [ ] 別workflowの証跡を再利用する設計を選ぶ場合は、不変の対象SHA、OS／architecture、必要なrunner条件、toolchain、features、ゲート、test inventory、信頼できる実行由来を照合する。branch名だけ、最新成功jobだけ、artifactの存在だけで完了としない。
- [ ] 証跡の欠落、失敗、skip、cancel、別SHA、設定不一致では必要な検証を実行するfallbackを用意する。既存の失敗証跡は保持し、再実行のgreenで失敗を黙って隠さない。判定できない状態を成功へ変換しない。
- [ ] 単独manual dispatchでは他workflowの偶然の先行実行に依存せず、自身で必要な検証を完結させる。required status名を変更する必要がある場合は、参照側・release依存を対応付け、旧checkを消すだけで受け入れを迂回しない。`ci.yml`と`pr-checks.yml`はjob名が同じ`Test (Linux)`なので、名前で照合する場合はworkflowも併せて特定する。
- [ ] Linux AArch64、x86-64のnamespaced機構、`ci.yml`のfuzz package clippy、各OS固有のdocs／path検査、Go実動作、releaseの既存検証を維持する。`docs_check`や`capability_matrix`等を名前だけでhost非依存と判断して全OSから除かない。
- [ ] 週次schedule、Releaseからの`workflow_call`、単独dispatch、証跡欠落・前段失敗の4経路を確認する。PR経路の確認は`pr-checks.yml`の対象を変更した場合に行う。cancel／設定不一致の判定も確認し、必要なjobが実行され、失敗が呼出側へ伝播し、artifactが保存されることを示す。
- [ ] 新しい実行経路の証跡が揃ってから旧jobを除去する。M8でjobの合計実行時間と全体完了時間を分けて比較し、runner差・queue待ち・cache条件を記録する。

**検証・完了条件:** 同じSHAに対し必要な保証集合が少なくとも一度実行され、未実行・不明・失敗がgreenへ変わらない。手動実行とreleaseの実行責任が維持され、時間削減を実測できる。参照結果の照合が複雑になりすぎる場合は、共通jobへの集約範囲を縮めるか採用を保留する。

**戻し方:** CI統合を戻す場合は旧job・呼出元・required status・artifactを一組で復元する。証跡参照が機能しないときは検証を実行する経路へ戻す。RF-T01・RF-T03のtarget名とRF-T02の失敗判定は現在の構成に合わせて維持する。

<a id="rf-t06"></a>

### RF-T06 launch失敗段階のfault-injection検証

**目的・依存:** RF09の段階表で、自然発生させる安全な手段がなくレビュー確認に留まった失敗箇所を、制御された故障注入で実行検証する。RF09完了後に実施する。製品の外部契約は変えない。

**現状・主な変更先:** RF09で`Launched::abort`と`FailCtx`に集約した失敗経路のうち、post-launch `--report`書込失敗と`TakeIo`子回収は実probeで検証済みだが、auditor relay起動失敗とstdio取得失敗は本ホストで安全に誘発する手段がなくレビュー確認のまま残っている。対象は[runtime/launch.rs](../src/runtime/launch.rs)の`into_session`周辺と、それを使う`tests`／probe fixture。

**タスク**

- [ ] auditor起動失敗・stdio取得失敗を、`#[cfg(test)]`等のテスト専用ビルド経路にある注入点で確実に誘発する方法を決める。環境変数・フラグ等で本番経路の注入を有効化する手段は設けない。probeにrunnerバイナリが必要なら、注入点を含む専用のテスト用runnerを別途用意し、製品runnerは使わない。
- [ ] 誘発した各失敗について、既に起動した子が成功状態で残らないこと、reportが`failed`+該当stageを記録すること、pin・ACL・子孫・一時物の回収が二重実行されないことを旧新で比較する。
- [ ] `TakeIo`／`into_report`系の既存検証と合わせ、段階表の全失敗行が「実probe」または「注入probe」で検証済みとなる対応表を残す。注入に依存しない段階は自然誘発のままにする。
- [ ] 注入点がOFFの通常経路の外部結果（exit・audit列・report）が注入導入前と一致することを確認する。

**検証・完了条件:** 段階表の全失敗箇所に実行証拠があり、`MCP_WRIT_REQUIRE_E2E_TESTS=1`下でskipがない。RF09が未検証として記録したauditor relay起動失敗とstdio取得失敗の2件は、本PRで注入probeを実行して記録するまで失敗段階表を完了とみなさない。注入機構自体が無効時に副作用を持たないこと。

**戻し方:** 注入点とprobeを一組で戻せる単位にする。検証用の緩和を製品経路に残さない。

### テスト整理PRの共通終了手順

- [ ] 削除前に保証対応表を更新し、置換が必要なものは新しい検査を先に追加して該当OSで実行する。短い移行期間の二重登録は許容するが、恒久的に残さない。
- [ ] 変更前後の登録一覧を比較し、減った名前と表形式へ移した入力バリエーションを説明する。実行済み、fail、skip、0件、タイムアウトを分け、CI selectorからの到達を確認する。
- [ ] 変更したassertion／probeの故障検出を、代表的な制御入力または使い捨ての検証用差分で確認する。検証用の製品変更は最終差分へ残さない。全suiteの網羅的mutation testingを条件にせず、削除判断に必要な保証に絞る。
- [ ] 影響targetの単独・通常並列実行、T-BASE、影響する回帰群を完了する。新targetのCI列挙、test matrix、開発手順を更新する。必須ゲート下の実機結果を保存する。
- [ ] M8を目的に応じて記録する。重複整理は保証と保守性、fixture／CI高速化は実測効果を完了条件にする。件数減少や時間短縮を機能・セキュリティの不足と交換しない。
- [ ] PRに対象名、保証対応表、実行環境とログ、M8、未検証項目、切り戻し単位を記載する。未検証の経路を完了扱いにしない。

## 4 PRの完了・切り戻し・引継ぎ

### 4.1 PRの完了記録

各RFのチェックを完了にする前に、次をPR本文またはリポジトリ内の検証記録へ残す。未実行項目を成功に含めず、測定値と目標値を区別する。

| 項目 | 記載内容 |
|---|---|
| 作業と基準 | RF番号、親SHA、候補SHA、未commit差分の有無、依存RFの完了commit |
| 問題と変更 | 具体的な入力・契機、変更前後の結果、変更ファイル、採用した内部設計 |
| 外部契約 | wire、KDL、policy hash、監査、report、終了コード、失敗段階の差分。意図する修正は個別に記載 |
| 保証 | 影響する不変条件とそれを確認したテスト。削除・移動は旧→新のassertion対応 |
| 検証 | OS・architecture・toolchain・features・fixture・権限・ゲート、実コマンド、終了コード、実行・失敗・skip・0件の内訳 |
| 性能 | M番号、入力hash、cache状態、反復数、元データ、A/Aの揺れ、A/B比較、CPU・時間・メモリ、未測定指標 |
| CI | 対象SHA、workflow／job、結果、artifact。target移行時は実行selectorの追従 |
| 残件 | 未検証経路、採用を保留した案と理由、必要な環境、次の作業 |
| 戻し方 | 戻すcommit単位、依存する後続PR、残す不具合修正、確認するcleanup |

RF番号が同じでも複数PRへ分割できる。その場合は範囲と完了条件を各PRに書き、RF全体を完了にするのは全条件を満たした後にする。計画の依存・範囲・採否を変える場合は[計画書](refactoring-plan-2026-11.ja.md)も更新する。単なるコマンド・配置・実行記録の具体化は本書を更新する。

### 4.2 切り戻し

製品に新旧両経路を恒久的に残さず、比較用実装はテスト用途に限定する。各PRの直前に、検証済みcommitとartifactを特定する。永続データ形式を変えない通常の内部変更はPR単位で戻せる設計にし、後続が新APIへ依存する場合は依存の逆順で戻す。

RF01・RF02・RF03の修正後は、性能変更の切り戻し先にもこれらの修正を含める。既知問題のある初期版へ機械的に戻さない。修正自体に回帰があれば、修正を保つ最小パッチまたは未リリース状態での再作業を優先する。

RF-Tの問題はtarget移動・fixture共有・CI集約の単位で戻す。旧targetへ戻すときはselectorとtest matrixも同時に戻し、RF-T02で修正した失敗判定と代替の子孫検証を維持する。CI結果参照が利用できない場合は検証を再実行する。

監査workerや実行中プロセスの所有権を、動作中のセッションで差し替えない。切替は既存手順でセッションを終了してから行い、drain結果と子孫回収を確認する。失敗時に監査モードやsandbox設定を緩めて運用を継続しない。

### 4.3 次のエージェントへの引継ぎ

会話履歴を読まなくても再開できるよう、担当RF、作業branch／SHA、変更済みファイル、完了したcheckboxと根拠、最後に実行したコマンド、残る失敗・未検証環境、元データの場所、次の一手を記録する。既存のユーザー変更と担当変更を区別する。原因不明の失敗を単なる環境要因として引き継がず、再現入力と実際の出力を添える。

推奨着手順は計画書の§4「実施順序とPRの分割」に従う。全作業を一度に進めず、担当RFを完了・検証・記録できる単位で進める。成果物の存在だけで完了とせず、機能・セキュリティ・実機検証・実測の各完了条件を確認する。
