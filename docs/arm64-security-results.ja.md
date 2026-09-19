# ARM64解析対応と運用改善の作業記録

本書は[作業手順書](arm64-security-runbook.ja.md)末尾の様式に従い、
各段階の実施結果を記録する。証拠の原本は `証拠の保存先` に従う。
記録は実施した環境と時点に限り有効であり、他OS・他環境の合格を意味しない。

## P0. 着手前の記録

```text
作業ID: P0
実施日 / 担当: 2026-09-19 / Devin（エージェント）
対象コミット / 未コミット差分: HEAD = 8553b6fbf457e3753c529b70586653b41f3df883。
  基準コミット cd8ebbf06badc5dc599aea3d3898d0f5e221d447 からの差分は
  docs/ への計画・手順書追加1コミットのみで、src/ 配下の実装差分なし。
  記録時点の未コミット差分は本節の記録ファイル、docs/README.md への本書リンク追加、
  tests/fixtures/inspector/ の新規fixture（いずれも後続コミット 27b9880 でコミット済み）。
OS・カーネル・CPU / native・emulation: Windows 11 Business build 26200 /
  AMD Ryzen 5 9600X（6コア）/ native x86-64。エミュレーション実行なし。
  シェルは WSL2 Ubuntu 24.04（kernel 5.15.167.4）上の bash だが、
  WSL 内にツールチェーンはなく、Windows 側の cargo.exe / py.exe を相互運用で実行。
Rust / Cコンパイラー / リンカー / Python・Node.js:
  rustc 1.98.1 (48a229cea 2026-09-01, host x86_64-pc-windows-msvc, LLVM 22.1.8)、
  cargo 1.98.1。rust-toolchain.toml の channel=1.98.1 と一致。
  インストール済み Rust target: x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu。
  Cツールチェーン（対象ごと）:
    Windows x86-64: MSVC cl 19.50.35725 / link.exe（Visual Studio 18 BuildTools, MSVC 14.50.35717）
    x86_64-pc-linux-gnu（fixture生成に使用）: clang 21.1.8 + ld.lld 21.1.8
    Windows（MinGW）: MSYS2 gcc 15.2.0 — PE出力のみ、Linux ELFには不使用
  Python 3.12.10（py -3）、Node.js v24.11.1、Go 1.25.4 windows/amd64。
Capstone crate・Cコア・feature / iced-x86: Capstone 未導入（P4で選定）。
  iced-x86 1.21.0、goblin 0.10.7、windows 0.62.2（いずれも Cargo.lock 確定値）。
Pure Rust候補の版 / 適合結果 / FFIが必要な場合の根拠: 未評価（P4の範囲）。
直接・推移的依存 / feature / build・dev依存 / ネイティブ依存の増減:
  変化なし。P0は測定のみで依存変更を行わない。棚卸しはD1で実施。
機能の維持 / 性能基準・測定条件・測定誤差 / 比較結果: 後述。既存テスト全件合格。
fixture生成元・ハッシュ / 形式・ISA・ABI・slice: 後述のfixture一覧。
検証コマンド / 終了コード: 後述。記載コマンドはすべて終了コード0。
期待値 / 実測結果: 後述。fixture期待値と実測は一致。
結果: PASS（本機で実施可能な範囲）。Docker依存のコンテナ検証と
  非Windows実機・他ISAの実機検証は SKIP 相当として「残る制約」に記録。
証拠の保存先: .local/arm64-p0/（gitignore対象の作業領域）と
  tests/fixtures/inspector/（管理fixture）。テスト・ベンチの生ログは前者。
残る制約・差分の理由: 後述の「使用できる実機と未検証項目」。
次段階へ進めるか / 必要な修正: P1〜P3は本環境で実施可能。
  P4以降の Linux/macOS 実機確認とコンテナ検証には環境整備が前提。
```

### リポジトリ状態と基準コミットからの差分（P0-1）

- `git status --short`: P0開始時点でクリーン。
- `git rev-parse HEAD`: `8553b6fbf457e3753c529b70586653b41f3df883`。
- `git diff --stat`: 空（未コミット差分なし）。
- `cd8ebbf..HEAD` の差分は `8553b6f Add dependency policy and link ARM64 planning documents`
  1件のみで、変更は `docs/` 4ファイルの追加。`src/` の実装は基準コミットと同一のため、
  手順書に記載された対象（parse_run.rs、inspector 配下、checker.rs、warden 配下、
  policy/validator.rs）は現行コードをそのまま読んで確認した。

### 文書エンコーディング（P0-3）

- `py -3 scripts/check_docs.py` → `Checked 16 Markdown files: encoding and local links OK`
  （本書追加後の再実行結果。追加前の実行は15件）。
- リポジトリは `.gitattributes`（`eol=lf`）と `.editorconfig`（`charset=utf-8`）で
  UTF-8・BOMなし・LFが規定。今回追加した fixture ソースも同形式を確認済み。

### x86 ELF fixture の基準結果（P0-4）

#### 既存のインライン fixture

既存の x86 fixture はテストコード内のバイト列であり、期待値は各テストに記録済み。
`cargo test --locked --lib inspector::` が120件すべて期待値通りに合格したことを、
変更前の基準結果として確認した。主な期待値:

| 入力（.text相当のバイト列） | 期待する結果 |
|---|---|
| `mov eax,1; syscall` | 解決: write (1) |
| `mov rax,59; syscall`（48 C7 C0 形） | 解決: execve (59) |
| `xor eax,eax; syscall` | 解決: read (0) |
| `mov eax,257; syscall` | 解決: openat (257) |
| `mov eax,231; / mov eax,60; syscall` | exit_group (231) / exit (60) |
| `mov eax,9999; syscall` | 番号解決（9999）、名称なし |
| `nop; nop; syscall`、先頭 `syscall` | 未解決 |
| `mov eax,0; mov al,59; syscall` | 未解決（部分レジスタ書き込み） |
| `mov eax,0; xchg eax,ebx; / xadd ecx,eax; syscall` | 未解決（暗黙・複合書き込み） |
| `mov eax,1; call +0; syscall` | 未解決（制御フローで打ち切り） |
| `0F 34`（sysenter） | syscallサイトとして検出しない |

#### 管理 fixture（新規作成、比較基盤用）

| 項目 | 値 |
|---|---|
| パス | `tests/fixtures/inspector/x86_64_linux_syscalls.elf`（1040 bytes） |
| 元ソース | `tests/fixtures/inspector/x86_64_linux_syscalls.s`（GNU as / intel_syntax。命令列は決定的で、各サイトの期待結果をコメントで記録） |
| 作成方法 | `clang --target=x86_64-pc-linux-gnu -c x86_64_linux_syscalls.s -o x86_64_linux_syscalls.o` → `ld.lld -o x86_64_linux_syscalls.elf x86_64_linux_syscalls.o`（Windows 上 LLVM 21.1.8） |
| SHA-256 | `a16868623779fa05b4151c159ef1c0171c08bef31c61f01369192447362dcc79` |
| 形式・ISA・ABI | ELF64 LSB、EM_X86_64 (62)、Linux x86-64 SYSV ABI、static、.symtab あり（非 strip）、.text 73 bytes @ vaddr 0x201180 |

テスト・解析はこのバイナリを実行しない。`inspect` の基準結果（release ビルド、
`--format json` の address フィールド）:

| .text内offset | address (dec/hex) | 命令列 | 期待 | 実測 |
|---|---|---|---|---|
| 5 | 2101637 / 0x201185 | `mov eax,1; syscall` | write (1) Resolved | 一致 |
| 12 | 2101644 / 0x20118c | `mov eax,257; syscall` | openat (257) Resolved | 一致 |
| 21 | 2101653 / 0x201195 | `mov rax,59; syscall` | execve (59) Resolved | 一致 |
| 25 | 2101657 / 0x201199 | `xor eax,eax; syscall` | read (0) Resolved | 一致 |
| 32 | 2101664 / 0x2011a0 | `mov eax,9999; syscall` | 9999 Resolved（名称なし） | 一致 |
| 41 | 2101673 / 0x2011a9 | `mov eax,0; mov al,59; syscall` | Unresolved（部分レジスタ） | 一致 |
| 45 | 2101677 / 0x2011ad | `nop; nop; syscall` | Unresolved（代入なし） | 一致 |
| 57 | 2101689 / 0x2011b9 | `mov eax,1; call +0; syscall` | Unresolved（制御フロー） | 一致 |
| 64 | 2101696 / 0x2011c0 | `mov eax,231; syscall` | exit_group (231) Resolved | 一致 |
| 71 | 2101703 / 0x2011c7 | `mov eax,60; syscall` | exit (60) Resolved | 一致 |

出力形式の基準（同 fixture に対する現行出力、`.local/arm64-p0/` に保存）:

- human: `Detected Syscalls (10)`。番号のみ解決は `unknown (9999) [Resolved]`、
  未解決は `unknown (?) [Unresolved]`。アドレスは表示しない。risk_score 55/100 (High)。
- JSON: `syscalls[]` は `{address, syscall_number, syscall_name, resolution}`、
  resolution は `"resolved"` / `"unresolved"`。`strings{urls,paths,env_vars}`、
  `is_stripped:false`、`risk_score:55`、`risk_level:"High"`。
- KDL: `syscalls { syscall address=… syscall_number=… syscall_name=… resolution="…" }`。
  番号のみ解決は `syscall_number=9999` で `syscall_name` 属性なし、未解決は番号・名称ともなし。
- `generate-policy`（静的解析のみ）: `defaults.syscalls.allow` に検出syscall名を列挙
  （read/write/openat/close/fstat/mmap/munmap/brk/exit_group/exit）、execve は
  REVIEW コメント付きで許可しない。9999 番と未解決サイトは生成物に現れない。

#### 実バイナリ参照 fixture（管理外・参照用）

| 項目 | 値 |
|---|---|
| パス | `.local/arm64-p0/bash-x86_64.elf`（1,446,024 bytes） |
| 元 | WSL2 Ubuntu 24.04 の `/bin/bash`（GNU bash 5.2.21(1)-release, x86_64-pc-linux-gnu） |
| 作成方法 | ディストリビューションバイナリのコピー。性能測定と実バイナリ挙動の参照用 |
| SHA-256 | `bc5945feb8bd26203ebfafea5ce1878bb2e32cb8fb50ab7ae395cfb1e1aaaef1` |
| inspect --format json | libraries 2、imports 239、syscall sites 0、risk_score 65 (High) |

動的リンクされた実バイナリは `.text` に直接 `syscall` を持たず、検出0件となる
基準例として記録する（「解析して0件」と「未対応で0件」は現行出力上区別されない点に注意）。

### 既存テストの変更前結果（P0-5）

| コマンド | 結果 |
|---|---|
| `cargo test --locked --lib inspector::` | 120 passed / 0 failed |
| `cargo test --locked --lib pathutil::` | 14 passed / 0 failed |
| `cargo test --locked --lib auditor::` | 288 passed / 0 failed |
| `cargo test --locked --lib policy::validator::` | 28 passed / 0 failed |
| `cargo test --locked --lib warden::` | 41 passed / 0 failed（AppContainer プロファイル作成・削除の実経路を約10秒かけて検証） |
| `cargo test --locked --test integration --test tool_enforcement_e2e --test kdl_policy_e2e --test self_test` | 12 + 25 + 18 + 4 passed / 0 failed |
| `cargo test --locked`（全 target） | lib 1295 を含め全件合格（container_e2e 4、containerize_e2e 14、go_runtime_policy 7、legislator_protocol_versions 5、wrap_image_e2e 16 ほか） |

変更前の失敗: なし。環境不足の切り分け:

- Docker デーモン停止中のため、コンテナ系テストの Docker 依存箇所は内部で
  `SKIP: no container engine` / `Docker not available` を出力し pass 扱い
  （`--nocapture` で確認）。実行経路としては未検証であり、合格とは区別して記録する。
- Windows 環境のため Warden の Linux 経路（Landlock/seccomp）と macOS 経路（SBPL）は
  未検証。Windows は AppContainer 経路を実検証。
- `self_test` の非 Linux 経路は `warden: skipped` と `spawn:` を分離する既存仕様どおり。

### 性能基準と測定方法（P0-6）

測定方法（比較時に同一条件を再現する手順。スクリプトは `.local/arm64-p0/`）:

- ビルド: `cargo build --locked --release --bins`。測定対象は `target/release/mcp-writ.exe`。
- 時間: `measure.py` — subprocess の wall-clock（`time.perf_counter`）。
  ウォームアップ5回＋本測定 N 回で min/median/mean/max/stdev。
- RPC 中継: `bench_relay.py` — `run --dry-run` + `scripted_stdio.py` fixture に対し、
  initialize と tools/list 応答の中継を待ってから 200 回の tools/call
  （160件は allow 相当の read_file、40件は deny の exec_shell → dry-run では
  observed として監査ログに記録し転送）を送信し、応答をすべて受信するまでの時間。
- メモリ: `mempeak.py` — 子プロセスハンドルへ `GetProcessMemoryInfo` を呼び、
  `PeakWorkingSetSize` を取得（終了後もハンドル経由で有効）。mcp-writ 自身の値であり、
  子プロセス（fixture サーバー）側は含まない。
- 測定誤差の判定: 中央値で比較する。変更後の中央値との差が基準値の
  `max(10%, 3×stdev)` を超えた場合のみ退行候補とし、同一セッションでの再測と
  ウォームアップ増加で測定誤差と切り分ける。起動系の差と大量解析の差は混ぜない。
  メモリとバイナリサイズは絶対値で比較する。

基準値（release プロファイル、本機、WSL 相互運用経由の起動を含む）:

| 処理 | 指標 | 基準値 |
|---|---|---|
| 起動 `mcp-writ --help` | 時間 median | 8.8 ms（n=30, min 8.0, max 10.1, stdev 0.6） |
| `inspect --format json` fixture（1 KB） | 時間 median | 10.2 ms（n=30, stdev 1.6） |
| `inspect --format json` bash（1.4 MB） | 時間 median | 18.8 ms（n=15, stdev 1.4） |
| `generate-policy`（静的のみ）fixture | 時間 median | 10.0 ms（n=30, stdev 1.7） |
| RPC 中継 200 calls（ペース制御、dry-run、監査ログ出力あり） | 時間 median | 32 ms ≒ 約6,200 calls/s（セッション全体 96 ms: mcp-writ・Python 起動と handshake・tools/list 検証を含む） |
| PeakWorkingSetSize | メモリ | help 6.7 / inspect(fixture) 7.6 / inspect(bash) 8.8 / generate-policy 7.6 / relay 8.2 MB |
| バイナリサイズ | 絶対値 | release: mcp-writ.exe 4,742,144 B、mcp-secure-runner.exe 2,795,008 B（debug: 10,371,072 B / 6,029,824 B） |
| ビルド時間 | wall-clock | release 全ビルド 29.6 s。debug は依存ビルド済み後の本クレートのみで 12.4 s |

機能の基準: 上記テスト全件合格、fixture の inspect 出力（命令位置・番号・解決状態・
3形式のフィールド構成）、generate-policy 生成物の内容を、変更前の機能基準とする。
依存変更を伴う作業では、これらと同一条件の測定値との比較で機能・性能の維持を判断する。

### 使用できる実機と未検証項目

| 環境 | 状態 |
|---|---|
| Windows x86-64 | 本機。本記録の実機検証済み |
| Linux x86-64 | 実機なし。WSL2 Ubuntu 24.04 は Rust/C/Python ツールチェーン未導入。Rust target x86_64-unknown-linux-gnu はインストール済みだが、Linux 向けリンクには C ツールチェーンが必要 |
| Linux AArch64 | なし |
| macOS Apple Silicon / x86-64 | なし |
| Windows ARM64 | なし |
| コンテナ | Docker Desktop 導入済みだがデーモン停止。コンテナ E2E の Docker 依存経路は未実施（内部 skip） |

P0 時点の未検証項目: Landlock/seccomp の実適用、SBPL の生成・適用、
macOS 実機、Linux AArch64 実機、Windows ARM64、コンテナ E2E の Docker 依存経路、
`generate-policy --self-test` の Linux 実機経路。
go_runtime_policy は合格したが、OS 固有の sandboxed 経路は各 OS での確認が必要。

### 証拠ファイル一覧（`.local/arm64-p0/`）

- fixture 出力: `inspect-fixture-human.txt`、`inspect-fixture.json`、`inspect-fixture.kdl`、
  `inspect-bash.json`、`genpol-fixture.kdl`、`genpol-err.txt`
- テストログ: `test-lib-inspector.log`、`test-lib-pathutil.log`、`test-lib-auditor.log`、
  `test-lib-policy-validator.log`、`test-lib-warden.log`、`test-e2e.log`、`test-all.log`
- 測定: `bench-times.txt`、`bench-relay.txt`、`bench-memory.txt`、
  `measure.py`、`bench_relay.py`、`mempeak.py`、`peakws.ps1`、
  `bench-policy.kdl`、`gen_rpc_input.py`、`rpc-input.jsonl`、
  `bash-x86_64.elf`、`bench-audit.jsonl`、`smoke-*`（事前確認用の出力）

## D1. プロジェクト全体の依存削減

```text
作業ID: D1
実施日 / 担当: 2026-09-19 / Devin（エージェント）
対象コミット / 未コミット差分: HEAD = 622d539a3eee9c7fa7a6ff41589189e06139aea0。
  変更ファイルは Cargo.toml、Cargo.lock、src/container/common.rs、
  および本節を追記した docs/arm64-security-results.ja.md。
OS・カーネル・CPU / native・emulation: P0と同一（Windows 11 build 26200 /
  AMD Ryzen 5 9600X / native x86-64、WSL2 bash + Windows側ツールチェーン）。
Rust / Cコンパイラー / リンカー / Python・Node.js: P0と同一（rustc/cargo 1.98.1、
  MSVC 19.50.35725、clang/lld 21.1.8、Python 3.12.10、Node.js v24.11.1、Go 1.25.4）。
Capstone crate・Cコア・feature / iced-x86: Capstone 未導入（P4で選定）。
  iced-x86 1.21.0 は default-features=false + ["std","decoder","instr_info"] へ縮小。
Pure Rust候補の版 / 適合結果 / FFIが必要な場合の根拠: 今回の削減はすべて
  既存Pure Rust依存の feature・不要crate の削減であり、新規FFI・新規crate導入なし。
  独自実装への置き換えは行っていない（評価した shlex は残置、理由は後述）。
直接・推移的依存 / feature / build・dev依存 / ネイティブ依存の増減:
  Cargo.lock 101 → 94 package（-7: aho-corasick, matchers, regex-automata,
  regex-syntax, serde, serde_core, serde_derive）。
  host向け cargo tree --edges normal,build のユニークcrate 80 → 73
  （出力のユニーク行数。数え方は後述の定量比較を参照）。
  feature削減: iced-x86 -8、goblin -6、kdl -1、tracing-subscriber -1、
  windows -1（いずれもcrate内の未使用コード経路を止めるものでcrate数不変）。
  dev依存・ネイティブ依存の増減なし（後述）。
機能の維持 / 性能基準・測定条件・測定誤差 / 比較結果: 後述。全テスト合格、
  inspect/generate-policy の出力はP0基準ファイルとバイト一致。
  全指標で後退なし（基準値の max(10%,3×stdev) 以内以上に改善または同等）。
fixture生成元・ハッシュ / 形式・ISA・ABI・slice: P0のfixtureをそのまま使用。
検証コマンド / 終了コード: 後述。すべて終了コード0。
期待値 / 実測結果: 後述の比較表。期待値=機能・性能非退行、実測は全項目で達成。
結果: PASS（本機で実施可能な範囲）。他OS実機・コンテナDocker経路は
  P0と同じ制約として残る。
証拠の保存先: .local/arm64-d1/（gitignore対象）。依存ツリー・測定出力の原本。
残る制約・差分の理由: 後述「残る制約」。
次段階へ進めるか / 必要な修正: 棚卸し結果は後述の一覧としてP4へ渡せる。
```

### 依存棚卸し（D1-1, D1-2）と各依存の処置

配布ターゲット6種（mcp-writ: win64/win-arm64/lin64/lin-arm64/mac64/mac-arm64、
runner: lin64/lin-arm64）について `cargo tree --locked --edges normal,build --target`
で依存グラフを記録し、`rg` で各crateの利用箇所を確認した。
生データは `.local/arm64-d1/tree-*.txt`（before/after）。

| 依存 | 版 | 用途（利用箇所の代表） | OS | build/dev | 処置 |
|---|---|---|---|---|---|
| tokio 1.53.1 | 直接 | 非同期ランタイム。process（サーバー・engine起動）、io-std/io-util（stdio中継）、fs（File::from_std）、signal（ctrl_c/unix SIGTERM）、sync（Mutex/watch）、time（timeout/sleep）、macros/rt-multi-thread（#[tokio::main]） | 全 | normal | 維持。全featureの利用を確認済み |
| noargs 0.4.3 | 直接 | CLI全サブコマンドの引数パース（src/cli/*） | 全 | normal | 維持 |
| nojson 0.3.15 | 直接 | JSON-RPCのパース・生成（auditor/legislator/verifier 全域） | 全 | normal | 維持 |
| orfail 2.0 | 直接 | エラー処理の接着（noargs/nojson/tomlと併用） | 全 | normal | 維持 |
| regex-lite 0.1.9 | 直接 | verifier/ris、manifest_rules、project_hints_*、inspector/strings、schema_validator の計8ファイル | 全 | normal | 維持 |
| kdl 6.7.1 | 直接 | ポリシーKDLのDOMパース・出力（policy/kdl_*、inspector format、policy_generator） | 全 | normal | **serde feature削除**（de/seモジュール未使用）。spanはエラー位置表示に必要で維持 |
| goblin 0.10.7 | 直接 | ELF header/section/symtab/dynsym/dynamic/interpreter（inspector/*、container/common.rs） | 全 | normal | **elf32/elf64/endian_fd/stdのみに削減**（mach/pe/te/archive未使用）。`Object::parse`は全feature限定APIのため `Elf::parse` へ置換（非ELF→警告の挙動は同等） |
| iced-x86 1.21.0 | 直接 | x86-64デコードとレジスタアクセス解析（inspector/disasm、slicer） | 全 | normal | **std/decoder/instr_infoのみに削減**（encoder/block_encoder/op_code_info/fast_fmt/各formatter未使用）。デコード対象ISAは不変（no_vex/no_evex等は指定しない） |
| tracing 0.1.44 | 直接 | 構造化ログ全般 | 全 | normal | 維持 |
| tracing-subscriber 0.3.23 | 直接 | stderr向けfmtサブスクライバ（commands/tracing_init.rs） | 全 | normal | **env-filter削除**（EnvFilter/RUST_LOG非対応経路が存在せず未使用） |
| shlex 2.0.1 | 直接 | 環境変数コマンド文字列のPOSIX風分割（runtime/argv.rs、引用符・エスケープ処理） | 全 | normal | 維持。0依存の小規模crateで、手書き置換は品質リスクに見合わないと評価 |
| uuid 1.26.1 (v7) | 直接 | 監査ログ・検証イベントの相関/イベントID（audit_log、proxy_c2s、verifier各所） | 全 | normal | 維持（v7生成にgetrandomが必須） |
| sha2 0.11 (default-features=false) | 直接 | manifest/ツール定義ハッシュ、イメージダイジェスト（verifier、policy/kdl_canon、container/inspect） | 全 | normal | 維持。すでに最小feature |
| shiguredo_toml 2026.2.0 | 直接 | pyproject.tomlの解析（legislator/project_hints_python.rs） | 全 | normal | 維持。TOMLパーサーは標準・既存依存に代替なし |
| unicode-normalization 0.1.25 | 直接 | セキュリティ関連の正規化（pathutil、secret_paths、verifier/unicode、manifest_rules） | 全 | normal | 維持 |
| libc 0.2.189 | 直接(unix) | kill/prctl/シグナル/SYS_*/errno（runtime/wait、warden/child・seccomp_impl・macos_sandbox、self_test_warden） | unix | normal | 維持。必要最小限のOS境界 |
| landlock 0.4.7 | 直接(linux) | Landlock FSサンドボックス（warden/landlock_impl） | linux | normal | 維持。隔離機能の根幹 |
| seccompiler 0.5.0 | 直接(linux) | seccomp-BPFフィルタ（warden/seccomp_impl） | linux | normal | 維持。同上 |
| windows 0.62.2 | 直接(windows) | AppContainer/ACL/JobObject/Pipe/Console/Threading/Globalization（warden/windows_*） | windows | normal | **Win32_System_Memory削除**（未使用namespace）。他8 featureは利用確認済み |
| tempfile 3.27 | dev | テスト用一時ディレクトリ | 全 | dev | 維持。テスト支援の削減は検証範囲を失わせるため対象外と判断 |

推移的依存の主な残置と理由: proc-macro2/quote/unicode-ident/syn（proc-macro基盤、
ビルド時のみ）、once_cell（tracing-core）、smallvec/sharded-slab/thread_local/
nu-ansi-term/tracing-log（tracing-subscriberのregistry/fmt/ansi/logブリッジ。
tracing-logはgoblin内部log出力をverbose時に可視化するため維持）、
miette/unicode-width/cfg-if/num-traits/autocfg/winnow（kdlの必須依存）、
plain/scroll/scroll_derive/log（goblinの必須依存）、lazy_static（iced-x86 std）、
digest/block-buffer/hybrid-array/typenum/crypto-common/cpufeatures（sha2）、
getrandom（uuid v7とtempfile）、tinyvec（unicode-normalization）、
bytes/mio/pin-project-lite/tokio-macros（tokio）、errno/signal-hook-registry
（tokio unix signal）、windows-*ファミリー（windows crate）、
thiserror/enumflags2（landlock）、fastrand/windows-sys（tempfile、devのみ）。

### 重複依存・複数バージョン

`cargo tree --duplicates` は syn v2.0.119 / v3.0.5 のみ。syn2はtracing-attributesと
windows-implement/-interfaceが、syn3はscroll_derive・tokio-macros・thiserror-implが
要求するため上流ピンの範囲であり、proc-macro（ホストビルド時のみ、配布物に
含まれない）のため統一不能・影響限定として削減対象外と記録する。

### ネイティブ依存・外部ツール

- Cライブラリのコンパイルを伴う依存: なし（全crate Pure Rust）。
- OSバインディング: windows crate（Win32 FFI境界）、libc（POSIX）、
  landlock/seccompiler（LinuxカーネルABIのPure Rustラッパー、Cコードなし）。
  いずれも隔離に必須の最小境界として維持。windows featureは利用namespaceのみに削減済み。
- 外部ツール（サブプロセス・CI・テスト実行環境。配布物に同梱されない）:
  Docker/Podman/Buildah CLI（container機能のengine）、Python 3（check_docs.pyと
  MCP fixtureサーバー）、Node.js（js_mcp fixture）、Go（go_mcp fixture・
  go-runtime workflow）、clang/lld（fixture生成のみ）、cross 0.2.5
  （CIのaarch64-linuxビルド）。いずれも機能上必須で、Rust依存とは別管理として維持。

### 削減前後の定量比較（D1-7）

| 指標 | 削減前（P0基準） | 削減後 | 差分 |
|---|---|---|---|
| Cargo.lock package数 | 101 | 94 | -7 |
| host tree crate数（normal+build） | 80 | 73 | -7 |
| mcp-writ.exe (release) | 4,742,144 B | 4,498,944 B | -243,200 B (-5.1%) |
| mcp-secure-runner.exe (release) | 2,795,008 B | 2,796,544 B | +1,536 B (+0.05%) |
| release全ビルド（clean） | 29.6 s | 22.5 s | -24% |
| `--help` 起動 median | 8.8 ms | 8.0 ms | -9% |
| `inspect --format json` fixture(1KB) median | 10.2 ms | 9.2 ms | -10% |
| `inspect --format json` bash(1.4MB) median | 18.8 ms | 18.2 ms | -3% |
| `generate-policy` fixture median | 10.0 ms | 9.1 ms | -9% |
| RPC中継 200 calls median | 32 ms (6,234 calls/s) | 29 ms (6,946 calls/s) | -9% |
| PeakWorkingSetSize (help/inspect-f/inspect-b/genpol/relay) | 6.7 / 7.6 / 8.8 / 7.6 / 8.2 MB | 6.6-6.7 / 7.5-7.6 / 8.7 / 7.6 / 8.2 MB | 誤差内・同等 |

`host tree crate数` は `cargo tree --edges normal,build` 出力のユニーク行数であり、
normal/build の両文脈に現れる依存の `(*)` 注記行を別行として計上する。
`name version` ペアでは 70 → 65、クレート名ベースでは 69 → 64
（いずれもワークスペースルートを含む。syn 2.0/3.0 の複数版は別計上）。

runnerの+1.5KBはコードレイアウト差の範囲（0.05%）で退行とはみなさない。
時間系はいずれも改善側であり、P0の退行判定（基準中央値の
max(10%,3×stdev)超の悪化）に該当する項目はない。

機能維持の確認: `cargo test --locked` 全件合格（lib 1295 + integration各件、
P0と同一構成）。`inspect --format json` と `generate-policy` の出力を
P0基準ファイル（`.local/arm64-p0/`）と diff しバイト一致を確認した。

### 検証コマンド（すべて終了コード0）

- 候補ごとの確認: `cargo check --bins`（各削減後に実施）
- `cargo test --locked --lib inspector::` → 120 passed
- `cargo test --locked --lib policy::` → 188 passed
- `cargo test --locked --lib -- inspector:: container::` → 264 passed
- `cargo test --locked --lib warden::` → 41 passed（AppContainer実経路）
- `cargo test --locked`（全target） → 全件合格
- `cargo check --target x86_64-unknown-linux-gnu --bins`
- `cargo fmt --all -- --check`、`cargo clippy --locked --all-targets -- -D warnings`、
  `RUSTDOCFLAGS=-D warnings cargo doc --locked --no-deps`、
  `py -3 scripts/check_docs.py`、`git diff --check`

### 残る制約

- インストール済みtargetは x86_64-pc-windows-msvc と x86_64-unknown-linux-gnu
  のみ。aarch64-pc-windows-msvc、x86_64/aarch64-apple-darwin、
  aarch64-unknown-linux-gnu の実ビルドは本機未検証。
  変更はPure Rust crateのfeature削減でありOS/ISA非依存だが、
  windows feature削減のARM64ビルド確認はCI/実機に残す。
  各targetの `cargo tree --target` 解決は全6ターゲットで確認済み。
- コンテナE2EのDocker依存経路はP0同様に未実施（デーモン停止）。
  `assert_static_runner` の変更はユニットテスト（static/dynamic ELF、
  非ELF・破損入力・読み取り失敗の各経路）と既存e2eの非Docker経路で検証。
- goblinのmach64はP6でMach-O解析を実装する際に再有効化する前提
  （現行コードはELFのみ使用するため現状では過剰featureと判断）。
- iced-x86はP7の置換判定まで維持。今回のfeature削減でencoder/formatterは
  除去済みだが、P4/P7で必要になった場合は再有効化と再評価を行う。

### 証拠ファイル一覧（`.local/arm64-d1/`）

- 依存ツリー: `tree-normal-build.txt`（before host）、`tree-all.txt`、
  `tree-features.txt`、`tree-duplicates.txt`、`tree-nb-<target>.txt`（before 6target）、
  `tree-normal-build-after.txt`、`tree-all-after.txt`、`tree-duplicates-after.txt`、
  `tree-nb-*-after.txt`（after 6target）
- 出力比較: `inspect-fixture.json`、`genpol-fixture.kdl`、`genpol-err.txt`
- 測定: `bench-audit.jsonl`、`mem-audit.jsonl`（ベンチ実行で生成された監査ログ）

## P1. dry-runヘルプの修正

```text
作業ID: P1
実施日 / 担当: 2026-09-19 / Devin（エージェント）
対象コミット / 未コミット差分: HEAD = cc58f86249431b60155372d545fcca634c78a344
  （D1マージ済み、P1開始時点でワーキングツリーはクリーン）。
  P1の変更は未コミット差分としてワーキングツリーに保持:
  src/cli/parse_run.rs、README.md、README.ja.md、docs/guide.md、
  docs/guide.ja.md、docs/policy-authoring.md、docs/policy-authoring.ja.md、
  および本節を追記した docs/arm64-security-results.ja.md。
  （記録時点では未コミット。その後これらの変更は a2a0f63
  "Clarify dry-run mode documentation to emphasize side effects and
  sandboxing behavior" としてコミット済み。本節末尾のレビュー追補は
  未コミットのまま）
OS・カーネル・CPU / native・emulation: P0と同一（Windows 11 build 26200 /
  AMD Ryzen 5 9600X / native x86-64、WSL2 bash + Windows側ツールチェーン）。
Rust / Cコンパイラー / リンカー / Python・Node.js: P0と同一（rustc/cargo 1.98.1、
  Python 3.12.10）。
Capstone crate・Cコア・feature / iced-x86: 変更なし（P1は依存に触れない。
  iced-x86 1.21.0 は D1 後の feature 構成のまま）。
Pure Rust候補の版 / 適合結果 / FFIが必要な場合の根拠: 対象外（P4の範囲）。
直接・推移的依存 / feature / build・dev依存 / ネイティブ依存の増減: 変化なし。
機能の維持 / 性能基準・測定条件・測定誤差 / 比較結果:
  dry-run の挙動（main.rs の skip_sandbox 経路、tools/call 違反の
  記録・転送、--fail-on 閾値での first-seen tools/list の fail-closed）は
  変更していない。文言のみの修正のため P0/D1 の性能基準への再測定は行わない。
  `cargo test --locked --lib cli::` 70件合格で既存のパース挙動を確認。
fixture生成元・ハッシュ / 形式・ISA・ABI・slice: 対象外（fixture不使用）。
検証コマンド / 終了コード: 後述。すべて終了コード0。
期待値 / 実測結果:
  期待値: ヘルプと日英説明から、dry-run が副作用のない検証モードでないこと、
    OSサンドボックス無効化・tools/call 違反の記録と転送・ツール定義の遮断検査が
    設定に従い継続することが読み取れること。
  実測: `run --help` の --dry-run 項に規定文言を確認（後述に転記）。
    日英各文書へ同内容を反映済み。
結果: PASS（本機で実施可能な範囲）。サーバー起動を伴う実動作の再検証は
  手順P1-3がヘルプ確認のみを要求するため未実施（文言変更で挙動不変）。
証拠の保存先: 差分は `git diff` で確認可能（後述の変更要約）。
  ヘルプ出力の該当行は本節に転記。
残る制約・差分の理由: 文言のみの変更のため、違反要求の転送とツール定義の遮断に
  関する既存テストの再実行・補強は行わない（手順P1-4）。文字列を丸写しした
  テストも追加していない。
次段階へ進めるか / 必要な修正: P2へ進める。
```

### 変更内容（P1-1, P1-2）

- `src/cli/parse_run.rs`: `--dry-run` の doc を次へ修正。
  "Run the server without OS sandboxing; log and forward tool-call policy
  violations. Blocking tool-definition checks still apply. Server execution
  may have side effects."
- README.md / README.ja.md: dry-run 例のコメントと「Security boundaries /
  保護範囲と制約」節を更新。OSサンドボックス無効でのサーバー実行、違反の
  記録と転送、ツール定義の遮断検査の継続、ファイル変更・通信などの副作用の
  可能性を明記。
- docs/guide.md / docs/guide.ja.md: `run` オプション表、実行例コメント、
  FAQ「dry-run」の説明を同内容へ更新。残存する遮断が `--fail-on` 設定に
  従う表現を維持し、manifest関連検査が無条件に同じ扱いになる説明には
  していない。
- docs/policy-authoring.md / docs/policy-authoring.ja.md:
  「What to check in dry-run mode / ドライランで確認すること」の説明を
  同内容へ更新。
- （レビュー追補・未コミット）docs/guide.md / docs/guide.ja.md:
  FAQ「dry-run」の箇条書きに例外挙動を明記。`tools/list` 収集・
  `list_changed` 再検証の進行中は `tools/call` が dry-run でも一時的に
  拒否される（fail-secure）こと、再検証の失敗（検証失敗・内部 re-list
  へのエラー応答）はセッションを abort すること、クライアント起点の
  `tools/list` でこれ以外の検証失敗（ハッシュ不一致など）は記録して
  転送すること。`--help` 文言は手順P1-1の指定どおり変更しない。

`run --help` の実測出力（`--dry-run` 項、終了コード0）:

```text
Run the server without OS sandboxing; log and forward tool-call policy violations. Blocking tool-definition checks still apply. Server execution may have side effects.
```

### 検証コマンド（すべて終了コード0）

- `cargo run --locked --bin mcp-writ -- run --help`（上記文言を端末で確認。
  サーバー起動なし）
- `cargo test --locked --lib cli::` → 70 passed / 0 failed
- `cargo fmt --all -- --check`
- `py -3 scripts/check_docs.py` → `Checked 16 Markdown files: encoding and
  local links OK`
- `git diff --check`

（2026-09-19 レビュー時に再実行: `cargo run --locked --bin mcp-writ --
run --help` で転記どおりの文言を確認、`cargo test --locked --lib cli::`
→ 70 passed / 0 failed、`cargo fmt --all -- --check`、
`python3 scripts/check_docs.py` → 同上メッセージ、`git diff --check`、
すべて終了コード0）

## P2. OS別の保証範囲とSBPL依存の整理

```text
作業ID: P2
実施日 / 担当: 2026-09-19 / Devin（エージェント）
対象コミット / 未コミット差分: HEAD = 6b15a5023f7912b987999fb43a0a0c3fd45f8a07
  （P1マージ済み、P2開始時点でワーキングツリーはクリーン）。
  P2の変更は未コミット差分としてワーキングツリーに保持:
  docs/guide.md、docs/guide.ja.md、docs/policy-authoring.md、
  docs/policy-authoring.ja.md、docs/development.md、
  および本節を追記した docs/arm64-security-results.ja.md。
  実装コード（src/）の変更はない（P2は文書化タスクであり、
  現行実装の挙動を正確に記述する範囲で実施）。
OS・カーネル・CPU / native・emulation: P0と同一（Windows 11 build 26200 /
  AMD Ryzen 5 9600X / native x86-64、WSL2 bash + Windows側ツールチェーン）。
  WSL側カーネル 5.15.167.4-microsoft-standard-WSL2（検証実行はWindows側バイナリ）。
Rust / Cコンパイラー / リンカー / Python・Node.js: rustc/cargo 1.98.1
  （x86_64-pc-windows-msvc）。Python 3.12.3（check_docs.py 実行に使用したWSL側）。
Capstone crate・Cコア・feature / iced-x86: 変更なし（P2は依存に触れない）。
Pure Rust候補の版 / 適合結果 / FFIが必要な場合の根拠: 対象外（P4の範囲）。
直接・推移的依存 / feature / build・dev依存 / ネイティブ依存の増減: 変化なし。
機能の維持 / 性能基準・測定条件・測定誤差 / 比較結果:
  実装変更なし。`cargo test --locked --lib policy::validator::` 28件、
  `cargo test --locked --lib warden::` 41件（AppContainer プロファイル
  作成・削除の実経路を約8秒で検証）、`cargo test --locked --lib auditor::`
  288件、すべて合格。ドキュメントに記述した挙動はこれらのテストと
  ソースコード上の文字列・条件分岐に対応付け済み。
fixture生成元・ハッシュ / 形式・ISA・ABI・slice: 対象外（KDL例の検証には
  一時的な管理ファイルを target/p2-kdl-check/ に作成し、検証後に削除。
  実データ・実サービスは未使用）。
検証コマンド / 終了コード: 後述。`run --policy` はケースごとに個別記録:
  読み込み成功3件は終了コード0、読み込み拒否5件は終了コード1。
  `Error loading policy` 系はバイナリ自身が `std::process::exit(1)`
  （src/main.rs）で終了するため、非ゼロ終了を0へ処理するラッパーは
  使用していない（処理前=1、処理後=1）。終了コードは PowerShell の
  `$LASTEXITCODE` で取得。成功ケースの fixture は
  `logging fail_closed=#false` を含めて `--audit-log` 省略時の起動拒否を
  回避し、spawn された `cmd /c exit 0` の終了コードがそのまま伝播する形を
  確認した。`run --policy` 以外の検証コマンドはすべて終了コード0。
期待値 / 実測結果:
  期待値: 日英ガイドの対応表・注記・KDL例が、現行 loader/validator/warden
    の挙動と一致し、未対応設定の結果（拒否・警告・未適用）を読み取れること。
  実測: 8個のKDLファイルを `run --policy` で読み込み確認（詳細は後述）。
    Windows固有の読み込み拒否3件と全OS共通の読み込み拒否2件は記述どおりの
    メッセージを確認。読み込み成功3件も確認。
結果: PASS（本機で実施可能な範囲）。Linux/macOS固有のメッセージ
  （Landlockスキップ警告、SBPLリモートホスト拒否、execve不足のspawn失敗）
  はソース上の文字列と対応テストを根拠とし、実機実行は未実施（SKIP）。
  macOSのSBPL実適用検証は macos-latest CI 依存であり本機では未実施。
証拠の保存先: 差分は `git diff -- docs` で確認可能。KDL検証の入出力は
  本節に転記。
残る制約・差分の理由:
  - `macos-latest` のOS版はGitHubランナーイメージ依存であり固定ではない。
    検証済みmacOS版として特定できるのはCI実行時点のイメージのみであり、
    その他の版は未検証として明記した。
  - Linux固有経路（Landlock適用・警告・degraded）は本機では実行不可のため
    実機検証は次段階以降またはCIの go-runtime（Linux sandboxed fixture）に委ねる。
  - 「未対応はすべて拒否」ではなく、拒否・警告・未適用・Auditor検査を
    設定ごとに区別して記述した（手順P2-2の最終項目）。
次段階へ進めるか / 必要な修正: P3へ進める。
```

### 変更内容（P2-1, P2-3, P2-5）

- `docs/guide.md` / `docs/guide.ja.md`:
  - 「Platform notes (macOS) / プラットフォーム注記（macOS）」を新設。
    SBPLの生成規則（グローバルFSのみ・loopback TCPポートのみ・リモート
    ホスト名はspawn拒否・syscalls未適用）、SBPLがAppleのサードパーティー
    向けサポート対象でないこと（根拠: Apple DTS の説明
    <https://developer.apple.com/forums/thread/661939>）、検証環境
    （macos-latest CIの `warden::` テスト、実spawn含む）、OS更新時の
    再検証手順を記載。
  - 「Per-OS enforcement matrix / OS別の適用範囲」を新設。手順P2-1の
    6行（FS・ネットワーク・syscall・適用失敗・非隔離実行・検証環境）を
    OSごとに「OSで適用 / Auditorで検査 / 拒否 / 警告 / 未適用」＋条件で整理。
  - 「KDL examples and rejection messages / KDL例と拒否メッセージ例」を
    新設。同一 `defaults.network` のOS別解釈4例と、全OS共通の読み込み
    拒否3例（サブパスdeny・per-tool syscalls・execve欠落はLinuxのみ
    spawn拒否）を掲載。
  - macOS FAQ の回答を新セクションへ誘導するよう更新。
- `docs/policy-authoring.md` / `docs/policy-authoring.ja.md`:
  `defaults.syscalls` が macOS/Windows で未適用であること、`defaults.network`
  のOS差と対応表への参照、グローバルFSのみがOS付与されるのは Windows と
  macOS（Linuxは許可ツール分も合成）である点、Linux のポート専用エントリと
  ホスト名スキップ警告、macOS loopback限定とリモートホスト spawn 失敗を追記。
  トラブルシュート表に `macOS SBPL cannot pin remote host` と
  `declares per-tool syscalls` の2行を追加。
- `docs/development.md`: 「Platform sandbox verification」節を新設。
  OSごとの検証環境・実行されているテスト・未実施範囲・必要な権限を記録
  （検証環境行の根拠）。

### 対応表の根拠対応（P2-2, P2-4）

- FS: `src/warden/landlock_impl.rs`（グローバル＋許可ツールのFS規則の合成、
  `landlock_base_path` のグロブ還元、失敗時 warn+skip、from_read=Execute
  含む）、`src/warden/macos_sandbox.rs`（グローバルのみ）、
  `src/warden/windows_sandbox.rs`（存在パスのみDACL、無警告スキップ）。
  サブパスdeny拒否は `src/policy/validator.rs`（全OS・読み込み時）と
  `landlock_impl.rs`（spawn時再検査）。
- ネットワーク: `landlock_impl.rs::collect_allowed_ports`（数値ポートのみ
  OS規則、非数値は warn+skip）、`macos_sandbox.rs::extract_local_port`
  （loopback変換・リモート拒否・ポートなしlocalhostは規則なし）、
  `windows_profile.rs::capabilities_for_policy`（deny-all=capabilityなし、
  無制限=internetClient系）、`validator.rs::validate_windows_network_enforcement`
  （`cfg!(windows)` 限定の読み込み拒否）。`inbound` は Landlock 非対応
  （BindTcp不付与）、SBPL・Windowsは無制限モード時のみ。
- syscall: `seccomp_impl.rs::require_execve_allowance`（spawn時拒否/
  degraded警告）、`linux_spawn.rs`（pre_exec内で no_new_privs→Landlock→
  seccomp の固定順）、`validator.rs::validate_per_tool_syscalls`（全OS拒否）。
- Auditor: `checker.rs`（グローバル allow/deny host 検査は allow 非空時、
  閉じた継承リストはツール側で拒否）。host:port→host の正規化は
  `src/policy/host.rs::normalize_policy_host` で、パース時に
  `kdl_parse.rs` から適用され、`checker.rs` の照合でも使用される。
- 非隔離実行: `main.rs`（--dry-run は `dry_run` を Auditor に渡し、
  `MCP_WRIT_SKIP_SANDBOX` は `skip_sandbox` のみに作用）、
  `auditor/proxy_c2s.rs`（`dry_run` 時のみ違反を転送=`Observed`、
  それ以外は遮断=`Denied`）、
  `warden/mod.rs`（非対応OSは警告のうえ無制約spawn）。

### KDL例の実測（P2-5、Windows側 `mcp-writ.exe` で `run --policy` を実行）

```text
deny-all.kdl      → Policy loaded (version 1)（読み込み成功）、終了コード0
allow-star.kdl    → Policy loaded (version 1)（読み込み成功）、終了コード0
no-execve.kdl     → Policy loaded (version 1)（読み込み成功）、終了コード0
                    （Linux spawn拒否は本機では検証不可のためコード上の
                    文言を転記）
port443.kdl       → Error loading policy: Invalid policy: Windows AppContainer
                    cannot enforce per-destination outbound allowlists; use an
                    empty allow list (deny all) or deny_all_others=false
                    (unrestricted), or place a network broker in front of the
                    sandbox、終了コード1
localhost8080.kdl → 同上（Windowsではホスト:ポートも同一の読み込み拒否）、
                    終了コード1
remote.kdl        → 同上、終了コード1
subpath-deny.kdl  → Error loading policy: Invalid policy: global path
                    '/workspace/secret/**' is denied under global allowed parent
                    path '/workspace/**'. Landlock additive rulesets cannot
                    carve out sub-path denials under an allowed directory、
                    終了コード1
tool-syscalls.kdl → Error loading policy: Invalid policy: tool 'read_file'
                    declares per-tool syscalls, which are not enforced; move
                    syscall rules to defaults.syscalls、終了コード1
```

終了コードは PowerShell `$LASTEXITCODE` で個別に取得。`Error loading
policy` の5件はポリシー読み込み失敗後にバイナリ自身が
`std::process::exit(1)` で終了する（src/main.rs の policy load エラー
経路）ため直接1を返し、非ゼロ終了を0へ変換するラッパーは介在しない
（ラッパー処理なし: 処理前=1、処理後=1）。

### 検証コマンド（`run --policy` 以外は終了コード0）

- `cargo build --locked --bin mcp-writ` → 成功、終了コード0
- `mcp-writ.exe run --policy <各KDL> -- cmd /c exit 0` → 上記の実測
  （成功3件=終了コード0、読み込み拒否5件=終了コード1。意図した
  エラー出力を確認）
- `cargo test --locked --lib policy::validator::` → 28 passed / 0 failed
- `cargo test --locked --lib warden::` → 41 passed / 0 failed
- `cargo test --locked --lib auditor::` → 288 passed / 0 failed
- `python3 scripts/check_docs.py` → `Checked 16 Markdown files: encoding and
  local links OK`
- `git diff --check` / `git diff --stat`

## P3. 診断と実アクセス比較

```text
作業ID: P3
実施日 / 担当: 2026-09-19 / Devin（エージェント）
対象コミット / 未コミット差分: HEAD = 204679af4e32c1cfd21fbb1db3852cba5bb45f5c
  （P2マージ済み、P3開始時点でワーキングツリーはクリーン）。
  P3の変更は未コミット差分としてワーキングツリーに保持
  （src/ 13ファイル、tests/ 5ファイル、docs/ 4ファイル、
  .github/workflows/ 2ファイル。一覧は `git status --short` 参照）。
OS・カーネル・CPU / native・emulation: P0と同一（Windows 11 build 26200 /
  AMD Ryzen 5 9600X / native x86-64、WSL2 bash + Windows側ツールチェーン）。
  WSL側カーネル 5.15.167.4-microsoft-standard-WSL2（検証実行はWindows側バイナリ）。
Rust / Cコンパイラー / リンカー / Python・Node.js: rustc/cargo 1.98.1
  （x86_64-pc-windows-msvc、x86_64-unknown-linux-gnu の両ターゲットで
  check/clippy を実施）。fixture は rustc -O 単体でコンパイル
  （tests/common::compiled_open_path_fixture）。
Capstone crate・Cコア・feature / iced-x86: 変更なし（P4の範囲）。
Pure Rust候補の版 / 適合結果 / FFIが必要な場合の根拠: 対象外（P4の範囲）。
直接・推移的依存 / feature / build・dev依存 / ネイティブ依存の増減:
  クレート増減なし。windows crate の有効化 feature（Win32_Security_Isolation
  等）は P3 開始前の HEAD に存在していたものをそのまま利用。
機能の維持 / 性能基準・測定条件・測定誤差 / 比較結果:
  既存 lib テスト 1301 件全合格（変更込み）。既存 e2e 4 ターゲット
  （integration 12、kdl_policy_e2e 18、self_test 4、tool_enforcement_e2e 25）
  全合格。新規 e2e 2 ターゲット追加（後述）。
fixture生成元・ハッシュ / 形式・ISA・ABI・slice:
  tests/fixtures/mcp_servers/open_path_server.rs（Rust、rustc -O で
  テスト時コンパイル）と tests/fixtures/mcp_servers/open_path.py
  （Python、同等ツール群）。ツール: read_file / create_file / ident /
  kind / wait_file / open_env。識別情報は Unix=dev/ino、
  Windows=GetFileInformationByHandle の volume/file_index（安定 API の
  FFI、FILETIME を u32 ペアで正しいレイアウトに修正済み）。
検証コマンド / 終了コード: 後述。すべて終了コード0。
期待値 / 実測結果:
  P3-A: Auditor拒否・tools/list検証失敗・サンドボックス設定/適用失敗・
    汎用spawn失敗・子プロセス側アクセス失敗を相互に区別し、確立した
    事実のみを stderr/JSONL 監査に出す（stdoutはJSON-RPCのみ）。
  P3-B: Auditorの解釈（extract_fs_targets→正規化→cwd結合+字句化+
    canonicalize）と、fixtureが実際にopenした対象のOS識別情報を比較。
    OS境界（Auditor非介在の内部アクセスがOS許可外へ届かない）と
    プロセス共通権限（ツール用fs許可≠プロセス単位のOS許可）を分離。
  実測: Windowsで新規8件全合格。Linuxはcheck/clippyでコンパイル確認、
    実行はCIに委譲（後述の制約）。
結果: PASS（本機で実施可能な範囲）。
証拠の保存先: 差分は `git diff` / `git status --short` で確認可能。
  新規テストファイルは tests/path_resolution_e2e.rs と
  tests/diagnostics_e2e.rs。
残る制約・差分の理由:
  - Linux 固有経路（Landlock/seccomp 適用下の fixture 実行）は本機では
    実行不可。x86_64-unknown-linux-gnu で check/clippy 済み（警告0）だが、
    実実行は ubuntu-latest CI に委譲。macOS は cfg コードレビューのみ。
  - Windows の sandboxed e2e は AppContainer の per-object DACL 付与に
    合わせ、exe ステージング・ファイル単位 grant で動作確認済み。
    Linux では同一ポリシー生成関数が Landlock PathBeneath 用に
    ディレクトリ grant を出力する（cfg 分岐）。
  - 子の自然終了コードの e2e 伝播は select! 競合（Auditor EOF完了と
    child wait の同時成立）で非決定的なため e2e 対象外とし、
    observed_exit_code のユニットテスト（signal→128+sig、exit code
    伝播）で担保。
次段階へ進めるか / 必要な修正: P4は本タスクの範囲外。P3としては完了。
```

### 変更内容（P3-A: 診断の分類）

- `src/error.rs`: `SandboxStage` enum（`Policy`/`Prepare`/`Apply`）を新設し、
  `WardenError::SandboxSetup{stage, detail}` が確立した失敗段階を保持。
  Display は `Sandbox setup failed during '<stage>' stage on <os>: <detail>`。
  `ProcessSpawn` は段階未確定の spawn 失敗専用（Sandbox 適用失敗とは
  表示しない）。`AuditorError::VerificationFailed` を新設し、tools/list・
  サーバーフレーム検証によるセッション中断をリクエスト単位のポリシー
  違反（`PolicyViolation`）と分離。
- `src/warden/*`: 全 `SandboxSetup` 構築箇所を段階分類（ポリシー変換=
  Policy、ルールセット/BPF/プロファイル/SID/パイプ等の成果物=Prepare、
  ACL付与・Job割当・スレッド再開等のOS状態適用=Apply）。fork/pre_exec/
  CreateProcessW の失敗は `ProcessSpawn` のまま（段階未確定をSandbox
  失敗と偽らない）。`windows_proc.rs` に `win32_to_io` ヘルパー追加。
  Linux `pre_exec` には割り当て・複雑処理を追加していない。
- `src/auditor/proxy_tools_list.rs` / `proxy_c2s.rs` / `proxy_s2c.rs` /
  `proxy.rs`: tools/list 検証・サーバーフレーム検証の中断経路を
  `PolicyViolation` → `VerificationFailed` に再分類。
  `proxy.rs` の abort 集約も両型を等しく扱う。
- `src/auditor/audit_log.rs`: `AuditEvent.request_id: Option<String>` を
  追加し JSONL に `request_id` フィールドを出力（生JSONトークン保持。
  文字列 id は引用符込み、数値 id は裸）。
- `src/auditor/proxy_c2s.rs`: `tool_call.denied` イベントにクライアントの
  生リクエスト id を `request_id` として設定。
- `src/runtime/launch.rs`: Warden spawn 失敗時に `server.error`
  （Severity::High / Failure / Observed）監査イベントを記録してから
  `LaunchError::Spawn` を返す。呼び出し側は stderr に
  `failed to spawn MCP server '<cmd>': <warden error>` を出力。
- `src/runtime/wait.rs`: `observed_exit_code` を追加し、子のシグナル死を
  `128 + signal`（Unix）で報告。exit code 1 への潰れを解消。
  ユニットテスト追加（signal→137、exit 7 伝播。Windows は exit 7）。

### 変更内容（P3-B: Auditor解釈と実アクセスの比較）

- `src/pathutil.rs`: `resolve_for_authorization_with_cwd` を追加し、
  `resolve_for_authorization`/`join_with_cwd` はそれぞれ
  `resolve_for_authorization_with_cwd`/`join_with` へ委譲。テストが子の
  cwd（=fixtureのcwd）での Auditor 解釈を再現できる。
- `tests/fixtures/mcp_servers/open_path_server.rs` / `open_path.py`:
  ツール群を拡張。`read_file`（実open+識別情報）、`create_file`
  （create_new書き込み+作成物と親dirの識別情報。相対パスは親=`.`）、
  `ident`（lstat/stat を open なしで報告）、`kind`、
  `wait_file`（barrier ファイル出現まで待ってから open。sleep ではなく
  決定論的同期）、`open_env`（環境変数経由の内部アクセス。引数に
  fs ターゲットを含まない）。Rust 側は自前の最小 JSON パーサー
  （nojson 非依存）を実装。ツール失敗は `result.isError=true` で報告
  （JSON-RPC プロトコルエラーにしない）。
- `tests/path_resolution_e2e.rs`（新設、6テスト）:
  - `interpretation_agrees_on_common_forms`: 絶対パス・相対`.`・`..`でB
    脱出・共有prefix兄弟（allowed_a vs allowed_a_extra）・Unicode名・
    存在しない末尾・create先+親識別情報。`checker::extract_fs_targets`→
    `normalize_fs_argument`→`resolve_for_authorization_with_cwd` で再現した
    Auditor解釈と、fixture が報告した canonical+handle識別情報を比較。
  - `interpretation_records_encoding_divergences`: JSON `\uXXXX`（両者一致）、
    percent-encoding（Auditorは正規化でデコード→marker解決、fixtureは
    リテラルopen→ENOENT。差異を記録）、file: URI（同上）、NUL（両者
    失敗）、大小文字（Windowsは同一object到達、case-sensitive FSでは
    Auditor字句解決 vs ENOENT）。
  - `symlink_resolution_and_wait_file_barrier`: 静的 symlink は Auditor/
    fixture ともにB実体へ一致。`wait_file`+barrier で検査時点（→A）と
    open時点（swap後→C）を確定的に分離し、TOCTOU の post-check swap を
    固定回帰ケースとして記録（handle識別情報でC到達を証明）。
  - `windows_verbatim_and_plain_drive_forms`（Windowsのみ）: verbatim
    `\\?\` と plain drive 形式は同一objectへ到達。UNCは管理対象の
    共有が無いため NOTE で skip を記録。
  - `windows_junction_and_drive_relative_forms`（Windowsのみ）: junction
    は Auditor/fixture ともにB実体へ一致（mklink /J 不可時は skip記録）。
    drive-relative `C:name` は Auditor が cwd 字句結合（`A\C:name`）する
    一方 Windows は drive のカレントディレクトリで解決し A/marker.txt を
    開く — 解釈と実アクセスの不一致を記録した回帰ケース。
  - `sandboxed_os_boundary_and_process_shared_access`: `mcp-writ run` を
    sandbox 有効（`MCP_WRIT_SKIP_SANDBOX` 除去）で起動。precondition
    「Cは sandbox 適用前に読める」を確認。Aの read_file（Auditor許可+
    OS許可）成功→Bの read_file（プロセス許可内だがtool fs外）を
    Auditor拒否→`open_env`（引数にfsターゲットなし=pathless許可ツール）
    による内部openでCが OS境界（EACCES）で失敗→同一`open_env`で
    Bはプロセス共通許可により到達可能（設計上の制約として記録）。
    監査 `tool_call.denied` の `request_id`/`target_tool` を検証。
- `tests/diagnostics_e2e.rs`（新設、P3-A e2e）:
  - `auditor_denial_carries_request_id_and_keeps_stdout_clean`: 文字列 id
    `"req-42"` の拒否で監査 `request_id` が `"req-42"`（引用符込み生
    トークン）、`server.error` 非発行、stdout は全行 JSON-RPC。
  - `child_enoent_is_tool_error_not_warden_denial`: 許可glob内の不存在
    ファイルは isError+ENOENT のツール結果。`tool_call.denied`/
    `server.error`/`sandbox.*` 非発行。
  - `child_eperm_is_tool_error_not_warden_denial`（Unixのみ）: chmod 000
    で EACCES。同上の非発行を検証。
  - `spawn_failure_is_audited_as_server_error_and_off_stdout`: 実行不能
    ファイルを子に指定（SKIP_SANDBOXで両OS決定的）→ 非ゼロ終了、
    stdout 空、stderr に `failed to spawn MCP server`、`Sandbox setup
    failed` を含まない、監査 `server.error`（spawn失敗記述）。
  - `sandbox_policy_stage_failure_is_distinct_from_spawn`（Linuxのみ）:
    execve 欠落 syscalls → `Sandbox setup failed during 'policy' stage`
    + execve を stderr に、監査 `server.error`（policy段階）。
- `tests/common/mod.rs`: `compiled_open_path_fixture` を共通ヘルパー化
  （rustc -O、テストバイナリごとに1回）。

### 組み込み（runbook手順8）

- `.github/workflows/ci.yml` / `platform-tests.yml`:
  `--test path_resolution_e2e --test diagnostics_e2e` を Protocol and
  policy integration tests に追加。
- `docs/arm64-security-runbook.ja.md`: P3の検証コマンド一覧に同2ターゲット
  を追記。

### 診断文書・モジュール不変条件（P3-A文書化）

- `docs/guide.md` / `docs/guide.ja.md`: FAQ に「障害が Auditor・
  サンドボックス・spawn・サーバー自身のどこで起きたか」の切り分け表を
  追加（Auditor拒否/検証失敗/各spawn段階/子側isError/シグナル死）。
  旧形式 `Sandbox setup failed: ...` の2例を新形式（stage+os入り）に更新。
- `docs/modules.md`: 不変条件に診断分類（stage保持・子側EPERMの
  再分類禁止・request_id保持・VerificationFailed分離・stdout非汚染）を追加。

### 検証コマンド（すべて終了コード0、Windows側で実行）

- `cargo fmt --all -- --check` → 差分なし
- `python3 scripts/check_docs.py` → `Checked 16 Markdown files` OK
- `cargo clippy --locked --all-targets` → 警告0
- `cargo clippy --locked --all-targets --target x86_64-unknown-linux-gnu`
  → 警告0
- `RUSTDOCFLAGS=-D warnings cargo doc --locked --no-deps` → 成功
- `cargo check --locked --all-targets --target x86_64-unknown-linux-gnu`
  → 成功
- `cargo test --locked --lib --bins` → 1301 passed / 0 failed
- `cargo test --locked --test integration --test tool_enforcement_e2e
  --test kdl_policy_e2e --test self_test` → 12+25+18+4 全合格
- `cargo test --locked --test diagnostics_e2e --test path_resolution_e2e`
  → 3+6 全合格（Windows。Unix/Linux限定テストはcfgで対象外）
- `cargo test --locked --lib runtime::` → 12 passed（wait::tests の
  Windows側 exit code 伝播を含む）
