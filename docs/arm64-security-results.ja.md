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
