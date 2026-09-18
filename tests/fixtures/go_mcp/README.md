# Go runtime MCP fixture

Go製MCPサーバとmcp-writの互換性を調べる、ローカルstdio専用のテスト用サーバです。
[公式MCP Go SDK v1.8.0](https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.8.0)を使用し、
サーバと動作確認クライアントを1つの実行ファイルにまとめています。
外部サービス、APIキー、LLM、実行時のネットワーク接続は不要です。依存関係の初回取得にはネットワークが必要です。

目的は、直接起動とmcp-writ経由の結果を比較し、MCP通信・Goランタイム・ポリシー拒否を切り分けることです。
本番サーバ、全Goバージョン、全OS・カーネルの安全性を保証するテストでもありません。

結果は実行したコミットと環境に依存します。直接起動とguard経由を、対象OSでそれぞれ確認してください。

## テスト内容

| ツール | 内容 |
| --- | --- |
| `echo` | 最大4,096バイトの文字列をそのまま返す。probeでは16並列呼び出しの応答対応も確認 |
| `runtime_info` | Goバージョン・OS・アーキテクチャ。Linuxでは`gettid`と`prctl`によるseccomp/NoNewPrivsの状態も取得 |
| `runtime_stress` | OSスレッド作成、再帰によるスタック拡張、メモリ確保、GC、タイマーを実行 |
| `blocked_echo` | 内容は安全なecho。直接起動では成功し、生成ポリシーではAuditorによる拒否を期待 |

`runtime_stress`の入力は`workers`が1～16、`rounds`が1～32、`allocKiB`が1～256です。
同時に実行するstress呼び出しは1つに制限します。保持するペイロードは最大128 MiBですが、
Goランタイム・SDK・スレッド等を含むプロセス全体のメモリ上限ではありません。
probeの既定値は8スレッド、64反復、計4 MiBです。チェックサムとGC実施、処理後の生存も確認します。

ツールは任意ファイル読み書き・子プロセス起動・ネットワーク接続を提供しません。
サーバの標準出力はMCP通信専用です。probe側は子プロセス起動と結果ファイル保存を行います。
通常のMCPクライアントにつなぐ場合は、ビルドした実行ファイルを**引数なし**のstdioサーバとして指定してください。
`probe`は検証クライアント用の引数です。MCPクライアントの設定へ`probe`を渡さないでください。

## Windowsでのビルドと実行

Go 1.25以上が必要です。以下はリポジトリルートからPowerShellで実行します。
GoモジュールはRust側と独立しており、`cargo test`だけではGoテストは実行されません。

```powershell
Push-Location tests/fixtures/go_mcp
go test ./...
go vet ./...
go build -trimpath -o ../../../target/go-runtime/go-runtime-mcp.exe .
Pop-Location

# まずサーバ単体で確認
.\target\go-runtime\go-runtime-mcp.exe probe
.\target\go-runtime\go-runtime-mcp.exe probe -protocol 2026-07-28

# 次にmcp-writ経由。こちらの成功は別途必要
cargo build --locked --bin mcp-writ
.\target\go-runtime\go-runtime-mcp.exe probe -guard .\target\debug\mcp-writ.exe
.\target\go-runtime\go-runtime-mcp.exe probe -guard .\target\debug\mcp-writ.exe -protocol 2026-07-28
```

実行ファイルとその専用ディレクトリは、mcp-writを動かすユーザー自身で作成してください。
Windows WardenはAppContainer用のACLを設定するため、別ユーザー所有のビルド出力では
`SetNamedSecurityInfoW`のアクセス拒否になり、Goの処理に到達しないことがあります。
管理者実行やサンドボックス無効化を常用するための手順ではありません。

## Linuxでのビルドと実行

以下はGo、Rustのビルド環境とmcp-writが要求するサンドボックス機能を備えたLinuxで、
リポジトリルートから実行します。Windowsでの成功はLinuxのseccomp/Landlock互換性を証明しません。

```sh
(
  cd tests/fixtures/go_mcp
  go test ./...
  go vet ./...
  CGO_ENABLED=0 go build -trimpath -o ../../../target/go-runtime/go-runtime-mcp .
)

./target/go-runtime/go-runtime-mcp probe
./target/go-runtime/go-runtime-mcp probe -protocol 2026-07-28

cargo build --locked --bin mcp-writ
./target/go-runtime/go-runtime-mcp probe -guard ./target/debug/mcp-writ
./target/go-runtime/go-runtime-mcp probe -guard ./target/debug/mcp-writ -protocol 2026-07-28
```

## ポリシーと結果の読み方

probeの既定プロトコルは`2025-11-25`です。`-protocol 2026-07-28`も選択できます。
要求したバージョンとネゴシエーション結果が一致しなければ失敗します。
全体のタイムアウトは既定で30秒です。低速環境では`-timeout 60s`などを指定します。

`-guard`を指定すると、実行ファイルのある専用ディレクトリの読み取り、外部通信禁止、
Go用の診断的syscall候補、4ツールの許可・拒否を含む`policy.kdl`を結果ディレクトリに生成します。
起動用FS権限はグローバルに残し、パス不要の3ツールでは`allow none=#true`と`require-path #false`を使います。
パスの持ち込みは引き続き拒否されます。この構文に対応したmcp-writが必要です。
これは本番用の最小権限ポリシーではなく、任意のGoサーバ・環境との動作保証もありません。
特に`clone`/`clone3`や`execve`を含むため、本番にそのまま転用しないでください。
`execve`は現在の起動条件に合わせたものです。プロセス起動禁止の検証ではありません。

`-policy /absolute/path/policy.kdl`を併用すると、そのポリシーを変更せずに使用します。
fixtureの3ツールが許可され、`blocked_echo`が拒否される必要があります。
実際のMCPサーバ用ポリシーにfixtureのツールがない場合、その拒否はGo互換性の失敗とは限りません。
probeは`MCP_WRIT_SKIP_SANDBOX`を子プロセス環境から除去し、dry-runやdegraded設定を自動追加しません。
指定ポリシー自体にdegraded等が設定されていないかも確認してください。

各回の結果は`target/go-runtime-results/probe-*`に保存されます。`-output`で親ディレクトリを変更できます。

- `result.json`: 成否、要求プロトコル、guard・policy指定、失敗内容。成功時は終了コード0、失敗時は1。
- `checks.log`: 成功済みチェックとランタイム情報。
- `stderr.log`: サーバとmcp-writの標準エラー。起動失敗やクラッシュの調査に使用。
- `policy.kdl`: 自動生成した場合のポリシー。
- `audit.jsonl`: guard実行時の監査ログ。起動に失敗した場合は作成されないことがあります。

`blocked_echo`の拒否はJSON-RPCのAuditor層の確認です。OSが禁止ファイルアクセスや通信を拒否することを証明しません。
Linuxで確認するseccomp=2とNoNewPrivs=1も、フィルター内容やLandlockの実効性の証明ではありません。
カーネル側の隔離検証には既存のWardenテストを併用してください。

`gettid`、`tgkill`、`eventfd2`などは生成ポリシーに含め、Wardenの名前変換にも対応を追加しています。
他のsyscallや古いmcp-writが名前変換に未対応の場合、名前を書いても許可されません。
`unknown syscall name`の警告やGoランタイム異常を、サンドボックス解除で隠さないでください。

## CI

`.github/workflows/go-runtime.yml`の`Go MCP runtime compatibility`は、手動実行とリリース時の検証で使用します。
WindowsとUbuntu 24.04でGo 1.25.4を使い、両プロトコルの直接起動とguard経由を比較します。
失敗時も結果・監査ログを7日間のartifactとして保存します。
Linuxで隔離機能が不足している場合も、隔離解除やdegradedへの自動切り替えはせず失敗として扱います。
