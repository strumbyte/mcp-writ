# クイックスタート詳解

README のクイックスタートを、版を固定した
`@modelcontextprotocol/server-filesystem` `2026.8.31` で端から端まで実行する
手順です。簡略版では省いたサンドボックス有りの検査も含みます。
`/srv/mcp-data` はサーバーにアクセスさせるディレクトリに置き換え、Rust と
Node.js をインストールした環境の
[ソースチェックアウト](https://github.com/strumbyte/mcp-writ)で実行します。

## 1. インストール

```sh
cargo install --locked --path . --bin mcp-writ
npm install -g @modelcontextprotocol/server-filesystem@2026.8.31
```

## 2. ホスト用ポリシーを書く

[レビュー済みの例](../examples/policies/filesystem.kdl)はサーバーのツール
一覧（`tools-list-hash`）とツールごとの規則をピンしていますが、ホスト固有の
パスは意図的に含んでいません。チェックアウト直下に `policy.kdl` を作成して
例を継承し、このホストの `defaults` — インタプリタの読み取りパス、データ
ルート、syscall 一覧（Node については実測値を `runtime/node.kdl` 経由で
例が継承済み）— を足します。

```sh
# このホストの node インストールとグローバルパッケージツリーを解決する —
# command -v node は shim/symlink を返すことがあるので、リンクをたどって
# 実体のディレクトリとプレフィックスを取る
node_bin="$(command -v node)"
while [ -L "$node_bin" ]; do
    link="$(readlink "$node_bin")"
    case "$link" in
        /*) node_bin="$link" ;;
        *)  node_bin="$(dirname "$node_bin")/$link" ;;
    esac
done
node_dir="$(dirname "$node_bin")"
node_prefix="$(dirname "$node_dir")"
npm_root="$(npm root -g)"

cat > policy.kdl <<EOF
policy version=1
extends "examples/policies/filesystem.kdl"
defaults {
    filesystem {
        allow "$node_dir" mode="read"                    // 解決済みの node bin ディレクトリ
        allow "$node_prefix" mode="read"               // 解決済みの node プレフィックス
        allow "$npm_root" mode="read"                  // グローバル npm パッケージツリー
        allow "/usr/lib" mode="read"                   // 共有ライブラリ
        allow "/usr/bin" mode="read"                   // shim の shebang から exec される env
        allow "/lib" mode="read"
        allow "/lib64" mode="read"
        allow "/proc" mode="read"                      // V8/libuv が /proc/self/* を読む。`self` は自己解決 symlink のため Landlock では /proc 以下へ絞れない — 他プロセスの procfs 情報も読めるため、専用 OS ユーザーで隔離した検証用の例としてのみ許可すること
        allow "/dev/null" mode="write"                 // インタプリタが O_RDWR で開く
        allow "/srv/mcp-data" mode="read"              // サーバーに渡すデータルート
        secret-overlay #true
    }
}
server "filesystem" {
    tool "read_file" { filesystem { allow "/srv/mcp-data/**" } }
}
EOF
```

例はパスを取るツールに空の許可リスト（`allow none=#true`）を設定して
います。`read_file` は上記の `allow "/srv/mcp-data/**"` 上書きでデータ
ルートを使えますが、上書きのないパスを取るツールは自分のデータ
ルートへの `allow` を追加するまで fail-closed のままです
（`list_allowed_directories` はパスを取らず、そのまま呼べます）。複数の
サーバーを定義したポリシーでは `--server <名前>` を指定してください。

## 3. ツール一覧の検出

`generate-policy --live-discovery` は制限環境でサーバーを起動して
`tools/list` を問い合わせ、検出した `tools-list-hash` を含む独立した草案
ポリシーを書き出します（`policy.kdl` は読み込みません）。

```sh
mcp-writ generate-policy --live-discovery --output policy.draft.kdl -- "$(command -v mcp-server-filesystem)" /srv/mcp-data
```

草案の `tools-list-hash` と `tool` ブロックを
`examples/policies/filesystem.kdl` のピン済みの値と比較してください。差が
あればサーバーのツール面が変わっているため、ポリシーの再レビューが必要
です。正式な照合は手順 5 で行われ、`run` が監査ログに `hash.verified`
を記録します。

`generate-policy` と `run` のどちらも、`mcp-server-filesystem` の裸名を
`PATH` 経由で解決し、npm の shim が指す `dist/index.js` がバインド
対象になります。shim を直接起動する場合、shebang の
`#!/usr/bin/env node` が選ぶ `node` はピンされず、`generate-policy` は
そのギャップを `// REVIEW:` コメントで記録します。インタプリタを
ピンするには JavaScript ファイルを `node` で起動してください —
`node <prefix>/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js`。
どちらの場合も、shim の shebang が起動時に `node` を `PATH` から
見つけられる必要があります。

## 4. ガードをドライランする

dry-run は OS サンドボックスを無効にし、ポリシー違反を `observed` として
記録しつつ転送するため、検証用データを使ってください。

```sh
mcp-writ run --dry-run --policy policy.kdl --audit-log ./audit.jsonl -- mcp-server-filesystem /srv/mcp-data
```

クライアント（または JSON-RPC スクリプト）をこのコマンドに向けると、許可
ルート配下の `read_file` は成功して `tool_call.allowed` と記録され、
`/tmp/hello-denied.txt` のような範囲外のテストファイルは転送されますが
`tool_call.denied`（`action="observed"`）として記録されます。

## 5. サンドボックス有りの検査

`check-server` はまず `server/discover` でサーバーのプロトコル世代を
確認し、交渉した世代のハンドシェイク + `tools/list` を OS
サンドボックスを有効にした状態でガード越しに再生します。`--call` を
付けると `tools/call` を 1 件追加します。

```sh
scripts/check-server.sh --policy policy.kdl -- mcp-server-filesystem /srv/mcp-data

# データルート配下にマーカーファイルを作り、許可される呼び出しを試す
scripts/check-server.sh --policy policy.kdl \
  --call '{"name":"read_file","arguments":{"path":"/srv/mcp-data/marker.txt"}}' \
  -- mcp-server-filesystem /srv/mcp-data
```

各段が PASS し、監査ログに `hash.verified`（details は
`tools-list-hash verified` — `tools/list` のピン照合）が記録されることを
確認してください。このポリシーは起動対象のハッシュ
（`binary-hash`/`entrypoint-hash`）を持たないため、起動対象の
`hash.verified` は記録されません。`--call` を付けた場合は
`tool_call.allowed` も記録されます。
Landlock ABI V1 のみのカーネルでは、ポリシーに
`sandbox allow_degraded=#true` がないとサンドボックス有りの段が
fail-closed で起動を拒否します（「[注意点](#注意点)」参照）。拒否された
呼び出しは JSON-RPC エラーとして返り、`check-server` はそれを段の失敗と
して数えるため、拒否の観察は dry-run またはクライアントセッションで
行ってください。

## 6. Windows

Windows では npm の shim は解析入力として使えず、AppContainer 下ではこの
パッケージの symlink 構造で Node の `fs.realpath` が失敗するため、この
検証手順は `node` 経由で起動し、同梱の realpath スタブを preload します。
このスタブは検証用の補助であり、デプロイ手順ではありません —
`fs.realpath` の置き換えはサーバー自身の symlink エスケープ検査を
無効にし、下のポリシーもデータルート以外（node のプレフィックス、
パッケージツリー、チェックアウト）への OS レベルの読み取りを許可して
います。スタブの使用は検証環境に限定してください。スタブ無しで
サンドボックス付きデプロイができるかは未検証です — symlink を含まない
パッケージ配置（例: 実ディレクトリにコピーした `dist/` ツリー）なら
サーバー自身の検査が `fs.realpath` の解決先を調べられる可能性は
ありますが、AppContainer 下では全パスで EPERM を返すため、スタブ無しの
サンドボックス起動はエンドツーエンドで確認されておらず、現時点では
デプロイ形として案内しません。

手順 2 の `policy.kdl` は Linux パスのみを許可するため、先に Windows 用の
`policy.kdl` を作成します。`/` を使うと KDL のバックスラッシュのエスケープを
避けられます。`nodeDir` はインストール済みのプレフィックス（例:
`C:/Program Files/nodejs`）に解決されます。

```powershell
$nodeDir = (Get-Command node).Source | Split-Path -Parent
$pkgDir = "$env:APPDATA\npm\node_modules" -replace '\\','/'
$workDir = $PWD.Path -replace '\\','/'
$policy = @"
policy version=1
extends "examples/policies/filesystem.kdl"
defaults {
    filesystem {
        allow "$($nodeDir -replace '\\','/')" mode="read"  // node のインストールディレクトリ
        allow "$pkgDir" mode="read"                        // サーバーのパッケージツリー
        allow "$workDir" mode="read"                       // チェックアウト直下: 子プロセスの cwd と realpath スタブ — チェックアウト全体が読み取り対象
        allow "C:/mcp/data" mode="read"                    // データルート
        secret-overlay #true
    }
}
server "filesystem" {
    tool "read_file" { filesystem { allow "C:/mcp/data/**" } }
}
"@
[IO.File]::WriteAllText("$PWD\policy.kdl", $policy)
```

`$workDir` の許可は意図的に広く取っています — 子プロセスの作業
ディレクトリがチェックアウトであり（AppContainer は許可のない cwd での
起動を拒否します）、realpath スタブが `tests/fixtures/real_servers/node`
配下にあるため、チェックアウト全体が OS レベルで読み取り可能になります。
絞り込む場合は `win-realpath-stub.cjs` を専用ディレクトリにコピーし、
`check-server.ps1` をそのディレクトリから実行して、`$workDir` の
代わりにそのディレクトリだけを許可してください。チェックアウト外から
実行するため、スクリプトはチェックアウト基準の絶対パス
（`C:\path\to\mcp-writ\scripts\check-server.ps1`）で呼び出し、
`--require` にはスタブコピーの絶対パスを指定します。`policy.kdl` は
チェックアウトに置いたまま `-Policy` に絶対パスを渡してください —
`extends` はポリシーファイル基準で解決されるため、ポリシーを専用
ディレクトリに移す場合は `examples/policies/` ツリー（`runtime/` を
含む）のコピーも必要です。

その後、Windows の起動形で検出・ドライラン・検査を実行します。

```powershell
mcp-writ generate-policy --live-discovery --output policy.draft.kdl -- node "$env:APPDATA\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js" C:\mcp\data
mcp-writ run --dry-run --policy policy.kdl --audit-log .\audit.jsonl -- node "$env:APPDATA\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js" C:\mcp\data
scripts\check-server.ps1 -Policy policy.kdl node --preserve-symlinks-main --preserve-symlinks --require (Resolve-Path tests\fixtures\real_servers\node\win-realpath-stub.cjs).Path "$env:APPDATA\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js" C:\mcp\data
```

## 注意点

- Landlock/seccomp は Linux のみの要件です — Linux のサンドボックス起動に
  は Landlock/seccomp 対応カーネルが必要です。Windows のサンドボックス
  経路は別で、§6 の AppContainer 起動形と `check-server.ps1` が対応します。
  Landlock ABI V1 のみのカーネル（WSL2 の kernel 5.15 など）では
  サンドボックスは部分適用になります。`sandbox allow_degraded=#true` で
  その状態の起動を許可できますが、完全な保護の証明にはなりません。
- 生成された草案のツール権限、パス、ネットワーク、システムコールは使用
  前に確認してください。静的解析だけでポリシーの完全性や安全性が保証
  されるわけではありません。[ポリシー作成ガイド](policy-authoring.ja.md)
  を参照してください。
- コンテナを使う場合は、CLI と同じ場所の `runners/` に Linux 用
  `mcp-secure-runner` を配置します。詳細は
  [コンテナガイド](guide.ja.md#6-コンテナラッピング詳解)を参照して
  ください。
