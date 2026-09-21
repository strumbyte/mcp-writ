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
cat > policy.kdl <<'EOF'
policy version=1
extends "examples/policies/filesystem.kdl"
defaults {
    filesystem {
        allow "/home/your-user/.local/node" mode="read"  // 解決済みの node プレフィックス
        allow "/usr/lib" mode="read"                   // 共有ライブラリ
        allow "/usr/bin" mode="read"                   // shim の shebang から exec される env
        allow "/lib" mode="read"
        allow "/lib64" mode="read"
        allow "/etc" mode="read"
        allow "/proc" mode="read"
        allow "/dev" mode="read"
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

例はすべてのツールに `<ALLOWED_ROOT>` プレースホルダをピンしているため、
上記の `read_file` のように対応する上書きがないツールは、自分のデータ
ルートで置き換えるまで fail-closed のままです。複数のサーバーを定義した
ポリシーでは `--server <名前>` を指定してください。

## 3. ツール一覧の検出

`generate-policy --live-discovery` は制限環境でサーバーを起動し、ピンされた
`tools-list-hash` をライブの `tools/list` 結果と照合します。

```sh
mcp-writ generate-policy --live-discovery --output policy.draft.kdl -- "$(command -v mcp-server-filesystem)" /srv/mcp-data
```

`generate-policy` は解析のためにサーバー引数をファイルとして開くため、
npm の shim（`dist/index.js` への symlink。上記のとおり）の解決済みパスを
渡すか、`node <prefix>/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js`
の形を使ってください。`mcp-server-filesystem` の裸名はここでは `PATH`
解決されず `Error reading binary` で失敗します。`run` は裸名を自分で
解決しますが、どちらの場合も shim の `#!/usr/bin/env node` shebang が
起動時に `node` を `PATH` から見つけられる必要があります。

## 4. ガードをドライランする

dry-run は OS サンドボックスを無効にし、ポリシー違反を `observed` として
記録しつつ転送するため、検証用データを使ってください。

```sh
mcp-writ run --dry-run --policy policy.kdl --audit-log ./audit.jsonl -- mcp-server-filesystem /srv/mcp-data
```

クライアント（または JSON-RPC スクリプト）をこのコマンドに向けると、許可
ルート配下の `read_file` は成功して `tool_call.allowed` と記録され、
`~/.ssh/id_rsa` のような範囲外のパスは転送されますが
`tool_call.denied`（`action="observed"`）として記録されます。

## 5. サンドボックス有りの検査

`check-server` は OS サンドボックスを有効にした状態で、ガード越しに
initialize + `tools/list` を再生します。`--call` を付けると `tools/call`
を 1 件追加します。

```sh
scripts/check-server.sh --policy policy.kdl -- mcp-server-filesystem /srv/mcp-data

# データルート配下にマーカーファイルを作り、許可される呼び出しを試す
scripts/check-server.sh --policy policy.kdl \
  --call '{"name":"read_file","arguments":{"path":"/srv/mcp-data/marker.txt"}}' \
  -- mcp-server-filesystem /srv/mcp-data
```

各段が PASS し、監査ログに `hash.verified` が記録されることを確認して
ください。`--call` を付けた場合は `tool_call.allowed` も記録されます。
拒否された呼び出しは JSON-RPC エラーとして返り、`check-server` はそれを
段の失敗として数えるため、拒否の観察は dry-run またはクライアント
セッションで行ってください。

## 6. Windows

Windows では npm の shim は解析入力として使えず、AppContainer 下ではこの
パッケージの symlink 構造で Node の `fs.realpath` が失敗します。`node`
経由でサーバーを起動し、同梱の realpath スタブを preload します。

```powershell
mcp-writ generate-policy --live-discovery --output policy.draft.kdl -- node "$env:APPDATA\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js" C:\mcp\data
mcp-writ run --dry-run --policy policy.kdl --audit-log .\audit.jsonl -- node "$env:APPDATA\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js" C:\mcp\data
scripts\check-server.ps1 -Policy policy.kdl node --preserve-symlinks-main --preserve-symlinks --require tests\fixtures\real_servers\node\win-realpath-stub.cjs "$env:APPDATA\npm\node_modules\@modelcontextprotocol\server-filesystem\dist\index.js" C:\mcp\data
```

## 注意点

- サンドボックス起動には Landlock/seccomp 対応の Linux が必要です。
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
