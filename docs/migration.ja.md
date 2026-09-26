# mcp-writ への移行

公開先は [strumbyte/mcp-writ](https://github.com/strumbyte/mcp-writ) です。
Git 履歴は新しく開始し、従来のリポジトリは別のものとして残します。

1. ソースを取得したディレクトリで `cargo install --locked --path . --bin mcp-writ` を実行し、新しい CLI をインストールします。
2. MCP クライアントの設定やスクリプトの起動コマンドを `mcp-guard` から `mcp-writ` に変更します。Rust から参照するクレート名は `mcp_writ` です。
3. 下表の環境変数を変更します。旧名は互換エイリアスではなく、mcp-writ は読み取りません。
4. 新しい CLI と同じバージョンの `mcp-secure-runner` を使い、wrap-image / containerize で作成したイメージを再ビルドします。ランナーのファイル名と、コンテナ内の `/etc/mcp-secure/`・`/var/log/mcp-secure/` は引き続き同じです。
5. ポリシーの環境選択、サーバー選択、監査ログ、許可・拒否の動作を確認してから、MCP クライアントの設定を切り替えます。

| 旧環境変数 | 新環境変数 |
|---|---|
| `MCP_GUARD_ENV` | `MCP_WRIT_ENV` |
| `MCP_GUARD_SERVER` | `MCP_WRIT_SERVER` |
| `MCP_GUARD_FAIL_ON` | `MCP_WRIT_FAIL_ON` |
| `MCP_GUARD_SKIP_SANDBOX` | `MCP_WRIT_SKIP_SANDBOX` |
| `MCP_GUARD_REQUIRE_CONTAINER_TESTS` | `MCP_WRIT_REQUIRE_CONTAINER_TESTS` |

KDL の構文と tools-list ハッシュ v4 の計算方法は維持します。内部の接頭辞 `mcp-guard-tools-list-v4:` はハッシュ形式の一部として残るため、プロジェクト名の変更だけを理由にツールハッシュを再設定する必要はありません。サーバー本体やツール定義を変更する場合は、従来どおり検証が必要です。

## KDL スキーマ v2 への移行（予定）

MCP 通過規則（`server` 内の `mcp` ブロック）は `policy version=2` でのみ受理されます。v1 のポリシーは追加規則なしでそのまま使えます — v1 の既定プロファイルは従来通り、ツール許可リストと既存の検査だけで閉じています。v2 はまだ生成・実行用には公開しておらず、現行バイナリは `version` が 1 でないポリシーを検証段階で拒否します（旧バイナリも同様に `unsupported policy version` で拒否します）。v2 の有効化は MRTR 追加要求の制御とあわせて公開する予定です。

v1 から v2 へ書き換える場合、これまで規則なしで通過していた通信を `mcp` ブロックで明示許可します。例:

```kdl
policy version=2
server "docs" {
    tool "search"
    mcp {
        // 2025 で従来通過していた読み取り系メソッドの明示許可
        allow "resources/list"
        allow "resources/templates/list"
        allow "resources/read" {
            uri "file:///srv/docs/**"
        }
        allow "resources/subscribe" {
            uri "file:///srv/docs/**"
        }
        allow "resources/unsubscribe" {
            uri "file:///srv/docs/**"
        }
        allow "prompts/list"
        allow "prompts/get"
        allow "completion/complete"
        allow "logging/setLevel"
        // サーバー起点機能も明示規則が必要
        allow "elicitation/create"
    }
}
```

`2026-07-28` では URI 購読と `logging/setLevel` が削除され、購読は `subscriptions/listen` のフィルターに置き換わります。要求単位の `logLevel` は削除された `logging/setLevel` RPC の代替であり、Logging 機能全体の推奨移行先ではありません。Logging 機能全体は非推奨ですが、少なくとも12か月は仕様に残ります。推奨される移行先は、stdio では stderr、構造化ログでは OpenTelemetry です。

```kdl
server "docs" {
    mcp {
        // toolsListChanged だけなら規則なしでも既定で許可。
        // それ以外の通知種別と URI 範囲は明示規則が必要。
        allow "subscriptions/listen" {
            filter "toolsListChanged"
            filter "resourceSubscriptions"
            uri "file:///srv/docs/**"
        }
    }
}
```

実験的 `tasks` や拡張 `resultType` など、メソッド台帳に未登録の要求・拡張は台帳に項目が追加されるまで拒否されます。ルールで黙って通す経路はありません。また `2026-07-28` のログ通知は元要求の `progressToken`・`logLevel` と相関させて判定します — stdio では HTTP の応答ストリームを相関根拠に使わず、元要求を特定できない通知はそれだけを破棄して監査に記録します。独自の必須フィールドを正式仕様の要件として追加しない点にも注意してください。

元の MIT ライセンスと著作権表示を保持しています。
