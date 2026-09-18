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

元の MIT ライセンスと著作権表示を保持しています。
