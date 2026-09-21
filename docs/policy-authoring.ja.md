# ポリシー作成ガイド

[English](policy-authoring.md) / [コマンド・設定リファレンス](guide.ja.md#5-ポリシーリファレンス)

このガイドでは、デプロイで実際に収束させる手順で MCP サーバー用の KDL ポリシーを作成します。
狭い default-deny の土台で起動し、サーバーを動かし、監査ログの拒否を読み、
拒否が裏付けた条項だけを足し、差分を pin し直す流れです。
`generate-policy` は土台となる草案を得る方法の 1 つです — 出力にはツール定義や実行に必要な権限が欠けていることがあり、出力を保存できたことと利用可能なポリシーが完成したことは別です。

既に草案がある場合は[権限の編集](#editing)から進めてください。[用途別の例](#recipes)、[動作確認](#verification)、[問題の切り分け](#troubleshooting)も参照できます。

## 1. 対象と許可する操作を決める

最初は、1 サーバーにつき 1 ポリシーファイルにすると設定を追いやすくなります。次の情報を確認します。

| 確認するもの | 例・決める内容 |
|---|---|
| 起動コマンド | 実行ファイル、スクリプト、引数、作業ディレクトリ。通常利用時と同じものを使う |
| 実際のツール名と引数 | サーバーの説明や MCP クライアントの `tools/list` で確認する。`read_file` などの名前を推測して追加しない |
| 起動に必要なファイル | 実行ファイル、Python/Node などのランタイム、ライブラリ、証明書、設定ファイル |
| ツールに読ませる場所 | 例: `/srv/mcp-data/public/`。起動用ファイルとは分けて考える |
| 書き込み先 | 必要な場合だけ、専用の出力ディレクトリを用意する |
| 通信先 | 外部通信が必要か。必要ならツールが受け取る URL・ホスト名と実際の接続先を確認する |

ファイルアクセス権限のパスには絶対パスを使います。Windows では `C:/mcp/data/**` のように `/` を使うと KDL のバックスラッシュのエスケープを避けられます。
コンテナ内の権限はコンテナ内のパスで記述します。`--policy` に渡すファイルの場所は、guard を起動する側のパスです。
出力先など、OS の許可対象にするディレクトリは起動前に作成してください。

## 2. 狭い default-deny のポリシーから始める

土台となるファイルが許可するのは、サーバーの起動に必要な読み取りパスと
利用するツールだけに留め、それ以外は default-deny にします。土台の作り方は
3 つあります。どれを選んでも、作業用は `policy.kdl` にコピーして進めます
（以後の再生成は別ファイルへ行い、編集済みの `policy.kdl` を上書きしないようにします）。

```sh
cp policy.draft.kdl policy.kdl
```

PowerShell では `Copy-Item -LiteralPath policy.draft.kdl -Destination policy.kdl` を使えます。

### レビュー済みの例を継承する

`examples/policies/` には、版を固定した実 MCP サーバ 4 本のレビュー済みポリシーがあります — `filesystem.kdl`、`memory.kdl`（Node）、`time.kdl`、`git.kdl`（Python）— それぞれ実測したツール一覧を `tools-list-hash` で固定しています。意図的にホスト固有のパスを含みません。デプロイ側のポリシーはこれを `extends` し、ホストの `defaults`（インタプリタの読み取りパス、データルート）と `server` スコープのツール規則を足します。

```kdl
policy version=1
extends "examples/policies/filesystem.kdl"
defaults {
    filesystem {
        allow "/usr/lib/node" mode="read"          // 解決済みの node プレフィックス
        allow "/srv/mcp/node_modules" mode="read"  // サーバのパッケージツリー
        allow "/srv/data" mode="read"
        secret-overlay #true
    }
}
server "filesystem" {
    tool "read_file" {
        filesystem { allow "/srv/data/**" }
    }
}
```

`extends` のパスは書かれたファイルからの相対パスで解決され、多段も機能します。各例は `runtime/node.kdl` または `runtime/python.kdl` を継承しています。これらの runtime ファイルに入っているのは、実測したインタプリタの syscall 許可リスト（`defaults.syscalls` — Linux seccomp 用で、macOS／Windows には適用されません。両 OS では sandbox-exec プロファイルと AppContainer 付与が代わりに強制します）と、ホスト側で追加すべき読み取りパスの一覧（コメント）です。runtime ポリシーはそのまま共有し、サーバポリシーがツール一覧を固定し、ホストポリシーがパスを与える分担です。

`scripts/check-server.sh` / `scripts/check-server.ps1` は Cargo なしで結果を健全性確認します — dry-run のハンドシェイクと `tools/list`、サンドボックス下での同じやり取り、任意で `tools/call` 1 回を実行し、いずれかが失敗すれば非ゼロで終了します。[開発ガイド](development.md#real-mcp-server-verification)を参照してください。

### 最小の骨格を書く

対象サーバーに合うレビュー済みの例がない場合は、起動時の読み取りだけを許し、
手順 1 で確認したツールを宣言した骨格から始めます。

```kdl
policy version=1
defaults {
    filesystem {
        secret-overlay #true
    }
}
server "my-server" {
    tool "read_file" side_effect="read_only"
}
```

### 草案を生成する

`generate-policy` も土台の 1 つであり、完成したポリシーではありません。
まずはサーバーを実行しない静的解析で出力します。以下のコマンド・パスを実際のものに置き換えてください。

```sh
mcp-writ generate-policy --output policy.draft.kdl -- python /opt/mcp-server/server.py
```

ネイティブ ELF / Mach-O なら `-- /opt/mcp-server/my-mcp-server`、JavaScript なら `-- node /opt/mcp-server/server.js` のように指定します。
ネイティブ解析は ELF（x86-64 / AArch64 Linux）と Mach-O（arm64 Darwin）向けであり、Windows の `.exe`（PE）をそのまま解析するものではありません。
ソース解析も対応する登録形式・ハンドラに限られます。動的登録や `python -m` などでソースを特定できない場合は、実際のツール一覧をもとに手動で補います。
`--project <dir>` は依存関係などのヒントを加えるオプションで、ツール検出や権限の完成を保証しません。

サーバーを実行してツール定義とスキーマを取得する場合は、別のファイルへ出力します。

```sh
mcp-writ generate-policy --live-discovery --output policy.discovered.kdl -- python /opt/mcp-server/server.py
```

`--live-discovery` は環境変数を制限しますが、OS サンドボックス内での検出ではありません。実行してよいと判断したサーバーを、検証用の環境で使います。
認証情報などの環境変数が渡らず検出に失敗する場合は、手動で設定を作る方法もあります。通常の `run` は親の環境変数を継承します。

生成した草案を土台にする前に、次を確認します。

- `server` / `tool` がない場合は、利用する実際のツールを追加する。ポリシーにないツールは拒否される。
- `filesystem` に許可パスがない場合は、起動用ファイルとツールの対象パスを補う。
- `REVIEW` / `WARNING` の理由を確認する。未束縛のハンドラや証拠不足のツールには、`side_effect` が付かないことがある。
- ライブ検出で得た `args_schema` と `tools-list-hash` は内容を確認して引き継ぐ。手動で架空のハッシュを記入しない。

`--self-test` は、生成した草案に対する任意の診断です。編集済みポリシーファイルを読み込んで検証するコマンドではありません。編集後の確認は[手順 3](#verification)で行います。

<a id="verification"></a>

## 3. サーバーを動かして拒否を読む

検証用のデータとして、許可ディレクトリ内の `hello.txt` と、許可範囲外の無害なファイルを用意します。秘密ファイルを読み書きする試験は不要です。
以下は Linux の読み取り例の起動コマンドです。監査ログの親ディレクトリは、guard を起動するユーザーが書き込める場所に作成しておきます。

```sh
mcp-writ run --dry-run --policy /opt/mcp-config/policy.kdl --audit-log /opt/mcp-logs/dry-run.jsonl -- /opt/mcp-server/my-mcp-server
```

Windows の例なら、PowerShell で次のように指定します。

```powershell
mcp-writ run --dry-run --policy C:/mcp/config/policy.windows.kdl --audit-log C:/mcp/logs/dry-run.jsonl -- C:/mcp/server/my-mcp-server.exe
```

これらを端末で起動しただけではツール検査は行われません。MCP クライアントの stdio 起動設定を guard に切り替え、そのクライアントで `tools/list` を取得してからツールを呼び出します。各クライアントに渡す
`command` / `args` / `env` の形は[クライアント設定](../README.ja.md#クライアント設定)
を参照してください（VS Code では `mcpServers` の代わりにトップレベルの
`servers` キーを使います）。
クライアントが PATH 上の `mcp-writ` を見つけられない場合は、`command` に実行ファイルの絶対パスを指定します。
複数の `server` を含むポリシーでは `--server files` などを指定します。これは KDL 内の名前であり、クライアント側の表示名ではありません。

### ドライランで確認すること

ドライランは、OS サンドボックスを無効にしてサーバーを実行し、通常は拒否されるツール呼び出しも転送します。サンドボックスなしで実行されるため、ファイル変更や通信などの副作用が起こり得ます。検証用データで実施してください。
設定した `--fail-on` の閾値に達するマニフェスト検査やハッシュ不一致は、引き続きセッションの停止要因となり得ます。

以下は、対応するツールを実装したサーバーで確認する操作です。未実装ツールに対するサーバー自身のエラーを、guard による拒否とは数えません。

| 呼び出し | 通常起動で期待する結果 |
|---|---|
| `read_file` に `/srv/mcp-data/public/hello.txt` | 成功 |
| `read_file` に `/srv/mcp-data/outside.txt` | guard が拒否 |
| `read_file` にパスを渡さない | guard が拒否 |
| ポリシーで拒否した `write_file` / `exec_shell` | guard が拒否 |
| 書き込み例の `write_file` に `output/result.txt` の絶対パス | 成功。`public` 内への書き込みは guard が拒否 |
| API 例の `fetch_url` に許可ホスト／別ホストの URL | 許可ホストは RPC 検査を通過し、別ホストは guard が拒否 |

Windows では表のファイルパスを `C:/mcp/data/...` に読み替えます。API の RPC 検査通過と、認証や通信を含むリクエスト全体の成功は分けて確認します。

### 監査ログを読む

監査ログでは `event_type`、`action`、`target_tool`、`details` を確認します。以下は説明用に必要なフィールドだけを抜き出した例です。

```json
{"event_type":"tool_call.denied","action":"observed","target_tool":"read_file","details":"path '...' not in tool fs allowed paths"}
```

`action="observed"` はドライランで違反を転送した記録です。ツールから結果が返っていても、ポリシー上は許可されていないことがあります。
正当な操作だけを通せるように、`details` に対応するツール・パス・ホストの設定を修正します。

<a id="troubleshooting"></a>

### 拒否理由から設定箇所を調べる

| 症状・メッセージ | 確認する箇所 |
|---|---|
| `tool not found in policy` / `tool is not allowed` | 実際のツール名、選択した `server`、`deny=#true`。草案のツール一覧が空でないか |
| `filesystem-restricted tool is missing a path target` | 引数名と構造。パス不要なら、専用の `allow none=#true` + `require-path #false` を使う |
| `not in tool fs allowed paths` | ツールの実効許可リスト、絶対パス、シンボリックリンクの解決先。`defaults` の追加だけで直るとは限らない |
| `network-restricted tool is missing a url/host target` / `not in tool network allowed hosts` | ツールの実際の引数と `tool.network`。固定接続先が引数にないケースも確認する |
| `Error loading policy` / `side_effect` の整合エラー | KDL の型、重複ツール、継承した書き込み権限やネットワーク指定。bool は `#true` / `#false` |
| `--audit-log <path> is required` / ログを開けない | `logging.fail_closed` は既定で有効。ログパス、親ディレクトリ、書き込み権限を確認する |
| Linux で `syscalls.allowed must include execve` | 起動用 syscall の明示許可。RPC の `exec_shell` 許可とは別 |
| 通常起動だけが失敗する／サーバー内で `EACCES`・`EPERM` | 実行ファイル、依存ライブラリ、データ、出力先、syscall。ドライランの成功だけでは OS 制限を検証できない |
| Windows でホスト許可リストの読み込みエラー | OS の通信設定と `tool.network` を分ける。[API 例](#api-access)を参照 |
| macOS で `macOS SBPL cannot pin remote host` | deny-all モードで指定できるのは loopback TCP ポートのみ。ホスト検査は `tool.network` へ移して OS の通信を開くか、deny-all を使う |
| `declares per-tool syscalls, which are not enforced` | syscall 規則は `defaults.syscalls` へ移す。プロセス共通かつ Linux 専用 |
| `CC-...` のマニフェスト指摘／ツール定義のハッシュ不一致 | サーバーの説明・スキーマ・バージョンの変化。ファイル権限を広げても解消しない |

<a id="editing"></a>

## 4. 確認した条項だけを足す

監査ログで読んだ拒否は、それぞれ 1 つの設定箇所に対応します。動かした操作が
実際に必要とした条項だけを足します — たとえば、次のような設定だけが出ても、
読む場所の制限や OS の起動権限は完成していません。

```kdl
policy version=1
defaults {
    filesystem {
        secret-overlay #true
    }
}
server "auto-generated" {
    tool "read_file" side_effect="read_only"
}
```

設定は次の役割に分けて編集します。

| 場所 | 設定する内容 |
|---|---|
| `defaults.filesystem` | サーバープロセスが実際に開くファイル。起動用とデータ用のパス、読み取り／読み書きを指定する |
| `defaults.syscalls` | Linux のプロセス全体に適用する seccomp 許可リスト。macOS／Windows では未適用 |
| `defaults.network` | 共通のネットワーク設定。OS ごとの強制範囲には違いがある — [OS 別の適用範囲](guide.ja.md#os-別の適用範囲)を参照 |
| `server` 内の `tool` | 許可するツールと、その RPC 引数に許すパス・ホスト・スキーマ |

Windows と macOS の OS 用ファイル権限はグローバル設定からのみ付与されます。Linux では許可ツールのファイル権限も Landlock に加わります。
いずれもプロセス全体の権限です。ツールごとに OS サンドボックスが切り替わるわけではありません。共通の起動権限を明示し、各ツールの引数は必要な範囲へ絞ります。

### 継承と上書き

ツールの設定は `defaults → profile → server-defaults → tool` の順で合成されます。
`filesystem` や `network` で後の層に許可リストを書くと、それ以前の許可リストを置き換えます。単純な追記ではありません。
許可を省略した場合は継承し、明示的な拒否は蓄積します。上位の `allow` で既存の `deny` を解除することはできません。

たとえば起動用に `/opt/mcp-server/**` を許可していても、`read_file` の `filesystem` に `/srv/mcp-data/public/**` だけを書くと、そのツールの RPC 引数は後者に絞られます。
継承したパス許可を空にしたい場合は `allow none=#true` を使います。空の `filesystem {}` だけでは許可リストの消去になりません。

<a id="linux-read-only"></a>

### 編集後の例: Linux でファイルを読む

以下は、サーバーを `/opt/mcp-server/` に置き、`read_file` に `/srv/mcp-data/public/` だけを読ませる例です。`policy.kdl` に保存します。
ライブラリの配置と必要 syscall はサーバー・CPU・ランタイムに合わせて確認してください。この syscall リストは出発点であり、すべての Python/Node/Go サーバーで起動できる一覧ではありません。

```kdl
policy version=1

defaults {
    filesystem {
        allow "/opt/mcp-server/**" mode="read"
        allow "/usr/lib/**" mode="read"
        allow "/lib/**" mode="read"
        allow "/srv/mcp-data/public/**" mode="read"
        secret-overlay #true
    }
    syscalls {
        allow "read" "write" "openat" "close" "fstat" "newfstatat"
        allow "mmap" "munmap" "mprotect" "brk" "pread64" "lseek"
        allow "rt_sigaction" "rt_sigprocmask" "rt_sigreturn" "futex"
        allow "set_tid_address" "set_robust_list" "rseq" "arch_prctl"
        allow "getrandom" "prlimit64" "execve" "exit" "exit_group"
    }
    network {
        deny host="*"
    }
}

server "files" {
    tool "read_file" side_effect="read_only" {
        filesystem {
            allow "/srv/mcp-data/public/**" mode="read"
        }
    }
    tool "write_file" deny=#true
    tool "exec_shell" deny=#true
}

logging level="info" fail_closed=#true
```

`mode="write"` は読み書き、省略時の `mode="read"` は読み取り用です。
`side_effect="read_only"` は設定の整合性を検査し、ホスト／URL 引数も拒否しますが、サーバー内部の処理が本当に読み取りだけかを証明するものではありません。

Linux の通常起動には `execve` または `execveat` の許可が必要です。その許可は子プロセスにも残るため、`exec_shell` の RPC 拒否とは区別します。
インタープリターで起動する場合は、その実行ファイル・標準ライブラリ・依存パッケージにも読み取り権限が必要です。例の `/opt/mcp-server/**` だけでは、別の場所にある Python や Node の実行環境を許可したことにはなりません。
ネイティブ ELF / Mach-O の syscall 候補は `mcp-writ inspect --format json /opt/mcp-server/my-mcp-server` で調べられます。実行経路や動的ライブラリのすべてを静的解析だけで網羅できるわけではないため、通常起動で確認します。

親ディレクトリ全体を許可してから、その下の秘密ディレクトリだけを `deny` で除く設定は、Landlock で表現できず読み込み時に拒否されます。許可してよいディレクトリを分けて列挙してください。

<a id="recipes"></a>

## 5. 用途に合わせて設定を変える

<a id="write-output"></a>

### 専用ディレクトリへの書き込み

上の Linux 例の `defaults.filesystem` に、次の 1 行を追加します。既存の読み取り許可は残します。

```kdl
allow "/srv/mcp-data/output/**" mode="write"
```

`tool "write_file" deny=#true` を次のブロックに置き換えます。同名のツールを追加して重複させないでください。

```kdl
tool "write_file" side_effect="write" {
    filesystem {
        allow "/srv/mcp-data/output/**" mode="write"
    }
}
```

`side_effect="write"` だけでは書き込み権限は増えません。`mode="write"` と、実際に必要な書き込み syscall を確認します。
この設定では `read_file` の RPC 対象は引き続き `public` 内だけですが、サーバープロセス全体は `output` へ書き込めます。

<a id="windows-files"></a>

### Windows でファイルを読み書きする

以下は、実行ファイルと依存ファイルが `C:/mcp/server/` にあり、データを `C:/mcp/data/` に置く場合の独立したポリシーです。`policy.windows.kdl` として保存できます。
別の場所にインストールしたランタイムを使う場合は、その実体のパスもグローバルの読み取り許可へ追加します。Linux の syscall 一覧は AppContainer には使いません。

```kdl
policy version=1
defaults {
    filesystem {
        allow "C:/mcp/server/**" mode="read"
        allow "C:/mcp/data/public/**" mode="read"
        allow "C:/mcp/data/output/**" mode="write"
        secret-overlay #true
    }
    network {
        deny host="*"
    }
}
server "files" {
    tool "read_file" side_effect="read_only" {
        filesystem {
            allow "C:/mcp/data/public/**" mode="read"
        }
    }
    tool "write_file" side_effect="write" {
        filesystem {
            allow "C:/mcp/data/output/**" mode="write"
        }
    }
    tool "exec_shell" deny=#true
}
logging level="info" fail_closed=#true
```

パス照合は大文字小文字を区別しません。`/srv/...` のような Linux のパスを `C:/...` に自動変換することはありません。
AppContainer 用の ACL を設定できる、実行ユーザーが管理するディレクトリを使ってください。

<a id="api-access"></a>

### 外部 API へ接続する

次は Windows 用の独立した例です。`fetch_url` が `{"url":"https://api.example.com/status"}` のような引数を取ることを想定します。ホスト名とツール名を実際のものに置き換え、`policy.api.kdl` に保存します。

```kdl
policy version=1
defaults {
    filesystem {
        allow "C:/mcp/server/**" mode="read"
        secret-overlay #true
    }
    network {
        allow host="*"
    }
}
server "api" {
    tool "fetch_url" side_effect="network" {
        filesystem {
            allow none=#true
            require-path #false
        }
        network {
            allow host="api.example.com"
        }
    }
    tool "exec_shell" deny=#true
}
logging level="info" fail_closed=#true
```

Windows の AppContainer はホスト単位の通信制限を行えないため、ここでは OS の通信を開き、Auditor が RPC 引数のホストを制限します。
`defaults.network` のホスト許可リストと `deny host="*"` の併用は Windows では読み込みエラーになります。
この例はサーバー内部の任意の接続先やリダイレクト先まで制限するものではありません。ホスト検査は URL のスキームやポートの制限でもありません。

Linux へ移す場合は、ファイルパスと起動用 syscall を合わせ、必要な `socket` / `connect` なども確認します。TLS 通信では証明書、DNS 設定などの読み取りが必要になることがあります。
`allow host="443"` のようなポートのみのエントリは、そのポートへの任意の宛先を許す Landlock 規則になり、ホスト名のエントリは警告付きでスキップされ Auditor のみの規則として残ります。
macOS では、deny-all モードで指定できるのは loopback の TCP ポートだけで、リモートホスト名は spawn を失敗させます。
OS と RPC の両方のネットワーク制約は [OS 別の適用範囲](guide.ja.md#os-別の適用範囲)と[リファレンス](guide.ja.md#フィールドリファレンス)を参照してください。

固定の API を使い、引数に URL・ホストがないツールには、この `tool.network` 例をそのまま使えません。ホストがない呼び出しも拒否されるためです。引数に存在しない接続先を Auditor で検証できるとは扱わず、サーバー実装と OS／実行環境側の通信制御を検討します。

<a id="pathless"></a>

### パスを受け取らないツール

計算や echo などのツールでは、起動用のファイル許可を継承すると、パス引数を要求されることがあります。
ファイル用ポリシーの `server` 内に追加する例は次のとおりです。

```kdl
tool "echo" side_effect="read_only" {
    filesystem {
        allow none=#true
        require-path #false
    }
}
```

これで `{"message":"hello"}` のようなパスなし引数を許可し、持ち込まれたパスは拒否します。`require-path #false` は、空の許可リストと組み合わせる場合にだけ使えます。
親のネットワーク許可も継承するので、この例をネットワークが開いたポリシーへ移すときは `tool.network` も見直してください。

### 引数の形式を制限する

パス制限に加え、引数の型や必須項目を検査する場合は、ツールに `args_schema` を指定します。
Linux 例の `server "files"` 内の既存の `read_file` を、次のブロックに置き換えます。Windows ではパスを対応する `C:/mcp/data/...` に変えてください。

```kdl
tool "read_file" side_effect="read_only" args_schema="@schemas/read-file.json" {
    filesystem {
        allow "/srv/mcp-data/public/**" mode="read"
    }
}
```

ポリシーと同じディレクトリの `schemas/read-file.json` に次を保存します。`@` の相対パスは、読み込むポリシーのディレクトリを基準に解決されます。

```json
{
  "type": "object",
  "properties": {"path": {"type": "string"}},
  "required": ["path"],
  "additionalProperties": false
}
```

`args_schema` は `params.arguments` の検査です。MRTR の `inputResponses` は別の入力であり、`auto` の既定動作では、スキーマや `side_effect`、実効的な権限制約を持つツールへの入力を拒否します。MRTR が必要なサーバーでは[プロトコルの説明](guide.ja.md#mcp-2026-07-28--2025-11-25--mrtrauditor)を確認してください。

## 6. 通常起動で再確認し、差分を pin し直す

クライアントの起動設定から `--dry-run` を外し、監査ログを `enforced.jsonl` など別名にして再起動します。設定変更は guard の再起動後に反映されます。
[手順 3](#verification) の表をもう一度試し、許可した操作の実行結果と、拒否した操作の JSON-RPC エラー・`action="denied"` を確認します。

RPC 検査を通過しても OS が起動やアクセスを拒否する場合があります。サーバーの標準エラーと監査ログを併せて確認してください。OS での拒否がすべて JSONL に記録されるわけではありません。
`MCP_WRIT_SKIP_SANDBOX` や `sandbox allow_degraded=#true` を回避策として有効にした状態を、通常の保護の検証結果にはしないでください。

ポリシーを変更したら guard を再起動し、成功ケースと拒否ケースの両方を再確認します。
サーバーを更新した場合は草案を別ファイルへ再生成し、ツール・スキーマ・ハッシュ・必要権限の差分を確認してから採用します — その差分の確認をもって `tools-list-hash` を pin し直します。`tools-list-hash` を消すだけで不一致を解消する手順にはしません。

継承やファイル分割など、追加の構文は [policy.example.kdl](../policy.example.kdl) と[ポリシーリファレンス](guide.ja.md#5-ポリシーリファレンス)を参照してください。
