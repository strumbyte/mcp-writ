#!/bin/sh
# Minimal MCP-conforming stdio server for the container E2E fixture.
#
# The guard enforces the MCP wire contract: request-shaped frames may not
# travel server->client, and tools/call is denied until the 2025-11-25
# handshake completes -- a verbatim request echo can never pass through.
# This fixture answers instead of echoing:
#   initialize          -> pinned 2025-11-25 result
#   notifications/*     -> swallowed (a notification has no answer)
#   tools/list          -> the test policy's tool inventory
#   other requests      -> a result whose text echoes the request line,
#     the same pass-through evidence a verbatim echo gave
#   lines without an id -> echoed verbatim (stray non-RPC input)

extract_id() {
    # `"id":<number>` or `"id":"<string>"` -- capture the raw token so a
    # string id keeps its quotes in the emitted JSON. Takes the last id
    # member on the line; the fixture's requests carry exactly one.
    printf '%s' "$1" |
        sed -n 's/.*"id":[[:space:]]*\("[^"]*"\|[0-9a-zA-Z_-]*\).*/\1/p' |
        sed 's/[[:space:]]*$//'
}

while IFS= read -r line; do
    case "$line" in
        *'"method":"notifications/'*)
            : ;;
        *'"id"'*)
            id=$(extract_id "$line")
            [ -z "$id" ] && id=null
            case "$line" in
                *'"method":"initialize"'*)
                    printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"echo-server\",\"version\":\"0\"}}}"
                    ;;
                *'"method":"tools/list"'*)
                    printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"tools\":[{\"name\":\"read_file\",\"description\":\"Read a workspace file\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}}}},{\"name\":\"write_file\",\"description\":\"Write a workspace file\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}}}},{\"name\":\"exec_shell\",\"description\":\"Run a shell command\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"cmd\":{\"type\":\"string\"}}}}]}}"
                    ;;
                *)
                    text=$(printf '%s' "$line" | sed 's/\\/\\\\/g; s/"/\\"/g')
                    printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"$text\"}]}}"
                    ;;
            esac
            ;;
        *)
            printf '%s\n' "$line"
            ;;
    esac
done
