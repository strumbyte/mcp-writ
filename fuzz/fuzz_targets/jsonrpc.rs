//! Fuzz target: JSON-RPC / MCP interpretation of one frame body.
//!
//! Input is the frame body verbatim — the property hands it to
//! `mcp_writ::fuzz::jsonrpc_line`, which walks every line-level
//! classifier (`is_response`, probe classification, error parse,
//! tools/list page, initialize shape) plus the `fields` member
//! extractors on `params`/`result` when the text parses as JSON.
//!
//! Search space: raw bytes and printable soup (the parser's worst
//! case), grammar-driven JSON documents built from protocol keys
//! (deep `_meta`, capability objects, `inputRequests` maps), and
//! MCP-flavored templates — initialize, tools/list pages, JSON-RPC
//! errors with `data.supported` — occasionally truncated or mutated.

use std::cell::Cell;

#[derive(Default)]
struct Gates {
    cases: Cell<usize>,
    valid: Cell<usize>,
    response: Cell<usize>,
    notification: Cell<usize>,
    error: Cell<usize>,
    tools_ok: Cell<usize>,
    meta: Cell<usize>,
}

/// Member names the extractors look for — the grammar mostly picks
/// from this pool so the structured arm reaches real parse paths.
const KEYS: &[&str] = &[
    "jsonrpc",
    "id",
    "method",
    "params",
    "result",
    "error",
    "code",
    "message",
    "data",
    "supportedVersions",
    "protocolVersion",
    "capabilities",
    "clientInfo",
    "serverInfo",
    "tools",
    "name",
    "title",
    "description",
    "inputSchema",
    "nextCursor",
    "cursor",
    "_meta",
    "io.modelcontextprotocol/protocolVersion",
    "io.modelcontextprotocol/clientCapabilities",
    "io.modelcontextprotocol/logLevel",
    "io.modelcontextprotocol/subscriptionId",
    "notifications",
    "listChanged",
    "resourceSubscriptions",
    "uri",
    "level",
    "reason",
    "requestId",
    "progressToken",
    "resultType",
    "ttlMs",
    "cacheScope",
    "requestState",
    "inputRequests",
    "arguments",
];

const STRINGS: &[&str] = &[
    "2.0",
    "initialize",
    "initialized",
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "tools/list",
    "tools/call",
    "subscriptions/listen",
    "logging/setLevel",
    "server/discover",
    "2026-07-28",
    "2025-11-25",
    "2025-03-26",
    "complete",
    "input_required",
    "public",
    "private",
    "debug",
    "info",
    "warning",
    "error",
    "mcp-writ",
    "example.com",
    "file:///etc/passwd",
    "",
    "�",
];

fn scalar(ctx: &mut noprop::TestCaseContext, out: &mut String) {
    match noprop::sample_weighted_index(ctx, &[45, 30, 15, 10]) {
        0 => {
            let s = noprop::sample_choice(ctx, STRINGS);
            out.push_str(&format!("{s:?}")); // JSON-quoted
        }
        1 => {
            let n = noprop::sample_usize_in(ctx, 0..=24);
            let s = noprop::sample_ascii_printable_string(ctx, n);
            out.push_str(&format!("{s:?}"));
        }
        2 => {
            let n = noprop::sample_with_boundaries(
                ctx,
                &[
                    0i64,
                    1,
                    -1,
                    -32000,
                    -32002,
                    -32022,
                    -32600,
                    i64::MAX,
                    i64::MIN,
                ],
                noprop::Ratio::new(1, 3),
                |ctx| noprop::sample_i64(ctx),
            );
            out.push_str(&n.to_string());
        }
        _ => out.push_str(noprop::sample_choice(
            ctx,
            &["true", "false", "null", "[]", "{}", "1.5", "-0"],
        )),
    }
}

fn json_value(ctx: &mut noprop::TestCaseContext, depth: usize, out: &mut String) {
    if depth >= 5 {
        scalar(ctx, out);
        return;
    }
    match noprop::sample_weighted_index(ctx, &[35, 20, 45]) {
        0 => {
            out.push('{');
            for i in 0..noprop::sample_usize_in(ctx, 0..=6) {
                if i > 0 {
                    out.push(',');
                }
                let key = noprop::sample_choice(ctx, KEYS);
                out.push_str(&format!("{key:?}:"));
                json_value(ctx, depth + 1, out);
            }
            out.push('}');
        }
        1 => {
            out.push('[');
            for i in 0..noprop::sample_usize_in(ctx, 0..=5) {
                if i > 0 {
                    out.push(',');
                }
                json_value(ctx, depth + 1, out);
            }
            out.push(']');
        }
        _ => scalar(ctx, out),
    }
}

/// MCP-flavored templates — guaranteed-valid shapes for the deep
/// paths (tools/list page, initialize result, probe error).
fn template(ctx: &mut noprop::TestCaseContext) -> String {
    let id = noprop::sample_u32(ctx);
    match noprop::sample_weighted_index(ctx, &[3, 2, 2, 2, 3]) {
        0 => {
            // tools/list response page.
            let mut tools = String::new();
            for i in 0..noprop::sample_usize_in(ctx, 0..=3) {
                if i > 0 {
                    tools.push(',');
                }
                tools.push_str("{\"name\":");
                scalar(ctx, &mut tools);
                tools.push_str(",\"description\":\"t\",\"inputSchema\":{\"type\":\"object\"}}");
            }
            let cursor = if noprop::sample_bool(ctx) {
                ",\"nextCursor\":\"c1\"".to_string()
            } else {
                String::new()
            };
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"tools\":[{tools}]{cursor}}}}}"
            )
        }
        1 => {
            // initialize result with protocolVersion + capabilities.
            let ver = noprop::sample_choice(ctx, &["2025-11-25", "2026-07-28", "1.0", ""]);
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"protocolVersion\":{ver:?},\"capabilities\":{{\"tools\":{{\"listChanged\":true}}}},\"serverInfo\":{{\"name\":\"s\",\"version\":\"1\"}}}}}}"
            )
        }
        2 => {
            // JSON-RPC error — the probe reads data.supported*.
            let code =
                noprop::sample_choice(ctx, &[0i64, -32022, -32600, -32601, -32602, -32700, 42]);
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":{code},\"message\":\"m\",\"data\":{{\"supportedVersions\":[\"2025-11-25\"],\"requestedVersion\":\"2026-07-28\"}}}}}}"
            )
        }
        3 => {
            // initialize request (2025-11-25 shape) or a notification.
            if noprop::sample_bool(ctx) {
                format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"c\",\"version\":\"1\"}}}}}}"
                )
            } else {
                "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}".to_string()
            }
        }
        _ => {
            // 2026-07-28 request — `_meta` claims the extractors read.
            let method = noprop::sample_choice(
                ctx,
                &[
                    "tools/list",
                    "tools/call",
                    "subscriptions/listen",
                    "logging/setLevel",
                ],
            );
            let caps = if noprop::sample_bool(ctx) {
                "{\"roots\":{\"listChanged\":true},\"sampling\":{}}"
            } else {
                "{}"
            };
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":{method:?},\"params\":{{\"_meta\":{{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{caps},\"io.modelcontextprotocol/logLevel\":\"warning\"}}}}}}"
            )
        }
    }
}

fn gen_input(ctx: &mut noprop::TestCaseContext) -> Vec<u8> {
    let mut doc = match noprop::sample_weighted_index(ctx, &[25, 20, 30, 25]) {
        0 => {
            let n = noprop::sample_usize_in(ctx, 0..=256);
            noprop::sample_bytes_vec(ctx, n)
        }
        1 => {
            let n = noprop::sample_usize_in(ctx, 0..=256);
            noprop::sample_ascii_printable_string(ctx, n).into_bytes()
        }
        2 => {
            let mut s = String::new();
            json_value(ctx, 0, &mut s);
            s.into_bytes()
        }
        _ => template(ctx).into_bytes(),
    };
    // A quarter of cases get a tail chop or a byte splice — malformed
    // JSON that still looks structured.
    if !doc.is_empty() && noprop::sample_ratio(ctx, noprop::Ratio::new(1, 4)) {
        match noprop::sample_weighted_index(ctx, &[2, 1]) {
            0 => doc.truncate(noprop::sample_usize_in(ctx, 0..=doc.len())),
            _ => {
                let i = noprop::sample_usize_in(ctx, 0..doc.len());
                doc[i] = noprop::sample_u8(ctx);
            }
        }
    }
    doc
}

fn property(g: &Gates, data: &[u8]) {
    let line = String::from_utf8_lossy(data);
    let s = mcp_writ::fuzz::jsonrpc_line(&line);

    // Cross-parse invariants: a tools page implies valid JSON (same
    // parser, same text); an error code implies the error member
    // parsed.
    if s.tools_page_ok {
        assert!(s.valid_json, "tools page accepted on invalid JSON");
    }
    // Every extractor early-returns on `RawJson::parse` failure — any
    // verdict or member from them implies the line parsed.
    let extracted = s.is_response
        || s.is_notification
        || s.id.is_some()
        || s.error_code.is_some()
        || s.initialize_result_version.is_some();
    assert!(
        !extracted || s.valid_json,
        "extractor verdict on invalid JSON"
    );
    assert!(s.input_request_entries <= 64, "inputRequests cap exceeded");
    g.cases.set(g.cases.get() + 1);
    g.valid.set(g.valid.get() + usize::from(s.valid_json));
    g.response
        .set(g.response.get() + usize::from(s.is_response));
    g.notification
        .set(g.notification.get() + usize::from(s.is_notification));
    g.error
        .set(g.error.get() + usize::from(s.error_code.is_some()));
    g.tools_ok
        .set(g.tools_ok.get() + usize::from(s.tools_page_ok));
    g.meta.set(g.meta.get() + usize::from(s.meta_present));
}

fn main() {
    let args = mcp_writ_fuzz::parse_args("jsonrpc");
    let g = Gates::default();
    std::process::exit(mcp_writ_fuzz::run(
        "jsonrpc",
        &args,
        gen_input,
        |data| property(&g, data),
        || {
            assert!(g.valid.get() > 0, "no valid JSON generated");
            assert!(g.tools_ok.get() > 0, "tools/list page never parsed");
            assert!(g.response.get() > 0, "no response-shaped line");
            format!(
                "valid={} response={} notif={} error={} tools_ok={} meta={}",
                g.valid.get(),
                g.response.get(),
                g.notification.get(),
                g.error.get(),
                g.tools_ok.get(),
                g.meta.get()
            )
        },
    ));
}
