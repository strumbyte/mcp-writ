//! Canonical JSON-RPC request ids: the `RpcId` correlation key, the
//! reserved internal-id namespace, and canonical JSON-number spelling.

/// Canonical JSON-RPC id (string/number/null) for request correlation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RpcId {
    Null,
    Number(String),
    String(String),
}

/// Reserved prefix for auditor-internal JSON-RPC request ids (tools/list
/// pagination and `list_changed` revalidation the proxy emits itself).
/// Internal ids are always STRINGS under this prefix, so they can never
/// alias a client numeric id in a correlation key — and a client frame
/// squatting on the namespace is detectable by this one test.
pub(crate) const INTERNAL_ID_PREFIX: &str = "__mcp_writ_internal__";

/// The wire text of the internal id for sequence `n` — the same text
/// [`RpcId::internal`] keys on, so emitted frames and correlation keys
/// cannot diverge.
pub(crate) fn internal_id_str(n: u64) -> String {
    format!("{INTERNAL_ID_PREFIX}{n}")
}

/// Canonical decimal form of a JSON number so mathematically equal
/// spellings (`1`, `1.0`, `10e-1`, `0.5e1`) correlate to the same `RpcId`.
/// No floating-point conversion: the coefficient stays a digit string and
/// the exponent an i128, so large integers and out-of-f64-range exponents
/// keep full precision and distinct values never collapse. Malformed input
/// or exponents beyond i128 fall back to the trimmed raw text.
fn canonicalize_json_number(raw: &str) -> String {
    let t = raw.trim();
    let (neg, unsigned) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t),
    };
    let (mantissa, exp_lit) = match unsigned.find(['e', 'E']) {
        Some(i) => (&unsigned[..i], &unsigned[i + 1..]),
        None => (unsigned, "0"),
    };
    let Ok(exp) = exp_lit.parse::<i128>() else {
        return t.to_string();
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if (int_part.is_empty() && frac_part.is_empty())
        || !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return t.to_string();
    }
    let digits = format!("{int_part}{frac_part}");
    let sig = digits.trim_start_matches('0');
    if sig.is_empty() {
        return "0".to_string();
    }
    let sig = sig.trim_end_matches('0');
    let trailing = (digits.trim_start_matches('0').len() - sig.len()) as i128;
    let Some(exp) = exp
        .checked_sub(frac_part.len() as i128)
        .and_then(|e| e.checked_add(trailing))
    else {
        return t.to_string();
    };
    format!("{}{}e{}", if neg { "-" } else { "" }, sig, exp)
}

impl RpcId {
    pub fn parse_from_json(id: nojson::RawJsonValue<'_, '_>) -> Option<Self> {
        match id.kind() {
            nojson::JsonValueKind::Null => Some(Self::Null),
            nojson::JsonValueKind::Integer | nojson::JsonValueKind::Float => {
                Some(Self::Number(canonicalize_json_number(id.as_raw_str())))
            }
            nojson::JsonValueKind::String => id
                .to_unquoted_string_str()
                .ok()
                .map(|s| Self::String(s.into_owned())),
            _ => None,
        }
    }

    pub fn from_line(line: &str) -> Option<Self> {
        let json = nojson::RawJson::parse(line).ok()?;
        let id = json.value().to_member("id").ok()?.optional()?;
        Self::parse_from_json(id)
    }

    /// Canonical `Number` id for a numeric id, matching what
    /// [`parse_from_json`](Self::parse_from_json) yields when the peer
    /// echoes it back.
    #[cfg(test)]
    pub(crate) fn from_u64(n: u64) -> Self {
        Self::Number(canonicalize_json_number(&n.to_string()))
    }

    /// The canonical id for an internally minted request — a `String` id
    /// in the reserved namespace, identical to what
    /// [`parse_from_json`](Self::parse_from_json) yields when the peer
    /// echoes the emitted `internal_id_str(n)` member back.
    pub(crate) fn internal(n: u64) -> Self {
        Self::String(internal_id_str(n))
    }

    /// True when this is a string id inside the reserved internal
    /// namespace. Client frames carrying one are refused/dropped by the
    /// C2S loop — a number can never match the prefix.
    pub(crate) fn is_internal_namespace(&self) -> bool {
        matches!(self, Self::String(s) if s.starts_with(INTERNAL_ID_PREFIX))
    }
}

/// Serialized byte cost of a canonical id for the accounting budgets.
pub(super) fn rpc_id_bytes(request_id: &RpcId) -> usize {
    match request_id {
        RpcId::Null => 4,
        RpcId::Number(n) | RpcId::String(n) => n.len(),
    }
}
