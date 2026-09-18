//! Unicode helpers shared by manifest detectors and tools_diff description
//! classification: invisible-codepoint predicates and the name-collision
//! fold (NFKC → fullwidth/ligature/Cyrillic/Greek → lowercase).

use unicode_normalization::UnicodeNormalization;

/// Invisible / bidi / tag / WJ-isolate code points (including U+2060–206F).
pub(crate) fn is_invisible_attack_char(c: char) -> bool {
    matches!(
        c as u32,
        0x202A..=0x202E | 0x200B..=0x200F | 0x2060..=0x206F | 0xFEFF | 0xE0000..=0xE007F
    )
}

pub(crate) fn fold_fullwidth_ascii(c: char) -> char {
    let code = c as u32;
    if (0xFF01..=0xFF5E).contains(&code) {
        char::from_u32(code - 0xFEE0).unwrap_or(c)
    } else {
        c
    }
}

/// Cyrillic↔Latin homoglyphs.
///
/// Explicit visual mappings include `в/к/м/н`, `т→t`, and `г→r`
/// (visual similarity to Latin r, rather than phonetic transliteration).
/// Not a Confusables.txt import. Armenian and font-dependent peers (`п`, …)
/// stay out.
fn fold_cyrillic_lookalike(c: char) -> char {
    match c {
        'а' | 'А' => 'a',
        'в' | 'В' => 'b',
        'г' | 'Г' => 'r',
        'е' | 'Е' | 'ё' | 'Ё' => 'e',
        'к' | 'К' => 'k',
        'м' | 'М' => 'm',
        'н' | 'Н' => 'h',
        'о' | 'О' => 'o',
        'р' | 'Р' => 'p',
        'с' | 'С' => 'c',
        'т' | 'Т' => 't',
        'у' | 'У' => 'y',
        'х' | 'Х' => 'x',
        'і' | 'І' | 'ї' | 'Ї' => 'i',
        'ѕ' | 'Ѕ' => 's',
        'ј' | 'Ј' => 'j',
        'ԛ' | 'Ԛ' => 'q',
        'ԝ' | 'Ԝ' => 'w',
        other => other,
    }
}

/// Usual Greek↔Latin homoglyphs, including capitals (Η→H, Ν→N, Μ→M, Ζ→Z).
/// Residual: unenumerated scripts (Armenian, some math symbols, …) are not
/// folded. NFKC runs before this table; Cyrillic/Greek still need it.
fn fold_greek_lookalike(c: char) -> char {
    match c {
        'Α' | 'α' => 'A',
        'Β' | 'β' => 'B',
        'Ε' | 'ε' | 'ϵ' => 'E',
        'Ζ' | 'ζ' => 'Z',
        'Η' | 'η' => 'H',
        'Ι' | 'ι' => 'I',
        'Κ' | 'κ' | 'ϰ' => 'K',
        'Μ' | 'μ' => 'M',
        'Ν' | 'ν' => 'N',
        'Ο' | 'ο' => 'O',
        'Ρ' | 'ρ' | 'ϱ' => 'P',
        'Τ' | 'τ' => 'T',
        'Υ' | 'υ' | 'ϒ' => 'Y',
        'Χ' | 'χ' => 'X',
        // Extra common confusables; not required for NAME/ΝΑΜΕ.
        'Ϲ' | 'ϲ' => 'C',
        'ω' | 'Ω' => 'W',
        'γ' => 'Y',
        'σ' | 'ς' | 'Σ' => 'S',
        other => other,
    }
}

/// Latin ligatures. Kept after NFKC (regression + forms NFKC may not expand).
fn fold_latin_ligature(c: char) -> Option<&'static str> {
    match c {
        'ﬀ' => Some("ff"),
        'ﬁ' => Some("fi"),
        'ﬂ' => Some("fl"),
        'ﬃ' => Some("ffi"),
        'ﬄ' => Some("ffl"),
        'ﬅ' | 'ﬆ' => Some("st"),
        _ => None,
    }
}

pub(crate) fn fold_name_for_collision(name: &str) -> String {
    // Normalize compatibility forms before applying the explicit visual mappings.
    let nfkc: String = name.nfkc().collect();
    let mut out = String::with_capacity(nfkc.len());
    for c in nfkc.chars() {
        let c = fold_fullwidth_ascii(c);
        if let Some(expanded) = fold_latin_ligature(c) {
            for part in expanded.chars() {
                out.push(part.to_ascii_lowercase());
            }
            continue;
        }
        let c = fold_cyrillic_lookalike(c);
        let c = fold_greek_lookalike(c);
        out.push(c.to_ascii_lowercase());
    }
    out
}
