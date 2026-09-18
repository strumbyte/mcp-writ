//! Small self-contained Reasoning-Impact Score approximation.
//!
//! IronContext weights (imperative / instruction leakage / length bloat) are
//! followed loosely. This is draft commentary only: RIS never rejects `run`.
//!
//! No ironcontext-core, no serde.

use std::sync::OnceLock;

use regex_lite::Regex;

use crate::tool_def::ToolDefinition;

const W_IMPERATIVE: f32 = 30.0;
const W_INSTRUCTION: f32 = 35.0;
const W_BLOAT: f32 = 10.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RisBand {
    Low,
    Medium,
    High,
    Severe,
}

impl RisBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Severe => "severe",
        }
    }

    fn from_score(score: u8) -> Self {
        match score {
            0..=29 => Self::Low,
            30..=59 => Self::Medium,
            60..=79 => Self::High,
            _ => Self::Severe,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RisScore {
    pub score: u8,
    pub band: RisBand,
    pub dominant: &'static str,
}

impl RisScore {
    /// Comment fragment: `ris 72 band=high dominant=instruction_leakage`.
    pub fn comment(&self) -> String {
        format!(
            "ris {} band={} dominant={}",
            self.score,
            self.band.as_str(),
            self.dominant
        )
    }
}

fn re_imperative() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:must|always|never|immediately|do\s+not|always\s+ensure|be\s+sure\s+to|make\s+sure)\b",
        )
        .expect("imperative regex")
    })
}

fn re_instruction_leak() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:think\s+step\s*by\s*step|first\s+(?:think|reason|plan)|before\s+answering|reason\s+about|consider\s+carefully|you\s+should\s+(?:think|plan|reason))\b",
        )
        .expect("leakage regex")
    })
}

fn tokens(s: &str) -> Vec<&str> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect()
}

fn imperative_density(desc: &str) -> f32 {
    let n = tokens(desc).len();
    if n == 0 {
        return 0.0;
    }
    let hits = re_imperative().find_iter(desc).count() as f32;
    (hits / n as f32 / 0.05).min(1.0)
}

fn instruction_leakage(desc: &str) -> f32 {
    match re_instruction_leak().find_iter(desc).count() {
        0 => 0.0,
        1 => 0.6,
        2 => 0.85,
        _ => 1.0,
    }
}

fn length_bloat(desc: &str) -> f32 {
    let n = tokens(desc).len() as f32;
    if n <= 60.0 {
        0.0
    } else if n >= 200.0 {
        1.0
    } else {
        (n - 60.0) / 140.0
    }
}

/// Approximate RIS for one tool. Peer overlap is omitted (small approx).
/// Uses the same advertised-text blob as heuristics (title + other
/// first-seen advertised fields), so an empty description is not blind.
pub fn score_tool(tool: &ToolDefinition) -> RisScore {
    score_description(&tool.advertised_text())
}

pub fn score_description(description: &str) -> RisScore {
    let imperative = imperative_density(description);
    let leakage = instruction_leakage(description);
    let bloat = length_bloat(description);

    let contributions = [
        ("imperative_density", W_IMPERATIVE * imperative),
        ("instruction_leakage", W_INSTRUCTION * leakage),
        ("length_bloat", W_BLOAT * bloat),
    ];
    let total = contributions
        .iter()
        .map(|(_, v)| *v)
        .sum::<f32>()
        .clamp(0.0, 100.0);
    let score = total.round() as u8;
    let dominant = contributions
        .iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(name, _)| *name)
        .unwrap_or("imperative_density");

    RisScore {
        score,
        band: RisBand::from_score(score),
        dominant,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str, description: &str) -> ToolDefinition {
        ToolDefinition::new(name, description)
    }

    #[test]
    fn clean_simple_tool_is_low() {
        let s = score_tool(&tool("add", "Adds two numbers and returns the sum."));
        assert!(s.score < 20, "got {}", s.score);
        assert_eq!(s.band, RisBand::Low);
        assert!(s.comment().starts_with("ris "));
        assert!(s.comment().contains("band="));
        assert!(s.comment().contains("dominant="));
    }

    #[test]
    fn injected_tool_is_high() {
        let s = score_tool(&tool(
            "calc",
            "You must always think step by step. Be sure to first reason about the input. \
             Never skip the planning phase. Always ensure correctness. Do not deviate.",
        ));
        assert!(s.score >= 60, "got {}", s.score);
        assert!(matches!(s.band, RisBand::High | RisBand::Severe));
        assert!(
            s.dominant == "instruction_leakage" || s.dominant == "imperative_density",
            "dominant={}",
            s.dominant
        );
    }

    #[test]
    fn title_imperative_scores_when_description_empty() {
        let mut t = tool("helper", "");
        t.title = Some(
            "You must always think step by step. Be sure to first reason about the input.".into(),
        );
        let s = score_tool(&t);
        assert!(
            s.score >= 30,
            "title-only advertised text must contribute to RIS, got {}",
            s.score
        );
    }

    #[test]
    fn comment_matches_generate_policy_shape() {
        let s = RisScore {
            score: 72,
            band: RisBand::High,
            dominant: "instruction_leakage",
        };
        assert_eq!(s.comment(), "ris 72 band=high dominant=instruction_leakage");
    }
}
