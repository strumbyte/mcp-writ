//! Exact-decimal arithmetic behind the numeric keywords: `ExactDecimal`
//! compares arbitrary-precision JSON `number` literals without binary
//! rounding, and the significand-divisibility helpers implement
//! `multipleOf` on zero-padded digit vectors.
//!
//! Exact comparison has no fixed significand-precision limit — the
//! digit vector carries as many digits as the literal does. The bound
//! is on exponents: parsing requires both the literal exponent *and*
//! the normalized (digit-position-adjusted) exponent to fit in `i64`,
//! and the literal is checked first — `10e-9223372036854775809` fails
//! before normalization even though the normalized exponent
//! (`i64::MIN`) would fit.

use std::cmp::Ordering;

use super::EvalError;
/// Work bound for `multipleOf`: the schoolbook remainder costs roughly
/// `dividend.len() * divisor.len()` digit steps, so extreme scales
/// (`1e1000000`) are rejected rather than materialized.
const MAX_MULTIPLE_OF_COST: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExactDecimal {
    pub(super) negative: bool,
    pub(super) digits: Vec<u8>,
    pub(super) exp: i64,
}

impl ExactDecimal {
    pub(super) fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty numeric string".to_string());
        }

        let (negative, rest) = if let Some(stripped) = s.strip_prefix('-') {
            (true, stripped)
        } else if let Some(stripped) = s.strip_prefix('+') {
            (false, stripped)
        } else {
            (false, s)
        };

        let (mantissa, exp_val) = if let Some(idx) = rest.find(['e', 'E']) {
            let exp_str = &rest[idx + 1..];
            let exp_parsed: i64 = exp_str
                .parse()
                .map_err(|e| format!("invalid exponent '{exp_str}': {e}"))?;
            (&rest[..idx], exp_parsed)
        } else {
            (rest, 0i64)
        };

        let (int_part, frac_part) = if let Some(idx) = mantissa.find('.') {
            (&mantissa[..idx], &mantissa[idx + 1..])
        } else {
            (mantissa, "")
        };

        let mut raw_digits = Vec::new();
        for b in int_part.bytes() {
            if b.is_ascii_digit() {
                raw_digits.push(b - b'0');
            } else {
                return Err(format!("invalid character in integer part of '{s}'"));
            }
        }
        let int_len = raw_digits.len() as i64;

        for b in frac_part.bytes() {
            if b.is_ascii_digit() {
                raw_digits.push(b - b'0');
            } else {
                return Err(format!("invalid character in fraction part of '{s}'"));
            }
        }

        let first_non_zero = raw_digits.iter().position(|&d| d != 0);
        let Some(start_idx) = first_non_zero else {
            return Ok(ExactDecimal {
                negative: false,
                digits: Vec::new(),
                exp: 0,
            });
        };

        let last_non_zero = raw_digits.iter().rposition(|&d| d != 0).unwrap();
        let trimmed_digits = raw_digits[start_idx..=last_non_zero].to_vec();

        let exp = (int_len - 1 - (start_idx as i64))
            .checked_add(exp_val)
            .ok_or_else(|| "exponent overflow".to_string())?;

        Ok(ExactDecimal {
            negative,
            digits: trimmed_digits,
            exp,
        })
    }

    fn cmp(&self, other: &Self) -> Ordering {
        let self_zero = self.digits.is_empty();
        let other_zero = other.digits.is_empty();

        if self_zero && other_zero {
            return Ordering::Equal;
        }
        if self_zero {
            return if other.negative {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        if other_zero {
            return if self.negative {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }

        match (self.negative, other.negative) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => self.cmp_abs(other),
            (true, true) => other.cmp_abs(self),
        }
    }

    fn cmp_abs(&self, other: &Self) -> Ordering {
        if self.exp != other.exp {
            return self.exp.cmp(&other.exp);
        }

        let min_len = self.digits.len().min(other.digits.len());
        for i in 0..min_len {
            match self.digits[i].cmp(&other.digits[i]) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        self.digits.len().cmp(&other.digits.len())
    }
}

pub(super) fn compare_numeric_strings(a: &str, b: &str) -> Result<Ordering, String> {
    let da = ExactDecimal::parse(a)?;
    let db = ExactDecimal::parse(b)?;
    Ok(da.cmp(&db))
}

pub(super) fn numbers_equal(a: &str, b: &str) -> bool {
    if let (Ok(da), Ok(db)) = (ExactDecimal::parse(a), ExactDecimal::parse(b)) {
        da.cmp(&db) == Ordering::Equal
    } else {
        a == b
    }
}

/// `v % d == 0` on exact decimal significands. `v = digits_v * 10^sv` and
/// `d = digits_d * 10^sd`; at the common scale `t = min(sv, sd)` the test
/// becomes integer divisibility of zero-padded digit vectors.
pub(super) fn is_multiple_of(value: &str, divisor: &str) -> Result<bool, EvalError> {
    let dv = ExactDecimal::parse(value).map_err(EvalError::Fatal)?;
    let dd = ExactDecimal::parse(divisor)
        .map_err(|e| EvalError::Fatal(format!("invalid multipleOf '{divisor}': {e}")))?;
    if dd.negative || dd.digits.is_empty() {
        return Err(EvalError::Fatal(format!(
            "multipleOf must be greater than 0, got '{divisor}'"
        )));
    }
    if dv.digits.is_empty() {
        return Ok(true); // zero is a multiple of every nonzero number
    }
    // `sv`/`sd` are each operand's scale — the power of ten of its least
    // significant digit. Exponents parse as i64 (`1e-9223372036854775808`
    // is a legal literal), so the span arithmetic runs in `i128`: `sv`
    // alone can sit past the i64 edge while the *shared* scale
    // difference `sv - t` cancels to a small shift — `1e-…808` mod
    // `1e-…808` must not Fatal on an i64 overflow that never survives
    // the subtraction. The cost product stays checked: operands that
    // sit astronomically past the bound are rejected, never wrapped
    // into a negative length feeding `resize` below.
    let span_overflow = || {
        EvalError::Fatal(
            "multipleOf operands exceed evaluation bound (exponent span overflows)".to_string(),
        )
    };
    let sv = dv.exp as i128 - (dv.digits.len() as i128 - 1);
    let sd = dd.exp as i128 - (dd.digits.len() as i128 - 1);
    let t = sv.min(sd);
    // Bound before materializing: a hostile schema like `1e999999` would
    // otherwise allocate the full exponent span as digits.
    let len_a = (dv.digits.len() as i128)
        .checked_add(sv.checked_sub(t).ok_or_else(span_overflow)?)
        .ok_or_else(span_overflow)?;
    let len_b = (dd.digits.len() as i128)
        .checked_add(sd.checked_sub(t).ok_or_else(span_overflow)?)
        .ok_or_else(span_overflow)?;
    let cost = len_a.checked_mul(len_b).ok_or_else(span_overflow)?;
    if cost > MAX_MULTIPLE_OF_COST as i128 {
        return Err(EvalError::Fatal(format!(
            "multipleOf operands exceed evaluation bound ({cost} digit cells > {MAX_MULTIPLE_OF_COST})"
        )));
    }
    let mut a = dv.digits.clone();
    a.resize(len_a as usize, 0);
    let mut b = dd.digits.clone();
    b.resize(len_b as usize, 0);
    Ok(digits_mod_is_zero(&a, &b))
}

/// `dividend mod divisor == 0` on most-significant-first digit vectors
/// with no leading zeros. The remainder stays below `divisor`, so each
/// dividend digit costs at most nine subtractions of a `divisor`-length
/// number — O(len(a) * len(b)) worst case.
fn digits_mod_is_zero(dividend: &[u8], divisor: &[u8]) -> bool {
    debug_assert!(!divisor.is_empty() && divisor[0] != 0);
    let mut rem: Vec<u8> = Vec::with_capacity(divisor.len() + 1);
    for &d in dividend {
        rem.push(d);
        trim_leading_zeros(&mut rem);
        while cmp_digits(&rem, divisor) != Ordering::Less {
            sub_assign(&mut rem, divisor);
        }
    }
    rem.iter().all(|&x| x == 0)
}

/// Compare two no-leading-zero digit vectors by magnitude.
fn cmp_digits(a: &[u8], b: &[u8]) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.iter().cmp(b.iter()))
}

/// `a -= b` in place; caller guarantees `a >= b`. Keeps `a` trimmed.
fn sub_assign(a: &mut Vec<u8>, b: &[u8]) {
    let mut borrow = 0i32;
    for i in 0..a.len() {
        let idx = a.len() - 1 - i;
        let bd = if i < b.len() {
            b[b.len() - 1 - i] as i32
        } else {
            0
        };
        let mut d = a[idx] as i32 - bd - borrow;
        if d < 0 {
            d += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[idx] = d as u8;
    }
    trim_leading_zeros(a);
}

fn trim_leading_zeros(v: &mut Vec<u8>) {
    let first_nonzero = v.iter().position(|&d| d != 0).unwrap_or(v.len());
    if first_nonzero > 0 {
        v.drain(..first_nonzero);
    }
}
