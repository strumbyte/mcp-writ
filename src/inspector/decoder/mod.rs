//! Internal decoder abstraction.
//!
//! Disassembler backends are wrapped behind per-architecture modules so that
//! higher-level inspector code never names backend types (`iced-x86` for
//! x86-64, `yaxpeax-arm` for AArch64 — see the ARM64 runbook P4/P5 records).
//! Only the information the analysis needs — instruction position/length,
//! control-flow class, syscall-entry recognition, and register-write
//! effects — crosses this boundary. Register aliasing and
//! constant-construction rules stay inside each backend.

pub(crate) mod aarch64;
pub(crate) mod x86;
