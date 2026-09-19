//! Internal decoder abstraction.
//!
//! Disassembler backends are wrapped behind per-architecture modules so that
//! higher-level inspector code never names backend types (currently
//! `iced-x86`; an AArch64 backend is selected separately — see the ARM64
//! runbook P4 record). Only the information the analysis needs — instruction
//! position/length, control-flow class, syscall-entry recognition, and
//! register-write effects — crosses this boundary. Register aliasing and
//! constant-construction rules stay inside each backend.

pub(crate) mod x86;
