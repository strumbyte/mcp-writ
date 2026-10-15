//! Per-flow / per-datagram verdicts for user-space egress proxies —
//! the same decision core `unotify`'s supervisor applies to
//! `connect(2)`, reached from packet interception (PR-09 namespaced
//! TUN proxy) or from CONNECT request targets (PR-11 macOS loopback
//! proxy) rather than syscall notification. Deny precedes allow;
//! grants only ever allow; qualifiers scope exactly what was minted.
//!
//! Audit vocabulary matches the rest of the launch: denied flows emit
//! `sandbox.network_denied` (committed durably for TCP — the record
//! lands before the RST; buffered for UDP — a datagram flood cannot
//! serialize the sink); allowed flows emit a committed
//! `sandbox.network_allowed` `stage=authorize` *before* the side effect
//! they authorize (backend spawn, CONNECT dial) — `Err` refuses the
//! flow — and optionally a buffered `stage=established` follow-up once
//! the flow is connected. Every record carries `layer=ip proto=<p>
//! dest=<ip> port=<n>` — the protocol and destination fields the PR
//! requires. A consumer whose interception
//! point carries a name (the CONNECT proxy's authority) also emits
//! `layer=name` variants for the denied name-layer half of the
//! judgment, so the audit stream mirrors the two-layer evaluation
//! order.

use std::net::IpAddr;

use crate::audit_log::{
    Action, AuditEvent, AuditLogger, EventType, Outcome, PolicyAuditContext, Severity,
};
use crate::dnsgate::allowlist::DynamicAllowList;
use crate::policy::EgressProto;
use crate::warden::ip_eval::{IpLayerEvaluator, IpVerdict};

/// The verdict + audit helper the proxy tasks share.
pub struct FlowGate {
    evaluator: IpLayerEvaluator,
    grants: std::sync::Arc<DynamicAllowList>,
    logger: AuditLogger,
    launch_id: uuid::Uuid,
    policy_ctx: Option<PolicyAuditContext>,
}

impl FlowGate {
    pub fn new(
        evaluator: IpLayerEvaluator,
        grants: std::sync::Arc<DynamicAllowList>,
        logger: AuditLogger,
        launch_id: uuid::Uuid,
        policy_ctx: Option<PolicyAuditContext>,
    ) -> Self {
        Self {
            evaluator,
            grants,
            logger,
            launch_id,
            policy_ctx,
        }
    }

    /// Evaluate one flow. `proto`/`port` are the packet's transport
    /// and destination port; grants covering `dest` are consulted with
    /// their proto/port qualifiers. A dead audit sink denies before
    /// any allow is evaluated — the same fail-closed gate the unotify
    /// supervisor applies (`is_failed` flips allows to deny under a
    /// `fail_closed` audit policy).
    pub fn verdict(&self, dest: IpAddr, proto: EgressProto, port: u16) -> IpVerdict {
        if self.logger.is_failed() {
            return IpVerdict::Deny {
                decision: "audit-unavailable",
                rule: None,
            };
        }
        // Grants are minted on — and looked up by — the judged
        // endpoint: a DNS64-synthesized AAAA (`64:ff9b::x`) mints a
        // grant on the v4 the proxy will dial, so a later CONNECT to
        // the same spelling finds it under the judged form.
        let endpoint = self.evaluator.judged_endpoint(dest);
        let names = self.grants.names_for(&endpoint);
        let covered = self.grants.is_allowed(&endpoint, proto, port);
        self.evaluator.evaluate(&dest, proto, port, &names, covered)
    }

    /// Verdict for a connect whose destination arrived as a raw IP
    /// literal: DNS-derived grants do not authorize it. A name-allowed
    /// workload that may CONNECT the bare resolved address could reach
    /// every service co-hosted on that IP with a different SNI/Host —
    /// the grant would be reusable authority, not the hostname's. Only
    /// static literal/CIDR allows (and the open posture) bind a literal
    /// connect; name-derived grants still authorize name-authority
    /// CONNECTs through [`Self::verdict`].
    ///
    /// `#[cfg]`: only the CONNECT proxy can distinguish a literal-IP
    /// authority — the sockaddr/packet paths see addresses either way.
    #[cfg(target_os = "macos")]
    pub fn verdict_literal(&self, dest: IpAddr, proto: EgressProto, port: u16) -> IpVerdict {
        if self.logger.is_failed() {
            return IpVerdict::Deny {
                decision: "audit-unavailable",
                rule: None,
            };
        }
        self.evaluator.evaluate(&dest, proto, port, &[], false)
    }

    fn event(
        &self,
        event_type: EventType,
        severity: Severity,
        outcome: Outcome,
        action: Action,
    ) -> AuditEvent {
        let mut event = AuditEvent::new(self.launch_id, event_type, severity, outcome, action);
        event.policy_context = self.policy_ctx.clone();
        if let Some(p) = &self.policy_ctx
            && p.id != "default"
        {
            event.target_server = Some(p.id.clone());
        }
        event
    }

    fn fields(&self, proto: EgressProto, dest: IpAddr, port: u16) -> String {
        format!("proto={} dest={dest} port={port}", proto.as_str())
    }

    /// `sandbox.network_denied` — committed for TCP (the RST goes out
    /// only after the record is durable on a fail-closed sink),
    /// buffered for UDP (no per-datagram fsync; see module docs).
    pub async fn denied(
        &self,
        proto: EgressProto,
        dest: IpAddr,
        port: u16,
        decision: &str,
        rule: Option<&str>,
    ) {
        let mut event = self.event(
            EventType::SandboxNetworkDenied,
            Severity::High,
            Outcome::Failure,
            Action::Denied,
        );
        let mut details = format!(
            "layer=ip {} decision={decision} session_id={}",
            self.fields(proto, dest, port),
            self.logger.session_id()
        );
        if let Some(rule) = rule {
            details.push_str(&format!(" rule={rule}"));
        }
        event.details = Some(details);
        if proto == EgressProto::Tcp {
            if let Err(e) = self.logger.log_committed(event).await {
                tracing::error!("audit commit for denied tcp flow failed: {e}");
            }
        } else {
            self.logger.log(event);
        }
    }

    /// `sandbox.network_allowed` `stage=authorize` — the pre-action
    /// gate a fail-closed consumer must await before performing the
    /// authorized side effect (backend spawn, `connect(2)`, byte
    /// relay). Committed for TCP — the record is durable before the
    /// dial begins — and ordered-admission for UDP (a fresh-flow fsync
    /// would serialize a datagram flood on the sink). `Err` means the
    /// record could not be accepted: the sink latches `writer_failed`,
    /// and the caller must refuse the flow rather than proceed
    /// unaudited.
    pub async fn authorize(
        &self,
        proto: EgressProto,
        dest: IpAddr,
        port: u16,
        basis: &str,
        rule: Option<&str>,
    ) -> Result<(), crate::error::AuditorError> {
        let mut event = self.event(
            EventType::SandboxNetworkAllowed,
            Severity::Info,
            Outcome::Success,
            Action::Allowed,
        );
        let mut details = format!(
            "layer=ip {} stage=authorize basis={basis} session_id={}",
            self.fields(proto, dest, port),
            self.logger.session_id()
        );
        if let Some(rule) = rule {
            details.push_str(&format!(" rule={rule}"));
        }
        event.details = Some(details);
        if proto == EgressProto::Tcp {
            self.logger.log_committed(event).await
        } else {
            self.logger.log_ordered(event).await
        }
    }

    /// `sandbox.network_allowed` `stage=established` — buffered post-fact
    /// record for consumers that report an established flow separately
    /// from its committed `authorize` (the macOS CONNECT proxy). The
    /// pre-action ordering contract lives in [`FlowGate::authorize`];
    /// this record is observational.
    #[allow(dead_code)] // consumed by the macOS CONNECT proxy
    pub fn allowed(
        &self,
        proto: EgressProto,
        dest: IpAddr,
        port: u16,
        basis: &str,
        rule: Option<&str>,
    ) {
        let mut event = self.event(
            EventType::SandboxNetworkAllowed,
            Severity::Info,
            Outcome::Success,
            Action::Allowed,
        );
        let mut details = format!(
            "layer=ip {} stage=established basis={basis} session_id={}",
            self.fields(proto, dest, port),
            self.logger.session_id()
        );
        if let Some(rule) = rule {
            details.push_str(&format!(" rule={rule}"));
        }
        event.details = Some(details);
        self.logger.log(event);
    }

    /// `sandbox.network_denied` for a name-layer refusal — the CONNECT
    /// authority's name judgment (or its resolution failure), recorded
    /// committed like any TCP deny: the refusal answer goes out only
    /// after the record is durable.
    #[allow(dead_code)] // consumed by the macOS CONNECT proxy; namespaced is IP-only
    pub async fn denied_name(
        &self,
        name: &str,
        proto: EgressProto,
        port: u16,
        decision: &str,
        rule: Option<&str>,
    ) {
        let mut event = self.event(
            EventType::SandboxNetworkDenied,
            Severity::High,
            Outcome::Failure,
            Action::Denied,
        );
        let mut details = format!(
            "layer=name via=connect name={name} proto={} port={port} decision={decision} session_id={}",
            proto.as_str(),
            self.logger.session_id()
        );
        if let Some(rule) = rule {
            details.push_str(&format!(" rule={rule}"));
        }
        event.details = Some(details);
        if let Err(e) = self.logger.log_committed(event).await {
            tracing::error!("audit commit for denied connect name failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_gate(logger: AuditLogger) -> FlowGate {
        let outbound = crate::policy::OutboundPolicy {
            allowed: Vec::new(),
            allowed_port_qualified: Vec::new(),
            allowed_cidrs: vec!["93.184.216.0/24".to_string()],
            allowed_cidrs_port_qualified: Vec::new(),
            denied_hosts: Vec::new(),
            denied_cidrs: Vec::new(),
            deny_all_others: false,
            egress_rules: Vec::new(),
        };
        FlowGate::new(
            // Per-platform evaluator constructor — `new` is the Linux
            // (unotify) flavor; macOS's is `new_connect_proxy`.
            #[cfg(target_os = "linux")]
            IpLayerEvaluator::new(&outbound).unwrap(),
            #[cfg(target_os = "macos")]
            IpLayerEvaluator::new_connect_proxy(&outbound).unwrap(),
            std::sync::Arc::new(DynamicAllowList::new(16)),
            logger,
            uuid::Uuid::now_v7(),
            None,
        )
    }

    fn dest() -> IpAddr {
        "93.184.216.34".parse().unwrap()
    }

    /// The authorization record must land durably before `authorize`
    /// reports Ok — the caller's side effect can only then proceed.
    #[tokio::test]
    async fn authorize_commits_the_record() {
        let dir = crate::testutil::real_tempdir().unwrap().keep();
        let path = dir.join("audit.jsonl");
        let gate = test_gate(AuditLogger::to_file(&path).unwrap());

        gate.authorize(EgressProto::Tcp, dest(), 443, "allow-cidr", None)
            .await
            .unwrap();
        let _ = gate.logger.shutdown().await;

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("\"event_type\":\"sandbox.network_allowed\""),
            "authorize record must persist, got: {body}"
        );
        assert!(body.contains("stage=authorize"), "got: {body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A dead/saturated sink refuses the authorization — the caller
    /// must not perform the side effect (backend spawn, connect).
    #[tokio::test]
    async fn authorize_refuses_after_sink_death() {
        let dir = crate::testutil::real_tempdir().unwrap().keep();
        let path = dir.join("audit.jsonl");
        let gate = test_gate(AuditLogger::to_file(&path).unwrap());
        let _ = gate.logger.shutdown().await;

        let err = gate
            .authorize(EgressProto::Tcp, dest(), 443, "allow-cidr", None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::error::AuditorError::AuditUnavailable(_)),
            "expected AuditUnavailable, got: {err:?}"
        );
        assert!(gate.logger.is_failed());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Same contract on the UDP path — admission is ordered rather than
    /// committed, but a dead sink still refuses.
    #[tokio::test]
    async fn authorize_udp_refuses_after_sink_death() {
        let dir = crate::testutil::real_tempdir().unwrap().keep();
        let path = dir.join("audit.jsonl");
        let gate = test_gate(AuditLogger::to_file(&path).unwrap());
        let _ = gate.logger.shutdown().await;

        assert!(
            gate.authorize(EgressProto::Udp, dest(), 53, "allow-cidr", None)
                .await
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
