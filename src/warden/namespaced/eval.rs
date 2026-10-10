//! Per-flow / per-datagram verdicts for the proxy — the same decision
//! core `unotify`'s supervisor applies to `connect(2)`, but reached
//! from packet interception rather than syscall notification. Deny
//! precedes allow; grants only ever allow; qualifiers scope exactly
//! what was minted.
//!
//! Audit vocabulary matches the rest of the launch: denied flows emit
//! `sandbox.network_denied` (committed durably for TCP — the record
//! lands before the RST; buffered for UDP — a datagram flood cannot
//! serialize the sink), allowed flows emit buffered
//! `sandbox.network_allowed`. Every record carries
//! `layer=ip proto=<p> dest=<ip> port=<n>` — the protocol and
//! destination fields the PR requires.

use std::net::IpAddr;

use crate::audit_log::{
    Action, AuditEvent, AuditLogger, EventType, Outcome, PolicyAuditContext, Severity,
};
use crate::dnsgate::allowlist::DynamicAllowList;
use crate::policy::EgressProto;
use crate::warden::unotify::{IpLayerEvaluator, IpVerdict};

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
        let names = self.grants.names_for(&dest);
        let covered = self.grants.is_allowed(&dest, proto, port);
        self.evaluator.evaluate(&dest, proto, port, &names, covered)
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

    /// `sandbox.network_allowed` — buffered, same availability
    /// contract as the unotify/dns-gate allow paths (the logger's
    /// `is_failed` gate converts a dead sink into denies upstream of
    /// here).
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
            "layer=ip {} basis={basis} session_id={}",
            self.fields(proto, dest, port),
            self.logger.session_id()
        );
        if let Some(rule) = rule {
            details.push_str(&format!(" rule={rule}"));
        }
        event.details = Some(details);
        self.logger.log(event);
    }
}
