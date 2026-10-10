//! Supervisor loop — poll the listener, inspect → revalidate →
//! evaluate → respond to each `connect` notification.

use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd};

use crate::audit_log::{
    Action, AuditEvent, AuditLogger, EventType, Outcome, PolicyAuditContext, Severity,
};

use super::evaluate::{IpLayerEvaluator, IpVerdict};
use super::filter::CONNECT_NR;
use super::grants::{GrantSource, Grants};
use super::inspect::{SockProto, SockTarget, inspect_sockaddr, socket_proto};
use super::notif::{
    notif_resp_continue, notif_resp_error, notify_id_valid, notify_recv, notify_send,
};

/// What the supervisor needs: the policy projection, the grant source,
/// the audit sink and correlation context.
pub struct SupervisorConfig {
    pub evaluator: IpLayerEvaluator,
    pub grants: GrantSource,
    pub logger: AuditLogger,
    pub launch_id: uuid::Uuid,
    pub policy_context: Option<PolicyAuditContext>,
}

/// Counters the report's capability block carries — what the
/// supervisor observably did, not a claim about every syscall.
#[derive(Debug, Default, Clone)]
pub struct SupervisorStats {
    /// Notifications received.
    pub notifications: u64,
    /// `connect` allowed by policy → `CONTINUE` sent.
    pub continued: u64,
    /// `connect` denied → `EACCES` sent after the audit record.
    pub denied: u64,
    /// Non-INET-family connects passed through unsupervised.
    pub noninet_skipped: u64,
    /// Notifications answered with a deny because the destination
    /// could not be read or decoded (fail closed).
    pub unreadable_denied: u64,
    /// Notifications whose task died before/while answering
    /// (ID_VALID failed, or SEND raced the death) — benign.
    pub expired: u64,
    /// Denial emitted because the fail-closed audit sink was dead
    /// (an allow verdict flipped to deny).
    pub audit_unavailable_denied: u64,
    /// SEND failures other than the dead-notification race.
    pub send_errors: u64,
    /// Denied-connect audit records whose commit failed.
    pub audit_errors: u64,
}

/// Why the supervisor loop exited.
#[derive(Debug)]
pub enum SupervisorExit {
    /// The stop fd was signalled (command-initiated shutdown).
    Shutdown,
    /// The listener/loop failed — monitoring is gone. The kernel makes
    /// pending + future connects fail (`ENOSYS`), and the command kills
    /// the supervised child — fail closed.
    Lost(String),
}

/// The supervisor's exit record: reason plus the counters it reached.
pub struct SupervisorEnd {
    pub reason: SupervisorExit,
    pub stats: SupervisorStats,
}

/// A running supervisor — the blocking notification loop on a
/// `spawn_blocking` task plus the eventfd the stop side writes.
pub struct Supervisor {
    task: tokio::task::JoinHandle<SupervisorEnd>,
    stop: File,
}

impl Supervisor {
    /// Start supervising `listener` — one blocking task per supervised
    /// launch. Must be called from inside the tokio runtime.
    pub fn start(listener: File, cfg: SupervisorConfig) -> io::Result<Self> {
        // Safety: eventfd creates a live fd; EFD_CLOEXEC keeps it out
        // of any exec'd image.
        let stop_raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        if stop_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let stop = unsafe { File::from_raw_fd(stop_raw) };
        let loop_stop = stop.try_clone()?;
        let task = tokio::task::spawn_blocking(move || {
            let mut sup = Loop {
                listener,
                stop: loop_stop,
                evaluator: cfg.evaluator,
                grants: Grants::new(cfg.grants),
                logger: cfg.logger,
                launch_id: cfg.launch_id,
                policy_ctx: cfg.policy_context,
                stats: SupervisorStats::default(),
            };
            sup.run()
        });
        Ok(Self { task, stop })
    }

    /// The supervisor's exit future for `tokio::select!` — resolves the
    /// moment the loop ends for any reason (that's the fail-closed
    /// signal the command must act on while the child lives).
    pub fn exited(&mut self) -> &mut tokio::task::JoinHandle<SupervisorEnd> {
        &mut self.task
    }

    /// Signal the loop to stop and await its exit record.
    pub async fn shutdown(self) -> SupervisorEnd {
        let byte = 1u64.to_ne_bytes();
        // Safety: `stop` is a live eventfd; 8 bytes is the eventfd write.
        unsafe {
            libc::write(
                self.stop.as_raw_fd(),
                byte.as_ptr().cast::<std::ffi::c_void>(),
                8,
            )
        };
        match self.task.await {
            Ok(end) => end,
            Err(e) => SupervisorEnd {
                reason: SupervisorExit::Lost(format!("supervisor task join failed: {e}")),
                stats: SupervisorStats::default(),
            },
        }
    }
}

struct Loop {
    listener: File,
    stop: File,
    evaluator: IpLayerEvaluator,
    grants: Grants,
    logger: AuditLogger,
    launch_id: uuid::Uuid,
    policy_ctx: Option<PolicyAuditContext>,
    stats: SupervisorStats,
}

impl Loop {
    fn run(&mut self) -> SupervisorEnd {
        let listener_fd = self.listener.as_raw_fd();
        let stop_fd = self.stop.as_raw_fd();
        loop {
            let mut pfds = [
                libc::pollfd {
                    fd: listener_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stop_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // Safety: `pfds` is live for the call.
            let rc = unsafe { libc::poll(pfds.as_mut_ptr(), 2, 500) };
            if rc < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return self.end(SupervisorExit::Lost(format!("poll failed: {e}")));
            }
            if pfds[1].revents & libc::POLLIN != 0 {
                return self.end(SupervisorExit::Shutdown);
            }
            if pfds[0].revents & libc::POLLIN != 0 {
                match notify_recv(listener_fd) {
                    Ok(notif) => self.handle(&notif),
                    Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                    // The pending notification expired with its task
                    // between poll and recv — nothing left to answer.
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                        self.stats.expired += 1;
                        continue;
                    }
                    // Listener dead/queue gone — monitoring is over.
                    Err(e) => {
                        return self.end(SupervisorExit::Lost(format!("NOTIF_RECV failed: {e}")));
                    }
                }
            } else if pfds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                // Error bits report regardless of `events`; without
                // POLLIN there is nothing readable and the listener is
                // dead — leave rather than spin on repeated polls.
                return self.end(SupervisorExit::Lost(format!(
                    "listener fd failed (revents={:#x})",
                    pfds[0].revents
                )));
            }
        }
    }

    fn end(&mut self, reason: SupervisorExit) -> SupervisorEnd {
        SupervisorEnd {
            reason,
            stats: std::mem::take(&mut self.stats),
        }
    }

    /// One notification: inspect → revalidate → evaluate → respond.
    fn handle(&mut self, notif: &libc::seccomp_notif) {
        self.stats.notifications += 1;
        if notif.data.nr != CONNECT_NR as i32 {
            // Defensive: the filter only emits connect, but an unknown
            // notification must never hang the task — continue it.
            self.continue_notif(notif.id);
            return;
        }
        let pid = notif.pid;
        let fd = notif.data.args[0];
        let target = inspect_sockaddr(pid, notif.data.args[1], notif.data.args[2]);
        // Revalidate after the memory read, before acting on it: a
        // dead id means the task no longer waits — answering or
        // auditing a verdict for it would be wasted work.
        if !notify_id_valid(self.listener.as_raw_fd(), notif.id) {
            self.stats.expired += 1;
            return;
        }
        match target {
            SockTarget::OtherFamily { family } => {
                self.stats.noninet_skipped += 1;
                tracing::debug!(
                    pid,
                    family,
                    "connect: non-INET family — continued unsupervised"
                );
                self.continue_notif(notif.id);
            }
            SockTarget::Unreadable { detail } => {
                self.stats.unreadable_denied += 1;
                self.deny(
                    notif.id,
                    pid,
                    "unreadable-dest",
                    &format!("proto=? dest=? port=? detail={detail}"),
                    None,
                );
            }
            SockTarget::Inet { dest, port } => {
                let proto = socket_proto(pid, fd);
                let fields = format!("proto={} dest={} port={}", proto.label(), dest, port);
                // The socket's transport as a flow proto — an
                // undetermined SO_TYPE matches only `proto=any` rules
                // rather than guessing a transport.
                let flow_proto = match proto {
                    SockProto::Stream => crate::policy::EgressProto::Tcp,
                    SockProto::Datagram => crate::policy::EgressProto::Udp,
                    SockProto::Other | SockProto::Unknown => crate::policy::EgressProto::Any,
                };
                let grant_names = self.grants.live_names(&dest);
                let grant_covered = self.grants.has_grant(&dest, flow_proto, port);
                let verdict =
                    self.evaluator
                        .evaluate(&dest, flow_proto, port, &grant_names, grant_covered);
                match verdict {
                    IpVerdict::Deny { decision, rule } => {
                        self.deny(notif.id, pid, decision, &fields, rule.as_deref())
                    }
                    IpVerdict::Allow { basis, rule } => {
                        if self.logger.is_failed() {
                            // Fail-closed audit: an allowed connect must
                            // not pass unaudited — flip it to a denial.
                            self.stats.audit_unavailable_denied += 1;
                            self.deny(
                                notif.id,
                                pid,
                                "audit-unavailable",
                                &format!("{fields} verdict_basis={basis}"),
                                None,
                            );
                        } else {
                            self.allow(notif.id, pid, basis, &fields, rule.as_deref());
                        }
                    }
                }
            }
        }
    }

    /// A `sandbox.*` event stamped with the launch's policy context —
    /// the same boilerplate `dns-gate`'s `Core::event` applies.
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

    /// Emit `sandbox.network_denied` through the launch's fail-closed
    /// audit path *before* answering the syscall — `log_committed` on a
    /// fail-closed logger returns after the record is durable, so the
    /// denial never lands unaudited. A commit failure does not lift the
    /// denial; the sink's `is_failed` flag flips later allows to deny.
    fn deny(&mut self, id: u64, pid: u32, decision: &str, fields: &str, rule: Option<&str>) {
        let mut event = self.event(
            EventType::SandboxNetworkDenied,
            Severity::High,
            Outcome::Failure,
            Action::Denied,
        );
        let mut details = format!(
            "layer=ip {fields} pid={pid} decision={decision} session_id={}",
            self.logger.session_id()
        );
        if let Some(rule) = rule {
            details.push_str(&format!(" rule={rule}"));
        }
        event.details = Some(details);
        let res = tokio::runtime::Handle::current().block_on(self.logger.log_committed(event));
        if let Err(e) = res {
            self.stats.audit_errors += 1;
            tracing::error!("audit commit for denied connect failed: {e}");
        }
        self.stats.denied += 1;
        self.send_err(notif_resp_error(id, libc::EACCES));
    }

    /// Emit `sandbox.network_allowed`, then answer CONTINUE — the allow
    /// half of the audit contract. Buffered (`log`, not
    /// `log_committed`): availability on the allow path is the
    /// `is_failed` gate in `handle`, not a per-record fsync — the same
    /// split `dns-gate` applies to its `sandbox.network_resolved`
    /// records. The record precedes the syscall it describes.
    fn allow(&mut self, id: u64, pid: u32, basis: &str, fields: &str, rule: Option<&str>) {
        let mut event = self.event(
            EventType::SandboxNetworkAllowed,
            Severity::Info,
            Outcome::Success,
            Action::Allowed,
        );
        let mut details = format!(
            "layer=ip {fields} pid={pid} basis={basis} session_id={}",
            self.logger.session_id()
        );
        if let Some(rule) = rule {
            details.push_str(&format!(" rule={rule}"));
        }
        event.details = Some(details);
        self.logger.log(event);
        self.stats.continued += 1;
        self.send_err(notif_resp_continue(id));
    }

    fn continue_notif(&mut self, id: u64) {
        self.send_err(notif_resp_continue(id));
    }

    fn send_err(&mut self, resp: libc::seccomp_notif_resp) {
        match notify_send(self.listener.as_raw_fd(), &resp) {
            Ok(()) => {}
            // The task died mid-answer — nothing to fail.
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ESRCH)) => {
                self.stats.expired += 1;
            }
            Err(e) => {
                self.stats.send_errors += 1;
                tracing::warn!("NOTIF_SEND failed: {e}");
            }
        }
    }
}
