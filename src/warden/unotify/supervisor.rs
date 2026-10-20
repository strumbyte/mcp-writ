//! Supervisor loop — poll the listener, inspect → revalidate →
//! evaluate → respond to each `connect` notification. Allowed
//! connects are emulated on a per-notification worker thread (the
//! blocking `connect(2)` must not stall the single loop); the
//! completion lands back on the loop through a channel + eventfd,
//! where the audit record, ID revalidation, and response stay
//! single-threaded.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd};

use crate::audit_log::{
    Action, AuditEvent, AuditLogger, EventType, Outcome, PolicyAuditContext, Severity,
};

use super::filter::CONNECT_NR;
use super::grants::{GrantSource, Grants};
use super::inspect::{
    SockDomain, SockProto, SockTarget, inspect_sockaddr, socket_domain, socket_proto,
    unix_sockaddr_is_pathname,
};
use super::notif::{
    emulate_connect, notif_resp_continue, notif_resp_error, notif_resp_result, notify_id_valid,
    notify_recv, notify_send,
};
use crate::warden::ip_eval::{IpLayerEvaluator, IpVerdict};

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
    /// `connect` allowed by policy → emulated on a dup'd socket fd
    /// (never `CONTINUE` — see [`LIMITATIONS`](super::LIMITATIONS)).
    /// Includes emulations whose kernel-side `connect` returned an
    /// errno — the verdict was allow either way.
    pub emulated: u64,
    /// Allowed by policy but denied anyway because the supervisor
    /// could not obtain the child's socket fd (`pidfd_getfd`
    /// `EPERM`, etc.) — fail closed.
    pub emulation_denied: u64,
    /// Non-INET-family connects continued unsupervised (plus any
    /// foreign-syscall notification, defensively).
    pub continued: u64,
    /// `connect` denied → `EACCES` sent after the audit record.
    pub denied: u64,
    /// Non-INET-family connects passed through after the socket's
    /// immutable `SO_DOMAIN` proved it is not INET — emulated on the
    /// dup'd object like an allowed INET connect, never `CONTINUE`d:
    /// a resume would re-resolve the child's fd number, which a
    /// sibling could have swapped for an INET socket.
    pub noninet_skipped: u64,
    /// Non-INET-sockaddr connects refused because the fd's real domain
    /// was INET/INET6 or unverifiable — a `CONTINUE` would re-read a
    /// child-mutable buffer that may already name a denied destination.
    pub noninet_denied: u64,
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

/// Worker → loop completion for one emulated connect.
enum EmuOutcome {
    /// `connect(2)` ran on the dup'd socket fd — the kernel's result
    /// (0 or a connect errno).
    Connected { id: u64, errno: i32 },
    /// The child's socket fd could not be dup'd at all — the raw
    /// errno `dup_child_fd` returned (`None` = a non-os error).
    DupFailed { id: u64, errno: Option<i32> },
}

/// Hard bound on concurrent emulation workers — one OS thread and one
/// dup'd fd each. A workload that fires allowed-looking connects in a
/// burst must not grow the pool unboundedly: admission checks the cap
/// *before* pending state is inserted or a thread spawns, and refusal
/// is the standard fail-closed `emulation_denied` + `EACCES` path.
const MAX_EMU_WORKERS: usize = 32;

/// The loop-side context for a queued emulation — what the audit
/// record and a fall-back denial need after the worker finishes, plus
/// the worker's handle so shutdown can join every in-flight emulation.
struct PendingEmu {
    pid: u32,
    fields: String,
    basis: String,
    rule: Option<String>,
    /// Worker handle — `Option` so `take_pending` can join it while
    /// still returning the record. Joining the completed worker keeps
    /// teardown deterministic (no detached emulation outlives the
    /// supervisor).
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Supervisor {
    /// Start supervising `listener` — one blocking task per supervised
    /// launch. Must be called from inside the tokio runtime.
    pub fn start(listener: File, cfg: SupervisorConfig) -> io::Result<Self> {
        // Safety: eventfd creates a live fd; EFD_CLOEXEC keeps it out
        // of any exec'd image.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let stop_raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        if stop_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let stop = unsafe { File::from_raw_fd(stop_raw) };
        let loop_stop = stop.try_clone()?;
        // Worker completions wake the poll loop through this eventfd —
        // EFD_NONBLOCK so draining it can never stall the loop.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let done_raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if done_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let done = unsafe { File::from_raw_fd(done_raw) };
        let (tx, rx) = std::sync::mpsc::channel::<EmuOutcome>();
        let task = tokio::task::spawn_blocking(move || {
            let mut sup = Loop {
                listener,
                stop: loop_stop,
                done,
                tx,
                rx,
                pending: HashMap::new(),
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
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    /// Eventfd a worker writes once per queued result — polled
    /// alongside the listener so completions are picked up promptly
    /// rather than on the 500 ms poll timeout.
    done: File,
    /// Result channel: workers `send` their [`EmuOutcome`], the loop
    /// drains `rx` whenever `done` fires.
    tx: std::sync::mpsc::Sender<EmuOutcome>,
    rx: std::sync::mpsc::Receiver<EmuOutcome>,
    /// Emulations in flight, keyed by notification id — one entry per
    /// spawned worker, consumed when its outcome drains.
    pending: HashMap<u64, PendingEmu>,
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
        let done_fd = self.done.as_raw_fd();
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
                libc::pollfd {
                    fd: done_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // Safety: `pfds` is live for the call.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let rc = unsafe { libc::poll(pfds.as_mut_ptr(), 3, 500) };
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
            if pfds[2].revents & libc::POLLIN != 0 {
                self.drain_worker_results();
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

    /// A worker wrote its result: drain the eventfd counter, then
    /// answer every queued [`EmuOutcome`]. The 8-byte read is
    /// nonblocking (`EFD_NONBLOCK` at creation); EAGAIN just means the
    /// counter was already consumed by a previous drain.
    fn drain_worker_results(&mut self) {
        let mut buf = [0u8; 8];
        loop {
            // Safety: `buf` is live for the call; `done` is a live
            // nonblocking eventfd.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let rc = unsafe {
                libc::read(
                    self.done.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    8,
                )
            };
            if rc < 0 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }
            if (rc as usize) < 8 {
                break;
            }
        }
        while let Ok(out) = self.rx.try_recv() {
            self.emulated_result(out);
        }
    }

    fn end(&mut self, reason: SupervisorExit) -> SupervisorEnd {
        // Completions that raced the exit still count — workers that
        // finish after this drain find a dead channel and drop their
        // result (their fds are self-owned; nothing here outlives them).
        while let Ok(out) = self.rx.try_recv() {
            self.emulated_result(out);
        }
        // Emulations still in flight: answer every parked notification
        // EACCES first (a parked syscall must not wait on the joins),
        // then join each worker — bounded by EMU_CONNECT_TIMEOUT, so
        // teardown cannot hang on a connect the kernel never answered.
        for id in self.pending.keys().copied().collect::<Vec<_>>() {
            self.send_err(notif_resp_error(id, libc::EACCES));
        }
        for id in self.pending.keys().copied().collect::<Vec<_>>() {
            let _ = self.take_pending(id);
        }
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
            SockTarget::OtherFamily { family, raw } => {
                // The sockaddr bytes are child-mutable: a sibling could
                // show a non-INET family here and rewrite the buffer to
                // an INET destination before the kernel re-reads it on
                // CONTINUE. The socket's own domain is immutable, so the
                // continuation decision is made on SO_DOMAIN, not the
                // buffer's family field.
                match socket_domain(pid, fd) {
                    SockDomain::Other => {
                        // A genuinely non-INET socket cannot form an
                        // INET connection no matter what the buffer is
                        // rewritten to — but `CONTINUE` would also
                        // re-resolve the child's fd *number* at resume
                        // time, and a sibling could `dup2` an INET
                        // socket into the slot between this SO_DOMAIN
                        // check and the resumed connect. Emulate on the
                        // dup'd object instead: the verdict (pass) was
                        // made on the socket itself, and the response
                        // never resumes the child's mutable arguments.
                        //
                        // A pathname AF_UNIX connect is the exception:
                        // `sun_path` resolves in the *caller's* mount
                        // namespace, and the supervisor's view of that
                        // path is not the child's — emulating here would
                        // connect a filesystem location under the wrong
                        // namespace. No child-context helper exists and
                        // CONTINUE would reopen the fd-swap hole above,
                        // so pathname unix connects are denied; abstract
                        // and unnamed unix sockets stay emulated below.
                        if unix_sockaddr_is_pathname(family, &raw) {
                            self.stats.noninet_denied += 1;
                            self.deny(
                                notif.id,
                                pid,
                                "unix-pathname-connect",
                                &format!("proto=? dest=? port=? family={family}"),
                                None,
                            );
                            return;
                        }
                        self.stats.noninet_skipped += 1;
                        tracing::debug!(
                            pid,
                            family,
                            "connect: non-INET family — emulated unsupervised"
                        );
                        self.queue_emulation(
                            notif,
                            raw,
                            "non-inet-family",
                            &format!("proto=? dest=? port=? family={family}"),
                            None,
                        );
                    }
                    SockDomain::Inet | SockDomain::Unknown => {
                        // INET socket claiming a non-INET sockaddr, or
                        // a socket we cannot verify — the pinned bytes
                        // were never evaluated as a destination, so
                        // resume would be an unchecked connect.
                        self.stats.noninet_denied += 1;
                        self.deny(
                            notif.id,
                            pid,
                            "non-inet-sockaddr",
                            &format!("proto=? dest=? port=? family={family}"),
                            None,
                        );
                    }
                }
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
            SockTarget::Inet { dest, port, raw } => {
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
                        // Fail-closed audit ordering: the authorization
                        // record must be durable before the connect is
                        // emulated — `is_failed` alone races (a buffered
                        // record can drop *after* the check). Commit the
                        // `stage=authorize` record now; a refused commit
                        // flips the allow to an audited denial.
                        let mut event = self.event(
                            EventType::SandboxNetworkAllowed,
                            Severity::Info,
                            Outcome::Success,
                            Action::Allowed,
                        );
                        let mut details = format!(
                            "layer=ip {fields} pid={pid} stage=authorize basis={basis} session_id={}",
                            self.logger.session_id()
                        );
                        if let Some(rule) = &rule {
                            details.push_str(&format!(" rule={rule}"));
                        }
                        event.details = Some(details);
                        let res = tokio::runtime::Handle::current()
                            .block_on(self.logger.log_committed(event));
                        if res.is_err() {
                            self.stats.audit_unavailable_denied += 1;
                            self.deny(
                                notif.id,
                                pid,
                                "audit-unavailable",
                                &format!("{fields} verdict_basis={basis}"),
                                None,
                            );
                        } else {
                            self.queue_emulation(notif, raw, basis, &fields, rule.as_deref());
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

    /// Allowed connect — queue its emulation on a worker thread so the
    /// blocking `connect(2)` cannot stall the notification loop. The
    /// worker dups the child's socket fd via `pidfd_getfd`, runs
    /// `connect` on the dup with the pinned sockaddr bytes the verdict
    /// evaluated, closes the dup, and reports through `done`+channel;
    /// [`emulated_result`] audits, revalidates, and answers. The
    /// child's original syscall is never resumed, so the kernel never
    /// re-reads the child's `sockaddr` pointer — the inspect-vs-use
    /// TOCTOU a `CONTINUE` answer would leave does not exist on this
    /// route.
    ///
    /// A worker that cannot even start fails closed the same way an
    /// unobtainable fd does: `emulation_denied` + `EACCES`.
    fn queue_emulation(
        &mut self,
        notif: &libc::seccomp_notif,
        sockaddr: Box<[u8]>,
        basis: &str,
        fields: &str,
        rule: Option<&str>,
    ) {
        let id = notif.id;
        let pid = notif.pid;
        let sock_fd = notif.data.args[0];
        // Worker-pool admission before any state is retained or a
        // thread spawns — saturation fails closed like any other
        // emulation-unavailable refusal.
        if self.pending.len() >= MAX_EMU_WORKERS {
            self.stats.emulation_denied += 1;
            self.deny(
                id,
                pid,
                "emulation-saturated",
                &format!("{fields} basis={basis} workers={MAX_EMU_WORKERS}"),
                None,
            );
            return;
        }
        let done = match self.done.try_clone() {
            Ok(d) => d,
            Err(e) => {
                self.stats.emulation_denied += 1;
                self.deny(
                    id,
                    pid,
                    "emulation-unavailable",
                    &format!("{fields} basis={basis} dup_error={e}"),
                    None,
                );
                return;
            }
        };
        let tx = self.tx.clone();
        let spawned = std::thread::Builder::new()
            .name("unotify-emulate".to_string())
            .spawn(move || {
                let out = match emulate_connect(pid, sock_fd, &sockaddr) {
                    Ok(errno) => EmuOutcome::Connected { id, errno },
                    Err(e) => EmuOutcome::DupFailed {
                        id,
                        errno: e.raw_os_error(),
                    },
                };
                // A dead channel means the loop is gone — the result
                // is dropped, the worker owns no shared state.
                if tx.send(out).is_ok() {
                    let byte = 1u64.to_ne_bytes();
                    // Safety: `done` is a live eventfd owned by this
                    // thread; 8 bytes is the eventfd write.
                    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
                    unsafe {
                        libc::write(done.as_raw_fd(), byte.as_ptr().cast::<libc::c_void>(), 8)
                    };
                }
            });
        let handle = match spawned {
            Ok(h) => h,
            Err(e) => {
                self.stats.emulation_denied += 1;
                self.deny(
                    id,
                    pid,
                    "emulation-unavailable",
                    &format!("{fields} basis={basis} dup_error={e}"),
                    None,
                );
                return;
            }
        };
        self.pending.insert(
            id,
            PendingEmu {
                pid,
                fields: fields.to_string(),
                basis: basis.to_string(),
                rule: rule.map(str::to_string),
                handle: Some(handle),
            },
        );
    }

    /// Consume one pending emulation: remove its record and join the
    /// worker. The worker already sent its outcome before the loop saw
    /// the eventfd bump, so the join waits only on thread exit.
    fn take_pending(&mut self, id: u64) -> Option<PendingEmu> {
        let mut p = self.pending.remove(&id)?;
        if let Some(h) = p.handle.take() {
            let _ = h.join();
        }
        Some(p)
    }

    /// One worker's emulation outcome — failure classification mirrors
    /// the old synchronous path:
    ///   * `connect` errno (including `EBADF` from a raced-shut fd —
    ///     what a native connect on that fd would report) → returned
    ///     to the child verbatim; the verdict was allow either way.
    ///   * task died before the dup (`ESRCH`/`ENOENT`) → `expired`,
    ///     no response sent — the kernel already released the
    ///     notification, so nothing can reach the syscall.
    ///   * the fd could not be obtained for any other reason
    ///     (`EPERM`, …) → `emulation_denied`, a fail-closed `EACCES` —
    ///     an allowed verdict never silently degrades into an
    ///     unchecked continue.
    ///
    /// `notify_id_valid` re-runs immediately before the emulated
    /// response — the notification may have expired while the worker
    /// was blocked in `connect`.
    ///
    /// The outcome record is committed (`log_committed`) before the
    /// child is answered — the `stage=authorize` commit in `handle`
    /// covered queuing the emulation, and the *result* record must
    /// likewise be durable before a success is reported to the child's
    /// syscall. On commit failure a would-be success answers `EACCES`
    /// instead: the connect already happened, but the child must not
    /// observe success for an unaudited connect.
    /// `emu_errno=N` in details makes a policy-allowed but
    /// kernel-failed connect auditable. The record precedes the
    /// response it describes.
    fn emulated_result(&mut self, out: EmuOutcome) {
        let (id, errno) = match out {
            EmuOutcome::Connected { id, errno } => (id, errno),
            EmuOutcome::DupFailed { id, errno } => match errno {
                Some(libc::ESRCH) | Some(libc::ENOENT) => {
                    // Task died before the dup — the kernel already
                    // released the notification; answering would just
                    // bounce ENOENT back into `send_errors`.
                    self.take_pending(id);
                    self.stats.expired += 1;
                    return;
                }
                Some(libc::EBADF) => (id, libc::EBADF),
                Some(e) => {
                    let Some(p) = self.take_pending(id) else {
                        return;
                    };
                    self.stats.emulation_denied += 1;
                    self.deny(
                        id,
                        p.pid,
                        "emulation-unavailable",
                        &format!("{} basis={} dup_error={e}", p.fields, p.basis),
                        None,
                    );
                    return;
                }
                None => {
                    let Some(p) = self.take_pending(id) else {
                        return;
                    };
                    self.stats.emulation_denied += 1;
                    self.deny(
                        id,
                        p.pid,
                        "emulation-unavailable",
                        &format!("{} basis={} dup_error=io", p.fields, p.basis),
                        None,
                    );
                    return;
                }
            },
        };
        let Some(p) = self.take_pending(id) else {
            return;
        };
        self.stats.emulated += 1;
        let mut event = self.event(
            EventType::SandboxNetworkAllowed,
            Severity::Info,
            Outcome::Success,
            Action::Allowed,
        );
        let mut details = format!(
            "layer=ip {} pid={} stage=established basis={} emu_errno={errno} session_id={}",
            p.fields,
            p.pid,
            p.basis,
            self.logger.session_id()
        );
        if let Some(rule) = p.rule {
            details.push_str(&format!(" rule={rule}"));
        }
        event.details = Some(details);
        // The outcome record must be durable before the child learns
        // the result — a success reported on an unaudited connect is
        // the exact gap the pre-queue `authorize` commit exists to
        // close.
        let committed =
            tokio::runtime::Handle::current().block_on(self.logger.log_committed(event));
        // Revalidate before answering — the notification could have
        // expired while the worker blocked in `connect`.
        if !notify_id_valid(self.listener.as_raw_fd(), id) {
            self.stats.expired += 1;
            return;
        }
        let resp = if errno == 0 && committed.is_ok() {
            notif_resp_result(id, 0)
        } else if committed.is_err() && errno == 0 {
            // The connect succeeded but its outcome record did not —
            // report EACCES, not success, to the child.
            self.stats.audit_unavailable_denied += 1;
            notif_resp_error(id, libc::EACCES)
        } else {
            notif_resp_error(id, errno)
        };
        self.send_err(resp);
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
