//! Spawn-time pinning for verified workload objects: hold the hashed
//! executable — and any payload-matched entrypoint script — open through
//! process creation so the launched object is the verified one. A
//! *native* image execs an immutable snapshot of the pinned bytes; an
//! interpreted payload launches through its real path — an interpreter
//! resolves its main module and its imports relative to that path, which
//! a snapshot spelling cannot carry — and the held pin's last-moment
//! re-check is the exec-time guarantee there.

mod anchor;
mod bind;
#[cfg(unix)]
mod plan;
mod spawn;
mod stamp;
mod workload;

#[cfg(test)]
pub(crate) use anchor::open_pinned;
pub use bind::bind_launched_workload;
#[cfg(unix)]
pub use plan::FdExecPlan;
// Linux exports it for `warden::select`'s masked-tree screen (PR-05)
// — the only production consumer, itself Linux-gated; a wider Unix
// scope would be an unused import there. Windows keeps it test-only.
#[cfg(any(target_os = "linux", all(test, windows)))]
pub(crate) use spawn::simplify_verbatim;
pub use spawn::{SpawnPin, reverify_immediately_before_spawn};
#[cfg(all(unix, test))]
pub(crate) use stamp::FileStamp;
#[cfg(all(target_os = "linux", test))]
pub(crate) use stamp::ftype_owns_ctime;
pub use workload::VerifiedWorkload;
