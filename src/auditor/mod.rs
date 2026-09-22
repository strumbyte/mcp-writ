pub mod checker;
pub mod proxy;
pub(crate) mod proxy_c2s;
mod proxy_list_state;
pub(crate) mod proxy_s2c;
pub(crate) mod proxy_state;
pub(crate) mod proxy_tools_list;
pub(crate) mod proxy_wire;
pub mod schema_validator;
pub mod session;

use std::sync::Arc;

use crate::error::AuditorError;
use crate::policy::Policy;
use crate::verifier::fail_on::FailOn;

pub struct Auditor {
    policy: Policy,
    dry_run: bool,
    fail_on: FailOn,
    audit_logger: Arc<crate::audit_log::AuditLogger>,
}

impl Auditor {
    pub fn new(policy: Policy, audit_logger: crate::audit_log::AuditLogger) -> Self {
        Self {
            policy,
            dry_run: false,
            fail_on: FailOn::DEFAULT,
            audit_logger: Arc::new(audit_logger),
        }
    }

    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn with_fail_on(mut self, fail_on: FailOn) -> Self {
        self.fail_on = fail_on;
        self
    }

    pub async fn run<W, R>(&self, child_stdin: W, child_stdout: R) -> Result<(), AuditorError>
    where
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
    {
        proxy::run_proxy(
            &self.policy,
            self.dry_run,
            self.fail_on,
            self.audit_logger.clone(),
            child_stdin,
            child_stdout,
        )
        .await
    }
}
