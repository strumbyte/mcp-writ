//! `LaunchReport.code_identity` assembly: which hash pins bind which part
//! of the launched workload, the points in the launch sequence where each
//! pin's check ran, and what stays mutable afterward. The record keeps
//! "hash-bound" from reading as "every byte of code the workload will run
//! is fixed" — see `docs/guide.md` for the reported scope contract.

use std::path::{Path, PathBuf};

use crate::enforcement::{CodeIdentity, IdentityKind, IdentityPin, PinCheck, PinRole};
use crate::policy::{HashEntry, HashType};
use crate::verifier::hash::VerifyError;
use crate::workload::{
    CommandNames, DelegatingLauncher, InterpreterKind, argv_contains_inline_eval_with_exe,
    first_payload_arg_with_exe, image_repository, interpreter_from_command, is_cmd_command,
    is_perl_command, is_powershell_command, is_ruby_command, is_shell_command,
    node_preload_flags_present_with_exe, payload_is_module_with_exe, repos_match, same_file,
    shebang_line,
};

/// How far a native launch's identity pipeline ran — the `pins[].checks`
/// lists derive from the marked stages, ordered so `Bound` implies every
/// earlier stage completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    /// `argv[0]` resolution finished (or failed); no hash check ran.
    Resolved,
    /// `verify_server_hashes` completed — per-pin truth lives in
    /// `initial`, so a mid-list failure still records honestly.
    Verified,
    /// `bind_launched_workload` passed — path correspondence plus the
    /// content re-hash ran for the exec/payload pins.
    Bound,
    /// `reverify_immediately_before_spawn` passed — the same binding
    /// checks re-ran immediately before spawn.
    Reverified,
}

/// Progressive builder for a native `run` launch's [`CodeIdentity`].
/// Create it before `argv[0]` resolution, mark the pipeline stages as
/// they complete, and [`finish`](Self::finish) into the report at every
/// outcome — including each failure path.
pub struct LaunchIdentity<'a> {
    argv: &'a [String],
    entries: &'a [HashEntry],
    /// Per-entry `initial` outcome, order-aligned with `entries`.
    initial: Vec<bool>,
    stage: Stage,
    resolved: Option<PathBuf>,
}

impl<'a> LaunchIdentity<'a> {
    /// Build the record for a native `run` launch from the caller-spelled
    /// argv and the bound policy's hash entries.
    pub fn for_launch(argv: &'a [String], hash_entries: &'a [HashEntry]) -> Self {
        Self {
            argv,
            entries: hash_entries,
            initial: vec![false; hash_entries.len()],
            stage: Stage::Resolved,
            resolved: None,
        }
    }

    /// Record the resolved `argv[0]` — fills `resolved`.
    pub fn set_resolved(&mut self, exe: &Path) {
        self.resolved = Some(exe.to_path_buf());
    }

    /// `verify_server_hashes` passed for `server` — every entry naming it
    /// earned the `initial` check.
    pub fn mark_server_verified(&mut self, server: &str) {
        for (i, e) in self.entries.iter().enumerate() {
            if e.server_name == server {
                self.initial[i] = true;
            }
        }
        if self.initial.iter().all(|x| *x) {
            self.stage = self.stage.max(Stage::Verified);
        }
    }

    /// `verify_server_hashes` failed for `server`; its entries verified
    /// before the failing one keep `initial` — `VerifyError` names the
    /// failing `(hash_type, target)` pair.
    pub fn mark_server_failed(&mut self, server: &str, err: &VerifyError) {
        // `verify_server_hashes` fails per entry — `Mismatch`/`FileError`
        // name the failing `(hash_type, target)`. `UnboundWorkload` is a
        // `bind_launched_workload` error, never produced here; it names
        // no entry, so nothing is claimed verified on it.
        let Some((failed_type, failed_target)) = (match err {
            VerifyError::Mismatch {
                hash_type, target, ..
            }
            | VerifyError::FileError {
                hash_type, target, ..
            } => Some((*hash_type, target.as_str())),
            VerifyError::UnboundWorkload { .. } => None,
        }) else {
            return;
        };
        let mut reached_failure = false;
        for (i, e) in self.entries.iter().enumerate() {
            if e.server_name != server || reached_failure {
                continue;
            }
            if e.hash_type == failed_type && e.target == failed_target {
                reached_failure = true;
            } else {
                self.initial[i] = true;
            }
        }
    }

    /// `bind_launched_workload` passed — exec/payload pins earned the
    /// `bind_path` and `bind_content` checks.
    pub fn mark_bound(&mut self) {
        self.stage = self.stage.max(Stage::Bound);
    }

    /// `reverify_immediately_before_spawn` passed — exec/payload pins
    /// earned the `pre_spawn_path` and `pre_spawn_content` checks.
    pub fn mark_reverified(&mut self) {
        self.stage = self.stage.max(Stage::Reverified);
    }

    /// The record as the report carries it — `pins[].checks` lists only
    /// the check points that ran and passed, in launch order.
    pub fn finish(&self) -> CodeIdentity {
        let kind = launch_kind(self.argv, self.resolved.as_deref());
        let pins: Vec<IdentityPin> = self
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let mut checks = Vec::new();
                if self.initial[i] {
                    checks.push(PinCheck::Initial);
                }
                // The binding rule is re-evaluated per pin: `bind_launched_workload`
                // skips a `binary-hash` whose target is not the resolved exe,
                // so such a pin verified content at `initial` but bound
                // nothing — it must not claim the bind/pre-spawn points.
                let bound = self.binds_launch(e);
                if bound && self.stage >= Stage::Bound {
                    checks.push(PinCheck::BindPath);
                    checks.push(PinCheck::BindContent);
                }
                if bound && self.stage >= Stage::Reverified {
                    checks.push(PinCheck::PreSpawnPath);
                    checks.push(PinCheck::PreSpawnContent);
                }
                IdentityPin {
                    hash_type: e.hash_type.as_str(),
                    target: e.target.clone(),
                    hash: e.hash_value.clone(),
                    role: pin_role(e),
                    checks,
                }
            })
            .collect();
        let (pinned, mutable) =
            launch_notes(kind, self.argv, self.entries, self.resolved.as_deref());
        CodeIdentity {
            kind,
            resolved: self.resolved.as_ref().map(|p| p.display().to_string()),
            pins,
            pinned,
            mutable,
        }
    }

    /// Whether `bind_launched_workload`'s binding covered `entry` — the
    /// same correspondence rule re-evaluated per pin: the target
    /// canonicalizes to the resolved executable, or (for
    /// `entrypoint-hash`) to the first payload argument. A `binary-hash`
    /// naming some other file was skipped by the binding loop, so it
    /// never earned the `bind_*`/`pre_spawn_*` points.
    fn binds_launch(&self, entry: &HashEntry) -> bool {
        if !matches!(entry.hash_type, HashType::Binary | HashType::Entrypoint) {
            return false;
        }
        let Some(exe) = self.resolved.as_deref() else {
            return false;
        };
        let target = Path::new(&entry.target);
        same_file(target, exe)
            || (entry.hash_type == HashType::Entrypoint
                && first_payload_arg_with_exe(self.argv, Some(exe))
                    .is_some_and(|arg| same_file(Path::new(arg), target)))
    }
}

/// The launch shape the record describes — see [`IdentityKind`]. The
/// resolved executable's file name classifies alongside `argv[0]`: a
/// renamed alias (`worker` → `python3.12`) still names the interpreter
/// family of the image the kernel execs.
fn launch_kind(argv: &[String], resolved: Option<&Path>) -> IdentityKind {
    if argv.is_empty() {
        return IdentityKind::NativeFile;
    }
    if argv_contains_inline_eval_with_exe(argv, resolved) {
        return IdentityKind::InlineEval;
    }
    let names = CommandNames::new(argv.first().map(String::as_str).unwrap_or(""), resolved);
    let interpreter = names.interpreter();
    // `npx` resolves the package and runtime at run time — its payload
    // token names a package, never a hash-bindable file.
    if matches!(interpreter, Some(InterpreterKind::Npx)) {
        return IdentityKind::LauncherOrModule;
    }
    let modeled = names.any_is(|s| {
        interpreter_from_command(s).is_some()
            || is_perl_command(s)
            || is_ruby_command(s)
            || is_shell_command(s)
            || is_powershell_command(s)
            || is_cmd_command(s)
    });
    if modeled {
        // `-m`-style module/exec spellings are a payload but not a file —
        // only the modeled Python/Node/Npx grammar reads `-m` that way.
        if interpreter.is_some() && payload_is_module_with_exe(argv, resolved) {
            return IdentityKind::LauncherOrModule;
        }
        return match first_payload_arg_with_exe(argv, resolved) {
            Some(_) => IdentityKind::InterpretedScript,
            None => IdentityKind::LauncherOrModule,
        };
    }
    if names.delegating_launcher().is_some() {
        return IdentityKind::LauncherOrModule;
    }
    IdentityKind::NativeFile
}

fn pin_role(entry: &HashEntry) -> PinRole {
    match entry.hash_type {
        HashType::Binary => PinRole::ExecImage,
        HashType::Entrypoint => PinRole::PayloadFile,
        HashType::Lockfile => PinRole::DependencyList,
        HashType::DockerManifest => PinRole::ImageManifest,
    }
}

/// The `pinned`/`mutable` scope statements for a native launch —
/// written as facts about this launch's pins, not generic caveats.
fn launch_notes(
    kind: IdentityKind,
    argv: &[String],
    entries: &[HashEntry],
    resolved: Option<&Path>,
) -> (Vec<String>, Vec<String>) {
    let mut pinned = Vec::new();
    let mut mutable = Vec::new();
    let argv0 = argv.first().map(String::as_str).unwrap_or("");
    let has_identity = entries
        .iter()
        .any(|e| matches!(e.hash_type, HashType::Binary | HashType::Entrypoint));
    let has_lockfile = entries.iter().any(|e| e.hash_type == HashType::Lockfile);
    let has_docker = entries
        .iter()
        .any(|e| e.hash_type == HashType::DockerManifest);

    if entries.is_empty() {
        mutable.push(
            "no hash entries configured — the launched code is not integrity-pinned".to_string(),
        );
        return (pinned, mutable);
    }
    if has_identity {
        match kind {
            IdentityKind::NativeFile => pinned.push(
                "the spawned process image — the resolved argv[0] file's content".to_string(),
            ),
            IdentityKind::InterpretedScript => pinned.push(
                "the interpreter image (resolved argv[0]) and each payload_file pin's \
                 script content"
                    .to_string(),
            ),
            IdentityKind::LauncherOrModule => pinned.push(
                "only the resolved argv[0] image — the workload the launcher or module \
                 name selects at run time is not bound"
                    .to_string(),
            ),
            IdentityKind::InlineEval => pinned.push(
                "only the resolved argv[0] image — the evaluated payload is argv text, \
                 never a bindable file"
                    .to_string(),
            ),
            IdentityKind::ImageDigest | IdentityKind::ImageTag => {}
        }
        mutable.push(
            "the pinned files are re-hashed at binding and again immediately before spawn; \
             nothing holds them immutable between that last check and exec — a filesystem \
             swap inside the window is not detected"
                .to_string(),
        );
    } else {
        mutable.push(
            "no binary-hash/entrypoint-hash entries — the launched process cannot be bound; \
             `run` fails closed"
                .to_string(),
        );
    }
    match kind {
        IdentityKind::NativeFile => {
            if resolved.is_some_and(|p| shebang_line(p).is_some()) {
                mutable.push(
                    "the spawned file starts with a '#!' shebang — the kernel selects \
                     that interpreter at run time; it is not pinned"
                        .to_string(),
                );
            }
            mutable.push(
                "code the workload loads at run time — shared libraries, plugins, \
                 fetched or generated code — is outside the pinned files"
                    .to_string(),
            );
        }
        IdentityKind::InterpretedScript => {
            if !entries.iter().any(|e| e.hash_type == HashType::Entrypoint) {
                mutable.push(
                    "the payload script has no entrypoint-hash pin — only the \
                     interpreter image is bound"
                        .to_string(),
                );
            }
            mutable.push(
                "modules the payload loads at run time (imports, native extensions) \
                 are outside the pinned files"
                    .to_string(),
            );
            if node_preload_flags_present_with_exe(argv, resolved) {
                mutable.push(
                    "Node preload flags (-r/--require/--import/--loader) load modules \
                     outside the pinned scope"
                        .to_string(),
                );
            }
            if let Some((DelegatingLauncher::PythonSelector, stem)) =
                CommandNames::new(argv0, resolved).delegating_launcher()
            {
                mutable.push(format!(
                    "the '{stem}' launcher selects the interpreter at run time — the \
                     selected interpreter is not pinned"
                ));
            }
        }
        IdentityKind::LauncherOrModule => {
            mutable.push(
                "the selected workload — a module, delegated command, package, or \
                 stdin payload — has no file pin"
                    .to_string(),
            );
        }
        IdentityKind::InlineEval => {
            mutable.push(
                "the evaluated payload is argv text — never a hash-bindable file; \
                 a policy with hash entries refuses this launch at binding"
                    .to_string(),
            );
        }
        IdentityKind::ImageDigest | IdentityKind::ImageTag => {}
    }
    if has_lockfile {
        mutable.push(
            "lockfile-hash pins cover the manifest's own content — the dependencies \
             it names are not verified"
                .to_string(),
        );
    }
    if has_docker {
        mutable.push(
            "docker-manifest-hash entries are image pins — on a native launch the \
             target is hashed as a file; they do not bind the process"
                .to_string(),
        );
    }
    (pinned, mutable)
}

/// Build the [`CodeIdentity`] for a `run-image` container launch.
/// `digest_pinned` is [`crate::container::runner`]'s
/// `image_ref_is_digest_pinned` verdict; `hash_entries` is the bound
/// policy's entry list — `None` before the policy binds, so an early
/// failure record does not claim pins it never saw; `inspected_digest`
/// is the image's manifest digest once `inspect` produced it (`None`
/// before). A pin earns `image_inspect` only when its own digest matched
/// *and* its `target` names the launched image's repository — the
/// enforcement check is an `any` over the pins, so a sibling pin's match
/// (or a pin for a different image) must not rub off on this one.
/// `allow_mutable_tag` keeps the `mutable` note honest on a launch
/// refused at the image-reference check.
pub fn for_image(
    image: &str,
    digest_pinned: bool,
    hash_entries: Option<&[HashEntry]>,
    inspected_digest: Option<&str>,
    allow_mutable_tag: bool,
) -> CodeIdentity {
    let kind = if digest_pinned {
        IdentityKind::ImageDigest
    } else {
        IdentityKind::ImageTag
    };
    let image_repo = image_repository(image);
    let pins: Vec<IdentityPin> = hash_entries
        .unwrap_or(&[])
        .iter()
        .filter(|e| e.hash_type == HashType::DockerManifest)
        .map(|e| {
            let inspected = inspected_digest.is_some_and(|d| d == e.hash_value)
                && repos_match(&image_repository(&e.target), &image_repo);
            IdentityPin {
                hash_type: e.hash_type.as_str(),
                target: e.target.clone(),
                hash: e.hash_value.clone(),
                role: PinRole::ImageManifest,
                checks: if inspected {
                    vec![PinCheck::ImageInspect]
                } else {
                    Vec::new()
                },
            }
        })
        .collect();

    let mut pinned = Vec::new();
    let mut mutable = Vec::new();
    if digest_pinned || !pins.is_empty() {
        pinned.push(
            "the image manifest digest — every file inside the image, interpreter \
             and baked-in dependencies included"
                .to_string(),
        );
    }
    if !digest_pinned {
        mutable.push(if allow_mutable_tag {
            "the image tag is mutable — --allow-mutable-tag accepted it; re-pointing \
             the tag between inspect and run is not detected"
                .to_string()
        } else {
            "the image tag is mutable and --allow-mutable-tag was not given — the \
             launch is refused at the image-reference check"
                .to_string()
        });
    }
    match hash_entries {
        Some(_) if pins.is_empty() => mutable.push(
            "no docker-manifest-hash pins — the image reference is the only identity \
             anchor"
                .to_string(),
        ),
        None => mutable.push(
            "the run stopped before the policy's docker-manifest-hash pins were known".to_string(),
        ),
        _ => {}
    }
    mutable.push(
        "host bind mounts — the policy, log dir, and guest report channel — are \
         outside the image"
            .to_string(),
    );
    mutable.push(
        "the container's writable layer and anything the workload fetches or \
         generates after start are not pinned"
            .to_string(),
    );
    mutable.push("the guest kernel and container engine are outside the pinned scope".to_string());
    let file_pins = hash_entries.unwrap_or(&[]).iter().any(|e| {
        matches!(
            e.hash_type,
            HashType::Binary | HashType::Entrypoint | HashType::Lockfile
        )
    });
    if file_pins {
        mutable.push(
            "binary-hash/entrypoint-hash/lockfile-hash entries are verified by \
             mcp-secure-runner inside the guest at workload launch — see the \
             attached guest report's code_identity"
                .to_string(),
        );
    }
    CodeIdentity {
        kind,
        resolved: Some(image.to_string()),
        pins,
        pinned,
        mutable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(server: &str, hash_type: HashType, target: &str) -> HashEntry {
        entry_with_hash(
            server,
            hash_type,
            target,
            &format!("sha256:{}", "0".repeat(64)),
        )
    }

    fn entry_with_hash(
        server: &str,
        hash_type: HashType,
        target: &str,
        hash_value: &str,
    ) -> HashEntry {
        HashEntry {
            server_name: server.to_string(),
            hash_type,
            hash_value: hash_value.to_string(),
            target: target.to_string(),
            approved: None,
        }
    }

    fn argv(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn kind_distinguishes_launch_shapes() {
        assert_eq!(
            launch_kind(&argv(&["/usr/bin/server", "--flag"]), None),
            IdentityKind::NativeFile
        );
        assert_eq!(
            launch_kind(&argv(&["python3", "server.py"]), None),
            IdentityKind::InterpretedScript
        );
        assert_eq!(
            launch_kind(&argv(&["pwsh", "-File", "run.ps1"]), None),
            IdentityKind::InterpretedScript
        );
        assert_eq!(
            launch_kind(&argv(&["python3", "-m", "http.server"]), None),
            IdentityKind::LauncherOrModule
        );
        assert_eq!(
            launch_kind(&argv(&["npx", "some-pkg"]), None),
            IdentityKind::LauncherOrModule
        );
        assert_eq!(
            launch_kind(&argv(&["env", "X=1", "python3", "s.py"]), None),
            IdentityKind::LauncherOrModule
        );
        assert_eq!(
            launch_kind(&argv(&["python3"]), None),
            IdentityKind::LauncherOrModule
        );
        assert_eq!(
            launch_kind(&argv(&["python3", "-c", "print(1)"]), None),
            IdentityKind::InlineEval
        );
        assert_eq!(
            launch_kind(&argv(&["pwsh", "-Command", "Get-Process"]), None),
            IdentityKind::InlineEval
        );
    }

    #[test]
    fn kind_reads_the_resolved_spelling() {
        // `worker` is uninformative as argv[0], but the resolved image
        // names the interpreter family — eval flags still classify.
        let resolved = Path::new("/usr/bin/python3.12");
        assert_eq!(
            launch_kind(&argv(&["worker", "server.py"]), Some(resolved)),
            IdentityKind::InterpretedScript
        );
        assert_eq!(
            launch_kind(&argv(&["worker", "-c", "print(1)"]), Some(resolved)),
            IdentityKind::InlineEval
        );
        // A shell grammar applies too when either spelling names one:
        // `worker -c x` resolved to bash still classifies as eval.
        assert_eq!(
            launch_kind(
                &argv(&["worker", "-c", "echo hi"]),
                Some(Path::new("/bin/bash"))
            ),
            IdentityKind::InlineEval
        );
    }

    #[test]
    fn checks_list_only_the_points_that_passed() {
        let entries = vec![
            entry("s", HashType::Binary, "/usr/bin/python3"),
            entry("s", HashType::Entrypoint, "/srv/server.py"),
            entry("s", HashType::Lockfile, "/srv/requirements.txt"),
        ];
        // The payload arg spells the pinned script identically so
        // `same_file`'s string fallback binds it without real files.
        let launch_argv = argv(&["python3", "/srv/server.py"]);
        let mut rec = LaunchIdentity::for_launch(&launch_argv, &entries);
        rec.set_resolved(Path::new("/usr/bin/python3"));

        // Before anything ran, no pin earned a check.
        let ident = rec.finish();
        assert!(ident.pins.iter().all(|p| p.checks.is_empty()));

        rec.mark_server_verified("s");
        let ident = rec.finish();
        assert_eq!(ident.pins[0].checks, [PinCheck::Initial]);
        assert_eq!(ident.pins[2].checks, [PinCheck::Initial]);

        rec.mark_bound();
        let ident = rec.finish();
        // Lockfile entries verify content only — no bind/spawn checks.
        assert_eq!(ident.pins[2].checks, [PinCheck::Initial]);
        assert_eq!(
            ident.pins[1].checks,
            [PinCheck::Initial, PinCheck::BindPath, PinCheck::BindContent]
        );

        rec.mark_reverified();
        let ident = rec.finish();
        assert_eq!(
            ident.pins[0].checks,
            [
                PinCheck::Initial,
                PinCheck::BindPath,
                PinCheck::BindContent,
                PinCheck::PreSpawnPath,
                PinCheck::PreSpawnContent
            ]
        );
        assert_eq!(ident.pins[2].checks, [PinCheck::Initial]);
    }

    #[test]
    fn failed_initial_verification_marks_only_verified_prefix() {
        let entries = vec![
            entry("s", HashType::Binary, "/usr/bin/python3"),
            entry("s", HashType::Entrypoint, "/srv/server.py"),
            entry("s", HashType::Lockfile, "/srv/requirements.txt"),
        ];
        let launch_argv = argv(&["python3", "server.py"]);
        let mut rec = LaunchIdentity::for_launch(&launch_argv, &entries);
        rec.mark_server_failed(
            "s",
            &VerifyError::Mismatch {
                hash_type: HashType::Entrypoint,
                target: "/srv/server.py".to_string(),
                expected: "sha256:a".into(),
                actual: "sha256:b".into(),
            },
        );
        let ident = rec.finish();
        // The entrypoint target failed; the lockfile after it never ran.
        assert_eq!(ident.pins[0].checks, [PinCheck::Initial]);
        assert!(ident.pins[1].checks.is_empty());
        assert!(ident.pins[2].checks.is_empty());
    }

    #[test]
    fn scope_notes_stay_honest_about_mutability() {
        let entries = vec![
            entry("s", HashType::Binary, "/usr/bin/python3"),
            entry("s", HashType::Entrypoint, "/srv/server.py"),
        ];
        let launch_argv = argv(&["python3", "server.py"]);
        let rec = LaunchIdentity::for_launch(&launch_argv, &entries);
        let ident = rec.finish();
        assert!(
            ident
                .mutable
                .iter()
                .any(|m| m.contains("nothing holds them immutable")),
            "the residual hash-to-exec window must be stated"
        );
        assert!(
            ident.pinned.iter().any(|p| p.contains("script content")),
            "a separate script's pinned scope must be named"
        );

        // Unpinned policy: nothing to claim.
        let launch_argv = argv(&["./server"]);
        let rec = LaunchIdentity::for_launch(&launch_argv, &[]);
        let ident = rec.finish();
        assert!(ident.pins.is_empty() && ident.pinned.is_empty());
        assert!(ident.mutable.iter().any(|m| m.contains("no hash entries")));
    }

    #[test]
    fn image_record_distinguishes_digest_pin_from_mutable_tag() {
        let entries = vec![entry(
            "s",
            HashType::DockerManifest,
            "registry.example/app@sha256:abc",
        )];
        let pinned = for_image(
            "registry.example/app@sha256:abc",
            true,
            Some(&entries),
            Some(&entries[0].hash_value),
            false,
        );
        assert_eq!(pinned.kind, IdentityKind::ImageDigest);
        assert_eq!(pinned.pins[0].checks, [PinCheck::ImageInspect]);
        assert!(pinned.pinned.iter().any(|p| p.contains("manifest digest")));

        let tagged = for_image(
            "registry.example/app:latest",
            false,
            Some(&entries),
            Some("sha256:does-not-match"),
            true,
        );
        assert_eq!(tagged.kind, IdentityKind::ImageTag);
        assert!(tagged.pins[0].checks.is_empty());
        assert!(
            tagged.mutable.iter().any(|m| m.contains("mutable")),
            "a mutable tag must stay visibly unpinned"
        );
    }

    #[test]
    fn image_inspect_marks_only_the_pin_whose_own_digest_matched() {
        // The enforcement check is an `any` over the docker-manifest
        // pins — a sibling pin's match must not mark every pin.
        let entries = vec![
            entry_with_hash(
                "s",
                HashType::DockerManifest,
                "registry.example/app@sha256:aaa",
                "sha256:aaa",
            ),
            entry_with_hash(
                "s",
                HashType::DockerManifest,
                "registry.example/side@sha256:bbb",
                "sha256:bbb",
            ),
        ];
        let ident = for_image(
            "registry.example/app@sha256:aaa",
            true,
            Some(&entries),
            Some("sha256:aaa"),
            false,
        );
        assert_eq!(ident.pins[0].checks, [PinCheck::ImageInspect]);
        assert!(
            ident.pins[1].checks.is_empty(),
            "a pin whose digest did not match must not claim image_inspect"
        );

        // A digest equal to the inspected one but pinned on a different
        // repository is not this image's pin.
        let entries = vec![entry_with_hash(
            "s",
            HashType::DockerManifest,
            "registry.example/other@sha256:aaa",
            "sha256:aaa",
        )];
        let ident = for_image(
            "registry.example/app@sha256:aaa",
            true,
            Some(&entries),
            Some("sha256:aaa"),
            false,
        );
        assert!(
            ident.pins[0].checks.is_empty(),
            "a pin naming a different repository was not this image's check"
        );
    }

    #[test]
    fn refused_mutable_tag_does_not_claim_acceptance() {
        let ident = for_image("registry.example/app:latest", false, None, None, false);
        assert!(
            ident.mutable.iter().any(|m| m.contains("refused")),
            "a refused tag launch must not say --allow-mutable-tag accepted it"
        );
        assert!(!ident.mutable.iter().any(|m| m.contains("accepted")));
    }

    #[test]
    fn bind_checks_stay_off_a_binary_pin_that_does_not_name_the_exe() {
        // A `binary-hash` entry whose target is not the resolved exe is
        // skipped by `bind_launched_workload` — its content verified at
        // `initial`, but it bound nothing.
        let entries = vec![
            entry("s", HashType::Binary, "/usr/bin/python3"),
            entry("s", HashType::Binary, "/opt/other/tool"),
            entry("s", HashType::Entrypoint, "/srv/server.py"),
        ];
        let launch_argv = argv(&["python3", "/srv/server.py"]);
        let mut rec = LaunchIdentity::for_launch(&launch_argv, &entries);
        rec.set_resolved(Path::new("/usr/bin/python3"));
        rec.mark_server_verified("s");
        rec.mark_bound();
        rec.mark_reverified();
        let ident = rec.finish();
        assert_eq!(
            ident.pins[1].checks,
            [PinCheck::Initial],
            "a binary-hash naming a different file bound nothing"
        );
        assert_eq!(ident.pins[0].checks.len(), 5);
        assert_eq!(ident.pins[2].checks.len(), 5);
    }

    #[test]
    fn unbound_workload_error_marks_no_pins_verified() {
        // `UnboundWorkload` names no entry — it is a bind error, not a
        // per-entry verify failure — so it must not mark initials.
        let entries = vec![entry("s", HashType::Binary, "/usr/bin/python3")];
        let launch_argv = argv(&["python3", "/srv/server.py"]);
        let mut rec = LaunchIdentity::for_launch(&launch_argv, &entries);
        rec.mark_server_failed(
            "s",
            &VerifyError::UnboundWorkload {
                executable: "/usr/bin/python3".to_string(),
                reason: "no binary-hash target canonicalizes".to_string(),
            },
        );
        let ident = rec.finish();
        assert!(ident.pins[0].checks.is_empty());
    }
}
