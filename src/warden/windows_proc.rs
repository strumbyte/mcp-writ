//! Process creation inside an AppContainer profile.
//!
//! Owns the Win32 spawn pipeline for [`AppContainerSandbox`]: anonymous
//! pipes, handle inheritance, `CreateProcessW` with proc-thread attributes,
//! the kill-on-close Job object, and [`WindowsChild`] (wait / kill / id /
//! Drop). The call order is fixed: pipes → attribute list → `CREATE_SUSPENDED`
//! → Job assign → `ResumeThread`.

use std::ffi::c_void;

use windows::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT,
    SetHandleInformation, WAIT_FAILED,
};
use windows::Win32::Security::SECURITY_CAPABILITIES;
use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess, GetProcessId, INFINITE,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    ResumeThread, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};

use crate::error::WardenError;

use super::SpawnOptions;
use super::windows_env::encode_windows_env_block;
use super::windows_profile::AppContainerSandbox;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = ProcThreadAttributeValue(9, FALSE, TRUE, FALSE)
/// = 9 | 0x20000 = 0x20009
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;

/// PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY
/// = ProcThreadAttributeValue(15, FALSE, TRUE, FALSE) = 15 | 0x20000 = 0x2000F
const PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: usize = 0x0002_000F;

/// Opt out of ALL_APPLICATION_PACKAGES group (enables LPAC).
const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 0x0000_0001;

/// PROC_THREAD_ATTRIBUTE_HANDLE_LIST = ProcThreadAttributeValue(2, FALSE, TRUE, FALSE)
/// = 2 | 0x20000 = 0x20002
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;

/// Closes pipe handles and an initialized attribute list unless ownership
/// has been transferred to a successful `WindowsChild`.
struct SpawnCleanup {
    stdin_read: Option<HANDLE>,
    stdin_write: Option<HANDLE>,
    stdout_read: Option<HANDLE>,
    stdout_write: Option<HANDLE>,
    stderr_dup: Option<HANDLE>,
    /// Backing buffer of the initialized `LPPROC_THREAD_ATTRIBUTE_LIST`.
    /// Owned by the guard so `DeleteProcThreadAttributeList` always runs
    /// while the buffer is still alive, regardless of drop order.
    attr_list_buf: Option<Vec<u8>>,
}

impl SpawnCleanup {
    /// Delete the initialized attribute list while its backing buffer is
    /// still alive.
    fn delete_attr_list(&mut self) {
        if let Some(mut buf) = self.attr_list_buf.take() {
            unsafe {
                DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST(
                    buf.as_mut_ptr().cast(),
                ));
            }
        }
    }
}

impl Drop for SpawnCleanup {
    fn drop(&mut self) {
        self.delete_attr_list();
        unsafe {
            for handle in [
                self.stdin_read.take(),
                self.stdin_write.take(),
                self.stdout_read.take(),
                self.stdout_write.take(),
                self.stderr_dup.take(),
            ]
            .into_iter()
            .flatten()
            {
                let _ = CloseHandle(handle);
            }
        }
    }
}

impl AppContainerSandbox {
    /// Spawn a process inside this AppContainer sandbox.
    ///
    /// The child process inherits the sandbox constraints. stdin/stdout are
    /// piped for JSON-RPC interception; stderr is inherited for diagnostics.
    pub(super) fn spawn(
        &self,
        command: &str,
        args: &[String],
        opts: &SpawnOptions,
    ) -> Result<WindowsChild, WardenError> {
        // Build the command line (Windows requires a single string)
        let mut cmdline = build_command_line(command, args);

        // Build SECURITY_CAPABILITIES
        let mut cap_attrs = Vec::new();
        let sec_caps = self.build_security_capabilities(&mut cap_attrs);

        // Create pipes first so PROC_THREAD_ATTRIBUTE_HANDLE_LIST can name them.
        let (stdin_read, stdin_write) = create_pipe()?;
        let mut cleanup = SpawnCleanup {
            stdin_read: Some(stdin_read),
            stdin_write: Some(stdin_write),
            stdout_read: None,
            stdout_write: None,
            stderr_dup: None,
            attr_list_buf: None,
        };
        let (stdout_read, stdout_write) = create_pipe()?;
        cleanup.stdout_read = Some(stdout_read);
        cleanup.stdout_write = Some(stdout_write);
        set_handle_inheritable(stdin_read)?;
        set_handle_inheritable(stdout_write)?;
        let stderr_dup = match unsafe { GetStdHandle(STD_ERROR_HANDLE) } {
            Ok(h) if !h.is_invalid() && h != HANDLE::default() => {
                let mut dup = HANDLE::default();
                let current = unsafe { GetCurrentProcess() };
                match unsafe {
                    DuplicateHandle(
                        current,
                        h,
                        current,
                        &mut dup,
                        0,
                        true,
                        DUPLICATE_SAME_ACCESS,
                    )
                } {
                    Ok(()) => Some(dup),
                    Err(e) => {
                        tracing::warn!(
                            "DuplicateHandle for stderr failed: {e}; child stderr will be unavailable"
                        );
                        None
                    }
                }
            }
            Ok(_) => None,
            Err(e) => {
                tracing::warn!(
                    "GetStdHandle(STD_ERROR_HANDLE) failed: {e}; child stderr will be unavailable"
                );
                None
            }
        };
        cleanup.stderr_dup = stderr_dup;

        // Number of proc thread attributes: security caps + optional LPAC + handle list
        let attr_count = if self.is_lpac { 3u32 } else { 2u32 };

        // Initialize proc thread attribute list
        let mut attr_list_size: usize = 0;

        // First call: get required size
        // Safety: InitializeProcThreadAttributeList with null buffer returns the
        // required size in attr_list_size. Expected to fail with ERROR_INSUFFICIENT_BUFFER.
        unsafe {
            let _ =
                InitializeProcThreadAttributeList(None, attr_count, Some(0), &mut attr_list_size);
        }

        let mut attr_list_buf = vec![0u8; attr_list_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buf.as_mut_ptr().cast());

        // Second call: initialize with our buffer
        // Safety: buffer is large enough (we got the size from the first call).
        unsafe {
            InitializeProcThreadAttributeList(
                Some(attr_list),
                attr_count,
                Some(0),
                &mut attr_list_size,
            )
            .map_err(|e| {
                WardenError::SandboxSetup(format!("InitializeProcThreadAttributeList: {e}"))
            })?;
        }
        // The Vec move into the guard does not relocate the heap buffer, so
        // `attr_list` remains valid; ownership ensures the buffer outlives
        // every DeleteProcThreadAttributeList call.
        cleanup.attr_list_buf = Some(attr_list_buf);

        // Add SECURITY_CAPABILITIES attribute
        // Safety: sec_caps is valid for the duration of this function.
        // The attribute list takes a pointer; the pointed-to data must remain valid
        // until CreateProcessW returns.
        unsafe {
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                Some(&sec_caps as *const _ as *const c_void),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                None,
                None,
            )
            .map_err(|e| {
                WardenError::SandboxSetup(format!("UpdateProcThreadAttribute (security caps): {e}"))
            })?;
        }

        // If LPAC, add ALL_APPLICATION_PACKAGES opt-out policy
        let lpac_policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        if self.is_lpac {
            // Safety: lpac_policy is valid for the duration of this function.
            unsafe {
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                    Some(&lpac_policy as *const u32 as *const c_void),
                    std::mem::size_of::<u32>(),
                    None,
                    None,
                )
                .map_err(|e| {
                    WardenError::SandboxSetup(format!(
                        "UpdateProcThreadAttribute(ALL_APPLICATION_PACKAGES_POLICY): {e}"
                    ))
                })?;
            }
        }

        let mut inherit_handles: Vec<HANDLE> = vec![stdin_read, stdout_write];
        if let Some(h) = stderr_dup {
            inherit_handles.push(h);
        }
        unsafe {
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                Some(inherit_handles.as_ptr() as *const c_void),
                inherit_handles.len() * std::mem::size_of::<HANDLE>(),
                None,
                None,
            )
            .map_err(|e| {
                WardenError::SandboxSetup(format!("UpdateProcThreadAttribute(HANDLE_LIST): {e}"))
            })?;
        }

        // Set up STARTUPINFOEXW with piped handles
        let mut si_ex = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                ..Default::default()
            },
            lpAttributeList: attr_list,
        };

        si_ex.StartupInfo.hStdInput = stdin_read;
        si_ex.StartupInfo.hStdOutput = stdout_write;
        si_ex.StartupInfo.dwFlags = windows::Win32::System::Threading::STARTF_USESTDHANDLES;
        if let Some(h) = stderr_dup {
            si_ex.StartupInfo.hStdError = h;
            tracing::debug!("stderr handle duplicated for sandboxed child");
        } else {
            tracing::debug!("no stderr handle available; child stderr will be closed");
        }

        let mut pi = PROCESS_INFORMATION::default();
        let env_block = encode_windows_env_block(opts);
        let env_ptr = env_block
            .as_ref()
            .map(|block| block.as_ptr() as *const c_void);
        let mut create_flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED;
        if env_block.is_some() {
            create_flags |= CREATE_UNICODE_ENVIRONMENT;
        }

        // Create the sandboxed process
        // Safety: all pointers and handles are valid for the duration of this call.
        let create_result = unsafe {
            CreateProcessW(
                None,
                Some(windows::core::PWSTR(cmdline.as_mut_ptr())),
                None,
                None,
                true, // Inherit handles
                create_flags,
                env_ptr,
                None,
                &si_ex.StartupInfo,
                &mut pi,
            )
        };

        cleanup.delete_attr_list();
        if let Some(h) = cleanup.stdin_read.take() {
            unsafe {
                let _ = CloseHandle(h);
            }
        }
        if let Some(h) = cleanup.stdout_write.take() {
            unsafe {
                let _ = CloseHandle(h);
            }
        }
        if let Some(h) = cleanup.stderr_dup.take() {
            unsafe {
                let _ = CloseHandle(h);
            }
        }

        create_result.map_err(|e| {
            unsafe {
                // CreateProcessW leaves pi.hProcess/pi.hThread NULL on
                // failure; CloseHandle on such a value is an invalid-handle
                // call, so only close real handles.
                for h in [pi.hProcess, pi.hThread] {
                    if !h.is_invalid() && h != HANDLE::default() {
                        let _ = CloseHandle(h);
                    }
                }
            }
            WardenError::SandboxSetup(format!("CreateProcessW: {e}"))
        })?;

        let job = create_kill_on_close_job().inspect_err(|_e| unsafe {
            let _ = TerminateProcess(pi.hProcess, 1);
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
        })?;
        unsafe {
            AssignProcessToJobObject(job, pi.hProcess).map_err(|e| {
                let _ = TerminateProcess(pi.hProcess, 1);
                let _ = CloseHandle(job);
                let _ = CloseHandle(pi.hProcess);
                let _ = CloseHandle(pi.hThread);
                WardenError::SandboxSetup(format!("AssignProcessToJobObject: {e}"))
            })?;
            if ResumeThread(pi.hThread) == u32::MAX {
                let e = std::io::Error::last_os_error();
                let _ = TerminateProcess(pi.hProcess, 1);
                let _ = CloseHandle(job);
                let _ = CloseHandle(pi.hProcess);
                let _ = CloseHandle(pi.hThread);
                return Err(WardenError::SandboxSetup(format!("ResumeThread: {e}")));
            }
            let _ = CloseHandle(pi.hThread);
        }

        let stdin_write = cleanup
            .stdin_write
            .take()
            .expect("parent stdin pipe still owned");
        let stdout_read = cleanup
            .stdout_read
            .take()
            .expect("parent stdout pipe still owned");

        // Construct WindowsChild with the real process handle and parent-side pipe handles.
        // Safety: pi.hProcess is a valid process handle from CreateProcessW.
        // stdin_write and stdout_read are valid pipe handles owned by the parent.
        let child = unsafe {
            use std::os::windows::io::FromRawHandle;

            let stdin =
                std::fs::File::from_raw_handle(stdin_write.0 as std::os::windows::io::RawHandle);
            let stdout =
                std::fs::File::from_raw_handle(stdout_read.0 as std::os::windows::io::RawHandle);

            WindowsChild {
                process_handle: pi.hProcess,
                job_handle: job,
                stdin: Some(stdin),
                stdout: Some(stdout),
                _sandbox: None,
            }
        };

        Ok(child)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WindowsChild — custom child process wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// Custom child process wrapper for Windows AppContainer sandboxes.
///
/// `std::process::Child` cannot be constructed from raw handles in stable Rust,
/// so this type provides equivalent functionality using Win32 process handles directly.
///
/// # Ownership
///
/// This struct owns the process handle and pipe handles. They are closed on `Drop`.
pub struct WindowsChild {
    process_handle: HANDLE,
    job_handle: HANDLE,
    pub stdin: Option<std::fs::File>,
    pub stdout: Option<std::fs::File>,
    /// Keeps the AppContainer sandbox profile alive until the child exits.
    /// The profile is deleted when this field is dropped.
    pub(super) _sandbox: Option<AppContainerSandbox>,
}

// Safety: WindowsChild is Send and Sync because:
// - process_handle is a process-wide HANDLE that WaitForSingleObject and
//   TerminateProcess may use from any thread;
// - Drop runs exactly once, so the handle cannot be closed twice;
// - the PSID is owned by AppContainerSandbox and is not mutated externally.
unsafe impl Send for WindowsChild {}
unsafe impl Sync for WindowsChild {}

impl WindowsChild {
    /// Wait for the process to exit and return its exit status.
    pub fn wait(&self) -> std::io::Result<std::process::ExitStatus> {
        use std::os::windows::process::ExitStatusExt;

        // Safety: process_handle is a valid handle from CreateProcessW.
        // INFINITE (0xFFFF_FFFF) means wait until the process exits.
        unsafe {
            let wait_result = WaitForSingleObject(self.process_handle, INFINITE);
            // WAIT_FAILED: the wait call itself failed (e.g. invalid handle).
            // Without this check, GetExitCodeProcess could return an inaccurate exit code.
            if wait_result == WAIT_FAILED {
                return Err(std::io::Error::last_os_error());
            }

            let mut exit_code: u32 = 0;
            GetExitCodeProcess(self.process_handle, &mut exit_code)
                .map_err(|e| std::io::Error::other(e.to_string()))?;

            Ok(std::process::ExitStatus::from_raw(exit_code))
        }
    }

    /// Forcefully terminate the process.
    pub fn kill(&self) -> std::io::Result<()> {
        unsafe {
            if !self.job_handle.is_invalid() {
                let _ = TerminateJobObject(self.job_handle, 1);
            }
            TerminateProcess(self.process_handle, 1)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        Ok(())
    }

    /// Get the OS-assigned process ID, if the process is still running.
    pub fn id(&self) -> Option<u32> {
        // Safety: process_handle is a valid handle from CreateProcessW.
        let pid = unsafe { GetProcessId(self.process_handle) };
        if pid == 0 { None } else { Some(pid) }
    }
}

impl Drop for WindowsChild {
    fn drop(&mut self) {
        self.stdin.take();
        self.stdout.take();
        unsafe {
            if !self.job_handle.is_invalid() {
                let _ = TerminateJobObject(self.job_handle, 1);
                let _ = CloseHandle(self.job_handle);
            }
            let _ = TerminateProcess(self.process_handle, 1);
            let _ = CloseHandle(self.process_handle);
        }
        drop(self._sandbox.take());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper functions
// ─────────────────────────────────────────────────────────────────────────────

/// Build a Windows command line string from command and arguments.
///
/// Windows CreateProcessW expects a single mutable UTF-16 string containing
/// the full command line. Arguments with spaces are quoted.
fn build_command_line(command: &str, args: &[String]) -> Vec<u16> {
    let mut cmdline = String::new();

    // Quote the command if it contains spaces
    if command.contains(' ') {
        cmdline.push('"');
        cmdline.push_str(command);
        cmdline.push('"');
    } else {
        cmdline.push_str(command);
    }

    for arg in args {
        cmdline.push(' ');
        if arg.is_empty() || arg.contains(' ') || arg.contains('\t') || arg.contains('"') {
            // Microsoft CommandLineToArgvW escaping rules:
            // - 2n   backslashes + " → n backslashes, end quoted string
            // - 2n+1 backslashes + " → n backslashes, literal "
            // - n    backslashes not before " → n literal backslashes
            cmdline.push('"');
            let chars: Vec<char> = arg.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                let mut num_backslashes: usize = 0;
                while i < chars.len() && chars[i] == '\\' {
                    num_backslashes += 1;
                    i += 1;
                }
                if i == chars.len() {
                    // Trailing backslashes: double them (closing quote follows)
                    for _ in 0..num_backslashes * 2 {
                        cmdline.push('\\');
                    }
                    break;
                } else if chars[i] == '"' {
                    // Backslashes before quote: double + one more to escape the quote
                    for _ in 0..num_backslashes * 2 + 1 {
                        cmdline.push('\\');
                    }
                    cmdline.push('"');
                    i += 1;
                } else {
                    // Backslashes not before quote: literal
                    for _ in 0..num_backslashes {
                        cmdline.push('\\');
                    }
                    cmdline.push(chars[i]);
                    i += 1;
                }
            }
            cmdline.push('"');
        } else {
            cmdline.push_str(arg);
        }
    }

    // Convert to null-terminated UTF-16
    cmdline
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .collect()
}

/// Create an anonymous pipe and return (read_end, write_end) handles.
///
/// Both handles are created as **non-inheritable** by default.
/// The caller must explicitly mark only child-side handles as inheritable
/// via [`set_handle_inheritable`] before passing them to `CreateProcessW`.
fn create_pipe() -> Result<(HANDLE, HANDLE), WardenError> {
    let mut read_handle = HANDLE::default();
    let mut write_handle = HANDLE::default();

    // Safety: CreatePipe creates an anonymous pipe with non-inheritable handles.
    unsafe {
        windows::Win32::System::Pipes::CreatePipe(&mut read_handle, &mut write_handle, None, 0)
            .map_err(|e| WardenError::SandboxSetup(format!("CreatePipe: {e}")))?;
    }

    Ok((read_handle, write_handle))
}

fn create_kill_on_close_job() -> Result<HANDLE, WardenError> {
    let job = unsafe {
        CreateJobObjectW(None, None)
            .map_err(|e| WardenError::SandboxSetup(format!("CreateJobObjectW: {e}")))?
    };
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .map_err(|e| {
            let _ = CloseHandle(job);
            WardenError::SandboxSetup(format!("SetInformationJobObject: {e}"))
        })?;
    }
    Ok(job)
}

/// Mark a handle as inheritable by child processes.
///
/// Only child-side pipe handles should be made inheritable. Parent-side handles
/// must remain non-inheritable to prevent leakage to other child processes.
fn set_handle_inheritable(handle: HANDLE) -> Result<(), WardenError> {
    // Safety: handle is a valid handle from CreatePipe.
    unsafe {
        SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
            .map_err(|e| WardenError::SandboxSetup(format!("SetHandleInformation: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_command_line_simple() {
        let cmdline = build_command_line("node", &["index.js".to_string()]);
        let s = String::from_utf16_lossy(
            &cmdline[..cmdline
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(cmdline.len())],
        );
        assert_eq!(s, "node index.js");
    }

    #[test]
    fn test_build_command_line_spaces_in_command() {
        let cmdline = build_command_line("C:\\Program Files\\node.exe", &[]);
        let s = String::from_utf16_lossy(&cmdline[..cmdline.len() - 1]); // strip null
        assert_eq!(s, "\"C:\\Program Files\\node.exe\"");
    }

    #[test]
    fn test_build_command_line_spaces_in_args() {
        let cmdline = build_command_line("cmd", &["hello world".to_string()]);
        let s = String::from_utf16_lossy(&cmdline[..cmdline.len() - 1]);
        assert_eq!(s, "cmd \"hello world\"");
    }

    #[test]
    fn test_build_command_line_quotes_in_args() {
        let cmdline = build_command_line("echo", &["say \"hi\"".to_string()]);
        let s = String::from_utf16_lossy(&cmdline[..cmdline.len() - 1]);
        assert_eq!(s, "echo \"say \\\"hi\\\"\"");
    }

    #[test]
    fn test_build_command_line_null_terminated() {
        let cmdline = build_command_line("test", &[]);
        assert_eq!(*cmdline.last().unwrap(), 0u16);
    }

    #[test]
    fn test_build_command_line_backslash_before_quote() {
        // Arg: a\"b (characters: a, \, ", b)
        // Backslash before quote must be doubled + quote escaped
        let cmdline = build_command_line("echo", &["a\\\"b".to_string()]);
        let s = String::from_utf16_lossy(&cmdline[..cmdline.len() - 1]);
        assert_eq!(s, "echo \"a\\\\\\\"b\"");
    }

    #[test]
    fn test_build_command_line_trailing_backslash_in_quoted_arg() {
        // Arg: "hello world\" — trailing backslash in arg that needs quoting
        // Trailing backslash must be doubled before closing quote
        let cmdline = build_command_line("cmd", &["hello world\\".to_string()]);
        let s = String::from_utf16_lossy(&cmdline[..cmdline.len() - 1]);
        assert_eq!(s, "cmd \"hello world\\\\\"");
    }

    #[test]
    fn test_build_command_line_empty_arg() {
        // Empty arg must still be represented as ""
        let cmdline = build_command_line("cmd", &["".to_string()]);
        let s = String::from_utf16_lossy(&cmdline[..cmdline.len() - 1]);
        assert_eq!(s, "cmd \"\"");
    }

    #[test]
    fn test_build_command_line_multiple_trailing_backslashes() {
        // Arg: "a b\\\\" (4 trailing backslashes + space → must double to 8)
        let cmdline = build_command_line("cmd", &["a b\\\\".to_string()]);
        let s = String::from_utf16_lossy(&cmdline[..cmdline.len() - 1]);
        assert_eq!(s, "cmd \"a b\\\\\\\\\"");
    }
}
