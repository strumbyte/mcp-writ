//! An unnamed Windows job owned only by the relay process. Joining it before
//! spawning the runner makes agent crashes reap the runner and its descendants.

#[cfg(windows)]
pub fn contain_current_process() -> std::io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};

    #[repr(C)]
    #[derive(Default)]
    struct BasicLimits {
        process_time: i64,
        job_time: i64,
        flags: u32,
        min_working_set: usize,
        max_working_set: usize,
        active_processes: u32,
        affinity: usize,
        priority: u32,
        scheduling: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimits {
        basic: BasicLimits,
        io: [u64; 6],
        process_memory: usize,
        job_memory: usize,
        peak_process_memory: usize,
        peak_job_memory: usize,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> *mut c_void;
        fn SetInformationJobObject(
            job: *mut c_void,
            class: i32,
            data: *const c_void,
            len: u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
        fn GetCurrentProcess() -> *mut c_void;
    }
    // SAFETY: unnamed, non-inheritable handle; all pointers/lengths describe
    // initialized repr(C) Windows structures and remain live for each call.
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let handle = OwnedHandle::from_raw_handle(job);
        let mut limits = ExtendedLimits::default();
        limits.basic.flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if SetInformationJobObject(
            job,
            9,
            std::ptr::from_ref(&limits).cast(),
            size_of::<ExtendedLimits>() as u32,
        ) == 0
            || AssignProcessToJobObject(job, GetCurrentProcess()) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // Closing the handle would kill this process too. The OS closes it on
        // process exit (including TerminateProcess); children cannot inherit it.
        std::mem::forget(handle);
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn contain_current_process() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Windows job required",
    ))
}
