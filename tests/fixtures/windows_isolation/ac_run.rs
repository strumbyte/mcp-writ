//! Mode `ac-run` — the shipping-path AppContainer baseline: named
//! profile, DACL grant/restore on caller-created dirs, security
//! capabilities (+LPAC opt-out, internetClient SID), spawn via
//! `spawn_wrapped`, profile cleanup.

use std::ffi::c_void;
use std::path::PathBuf;

use crate::ffi::*;
use crate::helpers::*;
use crate::spawn::*;

struct Grant {
    path: PathBuf,
    mask: u32,
    applied: bool,
    restored: bool,
    error: Option<u32>,
    backup_sd: *mut c_void,
    backup_dacl: *mut c_void,
}

fn apply_dacl_grant(path: &PathBuf, sid: PSID, mask: u32) -> Result<Grant, u32> {
    unsafe {
        let w = wide(&path.to_string_lossy());
        let mut old_dacl: *mut c_void = std::ptr::null_mut();
        let mut sd: *mut c_void = std::ptr::null_mut();
        let rc = GetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old_dacl,
            std::ptr::null_mut(),
            &mut sd,
        );
        if rc != ERROR_SUCCESS {
            return Err(rc);
        }
        let mut ea = ExplicitAccessW {
            access_permissions: mask,
            access_mode: SET_ACCESS,
            inheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            trustee_multiple: std::ptr::null_mut(),
            trustee_op: 0, // NO_MULTIPLE_TRUSTEE
            trustee_form: TRUSTEE_IS_SID,
            trustee_type: TRUSTEE_IS_UNKNOWN,
            trustee_name: sid,
        };
        let mut new_dacl: *mut c_void = std::ptr::null_mut();
        let rc = SetEntriesInAclW(1, &mut ea, old_dacl, &mut new_dacl);
        if rc != ERROR_SUCCESS {
            LocalFree(sd);
            return Err(rc);
        }
        let mut wmut = w.clone();
        let rc = SetNamedSecurityInfoW(
            wmut.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl,
            std::ptr::null_mut(),
        );
        LocalFree(new_dacl);
        if rc != ERROR_SUCCESS {
            LocalFree(sd);
            return Err(rc);
        }
        Ok(Grant {
            path: path.clone(),
            mask,
            applied: true,
            restored: false,
            error: None,
            backup_sd: sd,
            backup_dacl: old_dacl,
        })
    }
}

fn restore_grant(g: &mut Grant) {
    unsafe {
        if !g.backup_sd.is_null() {
            let mut w = wide(&g.path.to_string_lossy());
            let rc = SetNamedSecurityInfoW(
                w.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                g.backup_dacl,
                std::ptr::null_mut(),
            );
            g.restored = rc == ERROR_SUCCESS;
            LocalFree(g.backup_sd);
            g.backup_sd = std::ptr::null_mut();
        }
    }
}

pub(crate) fn mode_ac_run(args: &[String]) -> String {
    unsafe {
        let lpac = args.iter().any(|a| a == "--lpac");
        let net = args.iter().any(|a| a == "--net");
        let name = format!("mcp-writ-pr30-{:08x}", GetCurrentProcessId());
        let mut sid: PSID = std::ptr::null_mut();
        let hr = CreateAppContainerProfile(
            wide(&name).as_ptr(),
            wide(&name).as_ptr(),
            wide("PR-30 probe profile").as_ptr(),
            std::ptr::null_mut(),
            0,
            &mut sid,
        );
        if hr != 0 {
            // Profile may exist from a killed earlier run — delete+retry once.
            let _ = DeleteAppContainerProfile(wide(&name).as_ptr());
            let hr2 = CreateAppContainerProfile(
                wide(&name).as_ptr(),
                wide(&name).as_ptr(),
                wide("PR-30 probe profile").as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut sid,
            );
            if hr2 != 0 {
                return format!(
                    "{{\"mode\":\"ac-run\",\"profile_created\":false,\"create_hr\":\"{}\"}}",
                    hr_str(hr2)
                );
            }
        }
        let mut cleanup_error = false;

        // Optional internetClient capability (S-1-15-3-1) — network allow
        // contrast leg, mirroring the product's capability SID path.
        // SECURITY_CAPABILITIES.Capabilities is a SID_AND_ATTRIBUTES[]
        // ({Sid ptr, Attributes u32}), not a raw PSID array.
        let mut cap_sids: Vec<PSID> = Vec::new();
        if net {
            let mut csid: PSID = std::ptr::null_mut();
            if ConvertStringSidToSidW(wide("S-1-15-3-1").as_ptr(), &mut csid) != 0 {
                cap_sids.push(csid);
            }
        }
        let cap_attrs: Vec<SidAndAttributes> = cap_sids
            .iter()
            .map(|s| SidAndAttributes {
                sid: *s,
                attributes: 0,
            })
            .collect();

        // DACL grants on caller-created dirs only — backup before change,
        // restore after run, owner-tracked exactly like the product path.
        let mut grants: Vec<Grant> = Vec::new();
        for (env_var, mask) in [
            ("WINISO_RO_DIR", GENERIC_READ_EXECUTE),
            ("WINISO_RW_DIR", GENERIC_ALL),
        ] {
            if let Ok(p) = std::env::var(env_var) {
                let dir = PathBuf::from(p);
                match apply_dacl_grant(&dir, sid, mask) {
                    Ok(g) => grants.push(g),
                    Err(rc) => grants.push(Grant {
                        path: dir,
                        mask,
                        applied: false,
                        restored: false,
                        error: Some(rc),
                        backup_sd: std::ptr::null_mut(),
                        backup_dacl: std::ptr::null_mut(),
                    }),
                }
            }
        }

        // Attributes: security capabilities + optional LPAC opt-out;
        // spawn_wrapped adds the handle list itself.
        let caps = SecurityCapabilities {
            appcontainer_sid: sid,
            capabilities: if cap_attrs.is_empty() {
                std::ptr::null_mut()
            } else {
                cap_attrs.as_ptr() as *mut c_void
            },
            capability_count: cap_attrs.len() as u32,
            reserved: 0,
        };
        let opt_out: u32 = 1;
        let mut attrs: Vec<(usize, *const c_void, usize)> = vec![(
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &caps as *const _ as *const c_void,
            std::mem::size_of::<SecurityCapabilities>(),
        )];
        if lpac {
            attrs.push((
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                &opt_out as *const _ as *const c_void,
                4,
            ));
        }

        // `--image <exe> <argv...>` spawns an external binary under the
        // same AppContainer token + DACL grants — the Node/Python launch
        // leg (real-world launch conditions vs the probe's own exe).
        let (image, image_argv) = split_image(args);

        // Give the sandboxed child an executable it can actually run for
        // the grandchild leg: an exe copy inside the RW grant (test-owned
        // path; the repo dir itself is never ACL-touched). The context
        // travels on argv — a security-environment child is not promised
        // the parent's env block.
        let mut gc_note = String::new();
        let mut gc_exe_arg: Option<PathBuf> = None;
        if image.is_none() {
            if let Ok(rw) = std::env::var("WINISO_RW_DIR") {
                let exe = std::env::current_exe().unwrap();
                let copy = PathBuf::from(&rw).join("mcp-writ-pr30-child.exe");
                match std::fs::copy(&exe, &copy) {
                    Ok(_) => {
                        gc_exe_arg = Some(copy.clone());
                        gc_note = format!("gc_exe={}", copy.to_string_lossy());
                    }
                    Err(e) => {
                        gc_note = format!("gc exe copy failed: {e}");
                    }
                }
            }
        }
        // Loopback listener for the `net_connect_allow` leg — whether a
        // sandboxed child can reach it (and how the denied leg fails)
        // is the capability evidence, not just "is a socket possible".
        let listener = bind_loopback();
        let child_args = if image.is_some() {
            image_argv
        } else {
            attempts_args(
                gc_exe_arg.as_ref(),
                listener.as_ref().map(|(_, a)| a.clone()),
            )
        };
        let spawn_image = image.clone().unwrap_or_else(|| std::env::current_exe().unwrap());
        let mut spawn = spawn_wrapped(&spawn_image, &child_args, &attrs);
        drop(listener);
        if !gc_note.is_empty() {
            spawn.detail.push_str(&format!("; {gc_note}"));
        }

        for g in grants.iter_mut() {
            restore_grant(g);
        }
        let dhr = DeleteAppContainerProfile(wide(&name).as_ptr());
        for csid in cap_sids {
            LocalFree(csid);
        }
        if !sid.is_null() {
            FreeSid(sid);
        }
        if dhr != 0 {
            cleanup_error = true;
        }
        let grants_json = grants
            .iter()
            .map(|g| {
                format!(
                    "{{\"path\":{},\"mask\":\"0x{:08x}\",\"applied\":{},\"restored\":{},\"error\":{}}}",
                    js(&g.path.to_string_lossy()),
                    g.mask,
                    g.applied,
                    g.restored,
                    g.error.map(|v| v.to_string()).unwrap_or_else(|| "null".into())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let child_json = child_json_or_null(&spawn.child_json);
        format!(
            "{{\"mode\":\"ac-run\",\"profile_created\":true,\"lpac\":{},\"net_capability\":{},\"child_image\":{},\"grants\":[{}],\"spawn_ok\":{},\"spawn_detail\":{},\"child_pid\":{},\"gc_pid\":{},\"gc_killed\":{},\"child\":{},\"profile_deleted\":{},\"cleanup_error\":{}{}}}",
            lpac,
            net,
            image
                .as_ref()
                .map(|p| js(&p.to_string_lossy()))
                .unwrap_or_else(|| "null".into()),
            grants_json,
            spawn.ok,
            js(&spawn.detail),
            spawn.child_pid,
            spawn.gc_pid.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            spawn.gc_killed.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            child_json,
            dhr == 0,
            cleanup_error,
            child_stdout_field(&spawn.child_json)
        )
    }
}
