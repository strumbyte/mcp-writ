//! Mode `contracts` — contract-answer-tier evidence: API-set
//! implementation, export resolution, version/support queries, WinRT
//! activation. Never promoted to "the runtime contract works".

use std::ffi::c_void;

use crate::ffi::*;
use crate::helpers::*;

const PSEC_EXPORTS: &[&str] = &[
    "CreateProcessSecurityEnvironment",
    "QueryProcessSecurityEnvironmentSupport",
    "IsProcessSecurityEnvironmentVersionSupported",
    "CloseProcessSecurityEnvironment",
    "StartLearningModeTrace",
    "StopLearningModeTrace",
    "CloseLearningModeTrace",
    "CancelProcessSecurityEnvironmentTerminateOnClose",
    "SbeGetSecurityEnvironmentAppContainerSid",
    "Experimental_CompileSandboxSpecificationInternal",
    "Experimental_QuerySandboxSupport",
    "Experimental_CreateProcessInSandbox",
];

fn contracts_psec() -> String {
    unsafe {
        let mut out = String::from("{\"api_set\":");
        let cname =
            std::ffi::CString::new("api-win-appmodel-processmodel~securityenvironment").unwrap();
        out.push_str(&format!(
            "{}",
            IsApiSetImplemented(cname.as_ptr() as *const u8) != 0
        ));
        let lm = std::ffi::CString::new("api-win-appmodel-processmodel~learningmodetrace").unwrap();
        out.push_str(&format!(
            ",\"api_set_learning_mode\":{}",
            IsApiSetImplemented(lm.as_ptr() as *const u8) != 0
        ));

        let dll = load_system_dll("processmodel.dll");
        out.push_str(&format!(",\"dll_loaded\":{}", !dll.is_null()));
        if dll.is_null() {
            out.push('}');
            return out;
        }
        let exports = PSEC_EXPORTS
            .iter()
            .map(|e| format!("\"{}\":{}", e, !export_addr(dll, e).is_null()))
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&format!(",\"exports\":{{{exports}}}"));

        // Support-flags query — a real API answer, not inference.
        let qname = std::ffi::CString::new("QueryProcessSecurityEnvironmentSupport").unwrap();
        let qp = GetProcAddress(dll, qname.as_ptr() as *const u8);
        if !qp.is_null() {
            let q: unsafe extern "system" fn(*mut u64) -> HRESULT = std::mem::transmute(qp);
            let mut flags: u64 = 0;
            let hr = q(&mut flags);
            out.push_str(&format!(
                ",\"query_support\":{{\"hr\":\"{}\",\"flags\":\"0x{flags:016x}\"}}",
                hr_str(hr)
            ));
        }
        // Version query for majors 1 and 2 — MXC calls
        // (major, available*, minor*): supported iff returned minor >= ask.
        let vname = std::ffi::CString::new("IsProcessSecurityEnvironmentVersionSupported").unwrap();
        let vp = GetProcAddress(dll, vname.as_ptr() as *const u8);
        if !vp.is_null() {
            let v: unsafe extern "system" fn(u32, *mut u8, *mut u32) -> HRESULT =
                std::mem::transmute(vp);
            out.push_str(",\"version_support\":[");
            let mut first = true;
            for major in [1u32, 2] {
                let mut avail: u8 = 0;
                let mut minor: u32 = 0;
                let hr = v(major, &mut avail, &mut minor);
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&format!(
                    "{{\"major\":{major},\"hr\":\"{}\",\"available\":{},\"minor\":{minor}}}",
                    hr_str(hr),
                    avail != 0
                ));
            }
            out.push(']');
        }
        // Bounded create probes — malformed/empty specs prove the RPC
        // endpoint and schema check are live without creating an env.
        let cname2 = std::ffi::CString::new("CreateProcessSecurityEnvironment").unwrap();
        let cp = GetProcAddress(dll, cname2.as_ptr() as *const u8);
        if !cp.is_null() {
            let c: unsafe extern "system" fn(*const c_void, u32, u32, *mut HANDLE) -> HRESULT =
                std::mem::transmute(cp);
            out.push_str(",\"create_probes\":[");
            let specs: [(&str, Vec<u8>); 2] =
                [("empty", Vec::new()), ("magic-only", b"PSEC".to_vec())];
            let mut first = true;
            for (label, spec) in specs {
                let mut env: HANDLE = std::ptr::null_mut();
                let hr = c(
                    spec.as_ptr() as *const c_void,
                    spec.len() as u32,
                    0,
                    &mut env,
                );
                if !first {
                    out.push(',');
                }
                first = false;
                let mut closed = false;
                if !env.is_null() {
                    let clname = std::ffi::CString::new("CloseProcessSecurityEnvironment").unwrap();
                    let clp = GetProcAddress(dll, clname.as_ptr() as *const u8);
                    if !clp.is_null() {
                        let cl: unsafe extern "system" fn(HANDLE) = std::mem::transmute(clp);
                        cl(env);
                        closed = true;
                    }
                }
                out.push_str(&format!(
                    "{{\"spec\":\"{label}\",\"hr\":\"{}\",\"env_returned\":{},\"closed\":{closed}}}",
                    hr_str(hr),
                    !env.is_null()
                ));
            }
            out.push(']');
        }
        FreeLibrary(dll);
        out.push('}');
        out
    }
}

/// IActivationFactory IID {00000035-...-0046}.
const IACTIVATIONFACTORY_IID: [u8; 16] = [
    0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

fn hstring_to_string(hs: *mut c_void) -> Option<String> {
    unsafe {
        if hs.is_null() {
            return None;
        }
        let mut len = 0u32;
        let ptr = WindowsGetStringRawBuffer(hs, &mut len);
        if ptr.is_null() {
            return None;
        }
        Some(String::from_utf16_lossy(std::slice::from_raw_parts(
            ptr,
            len as usize,
        )))
    }
}

fn activate_class(name: &str) -> String {
    unsafe {
        let w = wide(name);
        let mut hs: *mut c_void = std::ptr::null_mut();
        let hr = WindowsCreateString(w.as_ptr(), (w.len() - 1) as u32, &mut hs);
        if hr != 0 {
            return format!(
                "{{\"class\":{},\"activation_hr\":\"{}\"}}",
                js(name),
                hr_str(hr)
            );
        }
        let mut factory: *mut c_void = std::ptr::null_mut();
        let hr = RoGetActivationFactory(
            hs,
            IACTIVATIONFACTORY_IID.as_ptr() as *const c_void,
            &mut factory,
        );
        if hr != 0 || factory.is_null() {
            WindowsDeleteString(hs);
            return format!(
                "{{\"class\":{},\"activation_hr\":\"{}\",\"activated\":false}}",
                js(name),
                hr_str(hr)
            );
        }
        // IActivationFactory::ActivateInstance = vtbl[6].
        let vtbl = *(factory as *const *const *const c_void);
        let activate: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT =
            std::mem::transmute(*vtbl.add(6));
        let mut obj: *mut c_void = std::ptr::null_mut();
        let ahr = activate(factory, &mut obj);
        let mut iid_count = 0u32;
        let mut runtime_class = String::new();
        if !obj.is_null() {
            let ovtbl = *(obj as *const *const *const c_void);
            let getiids: unsafe extern "system" fn(
                *mut c_void,
                *mut u32,
                *mut *mut c_void,
            ) -> HRESULT = std::mem::transmute(*ovtbl.add(3));
            let getname: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT =
                std::mem::transmute(*ovtbl.add(4));
            let mut iids: *mut c_void = std::ptr::null_mut();
            let _ = getiids(obj, &mut iid_count, &mut iids);
            if !iids.is_null() {
                CoTaskMemFree(iids);
            }
            let mut rcs: *mut c_void = std::ptr::null_mut();
            if getname(obj, &mut rcs) == 0 {
                runtime_class = hstring_to_string(rcs).unwrap_or_default();
                WindowsDeleteString(rcs);
            }
            let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                std::mem::transmute(*ovtbl.add(2));
            release(obj);
        }
        let fvtbl = *(factory as *const *const *const c_void);
        let release: unsafe extern "system" fn(*mut c_void) -> u32 =
            std::mem::transmute(*fvtbl.add(2));
        release(factory);
        WindowsDeleteString(hs);
        format!(
            "{{\"class\":{},\"activation_hr\":\"{}\",\"activated\":{},\"activate_hr\":\"{}\",\"runtime_class\":{},\"iid_count\":{}}}",
            js(name),
            hr_str(hr),
            !obj.is_null(),
            hr_str(ahr),
            js(&runtime_class),
            iid_count
        )
    }
}

fn contracts_isosession() -> String {
    unsafe {
        let mut out = String::from("{\"dlls\":{");
        for (i, d) in [
            "IsoSessionApp.dll",
            "IsoSessionClient.dll",
            "IsoSessionServer.dll",
        ]
        .iter()
        .enumerate()
        {
            let h = load_system_dll(d);
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!("\"{d}\":{{\"loaded\":{}", !h.is_null()));
            if !h.is_null() {
                for (j, e) in [
                    "DllGetActivationFactory",
                    "IsIsoSessionSupported",
                    "IsoSessionClientQueryLocalAgentUserSupport",
                ]
                .iter()
                .enumerate()
                {
                    let _ = j;
                    out.push_str(&format!(
                        ",\"export_{}\":{}",
                        e,
                        !export_addr(h, e).is_null()
                    ));
                }
                FreeLibrary(h);
            }
            out.push('}');
        }
        out.push_str("},\"classes\":[");
        let hr = RoInitialize(0);
        out.push_str(&format!("{{\"roinitialize_hr\":\"{}\"}},", hr_str(hr)));
        for (i, cls) in [
            "Windows.AI.IsolationSession.IsoSessionOps",
            "Windows.AI.IsolationSession.Preview.IsoSessionOps",
            "Windows.AI.IsolationSession.IsoStationOps",
            // control: an unregistered name must fail as REGDB_E_CLASSNOTREG,
            // proving activation success above is real and not indiscriminate.
            "Windows.AI.IsolationSession.NotARealClass",
        ]
        .iter()
        .enumerate()
        {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&activate_class(cls));
        }
        out.push(']');
        CoUninitialize();
        out.push('}');
        out
    }
}

pub(crate) fn mode_contracts() -> String {
    let psec = contracts_psec();
    let iso = contracts_isosession();
    // Win32 app isolation: packaging-level contract — the only honest
    // host-tier signals are preview service/registry artifacts.
    let svc = service_fact("appisolation");
    let reg = reg_read(HKLM, r"SOFTWARE\Microsoft\Windows\AppIsolation", "Enabled");
    format!(
        "{{\"mode\":\"contracts\",\"psec\":{},\"isolation_session\":{},\"win32_app_isolation\":{{\"service\":{},\"reg_enabled\":{},\"note\":\"packaging-level contract; host signal is preview-tier only\"}}}}",
        psec, iso, svc, jopt(reg)
    )
}
