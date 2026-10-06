//! Mode `facts` — presence-tier evidence: OS build, candidate binary
//! files, service registrations, API sets, and the host token.

use crate::ffi::*;
use crate::helpers::*;

pub(crate) fn mode_facts() -> String {
    unsafe {
        let mut vi = OsVersionInfoW {
            size: std::mem::size_of::<OsVersionInfoW>() as u32,
            ..std::mem::zeroed()
        };
        let _ = RtlGetVersion(&mut vi);
        let ubr = reg_dword(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR");
        let display = reg_read(
            HKLM,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "DisplayVersion",
        );
        let edition = reg_read(
            HKLM,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "EditionID",
        );
        let product = reg_read(
            HKLM,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
        );

        let files = [
            "processmodel.dll",
            "IsoSessionApp.dll",
            "IsoSessionCli.exe",
            "IsoSessionClient.dll",
            "IsoSessionServer.dll",
            "IsoSessionProxyStub.dll",
            "bfscfg.exe",
            "CheckNetIsolation.exe",
            "vmwp.exe",
            "wsb.exe",
            "wslc.exe",
            "hsnproxy.dll",
            "computestorage.dll",
            "appisolation.dll",
        ];
        let files_json = files
            .iter()
            .map(|f| file_fact(f))
            .collect::<Vec<_>>()
            .join(",");
        let services = ["IsoEnvBroker", "IsolationSession", "bfssvc", "appisolation"];
        let services_json = services
            .iter()
            .map(|s| service_fact(s))
            .collect::<Vec<_>>()
            .join(",");

        let apiset = |name: &str| -> String {
            let cname = std::ffi::CString::new(name).unwrap();
            let present = IsApiSetImplemented(cname.as_ptr() as *const u8);
            format!("{{\"name\":{},\"implemented\":{}}}", js(name), present != 0)
        };
        let apisets = [
            "api-win-appmodel-processmodel~securityenvironment",
            "api-win-appmodel-processmodel~learningmodetrace",
            "api-win-app-isolation-l1-1-0",
        ];
        let apiset_json = apisets
            .iter()
            .map(|a| apiset(a))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "{{\"mode\":\"facts\",\"host\":{{\"os\":{{\"major\":{},\"minor\":{},\"build\":{},\"ubr\":{}}},\"display_version\":{},\"edition\":{},\"product\":{},\"arch\":{}}},\"token\":{},\"files\":[{}],\"services\":[{}],\"api_sets\":[{}]}}",
            vi.major,
            vi.minor,
            vi.build,
            ubr.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            jopt(display),
            jopt(edition),
            jopt(product),
            js(std::env::consts::ARCH),
            token_facts(),
            files_json,
            services_json,
            apiset_json
        )
    }
}
