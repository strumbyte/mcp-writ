// run-to-completion one-shot driver — hits mxc_engine::run (Windows Sandbox etc.)
// args: <json> [exp]
fn main() {
    let json_path = std::env::args().nth(1).expect("json path");
    let exp = std::env::args().nth(2).map(|s| s == "exp").unwrap_or(false);
    let json = std::fs::read_to_string(&json_path).expect("read json");
    use mxc_sdk::mxc_common::config_parser::load_mxc_request_from_json;
    use mxc_sdk::mxc_common::logger::{Logger, Mode};
    use mxc_sdk::mxc_common::state_aware_request::MxcRequest;
    let mut logger = Logger::new(Mode::Console);
    let mut request = match load_mxc_request_from_json(&json, &mut logger) {
        Ok(MxcRequest::OneShot(r)) => r,
        Ok(_) => {
            println!("parse: not a one-shot request");
            return;
        }
        Err(e) => {
            println!("parse error: {e:?}");
            return;
        }
    };
    request.experimental_enabled = exp;
    match mxc_sdk::mxc_engine::run(&request, &mut logger) {
        Ok(resp) => {
            println!("{resp:#?}");
        }
        Err(e) => println!("run error: {e:?}"),
    }
}
