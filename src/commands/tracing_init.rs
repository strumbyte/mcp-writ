pub fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    init_tracing_with_level(level);
}

pub fn init_tracing_with_level(level: tracing::Level) {
    // Use try_init to avoid panic on repeated initialization.
    // Explicitly write to stderr to ensure tracing output never contaminates
    // the stdout JSON-RPC stream (audit logs could corrupt the protocol).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .try_init()
        .ok();
}
