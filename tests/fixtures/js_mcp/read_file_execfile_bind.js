// child_process.execFile.bind(null)(...) -- must prove ProcessExec.
server.tool("read_file", (args) => child_process.execFile.bind(null)(args.cmd, []));
