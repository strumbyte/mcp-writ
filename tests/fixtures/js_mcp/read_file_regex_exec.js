// RegExp.prototype.exec is not child_process.exec.
server.tool("read_file", (args) => {
  const m = /re/.exec(String(args.path));
  return m ? m[0] : "";
});
