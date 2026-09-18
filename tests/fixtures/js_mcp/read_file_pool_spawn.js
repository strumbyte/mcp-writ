// pool.spawn is not child_process.spawn unless bound to that module.
const pool = {
  spawn(path) {
    return path;
  },
};

server.tool("read_file", (args) => pool.spawn(args.path));
