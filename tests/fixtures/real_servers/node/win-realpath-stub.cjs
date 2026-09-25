// mcp-writ real-server e2e preload — Windows AppContainer only.
//
// Inside an AppContainer token, libuv's uv_fs_realpath (Node's fs.realpath /
// fs.promises.realpath / fs.realpathSync.native) resolves through
// GetFinalPathNameByHandleW, which requires NT-namespace / volume-mount access
// that cannot be granted by any file DACL — the call fails EPERM for every
// path. The filesystem server's validatePath calls fs.realpath on each
// request, so without this stub every tools/call fails inside the sandbox.
//
// The stub returns the path unchanged. This does not weaken the test: the
// AppContainer DACL still enforces every real open/stat, so OS-layer denial
// (stage 5) still fails closed, and the Auditor layer is unaffected.
//
// Deployment caution: replacing fs.realpath disables the server's own
// symlink-escape check, so this stub is acceptable only when the
// OS-granted filesystem access is restricted to the data root(s).
const fs = require('fs');
fs.realpath = function (p, opts, cb) {
  if (typeof opts === 'function') {
    cb = opts;
  }
  process.nextTick(() => cb(null, p));
};
fs.realpath.native = fs.realpath;
fs.realpathSync = (p) => p;
fs.realpathSync.native = fs.realpathSync;
fs.promises.realpath = async (p) => p;
