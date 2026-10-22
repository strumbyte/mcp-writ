// Invoked as `node run ...` by the check-server regression test, replacing
// the guard process. Delay tools/list so a pipelined tools/call fails reliably.
const fs = require('node:fs');
const readline = require('node:readline');
const scenario = process.env.MCP_WRIT_ORDER_SCENARIO;
if (scenario === 'nonzero-exit') process.exitCode = 17;
let listed = false;
const record = (event, params) => fs.appendFileSync(process.env.MCP_WRIT_ORDER_TRACE,
  JSON.stringify({ pid: process.pid, event, params }) + '\n');
const send = message => process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...message }) + '\n');
readline.createInterface({ input: process.stdin }).on('line', line => {
  const request = JSON.parse(line);
  record(request.method, request.params);
  const id = request.id;
  switch (request.method) {
    case 'server/discover':
      if (scenario === 'v26') send({ id, result: { supportedVersions: ['2026-07-28'] } });
      else send({ id, error: { code: -32601, message: 'Method not found' } });
      break;
    case 'initialize':
      send({ id, result: { protocolVersion: '2025-11-25', capabilities: {} } });
      break;
    case 'tools/list':
      // Neither nested IDs nor same-ID server requests are responses.
      send({ method: 'notifications/progress', params: { id } });
      send({ id, method: 'ping' });
      setTimeout(() => {
        if (scenario === 'list-error') {
          send({ id, error: { code: -32603, message: 'Listing failed' } });
        } else {
          listed = true;
          record('list-response');
          send({ id, result: { tools: [] } });
        }
      }, 250);
      break;
    case 'tools/call':
      if (!listed) send({ id, error: { code: -32001, message: 'No verified tools/list' } });
      else send({ id, result: { content: [{ type: 'text', text: 'ok' }] } });
      break;
  }
});
