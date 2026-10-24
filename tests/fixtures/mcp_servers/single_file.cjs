// Minimal single-file CJS MCP stdio server — the no-import baseline for
// the entrypoint-hash launch path (the interpreted-payload fix must not
// regress a script that needs no sibling resolution).
const readline = require('node:readline');

const send = message =>
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', ...message }) + '\n');

readline.createInterface({ input: process.stdin }).on('line', line => {
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    return;
  }
  if (request.id === undefined) return;
  switch (request.method) {
    case 'initialize':
      send({
        id: request.id,
        result: {
          protocolVersion: '2025-11-25',
          capabilities: { tools: {} },
          serverInfo: { name: 'single-file-cjs-fixture', version: '0.0.0' },
        },
      });
      break;
    case 'tools/list':
      send({ id: request.id, result: { tools: [] } });
      break;
    case 'ping':
      send({ id: request.id, result: {} });
      break;
  }
});
