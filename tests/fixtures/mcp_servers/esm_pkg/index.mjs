// Minimal multi-file ESM MCP stdio server — a regression fixture for the
// entrypoint-hash launch path. The relative import below is what a
// pinned-payload fd/staged spelling breaks: the interpreter realpaths
// the entry and resolves `./tools.mjs` from its directory.
import { tools } from './tools.mjs';
import readline from 'node:readline';

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
          serverInfo: { name: 'esm-pkg-fixture', version: '0.0.0' },
        },
      });
      break;
    case 'tools/list':
      send({ id: request.id, result: { tools } });
      break;
    case 'ping':
      send({ id: request.id, result: {} });
      break;
  }
});
