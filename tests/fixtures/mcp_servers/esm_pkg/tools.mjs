// Sibling module imported by index.mjs — the entry point must resolve
// this specifier relative to its real directory, which is exactly what
// a `/proc/self/fd/N` or staged-copy entrypoint spelling cannot do.
export const tools = [
  {
    name: 'echo_tool',
    description: 'Echo fixture tool.',
    inputSchema: { type: 'object', properties: { text: { type: 'string' } } },
  },
];
