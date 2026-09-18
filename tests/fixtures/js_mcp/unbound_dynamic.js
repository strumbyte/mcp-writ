// Dynamic tool names must stay Unbound and are not Capability evidence.
server.tool(process.env.NAME, async () => {
  return 1;
});
