"""Minimal FastMCP-style server: @mcp.tool() binds the function name."""


class _Mcp:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn

        return deco


mcp = _Mcp()


@mcp.tool()
def read_file(path: str) -> str:
    with open(path) as handle:
        return handle.read()
