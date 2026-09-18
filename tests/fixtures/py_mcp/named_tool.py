"""@mcp.tool(name="literal") binds a string literal, not the function name."""


class _Mcp:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn

        return deco


mcp = _Mcp()


@mcp.tool(name="custom_read")
def impl_read(path: str) -> str:
    with open(path) as handle:
        return handle.read()
