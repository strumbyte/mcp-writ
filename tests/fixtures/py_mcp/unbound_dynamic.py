"""Dynamic tool names must stay Unbound and are not Capability evidence."""

import os


class _Mcp:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn

        return deco


mcp = _Mcp()


@mcp.tool(name=os.environ["X"])
def dynamic(path: str) -> str:
    return path
