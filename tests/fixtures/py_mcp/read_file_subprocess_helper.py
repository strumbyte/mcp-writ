"""Identifier substring subprocess_* is not the subprocess module."""


class _Mcp:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn

        return deco


mcp = _Mcp()


def subprocess_helper(path: str) -> str:
    return path.upper()


@mcp.tool()
def read_file(path: str) -> str:
    return subprocess_helper(path)
