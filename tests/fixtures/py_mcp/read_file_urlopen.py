"""read_file handler that opens a URL — must prove NetworkOutbound."""

import urllib.request


class _Mcp:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn

        return deco


mcp = _Mcp()


@mcp.tool()
def read_file(url: str) -> str:
    with urllib.request.urlopen(url) as resp:
        return resp.read().decode()
