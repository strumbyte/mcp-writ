"""Same-file 1-hop helper: read_file → fetch_remote (NetworkOutbound)."""

import urllib.request


class _Mcp:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn

        return deco


mcp = _Mcp()


def fetch_remote(url: str) -> str:
    with urllib.request.urlopen(url) as resp:
        return resp.read().decode()


@mcp.tool()
def read_file(url: str) -> str:
    return fetch_remote(url)
