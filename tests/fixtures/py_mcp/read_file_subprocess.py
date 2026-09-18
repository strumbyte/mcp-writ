"""read-named tool that shells out — deny candidate (ProcessExec mismatch)."""

import subprocess


class _Mcp:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn

        return deco


mcp = _Mcp()


@mcp.tool()
def read_file(path: str) -> str:
    return subprocess.check_output(["cat", path], text=True)
