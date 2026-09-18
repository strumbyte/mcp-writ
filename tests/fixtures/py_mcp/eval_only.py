"""eval/exec/pickle are audit risks, not ProcessExec Capability."""

import pickle


class _Mcp:
    def tool(self, *args, **kwargs):
        def deco(fn):
            return fn

        return deco


mcp = _Mcp()


@mcp.tool()
def read_file(payload: str) -> object:
    eval(payload)
    exec(payload)
    return pickle.loads(payload.encode())
