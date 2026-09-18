"""add_tool("literal", fn) binds only when the first argument is a string literal."""


class _Mcp:
    def add_tool(self, name, fn):
        return fn


mcp = _Mcp()


def handle_literal(path: str) -> str:
    return path


mcp.add_tool("literal_tool", handle_literal)
