"""
Minimal MCP (Model Context Protocol) server — stdlib only, no pip dependencies.

Implements just enough of the MCP spec (JSON-RPC 2.0 over stdio) for Claude Code,
OpenAI, and other MCP-compatible AI agents to discover and call tools.

Protocol ref: https://modelcontextprotocol.io/specification/2025-11-25

Usage:
    from mcp_server import McpServer

    server = McpServer("my-tool", "1.0.0")

    @server.tool("greet", "Say hello", {
        "type": "object",
        "properties": {"name": {"type": "string", "description": "Who to greet"}},
        "required": ["name"]
    })
    def greet(name: str) -> str:
        return f"Hello, {name}!"

    server.run()   # blocks, reads JSON-RPC from stdin, writes to stdout
"""

import json
import sys
import traceback


class McpServer:
    """Minimal MCP server (JSON-RPC 2.0 over stdio)."""

    PROTOCOL_VERSION = "2024-11-05"

    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self._tools = {}       # name -> (func, schema)
        self._tool_list = []   # [{name, description, inputSchema}]

    def tool(self, name: str, description: str, parameters: dict):
        """Decorator to register a tool function.

        The decorated function receives keyword arguments matching the
        inputSchema properties and must return a string (the tool result).
        """
        def decorator(func):
            schema = {
                "name": name,
                "description": description,
                "inputSchema": parameters,
            }
            self._tools[name] = (func, schema)
            self._tool_list.append(schema)
            return func
        return decorator

    def run(self):
        """Main loop: read JSON-RPC messages from stdin, dispatch, respond on stdout.

        Notifications (no 'id') are acknowledged silently.
        Requests (with 'id') get a JSON-RPC response.
        """
        # Logging goes to stderr (stdout is reserved for JSON-RPC).
        print(f"[MCP] {self.name} v{self.version} server starting (stdio)", file=sys.stderr)

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            method = msg.get("method", "")
            msg_id = msg.get("id")

            # Notifications (no id) — acknowledge silently
            if msg_id is None:
                continue

            try:
                result = self._dispatch(method, msg.get("params", {}))
                self._send_result(msg_id, result)
            except Exception as e:
                self._send_error(msg_id, -32603, str(e))

    # ── Dispatch ──────────────────────────────────────────────────────

    def _dispatch(self, method: str, params: dict) -> dict:
        if method == "initialize":
            return {
                "protocolVersion": self.PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": self.name,
                    "version": self.version,
                },
            }
        elif method == "tools/list":
            return {"tools": self._tool_list}
        elif method == "tools/call":
            return self._call_tool(params)
        elif method == "ping":
            return {}
        else:
            raise ValueError(f"Unknown method: {method}")

    def _call_tool(self, params: dict) -> dict:
        name = params.get("name", "")
        arguments = params.get("arguments", {})

        if name not in self._tools:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                "isError": True,
            }

        func, _schema = self._tools[name]
        try:
            result = func(**arguments)
            if not isinstance(result, str):
                result = json.dumps(result)
            return {
                "content": [{"type": "text", "text": result}],
            }
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Error: {e}\n{traceback.format_exc()}"}],
                "isError": True,
            }

    # ── I/O ───────────────────────────────────────────────────────────

    def _send_result(self, msg_id, result: dict):
        response = {"jsonrpc": "2.0", "id": msg_id, "result": result}
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()

    def _send_error(self, msg_id, code: int, message: str):
        response = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": code, "message": message},
        }
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
