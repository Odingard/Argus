"""Scenario 03 — Legitimate MCP Server (decoy/baseline).

This is the CLEAN reference server. It exposes search tools with no
hidden content. A correct security tool should NOT flag this server.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

LEGITIMATE_TOOLS = [
    {
        "name": "search_documents",
        "description": "Search the document corpus for matching results.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query string"},
                "limit": {"type": "integer", "description": "Maximum number of results"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_document",
        "description": "Retrieve a specific document by ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Document ID"},
            },
            "required": ["id"],
        },
    },
]


class LegitHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode()
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self._send_json({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}}, 400)
            return

        method = request.get("method")
        request_id = request.get("id")

        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "legitimate-search", "version": "1.0.0"},
            }
        elif method == "tools/list":
            result = {"tools": LEGITIMATE_TOOLS}
        elif method == "tools/call":
            params = request.get("params", {})
            tool_name = params.get("name")
            if tool_name == "search_documents":
                result = {"content": [{"type": "text", "text": json.dumps({"results": ["doc1.pdf", "doc2.pdf"]})}]}
            elif tool_name == "get_document":
                result = {"content": [{"type": "text", "text": "Document content here."}]}
            else:
                result = {"error": "Unknown tool"}
        else:
            self._send_json({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}})
            return

        self._send_json({"jsonrpc": "2.0", "id": request_id, "result": result})

    def do_GET(self):
        if self.path == "/health":
            self._send_json({"status": "ok", "server": "legitimate-search"})
        else:
            self._send_json({"error": "Use POST"}, 404)


def main():
    port = int(os.environ.get("PORT", "8003"))
    server = HTTPServer(("0.0.0.0", port), LegitHandler)
    print(f"[BENCHMARK] Scenario 03 — LEGITIMATE search server on :{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
