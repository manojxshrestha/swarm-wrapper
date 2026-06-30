"""Minimal vulnerable HTTP server for end-to-end lab testing.
Exposes endpoints that the consensus oracles can detect:
  /sqli?q=...   → SQL error on single quote (simulated SQLite error)
  /xss?q=...    → reflects query param unescaped in HTML
  /safe?q=...   → returns benign JSON (no vuln)
"""

import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        q = params.get("q", [""])[0]

        if parsed.path == "/sqli" and "'" in q:
            self._json(200, {"error": {"message": "SQLITE_ERROR: near \"'%\": syntax error"}})
        elif parsed.path == "/xss":
            self._html(200, f"<html><body>search results for: {q}</body></html>")
        elif parsed.path == "/safe":
            self._json(200, {"status": "ok", "query": q})
        else:
            self._json(404, {"error": "not found"})

    def _json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, status, body):
        body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
