"""Mock server exposing passive /admin, /login, /version routes, deterministic favicon, and Set-Cookie."""

from http.server import BaseHTTPRequestHandler, HTTPServer

# Minimal deterministic 1x1 ICO bytes for repeatable MurmurHash3 clustering tests.
FAVICON_BYTES = (
    b"\x00\x00\x01\x00\x01\x00\x01\x01\x00\x00\x01\x00\x18\x00\x30\x00"
    b"\x00\x00\x16\x00\x00\x00\x28\x00\x00\x00\x01\x00\x00\x00\x02\x00"
    b"\x00\x00\x01\x00\x18\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff"
    b"\x00\x00\x00\x00\x00\x00"
)


class AdminStagingHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_HEAD(self) -> None:
        self._handle(send_body=False)

    def do_GET(self) -> None:
        self._handle(send_body=True)

    def _handle(self, send_body: bool) -> None:
        if self.path == "/favicon.ico":
            self.send_response(200)
            self.send_header("Content-Type", "image/x-icon")
            self.send_header("Content-Length", str(len(FAVICON_BYTES)))
            self.end_headers()
            if send_body:
                self.wfile.write(FAVICON_BYTES)
            return

        if self.path == "/version":
            body = b'{"app":"faculty-staging-app","version":"1.4.2-rc1","env":"staging"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Powered-By", "MockFramework/2.1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if send_body:
                self.wfile.write(body)
            return

        if self.path in ("/admin", "/login"):
            html = (
                "<!doctype html><html><head><title>Faculty Admin Panel - Staging</title></head>"
                "<body><h1>Administration Login (Mock Lab)</h1></body></html>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "ADMIN_SESSION=mock-only-value; Path=/")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            if send_body:
                self.wfile.write(html)
            return

        html = (
            "<!doctype html><html><head><title>Staging Faculty App</title></head>"
            "<body><h1>Faculty Staging Home</h1></body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "SESSIONID=mock-only-value; Path=/; HttpOnly")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        if send_body:
            self.wfile.write(html)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), AdminStagingHandler)
    print("mock-admin-staging listening on :8080", flush=True)
    server.serve_forever()
