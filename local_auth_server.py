import os
import uuid
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

os.environ.setdefault("DRY_RUN", "1")
os.environ.setdefault("LOG_LEVEL", "ERROR")

import lambda_function as lf


class LocalContext:
    def __init__(self) -> None:
        self.aws_request_id = f"local-auth-{uuid.uuid4().hex[:12]}"


class LocalAuthHandler(BaseHTTPRequestHandler):
    server_version = "ZoolandingLocalAuth/1.0"

    def do_OPTIONS(self) -> None:
        self._handle()

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.address_string()} - {format % args}")

    def _handle(self) -> None:
        event = self._event()
        response = lf.lambda_handler(event, LocalContext())
        self._send_lambda_response(response)

    def _event(self) -> Dict[str, Any]:
        parsed = urllib.parse.urlparse(self.path)
        raw_query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        query = {key: values[-1] for key, values in raw_query.items() if values}
        body = None

        if self.command.upper() in {"POST", "PUT", "PATCH"}:
            content_length = int(self.headers.get("Content-Length") or "0")
            body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else None

        return {
            "path": parsed.path,
            "rawPath": parsed.path,
            "httpMethod": self.command.upper(),
            "headers": {key: value for key, value in self.headers.items()},
            "queryStringParameters": query,
            "requestContext": {"http": {"path": parsed.path, "method": self.command.upper()}},
            "isBase64Encoded": False,
            "body": body,
        }

    def _send_lambda_response(self, response: Dict[str, Any]) -> None:
        status_code = int(response.get("statusCode") or 500)
        raw_body = response.get("body") or ""
        body = raw_body if isinstance(raw_body, bytes) else str(raw_body).encode("utf-8")

        self.send_response(status_code)
        headers = response.get("headers") if isinstance(response.get("headers"), dict) else {}
        for key, value in headers.items():
            if str(key).lower() == "content-length":
                continue
            self.send_header(str(key), str(value))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _env_enabled(name: str, default: str = "0") -> bool:
    return str(os.getenv(name, default)).strip().lower() in {"1", "true", "yes", "on"}


def main() -> None:
    if not _env_enabled("DRY_RUN"):
        raise SystemExit("Set DRY_RUN=1 to run the local auth proxy harness.")

    if not (os.getenv("LOCAL_AUTH_REGISTRY_DIR") or os.getenv("LOCAL_AUTH_REGISTRY_FILE")):
        raise SystemExit("Set LOCAL_AUTH_REGISTRY_DIR or LOCAL_AUTH_REGISTRY_FILE to a server-only registry source.")

    host = os.getenv("ZLP_LOCAL_AUTH_PROXY_HOST", "127.0.0.1")
    port = int(os.getenv("ZLP_LOCAL_AUTH_PROXY_PORT", "5055"))
    server = ThreadingHTTPServer((host, port), LocalAuthHandler)
    print(f"Local auth proxy listening on http://{host}:{port}")
    print("Routes: /auth/runtime-config and /Prod/auth/runtime-config")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping local auth proxy.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
