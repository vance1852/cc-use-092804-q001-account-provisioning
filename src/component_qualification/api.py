"""用于离线验收的无依赖 JSON HTTP API。"""

from __future__ import annotations

import argparse
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .service import ComponentService


class Handler(BaseHTTPRequestHandler):
    service = ComponentService()
    # 所有请求线程共享一个 SQLite 连接，串行进入避免事务交错。
    _gate = threading.Lock()

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        with self._gate:
            self._handle_get()

    def _handle_get(self):
        if self.path == "/health":
            return self._json(200, {"status": "ok", "service": "component-qualification"})
        if self.path.startswith("/lots/"):
            try:
                token = self.headers.get("Authorization", "").removeprefix("Bearer ")
                return self._json(200, self.service.get_lot(token, self.path.split("/", 2)[2]))
            except Exception as exc:
                return self._json(400, {"error": str(exc)})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        with self._gate:
            self._handle_post()

    def _handle_post(self):
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            if self.path == "/login":
                return self._json(200, {"token": self.service.auth.login(body["user_id"], body["password"])})
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            if self.path == "/lots":
                return self._json(201, self.service.create_lot(token, body["lot_id"], body["product"], body["process_rev"], body["unit_count"]))
            if self.path.startswith("/lots/") and self.path.endswith("/measurements"):
                lot_id = self.path.split("/")[2]
                return self._json(201, self.service.add_measurement(token, lot_id, body["signal_frequency_hz"], body["response"], body.get("noise", 0.0), body["instrument"]))
            if self.path.startswith("/lots/") and self.path.endswith("/analysis"):
                return self._json(200, self.service.analyze(token, self.path.split("/")[2]))
            return self._json(404, {"error": "not found"})
        except PermissionError as exc:
            return self._json(403, {"error": str(exc)})
        except Exception as exc:
            return self._json(400, {"error": str(exc)})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default=":memory:")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--bootstrap-admin-id", default=os.environ.get("CQ_ADMIN_ID", "admin"))
    args = parser.parse_args()
    Handler.service = ComponentService(args.database)
    # 首个管理员口令必须由带外环境变量提供，代码中不再内置默认口令。
    password = os.environ.get("CQ_ADMIN_PASSWORD", "")
    if not password:
        raise SystemExit("拒绝启动：必须通过环境变量 CQ_ADMIN_PASSWORD 设置首个管理员口令（至少 12 位）")
    Handler.service.bootstrap_admin(args.bootstrap_admin_id, password)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
