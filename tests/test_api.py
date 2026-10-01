from __future__ import annotations

import json
import sqlite3
import unittest

from embodied_ai.api import JsonApplication
from embodied_ai.service import TrialService


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        service = TrialService(self.connection)
        service.bootstrap_first_admin("root", "安全管理员", "local-cli")
        self.app = JsonApplication(service)

    def tearDown(self) -> None:
        self.connection.close()

    def test_health(self) -> None:
        response = self.app.handle("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "ok")

    def test_json_error_shape(self) -> None:
        response = self.app.handle("POST", "/users", body=b"not-json")
        self.assertEqual(response.status, 422)
        self.assertEqual(response.body["error"]["code"], "validation_failed")

    def test_anonymous_user_creation_is_unauthorized(self) -> None:
        payload = json.dumps({"user_id": "u0", "display_name": "越权", "role": "approver"}).encode()
        response = self.app.handle("POST", "/users", body=payload)
        self.assertEqual(response.status, 401)
        self.assertEqual(response.body["error"]["code"], "unauthorized")

    def test_user_route_requires_admin(self) -> None:
        self.app.handle(
            "POST", "/users", {"X-Actor-Id": "root"},
            json.dumps({"user_id": "u1", "display_name": "操作员", "role": "operator"}).encode(),
        )
        payload = json.dumps({"user_id": "u2", "display_name": "普通账号", "role": "operator"}).encode()
        response = self.app.handle("POST", "/users", {"X-Actor-Id": "u1"}, body=payload)
        self.assertEqual(response.status, 403)

    def test_admin_creates_user(self) -> None:
        payload = json.dumps({"user_id": "u1", "display_name": "操作员", "role": "operator"}).encode()
        response = self.app.handle("POST", "/users", {"X-Actor-Id": "root"}, body=payload)
        self.assertEqual(response.status, 201)
        self.assertEqual(response.body["role"], "operator")
        self.assertEqual(response.body["role_version"], 1)
        self.assertEqual(response.body["created_by"], "root")


if __name__ == "__main__":
    unittest.main()
