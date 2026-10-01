from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from embodied_ai.api import JsonApplication as AiApplication
from embodied_ai.errors import Conflict, Forbidden, InvalidState
from embodied_ai.service import TrialService
from embodied_ai.storage import connect as ai_connect
from robot_control.api import JsonApplication as DispatchApplication
from robot_control.errors import InvalidState as DispatchInvalidState
from robot_control.service import SupplyService
from robot_control.storage import connect as dispatch_connect


def _ai_service(connection: sqlite3.Connection) -> TrialService:
    service = TrialService(connection)
    service.bootstrap_first_admin("root", "安全管理员", "local-cli")
    return service


class AccountBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.service = _ai_service(self.connection)
        self.app = AiApplication(self.service, bootstrap_code="secret-code")

    def tearDown(self) -> None:
        self.connection.close()

    # 普通业务请求不能借缺失或伪造的身份获得高权限 ----------

    def test_anonymous_and_forged_and_non_admin_cannot_create_users(self) -> None:
        payload = json.dumps({"user_id": "x", "display_name": "越权", "role": "approver"}).encode()
        missing = self.app.handle("POST", "/users", body=payload)
        self.assertEqual(missing.status, 401)
        forged = self.app.handle("POST", "/users", {"X-Actor-Id": "ghost"}, body=payload)
        self.assertEqual(forged.status, 401)
        self.service.create_user("root", "op", "操作员", "operator")
        weak = self.app.handle("POST", "/users", {"X-Actor-Id": "op"}, body=payload)
        self.assertEqual(weak.status, 403)
        self.assertIsNone(self.connection.execute(
            "SELECT 1 FROM users WHERE user_id='x'"
        ).fetchone())

    def test_deactivated_actor_cannot_authorize_anything(self) -> None:
        self.service.create_user("root", "stat2", "统计", "statistician")
        self.service.deactivate_user("root", "stat2", "离岗")
        with self.assertRaises(Forbidden):
            self.service._require("stat2", "batch.seal")
        app = AiApplication(self.service)
        response = app.handle(
            "POST", "/batches/1/seal",
            {"X-Actor-Id": "stat2"},
            json.dumps({"expected_revision": 1}).encode(),
        )
        self.assertEqual(response.status, 403)

    # 初始化边界 -------------------------------------------

    def test_bootstrap_is_once_idempotent_and_never_overwrites(self) -> None:
        # 已有在职管理员：再次初始化被拒（即使用同名参数也不会重置）。
        with self.assertRaises(InvalidState):
            self.service.bootstrap_first_admin("root2", "另一个", "local-cli")
        # 同参数重跑幂等返回，且不产生重复记录。
        again = self.service.bootstrap_first_admin("root", "安全管理员", "local-cli")
        self.assertEqual(again["role"], "admin")
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM users WHERE user_id='root'"
        ).fetchone()[0], 1)
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM role_assignments WHERE user_id='root'"
        ).fetchone()[0], 1)
        # 不能借初始化覆盖已存在的普通账号。
        self.service.create_user("root", "op", "操作员", "operator")
        with self.assertRaises(Conflict):
            self.service.bootstrap_first_admin("op", "操作员", "local-cli")

    def test_remote_bootstrap_requires_out_of_band_code_and_closes_after_use(self) -> None:
        fresh = sqlite3.connect(":memory:", isolation_level=None)
        fresh.row_factory = sqlite3.Row
        try:
            closed = AiApplication(TrialService(fresh))  # 未配置注册码
            response = closed.handle(
                "POST", "/bootstrap",
                body=json.dumps({"user_id": "a", "display_name": "a", "registration_code": "x"}).encode(),
            )
            self.assertEqual(response.status, 404)
            enabled = AiApplication(TrialService(fresh), bootstrap_code="secret-code")
            bad = enabled.handle(
                "POST", "/bootstrap",
                body=json.dumps({"user_id": "a", "display_name": "a", "registration_code": "wrong"}).encode(),
            )
            self.assertEqual(bad.status, 401)
            ok = enabled.handle(
                "POST", "/bootstrap",
                body=json.dumps({"user_id": "a", "display_name": "甲", "registration_code": "secret-code"}).encode(),
            )
            self.assertEqual(ok.status, 201)
            second = enabled.handle(
                "POST", "/bootstrap",
                body=json.dumps({"user_id": "b", "display_name": "乙", "registration_code": "secret-code"}).encode(),
            )
            self.assertEqual(second.status, 409)
        finally:
            fresh.close()

    # 角色变更边界与版本 -----------------------------------

    def test_role_change_uses_versions_and_leaves_no_half_state(self) -> None:
        self.service.create_user("root", "u", "用户", "operator")
        with self.assertRaises(Conflict):
            self.service.change_role("root", "u", "approver", expected_version=99, reason="错版本")
        # 失败不得产生半成品角色版本或授权记录。
        self.assertEqual(self.service.get_user("u")["role_version"], 1)
        self.assertEqual(self.connection.execute(
            "SELECT count(*) FROM role_assignments WHERE user_id='u' AND action='role_changed'"
        ).fetchone()[0], 0)
        changed = self.service.change_role("root", "u", "approver", expected_version=1, reason="复核通过")
        self.assertEqual(changed["role"], "approver")
        self.assertEqual(changed["role_version"], 2)
        with self.assertRaises(Forbidden):
            self.service.change_role("root", "root", "approver", expected_version=1, reason="提权自己")
        # 额外管理员只能经角色变更产生；有两名管理员后，自停用仍被禁止。
        self.service.create_user("root", "root2", "备用管理员", "operator")
        self.service.change_role("root", "root2", "admin", 1, "增补管理员")
        with self.assertRaises(Forbidden):
            self.service.deactivate_user("root2", "root2", "停用自己")
        # 停用备用管理员后只剩一名管理员，最后一名不能被任何人（含自己）停用。
        self.service.deactivate_user("root", "root2", "收回备用管理员")
        with self.assertRaises(InvalidState):
            self.service.deactivate_user("root", "root", "停用最后管理员")

    # 授权者、角色版本、拒绝原因可通过 API 查看 --------------

    def test_security_api_shows_grantor_versions_and_denial_reasons(self) -> None:
        self.service.create_user("root", "aud", "审计", "auditor")
        self.service.create_user("root", "u", "用户", "operator")
        self.service.change_role("root", "u", "approver", 1, "上线复核")
        history_response = self.app.handle("GET", "/users/u/history", {"X-Actor-Id": "aud"})
        self.assertEqual(history_response.status, 200)
        self.assertEqual(history_response.body["current"]["role_version"], 2)
        actions = [item["action"] for item in history_response.body["assignments"]]
        self.assertEqual(actions, ["created", "role_changed"])
        grantors = {item["granted_by"] for item in history_response.body["assignments"]}
        self.assertEqual(grantors, {"root"})
        # 制造一次拒绝，再由审计员查看拒绝原因。
        self.app.handle("POST", "/users", body=json.dumps({"user_id": "z", "display_name": "z", "role": "operator"}).encode())
        denials = self.app.handle("GET", "/security/denials", {"X-Actor-Id": "aud"})
        self.assertEqual(denials.status, 200)
        self.assertTrue(any(
            item["code"] == "unauthorized" and "X-Actor-Id" in item["reason"]
            for item in denials.body["denials"]
        ))
        # 普通角色看不到安全视图。
        forbidden = self.app.handle("GET", "/security/denials", {"X-Actor-Id": "u"})
        self.assertEqual(forbidden.status, 403)


class ConcurrentCreationTests(unittest.TestCase):
    def test_concurrent_create_same_user_has_one_deterministic_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "ai.sqlite3"
            boot = TrialService(ai_connect(db))
            boot.bootstrap_first_admin("root", "管理员", "local-cli")
            del boot
            outcomes: list[str] = []
            barrier = threading.Barrier(8)

            def worker() -> None:
                service = TrialService(ai_connect(db))
                barrier.wait()
                try:
                    service.create_user("root", "dup", "并发账号", "approver")
                    outcomes.append("created")
                except Conflict:
                    outcomes.append("conflict")
                except Exception as exc:  # 其他结果都不允许出现
                    outcomes.append(f"error:{exc!r}")

            threads = [threading.Thread(target=worker) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(outcomes).count("created"), 1)
            self.assertEqual(sorted(outcomes).count("conflict"), 7)
            checker = TrialService(ai_connect(db))
            self.assertEqual(checker.connection.execute(
                "SELECT count(*) FROM users WHERE user_id='dup'"
            ).fetchone()[0], 1)
            self.assertEqual(checker.connection.execute(
                "SELECT count(*) FROM role_assignments WHERE user_id='dup'"
            ).fetchone()[0], 1)
            self.assertEqual(checker.get_user("dup")["role"], "approver")

    def test_concurrent_bootstrap_establishes_exactly_one_admin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "dispatch.sqlite3"
            # 先由单连接完成建表与 WAL 初始化（等价于服务启动），再让并发请求竞争首个管理员。
            starter = SupplyService(dispatch_connect(db))
            starter.connection.close()
            outcomes: list[str] = []
            barrier = threading.Barrier(6)

            def worker(index: int) -> None:
                service = SupplyService(dispatch_connect(db))
                barrier.wait()
                try:
                    # 各线程用不同的 admin 编号竞争唯一的首个管理员。
                    service.bootstrap_first_admin(f"root-{index}", f"管理员{index}", "local-cli")
                    outcomes.append("bootstrapped")
                except DispatchInvalidState:
                    outcomes.append("rejected")
                except Exception as exc:
                    outcomes.append(f"error:{exc!r}")

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(outcomes).count("bootstrapped"), 1)
            self.assertEqual(sorted(outcomes).count("rejected"), 5)
            service = SupplyService(dispatch_connect(db))
            self.assertEqual(service.connection.execute(
                "SELECT count(*) FROM supply_users WHERE role='admin' AND active=1"
            ).fetchone()[0], 1)
            self.assertEqual(service.connection.execute(
                "SELECT count(*) FROM role_assignments WHERE action='bootstrap'"
            ).fetchone()[0], 1)


class DispatchDomainParityTests(unittest.TestCase):
    def test_dispatch_account_chain_mirrors_boundaries(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        service = SupplyService(connection)
        service.bootstrap_first_admin("root", "管理员", "local-cli")
        app = DispatchApplication(service)
        payload = json.dumps({"user_id": "d", "display_name": "调度", "role": "dispatcher"}).encode()
        self.assertEqual(app.handle("POST", "/users", body=payload).status, 401)
        self.assertEqual(app.handle("POST", "/users", {"X-Actor-Id": "fake"}, body=payload).status, 401)
        created = app.handle("POST", "/users", {"X-Actor-Id": "root"}, body=payload)
        self.assertEqual(created.status, 201)
        self.assertEqual(created.body["created_by"], "root")
        # 日常新增不得产生 admin。
        admin_payload = json.dumps({"user_id": "a2", "display_name": "伪管理员", "role": "admin"}).encode()
        self.assertEqual(app.handle("POST", "/users", {"X-Actor-Id": "root"}, body=admin_payload).status, 403)
        # 变更角色并核验哈希链审计中记录了授权者与版本。
        changed = service.change_role("root", "d", "risk", 1, "安全复核")
        self.assertEqual(changed["role_version"], 2)
        chain = service.audit_chain("root")
        self.assertTrue(chain["valid"])
        history = app.handle("GET", "/users/d/history", {"X-Actor-Id": "root"})
        self.assertEqual([item["action"] for item in history.body["assignments"]], ["created", "role_changed"])
        service.deactivate_user("root", "d", "离岗")
        denied = app.handle("POST", "/nominations", {"X-Actor-Id": "d"}, body=json.dumps({}).encode())
        self.assertEqual(denied.status, 403)
        connection.close()


if __name__ == "__main__":
    unittest.main()
