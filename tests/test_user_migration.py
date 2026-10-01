from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path


class EmbodiedAiUserMigrationTests(unittest.TestCase):
    def _legacy_db(self) -> sqlite3.Connection:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.executescript("""
            CREATE TABLE users (
                user_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('operator','statistician','approver','auditor')),
                active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1))
            );
            INSERT INTO users VALUES ('legacy-stat','旧统计','statistician',1);
            INSERT INTO users VALUES ('legacy-approver','旧审批','approver',1);
        """)
        return connection

    def test_legacy_users_preserved_and_admin_role_allowed(self) -> None:
        from embodied_ai.service import TrialService
        from embodied_ai.storage import inspect_schema

        connection = self._legacy_db()
        try:
            service = TrialService(connection)
            # 迁移后可以补建首个管理员（旧库没有管理员）。
            service.bootstrap_first_admin("root", "管理员", "local-cli")
            rows = {
                row["user_id"]: dict(row)
                for row in connection.execute("SELECT * FROM users").fetchall()
            }
            self.assertEqual(rows["legacy-stat"]["role"], "statistician")
            self.assertEqual(rows["legacy-stat"]["role_version"], 1)
            self.assertEqual(rows["legacy-stat"]["display_name"], "旧统计")
            self.assertEqual(rows["root"]["role"], "admin")
            self.assertEqual(rows["root"]["created_by"], "system:bootstrap")
            summary = inspect_schema(connection)
            self.assertEqual(summary["schema_version"], "3")
            # 迁移可重复执行，不改变已有数据。
            service.bootstrap_first_admin("root", "管理员", "local-cli")
            self.assertEqual(
                connection.execute("SELECT count(*) FROM users WHERE user_id='root'").fetchone()[0], 1
            )
        finally:
            connection.close()

    def test_restart_keeps_permissions_and_audit_consistent(self) -> None:
        from embodied_ai.service import TrialService

        connection = self._legacy_db()
        try:
            first = TrialService(connection)
            first.bootstrap_first_admin("root", "管理员", "local-cli")
            first.create_user("root", "op", "操作员", "operator", "上线建号")
            first.change_role("root", "op", "approver", 1, "安全复核后转审批")
            # 用同一数据库重新构造服务，模拟进程重启。
            restarted = TrialService(connection)
            history = restarted.role_history("root", "op")
            self.assertEqual(history["current"]["role"], "approver")
            self.assertEqual(history["current"]["role_version"], 2)
            granted_by = [item["granted_by"] for item in history["assignments"]]
            self.assertEqual(granted_by, ["root", "root"])
            actions = [item["action"] for item in history["assignments"]]
            self.assertEqual(actions, ["created", "role_changed"])
            restarted.deactivate_user("root", "op", "离岗停用")
            self.assertFalse(restarted.get_user("op")["active"])
        finally:
            connection.close()

    def test_file_restart_preserves_permissions_and_audit(self) -> None:
        from embodied_ai.service import TrialService
        from embodied_ai.storage import connect

        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "ai.sqlite3"
            first = TrialService(connect(db))
            first.bootstrap_first_admin("root", "管理员", "local-cli")
            first.create_user("root", "op", "操作员", "operator", "上线")
            first.change_role("root", "op", "approver", 1, "复核转审批")
            # 关闭全部连接后以全新进程视角重开，权限与授权历史必须仍一致。
            restarted = TrialService(connect(db))
            self.assertEqual(restarted.get_user("op")["role"], "approver")
            self.assertEqual(restarted.get_user("op")["role_version"], 2)
            history = restarted.role_history("root", "op")
            self.assertEqual([a["action"] for a in history["assignments"]], ["created", "role_changed"])
            self.assertTrue(all(a["granted_by"] == "root" for a in history["assignments"]))
            denials_before = len(restarted.list_denials("root")["denials"])
            restarted.record_denial(None, "POST", "/users", "unauthorized", "缺少 X-Actor-Id")
            again = TrialService(connect(db))
            self.assertEqual(len(again.list_denials("root")["denials"]), denials_before + 1)


class RobotControlUserMigrationTests(unittest.TestCase):
    def test_legacy_supply_users_preserved_and_admin_role_allowed(self) -> None:
        from robot_control.service import SupplyService

        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.executescript("""
            CREATE TABLE supply_users (
                user_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('planner','dispatcher','risk','auditor')),
                active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
                created_at TEXT NOT NULL
            );
            INSERT INTO supply_users VALUES ('old-dispatch','旧调度','dispatcher',1,'2026-01-01T00:00:00Z');
        """)
        try:
            service = SupplyService(connection)
            service.bootstrap_first_admin("root", "管理员", "local-cli")
            row = connection.execute(
                "SELECT role,role_version,created_by FROM supply_users WHERE user_id='old-dispatch'"
            ).fetchone()
            self.assertEqual(row["role"], "dispatcher")
            self.assertEqual(row["role_version"], 1)
            self.assertIsNone(row["created_by"])
            self.assertEqual(connection.execute(
                "SELECT created_by FROM supply_users WHERE user_id='root'"
            ).fetchone()[0], "system:bootstrap")
            # 迁移幂等。
            SupplyService(connection)
            self.assertEqual(connection.execute(
                "SELECT count(*) FROM supply_users WHERE user_id='old-dispatch'"
            ).fetchone()[0], 1)
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
