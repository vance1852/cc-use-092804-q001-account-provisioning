"""账号建立链路的授权边界、并发确定性与审计可见性测试。"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

import embodied_ai.api as embodied_api
import robot_control.api as control_api
from embodied_ai.service import TrialService
from embodied_ai.storage import connect as trial_connect
from embodied_ai.storage import initialize as trial_initialize
from robot_control.service import SupplyService
from robot_control.storage import connect as supply_connect


class TrialAccessControlTests(unittest.TestCase):
    """embodied_ai（AI 准入域）的账号治理边界。"""

    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.service = TrialService(self.connection)
        self.service.bootstrap_admin("root", "平台管理员")
        self.service.create_user("root", "op", "操作员", "operator")
        self.service.create_user("root", "reviewer", "审批员", "approver")

    def tearDown(self) -> None:
        self.connection.close()

    def test_anonymous_or_forged_identity_cannot_register_privileged_role(self) -> None:
        from embodied_ai.errors import Forbidden, NotFound

        with self.assertRaises(NotFound):
            self.service.create_user("ghost", "mallory", "攻击者", "approver")
        with self.assertRaises(Forbidden):
            self.service.create_user("op", "mallory", "攻击者", "approver")
        row = self.connection.execute("SELECT count(*) FROM users WHERE user_id='mallory'").fetchone()
        self.assertEqual(row[0], 0)

    def test_bootstrap_runs_once_and_never_overwrites(self) -> None:
        from embodied_ai.errors import Conflict

        with self.assertRaises(Conflict):
            self.service.bootstrap_admin("root2", "第二个管理员")
        with self.assertRaises(Conflict):
            self.service.bootstrap_admin("op", "覆盖既有账号")
        row = self.connection.execute("SELECT role FROM users WHERE user_id='op'").fetchone()
        self.assertEqual(row[0], "operator")
        admins = self.connection.execute("SELECT count(*) FROM users WHERE role='admin'").fetchone()
        self.assertEqual(admins[0], 1)

    def test_failed_creation_leaves_no_partial_user_or_audit(self) -> None:
        from embodied_ai.errors import Conflict

        self.service.create_user("root", "dup", "第一次", "operator")
        events_before = self.connection.execute("SELECT count(*) FROM audit_events").fetchone()[0]
        with self.assertRaises(Conflict):
            self.service.create_user("root", "dup", "第二次", "approver")
        row = self.connection.execute("SELECT role, role_revision FROM users WHERE user_id='dup'").fetchone()
        self.assertEqual((row[0], row[1]), ("operator", 1))
        self.assertEqual(self.connection.execute("SELECT count(*) FROM audit_events").fetchone()[0], events_before)

    def test_role_change_requires_distinct_permission_and_bumps_revision(self) -> None:
        from embodied_ai.errors import Forbidden, ValidationFailed

        with self.assertRaises(Forbidden):
            self.service.change_user_role("reviewer", "op", "approver")
        changed = self.service.change_user_role("root", "op", "statistician")
        self.assertEqual(changed["role_revision"], 2)
        self.assertEqual(changed["granted_by"], "root")
        with self.assertRaises(ValidationFailed):
            self.service.change_user_role("root", "op", "statistician")

    def test_last_admin_cannot_be_demoted_or_deactivated(self) -> None:
        from embodied_ai.errors import Conflict

        with self.assertRaises(Conflict):
            self.service.change_user_role("root", "root", "auditor")
        with self.assertRaises(Conflict):
            self.service.deactivate_user("root", "root")

    def test_deactivation_takes_effect_immediately(self) -> None:
        from embodied_ai.errors import Forbidden, InvalidState

        self.service.deactivate_user("root", "reviewer")
        with self.assertRaises(Forbidden):
            self.service.decide("reviewer", "batch-x", 1, "approved", "越权尝试")
        with self.assertRaises(InvalidState):
            self.service.deactivate_user("root", "reviewer")

    def test_auditor_sees_grantor_role_revision_and_denial_reasons(self) -> None:
        from embodied_ai.errors import Forbidden, NotFound

        self.service.create_user("root", "aud", "审计员", "auditor")
        with self.assertRaises(Forbidden):
            self.service.create_user("op", "mallory", "攻击者", "approver")
        with self.assertRaises(NotFound):
            self.service.register_robot("ghost", "robot-x", "型号", "厂商")
        directory = self.service.list_users("aud")
        op_row = next(row for row in directory["users"] if row["user_id"] == "op")
        self.assertEqual((op_row["granted_by"], op_row["role_revision"]), ("root", 1))
        bootstrap_row = next(row for row in directory["users"] if row["user_id"] == "root")
        self.assertIsNone(bootstrap_row["granted_by"])
        denied = self.service.user_audit("aud", "op")["events"]
        self.assertEqual(denied[-1]["event_type"], "auth.denied")
        self.assertIn("user.create", denied[-1]["payload"]["reason"])
        forged = self.service.user_audit("aud", "ghost")["events"]
        self.assertEqual(forged[-1]["payload"]["reason"], "用户不存在: ghost")

    def test_business_roles_cannot_read_user_directory(self) -> None:
        from embodied_ai.errors import Forbidden

        with self.assertRaises(Forbidden):
            self.service.list_users("op")

    def test_api_exposes_governance_boundaries(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            app = embodied_api.JsonApplication(TrialService(connection))
            payload = json.dumps({"user_id": "x", "display_name": "X", "role": "approver"}).encode()
            self.assertEqual(app.handle("POST", "/users", body=payload).status, 422)
            forged = app.handle("POST", "/users", {"X-Actor-Id": "ghost"}, payload)
            self.assertEqual(forged.status, 404)
            boot = app.handle("POST", "/users/bootstrap", body=json.dumps({"user_id": "root", "display_name": "管理员"}).encode())
            self.assertEqual(boot.status, 201)
            replay = app.handle("POST", "/users/bootstrap", body=json.dumps({"user_id": "root2", "display_name": "管理员"}).encode())
            self.assertEqual(replay.status, 409)
            created = app.handle("POST", "/users", {"X-Actor-Id": "root"}, payload)
            self.assertEqual(created.status, 201)
            denied = app.handle("POST", "/users", {"X-Actor-Id": "x"}, payload)
            self.assertEqual(denied.status, 403)
        finally:
            connection.close()


class SupplyAccessControlTests(unittest.TestCase):
    """robot_control（控制资源分配域）的账号治理边界。"""

    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.service = SupplyService(self.connection)
        self.service.bootstrap_admin("root", "平台管理员")
        self.service.create_user("root", "dispatch", "调度员", "dispatcher")

    def tearDown(self) -> None:
        self.connection.close()

    def test_dispatcher_cannot_self_register_dispatcher(self) -> None:
        from robot_control.errors import Forbidden, NotFound

        with self.assertRaises(NotFound):
            self.service.create_user("ghost", "mallory", "攻击者", "dispatcher")
        with self.assertRaises(Forbidden):
            self.service.create_user("dispatch", "mallory", "攻击者", "dispatcher")
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM supply_users WHERE user_id='mallory'").fetchone()[0],
            0,
        )

    def test_bootstrap_conflict_keeps_existing_accounts_and_history(self) -> None:
        from robot_control.errors import Conflict

        events_before = self.connection.execute("SELECT count(*) FROM supply_audit_events").fetchone()[0]
        with self.assertRaises(Conflict):
            self.service.bootstrap_admin("root2", "第二个管理员")
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM supply_users WHERE role='admin'").fetchone()[0],
            1,
        )
        self.assertEqual(
            self.connection.execute("SELECT count(*) FROM supply_audit_events").fetchone()[0],
            events_before,
        )

    def test_role_change_and_deactivation_are_audited_with_grantor(self) -> None:
        from robot_control.errors import Forbidden

        self.service.create_user("root", "aud", "审计员", "auditor")
        changed = self.service.change_user_role("root", "dispatch", "risk")
        self.assertEqual((changed["role"], changed["role_revision"]), ("risk", 2))
        with self.assertRaises(Forbidden):
            self.service.submit_nomination("dispatch", {"nomination_id": "n-1"})
        self.service.deactivate_user("root", "dispatch")
        directory = self.service.list_users("aud")
        row = next(item for item in directory["users"] if item["user_id"] == "dispatch")
        self.assertEqual((row["granted_by"], row["active"]), ("root", 0))
        events = self.service.user_audit("aud", "dispatch")["events"]
        self.assertEqual(
            [event["event_type"] for event in events],
            ["user.created", "user.role_changed", "auth.denied", "user.deactivated"],
        )
        self.assertEqual(events[1]["payload"]["to_role"], "risk")
        self.assertTrue(self.service.audit_chain("aud")["valid"])

    def test_denial_events_join_hash_chain(self) -> None:
        from robot_control.errors import Forbidden

        self.service.create_user("root", "aud", "审计员", "auditor")
        with self.assertRaises(Forbidden):
            self.service.create_user("dispatch", "mallory", "攻击者", "dispatcher")
        self.assertTrue(self.service.audit_chain("aud")["valid"])

    def test_api_requires_real_admin_for_user_creation(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            app = control_api.JsonApplication(SupplyService(connection))
            payload = json.dumps({"user_id": "mallory", "display_name": "攻击者", "role": "dispatcher"}).encode()
            self.assertEqual(app.handle("POST", "/users", {"X-Actor-Id": "anyone"}, payload).status, 404)
            app.handle("POST", "/users/bootstrap", body=json.dumps({"user_id": "root", "display_name": "管理员"}).encode())
            self.assertEqual(app.handle("POST", "/users", {"X-Actor-Id": "root"}, payload).status, 201)
            self.assertEqual(app.handle("POST", "/users", {"X-Actor-Id": "mallory"}, payload).status, 403)
            directory = app.handle("GET", "/users", {"X-Actor-Id": "root"})
            self.assertEqual(directory.status, 403)
        finally:
            connection.close()


class PersistenceAndConcurrencyTests(unittest.TestCase):
    """并发确定结果、重启一致性与旧库迁移。"""

    def test_concurrent_creation_of_same_account_has_single_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trial.sqlite3"
            setup = TrialService(trial_connect(path))
            setup.bootstrap_admin("root", "平台管理员")
            results: list[str] = []
            barrier = threading.Barrier(2)

            def attempt(name: str) -> None:
                service = TrialService(trial_connect(path))
                try:
                    barrier.wait(timeout=10)
                    service.create_user("root", "same-user", "并发账号", "approver")
                    results.append(name)
                except Exception:
                    results.append("conflict")
                finally:
                    service.connection.close()

            threads = [threading.Thread(target=attempt, args=(f"worker-{index}",)) for index in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)
            self.assertEqual(results.count("conflict"), 1)
            self.assertEqual(len([item for item in results if item != "conflict"]), 1)
            check = TrialService(trial_connect(path))
            try:
                rows = check.connection.execute("SELECT * FROM users WHERE user_id='same-user'").fetchall()
                self.assertEqual(len(rows), 1)
                created = check.connection.execute(
                    "SELECT count(*) FROM audit_events WHERE entity_type='user' AND entity_id='same-user' AND event_type='user.created'"
                ).fetchone()[0]
                self.assertEqual(created, 1)
            finally:
                check.connection.close()
            setup.connection.close()

    def test_restart_preserves_permissions_and_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "supply.sqlite3"
            first = SupplyService(supply_connect(path))
            first.bootstrap_admin("root", "平台管理员")
            first.create_user("root", "dispatch", "调度员", "dispatcher")
            first.change_user_role("root", "dispatch", "planner")
            events_before = first.connection.execute("SELECT count(*) FROM supply_audit_events").fetchone()[0]
            first.connection.close()
            second = SupplyService(supply_connect(path))
            try:
                from robot_control.errors import Forbidden

                second.create_user("root", "aud", "审计员", "auditor")
                listing = second.list_users("aud")
                dispatch = next(row for row in listing["users"] if row["user_id"] == "dispatch")
                self.assertEqual((dispatch["role"], dispatch["role_revision"], dispatch["granted_by"]), ("planner", 2, "root"))
                with self.assertRaises(Forbidden):
                    second.create_user("dispatch", "mallory", "攻击者", "dispatcher")
                events_after = second.connection.execute("SELECT count(*) FROM supply_audit_events").fetchone()[0]
                self.assertGreaterEqual(events_after, events_before + 2)
            finally:
                second.connection.close()

    def test_legacy_trial_database_is_migrated_without_data_loss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.sqlite3"
            connection = sqlite3.connect(path, isolation_level=None)
            connection.execute(
                "CREATE TABLE users (user_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, "
                "role TEXT NOT NULL CHECK (role IN ('operator','statistician','approver','auditor')), "
                "active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)))"
            )
            connection.execute("INSERT INTO users VALUES('legacy-op','旧操作员','operator',1)")
            connection.execute(
                "CREATE TABLE legacy_batches (batch_id TEXT PRIMARY KEY, "
                "created_by TEXT NOT NULL REFERENCES users(user_id))"
            )
            connection.execute("INSERT INTO legacy_batches VALUES('b-1','legacy-op')")
            connection.close()
            migrated = TrialService(trial_connect(path))
            try:
                row = migrated.connection.execute("SELECT * FROM users WHERE user_id='legacy-op'").fetchone()
                self.assertEqual((row["role"], row["role_revision"], row["granted_by"]), ("operator", 1, None))
                history = migrated.connection.execute("SELECT * FROM legacy_batches").fetchall()
                self.assertEqual(len(history), 1)
                migrated.bootstrap_admin("root", "平台管理员")
                migrated.create_user("root", "new-approver", "审批员", "approver")
                version = migrated.connection.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()[0]
                self.assertEqual(version, "3")
            finally:
                migrated.connection.close()

    def test_legacy_supply_database_is_migrated_without_data_loss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy-supply.sqlite3"
            connection = sqlite3.connect(path, isolation_level=None)
            connection.execute(
                "CREATE TABLE supply_users (user_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, "
                "role TEXT NOT NULL CHECK(role IN ('planner','dispatcher','risk','auditor')), "
                "active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), created_at TEXT NOT NULL)"
            )
            connection.execute("INSERT INTO supply_users VALUES('legacy-plan','旧规划员','planner',1,'2026-09-01T00:00:00Z')")
            connection.close()
            migrated = SupplyService(supply_connect(path))
            try:
                row = migrated.connection.execute("SELECT * FROM supply_users WHERE user_id='legacy-plan'").fetchone()
                self.assertEqual((row["role"], row["role_revision"], row["granted_by"]), ("planner", 1, None))
                migrated.bootstrap_admin("root", "平台管理员")
                migrated.create_user("root", "new-dispatch", "调度员", "dispatcher")
            finally:
                migrated.connection.close()

    def test_initialize_rerun_does_not_touch_existing_users(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            service = TrialService(connection)
            service.bootstrap_admin("root", "平台管理员")
            service.create_user("root", "op", "操作员", "operator")
            trial_initialize(connection)
            trial_initialize(connection)
            row = connection.execute("SELECT role, role_revision FROM users WHERE user_id='op'").fetchone()
            self.assertEqual((row[0], row[1]), ("operator", 1))
            count = connection.execute("SELECT count(*) FROM users").fetchone()[0]
            self.assertEqual(count, 2)
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
