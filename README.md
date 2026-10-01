# 封住电子架构平台的越权账号入口基础平台

本项目是一套可离线运行的 Python 服务端平台，服务于具身智能机器人控制域、AI 计算域和国产电子部件质量域。平台管理控制计算节点、实时控制总线、资源时隙、机器人构建、验证测量、分析租约、部件批次与质量决定，业务状态、幂等结果和审计事件保存在 SQLite 中。

## 目录

- `src/robot_control/`：控制节点、实时总线、资源批次、时隙申请、容量分配和架构情景；
- `src/embodied_ai/`：机器人构建、验证协议、测量导入、排除复核、分析任务和准入决定；
- `src/component_qualification/`：国产电子部件批次、信号测量、统计分析、账号权限和质量审批；
- `fixtures/`：离线验收使用的验证协议与结构化测量；
- `tests/`：领域规则、事务、权限、HTTP API 和命令行验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m robot_control.acceptance --workspace .
PYTHONPATH=src python3 -m embodied_ai.acceptance --workspace .
PYTHONPATH=src python3 -m component_qualification.acceptance
```

三条命令会在临时 SQLite 数据库中完成控制资源分配、AI 验证分析和国产电子部件质量流程，不访问外部网络。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m robot_control.api --database robot-control.sqlite3 --host 127.0.0.1 --port 8080
PYTHONPATH=src python3 -m embodied_ai.api --database embodied-ai.sqlite3 --host 127.0.0.1 --port 8081
PYTHONPATH=src python3 -m component_qualification.api --database component.sqlite3 --host 127.0.0.1 --port 8082
```

服务提供 JSON 接口与健康检查。进程重启后可以继续读取 SQLite 中的业务状态和审计历史。

## 账号治理

控制资源域（`robot_control`）与 AI 准入域（`embodied_ai`）的账号建立链路实行显式授权边界：

- `POST /users/bootstrap`：首个管理员初始化，仅在系统从未有过管理员时可用，重跑返回冲突且不覆盖已有账号与历史审计；
- `POST /users`：日常新增，要求操作者具备 `user.create` 权限（`X-Actor-Id` 必须是真实有效的管理员账号）；
- `POST /users/{id}/role`：角色变更，要求 `user.role_change` 权限，角色版本（`role_revision`）递增并记录授权者；
- `POST /users/{id}/deactivate`：停用，要求 `user.deactivate` 权限，停用即刻生效；
- `GET /users` 与 `GET /users/{id}/audit`：安全审计视角（`audit.read` 权限），可查看每个账号的授权者、角色版本以及全部授权拒绝记录（含伪造身份尝试）。

三类账号权限互不混用，业务角色不具备任何账号管理能力；系统始终保留至少一名可用管理员。所有授权与拒绝事件写入 SQLite 审计表（控制资源域为哈希链），重启后权限与审计保持一致。
