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
# 控制资源调度域：先在本机初始化首个管理员，再启动服务
PYTHONPATH=src python3 -m robot_control.api --database robot-control.sqlite3 \
  --bootstrap-admin-id root --bootstrap-admin-name 安全管理员
PYTHONPATH=src python3 -m robot_control.api --database robot-control.sqlite3 --host 127.0.0.1 --port 8080

# AI 计算准入域：同样先初始化首个管理员
PYTHONPATH=src python3 -m embodied_ai.api --database embodied-ai.sqlite3 \
  --bootstrap-admin-id root --bootstrap-admin-name 安全管理员
PYTHONPATH=src python3 -m embodied_ai.api --database embodied-ai.sqlite3 --host 127.0.0.1 --port 8081

# 国产电子部件质量域：首个管理员口令必须由带外环境变量提供，代码不内置默认口令
CQ_ADMIN_PASSWORD='至少12位强口令' \
  PYTHONPATH=src python3 -m component_qualification.api --database component.sqlite3 --host 127.0.0.1 --port 8082
```

服务提供 JSON 接口与健康检查。进程重启后可以继续读取 SQLite 中的业务状态和审计历史。

## 账号与授权边界

- **首个管理员初始化**：`POST /bootstrap` 是唯一允许匿名的账号动作，仅当系统尚无在职管理员、且请求带与服务端带外预置值 `--bootstrap-code` 一致的注册码时才成功；也可在服务器本机用 `--bootstrap-admin-id` 直接初始化（初始化后进程退出，不与 HTTP 服务同时运行）。初始化重跑幂等返回，绝不覆盖已有账号和历史操作。
- **日常新增 / 角色变更 / 停用**：分别是 `POST /users`、`POST /users/{id}/role`、`POST /users/{id}/deactivate`，全部要求 `X-Actor-Id` 为在职 `admin`。普通业务接口缺失或伪造身份返回 401，身份存在但权限不足返回 403；停用账号立即失去全部授权。
- **角色版本**：每次角色变更 `role_version` 递增，变更必须携带 `expected_version`，并发下版本不符返回 409，失败不留半成品。
- **并发建号**：并发创建同一账号在数据库层确定为恰好一次成功，其余得到 409。
- **安全可见性**：`GET /users/{id}/history` 与 `GET /security/denials` 向管理员/审计人员展示授权者、角色版本和每次拒绝的原因；调度域账号事件同时进入哈希链审计。

