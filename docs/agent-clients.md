# Agent 客户端接入

NetFlow 将 Agent 能力提供为本机 CLI 和 MCP stdio 服务。先启动 GUI，或在终端运行 `netflow-agent serve` 启动无界面模式；同一配置目录只能运行一个实例。MCP 服务由客户端按需启动，连接正在运行的 NetFlow，退出 MCP 客户端不会关闭 NetFlow。

Windows 安装版在 PowerShell 7 中设置路径：

```powershell
$agent = Join-Path $env:LOCALAPPDATA 'Programs\NetFlow\netflow-agent.exe'
```

Codex CLI 可注册当前用户的 stdio 服务：

```powershell
codex mcp add netflow -- $agent mcp
codex mcp get netflow
```

Claude Code 可在当前项目注册，或将 `project` 改为 `user`：

```powershell
claude mcp add --scope project --transport stdio netflow -- $agent mcp
claude mcp get netflow
```

项目范围的 Claude 配置写入当前项目的 `.mcp.json`；用户范围会修改相应客户端的用户配置。请在希望配置的项目目录运行命令。上述注册由用户显式执行，NetFlow 安装程序不会更改现有 Agent 客户端配置。客户端显示 MCP 已连接只代表 stdio 服务启动成功；请求 `netflow_status` 才能检查 NetFlow 后端是否运行。如客户端无法读取它自己的配置，需要先修复该客户端的配置或版本。

macOS ARM64 应用中的命令位于 `NetFlow.app/Contents/Resources/netflow-agent`。安装到 `/Applications` 时可在终端使用以下命令；macOS 包尚未在 Mac 上运行验证：

```sh
agent='/Applications/NetFlow.app/Contents/Resources/netflow-agent'
codex mcp add netflow -- "$agent" mcp
# 或在目标项目目录中：
claude mcp add --scope project --transport stdio netflow -- "$agent" mcp
```

若使用非默认配置目录，在 `mcp` 前加入 `--config-dir <绝对路径>`；有多个运行实例时，还可在 `mcp` 前指定 `--pid <进程号>`。这些参数也适用于普通 CLI 命令。Windows 路径包含空格时请作为一个参数传递，PowerShell 变量展开如上例所示。

Agent 操作规则时，先调用 `netflow_preview_rewrite` 或 `netflow_preview_rollback` 检查范围、规则和警告，再明确调用 `netflow_apply_rewrite`；过期或状态变化后的提案需要重新预览。连接级匹配器影响之后符合条件的连接，不会重新路由已有连接。可用 `netflow_rewrite_history` 查看可回滚版本。Agent 状态与预览可能包含连接元数据或用户规则；发送给模型的内容由所选客户端及其服务处理。

本机已用 Codex CLI 0.118.0 的临时命令行配置验证 `mcp get` 能识别安装版路径；该版本遇到本机原有的 `service_tier = "default"` 时需要使用兼容设置才能加载配置。Claude Code 2.1.117 已在独立临时项目中注册安装版并通过 `claude mcp get` 的连接检查，未改写用户或其他项目配置。MCP 的初始化、工具列表和实际调用另由 NetFlow 的 Windows 冒烟测试覆盖；这些检查不代表所有客户端版本均已验证。
