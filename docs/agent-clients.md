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

Agent 操作规则时，先调用 `netflow_preview_rewrite` 或 `netflow_preview_rollback` 检查范围、规则和警告，再明确调用 `netflow_apply_rewrite`；过期或状态变化后的提案需要重新预览。若预览显示规则被截断，通过 `netflow_preview_rules` 和 `next_offset` 分页查看完整内容；不需要的提案可用 `netflow_cancel_preview` 释放。连接级匹配器影响之后符合条件的连接，不会重新路由已有连接。可用 `netflow_rewrite_history` 查看可回滚版本。Agent 状态与预览可能包含连接元数据或用户规则；发送给模型的内容由所选客户端及其服务处理。

链式代理使用独立的预览和应用流程：先用 `netflow_proxy_groups` / `netflow_proxy_group_nodes` 查询节点及 `provider`，调用 `netflow_preview_chain` 提供目标组和按入口到出口排序的节点，再用 `netflow_apply_chain` 应用。`netflow_chain_status` 报告链路是否仍配置及节点结构是否可用，不能代替网络连通性测试；`netflow_disconnect_chain` 尝试恢复原选择，`netflow_cancel_chain_preview` 释放未应用提案。规则模式只影响选定组，全局模式使用 GLOBAL；已有连接不重新路由。链路为当前进程临时状态，退出后不会自动重连。

可对某个组中的节点执行实际网络测速：CLI 从标准输入读取参数，例如 `'{"group":"Select","node":"DIRECT","timeout_ms":3000}' | & $agent delay-test`，再用返回的 `job_id` 调用 `& $agent delay-job-status '<job_id>'`。MCP 对应 `netflow_test_proxy_delay` 和 `netflow_delay_job_status`。可选 `url` 为 HTTP(S) 地址，省略时使用 GUI 已保存的全局测速地址；`timeout_ms` 范围为 100–60000，省略时使用已保存超时。界面中临时填写的组地址不会自动传给 Agent。请求经过所选节点，目标服务会收到测速请求；任务结果不返回 URL，但地址及节点名仍由所选 MCP 客户端处理。最多 8 个任务同时排队或运行，完成结果保留十分钟；关闭程序后任务不再保留。

从 GUI 复制提案 ID 后，分页查看期间应保持该规则编辑器打开；编辑规则、更换历史版本或关闭编辑器会丢弃其提案，应用或取消后也不能再读取该提案。提案最多有效两分钟。

本机已用 Codex 桌面应用附带的 CLI `0.169.0-alpha.11.1` 通过临时命令行配置验证 `mcp get` 能识别安装版路径。机器上另有独立安装的 Codex CLI `0.118.0`，该旧版本遇到本机原有的 `service_tier = "default"` 时需要兼容设置才能加载配置；桌面应用附带版本可以读取该配置。Claude Code 2.1.117 已在独立临时项目中注册安装版并通过 `claude mcp get` 的连接检查，未改写用户或其他项目配置。MCP 的初始化、工具列表和实际调用另由 NetFlow 的 Windows 冒烟测试覆盖；这些检查不代表所有客户端版本均已验证。
