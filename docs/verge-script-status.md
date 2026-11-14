# Verge 脚本扩展：当前进度与接入条件

目前 `internal/vergescript` 提供隔离执行原型，`migration.ReadArchivedScripts` 可以从迁入快照读取 `Script` 全局脚本和订阅引用脚本。单次存档快照与分阶段合成原型可保留全局合并、全局脚本、订阅合并、订阅脚本的顺序。GUI、CLI 和 MCP 可显式请求只读预览，桌面及 Headless 使用同一内核校验路径；预览不会启用脚本，内核运行路径尚未支持脚本。迁入本身不会执行脚本，也不会更改脚本文件。

[Verge 脚本说明](https://github.com/clash-verge-rev/clash-verge-rev.github.io/blob/be157f475583a5516bdc0cf6c197768339b1cfea/docs/guide/script.md) 定义 `main(config, profileName)`；[其配置合成实现](https://github.com/clash-verge-rev/clash-verge-rev/blob/bab4cd14cb24ed8e96fd2d7e8948fd2d6666d507/src-tauri/src/enhance/mod.rs) 在全局合并后执行全局脚本，在订阅合并后执行订阅脚本，并恢复受设置管理的字段。当前 NetFlow 的合成顺序不同，不能简单地在已有合并之后追加两段脚本并声称完全兼容。

当前原型采用 QuickJS WASM，未挂载宿主目录、环境变量或套接字；受时间、并发及线性内存上限约束。仅有这些隔离措施不能证明不存在运行时漏洞。脚本错误不会回显用户配置；`console` 暂时丢弃输出。为使预览可复现，执行器使用调用方指定的固定时间及确定性随机源；这与依赖实时日期或随机值的原版脚本行为不同，今后启用时必须向用户明确说明。预览原型重复执行并绑定输入、脚本、订阅名称、时间和输出的摘要，但这不等于内核校验，也不能代替应用时核对实际输出。YAML 转 JSON 会展开别名与合并，保留映射顺序并拒绝无法明确表示的类型。官方脚本使用的 API 或 JavaScript 行为与 QuickJS 仍可能不同。

内部预览准备器还提供完整规则分页、敏感值不回显的顶层变更摘要、校验和状态检查回调，并会在校验后重新检查存档。CLI/MCP 预览接入了现有隔离校验进程和当前运行状态检查；准备器独立使用时仍须由接入方提供这些能力。预览结果不能用于应用。顶层字段摘要不展示字段的具体变化，不能代替用户审查 DNS、节点、控制接口等配置。预览结果及分页会返回规则，而规则可能含有敏感信息。

在订阅卡片右键菜单中选择“预览 Verge 脚本”，可勾选脚本并分页查看规则。在已运行的 GUI 或 Headless 实例上，也可以向 `netflow-agent verge-script-preview` 的标准输入发送 `{"profile_id":"订阅ID","global":true,"profile":true}`。返回的 `preview_id` 可用于 `verge-script-preview-rules ID before|after [OFFSET [LIMIT]]` 和 `verge-script-preview-cancel ID`；两分钟后预览过期。MCP 对应工具是 `netflow_preview_verge_script`、`netflow_verge_script_preview_rules` 和 `netflow_cancel_verge_script_preview`。脚本必须由请求显式选择；若当前未启用存档数据扩展，预览会同时模拟启用它们并给出提示。

接入前仍需完成：

- 明确迁入规则、全局和订阅合并及脚本的顺序，并保留现有 Agent 全局、订阅和连接规则语义；验证 DNS、TUN、控制接口等受管理字段。
- GUI、CLI 和 MCP 提供显式启用；应用必须绑定具体脚本、配置、存档、有效输出和运行状态摘要，过期或变化后拒绝应用；支持关闭、回滚及失败恢复。
- 验证运行时与特权 TUN 工作进程、订阅更新、并发关闭和崩溃恢复；隔离 Windows 来宾执行迁入和全流程回归，评估不同脚本及大配置的兼容性和资源使用。
