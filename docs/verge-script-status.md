# Verge 脚本扩展：当前进度与接入条件

目前 `internal/vergescript` 提供隔离执行原型，`migration.ReadArchivedScripts` 可以从迁入快照读取 `Script` 全局脚本和订阅引用脚本。单次存档快照与分阶段合成原型可保留全局合并、全局脚本、订阅合并、订阅脚本的顺序。它们尚未连接 GUI、CLI、MCP 或内核运行路径；迁入不会执行脚本，也不会更改脚本文件。用户现有的行为保持不变。

[Verge 脚本说明](https://github.com/clash-verge-rev/clash-verge-rev.github.io/blob/be157f475583a5516bdc0cf6c197768339b1cfea/docs/guide/script.md) 定义 `main(config, profileName)`；[其配置合成实现](https://github.com/clash-verge-rev/clash-verge-rev/blob/bab4cd14cb24ed8e96fd2d7e8948fd2d6666d507/src-tauri/src/enhance/mod.rs) 在全局合并后执行全局脚本，在订阅合并后执行订阅脚本，并恢复受设置管理的字段。当前 NetFlow 的合成顺序不同，不能简单地在已有合并之后追加两段脚本并声称完全兼容。

当前原型采用 QuickJS WASM，未挂载宿主目录、环境变量或套接字；受时间、并发及线性内存上限约束。仅有这些隔离措施不能证明不存在运行时漏洞。脚本错误不会回显用户配置；`console` 暂时丢弃输出。YAML 转 JSON 会展开别名与合并，保留映射顺序并拒绝无法明确表示的类型。官方脚本使用的 API 或 JavaScript 行为与 QuickJS 仍可能不同。

接入前仍需完成：

- 明确迁入规则、全局和订阅合并及脚本的顺序，并保留现有 Agent 全局、订阅和连接规则语义；验证 DNS、TUN、控制接口等受管理字段。
- GUI、CLI 和 MCP 提供显式启用及预览；校验有效内核配置，绑定具体脚本、配置、存档和运行状态摘要，过期或变化后拒绝应用；支持关闭、回滚及失败恢复。
- 验证运行时与特权 TUN 工作进程、订阅更新、并发关闭和崩溃恢复；隔离 Windows 来宾执行迁入和全流程回归，评估不同脚本及大配置的兼容性和资源使用。
