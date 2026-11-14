# Verge 脚本扩展：当前进度与接入条件

`migration.ReadArchivedScripts` 可以从迁入快照读取 `Script` 全局脚本和订阅引用脚本。单次存档快照与分阶段合成保留全局合并、全局脚本、订阅合并、订阅脚本的顺序。GUI、CLI 和 MCP 提供预览、单独应用和上一份设置的回滚预览；桌面及 Headless 使用同一内核校验路径。内核运行时使用已批准的固定输出，不重新执行 JavaScript。迁入本身不会执行脚本，也不会更改脚本文件。

[Verge 脚本说明](https://github.com/clash-verge-rev/clash-verge-rev.github.io/blob/be157f475583a5516bdc0cf6c197768339b1cfea/docs/guide/script.md) 定义 `main(config, profileName)`；[其配置合成实现](https://github.com/clash-verge-rev/clash-verge-rev/blob/bab4cd14cb24ed8e96fd2d7e8948fd2d6666d507/src-tauri/src/enhance/mod.rs) 在全局合并后执行全局脚本，在订阅合并后执行订阅脚本，并恢复受设置管理的字段。当前 NetFlow 的合成顺序不同，不能简单地在已有合并之后追加两段脚本并声称完全兼容。

执行器采用 QuickJS WASM，未挂载宿主目录、环境变量或套接字；受时间、并发及线性内存上限约束。仅有这些隔离措施不能证明不存在运行时漏洞。脚本错误不会回显用户配置；`console` 暂时丢弃输出。为使预览可复现，执行器使用固定时间及确定性随机源；这与依赖实时日期或随机值的原版脚本行为不同。预览重复执行并绑定输入、脚本、订阅名称、时间和输出摘要，再执行隔离内核校验；应用时重新核对来源和有效输出。YAML 转 JSON 会展开别名与合并，保留映射顺序并拒绝无法明确表示的类型。官方脚本使用的 API 或 JavaScript 行为与 QuickJS 仍可能不同。

预览提供完整规则分页、敏感值不回显的顶层变更摘要和来源检查。顶层字段摘要不展示字段的具体变化；界面可显式选择“查看完整配置”，CLI 和 MCP 也提供全文分页。完整配置可能含订阅凭据，规则同样可能包含敏感信息。预览有效期最多两分钟，状态、配置、资源或连接规则过期时需要重新预览；应用活动订阅会重载内核，可能中断连接。

合成会恢复由 NetFlow 管理的端口、模式、TUN、监听器和控制接口等字段，这些字段的脚本修改不会生效。缓存按元数据和内容摘要核对，订阅、存档、名称或缓存变化时拒绝加载；缓存包含订阅数据，会随配置备份。脚本输出和更新时保留的私有订阅文件各自最多 128 项、256 MiB；可在脚本对话框中清理未引用文件，或使用 `verge-script-cache-prune` / MCP `netflow_prune_verge_script_cache`；当前和上一份设置引用的文件会保留。清理过程中检测到配置变化会停止，外部进程在最终检查后的并发修改仍有短暂竞争窗口。已启用脚本的远程订阅可下载并预览更新，复用当前批准的脚本选择，离线校验后须另行应用；上一份订阅文件和脚本设置可一起预览回滚。自动更新和更换链接仍不会自动重新批准脚本。当前只保留上一份设置，回滚时所需的原输入和缓存仍必须可用；存档不可用时可预览关闭脚本及存档数据扩展。订阅更新与失败恢复可能留下未引用的私有文件，可按需清理。

关闭脚本后重命名、更新订阅或更换链接时，会保留上一份脚本设置所需的订阅文件、名称、链接和流量信息，以便预览回滚；保留的旧链接及备份可能包含凭据。旧版产生的历史记录未包含链接或名称时，回滚沿用当前值。

在订阅卡片右键菜单中选择“预览 Verge 脚本”，可勾选脚本、分页查看并单独应用；全不选可关闭脚本。已启用脚本的远程订阅可选择“按已启用脚本预览订阅更新”。CLI 的 `verge-script-preview` 从标准输入读取 `{"profile_id":"订阅ID","global":true,"profile":true}`，返回的 ID 可用于 `verge-script-apply ID`；`verge-script-update-preview PROFILE` 下载并预览订阅更新，`verge-script-rollback-preview PROFILE` 预览上一份设置。`verge-script-preview-rules` 和 `verge-script-preview-config` 分别按规则和 UTF-8 字节分页，后者必须使用上一页的 `next_offset`。MCP 提供 `netflow_preview_verge_script`、`netflow_preview_verge_subscription_update`、`netflow_apply_verge_script`、`netflow_preview_verge_script_rollback`、规则和配置分页及取消工具。全局脚本按所选订阅单独批准，并非对所有订阅一次性生效。

迁入规则存储为 NetFlow 订阅规则并在脚本后应用，与原 Verge 的部分脚本观察顺序不同；Agent 的连接、订阅和全局规则也在脚本后应用。自动订阅更新、更多脚本 API、并发关闭和崩溃恢复仍需扩大兼容与真实环境验证，不能声称与 Verge 完全等价。
