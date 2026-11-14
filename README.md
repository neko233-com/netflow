# NetFlow

NetFlow 是一个使用 Go、[MyGo](https://github.com/egoist/mygo) GPU 原生 UI 和 [mihomo](https://github.com/MetaCubeX/mihomo) 的桌面代理客户端，目标是逐步实现 Clash Verge 的常用功能。界面不是网页，也不需要 WebView。内核目前使用 [基于 mihomo v1.19.33 的公开补丁版本](https://github.com/neko233-com/mihomo/tree/v1.19.33-netflow.12)，修复日志等级、规则集合更新等并发问题，支持 Agent 离线校验及安全的集合缓存快照。

**目前是开发预览版，尚未达到 Clash Verge 功能对等，也不建议替代现有稳定客户端。** 本项目从 [Clash Go](https://github.com/charlzyx/clash-go) 的 `0a0fd79` 版本开始，保留上游 MIT 许可和署名，正进行 Windows 适配。

## 下载

从 [GitHub Releases](https://github.com/neko233-com/netflow/releases) 下载 Windows x64 MSI 或便携 ZIP，或 macOS 13 及以上 Apple Silicon 的应用 ZIP。MSI 为当前用户安装到 `%LOCALAPPDATA%\Programs\NetFlow`，卸载和升级保留 `%APPDATA%\netflow` 中的用户数据。macOS 包在 Windows 上交叉构建，未在 Mac 上运行验证，也未进行 Apple 开发者签名和公证；Gatekeeper 可能阻止打开。Windows 文件同样未进行代码签名。

## GUI 与无界面模式

安装包同时包含图形界面和命令行。双击 `NetFlow.exe` 启动图形界面；在终端运行以下命令启动前台无界面服务，默认启用 TUN：

```powershell
$agent = "$env:LOCALAPPDATA\Programs\NetFlow\netflow-agent.exe"
& $agent serve
```

Windows 开启 TUN 可能请求管理员授权；服务就绪后会输出包含 `ready`、`headless` 和 `tun` 的 JSON。在另一个终端可运行 `& $agent status`、`& $agent shutdown` 及下面的 Agent 命令；`shutdown` 确认收到关闭请求后返回，GUI 实例会拒绝此命令。等待 `serve` 进程退出，确认内核已停止并恢复路由。前台终端按 Ctrl+C 也会请求干净退出；若启动器意外退出，子进程会检测控制管道关闭并退出。测试和诊断时可以使用 `serve --tun=false` 启动内核而不启用 TUN，再用 `tun on` 显式开启；不会修改系统代理设置。

设置文件在运行中被外部修改或无法读取时，`status` 会显示 `settings_warning`，开启 TUN 前会拒绝已知的设置冲突。关闭 TUN 时即使设置保存失败，也会保持 TUN 关闭并报告错误；外部文件不会被覆盖，请检查文件后重启。最终写入与外部修改之间仍存在短暂竞争窗口。

GUI 和无界面模式启动时都会先清除上次运行遗留的 TUN 状态；GUI 仅在明确启用“启动时请求虚拟网卡”后重新请求开启，headless 则按 `serve` 参数决定。清除状态失败时启动会报错，不会据此直接启动 TUN。

GUI 与无界面服务使用同一配置目录锁，不能同时操作同一个目录；如需独立实例，可在命令名前提供 `--config-dir <绝对路径>` 并确保网络端口、TUN 和路由不冲突。无界面模式不创建应用窗口；Agent MCP 的 `netflow_shutdown_headless` 可请求关闭。macOS 构建包含相同入口，但尚未在 Mac 上验证运行。

## 当前状态

- 已接入 mihomo 内核、订阅 URL 导入、配置激活、代理组切换、节点测速、代理与规则集合更新、模式切换、规则和连接显示、日志与托盘界面。部分功能仍需更完整的真实环境回归。
- TUN 特权内核中的 HTTP 代理和规则集合缓存会定期同步到用户配置目录；手动更新后立即同步，关闭内核时再同步一次。回写前会比较用户文件与原始快照，发现修改、删除、联接路径或不安全路径时保留用户文件并报告警告；其他可安全同步的集合仍会处理。异常终止可能丢失最近一次同步之后的缓存更新，下一次启动可能需要重新下载。文件系统中的外部并发修改仍可能与最终替换发生竞争。
- 系统接入聚焦虚拟网卡（TUN），界面和托盘不再提供系统代理开关。Windows 升级启动时只恢复仍由旧版 NetFlow 持有的系统代理备份，不覆盖其他应用的设置。
- Windows TUN 使用实验性独立特权内核：开启时会请求管理员授权，常见的活动 TUN 网卡会被拒绝以减少冲突。GUI 的“启动时请求虚拟网卡”默认关闭，显式启用后，下次启动会走同样的冲突检查和授权流程；不是免授权服务。当前授权需要使用同一 Windows 账户。隔离 Windows 10 来宾已验证真实 Wintun、四种协议栈、DNS/Fake-IP 流量、切换 TUN 时内存与持久 Fake-IP 映射双向保持，以及正常关闭、桌面进程退出、内核连接断开和强制终止后的路由与 DNS 恢复。普通权限进程将配置文件内容复制至管理员专属临时目录，特权内核不直接打开用户配置树，并禁用外部控制器；此快照不包含链接、运行缓存、桌面应用元数据和 Verge 原始恢复存档，最多 128 MiB、4096 个文件。macOS ARM64 包包含实验性授权内核和隔离配置实现，但尚未在 Mac 上运行验证，不应依赖其 TUN 功能。整体安全性和功能对等尚未完成，不应当作生产支持。Linux Docker 测试覆盖独立网络命名空间中的 IPv4 TUN、规则、DNS/Fake-IP 流量及连接断开后的清理。
- 支持本地文件选择或拖放导入、远程订阅后台下载、按订阅设置自动更新、批量更新与删除、重新激活订阅，并显示服务端提供的订阅流量及到期时间。可设置订阅下载的 User-Agent、超时、代理和证书验证；内核代理或系统手动 HTTP(S) 代理不可用时返回错误，不会改为直连。系统代理选项不处理 PAC、自动检测或绕过列表；同时启用时优先内核代理。删除时会保留当前订阅。Windows 开机自启通过当前用户注册表实现，静默启动依赖托盘；部分设置尚未接入。
- 未选择订阅代理时使用直接连接，不读取 `HTTP_PROXY` 等环境变量；允许用户明确提供 HTTP 订阅，但拒绝从 HTTPS 重定向到 HTTP，并在跳转时移除 `Referer`、跨来源移除认证和 Cookie 头，降低订阅凭据泄露风险。订阅下载最多 8 MiB。
- 代理模式、局域网、IPv6、统一延迟、日志等级和监听端口可在界面中修改，作为全局覆写持久化，不修改订阅原文件；设置失败会尝试恢复。旧版 NetFlow 遗留的系统代理会在升级时安全恢复。部分其他设置控件仍只保存界面偏好，请以实际功能和错误提示为准。
- 首页流量图使用内核连接统计的上传、下载速率，保留最近一分钟的有界内存采样，可切换平滑或线性曲线；进程启动前和重启前的数据不会保留。
- 代理组字母索引支持点击或按设置的延迟悬浮定位，滚动后索引仍可使用；关闭悬浮不影响点击。界面失焦时可暂停周期性重绘，连接与日志仍继续采集。可显示内联图片及公开 HTTP(S) 代理组图标：远程请求使用运行中内核的 DNS 解析公开地址，通过混合端口按该 IP 匹配规则，限制大小并拒绝内网地址，不会绕过内核代理；混合端口不可用时不下载。位图不得超过 512×512 像素，SVG 不允许外部引用。
- 链式代理可在代理页按入口到出口顺序选择 2–8 个节点并连接；规则模式只影响所选目标代理组，全局模式影响 GLOBAL。启用期间目标组只使用链路出口，缺失节点会拒绝而非自动直连，断开后尝试恢复原节点。该配置只在当前进程中生效，不改写订阅；进程重启后需重新连接。已有连接不会重新路由；入口节点不能已有上游代理，集合节点需要可用的本地缓存。链路状态只检查节点和配置，并不证明远端可达。
- TUN 协议栈可跟随订阅，也可持久化覆写为 System、Mixed、gVisor 或 Mips；发布构建包含 gVisor，Tailscale 出站未包含。更改协议栈会重新加载内核。
- DNS 覆写按订阅保存；设置中的编辑器接受 mihomo `dns` 段内容，应用时校验合并后的配置并在内核重载失败时尝试回滚。DNS 监听端口需要自行避免冲突。
- 手动更新 GeoData 会使用当前配置中的 HTTPS 地址，通过正在运行的内核混合代理下载配置目录里已有的数据库，并校验内容；不会回退到直连。更新先保存在用户配置目录中，退出并重新启动 NetFlow 后逐个原子替换，避免覆盖 Windows 正在映射的数据库，也不会只更新 TUN 的临时内核目录。下载期间原文件若被修改，启动时会保留原文件并隔离待更新内容；中断后可继续应用。每个数据库最多 64 MiB，单次最多 120 MiB。此操作需要启用可用的混合端口，不会自动下载尚不存在的数据库。
- “当前配置”显示内核上次成功应用的合成配置，可能包含凭据；查看器最多显示前 256 KiB。订阅文件可从订阅菜单打开，保存后需重新激活；远程订阅更新会覆盖下载前已有的手动编辑，若下载期间检测到文件变化则拒绝提交。
- 运行时可在界面或通过 Agent 创建本地备份并恢复到新目录，也可显式启用定时本地备份，或手动将已有备份上传至 WebDAV。Windows 启动时会尝试用当前账户的 DPAPI 加密旧版设置中的 WebDAV 地址、用户名和密码，成功后从设置中移除这些明文；密文通常无法由其他 Windows 账户或电脑解密。迁移失败时保留原设置并提示。其他平台尚未实现账户保护，旧配置可能仍以明文保存在设置中。WebDAV 页面可按用户操作复制已保存字段或清除单独保存的密码；清除密码不会移除地址中嵌入的凭据。Verge 兼容迁出仍可在退出程序后使用 Agent CLI。
- 订阅菜单可在本地生成分享二维码。二维码包含完整订阅链接，请只向可信设备展示。
- 网络端口由订阅或配置决定。默认使用混合端口 7897、SOCKS 7898、HTTP 7899；端口被其他程序占用时需在配置中调整。默认不开放 HTTP 控制接口；配置显式指定控制接口时，仅允许带密钥的回环 IP 地址。
- 同一配置目录只运行一个 NetFlow 实例；重复启动会尝试显示已有窗口。需要互相隔离的实例时，可为各实例指定不同的 `NETFLOW_CONFIG_DIR` 和监听端口。
- 配置、订阅、规则及 Agent 端点的托管文件操作会拒绝目录联接和最终文件链接，并通过固定目录句柄与原子替换减少越界及部分写入；检测到外部修改时会尽量保留当前文件。最终检查与替换之间仍存在外部并发修改的竞争，配置目录应只允许可信用户写入。配置锁要求文件系统能报告硬链接数量。
- 运行期间设置文件若被外部修改，后续保存会拒绝覆盖并返回错误，应检查后重启；保存已知设置时保留未知顶层字段。最终检查与替换之间仍有极短的外部并发竞争。
- 首页的出口 IP 查询仅在用户点击或开启自动刷新后执行，通过本地代理访问 [IP.SB 的 GeoIP API](https://ip.sb/api/)；该服务会看到代理出口 IP。代理不可用时不会回退到直连查询。

## 本地备份

运行 NetFlow 时，可在“备份设置”中创建本地备份，或使用 Agent 发起后台任务：

```powershell
$agent = "$env:LOCALAPPDATA\Programs\NetFlow\netflow-agent.exe"
& $agent backup-create 'D:\Backups\netflow-live.zip'
& $agent backup-job-status '<上一步返回的 job_id>'
& $agent restore-create 'D:\Backups\netflow-live.zip' 'D:\Restore\netflow-recovered'
& $agent backup-job-status '<恢复任务返回的 job_id>'
```

运行时备份排除 Agent 端点、锁、运行缓存、日志、临时文件和待处理的 GeoData 更新。备份会检查源文件及内容是否变化，检测到变化时失败并需重试；极端的外部并发修改仍不能完全排除。界面恢复时选择备份和上一级文件夹，程序会在其中创建新目录并提供复制目录的操作，不会覆盖正在使用的配置。对应 MCP 工具为 `netflow_backup_create`、`netflow_restore_backup` 和 `netflow_backup_job_status`；退出程序时未完成的任务会取消，任务记录不会保留。异常结束可能留下不完整的备份或新恢复目录，应检查后选择新路径重试。

也可以关闭 NetFlow 后离线备份，并恢复到一个不存在的新目录：

```powershell
$agent = "$env:LOCALAPPDATA\Programs\NetFlow\netflow-agent.exe"
& $agent backup-export 'D:\Backups\netflow.zip'
& $agent --config-dir 'D:\Restore\netflow-recovered' backup-restore 'D:\Backups\netflow.zip'
```

目标归档必须不存在，且位于配置目录之外；恢复目标目录也必须不存在，绝不会覆盖现有配置。备份包含订阅、规则、设置以及原始 Verge 恢复资料，排除运行时 Agent 端点和锁。备份包含敏感数据且未加密，需自行妥善保管；Windows DPAPI 保存的 WebDAV 设置通常只能由原账户和电脑解密。归档中的 SHA-256 用于检查损坏，不能证明归档来自可信来源。最多 4096 个文件、单文件 128 MiB、总计 512 MiB；遇到链接、非普通文件或不可移植的路径会拒绝备份。恢复前校验整份归档；若恢复过程中断或发生写入错误，新目标目录可能保留部分内容，应检查后另选新目录重试。恢复到新目录后，可设置 `NETFLOW_CONFIG_DIR` 指向该目录启动，或在完全退出并自行保管旧配置后手动迁移。

定时备份默认关闭，需在界面选择目录并启用，或通过 Agent 显式设置：

```powershell
& $agent backup-schedule-set on 'D:\Backups' 24
& $agent backup-on-change on  # 可选：显式启用配置变更备份
& $agent backup-schedule
& $agent backup-on-change off
# 可选：先保存受账户保护的 WebDAV 配置，再显式启用自动上传
& $agent backup-webdav on
& $agent backup-webdav off
& $agent backup-schedule-set off
```

对应 MCP 工具为 `netflow_backup_schedule`、`netflow_backup_schedule_set` 和 `netflow_backup_on_change`。频率为 1–168 小时，仅在 GUI 或无界面服务运行时执行，错过计划后下次启动会补做；失败后约 15 分钟重试，状态包含最近错误。每次执行前检查目标目录，已有 30 个 `netflow-auto-*.zip` 文件时停止创建，用户需要手动清理；不会自动删除文件，多个配置实例同时使用一个目录可能超过该上限。关闭定时计划或配置变更备份会尝试取消正在进行的自动备份；异常中断可能留下不完整归档。定时计划本身不进入备份，恢复不会自动启用它。备份不加密，应选择受保护的目录。配置变更备份是独立的显式选项，启用后先创建基线；运行期间约每 30 秒检查文件变化并合并短时间内的变化，保留大小和修改时间的内容修改通过约 10 分钟一次的完整内容核对发现，实际时间受任务和配置活动影响。现有用户不会自动启用此选项。

WebDAV 上传需要明确选择已有的 NetFlow 备份 ZIP。界面可输入本次对话框使用的地址与凭据，或使用已保存配置；默认不保存新输入。Windows 可显式选择保存或替换配置，地址、用户名和密码均使用当前账户的 DPAPI 保护；其他平台暂不支持安全保存新凭据，不会降级写入明文。CLI 的 `webdav-save` 从标准输入读取 `url`、`user`、`password` 并替换已保存配置，`webdav-config` 只返回是否已保存及保护是否可用，`webdav-clear` 删除保存的地址和全部凭据；对应 MCP 工具分别为 `netflow_webdav_save`、`netflow_webdav_config` 和 `netflow_webdav_clear`。正在运行备份任务时不能替换或删除配置。

CLI 的 `webdav-upload` 从标准输入读取 JSON，包含绝对路径 `archive`，以及 `url`、`user`、`password`，也可用 `use_saved: true` 使用已保存配置。对应 MCP 工具为 `netflow_webdav_upload`，任务通过 `backup-job-status` 或 `netflow_backup_job_status` 查询；结果中的 `remote_name` 是新生成的远端文件名。恢复时可通过界面读取列表并选择文件，也可向 CLI `webdav-list` / MCP `netflow_webdav_list` 提供凭据字段并从任务结果的 `remote_names` 读取文件名；随后通过 CLI `webdav-restore` / MCP `netflow_webdav_restore` 提供 `remote_name`、不存在的绝对路径 `destination` 和同样的凭据字段。列表仅包含所选目录下本程序生成格式的直接子项，超过 512 个符合条件的文件时返回错误。

传输只接受 HTTPS，不跟随重定向，也不使用系统代理环境变量；服务器会接收未加密的完整备份。客户端先验证归档并检查文件是否变化，使用随机文件名和 HTTP 条件请求避免符合协议的服务器覆盖同名文件；无法保证服务器正确实现条件请求或持久化数据。失败、取消或网络中断可能在远端留下不完整文件，客户端不会自动删除远端文件。远端恢复先将文件下载到目标上一级目录中的随机临时文件，再完整校验并恢复至全新目录；临时文件和恢复数据的访问权限受目标目录影响，应选择受保护的位置。正常结束或取消时尝试删除临时文件，异常终止可能留下该文件或不完整的新目录，需要手动检查。定时或配置变更备份可通过界面、CLI `backup-webdav on` 或 MCP `netflow_backup_webdav` 显式启用自动上传，默认关闭；需要先保存当前 Windows 账户保护的 WebDAV 配置。程序持久记录待上传的本地备份及内容摘要，失败约 15 分钟后重试；本地备份失败或达到本地数量上限期间，已排队且可重试的远端上传仍会执行。设置被外部修改、保存的凭据变化或归档内容改变时停止发送并在备份状态中报告。队列最多 30 项，满时暂停创建新的自动备份直到有空间；关闭自动上传会放弃待传队列，但不会删除本地或远端文件。上传成功后若程序在记录成功前异常退出，重试可能产生重复远端文件；中断也可能留下不完整文件，均需用户自行检查和清理。

## Agent 规则重写

链式代理也可由 CLI 和 MCP 操作。先运行 `groups` 或 `group-nodes <组名>` 获取节点名、所属组及可选的 `provider`，再预览、检查结果并应用：

```powershell
$request = @{target='Proxy'; hops=@(
  @{name='入口节点'; group='Proxy'},
  @{name='出口节点'; provider='订阅集合'; group='Proxy'}
)} | ConvertTo-Json -Depth 5 -Compress
$preview = $request | & $agent chain-preview | ConvertFrom-Json
& $agent chain-apply $preview.proposal_id
& $agent chain-status
& $agent chain-disconnect
```

无需的预览可用 `chain-cancel-preview <proposal_id>` 取消；提案两分钟后过期。MCP 对应 `netflow_preview_chain`、`netflow_apply_chain`、`netflow_chain_status`、`netflow_cancel_chain_preview` 和 `netflow_disconnect_chain`。链路作用于目标组的新连接，目标组之外的流量按原规则处理。

启动 NetFlow 后，随安装包提供的 `netflow-agent.exe` 支持命令行和 MCP 标准输入输出接口。`tun on` / `tun off` 会请求切换；若返回 `pending`，应通过 `status` 查看 `tun_pending` 与 `tun_error`，开启时可能弹出管理员授权。它通过当前用户配置目录中的临时令牌连接本机随机端口，不监听外网；Windows 上令牌文件以当前用户和 SYSTEM 专用的访问控制列表创建，同一账户下的进程仍能调用该接口。退出程序后临时端点被删除。

`tun-autostart` 查看 GUI 下次启动时是否请求 TUN，`tun-autostart on|off` 修改该偏好，不改变当前 TUN；对应 MCP 工具为 `netflow_tun_autostart` 和 `netflow_set_tun_autostart`。此偏好不影响无界面 `serve`，后者遵循自己的 `--tun` 参数。

```powershell
$agent = "$env:LOCALAPPDATA\Programs\NetFlow\netflow-agent.exe"
& $agent status
'{"scope":"global","operation":"set","layer":{"prepend":["DOMAIN,example.com,DIRECT"]}}' | & $agent preview
& $agent apply '<上一步返回的 proposal_id>'
```

也可以将 `netflow-agent.exe mcp` 配置为 MCP 客户端的 stdio 命令，使用 `netflow_status`、`netflow_preview_rewrite` 和 `netflow_apply_rewrite`。[Codex CLI 和 Claude Code 接入说明](https://github.com/neko233-com/netflow/blob/main/docs/agent-clients.md)包含注册示例及范围说明。隔离环境可传入 `--config-dir <绝对路径>`，必要时可在命令名前传入 `--pid <进程号>`。macOS 对应命令位于 `NetFlow.app/Contents/Resources/netflow-agent`。命令行输出 JSON，错误输出到 stderr；连接超时后应先执行 `status` 核实结果，再决定是否重试。

规则操作的 `scope` 为 `global`、`profile` 或 `connection`，`operation` 为 `set` 或 `clear`。全局/订阅规则也可从订阅页面打开编辑器，在界面中预览并应用。全局/订阅层可设置 `layer.prepend`、`layer.append` 和 `layer.remove`（按原规则字符串精确删除）；订阅层还须提供 `profile_id`。连接层 `set` 需要活动 `connection_id`、已有策略名 `policy` 和 1–86400 秒的 `ttl_seconds`，可选择 `close_existing: true`。顺序是连接规则、订阅前置、全局前置、原规则（去除指定项）、订阅追加、全局追加、原 MATCH 及之后规则。规则持久化在用户目录中，订阅原文件不会因此被改写。

预览在独立进程中离线校验配置和本地规则、代理集合，不会为校验下载或修复 GeoData；配置引用缺失或损坏的 GeoData 时会返回错误，缺少 HTTP 集合缓存时会提示其下载内容未被验证。提案最多有效两分钟，配置、已校验的集合文件、GeoData、订阅、路由模式或 TUN 状态变化后须重新预览，TUN 切换期间不能预览或应用。应用失败时尝试恢复旧规则。连接层根据源 IP、目标域名或 IP、端口及网络匹配**后续连接**，可能同时影响其他符合条件的连接；已建立的连接不能被重新路由，可显式选择关闭原连接。规则只在规则模式下控制路由。Agent 状态包含连接元数据，务必只授予可信程序访问权限。

预览默认只返回变更前后的前 100 条规则，每页还受编码后 256 KiB 上限约束；`rules_before_total`、`rules_after_total` 和对应 `truncated` 字段说明是否有更多内容。用 `preview-rules <proposal_id> before|after [偏移 [数量]]` 或 MCP `netflow_preview_rules` 分页，按返回的 `next_offset` 继续，直到等于 `total`；单次最多请求 500 条。GUI 展示首批结果、总数与警告，可复制提案 ID，通过 CLI/MCP 查看其余内容。用 `cancel-preview <proposal_id>` 或 MCP `netflow_cancel_preview` 可丢弃不再需要的提案。最多保留 32 个待处理提案，所保留的规则文字合计最多 64 MiB；单条规则编码后超过 256 KiB 会被拒绝。Agent 单次响应最多 32 MiB，超过时返回错误。

可以主动回滚指定范围：GUI 的全局或订阅规则编辑器可选择历史版本、预览并应用，离线校验在后台执行；修改输入或关闭编辑器会取消尚未完成的校验。CLI 先运行 `rewrite-history` 查看历史版本，再把例如 `'{"revision":1,"scope":"global"}'` 通过标准输入传给 `rollback-preview`，检查返回的规则和警告后用 `apply <proposal_id>` 应用。订阅范围还需 `profile_id`，连接范围还需 `connection_id`；对应 MCP 工具是 `netflow_rewrite_history`、`netflow_preview_rollback` 和 `netflow_apply_rewrite`。只恢复选择的范围，其余规则保留；订阅必须仍然存在，恢复连接匹配器时原连接必须仍活动且匹配内容未变，并且不会延长原来的到期时间。历史中没有该连接匹配器时，回滚会清除当前匹配器。

规则文件最多保存 8 个历史快照，历史与当前规则共限 4 MiB，空间不足时更早的快照会提前淘汰。快照可能包含曾应用失败的中间状态，应检查预览而非假定它此前生效。历史持久化并包含在备份中，可能保留过期连接的域名或 IP 等匹配信息；可用 `clear-rewrite-history` 或 MCP `netflow_clear_rewrite_history` 清除当前规则文件中的历史并使待应用提案失效。已有备份不受影响。

程序运行时若规则文件被外部修改，预览、应用和到期清理会拒绝覆盖该文件；`status` 的 `rewrite_warning` 会提示检查文件并重启。到期清理无法写入时会尝试重载内核，以移除已经到期的运行时规则；如果重载也失败，规则可能继续生效，应检查警告和日志。最终检查和替换之间仍存在外部并发竞争。

CLI 还提供 `version`、`diagnostics`、`groups`、`rules [偏移 [数量]]`、`select <组> <节点>`、`mode <rule|global|direct>`、`use-profile <订阅 ID>` 和 `close-connection <连接 ID>`。`version` 无需运行桌面程序；其余操作有对应的 `netflow_` MCP 工具。设置页、CLI 和 MCP 的诊断摘要仅包含版本、平台、运行状态及计数，不包含订阅地址、配置目录、错误原文、令牌或连接详情。切换节点、模式、订阅及关闭连接会直接改变运行状态；关闭不存在的连接会返回 `closed: false`。规则覆写仍需要先预览再应用。

`status` 最多返回前 100 条活动连接，并提供 `connections_total`、`connections_truncated`；需要更多时用 `connections [偏移 [数量]]` 或 MCP `netflow_connections`。连接按 ID 排序，每次请求都是新的实时快照，连接增减会使偏移变化，不保证跨页固定视图。`connections` 和 `rules` 每页默认 100 项、最多 500 项，并受编码后 256 KiB 上限约束；按返回的 `next_offset` 继续，直到等于 `total`，规则列表在重载时也可能变化。单条数据超过大小上限时分页返回错误；如果状态的首条连接过大，状态保留其他字段并显示 `connections_warning`。

`status` 中的订阅列表同样最多显示首批，`profiles_total` 与 `profiles_truncated` 标识总数和截断；使用 `profiles [偏移 [数量]]` 或 MCP `netflow_profiles` 翻页。`groups [偏移 [数量]]` / MCP `netflow_proxy_groups` 分页返回代理组及每组首批节点；节点较多时根据 `nodes_total`、`nodes_truncated` 使用 `group-nodes <组名> [偏移 [数量]]` 或 MCP `netflow_proxy_group_nodes` 继续查看。各列表按 `next_offset` 翻页，默认 100、最多 500 条，并有编码大小限制；配置重载或订阅变化会改变实时列表。

`providers` / MCP `netflow_providers` 分别显示代理和规则集合首批及其总数、下一偏移；其余项目可通过 `provider-page proxy|rule [偏移 [数量]]` 或 MCP `netflow_provider_page` 查看。分页不会限制按名称更新集合的能力。

GUI 和无界面模式都可通过 `kernel-options` 查看显式内核覆写及运行中内核报告的生效值，并通过 `kernel-option <名称> <值>` 修改：`allow-lan`、`ipv6`、`unified-delay` 接受 `true` 或 `false`；`log-level`、`tun-stack` 接受对应内核值；`mixed-port`、`socks-port`、`http-port` 接受端口数字。值为 `inherit` 时删除对应覆写并跟随订阅；`overrides` 中未列出的字段表示继承，`effective` 不包含 TUN 协议栈且内核停止时省略。对应 MCP 工具为 `netflow_kernel_options` 和 `netflow_set_kernel_option`，后者使用 `name`、相应的 `bool_value` / `string_value` / `port_value`，或 `inherit: true`。修改前校验，失败时尝试恢复原设置；修改可能重载内核、中断连接或改变监听范围。虚拟网卡切换中会拒绝修改；若选项文件被外部修改，会保留该文件并要求检查后重启。

```powershell
& $agent kernel-options
& $agent kernel-option log-level warning
& $agent kernel-option log-level inherit
```

GUI 或无界面实例运行时，`profiles` 可列出订阅；`import-profile` 从标准输入读取 JSON，避免把订阅地址放入命令参数。例如：

```powershell
'{"url":"https://example.com/subscription","name":"我的订阅","auto_update":true}' | & $agent import-profile
& $agent profile-job-status '<上一步返回的 job_id>'
& $agent update-profile '<订阅 ID>'
& $agent delete-profile '<非当前订阅 ID>'
```

导入和更新是后台任务，均通过 `profile-job-status` 查询；订阅 ID 在导入成功后返回。导入时名称、描述与下载选项和目录条目一起提交；无法确认回滚时，失败任务可能返回需要检查的订阅 ID。删除共享文件的订阅时保留其他订阅仍引用的文件；文件删除失败时尝试恢复目录。异常终止或外部并发修改仍可能留下部分状态，应检查后再重试；当前订阅不能删除。同一订阅的并发 Agent 更新会合并，GUI 与 Agent 不会同时更新同一订阅。默认不自动更新；JSON 可指定 `auto_update`、`update_interval_minutes`、`timeout_seconds`、`user_agent` 和 `use_core_proxy`，要求内核代理时不可用会失败，不回退到直连。任务错误和列表不包含订阅 URL 字段，默认名称不包含 URL 凭据或查询参数；自定义名称仍可能包含用户自行填写的敏感信息。完成的任务最多保留十分钟，容量不足时可能提前清理，程序退出后任务记录丢失。对应 MCP 工具为 `netflow_profiles`、`netflow_import_profile`、`netflow_update_profile`、`netflow_profile_job_status` 和 `netflow_delete_profile`。

`profile-settings <订阅 ID>` 查看名称、描述和下载选项；`profile-settings-set` 从标准输入读取包含 `profile_id` 与待修改字段的 JSON，只修改指定字段，不改变订阅 URL。例如：

```powershell
& $agent profile-settings '<订阅 ID>'
'{"profile_id":"<订阅 ID>","user_agent":"NetFlow","timeout_seconds":30,"auto_update":false}' | & $agent profile-settings-set
```

对应 MCP 工具为 `netflow_profile_settings` 和 `netflow_update_profile_settings`。新建或修改远程订阅时可显式设置 `use_system_proxy` 和 `allow_insecure`；后者会跳过该订阅的 TLS 证书验证。选项在后续下载时生效，下载进行中不能修改同一订阅。详情不返回订阅 URL，但用户填写的名称、描述及 User-Agent 可能自行包含敏感信息。

订阅菜单的“更换订阅链接”会先使用该订阅现有下载设置获取并校验新内容，成功后更新链接和配置；失败时尝试恢复原配置。无界面模式可从标准输入提交 JSON：

```powershell
'{"profile_id":"<订阅 ID>","url":"https://example.com/new-subscription"}' | & $agent profile-url-set
& $agent profile-job-status '<返回的 job_id>'
```

对应 MCP 工具为 `netflow_replace_profile_url`。任务结果不返回链接；任务失败或中断后应检查订阅状态再重试。若多个订阅指向同一文件，更新会先为目标订阅创建独立文件，避免修改其他订阅；异常终止可能留下未引用的新文件，外部并发修改仍存在竞争。

`providers` 列出当前代理与规则集合；`update-provider <proxy|rule> <名称>` 发起后台更新，返回 `job_id`，再用 `provider-job-status <job_id>` 查询 `pending`、`succeeded` 或 `failed`。对应 MCP 工具为 `netflow_providers`、`netflow_update_provider` 和 `netflow_provider_job_status`。重复提交同一订阅中仍在进行的同一更新会返回同一个任务；任务启动前如果活动订阅已切换，会失败而不会更新另一个订阅。完成的任务最多保留十分钟，容量不足时较旧的完成任务可能提前清理；程序退出后任务记录不保留。任务错误不会暴露订阅 URL 或凭据。

`update-geo` 和 MCP 的 `netflow_update_geodata` 可发起与设置页相同的 GeoData 更新。请求返回后通过 `status` 中的 `geo_pending`、`geo_error` 和 `geo_restart_required` 跟踪结果；下载完成后仍需退出并重新启动程序。`provider_cache_warning` 报告特权内核集合缓存未能安全回写的情况。

## Clash Verge 迁移

关闭 NetFlow 后，可用随安装包提供的命令行工具预览和导入 Clash Verge Rev 的配置目录或备份 ZIP：

```powershell
$agent = "$env:LOCALAPPDATA\Programs\NetFlow\netflow-agent.exe"
$source = "$env:APPDATA\io.github.clash-verge-rev.clash-verge-rev"
& $agent migrate-preview $source
& $agent migrate-import $source
& $agent migrate-export "$env:USERPROFILE\Desktop\netflow-verge-backup.zip"
```

导入会合并订阅，保留已有订阅、节点选择、流量信息、下载选项及可转换的规则；已有当前订阅不会被替换。新迁入订阅会应用关联的节点和代理组增删，以及全局和订阅级数据合并扩展；原始扩展保存在 NetFlow 配置目录的私有存档中。Verge 脚本只保存，不会自动执行；规则追加顺序和依赖脚本的配置可能与 Verge 不同。旧版本已经迁入的订阅不会自动启用数据扩展，可在新的配置目录重新迁入。迁出时会尝试恢复关联的原始扩展；未关联的全局扩展、临时连接规则和部分配置无法完整迁出。迁出备份可能包含脚本和订阅凭据，目标 Verge 可能执行其中的脚本。系统代理、TUN 和开机自启不会自动启用。对应 MCP 工具是 `netflow_migration_preview`、`netflow_migration_import` 和 `netflow_migration_export`，迁入和迁出同样要求先关闭 NetFlow。迁出不会覆盖已有文件。

新迁入的 Verge DNS 设置按字段覆盖订阅中的 DNS，保留未设置的原字段，并应用非空 hosts；编辑 DNS 内容后，该订阅改用 NetFlow 的整段 DNS 覆写，已迁入的 hosts 仍保留。旧版本已经迁入的订阅不会自动改变 DNS 行为，可在新的配置目录重新迁入以使用新的合并方式。

运行中的 GUI 或 Headless 实例可通过 Agent 显式执行迁入脚本的**只读预览**，例如将 `{"profile_id":"订阅ID","global":true,"profile":true}` 传给 `netflow-agent verge-script-preview`；返回的 `preview_id` 可用于 `verge-script-preview-rules ID before|after [OFFSET [LIMIT]]` 分页，或用 `verge-script-preview-cancel ID` 提前清除。对应 MCP 工具为 `netflow_preview_verge_script`、`netflow_verge_script_preview_rules` 和 `netflow_cancel_verge_script_preview`。预览执行真实的离线内核配置校验，不会启用脚本或改变内核；启用、GUI 预览和回滚仍未实现。脚本使用固定预览时间与确定性随机源，可能与 Verge 不同；顶层摘要不包含具体值，规则分页可能包含用户数据。更多限制见 [脚本扩展状态](docs/verge-script-status.md)。

新迁入订阅中的文件型规则和代理集合（包括数据合并扩展中的引用）会从所选目录或备份复制到独立的 `verge-providers` 目录；HTTP 集合缓存可用时一并复制，不存在时重新下载。源文件不在所选目录或备份中、无法安全读取或缺失时会显示提示，缺失的文件型集合必须补齐后才能正常使用。为避免误读其他配置，这些路径也会被重定向到独立目录。后续订阅更新沿用原始路径的映射；更新若引入了新的本地文件路径，需要手动提供该文件。单个集合文件最多 8 MiB，迁移读取总量最多 64 MiB。已由旧版迁入的订阅需要重新迁入才能获得这些映射。

## 开发

需要 Go 1.27.3（Go 可通过 `GOTOOLCHAIN=auto` 下载所需工具链）。Windows 开发示例：

```powershell
$env:GOMAXPROCS = '1'
$env:GOFLAGS = '-p=1'
go test ./...
go build -o build/NetFlow.exe ./cmd/clash-go
```

Windows 默认将用户数据保存在 `%APPDATA%\netflow`。开发时可通过绝对路径环境变量 `NETFLOW_CONFIG_DIR` 指定隔离的配置目录。配置、订阅链接、日志、代理备份及其他用户数据不应提交到仓库。

在 Windows 上安装 WiX Toolset 3.14 后，运行 `pwsh -File scripts/build-release.ps1` 可构建上述两个平台并生成 ZIP、Windows MSI 和 SHA-256 校验文件。发布脚本在构建前检查目标文件及排他锁，已有同版本产物时拒绝覆盖；构建完成后记录输入摘要和 Windows 文件哈希。程序不嵌入打包时可能尚未提交的 Git 工作区标记，可通过发行标签查看源码。打包脚本不创建 DMG，也不会替代 macOS 原机运行测试、签名或公证。更新依赖后运行 `python scripts/collect_licenses.py` 并检查 [第三方许可清单](LICENSES/third_party/README.md)。

隔离 Windows 验证器可通过 `pwsh -File scripts/test-windows-vm.ps1` 运行：缺少当前版本的 MSI 时会先自动在本机构建，已有产物则复用；运行前核对构建输入、Go 设置、三个程序及 MSI 的哈希，发现修改或缺少记录时拒绝测试，需要更新版本后重新构建。摘要是本地一致性检查，不是数字签名或可复现构建证明。验证器需要 Go、MyGo 所需依赖、Python、WiX Toolset 3.14、支持嵌套 KVM 的 Docker Desktop、约 4 GB 内存和足够磁盘空间；首次运行从微软下载约 4.9 GB 的 Windows 10 LTSC 评估镜像，并在专用 Docker 卷中创建一个 32 GB 上限的稀疏虚拟磁盘，后续运行复用该磁盘。Dockerfile 提供来宾环境，PowerShell 脚本负责宿主机构建和调度。测试只在经过 QEMU、单磁盘及非提升令牌检查的来宾中执行，不会切换宿主机 TUN。来宾内为无人值守测试启用 UAC 但自动同意该来宾的管理员提示；不要将其用于日常工作。验证涵盖 MSI、Verge 迁入、TUN 流量和异常恢复，不代表所有生产场景均已验证。

## 许可与来源

本项目分发使用 GPL-3.0，见 [LICENSE](LICENSE)；mihomo 为 GPL-3.0。Clash Go 上游代码的 MIT 许可和版权声明保留在 [LICENSES/Clash-Go-MIT.txt](LICENSES/Clash-Go-MIT.txt)，MyGo 标志的许可见 [internal/ui/assets/NOTICE](internal/ui/assets/NOTICE)。其他依赖各自保留其许可证。
