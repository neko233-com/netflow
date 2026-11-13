# NetFlow

NetFlow 是一个使用 Go、[MyGo](https://github.com/egoist/mygo) GPU 原生 UI 和 [mihomo](https://github.com/MetaCubeX/mihomo) 的桌面代理客户端，目标是逐步实现 Clash Verge 的常用功能。界面不是网页，也不需要 WebView。内核目前使用 [基于 mihomo v1.19.33 的公开补丁版本](https://github.com/neko233-com/mihomo/tree/v1.19.33-netflow.8)，修复日志等级并发访问、控制器生命周期竞争以及 TUN 状态同步问题。

**目前是开发预览版，尚未达到 Clash Verge 功能对等，也不建议替代现有稳定客户端。** 本项目从 [Clash Go](https://github.com/charlzyx/clash-go) 的 `0a0fd79` 版本开始，保留上游 MIT 许可和署名，正进行 Windows 适配。

## 下载

从 [GitHub Releases](https://github.com/neko233-com/netflow/releases) 下载 Windows x64 MSI 或便携 ZIP，或 macOS 13 及以上 Apple Silicon 的应用 ZIP。MSI 为当前用户安装到 `%LOCALAPPDATA%\Programs\NetFlow`，卸载和升级保留 `%APPDATA%\netflow` 中的用户数据。macOS 包在 Windows 上交叉构建，未在 Mac 上运行验证，也未进行 Apple 开发者签名和公证；Gatekeeper 可能阻止打开。Windows 文件同样未进行代码签名。

## 当前状态

- 已接入 mihomo 内核、订阅 URL 导入、配置激活、代理组切换、节点测速、代理与规则集合更新、模式切换、规则和连接显示、日志与托盘界面。部分功能仍需更完整的真实环境回归。
- 系统接入聚焦虚拟网卡（TUN），界面和托盘不再提供系统代理开关。Windows 升级启动时只恢复仍由旧版 NetFlow 持有的系统代理备份，不覆盖其他应用的设置。
- Windows TUN 使用实验性独立特权内核：开启时会请求管理员授权，常见的活动 TUN 网卡会被拒绝以减少冲突；每次重新启动应用后需重新开启并授权。当前授权需要使用同一 Windows 账户。隔离 Windows 10 来宾已验证真实 Wintun、四种协议栈、DNS/Fake-IP 流量、切换 TUN 时 Fake-IP 映射双向保持，以及正常关闭、桌面进程退出和内核连接断开后的路由与 DNS 恢复。普通权限进程将配置文件内容复制至管理员专属临时目录，特权内核不直接打开用户配置树，并禁用外部控制器；此快照不包含链接及运行缓存，最多 128 MiB、4096 个文件。持久化 Fake-IP 的跨存储交接已做单元测试，尚未在 Windows 来宾验证。整体安全性和功能对等尚未完成，不应当作生产支持。macOS TUN 的特权服务尚未实现。Linux Docker 测试覆盖独立网络命名空间中的 IPv4 TUN、规则、DNS/Fake-IP 流量及连接断开后的清理。
- 支持本地文件选择或拖放导入、远程订阅后台下载、按订阅设置自动更新、批量更新与删除、重新激活订阅，并显示服务端提供的订阅流量及到期时间。可设置订阅下载的 User-Agent、超时、代理和证书验证；内核代理或系统手动 HTTP(S) 代理不可用时返回错误，不会改为直连。系统代理选项不处理 PAC、自动检测或绕过列表；同时启用时优先内核代理。删除时会保留当前订阅。Windows 开机自启通过当前用户注册表实现，静默启动依赖托盘；部分设置尚未接入。
- 代理模式、局域网、IPv6、统一延迟、日志等级和监听端口可在界面中修改，作为全局覆写持久化，不修改订阅原文件；设置失败会尝试恢复。旧版 NetFlow 遗留的系统代理会在升级时安全恢复。链式代理尚未接入内核；其他设置页面中的部分控件仍只保存界面偏好，请以实际功能和错误提示为准。
- TUN 协议栈可跟随订阅，也可持久化覆写为 System、Mixed、gVisor 或 Mips；发布构建包含 gVisor，Tailscale 出站未包含。更改协议栈会重新加载内核。
- DNS 覆写按订阅保存；设置中的编辑器接受 mihomo `dns` 段内容，应用时校验合并后的配置并在内核重载失败时尝试回滚。DNS 监听端口需要自行避免冲突。
- “当前配置”显示内核上次成功应用的合成配置，可能包含凭据；查看器最多显示前 256 KiB。订阅文件可从订阅菜单打开，保存后需重新激活；远程订阅更新会覆盖文件中的手动编辑。
- 订阅菜单可在本地生成分享二维码。二维码包含完整订阅链接，请只向可信设备展示。
- 网络端口由订阅或配置决定。默认使用混合端口 7897、SOCKS 7898、HTTP 7899；端口被其他程序占用时需在配置中调整。默认不开放 HTTP 控制接口；配置显式指定控制接口时，仅允许带密钥的回环 IP 地址。
- 同一配置目录只运行一个 NetFlow 实例；重复启动会尝试显示已有窗口。需要互相隔离的实例时，可为各实例指定不同的 `NETFLOW_CONFIG_DIR` 和监听端口。
- 首页的出口 IP 查询仅在用户点击或开启自动刷新后执行，通过本地代理访问 [IP.SB 的 GeoIP API](https://ip.sb/api/)；该服务会看到代理出口 IP。代理不可用时不会回退到直连查询。

## Agent 规则重写

启动 NetFlow 后，随安装包提供的 `netflow-agent.exe` 支持命令行和 MCP 标准输入输出接口。`tun on` / `tun off` 会请求切换；若返回 `pending`，应通过 `status` 查看 `tun_pending` 与 `tun_error`，开启时可能弹出管理员授权。它通过当前用户配置目录中的临时令牌连接本机随机端口，不监听外网；Windows 上令牌文件以当前用户和 SYSTEM 专用的访问控制列表创建，同一账户下的进程仍能调用该接口。退出程序后临时端点被删除。

```powershell
$agent = "$env:LOCALAPPDATA\Programs\NetFlow\netflow-agent.exe"
& $agent status
'{"scope":"global","operation":"set","layer":{"prepend":["DOMAIN,example.com,DIRECT"]}}' | & $agent preview
& $agent apply '<上一步返回的 proposal_id>'
```

也可以将 `netflow-agent.exe mcp` 配置为 MCP 客户端的 stdio 命令，使用 `netflow_status`、`netflow_preview_rewrite` 和 `netflow_apply_rewrite`。隔离环境可传入 `--config-dir <绝对路径>`，必要时可在命令名前传入 `--pid <进程号>`。macOS 对应命令位于 `NetFlow.app/Contents/Resources/netflow-agent`。命令行输出 JSON，错误输出到 stderr；连接超时后应先执行 `status` 核实结果，再决定是否重试。

规则操作的 `scope` 为 `global`、`profile` 或 `connection`，`operation` 为 `set` 或 `clear`。全局/订阅规则也可从订阅页面打开编辑器，在界面中预览并应用。全局/订阅层可设置 `layer.prepend`、`layer.append` 和 `layer.remove`（按原规则字符串精确删除）；订阅层还须提供 `profile_id`。连接层 `set` 需要活动 `connection_id`、已有策略名 `policy` 和 1–86400 秒的 `ttl_seconds`，可选择 `close_existing: true`。顺序是连接规则、订阅前置、全局前置、原规则（去除指定项）、订阅追加、全局追加、原 MATCH 及之后规则。规则持久化在用户目录中，订阅原文件不会因此被改写。

预览验证配置并返回两分钟内有效的提案；配置或订阅变化后须重新预览。应用失败时尝试恢复旧规则。连接层根据源 IP、目标域名或 IP、端口及网络匹配**后续连接**，可能同时影响其他符合条件的连接；已建立的连接不能被重新路由，可显式选择关闭原连接。规则只在规则模式下控制路由。Agent 状态包含连接元数据，务必只授予可信程序访问权限。

CLI 还提供 `groups`、`rules [偏移 [数量]]`、`select <组> <节点>`、`mode <rule|global|direct>`、`use-profile <订阅 ID>` 和 `close-connection <连接 ID>`；对应的 MCP 工具分别以 `netflow_` 开头。关闭不存在的连接会返回 `closed: false`。这些操作直接改变运行状态，规则覆写仍需要先预览再应用。

## Clash Verge 迁移

关闭 NetFlow 后，可用随安装包提供的命令行工具预览和导入 Clash Verge Rev 的配置目录或备份 ZIP：

```powershell
$agent = "$env:LOCALAPPDATA\Programs\NetFlow\netflow-agent.exe"
$source = "$env:APPDATA\io.github.clash-verge-rev.clash-verge-rev"
& $agent migrate-preview $source
& $agent migrate-import $source
& $agent migrate-export "$env:USERPROFILE\Desktop\netflow-verge-backup.zip"
```

导入会合并订阅，保留已有订阅、节点选择、流量信息、下载选项及可转换的规则；已有当前订阅不会被替换。原始 Verge 扩展会保存在 NetFlow 配置目录的私有存档中，其中脚本、合并、节点和代理组扩展不会在 NetFlow 自动执行或应用。迁出时会尝试恢复关联的原始扩展；未关联的全局扩展、临时连接规则和部分配置无法完整迁出，规则追加顺序也可能不同。迁出备份可能包含脚本和订阅凭据，目标 Verge 可能执行其中的脚本。系统代理、TUN 和开机自启不会自动启用。对应 MCP 工具是 `netflow_migration_preview`、`netflow_migration_import` 和 `netflow_migration_export`，迁入和迁出同样要求先关闭 NetFlow。迁出不会覆盖已有文件。

## 开发

需要 Go 1.27.3（Go 可通过 `GOTOOLCHAIN=auto` 下载所需工具链）。Windows 开发示例：

```powershell
$env:GOMAXPROCS = '1'
$env:GOFLAGS = '-p=1'
go test ./...
go build -o build/NetFlow.exe ./cmd/clash-go
```

Windows 默认将用户数据保存在 `%APPDATA%\netflow`。开发时可通过绝对路径环境变量 `NETFLOW_CONFIG_DIR` 指定隔离的配置目录。配置、订阅链接、日志、代理备份及其他用户数据不应提交到仓库。

在 Windows 上安装 WiX Toolset 3.14 后，运行 `pwsh -File scripts/build-release.ps1` 可构建上述两个平台并生成 ZIP、Windows MSI 和 SHA-256 校验文件。打包脚本不创建 DMG，也不会替代 macOS 原机运行测试、签名或公证。更新依赖后运行 `python scripts/collect_licenses.py` 并检查 [第三方许可清单](LICENSES/third_party/README.md)。

隔离 Windows 验证器可通过 `pwsh -File scripts/test-windows-vm.ps1` 运行。它需要支持嵌套 KVM 的 Docker Desktop、约 4 GB 内存和足够磁盘空间；首次运行从微软下载约 4.9 GB 的 Windows 10 LTSC 评估镜像，并在专用 Docker 卷中创建一个 32 GB 上限的稀疏虚拟磁盘，后续运行复用该磁盘。测试只在经过 QEMU、单磁盘及非提升令牌检查的来宾中执行，不会切换宿主机 TUN。来宾内为无人值守测试启用 UAC 但自动同意该来宾的管理员提示；不要将其用于日常工作。验证涵盖 MSI、Verge 迁入、TUN 流量和异常恢复，不代表所有生产场景均已验证。

## 许可与来源

本项目分发使用 GPL-3.0，见 [LICENSE](LICENSE)；mihomo 为 GPL-3.0。Clash Go 上游代码的 MIT 许可和版权声明保留在 [LICENSES/Clash-Go-MIT.txt](LICENSES/Clash-Go-MIT.txt)，MyGo 标志的许可见 [internal/ui/assets/NOTICE](internal/ui/assets/NOTICE)。其他依赖各自保留其许可证。
