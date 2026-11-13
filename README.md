# NetFlow

NetFlow 是一个使用 Go、[MyGo](https://github.com/egoist/mygo) GPU 原生 UI 和 [mihomo](https://github.com/MetaCubeX/mihomo) 的桌面代理客户端，目标是逐步实现 Clash Verge 的常用功能。界面不是网页，也不需要 WebView。

**目前是开发预览版，尚未达到 Clash Verge 功能对等，也不建议替代现有稳定客户端。** 本项目从 [Clash Go](https://github.com/charlzyx/clash-go) 的 `0a0fd79` 版本开始，保留上游 MIT 许可和署名，正进行 Windows 适配。

## 下载

从 [GitHub Releases](https://github.com/neko233-com/netflow/releases) 下载 Windows x64 MSI 或便携 ZIP，或 macOS 13 及以上 Apple Silicon 的应用 ZIP。MSI 为当前用户安装到 `%LOCALAPPDATA%\Programs\NetFlow`，卸载和升级保留 `%APPDATA%\netflow` 中的用户数据。macOS 包在 Windows 上交叉构建，未在 Mac 上运行验证，也未进行 Apple 开发者签名和公证；Gatekeeper 可能阻止打开。Windows 文件同样未进行代码签名。

## 当前状态

- 已接入 mihomo 内核、订阅 URL 导入、配置激活、代理组切换、模式切换、规则和连接显示、日志与托盘界面。部分功能仍需更完整的真实环境回归。
- Windows 系统代理使用当前用户的 Internet Settings，启用前备份原值；关闭或正常退出时恢复。若其他程序修改了代理，NetFlow 会拒绝覆盖并保留备份。崩溃或外部修改后可能需要手动检查；Windows 代理自动检测等复杂配置尚未完整验证。
- Windows 的 TUN 和特权服务尚未实现。特权服务在所有平台暂时禁用，避免影响上游 Clash Go 的服务。Linux 系统代理尚未实现，macOS 代理实现沿用上游但本项目尚未验证。不要在这些平台把预览状态当成正式支持。
- 支持本地文件选择或拖放导入、远程订阅后台下载、批量更新与删除、重新激活订阅。删除时会保留当前订阅。Windows 开机自启通过当前用户注册表实现，静默启动依赖托盘；订阅自动更新和部分设置尚未接入。
- 代理模式、局域网、IPv6、统一延迟、日志等级和监听端口可在界面中修改，作为全局覆写持久化，不修改订阅原文件；设置失败会尝试恢复。修改混合端口前需先关闭系统代理。其他设置页面中的部分控件仍只保存界面偏好，请以实际功能和错误提示为准。
- 网络端口由订阅或配置决定。默认使用混合端口 7897、SOCKS 7898、HTTP 7899；端口被其他程序占用时需在配置中调整。默认不开放 HTTP 控制接口；配置显式指定控制接口时，仅允许带密钥的回环 IP 地址。

## Agent 规则重写

启动 NetFlow 后，随安装包提供的 `netflow-agent.exe` 支持命令行和 MCP 标准输入输出接口。它通过当前用户配置目录中的临时令牌连接本机随机端口，不监听外网；应保护配置目录及令牌，Windows 文件权限继承自所在目录，同一账户下的进程也能调用该接口。退出程序后临时端点被删除。

```powershell
$agent = "$env:LOCALAPPDATA\Programs\NetFlow\netflow-agent.exe"
& $agent status
'{"scope":"global","operation":"set","layer":{"prepend":["DOMAIN,example.com,DIRECT"]}}' | & $agent preview
& $agent apply '<上一步返回的 proposal_id>'
```

也可以将 `netflow-agent.exe mcp` 配置为 MCP 客户端的 stdio 命令，使用 `netflow_status`、`netflow_preview_rewrite` 和 `netflow_apply_rewrite`。若启动多个实例，在命令名前传入 `--pid <进程号>`；隔离环境可传入 `--config-dir <绝对路径>`。macOS 对应命令位于 `NetFlow.app/Contents/Resources/netflow-agent`。命令行输出 JSON，错误输出到 stderr；连接超时后应先执行 `status` 核实结果，再决定是否重试。

规则操作的 `scope` 为 `global`、`profile` 或 `connection`，`operation` 为 `set` 或 `clear`。全局/订阅规则也可从订阅页面打开编辑器，在界面中预览并应用。全局/订阅层可设置 `layer.prepend`、`layer.append` 和 `layer.remove`（按原规则字符串精确删除）；订阅层还须提供 `profile_id`。连接层 `set` 需要活动 `connection_id`、已有策略名 `policy` 和 1–86400 秒的 `ttl_seconds`，可选择 `close_existing: true`。顺序是连接规则、订阅前置、全局前置、原规则（去除指定项）、订阅追加、全局追加、原 MATCH 及之后规则。规则持久化在用户目录中，订阅原文件不会因此被改写。

预览验证配置并返回两分钟内有效的提案；配置或订阅变化后须重新预览。应用失败时尝试恢复旧规则。连接层根据源 IP、目标域名或 IP、端口及网络匹配**后续连接**，可能同时影响其他符合条件的连接；已建立的连接不能被重新路由，可显式选择关闭原连接。规则只在规则模式下控制路由。Agent 状态包含连接元数据，务必只授予可信程序访问权限。

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

## 许可与来源

本项目分发使用 GPL-3.0，见 [LICENSE](LICENSE)；mihomo 为 GPL-3.0。Clash Go 上游代码的 MIT 许可和版权声明保留在 [LICENSES/Clash-Go-MIT.txt](LICENSES/Clash-Go-MIT.txt)，MyGo 标志的许可见 [internal/ui/assets/NOTICE](internal/ui/assets/NOTICE)。其他依赖各自保留其许可证。
