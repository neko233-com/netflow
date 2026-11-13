# NetFlow

NetFlow 是一个使用 Go、[MyGo](https://github.com/egoist/mygo) GPU 原生 UI 和 [mihomo](https://github.com/MetaCubeX/mihomo) 的桌面代理客户端，目标是逐步实现 Clash Verge 的常用功能。界面不是网页，也不需要 WebView。

**目前是开发预览版，尚未达到 Clash Verge 功能对等，也不建议替代现有稳定客户端。** 本项目从 [Clash Go](https://github.com/charlzyx/clash-go) 的 `0a0fd79` 版本开始，保留上游 MIT 许可和署名，正进行 Windows 适配。

## 当前状态

- 已接入 mihomo 内核、订阅 URL 导入、配置激活、代理组切换、模式切换、规则和连接显示、日志与托盘界面。部分功能仍需更完整的真实环境回归。
- Windows 系统代理使用当前用户的 Internet Settings，启用前备份原值；关闭或正常退出时恢复。若其他程序修改了代理，NetFlow 会拒绝覆盖并保留备份。崩溃或外部修改后可能需要手动检查；Windows 代理自动检测等复杂配置尚未完整验证。
- Windows 的 TUN 和特权服务尚未实现。特权服务在所有平台暂时禁用，避免影响上游 Clash Go 的服务。Linux 系统代理尚未实现，macOS 代理实现沿用上游但本项目尚未验证。不要在这些平台把预览状态当成正式支持。
- 订阅批量操作、静默启动、自动更新、部分端口和内核设置等尚未完整接入；设置页面中一些控件当前只保存界面偏好。Windows 开机自启通过当前用户注册表实现。单份远程订阅可手动刷新，本地 YAML 可通过拖放导入；删除当前订阅前需先切换到另一份配置。请以实际功能和错误提示为准。
- 网络端口由订阅或配置决定。默认使用混合端口 7897、SOCKS 7898、HTTP 7899；端口被其他程序占用时需在配置中调整。默认不开放 HTTP 控制接口；配置显式指定控制接口时，仅允许带密钥的回环 IP 地址。

## 开发

需要 Go 1.27.3（Go 可通过 `GOTOOLCHAIN=auto` 下载所需工具链）。Windows 开发示例：

```powershell
$env:GOMAXPROCS = '1'
$env:GOFLAGS = '-p=1'
go test ./...
go build -o build/NetFlow.exe ./cmd/clash-go
```

Windows 默认将用户数据保存在 `%APPDATA%\netflow`。开发时可通过绝对路径环境变量 `NETFLOW_CONFIG_DIR` 指定隔离的配置目录。配置、订阅链接、日志、代理备份及其他用户数据不应提交到仓库。

## 许可与来源

本项目分发使用 GPL-3.0，见 [LICENSE](LICENSE)；mihomo 为 GPL-3.0。Clash Go 上游代码的 MIT 许可和版权声明保留在 [LICENSES/Clash-Go-MIT.txt](LICENSES/Clash-Go-MIT.txt)，MyGo 标志的许可见 [internal/ui/assets/NOTICE](internal/ui/assets/NOTICE)。其他依赖各自保留其许可证。
