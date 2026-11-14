# 依赖与发布安全检查

2026-11-15 使用 `govulncheck v1.9.0` 和 Go 漏洞数据库（更新至 `2026-11-11 02:51:11 UTC`）检查了 Windows 发布程序和源码。该工具只覆盖数据库中已知的 Go 漏洞，不能证明软件没有未知漏洞，也不能裁定 Defender 检测结果。

`0.2.99-alpha.1` 的 Windows GUI 程序二进制扫描报告 13 项可能受影响的问题，涉及 Go 标准库、`brotli`、`compress`、`dhcp`、`golang.org/x/net` 和 `golang.org/x/crypto`。二进制扫描无法单独证明所有报告的函数均可由应用调用，尤其不能将其等同于实际可利用漏洞。发布说明记录了这个结果。

后续源码将 Go 更新至 1.27.4，并更新上述五个模块至数据库所列修复版本或更新版本。使用 Windows、`with_gvisor,no_tailscale` 标签的源码级扫描对 `./...` 返回 `No vulnerabilities found`；这不包括测试代码、非 Go 依赖、所有运行时配置或未知漏洞，也不替代对实际发布二进制的检查。`mihomo` 使用本项目公开分支，漏洞数据库对替换模块的覆盖可能不同。

可在受信任网络下重现源码扫描：

```powershell
$env:GOMAXPROCS = '1'
$env:CGO_ENABLED = '0'
$env:GOWORK = 'off'
$env:GOFLAGS = '-p=1'
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 '-tags=with_gvisor,no_tailscale' ./...
```

单磁盘 Windows 来宾在复测 `0.2.99-alpha.1` 时将 `NetFlow.exe` 标记为 `Trojan:Win32/Wacatac.C!ml` 并阻止运行。本机对同哈希副本的不修复自定义扫描未检出威胁，但不能据此判断来宾检测为误报；完整证据和限制见 [Windows 验证记录](windows-vm-validation.md)。尚无微软最终裁定，也没有公开可信的 Windows 代码签名。
