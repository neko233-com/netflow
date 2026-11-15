# 依赖与发布安全检查

2026-11-15 使用 `govulncheck v1.9.0` 和 Go 漏洞数据库（更新至 `2026-11-11 02:51:11 UTC`）检查了 Windows 发布程序和源码。该工具只覆盖数据库中已知的 Go 漏洞，不能证明软件没有未知漏洞，也不能裁定 Defender 检测结果。

`0.2.99-alpha.1` 的 Windows GUI 程序二进制扫描报告 13 项可能受影响的问题，涉及 Go 标准库、`brotli`、`compress`、`dhcp`、`golang.org/x/net` 和 `golang.org/x/crypto`。二进制扫描无法单独证明所有报告的函数均可由应用调用，尤其不能将其等同于实际可利用漏洞。发布说明记录了这个结果。

后续源码将 Go 更新至 1.27.4，并更新上述五个模块至数据库所列修复版本或更新版本。使用 Windows、`with_gvisor,no_tailscale` 标签的源码级扫描对 `./...` 返回 `No vulnerabilities found`；这不包括测试代码、非 Go 依赖、所有运行时配置或未知漏洞，也不替代对实际发布二进制的检查。`mihomo` 使用本项目公开分支，漏洞数据库对替换模块的覆盖可能不同。

`0.2.100-alpha.1` 本地构建后，对实际 Windows `NetFlow.exe`、`netflow-agent.exe` 和 `netflow-kernel-worker.exe` 分别运行相同数据库的二进制扫描，均返回 `No vulnerabilities found`。构建版 GUI 文件副本的本机 Defender 不修复自定义扫描未报告威胁，单磁盘 Windows 来宾一次完整回归通过；这些结果不构成微软对 `0.2.99-alpha.1` 检测的裁定。

对同版 macOS ARM64 包中的 GUI、Agent 和内核工作进程也分别执行了 Go 二进制静态扫描，均未报告数据库中的已知漏洞。该检查不运行 macOS 程序，也不验证 macOS TUN、签名或公证。

可在受信任网络下重现源码扫描：

```powershell
$env:GOMAXPROCS = '1'
$env:CGO_ENABLED = '0'
$env:GOWORK = 'off'
$env:GOFLAGS = '-p=1'
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 '-tags=with_gvisor,no_tailscale' ./...
```

单磁盘 Windows 来宾在复测 `0.2.99-alpha.1` 时将 `NetFlow.exe` 标记为 `Trojan:Win32/Wacatac.C!ml` 并阻止运行。本机对同哈希副本的不修复自定义扫描未检出威胁，但不能据此判断来宾检测为误报；完整证据和限制见 [Windows 验证记录](windows-vm-validation.md)。尚无微软最终裁定，也没有公开可信的 Windows 代码签名。

2026-11-15 对 `0.2.133-alpha.1` 实际 Windows 发布文件补充本机 Microsoft Defender 自定义扫描：Defender 处于 Normal 模式、实时防护引擎启用，安全智能版本 `1.463.308.0`（更新时间 2026-11-15 08:31，本机时间）。分别扫描发布版 GUI、Agent、特权内核工作进程和 MSI，使用 `-Scan -ScanType 3 -File <文件> -DisableRemediation`，四次均返回退出码 0 且报告未发现威胁。该模式不执行修复，扫描结果只代表该主机、该版本的检测；它不是对 `0.2.99-alpha.1` 既往检测的微软误报裁定，也不能证明软件不存在恶意行为或其他漏洞。

同日对 `0.2.135-alpha.1` 的上述四个 Windows 发布文件重复本机不修复扫描，Defender 安全智能版本仍为 `1.463.308.0`，四次均返回退出码 0 且报告未发现威胁；上述限制同样适用。源码提交 `bf010e1` 的 Windows 环境全工程 `go vet -p 1 ./...` 通过；静态检查不证明运行时行为或安全性。

同日使用 `govulncheck v1.9.0` 重新扫描当前源码（Windows 发布标签 `with_gvisor,no_tailscale`）和 `0.2.135-alpha.1` 的 Windows、macOS ARM64 各三个实际程序，源码与六个二进制均返回 `No vulnerabilities found`。该结果受当时数据库、调用分析和替换模块识别范围限制；macOS 二进制扫描不代表程序已在 Mac 运行。

同日对 `0.2.137-alpha.1` 重复上述源码及六个程序的 Go 漏洞扫描，均返回 `No vulnerabilities found`；本机 Defender 安全智能版本 `1.463.308.0` 对 Windows 三个程序和 MSI 的不修复自定义扫描也均报告未发现威胁。上述覆盖范围、既往检测未裁定及未签名限制仍适用。

同日对 `0.2.138-alpha.1` 重复上述源码、六个程序的 Go 漏洞扫描以及 Windows 三个程序和 MSI 的本机 Defender 不修复扫描，均未检出已知问题；Defender 安全智能版本为 `1.463.308.0`。相同的覆盖范围和限制仍适用。
