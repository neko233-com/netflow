# Windows 隔离验证器

在支持嵌套 KVM 的 Windows Docker Desktop 上，本地构建发布包后运行：

```powershell
pwsh -File scripts/build-release.ps1
pwsh -File scripts/test-windows-vm.ps1
```

验证器使用带专用标签的容器与持久卷，来宾只有一块 QEMU 虚拟硬盘。每次运行还挂载一个临时只读光盘，用于传递按 SHA-256 校验的 MSI、测试程序和测试代理；光盘不是第二块虚拟硬盘。来宾检查 QEMU、非提升令牌和单硬盘后才会修改测试网络。宿主机的 TUN 和系统代理不会由测试切换。测试结束后容器自动停止，硬盘与结果保留以供复用；结果也会复制到 `build/windows-vm-result-<运行 ID>.json`。首次运行需要下载微软官方评估镜像；后续复用稀疏磁盘，不再保留该安装镜像。磁盘实际占用取决于 Windows、安装记录及测试缓存，本机此次约为 12 GiB。

测试代理不再从网络下载并运行更新版本。现有测试磁盘若没有新的启动项，验证器会在确认隔离来宾桌面已启动后，通过该来宾的 QEMU 控制台启动光盘上的固定程序；后续使用来宾内的启动项。所有操作只针对验证器自身的容器、卷和来宾。

Windows 评估版需要合法激活且有期限。此次使用的来宾显示许可已过期；微软说明未激活或到期的评估版可能每小时关机。验证器不会重置许可或修改时钟以延长评估期，持续使用需要有效的 Windows 测试许可。参见 [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/download-windows-10-enterprise/)。

隔离来宾的 Defender 曾将旧版测试代理的网络下载临时文件检测为 `Trojan:Win32/Wacatac.H!ml`；目前没有微软的误报裁定。宿主机对该代理的只读自定义扫描未检出威胁。新版验证器移除了网络可执行文件下载和自更新，并在保持来宾 Defender 开启的情况下通过回归；这不构成对旧检测的安全结论。

一次运行中，TUN 启动后的首次 DNS 拦截请求超时；后续运行通过。测试现在会在有限时间内等待真实流量并在失败时记录网络状态，但超时的根因尚未确定，不应据此声称所有网络环境均已验证。
