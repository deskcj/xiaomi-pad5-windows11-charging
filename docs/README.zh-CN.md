# 小米平板 5（nabu）Windows 11 ARM64 充电与 USB-C 修复

[![English](https://img.shields.io/badge/English-d0d7de?style=for-the-badge&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2MCAzNiI%2BPHJlY3Qgd2lkdGg9IjYwIiBoZWlnaHQ9IjM2IiBmaWxsPSIjMDEyMTY5Ii8%2BPHBhdGggZD0iTTAgMCA2MCAzNk02MCAwIDAgMzYiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxMCIvPjxwYXRoIGQ9Ik0wIDAgNjAgMzZNNjAgMCAwIDM2IiBzdHJva2U9IiNDODEwMkUiIHN0cm9rZS13aWR0aD0iNCIvPjxwYXRoIGQ9Ik0zMCAwdjM2TTAgMThoNjAiIHN0cm9rZT0iI2ZmZiIgc3Ryb2tlLXdpZHRoPSIxMiIvPjxwYXRoIGQ9Ik0zMCAwdjM2TTAgMThoNjAiIHN0cm9rZT0iI0M4MTAyRSIgc3Ryb2tlLXdpZHRoPSI2Ii8%2BPC9zdmc%2B)](README.md) [![Русский](https://img.shields.io/badge/%D0%A0%D1%83%D1%81%D1%81%D0%BA%D0%B8%D0%B9-d0d7de?style=for-the-badge&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2MCAzNiI%2BPHBhdGggZmlsbD0iI2ZmZiIgZD0iTTAgMGg2MHYxMkgweiIvPjxwYXRoIGZpbGw9IiMwMDM5QTYiIGQ9Ik0wIDEyaDYwdjEySDB6Ii8%2BPHBhdGggZmlsbD0iI0Q1MkIxRSIgZD0iTTAgMjRoNjB2MTJIMHoiLz48L3N2Zz4%3D)](README.ru.md) [![简体中文](https://img.shields.io/badge/%E7%AE%80%E4%BD%93%E4%B8%AD%E6%96%87-2f81f7?style=for-the-badge&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2MCAzNiI%2BPHJlY3Qgd2lkdGg9IjYwIiBoZWlnaHQ9IjM2IiBmaWxsPSIjREUyOTEwIi8%2BPHBvbHlnb24gcG9pbnRzPSIxMi4wLDMuNyAxMy41LDcuOSAxOC4wLDguMSAxNC41LDEwLjggMTUuNywxNS4xIDEyLjAsMTIuNiA4LjMsMTUuMSA5LjUsMTAuOCA2LjAsOC4xIDEwLjUsNy45IiBmaWxsPSIjRkZERTAwIi8%2BPHBvbHlnb24gcG9pbnRzPSIyNC4wLDEuNyAyNC42LDMuMiAyNi4yLDMuMyAyNS4wLDQuMyAyNS40LDUuOSAyNC4wLDUuMCAyMi42LDUuOSAyMy4wLDQuMyAyMS44LDMuMyAyMy40LDMuMiIgZmlsbD0iI0ZGREUwMCIvPjxwb2x5Z29uIHBvaW50cz0iMjkuMCw2LjcgMjkuNiw4LjIgMzEuMiw4LjMgMzAuMCw5LjMgMzAuNCwxMC45IDI5LjAsMTAuMCAyNy42LDEwLjkgMjguMCw5LjMgMjYuOCw4LjMgMjguNCw4LjIiIGZpbGw9IiNGRkRFMDAiLz48cG9seWdvbiBwb2ludHM9IjI5LjAsMTMuNyAyOS42LDE1LjIgMzEuMiwxNS4zIDMwLjAsMTYuMyAzMC40LDE3LjkgMjkuMCwxNy4wIDI3LjYsMTcuOSAyOC4wLDE2LjMgMjYuOCwxNS4zIDI4LjQsMTUuMiIgZmlsbD0iI0ZGREUwMCIvPjxwb2x5Z29uIHBvaW50cz0iMjQuMCwxOC43IDI0LjYsMjAuMiAyNi4yLDIwLjMgMjUuMCwyMS4zIDI1LjQsMjIuOSAyNC4wLDIyLjAgMjIuNiwyMi45IDIzLjAsMjEuMyAyMS44LDIwLjMgMjMuNCwyMC4yIiBmaWxsPSIjRkZERTAwIi8%2BPC9zdmc%2B)](README.zh-CN.md)

![构建版本](https://img.shields.io/badge/build-1871--HQ2--U4-blue?style=for-the-badge) ![状态](https://img.shields.io/badge/status-public%20preview-orange?style=for-the-badge) ![实测充电](https://img.shields.io/badge/accelerated%20charging-measured-brightgreen?style=for-the-badge)

**1871-HQ2-U4** 是目前经过实机验证的充电与 USB-C 驱动包。在已记录的测试中，直连充电器与 SSD/OTG 可以相互切换，也可以通过集线器同时充电并使用 SSD。**使用兼容充电器时，实测证实电池获得了更高的充电功率。** 但从集线器移除充电器电源仍会使 SSD 短暂断开；完整的 33 W 充电和 PPS 尚未得到证实。

## 下载

**[下载 Xiaomi-Pad5-Charging-1871-HQ2-U4.zip](https://github.com/deskcj/xiaomi-pad5-windows11-charging/raw/refs/heads/main/downloads/Xiaomi-Pad5-Charging-1871-HQ2-U4.zip)** · 314,150 字节

SHA-256：C4491C15E814E4A5840C93FA668941C75E6C47BE1B60EBA52D923CC2F6261386

**[下载开发源码包](https://github.com/deskcj/xiaomi-pad5-windows11-charging/raw/refs/heads/main/downloads/Xiaomi-Pad5-Charging-1871-HQ2-U4-Sources.zip)** · 346,211 字节 · 165 个文件

SHA-256：A7642A0A3735B2C30643088F9BC9789BA6E8A64A7E2BE6C0A63357D41B714AF5

驱动 ZIP 包含 **Install.cmd**、兼容性检查、安装后验证、备份与恢复以及本地诊断工具。无需 Python、SDK，也无需在设备管理器中手动安装。

单独的源码 ZIP 包含 U4 安装脚本、项目自制的 PD 筛选驱动 0.1.3 及其 EWDK 构建文件、现存的 C/汇编补丁与离线测试，以及 PD/PPS/LN8000/FRS 研究组件。**不包含 Qualcomm 完整源码**，因此无法仅凭该 ZIP 从零重建所有基础驱动。研究组件不会由 U4 安装。请下载这个单独的 ZIP；GitHub 自动生成的源码归档只包含仓库文档。参见[后续开发说明](CONTINUE-DEVELOPMENT.md)（英文）。

## 🎬 视频演示：OTG 切换与通过集线器充电

视频展示了 **OTG U 盘 → 充电 → U 盘 → 充电**的切换过程，以及在运行 **Windows 11 ARM64 的 Xiaomi Pad 5（nabu）**上通过 USB-C 集线器同时使用 U 盘和充电器。

[![观看 Xiaomi Pad 5（nabu）OTG 切换及通过集线器同时使用 U 盘和充电器的演示](https://img.youtube.com/vi/JUCgrsy8yiQ/hqdefault.jpg)](https://www.youtube.com/watch?v=JUCgrsy8yiQ)

▶️ **[在 YouTube 观看演示](https://www.youtube.com/watch?v=JUCgrsy8yiQ)**

## 已实现与待解决

- ✅ 在记录的测试中，直连 SSD/OTG ↔ 充电器切换无需重启。
- ✅ 开机时连接充电器或 SSD，以及之后切换设备，均已在记录的测试中工作。
- ✅ 测试过的墙插充电器和移动电源确实给电池充电。
- ✅ 集线器、充电器与 SSD 可以同时使用；重新接入充电器电源后，充电恢复。
- ✅ 已确认固定 **USB PD 9 V / 3 A**；一次持续测试测得电池净充电功率平均 **13.8 W**。
- ✅ 一款标称 **33 W 的充电器**，在分开的测试中测得 USB 输入电压约 **8.6 V**，电池净充电功率平均 **16–17.4 W**。
- ✅ 已在项目平板上验证 **Install.cmd → 重启 → Verify.cmd PASS**、诊断流程，以及已安装相同驱动时不重复安装的流程。
- ❌ 测试过的 **Acer 集线器**和另一款集线器在移除充电器电源后均会使 SSD 短暂断开并重新连接；即使事先安全弹出，现象仍会出现。其他已测试功能正常。**写入磁盘时不要改变集线器供电。**
- ❌ 集线器电源的无缝切换仍未解决；**已发布驱动包没有实现 PPS**。
- ⏳ 尚未确认 USB 输入端达到完整 **33 W**、达到 Android 的最高充电速度，或兼容所有修改过的 Windows 映像与驱动组合。

## 快速充电：测量实际证明了什么

**在已测试的连接方式中，较高的输入电压和电池能量的实际增长证实了加速充电。** 标称 33 W 的充电器在分开的测试中测得电池净充电功率平均约 16–17.4 W；一次 180 秒的后续测试峰值为 17.68 W。另一次电压采集测得 USB 输入端 8.55–8.63 V。这些数字来自不同的采集记录，不能合并成一次连续的最大功率测试。

测试过的一款充电器协商了固定的 9 V / 3 A。**27 W 是协商功率上限**，不是实测输入功率或电池充电功率。电池净功率不包括平板自身耗电和转换损耗；标称 33 W 充电器的测试没有记录 USB 输入电流，也没有确定其充电协议。**充电器标称 33 W 不等于实际输入 33 W。** PPS 和电荷泵路径仍在开发。安装显示 PASS 或出现充电图标也不能证明充电速度。参见[测量详情](FAST-CHARGING.md)（英文）。

## 兼容性

适用于 **小米平板 5（nabu）上的 Windows 11 ARM64**，并要求兼容的 nabu 基础驱动。安装程序通过所选 INF/SYS 的准确身份识别已审核的 Qualcomm **1.0.1680.0** 和 Xiaomi **1.0.10730.0** 电池 miniclass 基线。安装程序保留 miniclass，不安装或回滚它。

U4 还会根据完整的固定身份及辅助传输驱动，识别一组已审核的 **qcpmicext 23.5.57.553** 源文件。但从该版本迁移的过程尚未在实机安装中验证。遇到未知的更高版本驱动组或 PD 扩展，安装程序会停止。单独安装的 **NabuTypeC** 可能具有更高的驱动匹配优先级，导致暂存新包后旧 Type-C 后端仍保留。**重启后必须看到 Verify PASS；仅暂存成功不足以证明安装成功。** 不保证兼容所有修改版 Windows 映像。

> [!WARNING]
> 必须事先启用 Windows **测试模式（Test Mode）**。Install 不会启用它，也不会修改 Secure Boot 或 BCD。请保留备份和 Windows 恢复方法。参见 [nabu 设置指南](https://github.com/erdilS/Port-Windows-11-Xiaomi-Pad-5/blob/main/guide/English/disable-secureboot-en.md)（英文）。

## 安装

1. 将**整个 ZIP 解压到内部 C: 盘**，例如 C:\Xiaomi-Pad5-Charging。不要直接从 ZIP 或 USB 存储设备运行。
2. 双击 **Install.cmd**，如出现管理员权限提示，请确认，然后等待结果。
3. 若显示 **PendingReboot**，先保存工作、安全弹出存储设备、断开 USB-C 设备，然后手动执行一次**重新启动**。该状态只表示 Windows 接受了驱动暂存，尚未验证驱动已启用。安装程序不会自动重启。
4. Windows 启动后运行 **Verify.cmd**，并确认结果为 **PASS**。如果 Install 对完全相同且已启用的驱动组显示 **Verified**，则无需再次安装或重启。
5. 测试直连 SSD/OTG → 安全弹出并实际拔除 → 直连充电器，再反向测试。若安装、Verify 或设备使用失败，运行 **Diagnose.cmd** 并查看其生成的本地 ZIP。

| 组件 | 随包版本 |
|---|---|
| PMIC 扩展 | 1.0.1871.0 |
| Type-C 后端 | 1.0.1867.0 |
| USB-C 客户端 | 1.0.1853.0 |
| 电池管理器 | 1.0.10732.0 |
| 固定 PD 配置筛选驱动 | 0.1.3.0，安装程序使用模式 1 |
| 电池 miniclass | 已审核的 1680 或 10730 基线；予以保留 |

## U4 的变更

与较早公开的 U1 相比，PMIC 从 1869 更新为 **1871**。U4 修复了 PowerShell 模块启动、未自动加载模块时的 SHA-256 采集、空事件日志处理和诊断导出错误报告。**U4 的驱动 INF/SYS/CAT 与 U3 相同。** 尚未证实 U4 比 U1 充得更快或能无缝切换集线器电源；此包提供的是当前已验证的驱动组和更可靠的安装、诊断流程。

交付的 ZIP 与项目平板上实际安装并验证的归档（含文件索引）完全相同。源码包中的自制筛选驱动已使用 EWDK 重新构建，并在仿真中通过了 4,672 次 ARM64 解析器执行、40 次回调执行和 22 次生命周期执行。这些是离线检查，**不能证明**新增 PPS/FRS 的硬件支持。

## 诊断与恢复

**Check.cmd** 在不安装的情况下检查兼容性与包完整性。**Verify.cmd** 在重启后检查完整的所选 INF/SYS 身份、Running/Code0 状态以及 PD 筛选驱动是否真正附着。

**Diagnose.cmd** 在 %LOCALAPPDATA%\SK-Charging-Diagnostics 下创建 ZIP，**不会上传任何内容**。ZIP 包含系统版本、驱动身份、安装记录、USB/电池状态，以及所选五组充电/电池 INF/SYS/CAT 文件的副本。分享前请先检查设备标识符和本地路径。

更新前，Install 会检查并备份所选驱动包、已识别的 PD 扩展及旧配置，保存在 %ProgramData%\SK-Charging-Community\...\Previous。**Restore.cmd** 默认使用最新备份；特定备份目录中的副本则选择对应备份。请先安全弹出并断开 USB 存储设备，运行 Restore，再手动重启。Miniclass 始终保留。遇到未知的中途修改或不完整备份，恢复流程会拒绝继续。

仅提供**公开的开发证书**；安装程序可能将其导入 LocalMachine Root/TrustedPublisher。不提供私有签名密钥、固件、摄像头或音频更新。FILES-SHA256.json 和 manifest.json 用于标识驱动包。已记录的测试并未覆盖长期稳定性和全部配件。

## ❤️ 帮助改进充电与 USB-C

这是在真实平板上进行的独立社区工作：研究供电与 USB-C、构建 ARM64 驱动、测试充电器、移动电源和集线器，以及调查可能导致设备重启的故障。进展依赖谨慎实验和反复验证。如果这个项目对你有帮助，你的支持将帮助我们继续改进充电可靠性和 USB 切换。

[![通过 DonationAlerts 支持](https://img.shields.io/badge/Support-DonationAlerts-orange?style=for-the-badge)](https://www.donationalerts.com/r/deskcj) [![通过 PayPal 支持](https://img.shields.io/badge/Support-PayPal-0070BA?style=for-the-badge&logo=paypal&logoColor=white)](https://paypal.me/vladcj)

也可以**不捐款**：给仓库点星、向其他 nabu 用户介绍项目，或提供可复现的测试结果，并注明 Windows 版本、集线器或充电器型号及连接顺序。这些反馈有助于确定下一步修复的优先级。捐款支持研究，但不保证结果或完成时间。感谢你支持独立的 Windows on ARM 项目！

## 联系我

[![Telegram](https://img.shields.io/badge/Contact-Telegram-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/deskcj) [![发送邮件](https://img.shields.io/badge/Contact-Email-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:deskcj@gmail.com)

## 免责声明

这是独立的社区项目，**与 Xiaomi、Qualcomm 或 Microsoft 没有关联，也未获得其认可**。公司和产品名称仅用于说明兼容硬件及技术，其权利归各自所有者。原有 Qualcomm 驱动及其声明归权利人所有；原始 fix20 的作者身份尚未确定。

驱动属于采用测试签名的实验性内核软件，按**“原样”**提供，不保证稳定性、支持服务或达到 Android 的充电速度。可能出现系统崩溃、无法启动、设备故障或数据丢失。安装前请保留备份和恢复方法。是否测试以及相关风险由你自行决定。本文不授予违反许可协议重新分发第三方组件的权利。
