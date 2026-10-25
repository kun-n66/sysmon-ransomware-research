> 本文件是整理前的设计/验证记录，保留原日期和原包路径。当前项目操作以根目录 README.md 为准；本次测试见 INTEGRATION_CHECKS.md。

# 验证报告

日期：2026-09-08（更新就绪探测错误诊断、已完成结果检测及接收端退出收尾）。

## 结果

- C# 主程序使用 Windows 自带 .NET Framework C# 编译器编译成功，开启 `/warn:4 /warnaserror+`，无编译警告。
- Python 测试使用 Python 3.12.14。
- 25 项 Python/C# 自动化测试通过。
- PowerShell 外部进程参数往返测试、超时终止测试通过。
- PowerShell 脚本语法检查通过。
- 已在 Windows PowerShell 5.1 下运行完整测试；PowerShell 7 下也验证了完整测试。

## 已覆盖的行为

| 范围 | 验证内容 |
|---|---|
| 实际本地传输 | C# `NamedPipeServerStream` → Python Win32 重叠 I/O 客户端，不使用网络 |
| 跨语言协议 | C# 实际序列化代码、分片 UTF-8、中文、引号、XML 转义、消息版本及长度限制 |
| C# 发送队列 | 有界队列溢出、序号、停止后排空、END 中 observed/sent/dropped 统计 |
| 实验关联 | SHA-256 名称解析、非法标识拒绝、旧 run_id 排除、READY 哈希匹配 |
| 时间窗口 | 样本 ID 1 触发、无匹配进程超时、immediate 模式、源时间加观察时长 |
| 文件输出 | 可解析的 XML、原始事件嵌入、日志 SHA-256、独立实验目录、拒绝覆盖 |
| 异常结果 | 命名管道断开、重复序号、序号缺口、队列溢出、计数不一致、订阅错误 |
| 崩溃恢复 | 丢弃不完整尾记录、补全 XML、保留原始中断文件、重新计算哈希、标记 incomplete |
| 接入脚本 | 用 mock vmrun 和假 VMX 跑通真实控制脚本的就绪/启动信号/采集/收尾流程 |
| 断点续跑 | 第二次控制脚本运行验证已有 XML 哈希后跳过，不重复调用 mock VM 操作 |
| PowerShell | 空参数、空格、引号、尾反斜杠、中文参数、UTF-8 输出、进程超时、5.1 JSON 数组兼容性 |

完整自动化结果：`Ran 25 tests ... OK`。新增测试模拟 Guest 登录失败，验证原始错误会显示、最终超时包含最后错误、密码被脱敏，并执行实验后的快照恢复流程。

另有接收进程迟退回归测试：真实接收端完成 XML 和元数据提交后，测试包装器继续休眠 30 秒。控制脚本检测结果、核对 XML SHA-256，经测试设定的 2 秒退出宽限后终止该测试接收进程、写入 `controller_result.json` 并恢复 mock 快照；无需等待整个实验总超时。生产默认退出宽限为 10 秒。

## 测试边界

上述 C# 测试通过测试入口注入合成的 Sysmon 结构 XML；使用了生产代码中的队列和 JSON 序列化。没有在实际 Windows 10 虚拟机中验证 `EventLogWatcher → COM1 → VMware → Python` 的完整硬件虚拟化链路。

没有下载、打开或执行任何勒索软件样本，没有调用真实 `vmrun`，没有更改虚拟机、快照、Sysmon 配置或计划任务。接入脚本测试使用专门的 C# mock，不会执行传入的样本路径。

因此，本报告不声称已经验证 VMware 虚拟串口吞吐量、实际 Sysmon 事件覆盖率、样本启动行为、源日志防清除能力或零丢失保证。请按 README 先完成无害联通测试，并在代表性负载下确认队列峰值、dropped 与排空时间。

## 重现

在 Windows 的项目根目录运行：

```powershell
.\guest\build.ps1
.\tests\run-tests.ps1 -PythonExe 'C:\Python312\python.exe'
```

测试会在临时目录编译 `GuestHarness.exe`，无需安装 Sysmon 或配置 VMware。
