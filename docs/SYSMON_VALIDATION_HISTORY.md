> 历史 v1.0 文档。当前规则已更新为 v1.1.1，部署与范围请以 [2026-09-14 更新说明](UPDATE-20260914.md) 为准。本文旧哈希、全量注册表设计及体积估算不代表当前配置。

> 本文件是整理前的设计/验证记录，保留原日期和原包路径。当前项目操作以根目录 README.md 为准；本次测试见 INTEGRATION_CHECKS.md。

# 验证记录

验证日期：2026-09-11。状态：**静态检查通过；虚拟机运行验证待完成**。

## 实际完成

- 固定上游源文件提交 `a9ff298f6d228c181be71b213c73d111c6096f41`，保留原始字节与许可证。
- 上游 XML SHA256：`81933b12ec8df9edcb1175aff7db0dfc0076600d1ee4f71f7606869146449a0f`。
- 生成 XML SHA256：`0415d4b81db659f0c01d2f449fd57642229188e711dd963445b2a3ceb824f08e`。
- XML 解析成功，schema 属性为 `4.90`，完整处理上游全部 22 个可过滤类别标签。
- 15 个宽范围类别：每类恰有一个空 exclude 节点，没有额外包含或排除规则。
- 4 个关闭类别：FileDelete、ClipboardChange、FileBlockExecutable、FileBlockShredding，每类恰有一个空 include 节点。
- DriverLoad、ImageLoad、ProcessAccess 的 RuleGroup 属性、匹配字段、值及包含/排除关系与上游一致。
- HashAlgorithms 仅 SHA256；CheckRevocation 与 DnsLookup 为 False；无 CopyOnDelete 或 ArchiveDirectory 配置项。
- 同一固定上游离线重建后，生成 XML 与重建前逐字节相同。
- 负向检查：故意启用阻止功能、插入文件创建排除条件、改变保留的进程访问规则，均被验证器拒绝。负向检查在临时副本完成，交付 XML 未被修改。
- PowerShell 自检脚本语法解析通过；未执行脚本的文件、注册表或进程操作。

## 未执行及其含义

- 未在用户虚拟机加载配置；XML 可解析不等于目标 Sysmon 接受全部字段与 schema。
- 未运行 Sysmon 驱动级 schema 验证；需要使用虚拟机实际二进制加载确认。
- 未执行本地事件自检；八项预期结果不是已测结果。
- 未进行串口端到端负载测试；宽范围文件/注册表事件可能比旧规则产生更多日志。
- 未执行勒索软件，未修改物理机或虚拟机的 Sysmon、采集器、接收器与快照。
- 未重新训练 CNN-LSTM，无法据此声称检测准确率或召回率已提高。

放行顺序：支持的 schema 与当前配置核对 → 加载 → 无害本地自检 → 同一标记的主机 XML 核对 → 少量正常/勒索试采与质量审核 → 固定配置指纹和新快照 → 正式采集。
