# 2026-09-29 正常采集软件名称修复

根因：旧README示例固定传入Benign_NotepadPlusPlus，并使用benign_notepadpp运行名前缀。SHA256只作标识，不会自动查找程序名称。

更新：新增host/run_benign_realtime.ps1，每轮显式输入软件名称和SHA256；receiver 1.2.0保存software_name和operator_declared来源，统一生成family，拒绝名称冲突与缺名称的旧Benign_*调用；preprocess 2.0.1保留metadata软件名称，允许审核CSV覆盖。28字段/148维模型契约不变。

用法（物理机PowerShell）：

```powershell
Set-Location D:\SysmonRealtime
$python = (py -3 -c 'import sys; print(sys.executable)').Trim()
.\host\run_benign_realtime.ps1 -PythonExe $python
```

按提示输入本轮软件名（例如SumatraPDF）和虚拟机中实际exe的SHA256。默认输出D:\SysmonBenignLogs\thesis-v1_1-batch01，默认300秒。看到recording再手动操作虚拟机软件。可用-SoftwareName、-SoftwareHash、-OutputRoot指定参数；-Preview只查看，不采集。详细说明见主README第8节。

验证：receiver测试31项通过，7项原有环境相关测试跳过；预处理43项通过。PowerShell7.6及Windows PowerShell5.1均完成Preview与参数检查。模拟管道验证SumatraPDF、LibreOffice、带空格的软件名和中文名称。未启动虚拟机或真实采集。

新名称由操作者声明，不是由SHA256自动认证。原始历史日志不修改；旧批次可继续使用，在预处理review_template.csv的software_name和group_id中纠正身份，不需要仅因名称写错重采。
