# 正常工作负载 v1.0 验证记录

日期：2026-09-30。执行环境：Windows，Windows PowerShell 5.1。

- documents、archive、backup、reports、cleanup、mixed六个场景均成功执行单循环、3文件、1KiB的小规模测试。
- documents完成临时保存、覆盖、删除与重命名；archive压缩/解压逐文件SHA256相同；backup复制与更新校验成功；reports生成并重读CSV后输出JSON/HTML；cleanup只删除本轮生成的文件。
- 每轮操作计数与actions.jsonl行数一致；目录外哨兵文件SHA256不变；动作路径都位于本轮目录。
- 相同seed重复运行的生成文本逐字节相同。
- 盘符根目录、相对路径、暂停上限小于下限被拒绝。
- 1秒时间限制、80循环上限测试在循环边界以duration_limit结束，并未跑满80轮。
- host/run_scripted_benign.ps1 Preview正确生成Scripted_archive名称、对应family、独立scripted-v1输出路径。

这些测试验证本地工作流功能和路径边界，不是Sysmon事件覆盖或分类效果验证。未启动VMware、未执行样本、未采集虚拟机日志。默认240秒规模未做完整虚拟机端压力测试。
