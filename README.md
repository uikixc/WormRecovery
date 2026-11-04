# WormRecovery

Windows 蠕虫检测与原位恢复工具，当前版本为 **1.4.2**。针对已分析的 AutoIt / Synaptics 感染特征，提供文件检测、确认感染项修复和复核。

1.4.2 减少程序文件检查中的重复打开和规则初始化工作，复用有界且按文件实际大小读取的字节；不缩减内容规则。扫描队列非阻塞结果收集不再反复分配等待器。界面新增检查异常列表，直接说明活动分页文件等读取限制，错误和内容未检查状态继续保留。详细实测范围见 docs/RELEASE_1.4.2.md。

1.4.1 修复新增 XLM 库的导入提示污染 VBA 分析 JSON 通信，导致正常宏被误报“解析失败”的回归问题。引擎提示单独记录，未知结构和真实解析错误仍保留失败状态；不通过放宽白名单消除异常。另将内部工作进程临时目录收拢到已保护的工作区，并修复脚本扩展名未进入内容检测队列的问题。详见 docs/RELEASE_1.4.1.md。

只需复制 WormRecovery.exe。宏分析、命令行、ClamAV 病毒库、capa 和 REA 本地运行组件已嵌入，目标电脑不需要 Python、Node、Codex 或网络连接。运行时自动解包内部组件，因此启动速度和临时磁盘占用与原来的轻量版本不同。

离线分析现已实际接入 YARA-X 内容组合规则、AutoIt 静态提取、XLMMacroDeobfuscator 有界模拟、ClamAV 批量复核、capa 程序能力分析和 REA PE 导入分析。VBA 继续提取源码、MacroRaptor 标记及 pcodedmp 编译指令。复杂分析只针对筛选后的未解决候选文件，不逐文件启动全部引擎。

每项复核记录文件 SHA-256、实际引擎、病毒库版本、命中及失败原因。ClamAV 一批候选只加载一次病毒库；分析子进程有超时和 Windows 作业对象内存限制，超时结束其子进程。当前内置 REA 静态 PE 分析，不包含 Ghidra/JDK 深度反编译。未知宏和分析失败不会直接转为安全，也不会据此删除整份文档。

## 功能

- 提供“本机全盘”“可移动设备”和手动选择扫描范围；按物理设备归集可移动设备的全部盘符，并检查设备连接状态变化。
- 检查已知程序包装感染、恶意脚本、快捷方式以及相关持久化配置。
- 检查已确认的 Excel 宏感染；优先查找同路径历史原件，没有合适历史原件时清除已确认的恶意宏，并校验当前工作表内容。恢复结果写回原目录。
- 修复时默认处理占用感染文件的非关键应用；记录操作及隔离备份。系统关键进程受保护。
- 检查本次范围内的重解析点目标并去重；访问失败、未知结构及未完成检查会单独报告，不作为已清理结论。

活动病毒进程的遏制与磁盘文件处理范围分别判断；保护设备文件不会放任经指纹确认的病毒进程继续运行。关联清理已确认启动项的状态记录、已知家族残留快捷方式和处理后为空的家族目录；有未分类文件的目录予以保留。界面显示当前扫描路径、文件处理速度和当前项目耗时。

## 环境要求

只读文件检测采用有界线程池：识别为无寻道惩罚的设备默认最多 4 个读取线程，机械盘及类型未知的设备限制为单个读取任务；同一物理设备的多个盘符共享读取限额，总线程数不超过 8。文件内容检测结果由单一协调线程汇总，修复和文档写回仍逐项执行。Office 宏解析器受独立锁保护。

线程数更多并不保证更快，实际效果取决于文件数量、磁盘延迟、系统缓存和解析开销。停止后取消尚未开始的工作，等待正在执行的读取返回，不将未完成扫描报告为完成。

- 集成发行版需要 Windows 10 / 11 64 位系统。
- 从源码运行或构建时需要 Python 3.12、Tcl/Tk 和离线组件；使用发行版无需自行安装。
- 修复操作需要管理员权限。

在项目目录中执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe worm_recovery.py
```

## 命令行

```powershell
# 扫描本机磁盘
python cli_entry.py --scan --scope internal

# 扫描已连接的可移动设备，包含同设备的全部盘符
python cli_entry.py --scan --scope removable

# 扫描指定位置
python cli_entry.py --scan --root "C:\Data"

# 如需手动限制扫描线程，可设置 1 至 8；默认自动选择
python cli_entry.py --scan --scope internal --workers 4

# 扫描并修复确认感染项（管理员终端）
python cli_entry.py --clean --scope internal
```

退出代码：`0` 为检查完成且未报告确认感染项或未确认文件，`1` 为检查或复核未完成，`2` 为检测到需要处理的感染项，`3` 为文件检查结束但存在未确认的宏或脚本。`0` 仅描述本工具的检测范围，并不证明系统不存在其他威胁。修复期间默认关闭占用目标文件的非关键应用，使用前应保存工作。

结果分为“确认感染”“需进一步检查”和“组件说明”。已核对 Office 组件要求安装目录、文件名和完整文件 SHA-256 同时匹配，且本次解析未发现家族宏或解析失败；该结论仅表示与已静态核对的文件一致，并非 Microsoft 签名认证或全威胁安全证明。组件说明项不计入感染及待核查数量，不执行删除、格式转换或宏移除。选择结果可查看判定原因、建议操作和结论范围。未确认的宏文件保留原件、保持宏禁用，不自动删除；解析失败单独报告。

操作报告与隔离备份默认保存在 `%ProgramData%\WormRecovery`。文档目标路径已存在时保留双方文件并报告冲突；未知宏及不能安全处理的文档保留并标记待核查。历史原件可能早于最近编辑时间，因此应结合报告确认内容。

## 测试

在 Windows 上运行：

```powershell
python -m unittest discover -s tests -v
```

测试使用模拟接口、临时文件和无害文档结构，不依赖真实恶意样本。符号链接回归测试需要管理员权限或系统已启用开发者模式。测试不执行病毒样本，也不启动实际全盘清理。

无控制台回归测试在新进程中移除标准输出和错误流，再加载实际宏解析器，覆盖图形版运行环境。解析失败会明确记录为异常，并阻止“检查完成”结论。

## 构建

先从上游官方发行版准备固定版本的 capa 10.0.0、ClamAV 1.5.4 Windows 便携包、REA 6.8.0 与 Node 26.13.0，以及经 FreshClam 校验的 main.cvd、daily.cvd、bytecode.cvd。按实际准备位置执行：

    python prepare_engine_assets.py --tool-root C:/Build/offline-engines --rea-root C:/Build/rea --database-root C:/Build/clamdb --destination build/engine-assets/engines

运行时不下载依赖。新增源码包括 secondary_analysis.py（候选复核）、local_rules.py（内容规则）、engine_assets.py（引擎定位）、engine_process.py（进程生命周期）、prepare_engine_assets.py（组件准备）和 validate_offline_engines.py（真实引擎无害验证）。

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Python .\.venv\Scripts\python.exe
```

最终交付文件为 `dist\WormRecovery.exe`。命令行与宏分析组件在构建中先生成到 `build\embedded`，再嵌入主程序的 `engines` 目录；用户只需复制最终主程序。运行时自动解包到临时工作目录，内部仍采用独立进程；单文件指交付方式，不表示执行期间不产生工作文件。命令行参数也可以传给同一个主程序，报告按原规则保存。分发构建需要在干净 Windows 环境中验证。

## 源码结构

| 文件 | 用途 |
| --- | --- |
| `worm_recovery.py` | 检测、修复、原位恢复、持久化检查与复核 |
| `modern_ui.py` | 图形界面 |
| `device_scope.py` | 物理设备识别和扫描范围管理 |
| `reparse_scan.py` | 重解析点解析和目标检查 |
| `worm_residue.py` | 已确认家族残留指纹和精确路径匹配 |
| `scan_concurrency.py` | 有界扫描队列、物理磁盘识别与并发限制 |
| `office_triage.py` | 精确 Office 组件核对、未确认文件分类与处理建议 |
| `office_structure.py` | OOXML 活动内容与结构检查 |
| `office_analysis.py`、`analysis_entry.py` | 离线宏源码和编译指令分析及受限输出子进程 |
| `persistence_inventory.py` | 计划任务、服务与 WMI 枚举和身份核验 |
| `bundled_components.py` | 单文件内嵌组件定位 |
| `cli_entry.py` | 命令行入口 |
| `tests/` | 无害回归测试 |
| `build.ps1` | Windows 可执行程序构建 |

本仓库仅保存源码、依赖、构建配置和无害测试。真实样本、程序成品、用户文档、操作报告、隔离备份及本机设备配置均不纳入版本控制。

## 检测与恢复边界

检测与自动修复依据已分析家族的指纹和结构，无法覆盖全部恶意软件或保证恢复已被覆盖、加密、删除的历史内容。未匹配的感染变种、混合合法宏、损坏或加密文档、无法访问的位置需要进一步核查。重要系统文件若无法安全恢复，应使用可信安装介质和 Windows 官方修复机制处理。

当前集成状态见 [1.4.0 说明](docs/RELEASE_1.4.0.md)。完整规划及尚未实现的恢复环境、离线用户配置单元、Ghidra 深度分析等见 [离线检测与恢复集成评估](docs/OFFLINE_ANALYSIS_INTEGRATION.md)。
