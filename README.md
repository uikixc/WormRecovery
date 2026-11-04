# WormRecovery

Windows 蠕虫检测与原位恢复工具，当前版本为 **1.3.2**。针对已分析的 AutoIt / Synaptics 感染特征，提供文件检测、确认感染项修复和复核。

## 功能

- 提供“本机全盘”“可移动设备”和手动选择扫描范围；按物理设备归集可移动设备的全部盘符，并检查设备连接状态变化。
- 检查已知程序包装感染、恶意脚本、快捷方式以及相关持久化配置。
- 检查已确认的 Excel 宏感染；优先查找同路径历史原件，没有合适历史原件时清除已确认的恶意宏，并校验当前工作表内容。恢复结果写回原目录。
- 修复时默认处理占用感染文件的非关键应用；记录操作及隔离备份。系统关键进程受保护。
- 检查本次范围内的重解析点目标并去重；访问失败、未知结构及未完成检查会单独报告，不作为已清理结论。

## 环境要求

- Windows 10 / 11，建议使用 64 位系统。
- Python 3.12 或更新版本，需包含 Tcl/Tk。
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

# 扫描并修复确认感染项（管理员终端）
python cli_entry.py --clean --scope internal
```

退出代码：`0` 为检查完成且未报告确认感染项，`1` 为检查或复核未完成，`2` 为检测到需要处理的感染项。`0` 仅描述本工具的检测范围，并不证明系统不存在其他威胁。修复期间默认关闭占用目标文件的非关键应用，使用前应保存工作。

操作报告与隔离备份默认保存在 `%ProgramData%\WormRecovery`。文档目标路径已存在时保留双方文件并报告冲突；未知宏及不能安全处理的文档保留并标记待核查。历史原件可能早于最近编辑时间，因此应结合报告确认内容。

## 测试

在 Windows 上运行：

```powershell
python -m unittest discover -s tests -v
```

测试使用模拟接口、临时文件和无害文档结构，不依赖真实恶意样本。符号链接回归测试需要管理员权限或系统已启用开发者模式。测试不执行病毒样本，也不启动实际全盘清理。

无控制台回归测试在新进程中移除标准输出和错误流，再加载实际宏解析器，覆盖图形版运行环境。解析失败会明确记录为异常，并阻止“检查完成”结论。

## 构建

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Python .\.venv\Scripts\python.exe
```

生成 `dist\WormRecovery.exe`（图形界面）和 `dist\WormRecovery-CLI.exe`（命令行）。分发构建需要在干净 Windows 环境中验证。

## 源码结构

| 文件 | 用途 |
| --- | --- |
| `worm_recovery.py` | 检测、修复、原位恢复、持久化检查与复核 |
| `modern_ui.py` | 图形界面 |
| `device_scope.py` | 物理设备识别和扫描范围管理 |
| `reparse_scan.py` | 重解析点解析和目标检查 |
| `cli_entry.py` | 命令行入口 |
| `tests/` | 无害回归测试 |
| `build.ps1` | Windows 可执行程序构建 |

本仓库仅保存源码、依赖、构建配置和无害测试。真实样本、程序成品、用户文档、操作报告、隔离备份及本机设备配置均不纳入版本控制。

## 检测与恢复边界

检测与自动修复依据已分析家族的指纹和结构，无法覆盖全部恶意软件或保证恢复已被覆盖、加密、删除的历史内容。未匹配的感染变种、混合合法宏、损坏或加密文档、无法访问的位置需要进一步核查。重要系统文件若无法安全恢复，应使用可信安装介质和 Windows 官方修复机制处理。
