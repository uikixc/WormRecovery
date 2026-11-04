# WormRecovery 离线检测与恢复集成评估

评估日期：2026-11-05。基线：WormRecovery 1.3.5；本机 REA 6.8.0。

本文是对现有源码与官方资料的差距评估和实施方案，不表示下述组件已接入成品，也不表示安装组件即可证明系统已清理。目标是在没有网络、没有 Codex、没有远程模型的 Windows 电脑上自动检测、关联证据和执行已验证的原位恢复。

## 1. 现有代码的具体缺口

| 位置 | 已观察到的实现 | 对清理完整性的影响 | 需要补齐的能力 |
| --- | --- | --- | --- |
| `worm_recovery.py::_office_check` | OOXML 内未找到 `vbaProject.bin` 就返回 `clean`；找到 VBA 后主要检查两个指纹和四个家族字符串 | 不能将此结果解释为整个文档安全；尚未全面检查 XLM 宏、DDE、外部关系、嵌入对象和源码与编译代码不一致 | 文档结构、VBA 源码、P-code、XLM、DDE、嵌入对象分别记录检查结果和覆盖状态 |
| `worm_recovery.py::inspect_file_content` | 由扩展名分派；通用脚本和压缩档没有对应扫描管线 | 改名文件、脚本载荷、压缩档中的样本需要额外检测 | 内容类型识别、脚本归一化、受限递归解包；扩展名与内容不一致单独记录 |
| `worm_recovery.py::registry` | 检查本机及已加载用户配置单元中的三类 Run 路径 | 未登录用户及其他持久化入口不在当前实现中 | 全用户配置单元只读检查，扩展 Winlogon、IFEO、AppInit、COM 等入口；逐项验证后才修改 |
| `worm_recovery.py::system_persistence` | 计划任务、服务、WMI 主要由固定名称正则筛选；WMI 只读取 `CommandLineEventConsumer` | 改名可使候选项漏出筛选；脚本消费者、事件过滤器和绑定关系未形成完整检查 | 先枚举再分析目标内容；覆盖脚本消费者、过滤器、绑定，删除时精确关联并备份 |
| `worm_recovery.py::verify` | 复扫选定已挂载卷和现有家族入口；明确列出未验证区域 | 同一组规则复扫为零不能证明未知变种或遗漏入口已清除 | 独立核验、重启后复核、未完成检查阻断完成结论 |
| `office_triage.py::REVIEWED_COMPONENTS` | 8 个已人工核对组件的完整文件哈希加名称及安装位置匹配 | 只覆盖这些具体文件；不是 Office 组件自动认证，也不是通用行为分析 | 可信安装介质基线和内容分析；新组件不能因文件名、路径或单个工具未报警就被信任 |

这些是覆盖范围缺口，不是已在本机发现新增感染的证据。系统/隐藏属性也不能单独作为恶意或内核隐藏的证据。

## 2. 建议的组件组合

### 2.1 首先补强 Office 内容检查

- 继续使用 `oletools`，但把 `olevba`、`mraptor`、`msodde`、`oleobj` 等能力真正接入管线，而非只安装依赖。官方工具覆盖 VBA、XLM、DDE 和 OLE 对象。[S1]
- 对可疑 VBA 项目增加 `pcodedmp`，对照源码与可读编译代码中的入口、调用、字符串和数据流。差异是需要解释的证据，不能把普通反编译差异直接判成病毒。[S2]
- 对包含 XLM 宏表的文件调用 `XLMMacroDeobfuscator`；它支持 XLS、XLSM、XLSB，可在不安装 Excel 的情况下提取和模拟宏。仅允许其内部受限解释，不调用 Excel COM，不启动文档或执行还原出的命令；必须设置期限、内存和输出上限。[S3]
- 外部链接、ActiveX、嵌入对象、宏和隐藏工作表可能有合法用途；检测与修复分开。未知合法宏不得因可疑评分而全部删除。

### 2.2 本地规则扫描：YARA-X

YARA-X 提供 Windows 程序和 C/C++、Python 等接口，适合扫描本地文件及提取出来的脚本、宏和嵌入内容。[S4]

建议以经过测试的家族结构规则取代仅依赖完整文件哈希的识别。规则包含稳定结构、多个独立特征及排除条件，不能只匹配 `GoogleChrome`、`Synaptics` 或 `Shell` 等单个名称。YARA-X 是规则执行器，需要另行维护、授权和验证规则库。命中规则与能否安全恢复是两个结果。

编译规则复用，每个工作线程使用独立 scanner；不要为每个文件重新启动命令行和加载全部规则。[S4]

### 2.3 AutoIt 提取与脚本归一化

`AutoIt-Ripper` 可以静态提取 PE 中支持格式的 AutoIt 脚本，适合本次家族的分析方向。[S5]

独立 `.a3x` 必须用实际格式确认支持范围；不能把支持 PE 内嵌脚本当作所有 A3X 均可解码。未支持或提取失败要报告未知。归一化器只解释有严格语法和资源限制的常量表达式，例如字符串拼接、有限算术及 `Chr`/`ChrW`；禁止通过 `eval`、AutoIt、PowerShell 或 cmd 执行可疑内容。

将快捷方式目标、工作目录、命令行、提取脚本、落地文件和启动项组成证据链，识别改名后的同类行为。

### 2.4 通用防病毒引擎：ClamAV，加可用的系统 Defender

- ClamAV 官方提供 Windows 便携 ZIP，适合准备离线组件包。扫描需要本地病毒库，必须显示库版本和日期；更新在联网的干净电脑完成，再经离线导入。[S6][S7]
- 初期使用单独进程适配 ClamAV，默认只返回检测证据，不使用自动删除参数。后续如需常驻 `clamd`，需限制在本机、验证调用方并管理生命周期，不暴露未认证扫描接口。[S7]
- Defender 只调用目标系统已具备且可用的功能，不复制其二进制当作通用可再分发组件。定制扫描支持 `-DisableRemediation`，仅该扫描模式适用；不能用退出码 0 直接证明没发现感染，官方文档说明 0 也可能代表已发现并完成处理。[S8]
- Defender 病毒库可通过微软提供的手动更新包准备；没有联网和更新时，不能声称具有云端能力或最新情报。[S9]
- 两种引擎都以实际覆盖和失败状态报告结果，不用简单多数投票决定文件安全。外部杀毒软件的自有修复及实时保护可能独立于本工具运行，不能承诺它们遵循本工具的文件保护策略。

### 2.5 全面持久化检查：Windows API 为主，Autoruns 作交叉核对

实现对启动文件夹、Run/RunOnce、计划任务、服务及驱动、Winlogon、IFEO、AppInit、适用 COM 入口、WMI 永久事件订阅和 Office 启动加载位置的结构化枚举。覆盖所有选定用户和 32/64 位视图，不先按已知家族名称排除候选项。

Autoruns/Autorunsc 官方列出了包括 WMI、服务、驱动、Winlogon、劫持等大量入口，支持其他用户与离线 Windows 的检查，可作开发和维护时的对照。[S10] WMI 永久订阅包含消费者、过滤器和绑定，脚本型消费者也能执行代码；必须检查整个关联关系。[S11]

Autorunsc 在产品中仅适配用户另行取得的合法副本，不随安装包捆绑。微软 FAQ 明确不提供这类再分发许可。[S12] 离线模式不使用 VirusTotal 参数；签名核验另走明确禁止网络检索的实现。

### 2.6 可执行文件能力识别：capa，必要时再调用 REA/Ghidra

capa 能从 PE、ELF、.NET 等目标识别程序能力，并提供无需安装的独立程序。[S13] 可用来解释进程创建、服务安装、文件操作等候选能力；正常程序也具有这些能力，所以输出不能直接等同恶意结论。

REA 本地工具及 Ghidra 用于少量复杂样本的静态深入分析；分发包固定版本并带齐 Node、JDK、所需引擎和依赖，禁止运行时 `npx` 下载或寻找 Codex 的用户目录。[S14] 未配置引擎或不支持格式时记录未完成；不能回退为安全。

这层不作为全盘逐文件的必经步骤，也不作为第一版对任意未知病毒自动判定的承诺。

### 2.7 信任验证与 Windows 恢复

- 对适用 PE 和目录签名使用 Windows 原生信任接口，明确设置 `WTD_CACHE_ONLY_URL_RETRIEVAL` 禁止联网检索。[S15] 把内容签名、证书链、吊销信息是否可用分别报告；无网时吊销新鲜度可能未知。Office 宏签名是另一种格式，不能用 PE 证书解析器或签名存在本身证明其合法。
- 系统文件损坏时，接入 SFC 和 DISM 结果；DISM 支持指定本地修复源并用 `/LimitAccess` 避免 Windows Update。[S16] 需要与系统相匹配的可信修复源；这不能替代用户文档恢复，也不能把感染的组件存储当作可信原件。
- 对重启后仍复现、内核运行环境不可信或普通扫描无法访问的问题，提供可信启动环境下的检查路径。Microsoft Defender Offline 从正常 Windows 内核之外扫描，有系统、WinRE 等前提，可能重启电脑。[S17] 这里的 Offline 同时指脱离被检查的运行系统，不只是断网。研究样本保护在外部引擎和恢复环境中必须另行验证，不能默认继承当前程序配置。

## 3. 需要自行开发的核心能力

1. **统一证据与决策层。** 记录文件身份、引擎版本、规则/库版本、覆盖范围、发现、置信依据和缺失证据。区分确认感染、存在可疑行为、未发现匹配、检查未完成。没有报警不是安全证明；签名有效也不能覆盖已确认恶意内容。
2. **受控分析进程。** 解析器和模拟器使用受限子进程，限制时间、内存、输出、解包层数及大小；校验包成员路径，不跟随越界链接，禁止外联和执行提取内容。分析进程最小权限，只有恢复协调器持有所需写权限。
3. **原位恢复事务。** 检测和写回之间再次校验文件身份；先保存备份，再原子提交；保留单元格、公式、图表、样式、合法嵌入内容和其他业务部分。分别记录恶意内容移除与业务内容一致性；不能仅靠改扩展名证明已恢复。
4. **遏制与复发核验。** 先停止经证据确认的活动载荷、解除已确认持久化，再处理文件；复扫文件及入口，并提供重启后核验。只关闭确认感染文件的必要占用程序，不盲目终止系统关键进程。
5. **独立完成检查。** 未读取文件、引擎缺失、超时、损坏/加密内容、离线用户配置单元、未挂载卷和受保护范围分别列出；未完成检查不得算作零感染。
6. **可信离线更新。** 组件、规则、病毒库带清单、签名/校验、版本和回滚信息，防止更新包篡改和旧规则覆盖。目标机没有网络时仍能完整启动；无可用组件要清楚报告。
7. **磁盘感知调度。** 保留现有按物理磁盘限流；快速筛选后才解包和深度分析。缓存键同时包含文件内容、引擎和规则版本。每个分区共享物理设备读取预算，避免机械盘被多个引擎同时遍历。

本地大模型可在以后辅助解释分析结果，但不作为离线基础依赖，不直接批准删除或写回文件，也不据此承诺未知威胁可全部判断。

## 4. 建议实施顺序与验收

| 阶段 | 范围 | 必须通过的验收 |
| --- | --- | --- |
| P0 | Office 多层内容检查、完整持久化清单、统一覆盖状态 | XLM 且无 VBA 项目不再误报整份文档安全；P-code 不一致、嵌入对象和解析失败有单独结果；WMI 脚本消费者及未加载用户测试夹具可被发现 |
| P1 | YARA-X、AutoIt 提取、离线 ClamAV 适配、可用 Defender 适配 | 改名和不同哈希的无害家族结构夹具仍被识别；合法 AutoIt 和 Office 宏样本不被自动破坏；引擎失败/旧库有明确状态 |
| P2 | capa、REA/Ghidra、签名/安装介质基线、归档与 ADS 扩展检查 | 无网且无 Codex 的干净虚拟机能够启动、分析和输出证据；不支持格式及压缩档资源上限不被算作完成 |
| P3 | 恢复环境与系统修复协调、重启后复核 | 重启恢复流程可追踪；指定本地修复源；业务内容、原路径、冲突保留及恢复回滚通过验证 |

每阶段都需要测误报、漏检、超时及文件内容完整性。测试应包含多个 Office 版本、不同用户名和盘符、多分区可移动设备、机械盘与固态盘、中文/长路径，以及断网和没有分析组件的场景。对未知恶意行为只扩大检测，不自动扩大文档破坏性修复。真实样本研究在独立隔离环境进行，不能通过重新感染日常工作机验证；本次评估没有执行、修改或清理 U 盘样本。

## 5. 分发约束

- 内部模块与工作进程分别管理；1.3.7 已将现有命令行和宏分析组件嵌入单个 EXE，用户只需复制一个程序。未来引擎仍按相同的集成目标开发，但不把 Android、抓包、固件等无关工具塞入 Windows 蠕虫修复成品。
- REA 自身 MIT 不代表第三方引擎和规则也采用 MIT；逐项保留实际版本、许可和通知。[S14]
- `pcodedmp` 为 GPL-3.0；ClamAV/libclamav 为 GPLv2，官方明确指出直接链接 libclamav 的软件必须符合 GPL 要求。分发二进制前确定对应源码、许可及可组合性方案，不能因为仓库是私有的就忽略义务。独立进程不是自动免除许可要求的保证。[S2][S18]
- Autoruns 不捆绑分发；适配用户自备副本或自行实现 Windows 原生枚举。[S12]
- 离线更新和可信安装介质是维护过程的一部分。一次预装组件无法持续获得之后的新规则和威胁情报。

## 6. 官方来源

以下资料于 2026-11-05 核对；最终集成应固定具体版本，而非跟随上游 main/master 自动变化。

- [S1] oletools：<https://github.com/decalage2/oletools>
- [S2] pcodedmp（能力、限制及许可）：<https://github.com/bontchev/pcodedmp>
- [S3] XLMMacroDeobfuscator：<https://github.com/DissectMalware/XLMMacroDeobfuscator>
- [S4] YARA-X C API：<https://virustotal.github.io/yara-x/docs/api/c/c-/>；安装：<https://virustotal.github.io/yara-x/docs/intro/installation/>
- [S5] AutoIt-Ripper：<https://github.com/nazywam/AutoIt-Ripper>
- [S6] ClamAV Windows 安装：<https://docs.clamav.net/manual/Installing.html>
- [S7] ClamAV 扫描与病毒库：<https://docs.clamav.net/manual/Usage/Scanning.html>；<https://docs.clamav.net/manual/Usage/SignatureManagement.html>
- [S8] Defender 命令行参数与返回值：<https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus>
- [S9] Defender 手动更新：<https://www.microsoft.com/en-us/wdsi/defenderupdates>
- [S10] Autoruns：<https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns>
- [S11] WMI 永久事件消费者：<https://learn.microsoft.com/en-us/windows/win32/wmisdk/monitoring-and-responding-to-events-with-standard-consumers>
- [S12] Sysinternals 许可 FAQ：<https://learn.microsoft.com/en-us/sysinternals/license-faq>
- [S13] capa：<https://github.com/mandiant/capa>
- [S14] REA：<https://github.com/morluto/rea>；另核对本机安装包 `package.json` 的版本和依赖
- [S15] WINTRUST_DATA：<https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data>
- [S16] Windows 镜像修复：<https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/repair-a-windows-image?view=windows-11>
- [S17] Microsoft Defender Offline：<https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-offline>
- [S18] libclamav：<https://docs.clamav.net/manual/Development/libclamav.html>
