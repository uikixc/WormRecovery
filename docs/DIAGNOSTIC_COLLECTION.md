# 诊断资料收集与服务部署

采集功能从 1.7.0 起提供，1.7.1 按部署要求改为 HTTP 压缩传输。客户端仍以一个 WormRecovery.exe 分发。当前电脑可以同时运行客户端和接收服务，其他电脑只需运行客户端。

## 地址与传输

设备配置默认依次尝试 HTTP 内网 10.205.103.120:10888 和外网 8.134.112.170:10888。服务监听 TCP 10888；云安全组、主机防火墙及可能存在的端口映射都必须允许访问。服务只接收诊断资料，不提供远程命令执行或样本运行接口。

上传使用 gzip 压缩二进制正文，不再建立 TLS 会话、不使用加密封套或 Base64 包装。SHA-256 用于发现内容不一致，不提供传输加密或网络攻击防护。设备上传授权和独立管理授权仍保留，上传授权不能读取服务器保存的报告。授权在客户端使用 Windows DPAPI 保存，此保护只涉及本机凭据存储，不参与网络传输。

不要把 collector-server.json、admin-access.txt 或 devices.enroll 提交到公开仓库。向受检电脑分发 devices.enroll。1.7.0 的服务可停止后执行 migrate-http --directory 数据目录，再启动 1.7.1 接收程序；旧配置会保留 .v1-backup 备份。重新导入迁移后的设备配置，并使用 1.7.1 客户端。旧版加密队列不能由新版 HTTP 接收程序直接处理，应保留原密钥及队列，并从保留的扫描报告重新提交。

## 采集范围

- 完整扫描报告中的检测项目、待核依据、文件路径和已有哈希、宏行为指标、Office 结构关系、各引擎结果与规则版本。
- 操作日志、解析异常、访问受限原因、处理及恢复结果、复核结果、扫描范围和磁盘类型、线程数、各阶段耗时。
- Windows 版本、架构、逻辑处理器数量、内存情况、随机生成的设备编号，以及更新失败等应用故障事件。

本机账户目录名称、主机名称和常见凭据字段会被移除或脱敏。不读取待核文件原件，不上传文档正文、隔离文件、浏览历史、环境变量或访问凭据。诊断字段及文件名仍可能包含业务信息，应限制服务端目录访问。

单份扫描报告和日志各限 16 MiB，合并资料上限 20 MiB，传输包上限 12 MiB。客户端队列最多保留 20 份，超限时明确提示，不覆盖未提交资料。队列保存的是 gzip 压缩资料，不是加密文件。服务器默认存储上限 10 GiB，保留 90 天，在启动和接收时检查过期资料，每小时最多清理一次。上传在后台执行，不参与文件扫描队列；收到匹配诊断编号的接收凭据后才删除本地队列文件。

## Windows 服务器

以管理员身份在服务器上运行部署包内的 deploy/install-collector.ps1。脚本部署独立接收程序、限制目录权限、注册开机计划任务并创建 TCP 10888 入站规则。它不会修改云安全组。

    powershell -ExecutionPolicy Bypass -File .\deploy\install-collector.ps1

默认配置位于 C:\ProgramData\WormRecoveryCollector\collector-data。向客户端分发其中的 devices.enroll，保管其他文件。

手动运行或调试：

    .\WormRecovery-Collector.exe init --directory C:\WormRecoveryCollector\collector-data
    .\WormRecovery-Collector.exe serve --config C:\WormRecoveryCollector\collector-data\collector-server.json
    .\WormRecovery-Collector.exe summary --directory C:\WormRecoveryCollector\collector-data\received

## Linux 服务器

需要 Python 3.11 或以上、venv、systemd、useradd、runuser。将源码部署包复制到服务器后执行：

    sudo sh deploy/install-collector.sh

HTTP 接收程序只使用 Python 标准库，无需下载第三方 Python 依赖。部署脚本创建独立虚拟环境和 systemd 单元。

默认服务数据位于 /var/lib/wormrecovery-collector，运行账户为 wormcollector。部署脚本不会调整云安全组和 Linux 防火墙规则。运维操作：

    sudo systemctl status wormrecovery-collector
    sudo journalctl -u wormrecovery-collector -n 50
    sudo -u wormcollector /opt/wormrecovery-collector/venv/bin/python /opt/wormrecovery-collector/collector_server.py summary --directory /var/lib/wormrecovery-collector/received

## 受检电脑

1.7.2 起，扫描与处理分别保存独立操作快照和日志，使用不同操作编号并共享会话编号。扫描完成即可提交，无需先处理；处理后的复核资料另存另传。完成、停止和异常结束均记录状态。快照保存在扫描报告目录的 operations/操作编号/，处理不会覆盖已经保存的扫描证据。

打开“诊断反馈”，导入 devices.enroll 后自动启用完成任务后的提交。可以提交当前诊断、重试队列或暂停自动提交。暂停后保留待提交队列。命令行等效入口：

    WormRecovery.exe --enroll-diagnostics C:\path\devices.enroll
    WormRecovery.exe --submit-diagnostics C:\path\report.json
    WormRecovery.exe --diagnostics-status
    WormRecovery.exe --retry-diagnostics
    WormRecovery.exe --disable-diagnostics

GET /health 仅公开服务存活和协议版本。GET /v1/status 要求独立管理授权，只返回存储统计。没有公开报告下载端点。summary 命令在服务器本地按文件哈希和判定依据汇总待核项；默认读取最近 1000 份报告，并显示总存储份数和读取范围。

1.7.4 起，“检测日志服务器”分别检查内网和外网地址，GET /v1/upload-check 仅验证上传授权，不提交报告、不读取已收资料。服务可连接、上传授权通过、报告已获得接收凭据为三个不同状态。空队列不会显示本次上传成功。服务端 receiver-requests.jsonl 保存 POST 请求时间、来源、HTTP 状态及接收编号，最多保留当前和上一份各约 2 MiB 的记录。

命令行连接检测：WormRecovery.exe --check-diagnostics-connection。

资料汇总为后续规则完善提供证据。客户端继续依赖可解释的本地分析和签名发行版，不会把上传内容直接变成删除规则，也不会宣称收到资料即完成模型训练或未知威胁识别。

## 构建与验证

客户端：build.ps1。Windows 接收程序：build-collector.ps1。测试 tests/test_diagnostics.py 覆盖真实本机 HTTP 接收、授权隔离、gzip 直接传输、校验和异常、断网队列、匹配凭据、去重冲突、解压上限、脱敏和过期清理。

Windows 接收服务经本机测试；Linux 安装脚本需在目标 Linux 环境验收。未取得并使用目标服务器登录方式前，不能据本机测试宣称公网服务已部署。
