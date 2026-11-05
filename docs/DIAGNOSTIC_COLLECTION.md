# 诊断资料收集与服务部署

采集功能从 1.7.0 起提供。客户端仍以一个 WormRecovery.exe 分发，接收服务单独安装在服务器，不需要安装到每台受检电脑。

## 地址与传输

设备配置默认依次尝试 HTTPS 内网 10.205.103.120:10888 和外网 8.134.112.170:10888。服务监听 TCP 10888；云安全组、主机防火墙及可能存在的端口映射都必须允许访问。服务只接收诊断资料，不提供远程命令执行或样本运行接口。

服务端初始化生成 TLS 证书、X25519 加密密钥、设备上传授权与独立管理授权。客户端在发送授权和正文之前校验证书 SHA-256 指纹，诊断包另用临时 X25519、HKDF-SHA256 和 AES-GCM 加密。设备配置保存在当前 Windows 用户的 DPAPI 保护文件中，上传授权不能读取服务器保存的报告。

不要把 collector-server.json、collector-key.pem、admin-access.txt 或 devices.enroll 提交到公开仓库。只有 devices.enroll 需要通过可信渠道分发给受检电脑。更换证书或服务端加密密钥后，需要重新分发配置；已有队列依赖原服务端密钥解密，因此应保留原密钥直至队列处理完成。

## 采集范围

- 完整扫描报告中的检测项目、待核依据、文件路径和已有哈希、宏行为指标、Office 结构关系、各引擎结果与规则版本。
- 操作日志、解析异常、访问受限原因、处理及恢复结果、复核结果、扫描范围和磁盘类型、线程数、各阶段耗时。
- Windows 版本、架构、逻辑处理器数量、内存情况、随机生成的设备编号，以及更新失败等应用故障事件。

本机账户目录名称、主机名称和常见凭据字段会被移除或脱敏。不读取待核文件原件，不上传文档正文、隔离文件、浏览历史、环境变量或访问凭据。诊断字段及文件名仍可能包含业务信息，应限制服务端目录访问。

单份扫描报告和日志各限 16 MiB，合并资料上限 20 MiB，传输包上限 12 MiB。客户端队列最多保留 20 份，超限时明确提示，不覆盖未提交资料。服务器默认存储上限 10 GiB，保留 90 天，在启动和接收时检查过期资料，每小时最多清理一次。上传在后台执行，不参与文件扫描队列；收到匹配诊断编号的接收凭据后才删除本地队列文件。

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

安装时从 Python 包索引安装固定版本 cryptography。离线服务器可先在兼容环境准备依赖包，使用 pip --no-index --find-links 安装后，再按 systemd 单元部署。

默认服务数据位于 /var/lib/wormrecovery-collector，运行账户为 wormcollector。部署脚本不会调整云安全组和 Linux 防火墙规则。运维操作：

    sudo systemctl status wormrecovery-collector
    sudo journalctl -u wormrecovery-collector -n 50
    sudo -u wormcollector /opt/wormrecovery-collector/venv/bin/python /opt/wormrecovery-collector/collector_server.py summary --directory /var/lib/wormrecovery-collector/received

## 受检电脑

打开“诊断反馈”，导入 devices.enroll 后自动启用完成任务后的提交。可以提交当前诊断、重试队列或暂停自动提交。暂停后保留已加密的队列。命令行等效入口：

    WormRecovery.exe --enroll-diagnostics C:\path\devices.enroll
    WormRecovery.exe --submit-diagnostics C:\path\report.json
    WormRecovery.exe --diagnostics-status
    WormRecovery.exe --retry-diagnostics
    WormRecovery.exe --disable-diagnostics

GET /health 仅公开服务存活和协议版本。GET /v1/status 要求独立管理授权，只返回存储统计。没有公开报告下载端点。summary 命令在服务器本地按文件哈希和判定依据汇总待核项；默认读取最近 1000 份报告，并显示总存储份数和读取范围。

资料汇总为后续规则完善提供证据。客户端继续依赖可解释的本地分析和签名发行版，不会把上传内容直接变成删除规则，也不会宣称收到资料即完成模型训练或未知威胁识别。

## 构建与验证

客户端：build.ps1。Windows 接收程序：build-collector.ps1。测试 tests/test_diagnostics.py 覆盖真实本机 HTTPS 接收、授权隔离、证书指纹、加密篡改拒绝、断网队列、匹配凭据、去重冲突、解压上限、脱敏和过期清理。

Windows 接收服务经本机测试；Linux 安装脚本需在目标 Linux 环境验收。未取得并使用目标服务器登录方式前，不能据本机测试宣称公网服务已部署。
