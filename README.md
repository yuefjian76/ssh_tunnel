# ssh_tunnel

基于 SSH 的 **L3 VPN**：客户端把本机流量以原始 IP 包的形式送进隧道，服务端做真 NAT
（MASQUERADE）代其出网，因此「访问任意地址」表现为本机直接从云主机的公网 IP 出去。

与常见的 SSH 端口转发（`-L` / `-D`）的区别：那是**按连接**做 TCP 转发，只在应用层
转发了你显式指定的目标；这里是**按包**做隧道，客户端侧可以接管默认路由，于是
任何程序、任何协议（ICMP、UDP、非标准端口）都无需单独配置。

## 拓扑

```
[本机应用]
    │ 默认路由 0.0.0.0/1 + 128.0.0.0/1
    ▼
[client utun] 10.9.0.2 ──原始 IP 包──► channel "l3@ssh_tunnel"
                                         ▲
                                         │ 承载于外层 SSH 之上
    ┌────────────────────────────────────┘
    │  外层：本机 ──ssh(pem)──► 云主机系统 sshd :22   ← 云安全组已放行
    │          └── direct-tcpip ──► 127.0.0.1:8443
    ▼
[自研 SSH server 监听 127.0.0.1:8443]   ← 不暴露公网，无需改安全组
    │
[server ssh-tun0] 10.9.0.1
    ├─► net.ipv4.ip_forward = 1
    └─► iptables -t nat POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE
              │
              ▼
        任意地址 / 互联网（源地址被改写为云主机的公网 IP）
```

**为什么是双层 SSH**：入站通路复用已放行的 22 端口，因此不必在云安全组上开新端口；
代价是每个包两次加解密。隧道层保留独立的 SSH 认证，且能独立于系统 sshd 演进。
若日后吞吐不可接受，退化为单层协议的改动只落在 `internal/sshclient` 与
`internal/sshserver` 两个包内。

## 构建

```bash
go build ./...
go test -race ./...
```

交叉编译服务端（云主机上无需装 Go）：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ssh_tunnel_server ./cmd/server
```

## 部署服务端

```bash
SSH_KEY=~/cloud/soer.pem SERVER=ubuntu@43.155.231.133 ./deploy/deploy.sh
```

`deploy.sh` 会本地交叉编译、上传、并在云主机上执行 `deploy/install.sh`。
`install.sh` 是幂等的，只做两处系统级改动，都不触碰既有配置：

1. 写 `/etc/sysctl.d/99-ssh-tunnel.conf` 打开 `net.ipv4.ip_forward`
2. 在 `iptables` 表 `nat` 的 `POSTROUTING` 链**追加**一条针对 `10.9.0.0/24`
   的 MASQUERADE（先 `-C` 检查，已存在则跳过）

其余（二进制、systemd unit）由脚本生成，装了什么会打印出来；完全撤销的命令也在
脚本结束时打印。

## 运行客户端

需要 root（创建隧道网卡、改路由表）：

```bash
sudo ./bin/ssh_tunnel_client -key ~/cloud/soer.pem
```

**第一次务必先只验隧道、不动路由**，这样出问题时能立刻区分是隧道逻辑还是路由配置：

```bash
sudo ./bin/ssh_tunnel_client -key ~/cloud/soer.pem -take-default-route=false
# 另开一个终端：
ping 10.9.0.1          # 通 → 双层 SSH 通路成立
```

确认无误后再接管全部流量：

```bash
sudo ./bin/ssh_tunnel_client -key ~/cloud/soer.pem
curl ifconfig.me       # 应返回云主机的公网 IP
```

常用参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `-key` | （必填） | 两段 SSH 认证用的私钥，没有默认值 |
| `-server` | `43.155.231.133:22` | 外层 SSH 目标；主机部分**必须是 IP 字面量**（防回环路由需要确定地址） |
| `-take-default-route` | `true` | 设为 `false` 只建隧道、不改路由表 |
| `-mtu` | `1280` | 必须与服务端一致；双层 SSH 封装开销大，别照着 1500 设 |
| `-tun` | 平台默认 | macOS 留空由内核分配 `utunN`，**不可**硬编码 `utun0` |
| `-known-hosts` | `~/.ssh/known_hosts` | 复用系统文件，因此首次运行无需信任引导 |

## 设计要点

- **防路由回环**：隧道一旦接管默认路由，承载隧道自身的那条 TCP 连接也会被塞进隧道，
  当场自断。因此在装 `0.0.0.0/1` **之前**，先为服务端公网 IP 装一条走原网关的
  `/32` 主机路由；最长前缀匹配保证它始终走物理网卡。拆除时逆序执行。
  详见 [docs/architecture.md](docs/architecture.md)。
- **服务端进程不改路由表**：只给隧道网卡配地址。转发与 NAT 是一次性系统配置，
  由 `deploy/install.sh` 完成，权限面更小，也不会与主机上的既有规则相互干扰。
- **重连期间路由保持不变**：断线重连只在网络层之上进行，反复增删路由会造成流量
  黑洞与路由震荡。
- **密钥**：默认复用登录云主机的那把私钥（EC2 的 `.pem`）。这意味着登录凭据与隧道
  凭据是同一份，一处泄露全局失守，且轮换会连带影响主机登录。私钥路径是可配参数，
  便于日后换成专用密钥。仓库的 `.gitignore` 已排除 `*.pem`。

## 文档

- [docs/architecture.md](docs/architecture.md) —— 模块边界、不变量、协议
- [docs/verification.md](docs/verification.md) —— 分阶段验证清单与实测结果
