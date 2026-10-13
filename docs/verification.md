# 验证清单

分阶段推进的意义在于：每一阶段都能单独确认，出问题时能立刻定位到是哪一层的错。

## 已完成（无需 sudo，可重复执行）

| 阶段 | 内容 | 结果 |
|---|---|---|
| 1 | 骨架：go.mod、两个入口、config、logging | `go build ./...` / `go vet ./...` 通过 |
| 2 | `proto`：帧编解码、参数交换 | 单测覆盖畸形包/超长包边界，88.7% |
| 3 | `devtun`：跨平台建网卡 | 双平台构建通过；darwin 上建 utun 并读到实际名 |
| 4 | `sshserver`：公钥白名单 + l3 channel | 单测 + 集成测试通过，82.5% |
| 5 | `sshclient`：双层引导 + 重连 | **不需 root 即验证端到端**：假 sshd（direct-tcpip）→ 真 sshserver → 两端内存网卡，IP 包双向穿过双层 SSH，81.8% |
| 6 | `netcfg`：地址/MTU/路由/防回环 | 两平台规划器 + 回滚 + 逆序撤销 + 幂等，95.7% |

阶段 5 的验证方式是刻意的：把「IP 包能否穿过双层 SSH」与「路由配得对不对」分开，
前者用假 sshd 在无 root、无真实网卡、不改任何系统路由的前提下跑成了可重复的单测。

合计：`go test -race ./...` 全绿，业务包覆盖率 81%–95%。

## 已完成（云端，实测）

服务端部署后实测（`deploy/deploy.sh`）：

```
$ ip -4 addr show ssh-tun0
3: ssh-tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 ...
    inet 10.9.0.1/24 scope global ssh-tun0

$ sysctl -n net.ipv4.ip_forward
1

$ sudo iptables -t nat -S POSTROUTING
-P POSTROUTING ACCEPT
-A POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE     ← 既有策略未被改动

$ sudo ss -tlnp | grep 8443
LISTEN 0 4096 127.0.0.1:8443 0.0.0.0:* users:(("ssh_tunnel_serv",...))   ← 只绑回环
```

部署过程中发现并修掉了一个真实缺陷：`fspath.ExpandHome` 依赖 `$HOME`，而 systemd
的系统级服务默认不设置它，于是服务以「$HOME is not defined」反复重启。已改为
`$HOME` 取不到时退回 `os/user`（读 `/etc/passwd`），并补了对应的单测。

`install.sh` 幂等性已实测：第二次执行时 sysctl 文件、iptables 规则、unit 内容
均报告「无变化，跳过」。

## 待在真机确认（需要 sudo，因此由本人执行）

### A. 只验隧道，不动路由

```bash
sudo ./bin/ssh_tunnel_client -key ~/cloud/soer.pem -take-default-route=false
# 另开一个终端：
ping 10.9.0.1
```

通了说明双层 SSH 通路成立。此模式下 `netcfg` 只给网卡配地址与 MTU，不碰路由表，
因此任何失败都只可能出在隧道本身。

**这一步同时验证了两个尚未定稿的问题**：

1. **macOS 点对点地址写法**。代码采用 wg-quick 的做法
   （`ifconfig <utun> inet <地址>/<掩码> <同一个地址>`），另一派写法是
   `ifconfig <utun> inet <本端> <对端>`。若 `ping 10.9.0.1` 不通而 `ifconfig utunN`
   显示地址已配上，先换这一派写法试（见 `netcfg/darwin_plan.go` 的注释）。
2. **macOS 26.5.1 是否接受 `/1` 掩码路由**。本模式下不会用到，进入 B 步才会。

### B. 接管全部流量

```bash
sudo ./bin/ssh_tunnel_client -key ~/cloud/soer.pem
```

在**另一个终端**逐项确认：

```bash
curl ifconfig.me                      # 期望：云主机公网 IP
ping 8.8.8.8                          # 期望：通（ICMP 走隧道，这是 L3 VPN 与端口转发的区别）
curl 10.9.0.1:9119                    # 期望：通（经隧道访问服务端本机服务）
route -n get 43.155.231.133           # 期望：interface 仍是 en1，不是 utunN ← 防回环没生效的判据
traceroute -n 8.8.8.8                 # 期望：第一跳是 10.9.0.1
```

`route -n get` 那条是关键：它必须仍走物理网卡。若显示走了 utun，说明防回环主机
路由没装成功，隧道会表现为「几秒后自己断掉、然后重连」。

### C. MTU 校准

1280 是按封装开销推算的保守值。逐档试探真实可用值：

```bash
ping -D -s 1252 8.8.8.8    # 1252 + 28 头部 = 1280，应当通
ping -D -s 1372 8.8.8.8    # 1400；通了可以尝试把两端 --mtu/-mtu 一起调大
```

两端 MTU 必须一致，否则客户端会在建链时被 `checkResponse` 拒绝（这是刻意的：
MTU 不一致会产生静默的大包黑洞）。

### D. 清理验证

客户端退出（含 Ctrl-C、以及直接 kill）后：

```bash
netstat -rn | grep -E '^(0/1|128\.0\.0\.0/1)'   # 期望：无输出
route -n get 43.155.231.133                     # 期望：回到原默认网关
ifconfig | grep utun                            # 期望：新增的那张网卡已消失
```

与启动前 `netstat -rn` 的输出对比应当完全一致。

## 已知风险

- **复用登录私钥**：登录凭据与隧道凭据是同一份，一处泄露全局失守，轮换会连带
  影响主机登录。私钥路径可配，建议日后换成专用密钥。
- **依赖系统 sshd 的转发配置**：`AllowTcpForwarding` / `PermitOpen` 若被改动，
  隧道会失效（当前主机上这两项均满足）。
- **全流量接管**：本机已有 V2rayU/Xray（`utun0`–`utun13` 存在，但路由表里没有
  它们的路由）。首次接管全流量时需确认没有相互争夺。
- **DNS 未改写**：第一版刻意不改系统的 DNS 配置，查询会经隧道发出。若原 DNS 是
  内网私网地址，会解析失败——那时再指向公共解析器
  （`networksetup -setdnsservers <服务名> <dns>`）。
- **云端主机的 sshd 仍开着 `PasswordAuthentication yes` + `PermitRootLogin yes`
  且暴露在公网 22 端口**。这与本项目无关，但建议加固。本项目未改动它。
