# 架构

## 模块边界

```
cmd/server              服务端入口：flag → 建网卡 → 配地址 → 监听
cmd/client              客户端入口：flag → 建网卡 → 双层引导 → onReady 里配路由 → 退出时还原
internal/config         两端配置与校验（纯逻辑，零 I/O）
internal/proto          channel 常量、参数交换（JSON）、IP 包分帧（纯逻辑）
internal/bridge         共享的「长生命周期网卡 ↔ 短生命周期连接」搬运器
internal/sshserver      gliderlabs/ssh server + 公钥白名单 + l3 channel handler
internal/sshclient      外层 direct-tcpip 跳板 + 内层 SSH + l3 channel + 指数退避重连
internal/devtun         封装 wireguard-go/tun：跨平台建网卡、读写包
internal/netcfg         唯一直接改动系统网络状态的地方（平台差异见下）
internal/logging        结构化日志
internal/fspath         "~" 展开等路径小工具
internal/testutil       测试替身（内存 PacketConn 等）
```

## 不变量（改代码时不要破坏）

### 1. 防路由回环

隧道接管默认路由后，承载隧道自身的 TCP 连接不能进隧道，否则死循环。做法：

1. 在装两条 `/1` **之前**，读系统原默认路由（`route -n get default` /
   `ip -4 route show default`），为服务端公网 IP 装 `/32` 主机路由指向原网关；
2. 装 `0.0.0.0/1` + `128.0.0.0/1`；
3. 拆除时**逆序**：先删两条 `/1`，再删 `/32`。

顺序颠倒会在删 `/32` 的那一瞬间让 `/1` 把外层连接吞进隧道。`netcfg` 的
`step{do, undo}` 成对保存、`Revert` 逆序执行，正是为了让这个对称性不靠人记。

用两条 `/1` 而不是一条 `0.0.0.0/0` 的原因：不必删除系统原有默认路由，
拆除时只要删掉两条 `/1`，原默认路由立刻恢复生效——不会因为拆除失败把机器
留在没有默认路由的状态。

`Plan.Validate` 会拒绝「接管默认路由却没给穿透目标」以及「穿透目标落在隧道网段内」
这两种计划，把错误从运行期挪到配置期。

### 2. 网卡所有权

- `devtun.Device` 由创建方关闭。`sshserver.New` 成功后所有权转移给 Server；
  在此之前由 `cmd/server` 负责关。
- `sshclient.Deps.Packets` 的所有权**不**转移：Client 只读写，网卡由 `cmd/client` 掌握。
- `bridge.Close()` 不关闭底层网卡（长生命周期的那一端由调用方管）。
- `Setup.Revert` 只撤销路由，不销毁网卡；先撤路由、再关网卡的顺序由调用方保证。

### 3. Bridge 的排队语义

`bridge` 在**没有连接接入时也会把网卡上读到的包入队**（队列有界，满则形成背压），
而不是丢弃。这不是疏忽：

调用方装好路由之后内核会立刻开始往网卡投包，而那时搬运往往还没接上；
丢包会造成隧道建立后最初若干秒的无谓丢包与重传。反过来，「无连接就丢弃」
要求调用方严格遵守「先接入、再产生流量」的时序，而这个隐式契约没有任何地方
检查得到。残留包被投给新连接时的实际影响由内核兜住（TCP 会重传、不匹配的
UDP 包被丢弃）。

### 4. channel 关闭

`gossh.Channel.Close()` **不幂等**，每调用一次都会发一条 `channelCloseMsg`。
`bridge.ChannelConn` 用 `sync.Once` 守住；`Accept()` 返回的 channel 必须
`go gossh.DiscardRequests(reqs)`，否则 channel 会挂住。

## 平台差异

差异只体现在 `netcfg`，且分两层：

- `darwin_plan.go` / `linux_plan.go` —— **纯函数**，只负责「构造哪些命令」和
  「解析命令输出」，不带构建标签，因此两个平台的规划器都能在任意系统上单测。
- `platform_darwin.go` / `platform_linux.go` —— 带构建标签，只做一件事：
  指定 `currentPlatform`。

⚠️ 文件名不能写成 `plan_darwin.go`：Go 会把 `*_GOOS.go` 形式的文件名限制到对应
系统上编译，「两平台都能在 macOS 上测」这个前提会当场消失。同理，
`devtun/name_darwin.go` 这类确实是平台专属的文件才该用那个后缀。

其余模块（config、proto、bridge、sshserver、sshclient、devtun 主体）跨平台共用。

## 协议

打开 channel `l3@ssh_tunnel` 时，客户端在 payload 里带上请求参数，服务端在
channel 建立后回写第一帧作为应答（均为 JSON 编码）：

```json
请求: {"version":1,"client_ip":"10.9.0.2","mtu":1280}
应答: {"version":1,"server_ip":"10.9.0.1","client_ip":"10.9.0.2","prefix_len":24,"mtu":1280}
```

版本号从第一天就带上，便于日后协议演进。客户端的 `checkResponse` 要求
`client_ip` / `prefix_len` / `mtu` 与服务端**完全一致**，不一致即拒绝建链——
MTU 不一致会静默地产生大包黑洞，是最难排查的一类故障。

应答之后，channel 上传输的是分帧的 IP 包（`proto.WriteFrame` / `ReadFrame`）。

## MTU

隧道 MTU 必须让「隧道内 IP 包 + 两层 SSH 封装 + TCP/IP」不超过物理链路 MTU：

```
1500 (物理)
 - 40  外层 TCP/IP
 - 48  外层 SSH 封装
 - 48  内层 SSH 封装
 - 16  channel 帧头与余量
 ≈ 1348
```

取 **1280**（也是 IPv6 最小 MTU）留足安全边际，两端必须一致。真实可用值需用
`ping -D -s <size> 8.8.8.8` 逐档试探确定，是 `--mtu` 可配的原因。

## 依赖

- `github.com/gliderlabs/ssh` —— 只用于 server 侧的 host key / 公钥认证 / channel 路由
- `golang.zx2c4.com/wireguard/tun` —— 网卡创建与批量读写
  （注意该仓库的 tag 形如 `0.0.20250522`，**无 `v` 前缀**，不是合法 semver，
  必须用 commit 让 Go 生成 pseudo-version）
- `golang.org/x/crypto/ssh` —— 客户端与内层握手

wireguard-go/tun 的三个坑（已在 `devtun` 处理）：

1. `Read`/`Write` 是**批量**语义，返回包个数而非字节数；
2. macOS 的 `offset` 必须 ≥ 4（utun 包前有 4 字节地址族头），统一传 16；
3. `Name()` 才是真实接口名——macOS 上传 `"utun"` 由内核分配编号，不可硬编码 `utun0`。

该库**不提供**任何 IP / 掩码 / 路由配置 API，因此 `netcfg` 直接执行系统命令
（参数以数组传递、不经 shell，因此不存在命令注入）。
