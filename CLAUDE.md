# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目

基于 SSH 的 L3 VPN（Go）：客户端把本机流量以 IP 包送进隧道，服务端做 NAT 出网。
分层拓扑、模块地图、以及**改代码时不能破坏的不变量**见
[docs/architecture.md](docs/architecture.md)——动 `netcfg`、`bridge`、
`sshclient` 之前应先读它。

## 常用命令

```bash
go build ./...
go vet ./...
go test -race ./...
go test -race -run TestPlanValidate ./internal/netcfg/     # 单测跑一个用例

# 交叉编译服务端（云主机上没有 Go）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ssh_tunnel_server ./cmd/server

# 部署到云主机（本地构建 + 上传 + 在那边跑自己的 install.sh）
SSH_KEY=~/cloud/soer.pem SERVER=ubuntu@43.155.231.133 ./deploy/deploy.sh
```

## 需要 root 才能跑的验证

客户端创建隧道网卡、改路由表，因此要 `sudo`：

```bash
sudo ./bin/ssh_tunnel_client -key ~/cloud/soer.pem -take-default-route=false  # 只验隧道
sudo ./bin/ssh_tunnel_client -key ~/cloud/soer.pem                            # 接管全流量
```

完整的分阶段验证清单与实测结果见 [docs/verification.md](docs/verification.md)。
**先只验隧道、不动路由**：这样出问题能立刻区分是隧道逻辑还是路由配置。

## 容易踩的坑（都已有代码注释说明原因，改前先读）

- `netcfg` 的平台文件是 `darwin_plan.go` / `linux_plan.go`，**不能**写成
  `plan_darwin.go`——`*_GOOS.go` 会被 Go 按文件名限制到对应系统编译，
  「两个平台的规划器都能在 macOS 上单测」这个前提会消失。只有
  `platform_*.go` 和 `devtun/name_*.go` 才该用构建标签。
- `bridge` 在无连接接入时**排队**而非丢弃网卡上的包，这是刻意的（见
  architecture.md 的「Bridge 的排队语义」），别凭直觉改回丢弃。
- 装路由的顺序：`/32` 主机路由必须在两条 `/1` 之前；拆除时严格逆序。
- 隧道地址的权威是服务端应答，客户端的 `checkResponse` 要求 `client_ip`/
  `prefix_len`/`mtu` 完全一致。
- 私钥绝不入库（`.gitignore` 已排除 `*.pem`）；密钥路径必须是可配参数。

## 部署脚本

`deploy/install.sh` 幂等，只做两处系统改动（`net.ipv4.ip_forward` 与一条针对
`10.9.0.0/24` 的 MASQUERADE），不触碰云主机上既有的 sysctl 文件与 iptables 规则。
systemd unit 由脚本生成而非仓库里的独立文件，避免监听地址出现两个事实来源。
