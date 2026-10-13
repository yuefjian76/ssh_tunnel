#!/usr/bin/env bash
#
# 在云端主机上做一次性系统配置，并安装隧道服务端（systemd）。
#
# 用法（在云主机上，需要 sudo）：
#     sudo ./install.sh                  # 安装/更新
#     LISTEN_ADDR=127.0.0.1:9443 sudo -E ./install.sh
#
# 幂等：重复执行只确认现状，不会重复追加规则、也不会重复写文件。
#
# 本脚本只做两处系统级改动，且都不触碰既有配置：
#   1. 写 /etc/sysctl.d/99-ssh-tunnel.conf 打开 net.ipv4.ip_forward
#   2. 在 iptables 表 nat 的 POSTROUTING 链**追加**一条 MASQUERADE 规则
#      （先 -C 检查，已存在则跳过；绝不修改或删除任何既有规则）
#
# 注意：这些改动只影响**过境**流量。不会改变主机自身的入站策略，
# 也不会打开任何端口——自研 server 只绑 127.0.0.1，入站通路走系统 sshd。
#
# 为什么 systemd unit 由本脚本生成，而不是仓库里放一个 .service 文件：
# 避免「脚本里的监听地址」与「unit 文件里的监听地址」两个事实来源各写一份、
# 日后各自漂移。执行时会打印生成的 unit 内容，装的是什么一目了然。
set -euo pipefail

# ---- 可覆盖的配置（与 cmd/server 的默认值保持一致）---------------------------

# 隧道网段：只对这个来源的流量做 NAT。
TUNNEL_PREFIX="${TUNNEL_PREFIX:-10.9.0.0/24}"
# NAT 出接口。
EGRESS_IFACE="${EGRESS_IFACE:-eth0}"
# 自研 SSH server 的监听地址。默认只绑回环：入站通路走系统 sshd 的
# direct-tcpip 转发，因此无需在云安全组放行任何新端口。
LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1:8443}"
# 隧道网卡 MTU，必须与客户端一致。
MTU="${MTU:-1280}"
# authorized_keys 白名单，多个文件用逗号分隔。
AUTHORIZED_KEYS="${AUTHORIZED_KEYS:-/home/ubuntu/.ssh/authorized_keys}"

SERVICE_NAME="ssh-tunnel-server"
BINARY_DEST="/usr/local/bin/ssh_tunnel_server"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
SYSCTL_FILE="/etc/sysctl.d/99-ssh-tunnel.conf"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '==> %s\n' "$*"; }
warn() { printf '警告: %s\n' "$*" >&2; }

# ---- 前置检查 ----------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
	echo "请用 sudo 运行：sudo $0" >&2
	exit 1
fi

if [ ! -c /dev/net/tun ]; then
	log "/dev/net/tun 不存在，尝试加载 tun 模块"
	modprobe tun 2>/dev/null || true
fi
if [ ! -c /dev/net/tun ]; then
	echo "错误: /dev/net/tun 不可用，无法创建隧道网卡" >&2
	exit 1
fi

# ---- 1. 打开 IPv4 转发 -------------------------------------------------------

log "配置 ${SYSCTL_FILE}"
desired="# 由 ssh_tunnel 的 deploy/install.sh 生成，勿手工修改。
# 隧道客户端经本机出网时需要打开 IPv4 转发。
net.ipv4.ip_forward=1"
if [ -f "$SYSCTL_FILE" ] && [ "$(cat "$SYSCTL_FILE")" = "$desired" ]; then
	log "内容已是最新，跳过"
else
	printf '%s\n' "$desired" >"$SYSCTL_FILE"
	log "已写入"
fi

# 只加载这一个文件：--system 会重新应用全部 sysctl 配置，
# 在别人的生产主机上没有必要冒这个风险。
sysctl -q -p "$SYSCTL_FILE"

if [ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]; then
	warn "net.ipv4.ip_forward 仍不是 1。可能有其它配置文件在之后覆盖它，请检查：
      grep -rn ip_forward /etc/sysctl.d/ /etc/sysctl.conf"
fi

# ---- 2. 追加 MASQUERADE 规则 -------------------------------------------------

log "检查 nat POSTROUTING 的 MASQUERADE 规则（${TUNNEL_PREFIX} -> ${EGRESS_IFACE}）"
if iptables -t nat -C POSTROUTING -s "$TUNNEL_PREFIX" -o "$EGRESS_IFACE" -j MASQUERADE 2>/dev/null; then
	log "规则已存在，跳过"
else
	iptables -t nat -A POSTROUTING -s "$TUNNEL_PREFIX" -o "$EGRESS_IFACE" -j MASQUERADE
	log "已追加规则"
fi

# 转发策略若不是 ACCEPT，即便有 NAT 规则也出不去。这里只报告，不代为修改——
# 改动 FORWARD 策略可能影响主机上其它依赖它的服务。
#
# 匹配的是 iptables -S 的输出格式（"-P FORWARD ACCEPT"），不是 -L 的
# "Chain FORWARD (policy ACCEPT)"。两者写法不同，写错会得到一条凭空出现的警告。
if ! iptables -S FORWARD | head -1 | grep -q -- '-P FORWARD ACCEPT'; then
	warn "filter FORWARD 链的策略不是 ACCEPT。若客户端无法出网，需要额外放行：
      iptables -A FORWARD -s ${TUNNEL_PREFIX} -o ${EGRESS_IFACE} -j ACCEPT
      iptables -A FORWARD -d ${TUNNEL_PREFIX} -i ${EGRESS_IFACE} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
fi

# ---- 3. 安装服务端二进制 -----------------------------------------------------

log "安装服务端二进制到 ${BINARY_DEST}"
if [ -f "${SCRIPT_DIR}/ssh_tunnel_server" ]; then
	if [ -f "$BINARY_DEST" ] && cmp -s "${SCRIPT_DIR}/ssh_tunnel_server" "$BINARY_DEST"; then
		log "内容一致，跳过"
	else
		install -m 0755 -o root -g root "${SCRIPT_DIR}/ssh_tunnel_server" "$BINARY_DEST"
		log "已安装 $(du -h "$BINARY_DEST" | cut -f1)"
	fi
elif [ -f "$BINARY_DEST" ]; then
	log "${SCRIPT_DIR}/ssh_tunnel_server 不存在，沿用已安装的 ${BINARY_DEST}"
else
	echo "错误: 找不到服务端二进制。请先把为 linux/amd64 交叉编译出的 ssh_tunnel_server 放到 ${SCRIPT_DIR}/" >&2
	exit 1
fi

# ---- 4. 生成并安装 systemd unit ----------------------------------------------

log "生成 ${UNIT_PATH}"
unit="[Unit]
Description=ssh_tunnel 隧道服务端（L3 over SSH）
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 需要 CAP_NET_ADMIN 创建隧道网卡，故以 root 运行。
ExecStart=${BINARY_DEST} -listen ${LISTEN_ADDR} -mtu ${MTU} -authorized-keys ${AUTHORIZED_KEYS} -egress-iface ${EGRESS_IFACE}
Restart=always
RestartSec=3
# 网卡与密钥文件都不多，句柄数给宽一点，避免高并发时被无谓的上限打断。
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target"

if [ -f "$UNIT_PATH" ] && [ "$(cat "$UNIT_PATH")" = "$unit" ]; then
	log "unit 内容无变化，跳过"
else
	printf '%s\n' "$unit" >"$UNIT_PATH"
	log "已写入 unit："
	printf '%s\n' "$unit" | sed 's/^/    /'
fi

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null
systemctl restart "$SERVICE_NAME"

# ---- 5. 完成后自检 -----------------------------------------------------------

sleep 1
if systemctl is-active --quiet "$SERVICE_NAME"; then
	log "服务已启动"
	systemctl status "$SERVICE_NAME" --no-pager --lines=5 || true
else
	echo "错误: 服务未能启动，请查看日志：journalctl -u ${SERVICE_NAME} -n 50 --no-pager" >&2
	exit 1
fi

cat <<EOF

==> 完成。本脚本在系统上留下的全部改动如下；如需完全撤销，按此逆序执行：
      systemctl disable --now ${SERVICE_NAME}
      rm -f ${UNIT_PATH} ${BINARY_DEST}
      systemctl daemon-reload
      iptables -t nat -D POSTROUTING -s ${TUNNEL_PREFIX} -o ${EGRESS_IFACE} -j MASQUERADE
      rm -f ${SYSCTL_FILE}
      sysctl -w net.ipv4.ip_forward=0

==> 服务端日志：journalctl -u ${SERVICE_NAME} -f
EOF
