#!/usr/bin/env bash
#
# 本地构建 linux/amd64 的服务端，上传到云主机，并在那边执行 install.sh。
#
# 用法：
#     SSH_KEY=~/cloud/soer.pem SERVER=ubuntu@43.155.231.133 ./deploy.sh
#
# 私钥只用于本次 ssh/scp，不会被上传，也不出现在本脚本里——密钥路径因机器而异，
# 硬编码一个绝对路径既会泄露你的目录结构，也会在别人机器上失败。
set -euo pipefail

SSH_KEY="${SSH_KEY:?请用 SSH_KEY 指定登录云主机的私钥，例如 SSH_KEY=~/cloud/soer.pem}"
SERVER="${SERVER:?请用 SERVER 指定目标，例如 SERVER=ubuntu@43.155.231.133}"
REMOTE_DIR="${REMOTE_DIR:-/tmp/ssh-tunnel-deploy}"
TARGET_OS="${TARGET_OS:-linux}"
TARGET_ARCH="${TARGET_ARCH:-amd64}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

log() { printf '==> %s\n' "$*"; }

log "构建 ${TARGET_OS}/${TARGET_ARCH} 服务端"
(cd "$REPO_DIR" && CGO_ENABLED=0 GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" \
	go build -trimpath -ldflags "-s -w" -o "${BUILD_DIR}/ssh_tunnel_server" ./cmd/server)

log "上传到 ${SERVER}:${REMOTE_DIR}"
# 只上传二进制与安装脚本：私钥、源码都不需要过去。
ssh -i "$SSH_KEY" "$SERVER" "mkdir -p '$REMOTE_DIR'"
scp -i "$SSH_KEY" -q "${BUILD_DIR}/ssh_tunnel_server" "${SCRIPT_DIR}/install.sh" "${SERVER}:${REMOTE_DIR}/"

log "在远端执行 install.sh（需要 sudo）"
ssh -i "$SSH_KEY" "$SERVER" "cd '$REMOTE_DIR' && sudo ./install.sh"

log "服务端部署完成。"
cat <<EOF

本机自查（先只建隧道、不改路由表，用于把「隧道是否通」与「路由是否对」分开验证）：

    sudo ./bin/ssh_tunnel_client \\
        -key "${SSH_KEY}" \\
        -server "${SERVER#*@}:22" \\
        -take-default-route=false

连上后另开一个终端 ping 10.9.0.1，通了说明双层 SSH 通路成立，再考虑接管全流量。
EOF
