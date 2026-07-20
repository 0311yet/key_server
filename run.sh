#!/usr/bin/env bash
# ================================================
# Key Server 启动脚本（Linux / macOS）
# ================================================
set -e

cd "$(dirname "$0")"

# 1. 如无虚拟环境则创建并安装依赖
if [ ! -d ".venv" ]; then
    echo "[init] 创建虚拟环境..."
    python3 -m venv .venv
fi

echo "[init] 安装依赖..."
.venv/bin/pip install -q -r requirements.txt

# 2. 如无 .env 则从 .env.example 复制
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "[warn] .env 已创建，请编辑填写 LOGIN_PASSWORD 等配置！"
fi

# 3. 启动服务
echo "[start] 启动 Key Server..."
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 "$@"