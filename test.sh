#!/usr/bin/env bash
# 手动运行全部单元测试脚本
#
# 用法:
#   ./test.sh                          # 运行全部单元测试
#   ./test.sh tests/test_sessions.py   # 运行指定测试文件
#   ./test.sh tests/test_sessions.py tests/test_ctx.py -k concurrent
#
# 优先使用 uv 创建环境; 否则回退到 python venv + pip。
set -euo pipefail

cd "$(dirname "$0")"

TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
    TARGETS=("tests")
fi

if command -v uv >/dev/null 2>&1; then
    echo "==> 使用 uv 同步测试依赖"
    uv sync --frozen --group tests
    echo "==> 运行单元测试: ${TARGETS[*]}"
    uv run pytest "${TARGETS[@]}" -v
else
    echo "==> 使用 python venv 安装测试依赖"
    PYTHON_BIN="${PYTHON_BIN:-python3}"
    if [ ! -d .venv ]; then
        "$PYTHON_BIN" -m venv .venv
    fi
    .venv/bin/pip install -e ".[dotenv]"
    .venv/bin/pip install pytest pytest-asyncio pytest-cov pytest-sugar hypothesis python-dotenv
    echo "==> 运行单元测试: ${TARGETS[*]}"
    .venv/bin/python -m pytest "${TARGETS[@]}" -v
fi
