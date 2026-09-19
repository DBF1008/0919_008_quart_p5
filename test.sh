#!/usr/bin/env bash
# Quart 单元测试脚本
# 覆盖本次修复:session 并发安全(sessions.py / ctx.py)与
# cookie path/domain 空值语义统一。
#
# 用法:
#   ./test.sh                  运行全部单元测试(逐文件)
#   ./test.sh tests/test_sessions.py   只运行指定测试文件
#
# 环境:
#   默认使用项目 .venv;不存在时尝试 uv sync 创建;
#   也可用 PY=/path/to/python 指定解释器,
#   用 PYTHONPATH 指定额外的模块搜索路径。
set -euo pipefail
cd "$(dirname "$0")"

PY="${PY:-}"
if [ -z "$PY" ]; then
    if [ -x ".venv/bin/python" ]; then
        PY=".venv/bin/python"
    elif command -v uv >/dev/null 2>&1; then
        echo ">>> uv sync --frozen"
        uv sync --frozen
        PY=".venv/bin/python"
    else
        PY="python3"
    fi
fi
echo ">>> Python: $PY"
"$PY" --version

run() {
    echo
    echo "================================================================"
    echo ">>> $PY -m pytest $* -v"
    echo "================================================================"
    "$PY" -m pytest "$@" -v
}

if [ "$#" -gt 0 ]; then
    # 手动指定:只运行给定文件,便于单点验证
    for target in "$@"; do
        run "$target"
    done
    exit 0
fi

# 本次修复的重点测试,先单独运行
echo
echo "################################################################"
echo "# 重点:session 并发安全与 cookie 空值语义"
echo "################################################################"
run tests/test_sessions.py
run tests/test_ctx.py

# 全部单元测试脚本,逐文件运行
echo
echo "################################################################"
echo "# 全量单元测试"
echo "################################################################"
for f in tests/test_*.py tests/wrappers/test_*.py; do
    case "$f" in
        tests/test_sessions.py|tests/test_ctx.py) continue ;;
    esac
    run "$f"
done

echo
echo ">>> 全部单元测试通过"
