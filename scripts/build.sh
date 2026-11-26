#!/usr/bin/env bash
# SBOMScope 一键构建脚本：自测 -> 构建发行包 -> 校验产物
# 用法: bash scripts/build.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> [1/3] 运行全量单元测试"
python3 -m unittest discover -s tests -v

echo "==> [2/3] 构建 sdist + wheel"
python3 -m build --sdist --wheel --outdir dist 2>/dev/null || {
  echo "未安装 build 工具，使用 setup.py 降级构建"
  python3 setup.py sdist bdist_wheel
}

echo "==> [3/3] 校验产物"
ls -lh dist/
for f in dist/*; do
  echo "  sha256: $(sha256sum "$f" | cut -d' ' -f1)  $(basename "$f")"
done
echo "构建完成。"
