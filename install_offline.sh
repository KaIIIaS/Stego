#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ ! -d "$ROOT/wheelhouse" ]]; then
  echo "Не найден каталог wheelhouse. Поместите в него заранее подготовленные wheel-пакеты." >&2
  exit 2
fi
python3 -m pip install --no-index --find-links "$ROOT/wheelhouse" -r "$ROOT/requirements.txt"
echo "Установка завершена. Запуск: python3 main.py"
