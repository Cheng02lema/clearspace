#!/bin/bash
# Launch from Terminal or from the Finder wrapper without installing packages.
set -eu
export PATH="/Library/Frameworks/Python.framework/Versions/Current/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
cd "$PROJECT_ROOT"

fail() {
  printf '澄界无法启动：%s\n' "$1" >&2
  if [ "${CLEARSPACE_FINDER_LAUNCH:-0}" = '1' ] && [ -x /usr/bin/osascript ]; then
    /usr/bin/osascript - "$1" <<'APPLESCRIPT' || true
on run argv
  display dialog (item 1 of argv) with title "澄界无法启动" buttons {"好"} default button "好" with icon stop
end run
APPLESCRIPT
  fi
  exit 1
}

[ "$(uname -s)" = 'Darwin' ] || fail '此启动入口仅适用于 macOS。'
command -v python3 >/dev/null 2>&1 || fail '找不到 Python 3。请安装包含 Tkinter 的 Python 3.10 或更新版本。'
python3 -c 'import sys, tkinter; assert sys.version_info >= (3, 10)' >/dev/null 2>&1 || fail 'Python 版本过低或缺少 Tkinter。请安装包含 Tkinter 的 Python 3.10 或更新版本。'
command -v node >/dev/null 2>&1 || fail '找不到 Node.js。请安装 Node.js 24.4 或更新版本。'
node -e "const v=process.versions.node.split('.').map(Number);process.exit(v[0]>24 || (v[0]===24 && v[1]>=4) ? 0 : 1)" >/dev/null 2>&1 || fail 'Node.js 版本过低，请安装 Node.js 24.4 或更新版本。'
exec python3 "$PROJECT_ROOT/run.py"
