"""Serialized local transport to the existing cleanup and privacy core."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading


class CoreError(RuntimeError):
    pass


def windows_documents():
    if os.name != 'nt':
        return str(Path.home() / 'Documents')
    try:
        import ctypes
        from ctypes import wintypes
        # SHGetFolderPathW uses the same Documents shell folder as Electron.
        buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        if ctypes.windll.shell32.SHGetFolderPathW(None, 5, None, 0, buf) == 0:
            return buf.value
    except (AttributeError, OSError):
        pass
    return str(Path.home() / 'Documents')


class CoreClient:
    def __init__(self):
        self._process = None
        self._lock = threading.Lock()
        self._next_id = 0

    def _start(self):
        node = shutil.which('node')
        if not node:
            raise CoreError('没有找到 Node.js。当前预览版需要 Node.js 运行原有安全核心。')
        root = Path(__file__).resolve().parent.parent
        env = os.environ.copy()
        env['CLEARSPACE_PYTHON'] = sys.executable
        env['CLEARSPACE_DOCUMENTS'] = windows_documents()
        flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        try:
            version = subprocess.run([node, '-p', 'process.versions.node'], capture_output=True, text=True,
                                     encoding='utf-8', timeout=10, check=True, creationflags=flags).stdout.strip()
            numbers = tuple(int(part) for part in version.split('.')[:2])
            if len(numbers) != 2 or numbers < (24, 4):
                raise CoreError(f'当前 Node.js 版本为 {version}；请安装 Node.js 24.4 或更新版本。')
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            raise CoreError('无法验证 Node.js 版本，请安装 Node.js 24.4 或更新版本。') from error
        self._process = subprocess.Popen(
            [node, str(root / 'legacy' / 'bridge.js')],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding='utf-8', bufsize=1, env=env, creationflags=flags,
        )

    def call(self, command, **payload):
        with self._lock:
            if self._process is None:
                self._start()
            if self._process.poll() is not None:
                raise CoreError('本地核心已停止，请重新启动应用。')
            self._next_id += 1
            request_id = self._next_id
            try:
                self._process.stdin.write(json.dumps({'id': request_id, 'command': command, 'payload': payload}, ensure_ascii=True) + '\n')
                self._process.stdin.flush()
                line = self._process.stdout.readline()
                if not line:
                    raise CoreError('本地核心未返回结果，请重新启动应用。')
                response = json.loads(line)
                if response.get('id') != request_id:
                    raise CoreError('本地核心返回的数据不匹配。')
                if 'error' in response:
                    raise CoreError(response['error'])
                return response['result']
            except (BrokenPipeError, OSError, json.JSONDecodeError) as error:
                raise CoreError(f'无法连接本地核心：{error}') from error

    def close(self):
        process = self._process
        if not process:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if process.stdin:
            process.stdin.close()
        if process.stdout:
            process.stdout.close()
        self._process = None

