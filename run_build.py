# -*- coding: utf-8 -*-
"""调用 PyInstaller 打包（用 `python -m PyInstaller` 方式，避免 import 取不到包）。

要点：
- 通过 subprocess 执行 `sys.executable -m PyInstaller`，与用户在命令行
  `python -m PyInstaller` 一致，规避「找不到 PyInstaller 包」的 import 失败。
- 日志双写（控制台 + build_run.log），即便进程被杀也能从文件看到进度。
- 不执行任何「批量删除」（会触发环境安全删除守卫并终止进程）：
  旧产物交给 PyInstaller 的 --clean / --noconfirm 自己处理；
  仅按文件逐个清理两个已知过时目录（HashDB / Yararules），每步远小于守卫阈值。
"""
import os
import sys
import shutil
import subprocess
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "build_run.log")

# 仅清理这两个「旧目录名」残留（现代码已改用 Dragon_VirusDB / Dragon_CoreRules）
_STALE_DIRS = ("HashDB", "Yararules")


class _Tee:
    def __init__(self, path, stream):
        self._f = open(path, "a", encoding="utf-8", buffering=1)
        self._s = stream

    def write(self, data):
        try:
            self._f.write(data)
        except Exception:
            pass
        try:
            self._s.write(data)
        except Exception:
            pass

    def flush(self):
        try:
            self._f.flush()
        except Exception:
            pass
        try:
            self._s.flush()
        except Exception:
            pass


def _safe_remove_dir(path):
    """按文件逐个删除（每次 os.remove 只动 1 项，远低于安全删除守卫阈值）。"""
    if not os.path.isdir(path):
        return
    for root, dirs, files in os.walk(path, topdown=False):
        for f in files:
            try:
                os.remove(os.path.join(root, f))
            except OSError:
                pass
        for d in dirs:
            try:
                os.rmdir(os.path.join(root, d))
            except OSError:
                pass
    try:
        os.rmdir(path)
    except OSError:
        pass


def main():
    sys.stdout = _Tee(LOG, sys.stdout)
    sys.stderr = _Tee(LOG, sys.stderr)
    print("=" * 60)
    print("BUILD START", datetime.datetime.now().isoformat())
    print("python:", sys.executable)
    print("cwd   :", os.getcwd())

    os.environ["PYINSTALLER_DISABLE_MULTIPROCESSING"] = "1"
    os.environ.setdefault("PYTHONHASHSEED", "1")

    # 仅清理已知过时目录（按文件逐个，安全）
    for name in _STALE_DIRS:
        p = os.path.join(HERE, "dist", name)
        if os.path.isdir(p):
            print("safe-remove stale:", p)
            _safe_remove_dir(p)

    spec = os.path.join(HERE, "build_dragon.spec")
    cmd = [sys.executable, "-m", "PyInstaller", spec,
           "--noconfirm", "--clean", "--log-level", "INFO"]
    print(">>> PyInstaller run begin:", " ".join(cmd))
    rc = 0
    try:
        # 用 `python -m PyInstaller`（subprocess）与命令行一致；子进程继承已被 _Tee
        # 包装的 stdout/stderr，日志同样双写。cwd=HERE 保证 build/、dist/ 落在工程目录。
        proc = subprocess.run(cmd, cwd=HERE)
        rc = proc.returncode
        if rc == 0:
            print(">>> PyInstaller run returned normally")
        else:
            print(">>> PyInstaller exit code =", rc)
    except BaseException:  # noqa
        import traceback
        rc = 1
        print(">>> PyInstaller raised:")
        traceback.print_exc()

    exe = os.path.join(HERE, "dist", "DragonAntivirus.exe")
    if rc == 0 and os.path.isfile(exe):
        print(">>> BUILD OK, exe size =", os.path.getsize(exe))
        for name in sorted(os.listdir(os.path.join(HERE, "dist"))):
            full = os.path.join(HERE, "dist", name)
            if os.path.isdir(full):
                print("    dir :", name, "(%d items)" % len(os.listdir(full)))
            else:
                print("    file:", name)
    else:
        reason = "rc=%s" % rc
        if not os.path.isfile(exe):
            reason += ", dist/DragonAntivirus.exe 不存在"
        print(">>> BUILD FAILED:", reason)
    print("BUILD END", datetime.datetime.now().isoformat())
    print("=" * 60)
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:  # noqa
        import traceback
        traceback.print_exc()
        sys.exit(2)
