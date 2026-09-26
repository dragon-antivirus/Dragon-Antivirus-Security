# -*- coding: utf-8 -*-
"""天龙神盾安全中心 —— 持久化数据根目录

统一所有模块的可变数据（隔离区 / 信任区 / 配置 / 日志 / 基线 / 诱捕 等）的存放位置。

关键约束：
  - 绝不能放在 exe 同级 dist\\Data —— 打包流程 `rmdir /s /q dist build` 会清空它，
    导致每次重建 / 重启后隔离区、信任区、配置全部丢失（用户已踩坑）。
  - 改为稳定的用户级目录 %LOCALAPPDATA%\\天龙神盾\\Data，重建 / 重启都不会被清掉。
  - 若该目录不可写，回退到 exe 同级 Data（保证程序仍可运行）。
  - 首次切换到 AppData 时，把旧 exe 同级 Data 里的关键持久化数据一次性迁移过来
    （不搬 WebView2 缓存、不搬会被运行期重建的 baseline 等临时内容）。
"""

import os
import shutil
import sys
import threading

APP_NAME = "天龙神盾"

_lock = threading.RLock()
_resolved = None  # 缓存解析结果，避免重复计算


def _base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _appdata_root():
    local = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if not local:
        local = os.path.expanduser("~")
    return os.path.join(local, APP_NAME)


def _legacy_data_dir():
    return os.path.join(_base_dir(), "Data")


def _writable(path):
    try:
        os.makedirs(path, exist_ok=True)
        tmp = os.path.join(path, ".w")
        with open(tmp, "w") as f:
            f.write("1")
        os.remove(tmp)
        return True
    except Exception:
        return False


def data_root():
    """返回持久化数据根目录（含 Data 段），优先 %LOCALAPPDATA%\\天龙神盾\\Data。"""
    global _resolved
    with _lock:
        if _resolved is not None:
            return _resolved
        cand = os.path.join(_appdata_root(), "Data")
        if _writable(cand):
            _resolved = cand
        else:
            _resolved = _legacy_data_dir()
            try:
                os.makedirs(_resolved, exist_ok=True)
            except Exception:
                pass
        return _resolved


# 迁移时从旧目录搬过来的目录（不含会被运行期重建的 baseline）
_MIGRATE_DIRS = ("Quarantine", "boot_backup")

# 迁移时搬过来的关键文件（不含 WebView2 缓存、yara_rules 等运行期再生内容）
_MIGRATE_FILES = (
    "trusted.json",
    "config.json",
    "security.log",
    "engine.log",
    "decoy_manifest.json",
    "registry_backup.json",
    "archive_marks.json",
    "disabled_startup.json",
)


def _fix_quarantine_index(legacy, new):
    """迁移后改写隔离索引里的 stored 绝对路径：旧根 → 新根。

    不改写的话，记录里的 stored 仍指向旧 exe 同级目录（可能已被 rmdir 清掉），
    quarantine_list 会把整条记录判失效并重写空索引 —— 用户 66 条隔离记录就是
    这样丢的。幂等：只改以旧根为前缀的路径。
    """
    try:
        import json
        idx = os.path.join(new, "Quarantine", "index.json")
        if not os.path.isfile(idx):
            return
        with open(idx, "r", encoding="utf-8") as f:
            data = json.load(f)
        items = data.get("items") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return
        old_q = os.path.join(legacy, "Quarantine")
        new_q = os.path.join(new, "Quarantine")
        changed = False
        for it in items:
            if not isinstance(it, dict):
                continue
            stored = it.get("stored") or ""
            if stored and stored.lower().startswith(old_q.lower()):
                it["stored"] = new_q + stored[len(old_q):]
                changed = True
        if changed:
            with open(idx, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
    except Exception:
        pass


def ensure_persistent_data():
    """首次把旧 exe 同级 Data 的关键持久化数据迁移到新的 AppData 根。幂等。"""
    with _lock:
        new = data_root()
        legacy = _legacy_data_dir()
        if legacy == new or not os.path.isdir(legacy):
            return
        marker = os.path.join(new, ".migrated")
        if os.path.isfile(marker):
            return
        try:
            src_index = os.path.join(legacy, "Quarantine", "index.json")
            has_legacy_data = os.path.isfile(src_index) or os.path.isfile(
                os.path.join(legacy, "trusted.json")
            )
            if not has_legacy_data:
                # 没有需要迁移的数据，仅打标记以免每次启动都判断
                open(marker, "w").close()
                return
            for d in _MIGRATE_DIRS:
                s = os.path.join(legacy, d)
                if not os.path.isdir(s):
                    continue
                d2 = os.path.join(new, d)
                for root, _, files in os.walk(s):
                    rel = os.path.relpath(root, s)
                    for fn in files:
                        if fn == ".w":
                            continue
                        sp = os.path.join(root, fn)
                        dp = os.path.join(d2, fn) if rel == "." else os.path.join(d2, rel, fn)
                        if not os.path.exists(dp):
                            os.makedirs(os.path.dirname(dp), exist_ok=True)
                            shutil.copy2(sp, dp)
            for fn in _MIGRATE_FILES:
                s = os.path.join(legacy, fn)
                if os.path.isfile(s) and not os.path.exists(os.path.join(new, fn)):
                    shutil.copy2(s, os.path.join(new, fn))
            _fix_quarantine_index(legacy, new)
            open(marker, "w").close()
        except Exception:
            pass
