# -*- coding: utf-8 -*-
"""天龙神盾安全中心 —— 小工具集

职责（全部为函数形式，可直接被其它模块调用）：
    安全日志   safe_log(标题, 事件, 结果)
    隔离区     quarantine_add / quarantine_list / quarantine_restore / quarantine_remove / quarantine_to_trusted
    信任区     trusted_add / trusted_list / trusted_remove
    系统清理   clean_scan / clean_run
    系统修复   repair_list / repair_run
    启动项管理 startup_list / startup_set
    右键管理   contextmenu_list / contextmenu_set
    文件粉碎机 shred_files

对前端的接口统一以 dragon_ 前缀导出，返回约定：
    列表类 {"items": [...]}
    动作类 {"ok": True, "count": n} 或 {"error": "..."}

状态文件统一存放于工作目录下的 Data\\ 内。
"""

import ctypes
import ctypes.wintypes
import hashlib
import json
import os
import random
import shutil
import sys
import threading
import time

########################################常量与路径########################################

APP_TITLE = "天龙神盾安全中心"

BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
from dragon_paths import data_root, ensure_persistent_data
DATA_DIR = data_root()  # 持久化根：%LOCALAPPDATA%\天龙神盾\Data，重建/重启不丢失
QUARANTINE_DIR = os.path.join(DATA_DIR, "Quarantine")
TRUSTED_FILE = os.path.join(DATA_DIR, "trusted.json")
LOG_FILE = os.path.join(DATA_DIR, "security.log")
REPAIR_BACKUP_FILE = os.path.join(DATA_DIR, "repair_backup.json")

LOG_LIST_LIMIT = 500
QUARANTINE_SUFFIX = ".qtn"

STARTUP_BACKUP_KEY = r"Software\天龙神盾\DisabledStartup"
CONTEXTMENU_STATE_KEY = r"Software\天龙神盾\DisabledContextMenu"

RUN_KEYS = (
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "当前用户"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "当前用户(单次)"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "所有用户"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "所有用户(单次)"),
)

CONTEXTMENU_ROOTS = (
    r"*\shell",
    r"AllFilesystemObjects\shell",
    r"Directory\shell",
    r"Directory\Background\shell",
    r"Folder\shell",
    r"Drive\shell",
)

CONTEXTMENU_DISABLE_VALUE = "LegacyDisable"
CONTEXTMENU_SCAN_NAME = "DragonAntivirusScan"
CONTEXTMENU_SCAN_TITLE = "使用天龙神盾扫描"

IFEO_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

CRITICAL_SERVICES = (
    ("Winmgmt", 2),
    ("EventLog", 2),
    ("Dnscache", 2),
    ("wuauserv", 3),
    ("BITS", 3),
)

KEY_SYSTEM_FILES = (
    "kernel32.dll",
    "ntdll.dll",
    "user32.dll",
    "explorer.exe",
)

_PUSH_LOCK = threading.RLock()
_PUSH_FUNC = None


def _ensure_dirs():
    try:
        ensure_persistent_data()
    except Exception:
        pass
    for path in (DATA_DIR, QUARANTINE_DIR):
        try:
            os.makedirs(path, exist_ok=True)
        except Exception:
            pass


_ensure_dirs()

########################################前端推送########################################


def dragon_set_push(func):
    global _PUSH_FUNC
    with _PUSH_LOCK:
        _PUSH_FUNC = func
    return {"ok": True}


def push_frontend(channel, data):
    with _PUSH_LOCK:
        func = _PUSH_FUNC
    if func is None:
        return False
    try:
        func(channel, data)
        return True
    except Exception:
        return False


_TRAY_ICON = None
_TRAY_LOCK = threading.RLock()


def set_tray_icon(icon):
    global _TRAY_ICON
    with _TRAY_LOCK:
        _TRAY_ICON = icon


def toast(标题, 内容):
    """统一弹窗入口：同时触发 webview 内轻提示 + 系统原生 toast。"""
    消息 = (str(标题) + "｜" + str(内容)) if 标题 else str(内容)
    push_frontend("toast", {
        "style": "notify",
        "title": 标题,
        "message": 消息,
    })
    with _TRAY_LOCK:
        icon = _TRAY_ICON
    if icon is not None:
        try:
            threading.Thread(target=icon.notify, args=(消息, 标题 or "天龙神盾安全中心"), daemon=True).start()
        except Exception:
            pass
    return True

########################################通用工具########################################


def now_text():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def now_minute():
    return time.strftime("%Y-%m-%d %H:%M", time.localtime())


def today_text():
    return time.strftime("%Y-%m-%d", time.localtime())


def human_size(size):
    size = float(size or 0)
    if size >= 1099511627776:
        return "{:.2f} TB".format(size / 1099511627776)
    if size >= 1073741824:
        return "{:.2f} GB".format(size / 1073741824)
    if size >= 1048576:
        return "{:.0f} MB".format(size / 1048576)
    if size >= 1024:
        return "{:.0f} KB".format(size / 1024)
    return "{:.0f} B".format(size)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def read_json(path, default):
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, default.__class__):
                return data
    except Exception:
        pass
    return default


def write_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def file_md5(path, chunk=1048576):
    digest = hashlib.md5()
    try:
        with open(path, "rb") as f:
            while True:
                block = f.read(chunk)
                if not block:
                    break
                digest.update(block)
        return digest.hexdigest()
    except Exception:
        return ""


def expand(path):
    return os.path.expandvars(os.path.expanduser(str(path or "")))

########################################安全日志########################################


def safe_log(标题, 事件, 结果="已处理"):
    entry = {
        "time": now_text(),
        "title": str(标题 or ""),
        "event": str(事件 or ""),
        "result": str(结果 or ""),
    }
    line = json.dumps(entry, ensure_ascii=False)
    try:
        _ensure_dirs()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    push_frontend("security_log", {
        "time": entry["time"][:16],
        "event": entry["title"] + "｜" + entry["event"] if entry["title"] else entry["event"],
        "result": entry["result"],
    })
    return entry


def read_logs(limit=LOG_LIST_LIMIT):
    items = []
    try:
        if os.path.isfile(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        items.append(json.loads(line))
                    except Exception:
                        continue
    except Exception:
        return items
    if limit and len(items) > limit:
        items = items[-limit:]
    return items


def dragon_log_list():
    items = []
    for entry in reversed(read_logs()):
        title = entry.get("title") or ""
        event = entry.get("event") or ""
        items.append({
            "time": str(entry.get("time") or "")[:16],
            "event": title + "｜" + event if title else event,
            "result": entry.get("result") or "",
        })
    return {"items": items}

########################################隔离区########################################


def _quarantine_index_path():
    return os.path.join(QUARANTINE_DIR, "index.json")


def _quarantine_load():
    data = read_json(_quarantine_index_path(), {})
    if not isinstance(data, dict):
        data = {}
    items = data.get("items")
    if not isinstance(items, list):
        items = []
    # stored 兜底：记录里的 stored 是绝对路径，若数据目录被迁移/移动后原路径失效，
    # 按 .qtn 文件名在当前隔离目录找回，避免 quarantine_list 把记录整条判失效并清空索引。
    changed = False
    for it in items:
        if not isinstance(it, dict):
            continue
        stored = it.get("stored") or ""
        if stored and os.path.isfile(stored):
            continue
        name = os.path.basename(stored) if stored else ""
        if name and os.path.isfile(os.path.join(QUARANTINE_DIR, name)):
            it["stored"] = os.path.join(QUARANTINE_DIR, name)
            changed = True
    if changed:
        try:
            _quarantine_save(items)
        except Exception:
            pass
    return items


def _quarantine_save(items):
    return write_json(_quarantine_index_path(), {"items": items})


def _quarantine_find(items, path):
    target = os.path.normcase(os.path.abspath(str(path)))
    for item in items:
        if os.path.normcase(os.path.abspath(str(item.get("path") or ""))) == target:
            return item
    return None


def _terminate_processes_using_file(path):
    """用 Restart Manager 强制结束占用 path 的进程（含其锁定的文件句柄）。"""
    try:
        rm = ctypes.windll.rstrtmgr
    except Exception:
        return False
    session = ctypes.wintypes.DWORD(0)
    key = ctypes.create_unicode_buffer(33)
    rc = rm.RmStartSession(ctypes.byref(session), 0, key)
    if rc != 0:
        return False
    try:
        files = (ctypes.c_wchar_p * 1)(path)
        rc = rm.RmRegisterResources(session, 1, files, 0, None, 0, None)
        if rc != 0:
            return False
        needed = ctypes.wintypes.UINT(0)
        infocount = ctypes.wintypes.UINT(0)
        reasons = ctypes.wintypes.DWORD(0)
        rc = rm.RmGetList(session, ctypes.byref(needed), ctypes.byref(infocount), None, ctypes.byref(reasons))
        if rc != 0:
            return False
        if needed.value == 0:
            return True
        # RmForceShutdown=0x1：强制结束占用进程
        rc = rm.RmShutdown(session, 0x1, None)
        return rc in (0, 0x1C0)
    except Exception:
        return False
    finally:
        try:
            rm.RmEndSession(session)
        except Exception:
            pass


def _schedule_delete_on_reboot(path):
    """登记重启删除（MoveFileEx MOVEFILE_DELAY_UNTIL_REBOOT）。需管理员权限。"""
    try:
        kernel32 = ctypes.windll.kernel32
        if kernel32.MoveFileExW(ctypes.c_wchar_p(path), None, 0x4):  # MOVEFILE_DELAY_UNTIL_REBOOT
            return True
    except Exception:
        pass
    return False


def _remove_source_with_fallback(src, allow_reboot_delete=True):
    """尽力删除源文件：直删 → 强制释放占用进程后删 → 登记重启删除。
    返回是否已在当次成功删除。"""
    try:
        os.remove(src)
        if not os.path.isfile(src):
            return True
    except Exception:
        pass
    _terminate_processes_using_file(src)
    try:
        os.remove(src)
        if not os.path.isfile(src):
            return True
    except Exception:
        pass
    if allow_reboot_delete:
        _schedule_delete_on_reboot(src)
    return False


def quarantine_add(path, allow_reboot_delete=True):
    src = os.path.abspath(expand(path))
    if not os.path.isfile(src):
        return {"error": "文件不存在：{}".format(src)}
    items = _quarantine_load()
    if _quarantine_find(items, src):
        return {"error": "该文件已在隔离区"}
    try:
        stat = os.stat(src)
        size = stat.st_size
        digest = file_md5(src)
        name = (digest or hashlib.md5(src.encode("utf-8", "ignore")).hexdigest()) + QUARANTINE_SUFFIX
        dst = os.path.join(QUARANTINE_DIR, name)
        shutil.copy2(src, dst)
        if not os.path.isfile(dst) or os.path.getsize(dst) != size:
            try:
                os.remove(dst)
            except Exception:
                pass
            return {"error": "隔离文件写入失败"}
        # 关键修复：删除源文件失败时【不回滚副本】，改为强制释放占用进程 / 登记重启删除，
        # 保证隔离区始终能看到文件，且威胁被实质处置（副本已存、源文件待删）。
        removed = _remove_source_with_fallback(src, allow_reboot_delete=allow_reboot_delete)
        item = {
            "path": src,
            "name": os.path.basename(src),
            "stored": dst,
            "size": size,
            "hash": digest,
            "date": today_text(),
            "time": now_text(),
            "source_removed": removed,
        }
        items.append(item)
        _quarantine_save(items)
        # 弹窗与日志由调用端按来源模块成对调用（隔离区管理 / 静态扫描 / 主动防御），
        # 本函数只负责隔离动作本身并如实返回 removed / pending_reboot。
        if removed:
            return {"ok": True, "count": 1, "item": item, "removed": True}
        return {"ok": True, "count": 1, "item": item, "removed": False, "pending_reboot": True}
    except Exception as exc:
        return {"error": str(exc)}


def is_quarantined(path):
    """该路径是否已在隔离区（用于静态扫描避免重复处置 / 重复弹窗）。"""
    target = os.path.normcase(os.path.abspath(expand(path)))
    return _quarantine_find(_quarantine_load(), target) is not None


def quarantine_list():
    items = []
    alive = []
    changed = False
    for item in _quarantine_load():
        stored = item.get("stored") or ""
        if not os.path.isfile(stored):
            changed = True
            continue
        alive.append(item)
        items.append({
            "date": item.get("date") or today_text(),
            "time": item.get("time") or "",
            "path": item.get("path") or "",
            "name": item.get("name") or "",
            "size": item.get("size") or 0,
            "hash": item.get("hash") or "",
        })
    if changed:
        _quarantine_save(alive)
    return {"items": items}


def _restore_target(origin):
    if origin and not os.path.exists(origin):
        parent = os.path.dirname(origin)
        if parent and os.path.isdir(parent):
            return origin
    base = origin or os.path.join(os.path.expanduser("~"), "Desktop")
    name = os.path.basename(base)
    folder = os.path.dirname(base) if os.path.isdir(os.path.dirname(base)) else os.path.expanduser("~")
    target = os.path.join(folder, name)
    if not os.path.exists(target):
        return target
    stem, ext = os.path.splitext(name)
    for index in range(1, 1000):
        candidate = os.path.join(folder, "{}_恢复{}{}".format(stem, index, ext))
        if not os.path.exists(candidate):
            return candidate
    return os.path.join(folder, "restored_{}".format(name))


def quarantine_restore(paths):
    if isinstance(paths, str):
        paths = [paths]
    items = _quarantine_load()
    remain = list(items)
    done = 0
    for path in (paths or []):
        item = _quarantine_find(items, path)
        if not item:
            continue
        stored = item.get("stored") or ""
        try:
            if not os.path.isfile(stored):
                raise RuntimeError("隔离文件已丢失")
            target = _restore_target(item.get("path") or "")
            shutil.copy2(stored, target)
            if os.path.getsize(target) != item.get("size", os.path.getsize(target)):
                raise RuntimeError("校验失败")
            os.remove(stored)
            remain = [x for x in remain if x is not item]
            done += 1
            safe_log("隔离区", "{} 已恢复到 {}".format(item.get("path"), target), "已处理")
            toast("隔离区", "{} 已恢复到 {}".format(item.get("path"), target))
        except Exception as exc:
            safe_log("隔离区", "{} 恢复失败：{}".format(item.get("path"), exc), "失败")
            toast("隔离区", "{} 恢复失败：{}".format(item.get("path"), exc))
    _quarantine_save(remain)
    return {"ok": True, "count": done}


def quarantine_remove(paths):
    if isinstance(paths, str):
        paths = [paths]
    items = _quarantine_load()
    remain = list(items)
    done = 0
    for path in (paths or []):
        item = _quarantine_find(items, path)
        if not item:
            continue
        try:
            stored = item.get("stored") or ""
            if os.path.isfile(stored):
                os.remove(stored)
            remain = [x for x in remain if x is not item]
            done += 1
            safe_log("隔离区", "{} 已彻底移除".format(item.get("path")), "已处理")
            toast("隔离区", "{} 已彻底移除".format(item.get("path")))
        except Exception as exc:
            safe_log("隔离区", "{} 移除失败：{}".format(item.get("path"), exc), "失败")
            toast("隔离区", "{} 移除失败：{}".format(item.get("path"), exc))
    _quarantine_save(remain)
    return {"ok": True, "count": done}


def quarantine_to_trusted(paths):
    if isinstance(paths, str):
        paths = [paths]
    items = _quarantine_load()
    remain = list(items)
    done = 0
    for path in (paths or []):
        item = _quarantine_find(items, path)
        if not item:
            continue
        result = trusted_add(item.get("path") or "")
        if result.get("error"):
            safe_log("隔离区", "{} 加入白名单失败：{}".format(item.get("path"), result.get("error")), "失败")
            toast("隔离区", "{} 加入白名单失败：{}".format(item.get("path"), result.get("error")))
            continue
        try:
            stored = item.get("stored") or ""
            if os.path.isfile(stored):
                os.remove(stored)
            remain = [x for x in remain if x is not item]
            done += 1
            safe_log("隔离区", "{} 已加入白名单".format(item.get("path")), "已处理")
            toast("隔离区", "{} 已加入白名单".format(item.get("path")))
        except Exception as exc:
            safe_log("隔离区", "{} 转白名单失败：{}".format(item.get("path"), exc), "失败")
            toast("隔离区", "{} 转白名单失败：{}".format(item.get("path"), exc))
    _quarantine_save(remain)
    return {"ok": True, "count": done}


def dragon_quarantine_add(path):
    result = quarantine_add(path)
    if isinstance(result, dict) and result.get("ok"):
        safe_log("隔离区", "{} 已加入隔离".format(result.get("item", {}).get("path", path)), "已隔离")
    return result


def dragon_quarantine_list():
    return quarantine_list()


def dragon_quarantine_restore(paths):
    return quarantine_restore(paths)


def dragon_quarantine_remove(paths):
    return quarantine_remove(paths)


def dragon_quarantine_to_trusted(paths):
    return quarantine_to_trusted(paths)


def quarantine_restore_to_trusted(paths):
    """恢复并加入白名单：先把隔离文件恢复到原始路径，再把该路径加入信任区。
    两步任一步失败都如实记录，不静默吞错。"""
    if isinstance(paths, str):
        paths = [paths]
    items = _quarantine_load()
    remain = list(items)
    done = 0
    for path in (paths or []):
        item = _quarantine_find(items, path)
        if not item:
            continue
        original = item.get("path") or ""
        try:
            stored = item.get("stored") or ""
            if not os.path.isfile(stored):
                raise RuntimeError("隔离文件已丢失")
            target = _restore_target(original)
            shutil.copy2(stored, target)
            if os.path.getsize(target) != item.get("size", os.path.getsize(target)):
                raise RuntimeError("校验失败")
            os.remove(stored)
            remain = [x for x in remain if x is not item]
            if original:
                res = trusted_add(original)
                if res.get("error"):
                    safe_log("隔离区", "{} 已恢复但加白失败：{}".format(original, res.get("error")), "失败")
                    toast("隔离区", "{} 已恢复，加白失败：{}".format(original, res.get("error")))
                else:
                    safe_log("隔离区", "{} 已恢复并加入白名单".format(original), "已处理")
                    toast("隔离区", "{} 已恢复并加入白名单".format(original))
            else:
                safe_log("隔离区", "{} 已恢复（无原始路径，未加白）".format(path), "已处理")
            done += 1
        except Exception as exc:
            safe_log("隔离区", "{} 恢复并加白失败：{}".format(original or path, exc), "失败")
            toast("隔离区", "{} 恢复并加白失败：{}".format(original or path, exc))
    _quarantine_save(remain)
    return {"ok": True, "count": done}


def dragon_quarantine_restore_to_trusted(paths):
    return quarantine_restore_to_trusted(paths)

########################################信任区########################################


def _trusted_load():
    data = read_json(TRUSTED_FILE, {})
    if not isinstance(data, dict):
        data = {}
    items = data.get("items")
    if not isinstance(items, list):
        items = []
    return items


def _trusted_save(items):
    return write_json(TRUSTED_FILE, {"items": items})


def trusted_add(path):
    target = os.path.abspath(expand(path))
    if not target:
        return {"error": "路径为空"}
    items = _trusted_load()
    for item in items:
        if os.path.normcase(item.get("path") or "") == os.path.normcase(target):
            return {"error": "该路径已在白名单"}
    items.append({
        "path": target,
        "name": os.path.basename(target) or target,
        "date": today_text(),
        "time": now_text(),
    })
    if not _trusted_save(items):
        return {"error": "白名单写入失败"}
    safe_log("信任区", "{} 已加入白名单".format(target), "已处理")
    toast("信任区", "{} 已加入白名单".format(target))
    return {"ok": True, "count": 1}


def trusted_list():
    items = []
    for item in _trusted_load():
        items.append({
            "date": item.get("date") or today_text(),
            "path": item.get("path") or "",
            "name": item.get("name") or "",
        })
    return {"items": items}


def trusted_remove(paths):
    if isinstance(paths, str):
        paths = [paths]
    wanted = set(os.path.normcase(os.path.abspath(str(p))) for p in (paths or []))
    items = _trusted_load()
    remain = []
    done = 0
    for item in items:
        if os.path.normcase(item.get("path") or "") in wanted:
            done += 1
            safe_log("信任区", "{} 已移出白名单".format(item.get("path")), "已处理")
            toast("信任区", "{} 已移出白名单".format(item.get("path")))
            continue
        remain.append(item)
    _trusted_save(remain)
    return {"ok": True, "count": done}


def is_trusted(path):
    """判断路径是否位于信任白名单：精确路径匹配，或位于白名单目录内（目录级信任）。"""
    if not path:
        return False
    try:
        target = os.path.abspath(expand(path))
    except Exception:
        return False
    if not target:
        return False
    for item in _trusted_load():
        tp = item.get("path") or ""
        if not tp:
            continue
        try:
            tp = os.path.abspath(expand(tp))
        except Exception:
            continue
        if os.path.normcase(tp) == os.path.normcase(target):
            return True
        try:
            if os.path.isdir(tp) and os.path.normcase(target).startswith(
                    os.path.normcase(tp + os.sep)):
                return True
        except Exception:
            pass
    return False


def dragon_trusted_add(path):
    return trusted_add(path)


def dragon_trusted_list():
    return trusted_list()


def dragon_trusted_remove(paths):
    return trusted_remove(paths)

########################################系统清理########################################


def _walk_size(path, budget=2.0):
    total = 0
    deadline = time.time() + budget
    truncated = False
    for root, dirs, files in os.walk(path, onerror=lambda err: None):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except Exception:
                continue
        if time.time() > deadline:
            truncated = True
            break
    return total, truncated


def _purge_dir(path, budget=6.0):
    freed = 0
    deadline = time.time() + budget
    for root, dirs, files in os.walk(path, onerror=lambda err: None):
        for name in files:
            full = os.path.join(root, name)
            try:
                size = os.path.getsize(full)
                os.remove(full)
                freed += size
            except Exception:
                continue
        if time.time() > deadline:
            break
    for root, dirs, files in os.walk(path, topdown=False, onerror=lambda err: None):
        for name in dirs:
            try:
                os.rmdir(os.path.join(root, name))
            except Exception:
                continue
    return freed


class SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("i64Size", ctypes.c_longlong),
        ("i64NumItems", ctypes.c_longlong),
    ]


def _recycle_bin_info():
    try:
        info = SHQUERYRBINFO()
        info.cbSize = ctypes.sizeof(SHQUERYRBINFO)
        ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
        return max(0, int(info.i64Size)), max(0, int(info.i64NumItems))
    except Exception:
        return 0, 0


def _recycle_bin_empty():
    size_before, _ = _recycle_bin_info()
    try:
        flags = 0x00000001 | 0x00000002 | 0x00000004
        ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, flags)
    except Exception:
        return 0
    size_after, _ = _recycle_bin_info()
    return max(0, size_before - size_after)


def _clean_targets():
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")
    windir = os.environ.get("WINDIR", r"C:\Windows")
    temp = os.environ.get("TEMP", "")
    targets = {
        "系统临时文件": [temp, os.path.join(windir, "Temp")],
        "浏览器缓存": [
            os.path.join(local, r"Microsoft\Edge\User Data\Default\Cache"),
            os.path.join(local, r"Google\Chrome\User Data\Default\Cache"),
            os.path.join(local, r"Microsoft\Windows\INetCache"),
        ],
        "缩略图缓存": [os.path.join(local, r"Microsoft\Windows\Explorer")],
        "日志文件": [os.path.join(windir, "Logs"), os.path.join(local, "Temp", "Logs")],
        "系统缓存": [
            os.path.join(windir, r"SoftwareDistribution\Download"),
            os.path.join(roaming, r"Microsoft\Windows\Recent"),
        ],
    }
    return targets


def clean_scan():
    items = []
    for name, paths in _clean_targets().items():
        total = 0
        for path in paths:
            if not path or not os.path.isdir(path):
                continue
            if os.path.basename(path).lower() == "explorer":
                for entry in os.listdir(path):
                    if entry.lower().startswith("thumbcache_"):
                        try:
                            total += os.path.getsize(os.path.join(path, entry))
                        except Exception:
                            continue
                continue
            size, _ = _walk_size(path)
            total += size
        if total > 0:
            items.append({"name": name, "size": total})
    recycle_size, recycle_items = _recycle_bin_info()
    if recycle_size > 0:
        items.append({"name": "回收站", "size": recycle_size})
    admin_note = "" if is_admin() else "（部分系统目录需要管理员权限）"
    return {"items": items, "admin": is_admin(), "note": admin_note}


def clean_run(names):
    if isinstance(names, str):
        names = [names]
    wanted = [str(n) for n in (names or [])]
    targets = _clean_targets()
    freed = 0
    done = []
    for name in wanted:
        if name == "回收站":
            got = _recycle_bin_empty()
            freed += got
            done.append(name)
            continue
        paths = targets.get(name)
        if not paths:
            continue
        for path in paths:
            if not path or not os.path.isdir(path):
                continue
            if os.path.basename(path).lower() == "explorer":
                for entry in os.listdir(path):
                    if entry.lower().startswith("thumbcache_"):
                        full = os.path.join(path, entry)
                        try:
                            size = os.path.getsize(full)
                            os.remove(full)
                            freed += size
                        except Exception:
                            continue
                continue
            freed += _purge_dir(path)
        done.append(name)
    if done:
        safe_log("系统清理", "已清理 {}，释放 {}".format("、".join(done), human_size(freed)), "成功")
        toast("系统清理", "已清理 {}，释放 {}".format("、".join(done), human_size(freed)))
    return {"ok": True, "freedBytes": freed, "count": len(done)}

########################################系统修复########################################


def _read_reg_value(root, path, name):
    import winreg
    try:
        with winreg.OpenKey(root, path) as key:
            value, kind = winreg.QueryValueEx(key, name)
            return value, kind
    except Exception:
        return None, None


def _list_subkeys(root, path):
    import winreg
    names = []
    try:
        with winreg.OpenKey(root, path) as key:
            index = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, index))
                    index += 1
                except OSError:
                    break
    except Exception:
        return names
    return names


def _check_registry():
    import winreg
    hits = []
    for name in _list_subkeys(winreg.HKEY_LOCAL_MACHINE, IFEO_KEY):
        value, _ = _read_reg_value(winreg.HKEY_LOCAL_MACHINE, IFEO_KEY + "\\" + name, "Debugger")
        if value:
            hits.append({
                "key": IFEO_KEY + "\\" + name,
                "name": name,
                "debugger": value,
            })
    return hits


def _check_services():
    import winreg
    bad = []
    for name, expect in CRITICAL_SERVICES:
        value, _ = _read_reg_value(winreg.HKEY_LOCAL_MACHINE,
                                   r"SYSTEM\CurrentControlSet\Services" + "\\" + name, "Start")
        if value is None:
            bad.append({"name": name, "start": None, "expect": expect})
            continue
        if value == 4:
            bad.append({"name": name, "start": value, "expect": expect})
    return bad


def _hosts_path():
    windir = os.environ.get("WINDIR", r"C:\Windows")
    return os.path.join(windir, r"System32\drivers\etc\hosts")


def _check_hosts():
    bad = []
    path = _hosts_path()
    try:
        if not os.path.isfile(path):
            return bad
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for index, line in enumerate(f, 1):
                text = line.strip()
                if not text or text.startswith("#"):
                    continue
                parts = text.split()
                if len(parts) < 2:
                    continue
                host = parts[1].lower()
                if host in ("localhost", "localhost.localdomain", "127.0.0.1", "::1"):
                    continue
                bad.append({"line": index, "text": text, "host": host})
    except Exception:
        return bad
    return bad


def _check_startup_targets():
    bad = []
    for scope, key_path, label in RUN_KEYS:
        root = _hkey(scope)
        if root is None:
            continue
        import winreg
        try:
            with winreg.OpenKey(root, key_path) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    if isinstance(value, str):
                        target = value.strip().strip('"')
                        if target and not os.path.isfile(expand(target)) and not os.path.isdir(expand(target)):
                            bad.append({"scope": scope, "label": label, "name": name, "value": value})
        except Exception:
            continue
    return bad


def _check_thumbnail_cache():
    local = os.environ.get("LOCALAPPDATA", "")
    path = os.path.join(local, r"Microsoft\Windows\Explorer")
    total = 0
    if os.path.isdir(path):
        for entry in os.listdir(path):
            if entry.lower().startswith("thumbcache_"):
                try:
                    total += os.path.getsize(os.path.join(path, entry))
                except Exception:
                    continue
    return total


def repair_list():
    items = []
    lock = threading.RLock()
    with lock:
        try:
            reg_hits = _check_registry()
            items.append({
                "name": "注册表项",
                "abnormal": bool(reg_hits),
                "detail": "发现 {} 项劫持".format(len(reg_hits)) if reg_hits else "正常",
            })
        except Exception:
            items.append({"name": "注册表项", "abnormal": False, "detail": "无法检查"})
        try:
            svc = _check_services()
            items.append({
                "name": "系统服务状态",
                "abnormal": bool(svc),
                "detail": "发现 {} 项异常".format(len(svc)) if svc else "正常",
            })
        except Exception:
            items.append({"name": "系统服务状态", "abnormal": False, "detail": "无法检查"})
        try:
            hosts = _check_hosts()
            items.append({
                "name": "网络配置",
                "abnormal": bool(hosts),
                "detail": "hosts 存在 {} 条异常映射".format(len(hosts)) if hosts else "正常",
            })
        except Exception:
            items.append({"name": "网络配置", "abnormal": False, "detail": "无法检查"})
        try:
            startup = _check_startup_targets()
            items.append({
                "name": "启动项关联",
                "abnormal": bool(startup),
                "detail": "{} 项指向不存在的文件".format(len(startup)) if startup else "正常",
            })
        except Exception:
            items.append({"name": "启动项关联", "abnormal": False, "detail": "无法检查"})
        try:
            thumb = _check_thumbnail_cache()
            items.append({
                "name": "系统缓存",
                "abnormal": thumb > 512 * 1048576,
                "detail": "缩略图缓存 {}".format(human_size(thumb)),
            })
        except Exception:
            items.append({"name": "系统缓存", "abnormal": False, "detail": "无法检查"})
    return {"items": items, "admin": is_admin()}


def _backup_note(title, payload):
    data = read_json(REPAIR_BACKUP_FILE, {})
    if not isinstance(data, dict):
        data = {}
    records = data.get("records")
    if not isinstance(records, list):
        records = []
    records.append({"time": now_text(), "title": title, "payload": payload})
    data["records"] = records[-200:]
    write_json(REPAIR_BACKUP_FILE, data)


def _repair_registry():
    import winreg
    fixed = 0
    for hit in _check_registry():
        try:
            _backup_note("删除 IFEO 劫持", {"key": hit["key"], "debugger": hit["debugger"]})
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hit["key"], 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, "Debugger")
            fixed += 1
            safe_log("系统修复", "已清除劫持项 {}".format(hit["name"]), "成功")
            toast("系统修复", "已清除劫持项 {}".format(hit["name"]))
        except Exception as exc:
            safe_log("系统修复", "清除 {} 失败：{}".format(hit["name"], exc), "失败")
            toast("系统修复", "清除 {} 失败：{}".format(hit["name"], exc))
    return fixed


def _repair_services():
    import winreg
    fixed = 0
    for item in _check_services():
        try:
            path = r"SYSTEM\CurrentControlSet\Services" + "\\" + item["name"]
            current, _ = _read_reg_value(winreg.HKEY_LOCAL_MACHINE, path, "Start")
            _backup_note("恢复服务启动类型", {"service": item["name"], "start": current})
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, int(item["expect"]))
            fixed += 1
            safe_log("系统修复", "已恢复服务 {} 启动类型".format(item["name"]), "成功")
            toast("系统修复", "已恢复服务 {} 启动类型".format(item["name"]))
        except Exception as exc:
            safe_log("系统修复", "恢复服务 {} 失败：{}".format(item["name"], exc), "失败")
            toast("系统修复", "恢复服务 {} 失败：{}".format(item["name"], exc))
    return fixed


def _repair_hosts():
    bad = _check_hosts()
    if not bad:
        return 0
    path = _hosts_path()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        bad_lines = set(item["line"] for item in bad)
        _backup_note("清理 hosts 异常映射", {"removed": [item["text"] for item in bad]})
        kept = [line for index, line in enumerate(lines, 1) if index not in bad_lines]
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(kept)
        safe_log("系统修复", "已清理 hosts 异常映射 {} 条".format(len(bad)), "成功")
        toast("系统修复", "已清理 hosts 异常映射 {} 条".format(len(bad)))
        return len(bad)
    except Exception as exc:
        safe_log("系统修复", "清理 hosts 失败：{}".format(exc), "失败")
        toast("系统修复", "清理 hosts 失败：{}".format(exc))
        return 0


def _repair_startup_targets():
    bad = _check_startup_targets()
    fixed = 0
    for item in bad:
        result = startup_set(item["name"], False)
        if result.get("ok"):
            fixed += 1
    if fixed:
        safe_log("系统修复", "已禁用 {} 项失效启动项".format(fixed), "成功")
        toast("系统修复", "已禁用 {} 项失效启动项".format(fixed))
    return fixed


def _repair_thumbnail():
    local = os.environ.get("LOCALAPPDATA", "")
    path = os.path.join(local, r"Microsoft\Windows\Explorer")
    freed = 0
    if not os.path.isdir(path):
        return 0
    for entry in os.listdir(path):
        if entry.lower().startswith("thumbcache_"):
            full = os.path.join(path, entry)
            try:
                size = os.path.getsize(full)
                os.remove(full)
                freed += size
            except Exception:
                continue
    if freed:
        safe_log("系统修复", "已清理缩略图缓存 {}".format(human_size(freed)), "成功")
        toast("系统修复", "已清理缩略图缓存 {}".format(human_size(freed)))
    return 1 if freed else 0


_REPAIR_ACTIONS = {
    "注册表项": _repair_registry,
    "系统服务状态": _repair_services,
    "网络配置": _repair_hosts,
    "启动项关联": _repair_startup_targets,
    "系统缓存": _repair_thumbnail,
}


def repair_run(names):
    if isinstance(names, str):
        names = [names]
    fixed = 0
    for name in (names or []):
        action = _REPAIR_ACTIONS.get(str(name))
        if action is None:
            continue
        try:
            fixed += int(action() or 0)
        except Exception as exc:
            safe_log("系统修复", "{} 修复异常：{}".format(name, exc), "失败")
            toast("系统修复", "{} 修复异常：{}".format(name, exc))
    return {"ok": True, "count": fixed}

########################################启动项管理########################################


def _hkey(scope):
    import winreg
    if scope == "HKCU":
        return winreg.HKEY_CURRENT_USER
    if scope == "HKLM":
        return winreg.HKEY_LOCAL_MACHINE
    return None


def _startup_dirs():
    roaming = os.environ.get("APPDATA", "")
    program_data = os.environ.get("ProgramData", "")
    dirs = []
    if roaming:
        dirs.append((os.path.join(roaming, r"Microsoft\Windows\Start Menu\Programs\Startup"), "当前用户"))
    if program_data:
        dirs.append((os.path.join(program_data, r"Microsoft\Windows\Start Menu\Programs\Startup"), "所有用户"))
    return dirs


def startup_list():
    import winreg
    items = []
    for scope, key_path, label in RUN_KEYS:
        root = _hkey(scope)
        if root is None:
            continue
        try:
            with winreg.OpenKey(root, key_path) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    items.append({
                        "name": name,
                        "command": str(value),
                        "enabled": True,
                        "scope": scope,
                        "source": label,
                    })
        except Exception:
            continue
    disabled = read_json(os.path.join(DATA_DIR, "disabled_startup.json"), {})
    if isinstance(disabled, dict):
        for name, info in (disabled.get("items") or {}).items():
            items.append({
                "name": name,
                "command": str(info.get("command") or ""),
                "enabled": False,
                "scope": info.get("scope") or "HKCU",
                "source": info.get("source") or "已禁用",
            })
    for folder, label in _startup_dirs():
        if not os.path.isdir(folder):
            continue
        for entry in os.listdir(folder):
            if entry.lower() == "desktop.ini":
                continue
            full = os.path.join(folder, entry)
            items.append({
                "name": entry,
                "command": full,
                "enabled": not entry.lower().endswith(".disabled"),
                "scope": "FOLDER",
                "source": label,
            })
    return {"items": items}


def _disabled_file():
    return os.path.join(DATA_DIR, "disabled_startup.json")


def startup_set(name, enabled):
    import winreg
    name = str(name or "")
    items = startup_list().get("items") or []
    target = None
    for item in items:
        if item.get("name") == name:
            target = item
            break
    if target is None:
        return {"error": "未找到启动项：{}".format(name)}
    if target.get("scope") == "FOLDER":
        return _startup_set_folder(target, bool(enabled))
    return _startup_set_registry(target, bool(enabled))


def _startup_set_folder(item, enabled):
    full = expand(item.get("command") or "")
    try:
        if enabled:
            if full.lower().endswith(".disabled"):
                os.rename(full, full[: -len(".disabled")])
        else:
            if not full.lower().endswith(".disabled"):
                os.rename(full, full + ".disabled")
        safe_log("启动项管理", "{} 已{}".format(item.get("name"), "启用" if enabled else "禁用"), "成功")
        toast("启动项管理", "{} 已{}".format(item.get("name"), "启用" if enabled else "禁用"))
        return {"ok": True}
    except Exception as exc:
        return {"error": str(exc)}


def _startup_set_registry(item, enabled):
    import winreg
    scope = item.get("scope") or "HKCU"
    root = _hkey(scope)
    key_path = None
    for sc, path, label in RUN_KEYS:
        if sc == scope and label == item.get("source"):
            key_path = path
            break
    if key_path is None:
        key_path = RUN_KEYS[0][1]
    name = item.get("name") or ""
    command = item.get("command") or ""
    disabled_file = _disabled_file()
    disabled = read_json(disabled_file, {})
    if not isinstance(disabled, dict):
        disabled = {}
    entries = disabled.get("items")
    if not isinstance(entries, dict):
        entries = {}
    try:
        if enabled:
            info = entries.pop(name, None)
            if info is None:
                return {"error": "没有该启动项的禁用记录"}
            with winreg.CreateKey(root, key_path) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(info.get("command") or ""))
            disabled["items"] = entries
            write_json(disabled_file, disabled)
            safe_log("启动项管理", "{} 已启用".format(name), "成功")
            toast("启动项管理", "{} 已启用".format(name))
            return {"ok": True}
        with winreg.CreateKey(root, key_path) as key:
            winreg.DeleteValue(key, name)
        entries[name] = {"command": command, "scope": scope, "source": item.get("source") or ""}
        disabled["items"] = entries
        write_json(disabled_file, disabled)
        safe_log("启动项管理", "{} 已禁用".format(name), "成功")
        toast("启动项管理", "{} 已禁用".format(name))
        return {"ok": True}
    except PermissionError:
        return {"error": "需要管理员权限才能修改该项"}
    except Exception as exc:
        return {"error": str(exc)}

########################################右键管理########################################


def _context_scan_command():
    """生成 Windows 右键扫描命令，支持源码运行与 onefile 运行。"""
    if getattr(sys, "frozen", False):
        app = os.path.abspath(sys.executable)
        return '"{}" --dragon-context-scan "%1"'.format(app)
    script = os.path.abspath(os.path.join(BASE_DIR, "Dragon_Antivirus.py"))
    return '"{}" "{}" --dragon-context-scan "%1"'.format(os.path.abspath(sys.executable), script)


def install_context_scan_menu():
    """安装当前用户的文件/文件夹右键扫描项，不需要管理员权限。

    只创建或更新命令，不删除用户通过右键管理设置的 LegacyDisable 状态。
    """
    import winreg
    locations = (
        r"Software\Classes\*\shell" + "\\" + CONTEXTMENU_SCAN_NAME,
        r"Software\Classes\Directory\shell" + "\\" + CONTEXTMENU_SCAN_NAME,
    )
    command = _context_scan_command()
    try:
        for location in locations:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, location) as key:
                winreg.SetValueEx(key, "MUIVerb", 0, winreg.REG_SZ, CONTEXTMENU_SCAN_TITLE)
                winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, os.path.abspath(sys.executable))
                with winreg.CreateKey(key, "command") as cmd:
                    winreg.SetValueEx(cmd, "", 0, winreg.REG_SZ, command)
        safe_log("右键扫描", "已安装文件与文件夹右键扫描入口", "成功")
        return {"ok": True, "command": command}
    except PermissionError:
        return {"error": "需要权限才能安装右键扫描入口"}
    except Exception as exc:
        safe_log("右键扫描", "安装右键入口失败：{}".format(exc), "失败")
        return {"error": str(exc)}


def _contextmenu_keys():
    import winreg
    keys = []
    for root_name, root in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
        for sub in CONTEXTMENU_ROOTS:
            if root_name == "HKCU":
                path = r"Software\Classes" + "\\" + sub
            else:
                path = r"SOFTWARE\Classes" + "\\" + sub
            keys.append((root_name, root, path, sub))
    return keys


def contextmenu_list():
    import winreg
    items = []
    for root_name, root, path, sub in _contextmenu_keys():
        for name in _list_subkeys(root, path):
            if name.lower() in ("open", "openwith", "print", "runas", "cmd", "find", "powershell"):
                continue
            full = path + "\\" + name
            display, _ = _read_reg_value(root, full, "MUIVerb")
            if not display:
                display, _ = _read_reg_value(root, full, "")
            legacy, _ = _read_reg_value(root, full, CONTEXTMENU_DISABLE_VALUE)
            items.append({
                "name": name,
                "menu": str(display or name),
                "scope": root_name,
                "location": sub,
                "enabled": legacy is None,
            })
    return {"items": items}


def contextmenu_set(name, enabled):
    import winreg
    name = str(name or "")
    items = [item for item in (contextmenu_list().get("items") or [])
             if item.get("name") == name]
    if not items:
        return {"error": "未找到右键菜单项：{}".format(name)}
    changed = 0
    try:
        for target in items:
            root = _hkey(target.get("scope"))
            base = r"Software\Classes" if target.get("scope") == "HKCU" else r"SOFTWARE\Classes"
            path = base + "\\" + str(target.get("location") or "")
            full = path + "\\" + name
            with winreg.OpenKey(root, full, 0, winreg.KEY_SET_VALUE) as key:
                if enabled:
                    try:
                        winreg.DeleteValue(key, CONTEXTMENU_DISABLE_VALUE)
                    except FileNotFoundError:
                        pass
                else:
                    winreg.SetValueEx(key, CONTEXTMENU_DISABLE_VALUE, 0, winreg.REG_SZ, "")
            changed += 1
        safe_log("右键管理", "{} 个位置的 {} 已{}".format(changed, name, "启用" if enabled else "禁用"), "成功")
        toast("右键管理", "{} 已{}".format(name, "启用" if enabled else "禁用"))
        return {"ok": True, "count": changed}
    except PermissionError:
        return {"error": "需要管理员权限才能修改该项"}
    except Exception as exc:
        return {"error": str(exc)}

########################################文件粉碎机########################################

SHRED_PASSES = 3


def shred_files(paths):
    if isinstance(paths, str):
        paths = [paths]
    done = 0
    for raw in (paths or []):
        path = os.path.abspath(expand(raw))
        if not os.path.isfile(path):
            safe_log("文件粉碎机", "{} 不存在或不是文件，已跳过".format(path), "失败")
            toast("文件粉碎机", "{} 不存在或不是文件，已跳过".format(path))
            continue
        if _is_protected(path):
            safe_log("文件粉碎机", "{} 位于系统目录，已拒绝".format(path), "失败")
            toast("文件粉碎机", "{} 位于系统目录，已拒绝".format(path))
            continue
        try:
            size = os.path.getsize(path)
            with open(path, "r+b") as f:
                for _ in range(SHRED_PASSES):
                    f.seek(0)
                    remaining = size
                    while remaining > 0:
                        block = min(1048576, remaining)
                        f.write(os.urandom(block))
                        remaining -= block
                    f.flush()
                    os.fsync(f.fileno())
                f.seek(0)
                f.truncate(0)
            folder = os.path.dirname(path)
            temp = os.path.join(folder, "drg_{}.tmp".format(random.randint(10 ** 8, 10 ** 9)))
            try:
                os.rename(path, temp)
                os.remove(temp)
            except Exception:
                os.remove(path)
            done += 1
            safe_log("文件粉碎机", "{} 已粉碎（{}）".format(path, human_size(size)), "成功")
            toast("文件粉碎机", "{} 已粉碎（{}）".format(path, human_size(size)))
        except Exception as exc:
            safe_log("文件粉碎机", "{} 粉碎失败：{}".format(path, exc), "失败")
            toast("文件粉碎机", "{} 粉碎失败：{}".format(path, exc))
    return {"ok": True, "count": done}


def _is_protected(path):
    windir = os.environ.get("WINDIR", r"C:\Windows").lower()
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files").lower()
    target = path.lower()
    return target.startswith(windir) or target.startswith(program_files + "\\windows")


########################################前端接口别名########################################


def dragon_clean_scan():
    return clean_scan()


def dragon_clean_run(names):
    return clean_run(names)


def dragon_repair_list():
    return repair_list()


def dragon_repair_run(names):
    return repair_run(names)


def dragon_startup_list():
    return startup_list()


def dragon_startup_set(name, enabled):
    return startup_set(name, enabled)


def dragon_contextmenu_list():
    return contextmenu_list()


def dragon_contextmenu_set(name, enabled):
    return contextmenu_set(name, enabled)


def dragon_shred_files(paths):
    return shred_files(paths)


def dragon_tools_selftest():
    return {
        "admin": is_admin(),
        "log": len(dragon_log_list().get("items") or []),
        "quarantine": len(dragon_quarantine_list().get("items") or []),
        "trusted": len(dragon_trusted_list().get("items") or []),
        "clean": len(dragon_clean_scan().get("items") or []),
        "repair": len(dragon_repair_list().get("items") or []),
        "startup": len(dragon_startup_list().get("items") or []),
        "contextmenu": len(dragon_contextmenu_list().get("items") or []),
    }


if __name__ == "__main__":
    print(json.dumps(dragon_tools_selftest(), ensure_ascii=False, indent=2))
