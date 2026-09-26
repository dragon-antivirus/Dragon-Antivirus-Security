# -*- coding: utf-8 -*-
"""天龙神盾安全中心 —— 扫描衔接模块

负责扫描规划（智能 / 全盘 / 自定义）、调用四层引擎、把结果回填到病毒扫描页，
并在完成后推送扫描报告。
"""

import ctypes
import ctypes.wintypes
import json
import os
import sys
import threading
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor
from Dragon_Tools import safe_log, toast

########################################常量与路径########################################

BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
from dragon_paths import data_root
DATA_DIR = data_root()  # 持久化根：%LOCALAPPDATA%\天龙神盾\Data，重建/重启不丢失
SCAN_LOG_FILE = os.path.join(DATA_DIR, "scan.log")

SCAN_POOL_WORKERS = 2

SCAN_DEDUP = True
SCAN_DEDUP_MAX_BYTES = 256 * 1024 * 1024

MODE_SMART = "智能扫描"
MODE_FULL = "全盘扫描"
MODE_CUSTOM = "自定义扫描"
MODE_CUSTOM_FILE = "自定义文件"
MODE_CUSTOM_DIR = "自定义目录"
SCAN_MODES = (MODE_SMART, MODE_FULL, MODE_CUSTOM, MODE_CUSTOM_FILE, MODE_CUSTOM_DIR)

EXECUTABLE_EXTENSIONS = (
    ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".com", ".drv", ".efi",
    ".mui", ".ax", ".acm", ".tsp", ".pif", ".gadget", ".msstyles", ".ime",
)

SKIP_EXTENSIONS = (
    ".tmp", ".log", ".lnk", ".ini", ".db", ".dat", ".json", ".xml", ".txt",
)

SKIP_DIRECTORY_NAMES = {
    "winsxs", "$recycle.bin", "system volume information", "$windows.~bt",
    "$windows.~ws", "recovery", "installer", "assembly", "servicing",
    "driverstore", "softwaredistribution", "catroot", "catroot2", "wfp",
    "windowspowershell", "microsoft.net", "node_modules", ".git",
    "__pycache__", "temp", "tmp", "cache", "caches", "logs",
}

FULL_SCAN_MAX_DEPTH = 8
CUSTOM_SCAN_MAX_DEPTH = 16
SMART_SCAN_MAX_DEPTH = 12
MAGIC_READ_BYTES = 2

STAT_PUSH_INTERVAL = 0.25
PLAN_BATCH = 64

DETECTION_LABELS = {
    1: "SignedSafe",
    2: "HashDB",
    3: "YARA",
    4: "AiSmartEngine.Gen5",
}

########################################推送与日志########################################

_PUSH_FUNC = None
_PUSH_LOCK = threading.RLock()


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


def now_text():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _ensure_dirs():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except Exception:
        pass


def scan_log(event, detail=""):
    try:
        _ensure_dirs()
        with open(SCAN_LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write("{}\t{}\t{}\n".format(now_text(), event, detail))
    except Exception:
        pass


_ensure_dirs()

########################################扫描状态########################################

_STATE_LOCK = threading.RLock()
_STATE = {
    "running": False,
    "mode": "",
    "target": "",
    "scanned": 0,
    "total": 0,
    "found": 0,
    "started_at": 0.0,
    "finished_at": 0.0,
    "stop": None,
    "detections": {},
}

_DETECTIONS_LOCK = threading.RLock()
_DETECTIONS = {}


def _state_snapshot():
    with _STATE_LOCK:
        return {
            "running": _STATE["running"],
            "mode": _STATE["mode"],
            "target": _STATE["target"],
            "scanned": _STATE["scanned"],
            "total": _STATE["total"],
            "found": _STATE["found"],
            "started_at": _STATE["started_at"],
            "finished_at": _STATE["finished_at"],
        }


def scan_status():
    snapshot = _state_snapshot()
    with _DETECTIONS_LOCK:
        snapshot["detection_count"] = len(_DETECTIONS)
    return snapshot

########################################扫描规划########################################


def user_directory(name, fallback=""):
    try:
        value = os.path.expandvars("%{}%".format(name))
        if value and value != "%{}%".format(name) and os.path.isdir(value):
            return value
    except Exception:
        pass
    return fallback


def running_process_images():
    images = set()
    try:
        psapi = ctypes.windll.psapi
        kernel32 = ctypes.windll.kernel32
        process_ids = (ctypes.wintypes.DWORD * 4096)()
        needed = ctypes.wintypes.DWORD()
        if not psapi.EnumProcesses(ctypes.byref(process_ids), ctypes.sizeof(process_ids), ctypes.byref(needed)):
            return images
        count = needed.value // ctypes.sizeof(ctypes.wintypes.DWORD)
        for index in range(count):
            pid = process_ids[index]
            if not pid:
                continue
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                continue
            try:
                buffer = ctypes.create_unicode_buffer(1024)
                size = ctypes.wintypes.DWORD(ctypes.sizeof(buffer))
                if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                    if buffer.value:
                        images.add(buffer.value)
            except Exception:
                pass
            finally:
                kernel32.CloseHandle(handle)
    except Exception:
        pass
    return images


def running_process_modules():
    modules = set()
    windows_root = ""
    try:
        windows_root = os.path.abspath(os.environ.get("SystemRoot") or r"C:\Windows").lower()
    except Exception:
        windows_root = r"c:\windows"
    try:
        psapi = ctypes.windll.psapi
        kernel32 = ctypes.windll.kernel32
        process_ids = (ctypes.wintypes.DWORD * 4096)()
        needed = ctypes.wintypes.DWORD()
        if not psapi.EnumProcesses(ctypes.byref(process_ids), ctypes.sizeof(process_ids), ctypes.byref(needed)):
            return modules
        count = needed.value // ctypes.sizeof(ctypes.wintypes.DWORD)
        for index in range(count):
            pid = process_ids[index]
            if not pid:
                continue
            handle = kernel32.OpenProcess(0x0410, False, pid)
            if not handle:
                continue
            try:
                module_array = (ctypes.wintypes.HMODULE * 1024)()
                needed_bytes = ctypes.wintypes.DWORD()
                if not psapi.EnumProcessModules(handle, ctypes.byref(module_array), ctypes.sizeof(module_array), ctypes.byref(needed_bytes)):
                    continue
                total = min(needed_bytes.value // ctypes.sizeof(ctypes.wintypes.HMODULE), 1024)
                for position in range(total):
                    buffer = ctypes.create_unicode_buffer(1024)
                    if psapi.GetModuleFileNameExW(handle, module_array[position], buffer, ctypes.sizeof(buffer)):
                        path = buffer.value
                        if path and not path.lower().startswith(windows_root):
                            modules.add(path)
            except Exception:
                pass
            finally:
                kernel32.CloseHandle(handle)
    except Exception:
        pass
    return modules


def fixed_drives():
    drives = []
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for index in range(26):
            if not (mask >> index) & 1:
                continue
            root = "{}:\\".format(chr(ord("A") + index))
            if ctypes.windll.kernel32.GetDriveTypeW(root) == 3:
                drives.append(root)
    except Exception:
        pass
    return drives


def loud_directories():
    targets = []
    profile = user_directory("USERPROFILE")
    local = user_directory("LOCALAPPDATA")
    roaming = user_directory("APPDATA")
    program_data = user_directory("PROGRAMDATA")
    for path in (
        os.path.join(profile, "Desktop"),
        os.path.join(profile, "Downloads"),
        os.path.join(profile, "Documents"),
        local,
        os.path.join(local, "Temp"),
        roaming,
        program_data,
        os.path.join(profile, "AppData", "Local", "Programs"),
    ):
        if path and os.path.isdir(path):
            targets.append(path)
    return targets


def plan_smart_scan():
    roots = loud_directories()
    files = set()
    for path in sorted(running_process_images()):
        if os.path.isfile(path):
            files.add(path)
    modules = running_process_modules()
    for path in sorted(modules):
        if os.path.isfile(path):
            files.add(path)
    return {"mode": MODE_SMART, "roots": roots, "seeds": sorted(files), "max_depth": SMART_SCAN_MAX_DEPTH}


def plan_full_scan():
    return {"mode": MODE_FULL, "roots": fixed_drives(), "seeds": [], "max_depth": FULL_SCAN_MAX_DEPTH}


def plan_custom_scan(target):
    if not target:
        return {"error": "未指定扫描目标"}
    if os.path.isfile(target):
        return {"mode": MODE_CUSTOM, "roots": [], "seeds": [target], "max_depth": 0}
    if os.path.isdir(target):
        return {"mode": MODE_CUSTOM, "roots": [target], "seeds": [], "max_depth": CUSTOM_SCAN_MAX_DEPTH}
    return {"error": "扫描目标不存在：{}".format(target)}


def build_plan(mode, target=""):
    if mode == MODE_FULL:
        return plan_full_scan()
    if mode in (MODE_CUSTOM, MODE_CUSTOM_FILE, MODE_CUSTOM_DIR):
        return plan_custom_scan(target)
    return plan_smart_scan()

########################################文件筛选########################################


def magic_is_pe(path):
    try:
        with open(path, "rb") as handle:
            return handle.read(MAGIC_READ_BYTES) == b"MZ"
    except Exception:
        return False


def should_scan_file(path, options=None):
    options = options or {}
    if options.get("all_files"):
        return True
    name = os.path.basename(path)
    extension = os.path.splitext(name)[1].lower()
    if extension in SKIP_EXTENSIONS:
        return False
    if extension in EXECUTABLE_EXTENSIONS:
        return True
    return magic_is_pe(path)


def should_skip_directory(path):
    name = os.path.basename(path).lower()
    if name in SKIP_DIRECTORY_NAMES:
        return True
    try:
        if os.path.islink(path):
            return True
    except Exception:
        pass
    return False


def iter_planned_files(plan, should_stop=None):
    for seed in plan.get("seeds") or []:
        if should_stop and should_stop():
            return
        yield seed
    max_depth = plan.get("max_depth")
    for root in plan.get("roots") or []:
        if should_stop and should_stop():
            return
        base_depth = os.path.abspath(root).rstrip(os.sep).count(os.sep)
        for current, directories, names in os.walk(root, topdown=True):
            if should_stop and should_stop():
                return
            if max_depth:
                depth = os.path.abspath(current).rstrip(os.sep).count(os.sep) - base_depth
                if depth >= max_depth:
                    directories[:] = []
            directories[:] = [item for item in directories if not should_skip_directory(os.path.join(current, item))]
            for name in names:
                if should_stop and should_stop():
                    return
                yield os.path.join(current, name)

########################################扫描执行########################################


def _detect_file_type(path):
    """轻量文件类型识别：先看魔数，再按扩展名兜底，用于扫描结果展示。

    返回短码：PE / ELF / MACHO / PY / JS / VBS / PS / BAT / SH / JAR /
    DOC / XLS / PPT / PDF / ZIP / RAR / 7Z / GZ / HTML / JSON / TXT / LNK / FILE
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(4)
    except Exception:
        head = b""
    if head[:2] == b"MZ":
        return "PE"
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return "MACHO"
    ext = os.path.splitext(path)[1].lower()
    table = {
        ".exe": "PE", ".dll": "PE", ".sys": "PE", ".scr": "PE", ".com": "PE", ".cpl": "PE",
        ".py": "PY", ".pyw": "PY", ".js": "JS", ".vbs": "VBS", ".ps1": "PS",
        ".bat": "BAT", ".cmd": "BAT", ".sh": "SH", ".jar": "JAR",
        ".doc": "DOC", ".docx": "DOC", ".xls": "XLS", ".xlsx": "XLS",
        ".ppt": "PPT", ".pptx": "PPT",
        ".pdf": "PDF", ".zip": "ZIP", ".rar": "RAR", ".7z": "7Z", ".gz": "GZ",
        ".html": "HTML", ".htm": "HTML", ".json": "JSON",
        ".txt": "TXT", ".lnk": "LNK",
    }
    return table.get(ext, "FILE")


def _detection_payload(path, result, mode):
    layer = int(result.get("layer") or 0)
    label = DETECTION_LABELS.get(layer) or "Threat"
    detail = result.get("detail") or {}
    if layer == 2:
        hit = detail.get("hashdb") or {}
        label = "HashDB.{}".format(hit.get("type") or "match")
    elif layer == 3:
        matches = detail.get("yara") or []
        if matches:
            label = "YARA.{}".format(matches[0].get("rule") or "")
    confidence = result.get("score")
    if confidence is None:
        confidence = 1.0
    return {
        "path": path,
        "mode": mode,
        "file_type": _detect_file_type(path),
        "malicious": True,
        "label": label,
        "confidence": round(float(confidence), 6),
        "layer": layer,
        "reason": result.get("reason") or "",
    }


def _record_detection(payload):
    with _DETECTIONS_LOCK:
        _DETECTIONS[payload["path"]] = payload


def detection_list():
    with _DETECTIONS_LOCK:
        return list(_DETECTIONS.values())


_ENGINE_MODULE = None
_ENGINE_LOCK = threading.RLock()


def engine_module():
    global _ENGINE_MODULE
    with _ENGINE_LOCK:
        if _ENGINE_MODULE is None:
            try:
                _ENGINE_MODULE = __import__("Dragon_Engine")
            except Exception:
                return None
        return _ENGINE_MODULE


def _scan_worker(path):
    module = engine_module()
    if module is None:
        return None
    try:
        return module.scan_file(path)
    except Exception:
        return None


########################################扫描去重########################################


def _file_sha256(path):
    if SCAN_DEDUP_MAX_BYTES and os.path.getsize(path) > SCAN_DEDUP_MAX_BYTES:
        return ""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return ""


def _run_scan(plan, mode, stop_event):
    started = time.time()
    scanned = 0
    found = 0
    last_push = 0.0
    pool = ThreadPoolExecutor(max_workers=SCAN_POOL_WORKERS, thread_name_prefix="dragon-scan")
    futures = []
    seen_hashes = set()
    seen_paths = set()
    deduped = 0
    try:
        for path in iter_planned_files(plan, should_stop=lambda: stop_event.is_set()):
            if stop_event.is_set():
                break
            if not os.path.isfile(path):
                continue
            if not should_scan_file(path, plan.get("options")):
                continue
            real = os.path.realpath(path)
            if real in seen_paths:
                deduped += 1
                continue
            digest = _file_sha256(path) if SCAN_DEDUP else ""
            if digest:
                if digest in seen_hashes:
                    deduped += 1
                    continue
                seen_hashes.add(digest)
            seen_paths.add(real)
            futures.append(pool.submit(_scan_worker, path))
            if len(futures) >= PLAN_BATCH:
                scanned, found, last_push = _drain(futures, mode, scanned, found, last_push, started)
                futures = []
        if futures:
            scanned, found, last_push = _drain(futures, mode, scanned, found, last_push, started)
    finally:
        pool.shutdown(wait=True)
    elapsed = round(time.time() - started, 2)
    with _STATE_LOCK:
        _STATE["running"] = False
        _STATE["scanned"] = scanned
        _STATE["total"] = scanned
        _STATE["found"] = found
        _STATE["finished_at"] = time.time()
    push_frontend("scan_stat", {"scanned": scanned, "total": scanned, "found": found, "secs": elapsed})
    push_frontend("scan_done", {"scanned": scanned, "total": scanned, "found": found, "secs": elapsed,
                                "deduped": deduped, "stopped": bool(stop_event.is_set()), "mode": mode})
    push_frontend("scan_state", {
        "stage": "done",
        "title": "病毒扫描",
        "desc": "扫描完成：扫描 {} 个文件，发现 {} 个风险".format(scanned, found),
    })
    报告明细 = "扫描 {} 个文件（去重跳过 {} 个），检测到 {} 个风险".format(scanned, deduped, found)
    safe_log("扫描报告", "{}：{}".format(mode, 报告明细), "发现威胁" if found else "未发现威胁")
    toast("扫描报告", "{}：{}".format(mode, 报告明细))
    scan_log("scan.done", "{} 模式={} 扫描={} 去重={} 发现={} 用时={}s".format(
        plan.get("mode"), mode, scanned, deduped, found, elapsed))
    return {"scanned": scanned, "found": found, "elapsed": elapsed}


def _drain(futures, mode, scanned, found, last_push, started):
    for future in futures:
        try:
            result = future.result()
        except Exception:
            result = None
        scanned += 1
        if result and result.get("verdict") == "malicious":
            found += 1
            payload = _detection_payload(result.get("path"), result, mode)
            _record_detection(payload)
            push_frontend("scan_item", payload)
            safe_log("扫描拦截", "{}｜{}".format(payload["path"], payload["reason"]), "已处理")
            toast("扫描拦截", "{}｜{}".format(payload["path"], payload["reason"]))
        now = time.time()
        if now - last_push >= STAT_PUSH_INTERVAL:
            last_push = now
            with _STATE_LOCK:
                _STATE["scanned"] = scanned
                _STATE["total"] = scanned
                _STATE["found"] = found
            push_frontend("scan_stat", {
                "scanned": scanned,
                "total": scanned,
                "found": found,
                "secs": round(now - started, 2),
            })
    return scanned, found, last_push

########################################扫描入口########################################


def prepare_engine():
    module = engine_module()
    if module is None:
        return {"ready": False, "error": "引擎模块未接入"}
    try:
        status = module.engine_prepare()
    except Exception as exc:
        return {"ready": False, "error": str(exc)}
    layers = status.get("layers") or []
    pending = [str(item.get("title")) for item in layers if not item.get("ready")]
    if pending:
        scan_log("engine.partial", "未就绪层：{}".format("、".join(pending)))
    return {"ready": not pending, "pending": pending, "status": status}


def dragon_scan_start(mode, target="", push=None):
    with _STATE_LOCK:
        if _STATE["running"]:
            return {"ok": False, "error": "已有扫描任务正在执行"}
    if push is not None:
        dragon_set_push(push)
    if not mode:
        mode = MODE_SMART
    if mode not in SCAN_MODES:
        return {"ok": False, "error": "未知扫描模式：{}".format(mode)}
    readiness = prepare_engine()
    if not readiness.get("ready") and readiness.get("pending"):
        scan_log("scan.prepare", "引擎部分层未就绪：{}".format("、".join(readiness["pending"])))
    plan = build_plan(mode, target)
    if plan.get("error"):
        return {"ok": False, "error": plan["error"]}
    if not plan.get("roots") and not plan.get("seeds"):
        return {"ok": False, "error": "没有可扫描的目标目录"}
    stop_event = threading.Event()
    with _STATE_LOCK:
        _STATE["running"] = True
        _STATE["mode"] = mode
        _STATE["target"] = target or "、".join(plan.get("roots") or [])
        _STATE["scanned"] = 0
        _STATE["total"] = 0
        _STATE["found"] = 0
        _STATE["started_at"] = time.time()
        _STATE["finished_at"] = 0.0
        _STATE["stop"] = stop_event
    description = "正在扫描：{}".format(target or "、".join(plan.get("roots") or []))
    push_frontend("scan_state", {"stage": "running", "title": "正在扫描", "desc": description})
    push_frontend("scan_stat", {"scanned": 0, "total": 0, "found": 0, "secs": 0})
    with _STATE_LOCK:
        resolved_target = _STATE["target"]
    scan_log("scan.start", "{} 目标={}".format(mode, resolved_target))
    threading.Thread(target=_run_scan, args=(plan, mode, stop_event), name="dragon-scan-main", daemon=True).start()
    return {"ok": True, "mode": mode, "target": resolved_target, "roots": len(plan.get("roots") or []),
            "seeds": len(plan.get("seeds") or [])}


def dragon_scan_once(target):
    """执行一次无界面扫描，供 Windows 右键菜单调用。"""
    target = os.path.abspath(os.path.expandvars(str(target or "").strip().strip('"')))
    if not target:
        return {"ok": False, "error": "未指定扫描目标"}
    mode = MODE_CUSTOM_FILE if os.path.isfile(target) else MODE_CUSTOM_DIR
    readiness = prepare_engine()
    if not readiness.get("ready") and readiness.get("pending"):
        scan_log("context.prepare", "引擎部分层未就绪：{}".format("、".join(readiness["pending"])))
    plan = build_plan(mode, target)
    if plan.get("error"):
        return {"ok": False, "error": plan["error"]}
    if not plan.get("roots") and not plan.get("seeds"):
        return {"ok": False, "error": "没有可扫描的目标"}
    result = _run_scan(plan, "右键扫描", threading.Event())
    return {"ok": True, "target": target, **(result or {})}


def dragon_scan_stop():
    with _STATE_LOCK:
        stop_event = _STATE.get("stop")
    if stop_event is None:
        return {"ok": True, "stopped": False}
    stop_event.set()
    scan_log("scan.stop", "收到停止请求")
    return {"ok": True, "stopped": True}

########################################结果处理########################################


def _is_known_detection(path):
    with _DETECTIONS_LOCK:
        return path in _DETECTIONS


def _quarantine_one(path):
    try:
        module = __import__("Dragon_Tools")
        function = getattr(module, "quarantine_add", None)
        if callable(function):
            return function(path)
    except Exception:
        pass
    return {"ok": False, "error": "隔离区不可用"}


def _trusted_one(path):
    try:
        module = __import__("Dragon_Tools")
        function = getattr(module, "trusted_add", None)
        if callable(function):
            return function(path)
    except Exception:
        pass
    return {"ok": False, "error": "信任区不可用"}


def dragon_scan_handle(action, paths):
    if not paths:
        return {"ok": False, "error": "没有选中任何项目"}
    paths = [str(item) for item in paths if item]
    handled = 0
    errors = []
    if action == "delete":
        for path in paths:
            if not _is_known_detection(path):
                errors.append("{} 不在本次扫描的威胁列表中，已跳过".format(os.path.basename(path)))
                continue
            result = _quarantine_one(path)
            if result.get("ok"):
                handled += 1
            else:
                errors.append("{}：{}".format(os.path.basename(path), result.get("error") or "删除失败"))
        if handled:
            safe_log("删除威胁", "已将 {} 个项目移入隔离区并清除原文件".format(handled), "已处理")
            toast("删除威胁", "已将 {} 个项目移入隔离区并清除原文件".format(handled))
    elif action == "ignore":
        handled = len(paths)
        safe_log("忽略威胁", "本次扫描忽略 {} 个项目".format(handled), "已忽略")
        toast("忽略威胁", "本次扫描忽略 {} 个项目".format(handled))
    elif action == "quarantine":
        for path in paths:
            result = _quarantine_one(path)
            if result.get("ok"):
                handled += 1
            else:
                errors.append("{}：{}".format(os.path.basename(path), result.get("error") or "隔离失败"))
        if handled:
            safe_log("加入隔离区", "已隔离 {} 个项目".format(handled), "已隔离")
            toast("加入隔离区", "已隔离 {} 个项目".format(handled))
    elif action == "trusted":
        for path in paths:
            result = _trusted_one(path)
            if result.get("ok"):
                handled += 1
            else:
                errors.append("{}：{}".format(os.path.basename(path), result.get("error") or "加入白名单失败"))
        if handled:
            safe_log("加入白名单", "已信任 {} 个项目".format(handled), "已处理")
            toast("加入白名单", "已信任 {} 个项目".format(handled))
    else:
        return {"ok": False, "error": "未知处理动作：{}".format(action)}
    return {"ok": True, "action": action, "count": handled, "errors": errors}


def dragon_scan_status():
    snapshot = scan_status()
    snapshot["detections"] = detection_list()
    snapshot["ok"] = True
    return snapshot


def dragon_scan_detections():
    return {"ok": True, "items": detection_list(), "count": len(detection_list())}


def dragon_scan_clear():
    with _DETECTIONS_LOCK:
        _DETECTIONS.clear()
    return {"ok": True}


if __name__ == "__main__":
    print(json.dumps({
        "smart_roots": plan_smart_scan()["roots"],
        "smart_seeds": len(plan_smart_scan()["seeds"]),
        "drives": plan_full_scan()["roots"],
        "status": scan_status(),
    }, ensure_ascii=False, indent=1))
