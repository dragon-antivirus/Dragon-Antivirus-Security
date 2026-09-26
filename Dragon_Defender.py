# -*- coding: utf-8 -*-
"""天龙神盾安全中心 —— 主动防御模块。

负责九大防护面：进程 / 文件 / 注册表 / 引导区 / 自保护 / 网络监控 / 内存扫描 /
压缩包标记 / 勒索诱捕；另含静态扫描与驱动接入位。所有规则硬编码，clean-room 自写。
"""

import ctypes
import ctypes.wintypes
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import threading
import time
import winreg
from concurrent.futures import ThreadPoolExecutor
import Dragon_Tools as T
from Dragon_Tools import toast

########################################常量与路径########################################

# 冻结态（onefile）下 Python 模块被解包到 sys._MEIPASS 临时目录，但运行期所有外部资源
#（Dragon_VirusDB / Dragon_CoreRules / Dragon_AIModels / Dragon-Drivers / Data）都位于 exe
# 同级目录。受保护文件快照/还原、驱动规则/工具路径都必须指向 exe 目录，否则会解析到
# 只读临时目录而失效。故 BASE_DIR 在冻结态取 exe 所在目录（与 _RUNTIME_BASE_DIR 一致）。
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
    _RUNTIME_BASE_DIR = BASE_DIR
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    _RUNTIME_BASE_DIR = BASE_DIR
from dragon_paths import data_root
DATA_DIR = data_root()  # 持久化根：%LOCALAPPDATA%\天龙神盾\Data，重建/重启不丢失
QUARANTINE_DIR = os.path.join(DATA_DIR, "Quarantine")
BASELINE_DIR = os.path.join(DATA_DIR, "baseline")
BOOT_BACKUP_DIR = os.path.join(DATA_DIR, "boot_backup")
ARCHIVE_MARKS_FILE = os.path.join(DATA_DIR, "archive_marks.json")
REG_BACKUP_FILE = os.path.join(DATA_DIR, "registry_backup.json")
DISABLED_STARTUP_FILE = os.path.join(DATA_DIR, "disabled_startup.json")
DECOY_MANIFEST_FILE = os.path.join(DATA_DIR, "decoy_manifest.json")
STATIC_SCAN_STATE_FILE = os.path.join(DATA_DIR, "static_scan_state.json")
DEFENDER_LOG_FILE = os.path.join(DATA_DIR, "defender.log")

LEVEL_USERMODE = "userMode"
LEVEL_ENGINESCAN = "engineScan"
LEVEL_REALTIME = "realtime"
LEVEL_KEYPOSITIONS = "keyPositions"
LEVEL_DRIVER = "driver"
LEVEL_STATIC_POLL = "staticPoll"
LEVEL_ALWAYS = "alwaysOn"

ALL_LEVELS = (LEVEL_USERMODE, LEVEL_ENGINESCAN, LEVEL_REALTIME,
              LEVEL_KEYPOSITIONS, LEVEL_DRIVER, LEVEL_STATIC_POLL, LEVEL_ALWAYS)

DEFAULT_LEVELS = {
    LEVEL_USERMODE: True,
    LEVEL_ENGINESCAN: True,
    LEVEL_REALTIME: True,
    LEVEL_KEYPOSITIONS: True,
    LEVEL_DRIVER: False,
    LEVEL_STATIC_POLL: False,
    LEVEL_ALWAYS: True,
}

ATTACK_T1055_DLL = "T1055.001_DLL_Injection"
ATTACK_T1055_PE = "T1055.002_Portable_Executable_Injection"
ATTACK_T1055_APC = "T1055.004_Asynchronous_Procedure_Call"
ATTACK_T1055_THREAD = "T1055.005_Thread_Hijacking"
ATTACK_T1055_HOLLOW = "T1055.012_Process_Hollowing"
ATTACK_T1574_MODULE = "T1574.002_Module_Stomping"

DECOY_COUNT_DOCX = 5
DECOY_COUNT_JPG = 5
DECOY_COUNT_TXT = 5
DECOY_COUNT_DEEP_DOCX = 3
DECOY_COUNT_DEEP_TXT = 3
DECOY_TOTAL = DECOY_COUNT_DOCX + DECOY_COUNT_JPG + DECOY_COUNT_TXT + DECOY_COUNT_DEEP_DOCX + DECOY_COUNT_DEEP_TXT

SUSPEND_TIMEOUT_SEC = 5
PROCESS_POLL_INTERVAL_SEC = 1
FILE_POLL_INTERVAL_SEC = 2
REGISTRY_POLL_INTERVAL_SEC = 3
BOOT_POLL_INTERVAL_SEC = 300
SELF_POLL_INTERVAL_SEC = 60
NET_POLL_INTERVAL_SEC = 30
MEMORY_POLL_INTERVAL_SEC = 60
ARCHIVE_POLL_INTERVAL_SEC = 2
DECOY_POLL_INTERVAL_SEC = 2
STATIC_POLL_INTERVAL_SEC = 300

PROTECTION_POOL_WORKERS = 8
STATIC_SCAN_WORKERS = 2
STATIC_SCAN_MAX_BYTES = 256 * 1024 * 1024

########################################硬编码规则########################################

PROCESS_RULES = {
    "lolbin_parents": {
        "rundll32.exe": ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe",
                         "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                         "mshta.exe", "regsvr32.exe"),
        "mshta.exe": ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
                      "opera.exe", "brave.exe", "safari.exe", "360se.exe",
                      "sogouexplorer.exe", "ucbrowser.exe", "maxthon.exe"),
        "certutil.exe": ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                         "cscript.exe", "rundll32.exe"),
        "regsvr32.exe": (),
        "msbuild.exe": ("cmd.exe", "powershell.exe", "pwsh.exe", "explorer.exe",
                        "winword.exe", "excel.exe"),
        "odbcconf.exe": ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe"),
        "installutil.exe": ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                            "mshta.exe", "rundll32.exe"),
        "msxsl.exe": ("cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe"),
        "cmstp.exe": ("cmd.exe", "powershell.exe", "mshta.exe"),
        "wmic.exe": ("cmd.exe", "powershell.exe", "winword.exe", "excel.exe"),
        "forfiles.exe": ("powershell.exe", "cmd.exe"),
        "pcalua.exe": ("cmd.exe", "powershell.exe", "explorer.exe"),
    },
    "double_extensions": (
        "*.doc.exe", "*.docm.exe", "*.docx.exe", "*.dot.exe", "*.dotm.exe",
        "*.xls.exe", "*.xlsm.exe", "*.xlsx.exe", "*.xla.exe",
        "*.ppt.exe", "*.pptm.exe", "*.pptx.exe",
        "*.pdf.exe", "*.pdf.scr", "*.pdf.com",
        "*.txt.exe", "*.rtf.exe", "*.odt.exe",
        "*.jpg.exe", "*.jpeg.exe", "*.png.exe", "*.bmp.exe", "*.gif.exe",
        "*.svg.exe", "*.webp.exe",
        "*.mp3.exe", "*.mp4.exe", "*.avi.exe", "*.mkv.exe",
        "*.zip.exe", "*.rar.exe", "*.7z.exe", "*.tar.exe", "*.gz.exe",
        "*.html.exe", "*.htm.exe", "*.url.exe", "*.lnk.exe",
    ),
    "temp_exec_dirs": (
        "%TEMP%", "%LOCALAPPDATA%\\Temp", "%APPDATA%\\Microsoft\\Windows\\INetCache",
        "%APPDATA%\\Microsoft\\Windows\\INetCookies",
        "C:\\ProgramData\\", "C:\\Users\\Public\\",
        "C:\\Windows\\Temp\\", "C:\\Temp\\",
    ),
    "miner_implant": (
        "xmrig.exe", "minerd.exe", "minergate.exe", "cpuminer.exe",
        "karspersky.exe", "svhost.exe", "scvhost.exe",
        "winupdate.exe", "system64.exe", "csrs.exe",
    ),
    "whitelist": (
        "System", "Registry", "MemCompression",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "svchost.exe",
        "dwm.exe", "audiodg.exe", "fontdrvhost.exe",
        "ctfmon.exe", "sihost.exe", "RuntimeBroker.exe",
        "SearchIndexer.exe", "WerFault.exe", "WmiPrvSE.exe",
        "taskhostw.exe", "conhost.exe", "dllhost.exe",
        "LsaIso.exe", "spoolsv.exe", "W32Time.exe",
        "Wcmsvc.exe", "WaaSMedicSvc.exe",
    ),
    "whitelist_explorer_blocked": True,
}

FILE_RULES = {
    "ransom_prefixes": (
        "HOW_DECRYPT", "README_DECRYPT", "DECRYPT_INSTRUCTIONS",
        "!README", "_README", "HELP_DECRYPT", "YOUR_FILES",
        "RESTORE_FILES", "READ_ME_FOR_DECRYPT", "DECRYPT_FILES",
        "HOW_TO_DECRYPT", "RECOVERY_INSTRUCTIONS",
    ),
    "ransom_extensions": (
        ".locked", ".encrypted", ".crypto", ".cry", ".zepto",
        ".cerber", ".locky", ".osiris", ".alcatraz", ".actin",
        ".akira", ".phobos", ".djvu", ".stop", ".promorad",
        ".cerber3", ".thor", ".arena", ".harma", ".sage",
        ".coded", ".shadow", ".zzzzz", ".mp3", ".darkness",
        ".dalle", ".wfl", ".lh-97", ".gonnacry", ".corona",
    ),
    "unsigned_large": {
        "dirs": ("%USERPROFILE%\\Downloads", "%TEMP%", "%LOCALAPPDATA%\\Temp"),
        "size_min_bytes": 100000000,
        "age_max_seconds": 86400,
        "must_be_unsigned": True,
    },
    "startup_folders": (
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    ),
}

REG_HIGH_RISK_KEYS = (
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\Debugger"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit"),
    ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"),
    ("HKLM", r"System\CurrentControlSet\Control\Lsa\Authentication Packages"),
    ("HKLM", r"System\CurrentControlSet\Control\Lsa\Notification Packages"),
    ("HKLM", r"System\CurrentControlSet\Control\Lsa\Security Packages"),
    ("HKLM", r"System\CurrentControlSet\Control\Lsa\OSConfig\Security Packages"),
    ("HKLM", r"System\CurrentControlSet\Control\Lsa\Extensions"),
    ("HKLM", r"System\CurrentControlSet\Services\*\ImagePath"),
)

REG_PERSISTENCE_KEYS = (
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjectDelayLoad"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
    ("HKCU", r"Software\Microsoft\Office\*\Outlook\Addins\*"),
    ("HKCU", r"Software\Microsoft\Office\*\Word\Addins\*"),
    ("HKCU", r"Software\Microsoft\Office\*\Excel\Addins\*"),
    ("HKCU", r"Software\Microsoft\Office\*\Powerpoint\Addins\*"),
)

REG_COM_HIJACK_KEYS = (
    ("HKCU", r"Software\Classes\CLSID\*\InprocServer32"),
    ("HKCU", r"Software\Classes\CLSID\*\LocalServer32"),
    ("HKCU", r"Software\Classes\CLSID\*\TreatAs"),
    ("HKCU", r"Software\Classes\CLSID\*\ScriptletURL"),
)

REG_TASK_CACHE_KEYS = (
    ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*"),
)

BOOT_RULES = {
    "check_interval_sec": BOOT_POLL_INTERVAL_SEC,
    "new_proc_window_sec": 60,
    "handle_patterns": (
        r"\\\\.\\PhysicalDrive\d+",
        r"\\\\.\\Harddisk\d+",
        r"\\\\.\\C:",
    ),
    "backup_targets": (
        {"type": "first_1mb", "size": 1048576, "drive": None},
        {"type": "mbr", "size": 512, "drive": 0},
        {"type": "gpt_header", "size": 512, "drive": 0},
        {"type": "gpt_backup", "size": 512, "drive": 0},
        {"type": "vbr_c", "size": 512, "drive": "C"},
    ),
}

SELF_RULES = {
    "protected_files": (
        "Dragon_VirusDB\\malware_hashes.tsv",
        "Dragon_VirusDB\\*.srule",
        "Dragon_CoreRules\\*.yar",
        "Data\\boot_backup\\*",
        "Data\\baseline\\*",
        "Dragon_Drivers\\*.sys",
        "Dragon_Drivers\\Rules\\*.json",
    ),
    "check_interval_sec": SELF_POLL_INTERVAL_SEC,
    "baseline_dir": BASELINE_DIR,
}

NET_RULES = {
    "polling_interval_sec": NET_POLL_INTERVAL_SEC,
    "danger_ports": (
        4444, 1337, 31337, 6667, 9001, 5554, 8888, 1080, 9050,
        12345, 50050, 50389, 161, 1900, 23023, 27374, 31485,
        27017, 6379, 11211, 9200, 5984, 11223, 3389, 1433,
    ),
    "ip_blacklist": (),
    "danger_dirs": (
        "%TEMP%", "%LOCALAPPDATA%\\Temp",
        "C:\\ProgramData\\", "C:\\Users\\Public\\",
        "C:\\Windows\\Temp\\",
    ),
    "unsigned_required": True,
}

MEMORY_RULES = {
    "polling_interval_sec": MEMORY_POLL_INTERVAL_SEC,
    "injection_patterns": (
        {"name": ATTACK_T1055_DLL, "apis": ("OpenProcess", "VirtualAllocEx",
                                            "WriteProcessMemory", "CreateRemoteThread"),
         "min_count": 3},
        {"name": ATTACK_T1055_PE, "apis": ("OpenProcess", "VirtualAllocEx",
                                           "WriteProcessMemory", "NtCreateSection"),
         "min_count": 3},
        {"name": ATTACK_T1055_APC, "apis": ("OpenThread", "QueueUserAPC", "NtTestAlert"),
         "min_count": 2},
        {"name": ATTACK_T1055_THREAD, "apis": ("OpenThread", "SuspendThread",
                                               "SetThreadContext", "ResumeThread"),
         "min_count": 4},
        {"name": ATTACK_T1055_HOLLOW, "apis": ("CreateProcess", "NtUnmapViewOfSection",
                                               "VirtualAllocEx", "WriteProcessMemory",
                                               "SetThreadContext", "ResumeThread"),
         "min_count": 5},
        {"name": ATTACK_T1574_MODULE, "detect": "loaded_dll_from_temp",
         "whitelist_dirs": ("C:\\Windows\\", "C:\\Program Files\\"),
         "danger_dirs": ("%TEMP%", "%LOCALAPPDATA%", "%APPDATA%",
                         "%USERPROFILE%\\Downloads")},
    ),
    "shellcode_patterns": (
        b"MZ\x90\x00\x03",
        b"\xfc\x48\x83\xe4\xf0",
    ),
    "escalate_to_engine": True,
}

ARCHIVE_RULES = {
    "extensions": (".zip", ".7z", ".rar", ".tar", ".gz", ".bz2",
                   ".xz", ".iso", ".cab", ".whl", ".jar", ".war", ".egg"),
    "burst_window_sec": 30,
    "burst_file_count": 3,
    "polling_interval_sec": ARCHIVE_POLL_INTERVAL_SEC,
}

DECOY_RULES = {
    "polling_interval_sec": DECOY_POLL_INTERVAL_SEC,
    "decoy_paths": (
        {"root": "%USERPROFILE%", "subdir": "Documents", "ext": ".docx", "count": DECOY_COUNT_DOCX, "name": "dragon_decoy_doc"},
        {"root": "%USERPROFILE%", "subdir": "Pictures", "ext": ".jpg", "count": DECOY_COUNT_JPG, "name": "dragon_decoy_img"},
        {"root": "%USERPROFILE%", "subdir": "Desktop", "ext": ".txt", "count": DECOY_COUNT_TXT, "name": "dragon_decoy_txt"},
        {"root": "%APPDATA%", "subdir": "Microsoft\\Windows", "ext": ".docx", "count": DECOY_COUNT_DEEP_DOCX, "name": "dragon_decoy_app_doc"},
        {"root": "%LOCALAPPDATA%", "subdir": "", "ext": ".txt", "count": DECOY_COUNT_DEEP_TXT, "name": "dragon_decoy_local_txt"},
    ),
    "baseline_copy": os.path.join(BASELINE_DIR, "decoy"),
    "hidden_attribute": True,
}

STATIC_RULES = {
    "scan_dirs": (
        "%USERPROFILE%\\Desktop", "%USERPROFILE%\\Downloads",
        "%USERPROFILE%\\Documents", "%USERPROFILE%\\Pictures",
        "%TEMP%", "%SystemRoot%\\Temp", "%LOCALAPPDATA%\\Temp",
    ),
    "auto_include_keywords": ("download", "下载"),
    "auto_include_roots": ("%USERPROFILE%", "C:\\"),
    "snapshot_interval_sec": STATIC_POLL_INTERVAL_SEC,
    "realtime_extensions": (".exe", ".dll", ".sys", ".scr", ".com", ".cpl",
                            ".drv", ".ocx", ".msi", ".bat", ".cmd", ".ps1",
                            ".vbs", ".js", ".wsf", ".jar", ".lnk", ".hta",
                            ".iso", ".img", ".vhd"),
    "archive_extensions": (".zip", ".7z", ".rar", ".tar", ".gz", ".iso"),
}

DRIVER_HOOK_NAMES = (
    "_defense_hook_process_event",
    "_defense_hook_image_load",
    "_defense_hook_registry_write",
)

########################################推送与日志########################################

_PUSH_FUNCS = {}
_PUSH_LOCK = threading.RLock()
_LOCK = threading.RLock()
_STATE = {
    "running": False,
    "levels": dict(DEFAULT_LEVELS),
    "events": [],
    "started_at": 0.0,
    "finished_at": 0.0,
    "static_last_run": 0.0,
}


def _register_push(channel, func):
    with _PUSH_LOCK:
        if func is None:
            _PUSH_FUNCS.pop(channel, None)
        else:
            _PUSH_FUNCS[channel] = func
    return {"ok": True}


def _emit_push(channel, payload):
    with _PUSH_LOCK:
        func = _PUSH_FUNCS.get(channel)
    if not func:
        return False
    try:
        func(payload)
        return True
    except Exception:
        return False


def safe_log(event, detail=""):
    try:
        T.safe_log(event, detail or "", "已处理")
    except Exception:
        pass
    defender_log(event, detail)
    return False


_ALERT_LOCK = threading.Lock()
_ALERT_SEEN = {}
ALERT_COOLDOWN_SEC = 600


def alert_once(key, cooldown_sec=ALERT_COOLDOWN_SEC):
    """同一告警键在冷却期内只放行一次，防轮询监控反复弹窗。"""
    now = time.monotonic()
    with _ALERT_LOCK:
        last = _ALERT_SEEN.get(key)
        if last is not None and now - last < cooldown_sec:
            return False
        _ALERT_SEEN[key] = now
        if len(_ALERT_SEEN) > 512:
            expired = [k for k, ts in _ALERT_SEEN.items() if now - ts >= cooldown_sec]
            for k in expired:
                _ALERT_SEEN.pop(k, None)
    return True


def _defense_blocked_file():
    return os.path.join(DATA_DIR, "_blocked_today.json")


_BLOCKED_LOCK = threading.Lock()


def _defense_blocked_load():
    try:
        today = time.strftime("%Y-%m-%d")
        path = _defense_blocked_file()
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("date") == today:
                return int(data.get("count", 0))
    except Exception:
        pass
    return 0


def _defense_blocked_inc():
    """主动防御真实拦截一次：自增当日计数并实时推前端（首页'今日拦截'卡）。

    按日期键每日自动清零，进程重启不丢当天计数。
    """
    today = time.strftime("%Y-%m-%d")
    try:
        path = _defense_blocked_file()
        with _BLOCKED_LOCK:
            count = 0
            try:
                if os.path.isfile(path):
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if data.get("date") == today:
                        count = int(data.get("count", 0))
            except Exception:
                pass
            count += 1
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"date": today, "count": count}, f)
        _emit_push("defense_event", {"kind": "blocked", "count": count})
        return count
    except Exception:
        return 0


def defense_get_blocked():
    return {"ok": True, "date": time.strftime("%Y-%m-%d"), "count": _defense_blocked_load()}


def alert_pair(title, detail, count=True):
    """按用户核心铁律：调用端显式成对调用 safe_log + toast。

    主动防御真实拦截（title 为 '主动防御拦截' 且非白名单放行）会计入'今日拦截'计数。
    """
    safe_log(title, detail)
    toast(title, detail)
    if count and title == "主动防御拦截":
        _defense_blocked_inc()


def _quarantine_notify(title, path, result):
    """隔离动作后的成对播报：标题按来源模块（主动防御拦截 / 静态扫描），如实反映处置结果。"""
    ok = isinstance(result, dict) and result.get("ok")
    if not ok:
        err = (result.get("error") if isinstance(result, dict) else result) or "未知错误"
        alert_pair(title, "{}｜处置失败：{}".format(os.path.basename(path), err))
        return False
    if result.get("pending_reboot"):
        alert_pair(title, "{}｜已隔离（源文件占用，重启后清除）".format(os.path.basename(path)))
    else:
        alert_pair(title, "{}｜已隔离".format(os.path.basename(path)))
    return True


def _monitor_stop(stop_event, thread_attr, timeout=10.0):
    """停止监控线程：置位停止事件并 join，确保开关关闭后线程确定性地退出。"""
    stop_event.set()
    thread = globals().get(thread_attr)
    if thread is not None and thread.is_alive():
        try:
            thread.join(timeout=timeout)
        except Exception:
            pass
    return {"ok": True}


def _monitor_start(stop_event, thread_attr, target, name, args=()):
    """启动监控线程：正确处理"旧线程停止中"的状态，避免误判 already_running。"""
    thread = globals().get(thread_attr)
    if thread is not None and thread.is_alive():
        if not stop_event.is_set():
            return {"ok": True, "already_running": True}
        try:
            thread.join(timeout=2.0)
        except Exception:
            pass
    stop_event.clear()
    new_thread = threading.Thread(target=target, args=args, daemon=True, name=name)
    globals()[thread_attr] = new_thread
    new_thread.start()
    return {"ok": True}


def defender_log(event, detail=""):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        with open(DEFENDER_LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write("{}\t{}\t{}\n".format(ts, event, detail))
    except Exception:
        pass

########################################NtSuspendProcess 包装########################################

_ntdll = None
_NtSuspendProcess = None
_NtResumeProcess = None


def _ensure_ntdll():
    global _ntdll, _NtSuspendProcess, _NtResumeProcess
    if _ntdll is not None:
        return True
    try:
        _ntdll = ctypes.WinDLL("ntdll.dll")
        _NtSuspendProcess = _ntdll.NtSuspendProcess
        _NtSuspendProcess.restype = ctypes.c_long
        _NtSuspendProcess.argtypes = [ctypes.c_void_p]
        _NtResumeProcess = _ntdll.NtResumeProcess
        _NtResumeProcess.restype = ctypes.c_long
        _NtResumeProcess.argtypes = [ctypes.c_void_p]
        return True
    except Exception as exc:
        defender_log("ntdll_load_failed", str(exc))
        return False


def process_suspend(pid):
    if not _ensure_ntdll():
        return False
    try:
        _NtSuspendProcess(ctypes.c_void_p(int(pid)))
        return True
    except Exception as exc:
        defender_log("suspend_failed", "pid={} err={}".format(pid, exc))
        return False


def process_resume(pid):
    if not _ensure_ntdll():
        return False
    try:
        _NtResumeProcess(ctypes.c_void_p(int(pid)))
        return True
    except Exception:
        return False


def process_suspend_with_timeout(pid, timeout_sec, callback):
    """callable callback(pid) -> 'malicious' | 'safe' | 'timeout'.
    Returns callback result string.
    """
    if not process_suspend(pid):
        return "safe"
    deadline = time.monotonic() + timeout_sec
    result = "timeout"
    try:
        result = callback(pid) or "safe"
    except Exception as exc:
        defender_log("suspend_callback_error", "pid={} err={}".format(pid, exc))
        result = "safe"
    if time.monotonic() >= deadline:
        result = "timeout"
    if result == "safe":
        process_resume(pid)
    return result

########################################路径与字符串工具########################################

def expand_user_env(template):
    if template is None:
        return ""
    result = str(template)
    pattern = re.compile(r"%([A-Za-z_][A-Za-z0-9_()]*?)%")
    while True:
        match = pattern.search(result)
        if not match:
            break
        name = match.group(1)
        value = os.environ.get(name, "")
        result = result[:match.start()] + value + result[match.end():]
    return os.path.normpath(result)


def now_text():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def normalize_path(path):
    if not path:
        return ""
    try:
        return os.path.normcase(os.path.normpath(str(path)))
    except Exception:
        return str(path)


def is_self_path(path):
    if not path:
        return False
    norm = normalize_path(path)
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        meipass_norm = normalize_path(meipass)
        if norm == meipass_norm or norm.startswith(meipass_norm + os.sep):
            return True
    if re.search(r"[\\/]_mei\d+[\\/]", norm):
        return True
    if re.search(r"[\\/]Data[\\/]Quarantine[\\/]", norm):
        return True
    base_norm = normalize_path(BASE_DIR)
    if norm == base_norm or norm.startswith(base_norm + os.sep):
        return True
    data_norm = normalize_path(DATA_DIR)
    if norm.startswith(data_norm + os.sep):
        return True
    return False


def file_sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

########################################进程工具########################################

_psapi = None
_kernel32 = None
_debug_privilege_enabled = False


def _enable_debug_privilege_once():
    """启用 SeDebugPrivilege，使本进程能终止受保护/提权的恶意进程。
    进程防护命中恶意进程后 kill_tree 会调用 TerminateProcess；
    若当前令牌缺调试特权，TerminateProcess 返回 ACCESS_DENIED(5)。
    仅在首次接触进程 API 时尝试一次，失败不抛异常（降级为无特权终止）。"""
    global _debug_privilege_enabled
    if _debug_privilege_enabled:
        return True
    _debug_privilege_enabled = True
    try:
        from ctypes import wintypes
        adv = ctypes.windll.advapi32
        k32 = ctypes.windll.kernel32
        TOKEN_ADJUST_PRIVILEGES = 0x20
        TOKEN_QUERY = 0x8
        SE_PRIVILEGE_ENABLED = 0x2

        # 结构必须先于 argtypes 声明（argtypes 引用其指针类型）
        class _LUID(ctypes.Structure):
            _fields_ = [("LowPart", ctypes.c_ulong), ("HighPart", ctypes.c_long)]

        class _TOKEN_PRIVILEGE(ctypes.Structure):
            _fields_ = [
                ("PrivilegeCount", ctypes.c_ulong),
                ("Luid", _LUID),
                ("Attributes", ctypes.c_ulong),
            ]

        # 必须声明 argtypes/restype，否则：
        #  - GetCurrentProcess() 的伪句柄 -1 会被当作 32 位 int 截断，
        #    导致 OpenProcessToken 拿到无效句柄而失败（GetLastError 6）；
        #  - LookupPrivilegeValueW 第 3 参数需为 PLUID（指向 _LUID 的指针），
        #    传 c_void_p 指针会导致调用失败。
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        k32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        k32.OpenProcessToken.restype = wintypes.BOOL
        adv.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(_LUID)]
        adv.LookupPrivilegeValueW.restype = wintypes.BOOL
        adv.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL,
                                              ctypes.POINTER(_TOKEN_PRIVILEGE), wintypes.DWORD,
                                              ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
        adv.AdjustTokenPrivileges.restype = wintypes.BOOL

        token = wintypes.HANDLE()
        if not k32.OpenProcessToken(k32.GetCurrentProcess(),
                                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                    ctypes.byref(token)):
            return False
        luid = _LUID()
        if not adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False
        tp = _TOKEN_PRIVILEGE(1, luid, SE_PRIVILEGE_ENABLED)
        if not adv.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None):
            return False
        # AdjustTokenPrivileges 即便特权不可用也返回 TRUE，需查 GetLastError 确认是否真正生效
        return k32.GetLastError() == 0
    except Exception:
        return False


def _ensure_psapi():
    global _psapi, _kernel32
    if _psapi is not None:
        return True
    try:
        _psapi = ctypes.windll.psapi
        _kernel32 = ctypes.windll.kernel32
        _enable_debug_privilege_once()
        return True
    except Exception:
        return False


def enumerate_process_ids():
    if not _ensure_psapi():
        return []
    try:
        size = ctypes.sizeof(ctypes.wintypes.DWORD) * 8192
        buffer = (ctypes.wintypes.DWORD * (size // 4))()
        needed = ctypes.wintypes.DWORD()
        if not _psapi.EnumProcesses(ctypes.byref(buffer), size, ctypes.byref(needed)):
            return []
        count = needed.value // ctypes.sizeof(ctypes.wintypes.DWORD)
        return [int(buffer[index]) for index in range(count) if int(buffer[index])]
    except Exception:
        return []


def query_process_image(pid):
    if not _ensure_psapi():
        return ""
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, ctypes.wintypes.DWORD(int(pid)))
    if not handle:
        return ""
    try:
        buffer = ctypes.create_unicode_buffer(1024)
        size = ctypes.wintypes.DWORD(ctypes.sizeof(buffer))
        if _kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value
        return ""
    finally:
        _kernel32.CloseHandle(handle)


def kill_tree(pid, reason=""):
    if not _ensure_psapi():
        return 0
    PROCESS_TERMINATE = 0x0001
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    try:
        children = _collect_descendants(int(pid))
        targets = list(reversed(children)) if children else [int(pid)]
        killed = 0
        for target in targets:
            handle = _kernel32.OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                                           False, ctypes.wintypes.DWORD(int(target)))
            if not handle:
                continue
            try:
                if _kernel32.TerminateProcess(handle, 1):
                    killed += 1
            finally:
                _kernel32.CloseHandle(handle)
        if reason:
            defender_log("kill_tree", "pid={} reason={} killed={}".format(pid, reason, killed))
        return killed
    except Exception as exc:
        defender_log("kill_tree_error", "pid={} err={}".format(pid, exc))
        return 0


def _collect_descendants(root_pid):
    # _build_parent_map 返回 pid -> 父pid；这里反转为 父pid -> [子pid]，否则会迭代 int 崩溃。
    parent_map = _build_parent_map()
    children_map = {}
    for child, parent in parent_map.items():
        children_map.setdefault(parent, []).append(child)
    descendants = []
    stack = [int(root_pid)]
    seen = {int(root_pid)}
    while stack:
        current = stack.pop()
        for child in children_map.get(current, ()):
            if child in seen:
                continue
            seen.add(child)
            descendants.append(child)
            stack.append(child)
    return descendants


_parent_map_cache = {"ts": 0.0, "map": {}}


def _build_parent_map():
    now = time.monotonic()
    if now - _parent_map_cache["ts"] < 1.5:
        return _parent_map_cache["map"]
    if not _ensure_psapi():
        return {}
    pids = enumerate_process_ids()
    mapping = {}
    TH32CS_SNAPPROCESS = 0x00000002
    snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot and snapshot != ctypes.c_void_p(-1).value:
        try:
            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.wintypes.DWORD),
                    ("cntUsage", ctypes.wintypes.DWORD),
                    ("th32ProcessID", ctypes.wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", ctypes.wintypes.DWORD),
                    ("cntThreads", ctypes.wintypes.DWORD),
                    ("th32ParentProcessID", ctypes.wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", ctypes.wintypes.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260),
                ]
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            if _kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                while True:
                    mapping[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                    if not _kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                        break
        finally:
            _kernel32.CloseHandle(snapshot)
    _parent_map_cache["ts"] = now
    _parent_map_cache["map"] = mapping
    return mapping


def get_parent_pid(pid):
    mapping = _build_parent_map()
    return mapping.get(int(pid), 0)


def is_in_whitelist(image_path):
    if not image_path:
        return False
    base = os.path.basename(image_path).lower()
    whitelist = tuple(item.lower() for item in PROCESS_RULES["whitelist"])
    return base in whitelist


def get_process_basename_lower(pid):
    image = query_process_image(pid)
    if not image:
        return ""
    return os.path.basename(image).lower()


########################################公共:依靠引擎扫描########################################

_engine_module = None


def _engine():
    global _engine_module
    if _engine_module is not None:
        return _engine_module
    try:
        import Dragon_Engine as E
        _engine_module = E
        return E
    except Exception as exc:
        defender_log("engine_import_failed", str(exc))
        return None


def engine_scan(path):
    E = _engine()
    if E is None:
        return None
    try:
        return E.scan_file(path)
    except Exception as exc:
        defender_log("engine_scan_error", "{}: {}".format(path, exc))
        return None


def engine_prepare():
    E = _engine()
    if E is None:
        return {"ready": False, "error": "引擎模块未加载"}
    try:
        return E.engine_prepare()
    except Exception as exc:
        return {"ready": False, "error": str(exc)}


########################################公共:依靠工具模块########################################

_tools_module = None


def _tools():
    global _tools_module
    if _tools_module is not None:
        return _tools_module
    try:
        import Dragon_Tools as T
        _tools_module = T
        return T
    except Exception as exc:
        defender_log("tools_import_failed", str(exc))
        return None


def quarantine_add(path):
    T = _tools()
    if T is None:
        return {"error": "工具模块未加载"}
    function = getattr(T, "quarantine_add", None)
    if not function:
        return {"error": "隔离入口不存在"}
    try:
        return function(path)
    except Exception as exc:
        return {"error": str(exc)}


def engine_suspend_and_scan(pid, image_path):
    E = _engine()
    if E is None:
        return "safe"

    def _callback(inner_pid):
        result = engine_scan(image_path)
        if not result or not result.get("ok"):
            return "safe"
        if result.get("verdict") == "malicious":
            return "malicious"
        return "safe"

    return process_suspend_with_timeout(pid, SUSPEND_TIMEOUT_SEC, _callback)

########################################进程防护 PROCESS_GUARD########################################

_DOUBLE_EXT_RE = re.compile(r"\.(?:doc|docm|docx|dot|dotm|xls|xlsm|xlsx|xla|ppt|pptm|pptx|pdf|txt|rtf|odt|jpg|jpeg|png|bmp|gif|svg|webp|mp3|mp4|avi|mkv|zip|rar|7z|tar|gz|html|htm|url|lnk)\.(?:exe|scr|com)$", re.IGNORECASE)


def _match_double_extension(name):
    if not name:
        return None
    base = name.lower()
    if _DOUBLE_EXT_RE.search(base):
        return "double_extension"
    return None


def _match_lolbin_parent(name_lower, parent_lower):
    if not name_lower:
        return None
    parents = PROCESS_RULES["lolbin_parents"].get(name_lower)
    if parents is None:
        return None
    if not parents:
        return "lolbin_{}_suspicious".format(name_lower.rsplit(".", 1)[0])
    if parent_lower and parent_lower in parents:
        return "lolbin_{}_from_{}".format(name_lower.rsplit(".", 1)[0], parent_lower.rsplit(".", 1)[0])
    return None


def _match_temp_exec(image_path):
    if not image_path:
        return None
    norm = normalize_path(image_path)
    for template in PROCESS_RULES["temp_exec_dirs"]:
        candidate = normalize_path(expand_user_env(template))
        if norm == candidate or norm.startswith(candidate + os.sep):
            return "temp_exec_{}".format(os.path.basename(template).strip("%").lower() or "dir")
    return None


def _match_miner(name_lower):
    if name_lower in PROCESS_RULES["miner_implant"]:
        return "miner_implant"
    return None


def match_process_rules(name_lower, image_path, parent_name_lower):
    rule_hit = _match_miner(name_lower)
    if rule_hit:
        return rule_hit
    rule_hit = _match_double_extension(name_lower)
    if rule_hit:
        return rule_hit
    rule_hit = _match_lolbin_parent(name_lower, parent_name_lower)
    if rule_hit:
        return rule_hit
    rule_hit = _match_temp_exec(image_path)
    if rule_hit:
        return rule_hit
    return None


def on_process_event(pid, image_path, parent_pid, parent_image):
    # 总开关关闭后必须立即失效：内核驱动或残留线程触发的进程事件不再扫描/处置，
    # 否则会出现"UI 已关主动防御却仍在弹主动防御拦截"的现象。
    if not _STATE["running"]:
        return
    if is_self_path(image_path):
        return
    if not image_path or not os.path.isfile(image_path):
        return
    name_lower = os.path.basename(image_path or "").lower()
    parent_lower = os.path.basename(parent_image or "").lower()
    if name_lower in PROCESS_RULES["whitelist"]:
        return
    rule_hit = match_process_rules(name_lower, image_path, parent_lower)
    if rule_hit:
        if not alert_once("proc|{}|{}".format(image_path, rule_hit)):
            return
        if T.is_trusted(image_path):
            safe_log("主动防御拦截", "{}｜命中信任白名单，已放行".format(image_path))
            return
        if _STATE["levels"].get(LEVEL_ENGINESCAN):
            verdict = engine_suspend_and_scan(int(pid), image_path)
        else:
            verdict = "malicious"
        if verdict == "malicious":
            kill_tree(int(pid), reason=rule_hit)
            alert_pair("主动防御拦截", "{}｜{}".format(image_path, rule_hit))
        elif verdict == "timeout":
            kill_tree(int(pid), reason="suspend_timeout_5s")
            alert_pair("主动防御拦截", "{}｜suspend超时默认杀".format(image_path))
        return
    if not _STATE["levels"].get(LEVEL_ENGINESCAN):
        return
    if not alert_once("procscan|{}".format(image_path.lower()), cooldown_sec=60):
        return
    verdict = engine_suspend_and_scan(int(pid), image_path)
    if verdict == "malicious":
        if T.is_trusted(image_path):
            safe_log("主动防御拦截", "{}｜命中信任白名单，已放行".format(image_path))
            process_resume(int(pid))
            return
        kill_tree(int(pid), reason="engine_new_process")
        alert_pair("主动防御拦截", "{}｜新进程引擎扫描判毒".format(image_path))
    elif verdict == "timeout":
        process_resume(int(pid))
        defender_log("procscan_timeout", "{} 挂起扫描超时，已放行".format(image_path))


_PROC_THREAD = None
_PROC_STOP = threading.Event()
_PROC_SEEN = set()
_PROC_SEEN_LOCK = threading.Lock()


def protect_proc_thread(stop_event, driver_hook, interval_sec=PROCESS_POLL_INTERVAL_SEC):
    """轮询进程列表检测新进程，交由 on_process_event 处置（对应 PYAS protect_proc_thread + handle_new_process）。
    轮询本身即兜底：任何漏检的新进程会在下一轮被捕获，无需 WMI 事件订阅。"""
    # 启动快照：避免把存量进程当成"新进程"全量扫一遍
    try:
        with _PROC_SEEN_LOCK:
            _PROC_SEEN.update(enumerate_process_ids())
    except Exception:
        pass
    while not stop_event.is_set():
        if not _STATE["running"]:
            break
        try:
            current = enumerate_process_ids()
            parent_map = _build_parent_map()
            new_pids = []
            with _PROC_SEEN_LOCK:
                for pid in current:
                    if pid not in _PROC_SEEN:
                        new_pids.append(pid)
                        _PROC_SEEN.add(pid)
                # 清理已退出进程，防止集合无限增长
                dead = _PROC_SEEN - set(current)
                if dead:
                    _PROC_SEEN.difference_update(dead)
            for pid in new_pids:
                if stop_event.is_set():
                    break
                image = query_process_image(pid)
                parent_pid = parent_map.get(int(pid), 0)
                parent_image = query_process_image(parent_pid) if parent_pid else ""
                if driver_hook:
                    try:
                        driver_hook(pid, image)
                    except Exception:
                        pass
                try:
                    on_process_event(pid, image, parent_pid, parent_image)
                except Exception as exc:
                    defender_log("proc_thread_error", "pid={} err={}".format(pid, exc))
        except Exception as exc:
            defender_log("proc_poll_error", str(exc))
        if stop_event.wait(interval_sec):
            break


def start_process_monitor(driver_hook=None):
    if not _STATE["levels"].get(LEVEL_USERMODE):
        return {"ok": True, "skipped": "userMode_off"}
    return _monitor_start(_PROC_STOP, "_PROC_THREAD", protect_proc_thread,
                          "dragon-process-poll", args=(_PROC_STOP, driver_hook))


def stop_process_monitor():
    return _monitor_stop(_PROC_STOP, "_PROC_THREAD")

########################################文件防护 FILE_GUARD########################################

_REALTIME_EXTS_LOWER = tuple(ext.lower() for ext in STATIC_RULES["realtime_extensions"])
_ARCHIVE_EXTS_LOWER = tuple(ext.lower() for ext in ARCHIVE_RULES["extensions"])


def _match_ransom_prefix(name):
    upper = name.upper()
    for prefix in FILE_RULES["ransom_prefixes"]:
        if upper.startswith(prefix):
            return "ransom_prefix_{}".format(prefix.lower())
    return None


def _match_ransom_extension(name):
    lower = name.lower()
    for ext in FILE_RULES["ransom_extensions"]:
        if lower.endswith(ext):
            return "ransom_ext_{}".format(ext.strip("."))
    return None


def _match_unsigned_large(path):
    if not path:
        return None
    norm = normalize_path(path)
    for template in FILE_RULES["unsigned_large"]["dirs"]:
        candidate = normalize_path(expand_user_env(template))
        if not (norm == candidate or norm.startswith(candidate + os.sep)):
            continue
        try:
            stat = os.stat(path)
        except Exception:
            return None
        if stat.st_size < FILE_RULES["unsigned_large"]["size_min_bytes"]:
            return None
        if (time.time() - stat.st_mtime) > FILE_RULES["unsigned_large"]["age_max_seconds"]:
            return None
        if FILE_RULES["unsigned_large"].get("must_be_unsigned") and not _file_is_unsigned(path):
            return None
        return "unsigned_large_{}".format(os.path.basename(template).strip("%").lower() or "dir")
    return None


def _match_startup_folder(path):
    if not path:
        return None
    norm = normalize_path(path)
    for template in FILE_RULES["startup_folders"]:
        candidate = normalize_path(expand_user_env(template))
        if norm == candidate or norm.startswith(candidate + os.sep):
            return "startup_folder_write"
    return None


def match_file_rules(path, action=""):
    if not path:
        return None
    name = os.path.basename(path)
    rule_hit = _match_ransom_prefix(name)
    if rule_hit:
        return rule_hit
    rule_hit = _match_ransom_extension(name)
    if rule_hit:
        return rule_hit
    rule_hit = _match_unsigned_large(path)
    if rule_hit:
        return rule_hit
    if action.lower() == "created":
        rule_hit = _match_startup_folder(path)
        if rule_hit:
            return rule_hit
    return None


def on_file_event(path, action):
    if not _STATE["running"]:
        return
    if is_self_path(path):
        return
    rule_hit = match_file_rules(path, action)
    if rule_hit:
        if not alert_once("file|{}|{}".format(path, rule_hit)):
            return True
        if rule_hit.startswith("unsigned_large"):
            alert_pair("主动防御拦截", "{}｜{}｜已提示，未隔离".format(path, rule_hit))
            return True
        if T.is_trusted(path):
            safe_log("主动防御拦截", "{}｜命中信任白名单，已放行".format(path))
            toast("主动防御拦截", "{}｜已在白名单，已放行".format(path))
            return True
        result = quarantine_add(path)
        _quarantine_notify("主动防御拦截", path, result)
        return True
    if action.lower() not in ("created", "modified"):
        return False
    if not path.lower().endswith(_REALTIME_EXTS_LOWER):
        return False
    if not alert_once("filescan|{}".format(path.lower()), cooldown_sec=60):
        return False
    result = engine_scan(path)
    if result and result.get("verdict") == "malicious":
        if T.is_trusted(path):
            safe_log("主动防御拦截", "{}｜命中信任白名单，已放行".format(path))
            return False
        qres = quarantine_add(path)
        _quarantine_notify("主动防御拦截", path, qres)
        return True
    return False


_FILE_STATE_FILE = os.path.join(DATA_DIR, "_file_scan_state.json")
_FILE_STATE_LOCK = threading.Lock()
_FILE_STATE = {}


def _load_file_state():
    global _FILE_STATE
    with _FILE_STATE_LOCK:
        if _FILE_STATE:
            return _FILE_STATE
        try:
            with open(_FILE_STATE_FILE, "r", encoding="utf-8") as handle:
                _FILE_STATE = json.load(handle)
        except Exception:
            _FILE_STATE = {}
        return _FILE_STATE


def _save_file_state():
    try:
        with open(_FILE_STATE_FILE, "w", encoding="utf-8") as handle:
            json.dump(_FILE_STATE, handle, ensure_ascii=False)
    except Exception:
        pass


def _iter_candidate_files(roots, extensions, recursive=True):
    for root_template in roots:
        root = expand_user_env(root_template)
        if not root or not os.path.isdir(root):
            continue
        try:
            if recursive:
                for current, _dirs, names in os.walk(root):
                    for name in names:
                        if name.lower().endswith(extensions):
                            yield os.path.join(current, name)
            else:
                for name in os.listdir(root):
                    full = os.path.join(root, name)
                    if os.path.isfile(full) and name.lower().endswith(extensions):
                        yield full
        except Exception:
            continue


def _file_state_signature(path):
    try:
        stat = os.stat(path)
        return (int(stat.st_size), int(stat.st_mtime))
    except Exception:
        return None


def _scan_files_for_changes(roots, extensions, recursive):
    state = _load_file_state()
    changed = []
    for path in _iter_candidate_files(roots, extensions, recursive):
        signature = _file_state_signature(path)
        if signature is None:
            continue
        previous = state.get(path)
        if previous != signature:
            state[path] = signature
            changed.append((path, "modified" if previous else "created"))
    _save_file_state()
    return changed


_FILE_THREAD = None
_FILE_STOP = threading.Event()


def _file_monitor_loop(stop_event):
    while not stop_event.is_set():
        if not _STATE["running"]:
            break
        if _STATE["levels"].get(LEVEL_REALTIME):
            try:
                for root in STATIC_RULES["scan_dirs"]:
                    if stop_event.is_set():
                        break
                    changes = _scan_files_for_changes([root],
                                                      _REALTIME_EXTS_LOWER, recursive=True)
                    for path, action in changes:
                        if stop_event.is_set():
                            break
                        try:
                            on_file_event(path, action)
                        except Exception as exc:
                            defender_log("file_event_error", "{}: {}".format(path, exc))
            except Exception as exc:
                defender_log("file_scan_error", str(exc))
        if stop_event.wait(FILE_POLL_INTERVAL_SEC):
            break


########################################ReadDirectoryChangesW 主监测########################################

_FILE_RDCW_THREADS = []
_FILE_RDCW_STOP = threading.Event()
_RDCW_HANDLES = {}  # root -> 目录句柄；异步 OVERLAPPED 模式下 CancelIoEx 可靠取消
_RDCW_STOP_HEV = None  # 原生事件句柄，用于可靠唤醒 ReadDirectoryChangesW 的等待


class _RDCW_OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", ctypes.c_uint32),
        ("OffsetHigh", ctypes.c_uint32),
        ("hEvent", ctypes.c_void_p),
    ]


def _rdcw_stop_hev():
    global _RDCW_STOP_HEV
    if _RDCW_STOP_HEV is None and _kernel32 is not None:
        try:
            _kernel32.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
            _kernel32.CreateEventW.restype = ctypes.wintypes.HANDLE
            _RDCW_STOP_HEV = _kernel32.CreateEventW(None, 1, 0, None)
        except Exception:
            _RDCW_STOP_HEV = None
    return _RDCW_STOP_HEV


def _rdcw_rebuild(root, old_hdir):
    """溢出/句柄失效时重建目录句柄，并同步更新 _RDCW_HANDLES。"""
    try:
        if _kernel32 is not None:
            _kernel32.CancelIoEx(old_hdir, None)
    except Exception:
        pass
    try:
        if _kernel32 is not None:
            _kernel32.CloseHandle(old_hdir)
    except Exception:
        pass
    nh = _rdcw_open_dir(root)
    if not nh:
        defender_log("rdcw_reopen_failed", root)
        return None
    _RDCW_HANDLES[root] = nh
    return nh


def _rdcw_cancel_io():
    """取消所有 RDCW 目录句柄上挂起的 I/O，使阻塞中的 ReadDirectoryChangesW 立即返回，
    监控线程得以检测到 stop_event 并退出（否则线程会一直阻塞到下次文件变更才检查开关）。"""
    if not _kernel32 or not hasattr(_kernel32, "CancelIoEx"):
        return
    try:
        _kernel32.CancelIoEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p]
        _kernel32.CancelIoEx.restype = ctypes.wintypes.BOOL
    except Exception:
        return
    for h in list(_RDCW_HANDLES.values()):
        try:
            _kernel32.CancelIoEx(h, None)
        except Exception:
            pass

_FILE_LIST_DIRECTORY = 0x0001
_FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
_FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
_FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
_FILE_NOTIFY_CHANGE_SIZE = 0x00000008
_FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_OPEN_EXISTING = 3
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004

_RDCW_ACTION_MAP = {
    1: "created", 2: "removed", 3: "modified", 4: "renamed", 5: "created",
}


def _rdcw_longpath(path):
    try:
        ap = os.path.abspath(path)
    except Exception:
        return path
    if ap.startswith("\\\\?\\"):
        return ap
    return "\\\\?\\" + ap


def _rdcw_open_dir(path):
    try:
        _kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
            ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
            ctypes.wintypes.HANDLE]
        _kernel32.CreateFileW.restype = ctypes.wintypes.HANDLE
        h = _kernel32.CreateFileW(
            _rdcw_longpath(path), _FILE_LIST_DIRECTORY,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            None, _OPEN_EXISTING, _FILE_FLAG_BACKUP_SEMANTICS, None)
        if h is None or h == ctypes.c_void_p(-1).value:
            return None
        return h
    except Exception:
        return None


def _rdcw_parse(buffer, nbytes, root):
    results = []
    data = bytes(buffer[:nbytes])
    pos = 0
    while pos + 12 <= len(data):
        next_off, action, fn_len = struct.unpack_from("<III", data, pos)
        if fn_len <= 0 or pos + 12 + fn_len > len(data):
            break
        fn_bytes = data[pos + 12: pos + 12 + fn_len]
        try:
            name = fn_bytes.decode("utf-16-le", errors="ignore")
        except Exception:
            name = ""
        if name:
            results.append((os.path.join(root, name), _RDCW_ACTION_MAP.get(action, "modified")))
        if next_off == 0:
            break
        pos += next_off
    return results


def _rdcw_watch_loop(root, stop_event):
    """异步（OVERLAPPED）目录变更监控：用原生 stop 事件唤醒 WaitForMultipleObjects，
    关闭时 SetEvent + CancelIoEx 可可靠终止阻塞中的 ReadDirectoryChangesW（同步版 CancelIoEx 不可靠）。"""
    hev = _rdcw_stop_hev()
    hdir = _rdcw_open_dir(root)
    if not hdir:
        defender_log("rdcw_open_failed", root)
        return
    _RDCW_HANDLES[root] = hdir
    try:
        _kernel32.ReadDirectoryChangesW.argtypes = [
            ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD,
            ctypes.wintypes.BOOL, ctypes.wintypes.DWORD,
            ctypes.POINTER(_RDCW_OVERLAPPED), ctypes.c_void_p]
        _kernel32.ReadDirectoryChangesW.restype = ctypes.wintypes.BOOL
        _kernel32.GetOverlappedResult.argtypes = [
            ctypes.wintypes.HANDLE, ctypes.POINTER(_RDCW_OVERLAPPED),
            ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.wintypes.BOOL]
        _kernel32.GetOverlappedResult.restype = ctypes.wintypes.BOOL
        _kernel32.WaitForMultipleObjects.argtypes = [
            ctypes.c_uint32, ctypes.POINTER(ctypes.wintypes.HANDLE),
            ctypes.c_int, ctypes.wintypes.DWORD]
        _kernel32.WaitForMultipleObjects.restype = ctypes.c_uint32
        _kernel32.CancelIoEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p]
        _kernel32.CancelIoEx.restype = ctypes.wintypes.BOOL
        _kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        buf = ctypes.create_string_buffer(65536)
        bytes_ret = ctypes.wintypes.DWORD()
        flt = (_FILE_NOTIFY_CHANGE_FILE_NAME | _FILE_NOTIFY_CHANGE_DIR_NAME |
               _FILE_NOTIFY_CHANGE_ATTRIBUTES | _FILE_NOTIFY_CHANGE_SIZE |
               _FILE_NOTIFY_CHANGE_LAST_WRITE)
        overlapped = _RDCW_OVERLAPPED()
        overlapped.hEvent = _kernel32.CreateEventW(None, 0, 0, None)
        wait_handles = (ctypes.wintypes.HANDLE * 2)()
        wait_handles[0] = hev
        wait_handles[1] = overlapped.hEvent
        WAIT_STOP = 0
        WAIT_IO = 1
        while not stop_event.is_set():
            if not _STATE["running"]:
                break
            bytes_ret.value = 0
            overlapped.Internal = 0
            overlapped.InternalHigh = 0
            overlapped.Offset = 0
            overlapped.OffsetHigh = 0
            rc = _kernel32.ReadDirectoryChangesW(
                hdir, buf, ctypes.wintypes.DWORD(len(buf)), True,
                ctypes.wintypes.DWORD(flt), ctypes.byref(overlapped), None)
            if not rc:
                # 同步发起失败（异步模式罕见）：重建句柄后重试
                nh = _rdcw_rebuild(root, hdir)
                if nh is None:
                    break
                hdir = nh
                _kernel32.ResetEvent(overlapped.hEvent)
                continue
            wres = _kernel32.WaitForMultipleObjects(2, wait_handles, 0, 0xFFFFFFFF)
            if wres == WAIT_STOP or stop_event.is_set():
                _kernel32.CancelIoEx(hdir, ctypes.byref(overlapped))
                break
            # I/O 完成
            if not _kernel32.GetOverlappedResult(hdir, ctypes.byref(overlapped), ctypes.byref(bytes_ret), 0):
                # 溢出/中止：重建监听（同步更新句柄与 _RDCW_HANDLES），漏检由轮询兜底覆盖
                defender_log("rdcw_overflow", root)
                nh = _rdcw_rebuild(root, hdir)
                if nh is None:
                    break
                hdir = nh
                _kernel32.ResetEvent(overlapped.hEvent)
                continue
            n = bytes_ret.value
            if n:
                for path, action in _rdcw_parse(buf, n, root):
                    if stop_event.is_set():
                        break
                    try:
                        on_file_event(path, action)
                    except Exception as exc:
                        defender_log("rdcw_event_error", "{}: {}".format(path, exc))
            _kernel32.ResetEvent(overlapped.hEvent)
    finally:
        try:
            if overlapped.hEvent:
                _kernel32.CloseHandle(overlapped.hEvent)
        except Exception:
            pass
        try:
            _kernel32.CloseHandle(hdir)
        except Exception:
            pass
        _RDCW_HANDLES.pop(root, None)


def _rdcw_is_running():
    """是否已有 RDCW 监控线程在跑（用于去重，避免重复启动叠加线程）。"""
    return any(t.is_alive() for t in _FILE_RDCW_THREADS)


def _start_rdcw_watchers():
    # 复位停止事件与原生唤醒事件（幂等：重复调用不会叠加重复线程）
    _FILE_RDCW_STOP.clear()
    hev = _rdcw_stop_hev()
    if hev is not None:
        _kernel32.ResetEvent(hev)
    # 已在运行：不再重复启动，否则多个 RDCW 线程监听同一目录会造成
    # 重复拦截/重复扫描并泄漏目录句柄——正是"开关玄学"的隐患之一。
    if _rdcw_is_running():
        return {"ok": True, "already_running": True}
    roots = []
    for template in STATIC_RULES["scan_dirs"]:
        root = expand_user_env(template)
        if root and os.path.isdir(root):
            roots.append(root)
    if not roots:
        return {"ok": True, "skipped": "no_scan_dirs"}
    for root in roots:
        t = threading.Thread(target=_rdcw_watch_loop, args=(root, _FILE_RDCW_STOP),
                             daemon=True, name="dragon-rdcw")
        _FILE_RDCW_THREADS.append(t)
        t.start()
    return {"ok": True, "watchers": len(roots)}


def _stop_rdcw_watchers():
    _FILE_RDCW_STOP.set()
    hev = _rdcw_stop_hev()
    if hev is not None:
        _kernel32.SetEvent(hev)  # 唤醒 WaitForMultipleObjects，使其立即检查 stop
    _rdcw_cancel_io()  # 取消仍可能 pending 的异步 I/O（OVERLAPPED 模式下可靠）
    for t in _FILE_RDCW_THREADS:
        try:
            t.join(timeout=3.0)
        except Exception:
            pass
    _FILE_RDCW_THREADS.clear()
    _RDCW_HANDLES.clear()
    if hev is not None:
        _kernel32.ResetEvent(hev)
    return {"ok": True}


def start_file_monitor():
    if not _STATE["levels"].get(LEVEL_REALTIME):
        return {"ok": True, "skipped": "realtime_off"}
    rdcw = _start_rdcw_watchers()  # 主：内核级目录变更通知
    poll = _monitor_start(_FILE_STOP, "_FILE_THREAD", _file_monitor_loop,
                          "dragon-file-monitor", args=(_FILE_STOP,))  # 兜底：轮询
    return {"ok": rdcw.get("ok", False) and poll.get("ok", False),
            "rdcw": rdcw, "poll": poll}


def stop_file_monitor():
    _stop_rdcw_watchers()
    return _monitor_stop(_FILE_STOP, "_FILE_THREAD")

########################################注册表防护 REG_GUARD########################################

_HIVE_MAP = {
    "HKLM": (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
    "HKCU": (winreg.HKEY_CURRENT_USER, "HKCU"),
    "HKCR": (winreg.HKEY_CLASSES_ROOT, "HKCR"),
}


def _open_key(hive_name, subkey):
    info = _HIVE_MAP.get(hive_name)
    if info is None:
        return None
    hive, _label = info
    try:
        return winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _iter_persistence_keys():
    for hive_name, pattern in REG_PERSISTENCE_KEYS:
        try:
            hive, _ = _HIVE_MAP[hive_name]
        except KeyError:
            continue
        base_match = re.sub(r"\\\*$", "", pattern)
        try:
            key = winreg.OpenKey(hive, base_match, 0, winreg.KEY_READ)
        except FileNotFoundError:
            continue
        except Exception:
            continue
        try:
            values = []
            index = 0
            while True:
                try:
                    name, value, _type = winreg.EnumValue(key, index)
                except OSError:
                    break
                values.append((name, value))
                index += 1
            yield hive_name, base_match, values
        finally:
            winreg.CloseKey(key)


def _read_key_values(hive_name, subkey):
    info = _HIVE_MAP.get(hive_name)
    if info is None:
        return []
    hive, _ = info
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return []
    except Exception:
        return []
    collected = []
    try:
        index = 0
        while True:
            try:
                name, value, _type = winreg.EnumValue(key, index)
            except OSError:
                break
            collected.append((name, value))
            index += 1
    finally:
        winreg.CloseKey(key)
    return collected


def _write_registry_value(hive_name, subkey, value_name, value, kind=winreg.REG_SZ):
    info = _HIVE_MAP.get(hive_name)
    if info is None:
        return False
    hive, _ = info
    try:
        key = winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
    except Exception:
        return False
    try:
        winreg.SetValueEx(key, value_name, 0, kind, value)
        return True
    except Exception:
        return False
    finally:
        winreg.CloseKey(key)


def _delete_registry_value(hive_name, subkey, value_name):
    info = _HIVE_MAP.get(hive_name)
    if info is None:
        return False
    hive, _ = info
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
    except Exception:
        return False
    try:
        winreg.DeleteValue(key, value_name)
        return True
    except FileNotFoundError:
        return True
    except Exception:
        return False
    finally:
        winreg.CloseKey(key)


def _load_registry_backup():
    try:
        with open(REG_BACKUP_FILE, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def _save_registry_backup(backup):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(REG_BACKUP_FILE, "w", encoding="utf-8") as handle:
            json.dump(backup, handle, ensure_ascii=False, indent=1)
    except Exception as exc:
        defender_log("registry_backup_save_failed", str(exc))


def _append_disabled_startup(entry):
    data = []
    try:
        with open(DISABLED_STARTUP_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        data = []
    data.append(entry)
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(DISABLED_STARTUP_FILE, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=1)
    except Exception as exc:
        defender_log("disabled_startup_save_failed", str(exc))


def on_registry_change(hive_name, subkey, value_name, new_value, source_pid):
    if not _STATE["running"]:
        return
    high_risk_patterns = {item[1]: item for item in REG_HIGH_RISK_KEYS}
    persistence_patterns = {item[1]: item for item in REG_PERSISTENCE_KEYS}
    backup = _load_registry_backup()
    if subkey in high_risk_patterns:
        backup_key = "{}\\{}\\{}".format(hive_name, subkey, value_name)
        original = backup.get(backup_key)
        if original is not None:
            _write_registry_value(hive_name, subkey, value_name, original["value"], original.get("kind", winreg.REG_SZ))
            message = "高危键回滚"
        else:
            _delete_registry_value(hive_name, subkey, value_name)
            message = "高危键删除"
        if source_pid:
            kill_tree(source_pid, reason="registry_high_risk_rollback")
        alert_pair("主动防御拦截", "{}|{}|{}｜{}".format(hive_name, subkey, value_name, message))
        return
    if subkey in persistence_patterns:
        _delete_registry_value(hive_name, subkey, value_name)
        _append_disabled_startup({
            "hive": hive_name, "subkey": subkey, "value_name": value_name,
            "value": new_value, "removed_at": now_text(),
        })
        if source_pid:
            kill_tree(source_pid, reason="registry_persistence_removed")
        alert_pair("主动防御拦截", "{}|{}|{}｜自启动项已禁用".format(hive_name, subkey, value_name))


def snapshot_registry_state():
    """扫描所有持久化键与高危键，返回当前值快照。

    Returns a dict ``{(hive, subkey, value_name): {"value": ..., "kind": int}}``.
    """
    snapshot = {}
    for hive_name, pattern in REG_PERSISTENCE_KEYS + REG_HIGH_RISK_KEYS:
        base_match = re.sub(r"\\\*$", "", pattern)
        values = _read_key_values(hive_name, base_match)
        for name, value in values:
            snapshot[(hive_name, base_match, name)] = {"value": value, "kind": winreg.REG_SZ}
    return snapshot


_REGISTRY_THREAD = None
_REGISTRY_STOP = threading.Event()
_REGISTRY_LAST_SNAPSHOT = {}
_REGISTRY_DRIVER_HOOK = None


def _registry_loop(stop_event):
    global _REGISTRY_LAST_SNAPSHOT
    _REGISTRY_LAST_SNAPSHOT = snapshot_registry_state()
    while not stop_event.is_set():
        if not _STATE["running"]:
            break
        if _STATE["levels"].get(LEVEL_KEYPOSITIONS):
            try:
                current = snapshot_registry_state()
            except Exception as exc:
                defender_log("registry_snapshot_error", str(exc))
                current = {}
            added = set(current.keys()) - set(_REGISTRY_LAST_SNAPSHOT.keys())
            removed = set(_REGISTRY_LAST_SNAPSHOT.keys()) - set(current.keys())
            changed = set()
            for key in current.keys() & _REGISTRY_LAST_SNAPSHOT.keys():
                if current[key] != _REGISTRY_LAST_SNAPSHOT[key]:
                    changed.add(key)
            for hive_name, subkey, value_name in added | changed:
                if _REGISTRY_DRIVER_HOOK:
                    try:
                        _REGISTRY_DRIVER_HOOK(hive_name, subkey, value_name)
                    except Exception:
                        pass
                new_value = current[(hive_name, subkey, value_name)].get("value")
                on_registry_change(hive_name, subkey, value_name, new_value, source_pid=0)
            for hive_name, subkey, value_name in removed:
                if _REGISTRY_DRIVER_HOOK:
                    try:
                        _REGISTRY_DRIVER_HOOK(hive_name, subkey, value_name)
                    except Exception:
                        pass
                on_registry_change(hive_name, subkey, value_name, None, source_pid=0)
            _REGISTRY_LAST_SNAPSHOT = current
        if stop_event.wait(REGISTRY_POLL_INTERVAL_SEC):
            break


def start_registry_monitor(driver_hook=None):
    global _REGISTRY_DRIVER_HOOK
    _REGISTRY_DRIVER_HOOK = driver_hook
    return _monitor_start(_REGISTRY_STOP, "_REGISTRY_THREAD", _registry_loop,
                          "dragon-registry-monitor", args=(_REGISTRY_STOP,))


def stop_registry_monitor():
    return _monitor_stop(_REGISTRY_STOP, "_REGISTRY_THREAD")

########################################引导区防护 BOOT_GUARD########################################

_kernel32_full = None


def _ensure_kernel32_full():
    global _kernel32_full
    if _kernel32_full is not None:
        return _kernel32_full
    try:
        _kernel32_full = ctypes.windll.kernel32
        return _kernel32_full
    except Exception as exc:
        defender_log("kernel32_load_failed", str(exc))
        return None


def _read_physical(disk_index, offset, size):
    k32 = _ensure_kernel32_full()
    if k32 is None:
        return None
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    path = "\\\\.\\PhysicalDrive{}".format(disk_index)
    handle = k32.CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             None, OPEN_EXISTING, 0, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        return None
    try:
        k32.SetFilePointer(handle, offset, None, 0)
        buffer = (ctypes.c_ubyte * size)()
        read = ctypes.wintypes.DWORD()
        if not k32.ReadFile(handle, buffer, size, ctypes.byref(read), None):
            return None
        return bytes(buffer[:read.value])
    finally:
        k32.CloseHandle(handle)


def _read_logical(drive_letter, offset, size):
    k32 = _ensure_kernel32_full()
    if k32 is None:
        return None
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    path = "\\\\.\\{}:".format(drive_letter)
    handle = k32.CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             None, OPEN_EXISTING, 0, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        return None
    try:
        k32.SetFilePointer(handle, offset, None, 0)
        buffer = (ctypes.c_ubyte * size)()
        read = ctypes.wintypes.DWORD()
        if not k32.ReadFile(handle, buffer, size, ctypes.byref(read), None):
            return None
        return bytes(buffer[:read.value])
    finally:
        k32.CloseHandle(handle)


def _write_physical(disk_index, offset, data):
    k32 = _ensure_kernel32_full()
    if k32 is None:
        return False
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    path = "\\\\.\\PhysicalDrive{}".format(disk_index)
    handle = k32.CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             None, OPEN_EXISTING, 0, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        return False
    try:
        k32.SetFilePointer(handle, offset, None, 0)
        buffer = (ctypes.c_ubyte * len(data))(*data)
        written = ctypes.wintypes.DWORD()
        if not k32.WriteFile(handle, buffer, len(data), ctypes.byref(written), None):
            return False
        return written.value == len(data)
    finally:
        k32.CloseHandle(handle)


def backup_all_boot_sectors():
    os.makedirs(BOOT_BACKUP_DIR, exist_ok=True)
    manifest = []
    for target in BOOT_RULES["backup_targets"]:
        if target["type"] == "first_1mb":
            content = _read_physical(0, 0, target["size"])
        elif target["type"] == "mbr":
            content = _read_physical(target["drive"], 0, target["size"])
        elif target["type"] == "gpt_header":
            content = _read_physical(target["drive"], 512, target["size"])
        elif target["type"] == "gpt_backup":
            content = _read_physical(target["drive"], -target["size"], target["size"])
        elif target["type"] == "vbr_c":
            content = _read_logical(target["drive"], 0, target["size"])
        else:
            continue
        if content is None:
            continue
        digest = hashlib.sha256(content).hexdigest()
        name = "disk{}_{}.bin".format(target["drive"] if target.get("drive") is not None else 0,
                                      target["type"])
        path = os.path.join(BOOT_BACKUP_DIR, name)
        try:
            with open(path, "wb") as handle:
                handle.write(content)
        except Exception as exc:
            defender_log("boot_backup_write_failed", "{}: {}".format(path, exc))
            continue
        manifest.append({"name": name, "type": target["type"], "sha256": digest,
                         "size": len(content)})
    try:
        with open(os.path.join(BOOT_BACKUP_DIR, "manifest.json"), "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, ensure_ascii=False, indent=1)
    except Exception as exc:
        defender_log("boot_manifest_save_failed", str(exc))
    return manifest


def verify_boot_sectors():
    manifest_path = os.path.join(BOOT_BACKUP_DIR, "manifest.json")
    if not os.path.isfile(manifest_path):
        return {"ok": False, "error": "无引导区备份"}
    try:
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    drift = []
    for entry in manifest:
        path = os.path.join(BOOT_BACKUP_DIR, entry["name"])
        try:
            with open(path, "rb") as handle:
                stored = handle.read()
        except Exception:
            continue
        if entry["type"] == "first_1mb":
            actual = _read_physical(0, 0, entry["size"])
        elif entry["type"] == "mbr":
            actual = _read_physical(0, 0, entry["size"])
        elif entry["type"] == "gpt_header":
            actual = _read_physical(0, 512, entry["size"])
        elif entry["type"] == "gpt_backup":
            actual = _read_physical(0, -entry["size"], entry["size"])
        elif entry["type"] == "vbr_c":
            actual = _read_logical("C", 0, entry["size"])
        else:
            continue
        if actual is None:
            continue
        if hashlib.sha256(actual).hexdigest() != entry["sha256"]:
            drift.append({"name": entry["name"], "type": entry["type"]})
    return {"ok": not drift, "drift": drift}


def _find_boot_attack_candidates(window_sec):
    pids = enumerate_process_ids()
    now = time.time()
    recent = []
    for pid in pids:
        try:
            stat = os.stat("/proc/{}".format(pid))  # placeholder
        except Exception:
            pass
        image = query_process_image(pid)
        if not image:
            continue
        name = os.path.basename(image).lower()
        if name in PROCESS_RULES["whitelist"]:
            continue
        recent.append(pid)
    return recent


def restore_boot_sector(entry):
    path = os.path.join(BOOT_BACKUP_DIR, entry["name"])
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "rb") as handle:
            stored = handle.read()
    except Exception:
        return False
    if entry["type"] == "first_1mb":
        return _write_physical(0, 0, stored)
    if entry["type"] == "mbr":
        return _write_physical(0, 0, stored)
    if entry["type"] == "gpt_header":
        return _write_physical(0, 512, stored)
    if entry["type"] == "gpt_backup":
        return _write_physical(0, -entry["size"], stored)
    if entry["type"] == "vbr_c":
        k32 = _ensure_kernel32_full()
        if k32 is None:
            return False
        GENERIC_WRITE = 0x40000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        handle = k32.CreateFileW("\\\\.\\C:", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 None, OPEN_EXISTING, 0, None)
        if not handle or handle == ctypes.c_void_p(-1).value:
            return False
        try:
            k32.SetFilePointer(handle, 0, None, 0)
            buffer = (ctypes.c_ubyte * len(stored))(*stored)
            written = ctypes.wintypes.DWORD()
            if not k32.WriteFile(handle, buffer, len(stored), ctypes.byref(written), None):
                return False
            return written.value == len(stored)
        finally:
            k32.CloseHandle(handle)
    return False


_BOOT_THREAD = None
_BOOT_STOP = threading.Event()


def _boot_loop(stop_event):
    while not stop_event.is_set():
        if not _STATE["running"]:
            break
        if _STATE["levels"].get(LEVEL_KEYPOSITIONS):
            try:
                status = verify_boot_sectors()
                if status.get("ok") is False and status.get("drift"):
                    for entry in status["drift"]:
                        restore_boot_sector(entry)
                        candidates = _find_boot_attack_candidates(BOOT_RULES["new_proc_window_sec"])
                        for pid in candidates:
                            kill_tree(pid, reason="boot_sector_modified")
                        alert_pair("主动防御拦截", "引导区 {} 已恢复 候选杀进程 {}".format(entry["type"], len(candidates)))
            except Exception as exc:
                defender_log("boot_verify_error", str(exc))
        if stop_event.wait(BOOT_RULES["check_interval_sec"]):
            break


def start_boot_monitor():
    return _monitor_start(_BOOT_STOP, "_BOOT_THREAD", _boot_loop,
                          "dragon-boot-monitor", args=(_BOOT_STOP,))


def stop_boot_monitor():
    return _monitor_stop(_BOOT_STOP, "_BOOT_THREAD")

########################################自保护 SELF_GUARD########################################

_BASELINE_MANIFEST = {}


def _build_baseline():
    os.makedirs(BASELINE_DIR, exist_ok=True)
    manifest = {}
    for pattern in SELF_RULES["protected_files"]:
        matches = []
        if pattern.endswith("*") or "?" in pattern:
            base_pattern = pattern.rstrip("*").rstrip("?")
            directory = os.path.join(BASE_DIR, base_pattern)
            if not os.path.isdir(directory):
                continue
            for root, _dirs, names in os.walk(directory):
                for name in names:
                    full = os.path.join(root, name)
                    matches.append(full)
        else:
            full = os.path.join(BASE_DIR, pattern)
            if os.path.isfile(full):
                matches.append(full)
        for path in matches:
            digest = file_sha256(path)
            if not digest:
                continue
            try:
                rel = os.path.relpath(path, BASE_DIR)
            except ValueError:
                continue
            target_dir = os.path.join(BASELINE_DIR, os.path.dirname(rel))
            os.makedirs(target_dir, exist_ok=True)
            target = os.path.join(BASELINE_DIR, rel)
            try:
                if not os.path.isfile(target):
                    with open(target, "wb") as handle:
                        with open(path, "rb") as src:
                            handle.write(src.read())
            except Exception as exc:
                defender_log("baseline_copy_failed", "{}: {}".format(path, exc))
                continue
            manifest[rel] = digest
    try:
        with open(os.path.join(BASELINE_DIR, "manifest.json"), "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, ensure_ascii=False, indent=1)
    except Exception as exc:
        defender_log("baseline_manifest_save_failed", str(exc))
    _BASELINE_MANIFEST.clear()
    _BASELINE_MANIFEST.update(manifest)
    return manifest


def _load_baseline():
    try:
        with open(os.path.join(BASELINE_DIR, "manifest.json"), "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except Exception:
        manifest = {}
    _BASELINE_MANIFEST.clear()
    _BASELINE_MANIFEST.update(manifest)
    return manifest


def _restore_baseline_file(rel_path):
    source = os.path.join(BASELINE_DIR, rel_path)
    target = os.path.join(BASE_DIR, rel_path)
    if not os.path.isfile(source):
        return False
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(source, "rb") as src:
            data = src.read()
        with open(target, "wb") as dst:
            dst.write(data)
        return True
    except Exception as exc:
        defender_log("baseline_restore_failed", "{}: {}".format(target, exc))
        return False


def check_baseline():
    if not _BASELINE_MANIFEST:
        _load_baseline()
    drift = []
    for rel_path, expected in _BASELINE_MANIFEST.items():
        full = os.path.join(BASE_DIR, rel_path)
        actual = file_sha256(full)
        if actual != expected:
            drift.append(rel_path)
    return drift


_SELF_THREAD = None
_SELF_STOP = threading.Event()


def _self_loop(stop_event):
    while not stop_event.is_set():
        if not _STATE["running"]:
            break
        try:
            drift = check_baseline()
        except Exception as exc:
            defender_log("self_check_error", str(exc))
            drift = []
        for rel_path in drift:
            _restore_baseline_file(rel_path)
            alert_pair("主动防御拦截", "自保护 {} 已还原".format(rel_path))
        if stop_event.wait(SELF_RULES["check_interval_sec"]):
            break


def start_self_monitor():
    if not _BASELINE_MANIFEST:
        _load_baseline()
    return _monitor_start(_SELF_STOP, "_SELF_THREAD", _self_loop,
                          "dragon-self-monitor", args=(_SELF_STOP,))


def stop_self_monitor():
    return _monitor_stop(_SELF_STOP, "_SELF_THREAD")

########################################网络监控 NET_GUARD########################################

_iphlpapi = None


def _ensure_iphlpapi():
    global _iphlpapi
    if _iphlpapi is not None:
        return _iphlpapi
    try:
        _iphlpapi = ctypes.windll.iphlpapi
        return _iphlpapi
    except Exception as exc:
        defender_log("iphlpapi_load_failed", str(exc))
        return None


class _MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.wintypes.DWORD),
        ("dwLocalAddr", ctypes.wintypes.DWORD),
        ("dwLocalPort", ctypes.wintypes.DWORD),
        ("dwRemoteAddr", ctypes.wintypes.DWORD),
        ("dwRemotePort", ctypes.wintypes.DWORD),
        ("dwOwningPid", ctypes.wintypes.DWORD),
    ]


class _MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", ctypes.wintypes.DWORD),
        ("table", _MIB_TCPROW_OWNER_PID * 1),
    ]


def _enumerate_tcp():
    dll = _ensure_iphlpapi()
    if dll is None:
        return []
    AF_INET = 2
    TCP_TABLE_OWNER_PID_ALL = 5
    size = ctypes.wintypes.DWORD(0)
    dll.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if size.value == 0:
        return []
    buffer = (ctypes.c_ubyte * size.value)()
    result = dll.GetExtendedTcpTable(buffer, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if result != 0:
        return []
    table = ctypes.cast(buffer, ctypes.POINTER(_MIB_TCPTABLE_OWNER_PID))
    count = table.contents.dwNumEntries
    rows = ctypes.cast(table.contents.table, ctypes.POINTER(_MIB_TCPROW_OWNER_PID * count)).contents
    connections = []
    for row in rows:
        connections.append({
            "state": int(row.dwState),
            "local_addr": int(row.dwLocalAddr),
            "local_port": int(row.dwLocalPort),
            "remote_addr": int(row.dwRemoteAddr),
            "remote_port": int(row.dwRemotePort),
            "pid": int(row.dwOwningPid),
        })
    return connections


def _format_addr(value):
    return "{}.{}.{}.{}".format(value & 0xff, (value >> 8) & 0xff,
                                 (value >> 16) & 0xff, (value >> 24) & 0xff)


def _is_established(state):
    MIB_TCP_STATE_ESTAB = 5
    return state == MIB_TCP_STATE_ESTAB


def _file_is_unsigned(path):
    E = _engine()
    if E is None:
        return True
    checker = getattr(E, "file_signed", None)
    if not callable(checker):
        return True
    try:
        return not checker(path)
    except Exception:
        return True


def _match_network_rule(pid, image_path, remote_addr, remote_port):
    name_lower = os.path.basename(image_path or "").lower()
    if name_lower in PROCESS_RULES["whitelist"]:
        return None
    if is_self_path(image_path):
        return None
    if remote_port in NET_RULES["danger_ports"]:
        return "danger_port_{}".format(remote_port)
    if remote_addr in NET_RULES["ip_blacklist"]:
        return "ip_blacklist_{}".format(remote_addr)
    norm = normalize_path(image_path)
    in_danger_dir = False
    for template in NET_RULES["danger_dirs"]:
        candidate = normalize_path(expand_user_env(template))
        if norm == candidate or norm.startswith(candidate + os.sep):
            in_danger_dir = True
            break
    if in_danger_dir and NET_RULES["unsigned_required"] and _file_is_unsigned(image_path):
        return "danger_dir_unsigned"
    return None


def on_network_event(pid, image_path, remote_addr, remote_port):
    if not _STATE["running"]:
        return
    rule_hit = _match_network_rule(pid, image_path, remote_addr, remote_port)
    if not rule_hit:
        return
    if not alert_once("net|{}|{}".format(image_path, rule_hit)):
        return
    if T.is_trusted(image_path):
        safe_log("主动防御拦截", "{}｜命中信任白名单，已放行".format(image_path))
        return
    kill_tree(pid, reason="network_{}".format(rule_hit))
    alert_pair("主动防御拦截", "{}｜{}:{}｜{}".format(image_path, remote_addr, remote_port, rule_hit))


_NET_THREAD = None
_NET_STOP = threading.Event()
_NET_DRIVER_HOOK = None


def _net_loop(stop_event):
    while not stop_event.is_set():
        if not _STATE["running"]:
            break
        if _STATE["levels"].get(LEVEL_REALTIME):
            try:
                for entry in _enumerate_tcp():
                    if stop_event.is_set():
                        break
                    if not _is_established(entry["state"]):
                        continue
                    pid = entry["pid"]
                    image = query_process_image(pid)
                    if not image:
                        continue
                    addr = _format_addr(entry["remote_addr"])
                    port = entry["remote_port"]
                    if _NET_DRIVER_HOOK:
                        try:
                            _NET_DRIVER_HOOK(pid, image)
                        except Exception:
                            pass
                    on_network_event(pid, image, addr, port)
            except Exception as exc:
                defender_log("net_loop_error", str(exc))
        if stop_event.wait(NET_RULES["polling_interval_sec"]):
            break


def start_network_monitor(driver_hook=None):
    global _NET_DRIVER_HOOK
    _NET_DRIVER_HOOK = driver_hook
    return _monitor_start(_NET_STOP, "_NET_THREAD", _net_loop,
                          "dragon-net-monitor", args=(_NET_STOP,))


def stop_network_monitor():
    return _monitor_stop(_NET_STOP, "_NET_THREAD")

########################################内存扫描 MEM_GUARD########################################

_api_call_map = {}


def _record_api_call(pid, api_name):
    if not pid or not api_name:
        return
    with _LOCK:
        bucket = _api_call_map.setdefault(int(pid), {})
        bucket[api_name] = bucket.get(api_name, 0) + 1
        now = time.monotonic()
        bucket["__last_seen__"] = now
        expired = [other_pid for other_pid, data in _api_call_map.items()
                   if now - data.get("__last_seen__", 0) > 120]
        for other_pid in expired:
            _api_call_map.pop(other_pid, None)


def _detect_injection_patterns(pid, image_path):
    api_calls = _api_call_map.get(int(pid), {})
    matches = []
    for pattern in MEMORY_RULES["injection_patterns"]:
        if pattern.get("detect") == "loaded_dll_from_temp":
            continue
        required = pattern["apis"]
        threshold = pattern["min_count"]
        seen = sum(1 for name in required if api_calls.get(name, 0) >= threshold)
        if seen >= threshold:
            matches.append(pattern["name"])
    return matches


def _detect_module_stomping(pid, image_path):
    pattern = next((p for p in MEMORY_RULES["injection_patterns"] if p.get("detect") == "loaded_dll_from_temp"), None)
    if pattern is None:
        return None
    whitelist_dirs = [normalize_path(expand_user_env(t)) for t in pattern["whitelist_dirs"]]
    danger_dirs = [normalize_path(expand_user_env(t)) for t in pattern["danger_dirs"]]
    name_lower = os.path.basename(image_path or "").lower()
    if name_lower not in {"dllhost.exe", "werfault.exe", "svchost.exe", "explorer.exe"}:
        return None
    parent_pid = get_parent_pid(int(pid))
    parent_image = query_process_image(parent_pid) if parent_pid else ""
    if not parent_image:
        return None
    parent_norm = normalize_path(parent_image)
    if any(parent_norm.startswith(d + os.sep) or parent_norm == d for d in danger_dirs):
        return pattern["name"]
    if any(parent_norm.startswith(d + os.sep) or parent_norm == d for d in whitelist_dirs):
        return None
    return None


def on_memory_event(src_pid, src_image, dst_pid, dst_image, pattern_name):
    verdict = "safe"
    if _STATE["levels"].get(LEVEL_ENGINESCAN):
        verdict = engine_suspend_and_scan(int(src_pid), src_image)
    if verdict in ("malicious", "timeout"):
        kill_tree(int(src_pid), reason="mem_inject_{}".format(pattern_name))
        if dst_pid:
            kill_tree(int(dst_pid), reason="mem_inject_victim_{}".format(pattern_name))
        alert_pair("主动防御拦截", "{}→{}｜{}".format(src_image, dst_image, pattern_name))


_MEMORY_THREAD = None
_MEMORY_STOP = threading.Event()


def _memory_loop(stop_event):
    while not stop_event.is_set():
        if not _STATE["running"]:
            break
        if _STATE["levels"].get(LEVEL_REALTIME):
            try:
                for pid in enumerate_process_ids():
                    image = query_process_image(pid)
                    if not image:
                        continue
                    if is_self_path(image):
                        continue
                    name_lower = os.path.basename(image).lower()
                    if name_lower in PROCESS_RULES["whitelist"]:
                        continue
                    matches = _detect_injection_patterns(pid, image)
                    stomping = _detect_module_stomping(pid, image)
                    for match in matches:
                        on_memory_event(pid, image, 0, "", match)
                    if stomping:
                        on_memory_event(pid, image, 0, "", stomping)
            except Exception as exc:
                defender_log("memory_loop_error", str(exc))
        if stop_event.wait(MEMORY_RULES["polling_interval_sec"]):
            break


def start_memory_monitor():
    return _monitor_start(_MEMORY_STOP, "_MEMORY_THREAD", _memory_loop,
                          "dragon-memory-monitor", args=(_MEMORY_STOP,))


def stop_memory_monitor():
    return _monitor_stop(_MEMORY_STOP, "_MEMORY_THREAD")

########################################压缩包标记 ARCHIVE_GUARD########################################

_archive_state = {}
_archive_state_file = os.path.join(DATA_DIR, "_archive_state.json")


def _load_archive_state():
    global _archive_state
    try:
        with open(_archive_state_file, "r", encoding="utf-8") as handle:
            _archive_state = json.load(handle)
    except Exception:
        _archive_state = {}


def _save_archive_state():
    try:
        with open(_archive_state_file, "w", encoding="utf-8") as handle:
            json.dump(_archive_state, handle, ensure_ascii=False)
    except Exception:
        pass


def _is_archive_file(path):
    if not path:
        return False
    return path.lower().endswith(ARCHIVE_RULES["extensions"])


def _mark_zone_identifier(path, note):
    try:
        ads_path = "{}:Zone.Identifier".format(path)
        payload = "[Dragon Marked]\r\nNote={}\r\n".format(note)
        with open(ads_path, "w", encoding="utf-8") as handle:
            handle.write(payload)
        return True
    except Exception as exc:
        defender_log("zone_mark_failed", "{}: {}".format(path, exc))
        return False


def _check_archive_burst(parent_dir, archive_path):
    try:
        entries = os.listdir(parent_dir)
    except Exception:
        return []
    archive_state = _archive_state.get(archive_path, {})
    archive_mtime = os.path.getmtime(archive_path) if os.path.isfile(archive_path) else 0
    if archive_state.get("mtime") and archive_mtime != archive_state.get("mtime"):
        _mark_zone_identifier(archive_path, "Dragon burst detection mtime drift")
        _archive_state[archive_path] = {"mtime": archive_mtime, "ts": time.time()}
        return entries
    new_files = []
    window = ARCHIVE_RULES["burst_window_sec"]
    threshold = ARCHIVE_RULES["burst_file_count"]
    now = time.time()
    for entry in entries:
        full = os.path.join(parent_dir, entry)
        if not os.path.isfile(full):
            continue
        if full == archive_path:
            continue
        try:
            mtime = os.path.getmtime(full)
        except Exception:
            continue
        if now - mtime <= window:
            new_files.append(full)
    if len(new_files) >= threshold:
        _mark_zone_identifier(archive_path, "Dragon burst detection sibling count {}".format(len(new_files)))
        _archive_state[archive_path] = {"mtime": archive_mtime, "ts": now}
        return new_files
    return []


def on_archive_burst(parent_dir, archive_path, new_files):
    if not _STATE["running"]:
        return
    for new_path in new_files:
        try:
            if not new_path.lower().endswith(STATIC_RULES["realtime_extensions"]):
                continue
            result = engine_scan(new_path)
            if result and result.get("verdict") == "malicious":
                if T.is_trusted(new_path):
                    safe_log("主动防御拦截", "{}｜命中信任白名单，已放行".format(new_path))
                    continue
                qres = quarantine_add(new_path)
                _quarantine_notify("主动防御拦截", new_path, qres)
        except Exception as exc:
            defender_log("archive_burst_event_error", "{}: {}".format(new_path, exc))


_ARCHIVE_THREAD = None
_ARCHIVE_STOP = threading.Event()


def _archive_loop(stop_event):
    if not _archive_state:
        _load_archive_state()
    while not stop_event.is_set():
        if not _STATE["running"]:
            break
        if _STATE["levels"].get(LEVEL_REALTIME):
            try:
                for archive in _iter_archive_files():
                    if stop_event.is_set():
                        break
                    parent = os.path.dirname(archive)
                    new_files = _check_archive_burst(parent, archive)
                    if new_files:
                        on_archive_burst(parent, archive, new_files)
                _save_archive_state()
            except Exception as exc:
                defender_log("archive_loop_error", str(exc))
        if stop_event.wait(ARCHIVE_RULES["polling_interval_sec"]):
            break


def _iter_archive_files():
    for template in STATIC_RULES["scan_dirs"]:
        root = expand_user_env(template)
        if not root or not os.path.isdir(root):
            continue
        try:
            for current, _dirs, names in os.walk(root):
                for name in names:
                    if _is_archive_file(name):
                        yield os.path.join(current, name)
        except Exception:
            continue


def start_archive_monitor():
    return _monitor_start(_ARCHIVE_STOP, "_ARCHIVE_THREAD", _archive_loop,
                          "dragon-archive-monitor", args=(_ARCHIVE_STOP,))


def stop_archive_monitor():
    return _monitor_stop(_ARCHIVE_STOP, "_ARCHIVE_THREAD")

########################################勒索诱捕 DECOY_GUARD########################################

_decoy_manifest = []


def _decoy_template_path(template):
    root = expand_user_env(template["root"])
    if template["subdir"]:
        root = os.path.join(root, template["subdir"])
    return os.path.normpath(root)


def _decoy_baseline_path(template, index):
    rel_root = template["root"].strip("%").lower() or "root"
    return os.path.join(DECOY_RULES["baseline_copy"], rel_root,
                        template["subdir"].replace("\\", "_") or "_root",
                        "{}_{:03d}{}".format(template["name"], index, template["ext"]))


def _ensure_decoy_file(template, index):
    rel_root = template["root"].strip("%").lower() or "root"
    decoy_dir = _decoy_template_path(template)
    os.makedirs(decoy_dir, exist_ok=True)
    decoy_path = os.path.join(decoy_dir,
                              "{}_{:03d}{}".format(template["name"], index, template["ext"]))
    if not os.path.isfile(decoy_path):
        try:
            content = ("Dragon Decoy File\n" * 200).encode("utf-8")
            if template["ext"] == ".docx":
                content = b"PK\x03\x04" + b"\x00" * 200
            with open(decoy_path, "wb") as handle:
                handle.write(content)
        except Exception as exc:
            defender_log("decoy_create_failed", "{}: {}".format(decoy_path, exc))
            return None
        try:
            if DECOY_RULES["hidden_attribute"]:
                ctypes.windll.kernel32.SetFileAttributesW(decoy_path, 0x02)
        except Exception:
            pass
    baseline_path = _decoy_baseline_path(template, index)
    os.makedirs(os.path.dirname(baseline_path), exist_ok=True)
    if not os.path.isfile(baseline_path):
        try:
            with open(decoy_path, "rb") as src, open(baseline_path, "wb") as dst:
                dst.write(src.read())
        except Exception as exc:
            defender_log("decoy_baseline_failed", "{}: {}".format(baseline_path, exc))
    return decoy_path


def build_all_decoys():
    manifest = []
    for template in DECOY_RULES["decoy_paths"]:
        for index in range(template["count"]):
            decoy_path = _ensure_decoy_file(template, index)
            if decoy_path:
                manifest.append({"path": decoy_path, "template": template["name"]})
    try:
        with open(DECOY_MANIFEST_FILE, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, ensure_ascii=False, indent=1)
    except Exception as exc:
        defender_log("decoy_manifest_save_failed", str(exc))
    _decoy_manifest.clear()
    _decoy_manifest.extend(manifest)
    return manifest


def _load_decoy_manifest():
    try:
        with open(DECOY_MANIFEST_FILE, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        _decoy_manifest.clear()
        _decoy_manifest.extend(manifest)
        return manifest
    except Exception:
        return []


def restore_decoy(decoy_path):
    manifest = _decoy_manifest or _load_decoy_manifest()
    for entry in manifest:
        if entry.get("path") == decoy_path:
            rel_root = entry["template"]
            template = next((t for t in DECOY_RULES["decoy_paths"] if t["name"] == rel_root), None)
            if template is None:
                return False
            index = int(os.path.basename(decoy_path).rsplit("_", 1)[1].split(".")[0])
            baseline_path = _decoy_baseline_path(template, index)
            if not os.path.isfile(baseline_path):
                _ensure_decoy_file(template, index)
                return True
            try:
                with open(baseline_path, "rb") as src, open(decoy_path, "wb") as dst:
                    dst.write(src.read())
                return True
            except Exception as exc:
                defender_log("decoy_restore_failed", "{}: {}".format(decoy_path, exc))
                return False
    return False


def _scan_decoy_state():
    if not _decoy_manifest:
        _load_decoy_manifest()
    state = []
    for entry in _decoy_manifest:
        path = entry["path"]
        if not os.path.isfile(path):
            state.append({"path": path, "exists": False})
            continue
        try:
            stat = os.stat(path)
            state.append({"path": path, "exists": True, "size": stat.st_size,
                          "mtime": int(stat.st_mtime)})
        except Exception:
            state.append({"path": path, "exists": True})
    return state


_DECOY_THREAD = None
_DECOY_STOP = threading.Event()
_DECOY_LAST_STATE = []


def _decoy_loop(stop_event):
    global _DECOY_LAST_STATE
    if not _decoy_manifest:
        _load_decoy_manifest()
    _DECOY_LAST_STATE = _scan_decoy_state()
    while not stop_event.is_set():
        if not _STATE["running"]:
            break
        current = _scan_decoy_state()
        prev_map = {item["path"]: item for item in _DECOY_LAST_STATE if "size" in item}
        for item in current:
            path = item["path"]
            prev = prev_map.get(path)
            if not prev:
                if item.get("exists") is False:
                    on_decoy_event(path, "deleted", 0)
                continue
            if item.get("exists") is False:
                on_decoy_event(path, "deleted", 0)
            elif item.get("size") != prev.get("size") or item.get("mtime") != prev.get("mtime"):
                on_decoy_event(path, "modified", 0)
        _DECOY_LAST_STATE = current
        if stop_event.wait(DECOY_RULES["polling_interval_sec"]):
            break


def on_decoy_event(decoy_path, action, trigger_pid):
    # 当前诱捕监控基于轮询，无法稳定取得触发进程 PID（调用方一律传 0）；
    # 仅当拿到真实 PID 时才处置进程，避免误杀 PID 0（System Idle Process）。
    if trigger_pid:
        try:
            kill_tree(int(trigger_pid), reason="ransom_decoy_{}".format(action))
        except Exception as exc:
            defender_log("decoy_kill_failed", "pid={} err={}".format(trigger_pid, exc))
    restore_decoy(decoy_path)
    alert_pair("主动防御拦截", "诱捕被触: {} action={}".format(decoy_path, action))


def start_decoy_monitor():
    if not _decoy_manifest:
        _load_decoy_manifest()
    return _monitor_start(_DECOY_STOP, "_DECOY_THREAD", _decoy_loop,
                          "dragon-decoy-monitor", args=(_DECOY_STOP,))


def stop_decoy_monitor():
    return _monitor_stop(_DECOY_STOP, "_DECOY_THREAD")

########################################静态扫描 STATIC_SCAN########################################

_AUTO_INCLUDE_CACHE = {"ts": 0.0, "paths": []}


def _resolve_static_roots(should_abort=None):
    roots = []
    for template in STATIC_RULES["scan_dirs"]:
        resolved = expand_user_env(template)
        if resolved and os.path.isdir(resolved):
            roots.append(resolved)
    now = time.monotonic()
    if now - _AUTO_INCLUDE_CACHE["ts"] < 600:
        roots.extend(_AUTO_INCLUDE_CACHE["paths"])
        return roots
    extra = []
    for root_template in STATIC_RULES["auto_include_roots"]:
        root = expand_user_env(root_template)
        if not root or not os.path.isdir(root):
            continue
        try:
            for current, dirs, _names in os.walk(root):
                if should_abort is not None and should_abort():
                    return roots
                depth = current.count(os.sep) - root.count(os.sep)
                if depth > 4:
                    dirs[:] = []
                    continue
                lowered = current.lower()
                if any(keyword in lowered for keyword in STATIC_RULES["auto_include_keywords"]):
                    extra.append(current)
        except Exception:
            continue
    _AUTO_INCLUDE_CACHE["ts"] = now
    _AUTO_INCLUDE_CACHE["paths"] = extra
    roots.extend(extra)
    return roots


def static_scan_now(targets=None, should_abort=None):
    E = _engine()
    if E is None:
        return {"scanned": 0, "found": 0, "error": "引擎未加载"}
    roots = targets if targets else _resolve_static_roots(should_abort=should_abort)
    scanned = 0
    found = 0
    aborted = False
    pool = ThreadPoolExecutor(max_workers=STATIC_SCAN_WORKERS, thread_name_prefix="dragon-static")
    try:
        futures = []
        for root in roots:
            if should_abort is not None and should_abort():
                aborted = True
                break
            try:
                for current, _dirs, names in os.walk(root):
                    if should_abort is not None and should_abort():
                        aborted = True
                        break
                    stop_names = False
                    for name in names:
                        if not name.lower().endswith(_REALTIME_EXTS_LOWER + _ARCHIVE_EXTS_LOWER):
                            continue
                        full = os.path.join(current, name)
                        if is_self_path(full):
                            continue
                        try:
                            if os.path.getsize(full) > STATIC_SCAN_MAX_BYTES:
                                continue
                        except Exception:
                            continue
                        futures.append(pool.submit(_static_scan_one, full))
                        scanned += 1
                        if len(futures) >= 256:
                            for fut in futures:
                                if should_abort is not None and should_abort():
                                    break
                                if fut.result():
                                    found += 1
                            futures = []
                            if should_abort is not None and should_abort():
                                stop_names = True
                                break
                    if stop_names:
                        aborted = True
                        break
                if aborted:
                    break
            except Exception:
                continue
        if futures:
            for fut in futures:
                if should_abort is not None and should_abort():
                    break
                if fut.result():
                    found += 1
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    _STATE["static_last_run"] = time.time()
    _emit_push("defense_static_alert", {"scanned": scanned, "found": found})
    return {"scanned": scanned, "found": found}


def _static_scan_one(path):
    # 注意：此处不检查 _STATE["running"]，因为手动"立即扫描"(static_scan_now) 与后台轮询均会调用本函数；
    # 后台轮询已由 _static_loop 的 running 门禁把控，手动扫描应在主动防御关闭时仍可用。
    result = engine_scan(path)
    if result and result.get("verdict") == "malicious":
        if T.is_quarantined(path):
            return False
        if not alert_once("static|{}".format(path.lower())):
            return False
        qres = T.quarantine_add(path)
        _quarantine_notify("静态扫描", path, qres)
        return True
    return False


_STATIC_THREAD = None
_STATIC_STOP = threading.Event()
_STATIC_RUN_LOCK = threading.Lock()


def _static_loop(stop_event):
    while not stop_event.is_set():
        if not _STATE["running"]:
            break
        if _STATE["levels"].get(LEVEL_STATIC_POLL):
            try:
                with _STATIC_RUN_LOCK:
                    if stop_event.is_set():
                        break
                    static_scan_now(should_abort=stop_event.is_set)
            except Exception as exc:
                defender_log("static_scan_error", str(exc))
        if stop_event.wait(STATIC_RULES["snapshot_interval_sec"]):
            break


def start_static_monitor():
    return _monitor_start(_STATIC_STOP, "_STATIC_THREAD", _static_loop,
                          "dragon-static-monitor", args=(_STATIC_STOP,))


def stop_static_monitor():
    return _monitor_stop(_STATIC_STOP, "_STATIC_THREAD", timeout=30.0)

########################################驱动接入位 DRIVER_HOOKS########################################

_driver_hook = None


def _defense_hook_process_event(pid, image_path):
    on_process_event(int(pid), image_path, get_parent_pid(int(pid)),
                     query_process_image(get_parent_pid(int(pid))))


def _defense_hook_image_load(pid, image_path):
    if not _STATE["running"]:
        return
    if is_self_path(image_path):
        return
    name_lower = os.path.basename(image_path or "").lower()
    if name_lower in PROCESS_RULES["whitelist"]:
        return
    if not name_lower.endswith((".dll", ".exe")):
        return
    result = engine_scan(image_path)
    if result and result.get("verdict") == "malicious":
        if T.is_trusted(image_path):
            safe_log("主动防御拦截", "{}｜命中信任白名单，已放行".format(image_path))
            return
        if not alert_once("imgload|{}".format(image_path.lower())):
            return
        kill_tree(int(pid), reason="image_load_malicious")
        alert_pair("主动防御拦截", "{}｜image_load_malicious".format(image_path))


def _defense_hook_registry_write(hive, subkey, value_name):
    new_value = _read_key_values(hive, subkey)
    payload = None
    for name, value in new_value:
        if name == value_name:
            payload = value
            break
    on_registry_change(hive, subkey, value_name, payload, source_pid=0)


def defense_register_driver_hook(callable_):
    global _driver_hook
    _driver_hook = callable_
    return {"ok": True}


# 驱动开关最近一次处理结果：是否需要重启以让签名策略/驱动生效
_DRIVER_REBOOT_REQUIRED = False


def driver_connected():
    if not _STATE["levels"].get(LEVEL_DRIVER):
        return False
    if _driver_hook is None:
        return False
    try:
        return bool(_driver_hook())
    except Exception:
        return False


# 驱动客户端与监听线程状态现由 Dragon_Drivers 模块统一管理（见 Dragon_Drivers.py）。

# 内核自保护事件码（与 Dragon-Drivers 驱动硬编码一致；详见 DragonProtocol.h）
_DRIVER_SELF_CODES = {
    9001: "驱动镜像被改写",
    9002: "规则目录被改写",
    9003: "服务注册表键被改写",
    9004: "客户端进程被终止/处置权限被剥夺",
    9005: "受保护进程被操作",
    9006: "主程序/外置文件被改写",
    9007: "勒索备份区被非内核发起者写入",
}
# 勒索防护事件码（9200 段，详见 DragonProtocol.h）
_DRIVER_RANSOM_CODES = {
    9201: "行为评分达到阻断阈值",
    9202: "已从备份恢复文件",
}
_DRIVER_ACTION_NAMES = {0: "Report", 1: "Terminate"}

# 同一条内核事件（码 + 进程 + 目标）在此窗口内只播报一次。
# 背景：被判定为勒索的进程在解除阻断前，其每一次文件操作都会被内核拦截并上报，
# 若不节流，界面会被同一条事件刷屏（表现为「软件一直在拦截同一个文件」）。
_DRIVER_EVENT_THROTTLE_SECONDS = 30.0
_DRIVER_EVENT_THROTTLE = {}
_DRIVER_EVENT_THROTTLE_LOCK = threading.Lock()
_DRIVER_EVENT_THROTTLE_MAX = 512


def _driver_event_throttled(code, pid, path):
    """返回 (是否放行播报, 期间被抑制的同类事件条数)。"""
    try:
        key = (int(code), int(pid or 0), (path or "").lower())
    except Exception:
        key = (code, pid, path)
    now = time.time()
    with _DRIVER_EVENT_THROTTLE_LOCK:
        record = _DRIVER_EVENT_THROTTLE.get(key)
        if record is None:
            if len(_DRIVER_EVENT_THROTTLE) >= _DRIVER_EVENT_THROTTLE_MAX:
                # 清理过期键，避免长时间运行后字典无限增长
                expired = [k for k, v in _DRIVER_EVENT_THROTTLE.items()
                           if now - v[0] >= _DRIVER_EVENT_THROTTLE_SECONDS * 4]
                for k in expired[:_DRIVER_EVENT_THROTTLE_MAX // 2]:
                    _DRIVER_EVENT_THROTTLE.pop(k, None)
                if len(_DRIVER_EVENT_THROTTLE) >= _DRIVER_EVENT_THROTTLE_MAX:
                    _DRIVER_EVENT_THROTTLE.clear()
            _DRIVER_EVENT_THROTTLE[key] = [now, 0]
            return True, 0
        suppressed = record[1]
        if now - record[0] >= _DRIVER_EVENT_THROTTLE_SECONDS:
            record[0] = now
            record[1] = 0
            return True, suppressed
        record[1] = suppressed + 1
        return False, 0


def _driver_event_router(code, action, pid, path):
    """内核事件路由：内核已完成处置（Report/Terminate），用户态只做可见性与
    遥测，绝不再二次处置（避免与内核重复拦截）。

    事件码分段（与 DragonProtocol.h 保持一致）：
      · 9001-9007 自保护 —— 单独告警；
      · 9200 段    勒索防护 —— 单独告警，绝不能混进自保护文案（历史 bug：
        早期用 9000 <= code <= 9999 一刀切，导致 9201 被显示成「内核自保护」）；
      · 其它       动态规则命中 —— 走内核主动防御。
    同一条事件在 30 秒窗口内只播报一次，防止界面被重复事件刷屏。
    """
    try:
        action_name = _DRIVER_ACTION_NAMES.get(action, "0x%X" % action)
        target = os.path.basename(path) if path else "-"

        allowed, suppressed = _driver_event_throttled(code, pid, path)
        if not allowed:
            return

        if code in _DRIVER_SELF_CODES:
            title = "内核自保护"
            detail = "驱动拦截了对自身/受保护对象的操作：{}｜进程 {}｜目标 {}".format(
                _DRIVER_SELF_CODES[code], pid, target)
            event_name = "driver_selfprotect"
        elif 9200 <= code <= 9299:
            title = "勒索防护"
            detail = "已阻断疑似勒索行为（{}）：进程 {}｜目标 {}".format(
                _DRIVER_RANSOM_CODES.get(code, "事件 %d" % code), pid, target)
            event_name = "driver_ransom"
        else:
            title = "内核主动防御"
            detail = "内核驱动拦截：规则 {}｜动作 {}｜进程 {}｜目标 {}".format(
                code, action_name, pid, target)
            event_name = "driver_event"

        if suppressed:
            detail += "（近 {:.0f} 秒内已抑制 {} 条同类重复事件）".format(
                _DRIVER_EVENT_THROTTLE_SECONDS, suppressed)

        defender_log(event_name, "code=%d action=%s pid=%s path=%s suppressed=%d"
                     % (code, action_name, pid, path, suppressed))
        alert_pair(title, detail)
    except Exception as exc:
        defender_log("driver_event_router_error", str(exc))


def defense_set_driver_enabled(enabled):
    """按"驱动防护"开关连接/断开内核驱动客户端；驱动未加载或权限不足时安全降级。

    实际通信、规则下发、事件监听全部委托给 Dragon_Drivers 模块。连接成功后：
    ① 内核已加载规则（驱动启动自动从 Rules\\ 加载，Dragon_Drivers 再显式刷新）；
    ② 启动内核事件监听线程，把驱动上报的事件路由到主动防御逻辑。驱动侧的
    拦截/终止在内核完成，用户态只做可见性与遥测，不二次处置。
    """
    global _DRIVER_REBOOT_REQUIRED
    try:
        import Dragon_Drivers as drv
    except Exception as exc:
        defender_log("driver_module_missing", str(exc))
        _DRIVER_REBOOT_REQUIRED = False
        return {"ok": True, "connected": False}
    if not bool(enabled):
        try:
            drv.driver_disconnect()
        except Exception:
            pass
        try:
            defense_register_driver_hook(None)
        except Exception:
            pass
        _DRIVER_REBOOT_REQUIRED = False
        return {"ok": True, "connected": False}
    try:
        res = drv.driver_enable(on_event=_driver_event_router)
    except Exception as exc:
        defender_log("driver_connect_failed", str(exc))
        res = {"ok": False, "connected": False, "error": str(exc)}
    if not res.get("connected") and not res.get("error"):
        # 连接失败但驱动模块未给出明确原因：多为安全启动/内存完整性拒绝加载
        res = dict(res)
        res["error"] = ("内核驱动连接失败：驱动可能未加载，或被安全启动(Secure Boot)/"
                        "Windows 内存完整性（内核隔离）拒绝加载")
    connected = bool(res.get("connected"))
    _DRIVER_REBOOT_REQUIRED = bool(res.get("reboot_required"))
    if connected:
        defense_register_driver_hook(lambda: True)
    else:
        defense_register_driver_hook(None)
    return {
        "ok": res.get("ok", False),
        "connected": connected,
        "reboot_required": _DRIVER_REBOOT_REQUIRED,
        "error": res.get("error"),
    }

########################################等级管理 LEVELS########################################

_LEVEL_LOCK = threading.RLock()


def _level_set(name, value):
    with _LEVEL_LOCK:
        if name == LEVEL_ALWAYS:
            return False
        _STATE["levels"][name] = bool(value)
    _emit_push("defense_event", {"kind": "level_change", "level": name, "value": bool(value)})
    return True


def defense_set_level(name, value):
    if name not in ALL_LEVELS:
        return {"error": "未知等级：{}".format(name)}
    if name == LEVEL_ALWAYS:
        return {"error": "alwaysOn 不可关闭"}
    with _LEVEL_LOCK:
        _STATE["levels"][name] = bool(value)
        val = bool(value)
        # 主开关：用户态防护。running 完全由主开关决定，避免与监控线程状态错位。
        if name == LEVEL_USERMODE and val:
            if not _STATE["running"]:
                _STATE["running"] = True
                _STATE["started_at"] = time.time()
                _setup_all_monitors()
                defense_set_driver_enabled(_STATE["levels"].get(LEVEL_DRIVER))
            return {"ok": True, "level": name, "value": True, "running": True}
        if not _STATE["levels"].get(LEVEL_USERMODE):
            # 主开关关闭：停止整条防护链（running=False 后 _setup_all_monitors 会全停）。
            _STATE["running"] = False
            _STATE["finished_at"] = time.time()
            _setup_all_monitors()
            return {"ok": True, "level": name, "value": False, "running": False}
        # 主开关开启：针对变化项精确对账，立即生效（无需重启）。
        _setup_all_monitors()
        if name == LEVEL_DRIVER:
            defense_set_driver_enabled(val)
        return {"ok": True, "level": name, "value": val}


def defense_get_level(name=None):
    with _LEVEL_LOCK:
        if name:
            return _STATE["levels"].get(name)
        return dict(_STATE["levels"])


def defense_set_levels(payload):
    if not isinstance(payload, dict):
        return {"error": "参数必须是 dict"}
    with _LEVEL_LOCK:
        for key, value in payload.items():
            if key in ALL_LEVELS and key != LEVEL_ALWAYS:
                _STATE["levels"][key] = bool(value)
        user_mode = _STATE["levels"].get(LEVEL_USERMODE)
        if user_mode and not _STATE["running"]:
            _STATE["running"] = True
            _STATE["started_at"] = time.time()
    # 在锁外执行监控对账与驱动，避免重入
    if _STATE["levels"].get(LEVEL_USERMODE):
        _setup_all_monitors()
        defense_set_driver_enabled(_STATE["levels"].get(LEVEL_DRIVER))
    else:
        _STATE["running"] = False
        _teardown_all_monitors()
    if LEVEL_DRIVER in payload:
        defense_set_driver_enabled(bool(payload[LEVEL_DRIVER]))
    return {"ok": True, "levels": defense_get_level()}

########################################接口层 DRAGON_API########################################

def defense_status():
    with _LEVEL_LOCK:
        levels = dict(_STATE["levels"])
    return {
        "running": _STATE["running"],
        "levels": levels,
        "started_at": _STATE["started_at"],
        "finished_at": _STATE["finished_at"],
        "static_last_run": _STATE["static_last_run"],
        "engine_prepare": engine_prepare(),
        "driver_connected": driver_connected(),
        "driver_reboot_required": _DRIVER_REBOOT_REQUIRED,
    }


def defense_register_push(func):
    return _register_push("defense_event", func)


def defense_kill_tree(pid, reason="manual"):
    killed = kill_tree(int(pid), reason=reason)
    safe_log("主动防御拦截", "pid={} 已被手动处置({})".format(pid, reason))
    toast("主动防御拦截", "pid={} 已被手动处置({})".format(pid, reason))
    return {"ok": True, "killed": killed}


def defense_static_scan_now(targets=None):
    return static_scan_now(targets=targets)


def _setup_all_monitors():
    """按当前 running + levels 精确对账各监控线程的启动/停止（幂等，可重复调用）。

    关键修复（根治"开关玄学"）：
    1. 不再以 running 作为早退条件——否则 running 与监控线程状态短暂错位时，
       后续开关操作会空跑、表现为"有时好使有时不好使"。
    2. 每一项都显式 start（若应开启且未运行）或 stop（若应关闭），保证
       后端实际监控状态永远 == 前端开关应有的状态。
    """
    levels = _STATE["levels"]
    running = _STATE["running"]
    # 用户态防护：进程监控
    if running and levels.get(LEVEL_USERMODE):
        start_process_monitor(driver_hook=_defense_hook_process_event)
    else:
        stop_process_monitor()
    # 文件实时监控
    if running and levels.get(LEVEL_REALTIME):
        start_file_monitor()
    else:
        stop_file_monitor()
    # 压缩包标记：仅运行时常驻
    if running:
        start_archive_monitor()
    else:
        stop_archive_monitor()
    # 关键位置保护：注册表 + 引导区 + 自保护
    if running and levels.get(LEVEL_KEYPOSITIONS):
        start_registry_monitor(driver_hook=_defense_hook_registry_write)
        start_boot_monitor()
        start_self_monitor()
    else:
        stop_registry_monitor()
        stop_boot_monitor()
        stop_self_monitor()
    # 实时监控衍生：网络 + 内存 + 勒索诱捕
    if running and levels.get(LEVEL_REALTIME):
        start_network_monitor(driver_hook=_defense_hook_process_event)
        start_memory_monitor()
        start_decoy_monitor()
    else:
        stop_network_monitor()
        stop_memory_monitor()
        stop_decoy_monitor()
    # 静态轮询扫描
    if running and levels.get(LEVEL_STATIC_POLL):
        start_static_monitor()
    else:
        stop_static_monitor()


def _teardown_all_monitors():
    stop_process_monitor()
    stop_file_monitor()
    stop_registry_monitor()
    stop_boot_monitor()
    stop_self_monitor()
    stop_network_monitor()
    stop_memory_monitor()
    stop_archive_monitor()
    stop_decoy_monitor()
    stop_static_monitor()


def defense_install_hooks():
    with _LEVEL_LOCK:
        if _STATE["running"]:
            return {"ok": True, "already_running": True}
        if not _STATE["levels"].get(LEVEL_USERMODE):
            return {"ok": False, "error": "总开关未启用"}
        _STATE["running"] = True
        _STATE["started_at"] = time.time()
    _setup_all_monitors()
    defense_set_driver_enabled(_STATE["levels"].get(LEVEL_DRIVER))
    return {"ok": True, "running": True}


def defense_stop_hooks():
    # 先断开内核驱动（停止监听线程 + 断端口），再拆除用户态监控
    try:
        import Dragon_Drivers as drv
        drv.driver_disconnect()
    except Exception:
        pass
    try:
        defense_register_driver_hook(None)
    except Exception:
        pass
    # 彻底拆除所有用户态监控线程（含 RDCW 文件监控），避免退出时线程残留/累积
    try:
        _teardown_all_monitors()
    except Exception:
        log_exception("defense.teardown")
    with _LEVEL_LOCK:
        if not _STATE["running"]:
            return {"ok": True, "already_stopped": True}
        _STATE["running"] = False
        _STATE["finished_at"] = time.time()
    _teardown_all_monitors()
    return {"ok": True, "running": False}

########################################启动与提权 FIRST_RUN########################################

_shell32 = None


def _ensure_shell32():
    global _shell32
    if _shell32 is not None:
        return _shell32
    try:
        _shell32 = ctypes.windll.shell32
        return _shell32
    except Exception as exc:
        defender_log("shell32_load_failed", str(exc))
        return None


def is_admin():
    s = _ensure_shell32()
    if s is None:
        return False
    try:
        return bool(s.IsUserAnAdmin())
    except Exception:
        return False


def _apply_directory_dacl(path):
    try:
        cmd = ["icacls", path, "/inheritance:r", "/grant:r",
               "Administrators:(OI)(CI)F", "SYSTEM:(OI)(CI)F",
               "Users:(OI)(CI)R"]
        subprocess.run(cmd, capture_output=True, timeout=10, check=False)
        return True
    except Exception as exc:
        defender_log("acl_failed", "{}: {}".format(path, exc))
        return False


def install_persistence():
    name_boot = "DragonDefenderBootBackup"
    name_start = "DragonDefenderStartup"
    commands = [
        ["schtasks", "/Create", "/SC", "ONLOGON", "/TN", name_boot,
         "/TR", '"{}" defense_first_run'.format(sys.executable), "/F", "/RL", "HIGHEST"],
        ["schtasks", "/Create", "/SC", "ONSTART", "/TN", name_start,
         "/TR", '"{}" defense_first_run'.format(sys.executable), "/F", "/RL", "HIGHEST"],
    ]
    results = []
    for cmd in commands:
        try:
            completed = subprocess.run(cmd, capture_output=True, timeout=15, check=False)
            results.append({"cmd": " ".join(cmd), "code": completed.returncode})
        except Exception as exc:
            results.append({"cmd": " ".join(cmd), "error": str(exc)})
    return results


def apply_acls():
    directories = [DATA_DIR, QUARANTINE_DIR, BASELINE_DIR, BOOT_BACKUP_DIR]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        _apply_directory_dacl(directory)
    return {"ok": True, "directories": directories}


def defense_first_run():
    if not is_admin():
        return {"ready": False, "error": "请以管理员权限运行"}
    backup_result = backup_all_boot_sectors()
    baseline_result = _build_baseline()
    decoys = build_all_decoys()
    acls = apply_acls()
    persistence = install_persistence()
    _load_baseline()
    return {
        "ready": True,
        "boot_backup": len(backup_result),
        "baseline_files": len(baseline_result),
        "decoys": len(decoys),
        "acls": acls,
        "persistence": persistence,
    }

########################################主入口########################################

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    if not target:
        print(json.dumps(defense_status(), ensure_ascii=False, indent=1))
    elif target == "first_run":
        print(json.dumps(defense_first_run(), ensure_ascii=False, indent=1))
    elif target == "install":
        print(json.dumps(defense_install_hooks(), ensure_ascii=False, indent=1))
    elif target == "stop":
        print(json.dumps(defense_stop_hooks(), ensure_ascii=False, indent=1))
    elif target == "static":
        targets = [arg for arg in sys.argv[2:] if arg.strip()]
        print(json.dumps(static_scan_now(targets=targets or None), ensure_ascii=False, indent=1))
    elif target == "status":
        print(json.dumps(defense_status(), ensure_ascii=False, indent=1))
    elif target == "level":
        if len(sys.argv) >= 4:
            value = sys.argv[3].lower() in ("1", "true", "on", "yes")
            print(json.dumps(defense_set_level(sys.argv[2], value), ensure_ascii=False, indent=1))
        else:
            print(json.dumps(defense_get_level(sys.argv[2] if len(sys.argv) >= 3 else None),
                             ensure_ascii=False, indent=1))
    else:
        print(json.dumps({"error": "未知命令：{}".format(target)}, ensure_ascii=False, indent=1))