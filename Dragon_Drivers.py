# -*- coding: utf-8 -*-
"""天龙神盾安全中心 —— 内核驱动对接模块。

封装与 Dragon-Drivers（KMDF + minifilter）内核驱动的用户态通信：

  · 服务就绪：已安装的前提下按需 StartService
  · 端口连接/断开（\\DragonGuard_Event_Port，ConnectionContext 握手）
  · 下发命令：加载规则 / 白名单增删 / 授权卸载 / 勒索恢复 / 查询状态与指标
  · 异步监听内核上报事件并转发给上层回调（内核已处置，用户态不再二次处置）
  · 连接状态变化推送前端（dragon_set_push 契约，供首页驱动状态呈现）

内核侧已完成拦截/终止，用户态只做可见性与遥测。

依赖：dragon_client（随 Dragon-Drivers/tools 一并打包到 exe 根目录）。
"""

import ctypes
import ctypes.wintypes
import os
import shutil
import subprocess
import sys
import threading

########################################客户端可达性########################################

_HAVE_CLIENT = False
_DragonClient = None
_CMD = {}
_RansomStatus = None
_Metrics = None
_RestoreReply = None
_StateReply = None


def _ensure_client_importable():
    """把随 exe 打包的 Dragon-Drivers/tools 加进 sys.path，使 `import dragon_client` 可达。"""
    try:
        import dragon_client  # noqa: F401
        return True
    except Exception:
        pass
    base = os.path.dirname(os.path.abspath(
        sys.executable if getattr(sys, "frozen", False) else __file__))
    for sub in ("Dragon_Drivers", "Dragon-Drivers"):
        for leaf in ("tools",):
            cand = os.path.join(base, sub, leaf)
            if os.path.isdir(cand) and cand not in sys.path:
                sys.path.insert(0, cand)
    try:
        import dragon_client  # noqa: F401
        return True
    except Exception:
        return False


try:
    _ensure_client_importable()
    import dragon_client as _dc  # type: ignore
    _HAVE_CLIENT = True
    _DragonClient = _dc.DragonClient
    _CMD = {
        "ADD_WHITELIST": _dc.CMD_ADD_WHITELIST,
        "REMOVE_WHITELIST": _dc.CMD_REMOVE_WHITELIST,
        "LOAD_RULE_FILE": _dc.CMD_LOAD_RULE_FILE,
        "CLEAR_RULES": _dc.CMD_CLEAR_RULES,
        "AUTHORIZE_UNLOAD": _dc.CMD_AUTHORIZE_UNLOAD,
        "QUERY_STATE": _dc.CMD_QUERY_STATE,
        "QUERY_RANSOM": _dc.CMD_QUERY_RANSOM,
        "RESTORE_FILES": _dc.CMD_RESTORE_FILES,
        "QUERY_METRICS": _dc.CMD_QUERY_METRICS,
        "RESTORE_ROLLBACK": _dc.RESTORE_MODE_ROLLBACK,
        "RESTORE_RELEASE": _dc.RESTORE_MODE_RELEASE,
    }
    _RansomStatus = getattr(_dc, "RansomStatus", None)
    _Metrics = getattr(_dc, "Metrics", None)
    _RestoreReply = getattr(_dc, "RestoreReply", None)
    _StateReply = getattr(_dc, "StateReply", None)
except Exception:
    _HAVE_CLIENT = False


########################################前端播报契约########################################

_PUSH_FUNC = None
_LOCK = threading.RLock()

# 驱动事件监听线程状态
_CLIENT = None
_LISTEN_THREAD = None
_LISTEN_STOP = threading.Event()
_CONNECTED = False
_ON_EVENT = None

SERVICE_NAME = "Dragon-Drivers"

# 驱动镜像/规则文件（交付目录优先下划线，工程目录用连字符）
_DRIVER_SYS_NAMES = ("Dragon_Drivers.sys", "Dragon-Drivers.sys")
_RULES_REL = os.path.join("Rules", "DragonDriver_DefenderRules.json")


def dragon_set_push(func):
    """bind_module_push 契约：接收主程序推送函数，用于把驱动状态变化发到前端。"""
    global _PUSH_FUNC
    _PUSH_FUNC = func
    return {"ok": True}


def _push(channel, data):
    func = _PUSH_FUNC
    if not func:
        return False
    try:
        func(channel, data)
        return True
    except Exception:
        return False


########################################路径定位########################################

def locate():
    """定位驱动镜像与规则文件，返回 {dir, sys, rules}。"""
    base = os.path.dirname(os.path.abspath(
        sys.executable if getattr(sys, "frozen", False) else __file__))
    for sub in ("Dragon_Drivers", "Dragon-Drivers"):
        d = os.path.join(base, sub)
        if not os.path.isdir(d):
            continue
        sys_path = None
        for name in _DRIVER_SYS_NAMES:
            cand = os.path.join(d, name)
            if os.path.isfile(cand):
                sys_path = cand
                break
        rules = os.path.join(d, _RULES_REL)
        return {
            "dir": d,
            "sys": sys_path,
            "rules": rules if os.path.isfile(rules) else None,
        }
    return {"dir": None, "sys": None, "rules": None}


########################################服务就绪（SCM）########################################

_advapi = None


def _init_advapi():
    global _advapi
    if _advapi is not None:
        return _advapi
    try:
        adv = ctypes.windll.advapi32
        adv.OpenSCManagerW.restype = ctypes.c_void_p
        adv.OpenSCManagerW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        adv.OpenServiceW.restype = ctypes.c_void_p
        adv.OpenServiceW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
        adv.CloseServiceHandle.restype = ctypes.c_int
        adv.CloseServiceHandle.argtypes = [ctypes.c_void_p]
        adv.QueryServiceStatus.restype = ctypes.c_int
        adv.QueryServiceStatus.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        adv.StartServiceW.restype = ctypes.c_int
        adv.StartServiceW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
        _advapi = adv
        return adv
    except Exception:
        _advapi = False
        return None


class _SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", ctypes.c_uint32),
        ("dwCurrentState", ctypes.c_uint32),
        ("dwControlsAccepted", ctypes.c_uint32),
        ("dwWin32ExitCode", ctypes.c_uint32),
        ("dwServiceSpecificExitCode", ctypes.c_uint32),
        ("dwCheckPoint", ctypes.c_uint32),
        ("dwWaitHint", ctypes.c_uint32),
    ]


_SERVICE_STATE_NAMES = {
    1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING",
    4: "RUNNING", 5: "CONTINUE_PENDING", 6: "PAUSE_PENDING", 7: "PAUSED",
}


def _service_state():
    """返回 (状态名, 状态码)；未安装/打开失败返回 ('NOT_INSTALLED', 0)。"""
    adv = _init_advapi()
    if adv is None:
        return "NOT_INSTALLED", 0
    scm = adv.OpenSCManagerW(None, None, 0x0001)
    if not scm:
        return "NOT_INSTALLED", 0
    try:
        svc = adv.OpenServiceW(scm, SERVICE_NAME, 0x0004)
        if not svc:
            return "NOT_INSTALLED", 0
        try:
            st = _SERVICE_STATUS()
            if not adv.QueryServiceStatus(svc, ctypes.byref(st)):
                return "UNKNOWN", 0
            return _SERVICE_STATE_NAMES.get(st.dwCurrentState, "0x%X" % st.dwCurrentState), st.dwCurrentState
        finally:
            adv.CloseServiceHandle(svc)
    finally:
        adv.CloseServiceHandle(scm)


def ensure_service_running():
    """已安装的前提下，若驱动服务未运行则尝试 StartService。失败不抛异常，仅记录。"""
    adv = _init_advapi()
    if adv is None:
        return False
    scm = adv.OpenSCManagerW(None, None, 0x0001)
    if not scm:
        return False
    try:
        svc = adv.OpenServiceW(scm, SERVICE_NAME, 0x0004 | 0x0010)
        if not svc:
            return False
        try:
            st = _SERVICE_STATUS()
            if adv.QueryServiceStatus(svc, ctypes.byref(st)) and st.dwCurrentState == 4:
                return True
            return bool(adv.StartServiceW(svc, 0, None))
        finally:
            adv.CloseServiceHandle(svc)
    except Exception:
        return False
    finally:
        adv.CloseServiceHandle(scm)


########################################安装 / 加载（开箱即用）########################################
# 让「驱动防护」开关一键完成：安装服务 → 登记客户端 → 启动 → 连接。
# 本项目驱动镜像带正规代码签名，正常 DSE 模式下可直接加载——不做任何签名检测、
# 不改动 bcdedit / 内核完整性检查策略，装载失败直接把错误返回给上层重试。

_SYSTEM_DRIVERS = r"C:\Windows\System32\drivers"
_INSTALLED_NAME = "Dragon-Drivers.sys"
_DRIVER_ALTITUDE = "328900"
_DRIVER_LOAD_GROUP = "FSFilter Anti-Virus"
_DRIVER_SERVICE_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\Dragon-Drivers"


def _has_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:  # noqa: BLE001
        return -1, str(exc)


def _nt_path_of(dos_path):
    """DOS 路径 -> NT 设备路径。驱动用 SeLocateProcessImageName 取发起进程映像名并做全等比对，
    该名称是设备路径形式（\\Device\\HarddiskVolumeN\\...），故登记值必须同形。"""
    if not dos_path:
        return None
    if dos_path.startswith("\\\\Device\\"):
        return dos_path
    raw = dos_path[4:] if dos_path.startswith("\\\\??\\") else dos_path
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.restype = ctypes.c_void_p
        k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                    ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p]
        k32.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
        k32.GetFinalPathNameByHandleW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                                  ctypes.c_uint32, ctypes.c_uint32]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = k32.CreateFileW(raw, 0, 0x7, None, 3, 0x80, None)
        if not handle or handle == ctypes.c_void_p(-1).value:
            return None
        try:
            buf = ctypes.create_unicode_buffer(1024)
            length = k32.GetFinalPathNameByHandleW(handle, buf, 1024, 0x00000002)
            if length == 0 or length >= 1024:
                return None
            return buf.value
        finally:
            k32.CloseHandle(handle)
    except Exception:
        return None


def _install_service(exe_path):
    """把驱动镜像/规则拷到 System32\\drivers 并创建 minifilter 服务。幂等。"""
    info = locate()
    src = info.get("sys")
    if not src or not os.path.isfile(src):
        return False, "未找到驱动镜像（Dragon_Drivers/Dragon_Drivers.sys）"
    if _service_state()[1] == 4:
        return True, "already_running"
    try:
        os.makedirs(_SYSTEM_DRIVERS, exist_ok=True)
        target = os.path.join(_SYSTEM_DRIVERS, _INSTALLED_NAME)
        shutil.copy2(src, target)
    except Exception as exc:  # noqa: BLE001
        return False, "复制驱动镜像失败：%s" % exc
    rules_src = os.path.join(os.path.dirname(src), "Rules")
    if os.path.isdir(rules_src):
        try:
            os.makedirs(os.path.join(_SYSTEM_DRIVERS, "Rules"), exist_ok=True)
            for f in os.listdir(rules_src):
                if f.endswith(".json"):
                    shutil.copy2(os.path.join(rules_src, f),
                                 os.path.join(_SYSTEM_DRIVERS, "Rules", f))
        except Exception:
            pass
    bin_path = target if " " not in target else '"%s"' % target
    _run(["sc", "create", SERVICE_NAME, "type=", "filesys", "binPath=", bin_path,
          "start=", "demand", "error=", "normal", "group=", _DRIVER_LOAD_GROUP,
          "depend=", "FltMgr", "DisplayName=", SERVICE_NAME])
    # minifilter 实例键：Windows 11 24H2 起位置变更，两处都写，FltMgr 各取所需
    for base in (_DRIVER_SERVICE_KEY + r"\Instances",
                 _DRIVER_SERVICE_KEY + r"\Parameters\Instances"):
        _run(["reg", "add", base, "/v", "DefaultInstance", "/t", "REG_SZ",
              "/d", "Dragon Instance", "/f"])
        inst = base + r"\Dragon Instance"
        _run(["reg", "add", inst, "/v", "Altitude", "/t", "REG_SZ", "/d", _DRIVER_ALTITUDE, "/f"])
        _run(["reg", "add", inst, "/v", "Flags", "/t", "REG_DWORD", "/d", "0", "/f"])
    _run(["reg", "add", _DRIVER_SERVICE_KEY + r"\Parameters", "/v", "SupportedFeatures",
          "/t", "REG_DWORD", "/d", "3", "/f"])
    # 登记客户端镜像路径（NT 形式），否则驱动拒绝一切端口连接
    client = exe_path or sys.executable
    nt = _nt_path_of(client)
    if nt:
        _run(["reg", "add", _DRIVER_SERVICE_KEY + r"\Parameters", "/v", "ClientImagePath",
              "/t", "REG_SZ", "/d", nt, "/f"])
    return True, "installed"


def driver_install(exe_path=None):
    """安装驱动服务（开箱即用）。

    本项目驱动镜像带正规代码签名，正常 DSE 模式下直接加载——不做任何签名检测、
    不调用 _driver_is_ms_cross_signed / _no_integrity_enabled 之类的签名或内核完整性
    判定，也不改动 bcdedit / 内核完整性检查策略。装载失败仅把错误返回给上层，由上层
    （主动防御界面底部弹窗）提示用户关闭安全启动或重启系统后重试。
    """
    if not _has_admin():
        return {"ok": False, "error": "需要管理员权限才能安装内核驱动"}
    ok, msg = _install_service(exe_path)
    if not ok:
        return {"ok": False, "error": msg, "reboot_required": False}
    return {"ok": True, "installed": True, "reboot_required": False}


def driver_enable(on_event=None, exe_path=None, load_rules=True):
    """开箱即用入口：安装(如需) → 启动 → 连接。返回 dict（含 connected / reboot_required）。"""
    if not _HAVE_CLIENT or _DragonClient is None:
        return {"ok": False, "connected": False, "error": "驱动客户端不可用（dragon_client 未打包）"}
    if not _has_admin():
        return {"ok": False, "connected": False, "error": "需要管理员权限"}
    res = driver_install(exe_path)
    if not res.get("ok"):
        return {"ok": False, "connected": False, "error": res.get("error"),
                "reboot_required": res.get("reboot_required", False)}
    if res.get("reboot_required"):
        return {"ok": True, "connected": False, "reboot_required": True, "note": res.get("note")}
    with _LOCK:
        if _CONNECTED:
            return {"ok": True, "connected": True, "reboot_required": False}
    connected = driver_connect(on_event=on_event, load_rules=load_rules)
    return {"ok": True, "connected": bool(connected), "reboot_required": False}


########################################规则下发########################################

def _load_rules(client):
    info = locate()
    rules = info.get("rules")
    if not rules:
        return False
    nt_path = os.path.abspath(rules)
    if not nt_path.startswith("\\\\?\\"):
        nt_path = "\\??\\" + nt_path
    try:
        client.send_command(_CMD["LOAD_RULE_FILE"], nt_path)
        return True
    except Exception:
        return False


########################################事件转发########################################

def _forward(code, action, pid, path):
    cb = _ON_EVENT
    if callable(cb):
        try:
            cb(code, action, pid, path)
        except Exception:
            pass


def _listen_loop():
    global _CONNECTED
    client = _CLIENT
    if client is None:
        return
    try:
        client.listen(stop_flag=lambda: _LISTEN_STOP.is_set(), on_event=_forward)
    except Exception:
        pass
    finally:
        with _LOCK:
            _CONNECTED = False
            _push("driver_status", {"connected": False})


########################################连接 / 断开########################################

# 系统关键进程信任白名单：这些进程的「正常行为」不应被内核规则判为攻击
# （例：事件日志服务 svchost 正常写 winevt\Logs 的 .evtx；服务控制管理器
#  services.exe 访问 svchost）。与用户态 R3 的 PROCESS_RULES["whitelist"] 对齐，
# 按「完整目录前缀」下发（*\\System32\\<name>），避免同名恶意程序被误信。
_TRUSTED_SYSTEM_IMAGES = (
    "*\\System32\\smss.exe",
    "*\\System32\\csrss.exe",
    "*\\System32\\wininit.exe",
    "*\\System32\\winlogon.exe",
    "*\\System32\\services.exe",
    "*\\System32\\lsass.exe",
    "*\\System32\\svchost.exe",
    "*\\System32\\dwm.exe",
    "*\\System32\\audiodg.exe",
    "*\\System32\\fontdrvhost.exe",
    "*\\System32\\ctfmon.exe",
    "*\\System32\\sihost.exe",
    "*\\System32\\RuntimeBroker.exe",
    "*\\System32\\SearchIndexer.exe",
    "*\\System32\\WerFault.exe",
    "*\\System32\\WmiPrvSE.exe",
    "*\\System32\\taskhostw.exe",
    "*\\System32\\conhost.exe",
    "*\\System32\\dllhost.exe",
    "*\\System32\\LsaIso.exe",
    "*\\System32\\spoolsv.exe",
    "*\\System32\\W32Time.exe",
    "*\\System32\\Wcmsvc.exe",
    "*\\System32\\WaaSMedicSvc.exe",
)


def _seed_trusted_whitelist():
    """把系统关键进程下发到内核信任白名单（幂等；连接成功后调用）。

    内核侧 DragonIsProcessTrusted 会据此放行这些进程发起的操作，避免把
    「事件日志服务写日志」「服务控制管理器访问 svchost」这类正常系统行为
    误判成攻击并刷屏。"""
    seeded = 0
    for pattern in _TRUSTED_SYSTEM_IMAGES:
        try:
            if driver_add_whitelist(pattern):
                seeded += 1
        except Exception:
            pass
    return seeded


def driver_connect(on_event=None, load_rules=True):
    """连接内核驱动：确保服务运行 → 握手连接 → 下发规则 → 启动监听线程。

    返回 bool（是否成功连接）。连接失败（驱动未装/未授权/签名策略未生效）时安全降级返回 False。
    """
    global _CLIENT, _LISTEN_THREAD, _LISTEN_STOP, _CONNECTED, _ON_EVENT
    if not _HAVE_CLIENT or _DragonClient is None:
        return False
    with _LOCK:
        if _CONNECTED:
            return True
        _ON_EVENT = on_event
        _LISTEN_STOP = threading.Event()
    ensure_service_running()
    try:
        client = _DragonClient()
        if not client.connect():
            return False
        _CLIENT = client
    except Exception:
        return False
    if load_rules:
        try:
            _load_rules(client)
        except Exception:
            pass
    t = threading.Thread(target=_listen_loop, name="dragon-driver-listen", daemon=True)
    t.start()
    _LISTEN_THREAD = t
    with _LOCK:
        _CONNECTED = True
        _push("driver_status", {"connected": True})
    _seed_trusted_whitelist()
    return True


def driver_disconnect():
    """停止监听线程并断开端口。幂等，可重复调用。"""
    global _CLIENT, _LISTEN_THREAD, _CONNECTED
    with _LOCK:
        _LISTEN_STOP.set()
    thread = _LISTEN_THREAD
    if thread is not None:
        try:
            thread.join(timeout=2)
        except Exception:
            pass
    with _LOCK:
        _LISTEN_THREAD = None
    client = _CLIENT
    if client is not None:
        try:
            client.disconnect()
        except Exception:
            pass
        _CLIENT = None
    _CONNECTED = False
    _push("driver_status", {"connected": False})
    return True


def driver_connected():
    return _CONNECTED


def driver_available():
    return _HAVE_CLIENT


def driver_status():
    return {
        "connected": _CONNECTED,
        "have_client": _HAVE_CLIENT,
        "service": _service_state()[0],
    }


########################################命令封装########################################

def _cmd(command, path="", argument=0, want_reply=False, reply_type=None):
    if not _CONNECTED or _CLIENT is None:
        return None
    try:
        return _CLIENT.send_command(command, path, argument, want_reply, reply_type)
    except Exception:
        return None


def driver_load_rules():
    if _CLIENT is None:
        return False
    return _load_rules(_CLIENT)


def driver_add_whitelist(pattern):
    return _cmd(_CMD["ADD_WHITELIST"], pattern) is not None


def driver_remove_whitelist(pattern):
    return _cmd(_CMD["REMOVE_WHITELIST"], pattern) is not None


def driver_clear_rules():
    return _cmd(_CMD["CLEAR_RULES"]) is not None


def driver_authorize_unload():
    return _cmd(_CMD["AUTHORIZE_UNLOAD"]) is not None


def driver_query_state():
    return _cmd(_CMD["QUERY_STATE"], want_reply=True, reply_type=_StateReply)


def driver_query_ransom():
    if _RansomStatus is None:
        return None
    return _cmd(_CMD["QUERY_RANSOM"], want_reply=True, reply_type=_RansomStatus)


def driver_query_metrics():
    if _Metrics is None:
        return None
    return _cmd(_CMD["QUERY_METRICS"], want_reply=True, reply_type=_Metrics)


def driver_restore_files(path="", release=False):
    """从勒索备份恢复（rollback）或仅解除阻断（release）。返回 RestoreReply 或 None。"""
    if _RestoreReply is None:
        return None
    mode = _CMD["RESTORE_RELEASE"] if release else _CMD["RESTORE_ROLLBACK"]
    return _cmd(_CMD["RESTORE_FILES"], path, argument=mode, want_reply=True, reply_type=_RestoreReply)


########################################主入口########################################

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="天龙神盾 内核驱动对接（调试用）")
    parser.add_argument("--state", action="store_true", help="查询驱动状态")
    parser.add_argument("--service", action="store_true", help="查询服务状态")
    parser.add_argument("--connect", action="store_true", help="连接并监听事件")
    parser.add_argument("--metrics", action="store_true", help="查询诊断统计")
    parser.add_argument("--ransom", action="store_true", help="查询勒索防护状态")
    args = parser.parse_args()

    if args.service:
        name, code = _service_state()
        print("[服务] %s (0x%X)" % (name, code))
    if args.state:
        rep = driver_query_state()
        print("[状态] %r" % rep)
    if args.ransom:
        print("[勒索] %r" % driver_query_ransom())
    if args.metrics:
        print("[指标] %r" % driver_query_metrics())
    if args.connect:
        def _print_event(code, action, pid, path):
            print("[EVENT] code=%s action=%s pid=%s path=%s" % (code, action, pid, path))
        print("[INFO] 连接驱动并监听事件（Ctrl+C 退出）...")
        if driver_connect(on_event=_print_event):
            try:
                while True:
                    threading.Event().wait(1)
            except KeyboardInterrupt:
                driver_disconnect()
                print("\n[INFO] 已断开")
        else:
            print("[ERR] 连接失败")
    elif not any([args.service, args.state, args.ransom, args.metrics]):
        parser.print_help()
