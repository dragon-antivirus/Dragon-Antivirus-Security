#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dragon-Drivers 部署脚本
=========================================================================
把产物安装为内核过滤驱动服务，或卸载/查询状态。

!! 高权限操作警告 !!
  本脚本会：
    · 向 C:\\Windows\\System32\\drivers\\Rules 写入规则文件；
    · 创建 / 删除内核服务 Dragon-Drivers 及其 Instances 注册表项；
    · 可选修改启动配置以放行内核驱动（见下「签名策略」）。
  每一步系统级变更都需要显式传入 --yes，不做静默执行。

签名策略（load_driver.py 会自动选择，也可手动指定）——
  x64 Windows 只允许「微软认可签名」的内核驱动加载。分两种情况：

  0) **正规 EV 代码签名 + 微软交叉签名**（本项目的 Dragon_Drivers.sys 即此类）：
     证书链形如  <你的 EV 证书> → <代码签名 CA> → Microsoft Code Verification Root，
     并带 RFC3161 时间戳。这类镜像**已经是「微软认可签名」**，正常 DSE 模式
     （DSE 开、Secure Boot 开、HVCI 开、测试模式关）下 StartService 直接加载，
     **不需要测试模式、不需要 nointegritychecks、不需要重启**。下面 A/B 都不适用。

  1) 自签 / 未签名驱动（dev 调试用）：只有两条路，**都必须改启动配置并重启一次**：

    A) --enable-nointegritychecks   bcdedit /set nointegritychecks on
       · 关闭完整性检查，**不进入测试模式、没有桌面水印**；
       · 连完全未签名的驱动也放行；
       · 要求安全启动已关闭；微软文档标注「不应使用」。

    B) --enable-testsigning         bcdedit /set testsigning on
       · 进入测试模式（右下角有水印），放行受本机信任根签过的镜像；
       · 要求安全启动已关闭；比 A 更"正规"，兼容性最好。

  注：上面 A/B 的测试模式 / nointegritychecks 配置在**开机时读取**，运行期
  无法从用户态改变 —— 所以对自签 / 未签名驱动，"零重启加载"在不借助内核漏洞
  （BYOVD / CI 绕过）的前提下不存在，本脚本不做那种事。而情况 0 的正规交叉签名
  驱动本就在 DSE 认可列表内，StartService 即可加载，与上述配置无关。

用法：
    python deploy_dragon.py --status
    python deploy_dragon.py --install  --yes
    python deploy_dragon.py --install --from "D:\\Dragon-Antivirus\\Dragon_Drivers" --yes
    python deploy_dragon.py --install --inplace --no-rules --yes
    python deploy_dragon.py --set-client "C:\\Tools\\DragonAgent.exe" --yes
    python deploy_dragon.py --set-guard-paths "C:\\App\\Main.exe;C:\\App\\data\\*" --yes
    python deploy_dragon.py --start | --stop
    python deploy_dragon.py --uninstall --yes
    python deploy_dragon.py --enable-nointegritychecks --yes
    python deploy_dragon.py --revert-signing --yes

关于 --set-guard-paths（主程序 / 主程序外置文件保护清单）：
    内置自保护除硬编码的「驱动镜像 / 规则目录 / 服务键」外，还会保护注册表
    Parameters\\GuardPaths 列出的路径。清单条目为 NT 路径或通配符模式，
    支持两种写法：
        C:\\Program Files\\Dragon\\Dragon-Antivirus.exe   （具体文件）
        C:\\Program Files\\Dragon\\*                      （整个目录）
        *\\Dragon-Antivirus\\*                            （不限卷）
    多条用分号分隔。清单在驱动启动时读取；**驱动运行期间自保护会拦住对该服务
    键的写入**，所以修改清单同样需要「先停驱动」（用 --authorize-unload + --stop）。
"""

from __future__ import annotations

import argparse
import ctypes
import shutil
import subprocess
import sys
import time
from pathlib import Path

SERVICE_NAME = "Dragon-Drivers"
DRIVER_FILE = "Dragon-Drivers.sys"
RULE_FILE_NAME = "DragonDriver_DefenderRules.json"
SERVICE_KEY = rf"HKLM\SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}"
DRIVERS_DIR = Path(r"C:\Windows\System32\drivers")
RULE_DIR = DRIVERS_DIR / "Rules"
ALTITUDE = "328900"
# 328900 落在 FSFilter Anti-Virus 官方区间 (320000-329999) 内，
# 本驱动是杀毒/安全类微过滤器，必须归属该组；Group 与 Altitude 必须对应。
LOAD_ORDER_GROUP = "FSFilter Anti-Virus"
ALTITUDE_RANGES = {
    "FSFilter Top": (400000, 409999),
    "FSFilter Activity Monitor": (360000, 389999),
    "FSFilter Undelete": (340000, 349999),
    "FSFilter Anti-Virus": (320000, 329999),
    "FSFilter Replication": (300000, 309999),
    "FSFilter Continuous Backup": (280000, 289999),
    "FSFilter Content Screener": (260000, 269999),
    "FSFilter Encryption": (140000, 149999),
    "FSFilter Security Enhancer": (80000, 89999),
}

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
OUT_DIR = PROJECT_DIR / "out"

# 交付目录：与工程目录并列（D:\Dragon-Antivirus\Dragon_Drivers）。
# 成品在那里用**下划线**命名；构建产物在 out\ 用连字符命名 —— 两种都接受。
DELIVERY_DIR = PROJECT_DIR.parent / "Dragon_Drivers"
SOURCE_FILE_NAMES = ("Dragon_Drivers.sys", "Dragon-Drivers.sys")

# 安装时使用的文件名（落在 DRIVERS_DIR 下），保持工程一贯的连字符命名
INSTALLED_FILE_NAME = DRIVER_FILE


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def require_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def run(command: list[str], check: bool = False) -> tuple[int, str]:
    completed = subprocess.run(command, capture_output=True, text=True, errors="replace")
    output = ((completed.stdout or "") + (completed.stderr or "")).strip()
    if check and completed.returncode != 0:
        raise RuntimeError(f"命令失败 ({completed.returncode}): {' '.join(command)}\n{output}")
    return completed.returncode, output


def powershell(script: str) -> str:
    """执行一段 PowerShell 并返回输出（仅用于只读查询）。

    受限环境（沙箱禁用 powershell.exe 子进程）下 CreateProcess 会抛 PermissionError，
    这里兜底返回空串，不让任何调用点崩溃——诊断信息缺这一项而已，其余照常。
    """
    try:
        _, output = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
    except Exception:  # noqa: BLE001
        return ""
    return output


# --------------------------------------------------------------------------
# 服务控制：直接调用 SCM API，不派发 sc.exe
#
# 为什么不能派发 sc.exe ——
#   规则包 1005「命令行停用或删除本产品防护服务」匹配的是
#       *sc stop Dragon-Drivers* / *sc delete Dragon-Drivers* / *fltmc unload Dragon-Drivers*
#   这类**命令行**，动作是 Terminate，且判定发生在**进程创建**阶段。后果有两个：
#     1. sc.exe 根本创建不出来（CreationStatus = ACCESS_DENIED），命令必然失败；
#     2. 紧接着终止它的**父进程** —— 也就是发起卸载的那个脚本 / 终端。
#   所以带着规则运行时，`sc stop` 既停不掉驱动，还会把调用者一起杀掉 ——
#   连管理员「先授权、再停止」的正常卸载流程都被自己挡住。
#   直接调用 SCM API 时进程命令行里不含上述字样，规则不命中，卸载才走得通。
# --------------------------------------------------------------------------
ADVAPI32 = ctypes.WinDLL("advapi32", use_last_error=True)

SC_MANAGER_CONNECT = 0x0001
SERVICE_QUERY_STATUS = 0x0004
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
SERVICE_DELETE = 0x00010000

SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004

CONTROL_STOP = 0x00000001

SERVICE_STATE_NAMES = {
    0x00000001: "STOPPED",
    0x00000002: "START_PENDING",
    0x00000003: "STOP_PENDING",
    0x00000004: "RUNNING",
    0x00000005: "CONTINUE_PENDING",
    0x00000006: "PAUSE_PENDING",
    0x00000007: "PAUSED",
}


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", ctypes.c_uint32),
        ("dwCurrentState", ctypes.c_uint32),
        ("dwControlsAccepted", ctypes.c_uint32),
        ("dwWin32ExitCode", ctypes.c_uint32),
        ("dwServiceSpecificExitCode", ctypes.c_uint32),
        ("dwCheckPoint", ctypes.c_uint32),
        ("dwWaitHint", ctypes.c_uint32),
    ]


ADVAPI32.OpenSCManagerW.restype = ctypes.c_void_p
ADVAPI32.OpenSCManagerW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
ADVAPI32.OpenServiceW.restype = ctypes.c_void_p
ADVAPI32.OpenServiceW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
ADVAPI32.CloseServiceHandle.restype = ctypes.c_int
ADVAPI32.CloseServiceHandle.argtypes = [ctypes.c_void_p]
ADVAPI32.QueryServiceStatus.restype = ctypes.c_int
ADVAPI32.QueryServiceStatus.argtypes = [ctypes.c_void_p, ctypes.POINTER(SERVICE_STATUS)]
ADVAPI32.ControlService.restype = ctypes.c_int
ADVAPI32.ControlService.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                    ctypes.POINTER(SERVICE_STATUS)]
ADVAPI32.StartServiceW.restype = ctypes.c_int
ADVAPI32.StartServiceW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
ADVAPI32.DeleteService.restype = ctypes.c_int
ADVAPI32.DeleteService.argtypes = [ctypes.c_void_p]


def _open_service(access: int):
    """返回 (scm, svc)；任一步失败返回 (None, None)。调用方负责 CloseServiceHandle。"""
    scm = ADVAPI32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not scm:
        return None, None
    svc = ADVAPI32.OpenServiceW(scm, SERVICE_NAME, access)
    if not svc:
        ADVAPI32.CloseServiceHandle(scm)
        return None, None
    return scm, svc


def service_state() -> tuple[str, int]:
    """返回 (状态名, 原始状态码)；服务不存在返回 ('NOT_INSTALLED', 0)。"""
    scm, svc = _open_service(SERVICE_QUERY_STATUS)
    if not svc:
        return "NOT_INSTALLED", 0
    try:
        status = SERVICE_STATUS()
        if not ADVAPI32.QueryServiceStatus(svc, ctypes.byref(status)):
            return "UNKNOWN", 0
        return (SERVICE_STATE_NAMES.get(status.dwCurrentState, f"0x{status.dwCurrentState:X}"),
                status.dwCurrentState)
    finally:
        ADVAPI32.CloseServiceHandle(svc)
        ADVAPI32.CloseServiceHandle(scm)


def service_is_running() -> bool:
    return service_state()[1] == SERVICE_RUNNING


def svc_start() -> int:
    scm, svc = _open_service(SERVICE_QUERY_STATUS | SERVICE_START)
    if not svc:
        print(f"[ERR] 打开服务 {SERVICE_NAME} 失败（错误 {ctypes.get_last_error()}）—— 服务未安装？")
        return 1
    try:
        if not ADVAPI32.StartServiceW(svc, 0, None):
            err = ctypes.get_last_error()
            print(f"[ERR] StartService 失败，错误码 {err} (0x{err:X})")
            return err
        print("[ OK ] StartService 已下发")
        return 0
    finally:
        ADVAPI32.CloseServiceHandle(svc)
        ADVAPI32.CloseServiceHandle(scm)


def svc_stop(wait_seconds: float = 15.0) -> int:
    scm, svc = _open_service(SERVICE_QUERY_STATUS | SERVICE_STOP)
    if not svc:
        print(f"[ERR] 打开服务 {SERVICE_NAME} 失败（错误 {ctypes.get_last_error()}）")
        return 1
    try:
        status = SERVICE_STATUS()
        if not ADVAPI32.QueryServiceStatus(svc, ctypes.byref(status)):
            err = ctypes.get_last_error()
            print(f"[ERR] QueryServiceStatus 失败，错误码 {err}")
            return err

        if status.dwCurrentState == SERVICE_STOPPED:
            print("[INFO] 服务已是 STOPPED")
            return 0

        if not ADVAPI32.ControlService(svc, CONTROL_STOP, ctypes.byref(status)):
            err = ctypes.get_last_error()
            print(f"[ERR] ControlService(STOP) 失败，错误码 {err} (0x{err:X})")
            return err

        print("[ OK ] 已下发停止请求，等待收敛…")
        remaining = wait_seconds
        while remaining > 0:
            time.sleep(0.5)
            remaining -= 0.5
            if not ADVAPI32.QueryServiceStatus(svc, ctypes.byref(status)):
                break
            if status.dwCurrentState == SERVICE_STOPPED:
                print(f"[ OK ] 服务已停止（Win32 退出码 {status.dwWin32ExitCode}）")
                return 0

        print("[WARN] 等待超时，当前状态 "
              f"{SERVICE_STATE_NAMES.get(status.dwCurrentState, str(status.dwCurrentState))}")
        return 1
    finally:
        ADVAPI32.CloseServiceHandle(svc)
        ADVAPI32.CloseServiceHandle(scm)


def svc_delete() -> int:
    scm, svc = _open_service(SERVICE_QUERY_STATUS | SERVICE_DELETE)
    if not svc:
        print(f"[INFO] 服务 {SERVICE_NAME} 不存在或无法打开（错误 {ctypes.get_last_error()}）")
        return 0
    try:
        if not ADVAPI32.DeleteService(svc):
            err = ctypes.get_last_error()
            print(f"[ERR] DeleteService 失败，错误码 {err} (0x{err:X})")
            return err
        print("[ OK ] DeleteService 已下发（服务标记为删除）")
        return 0
    finally:
        ADVAPI32.CloseServiceHandle(svc)
        ADVAPI32.CloseServiceHandle(scm)


# --------------------------------------------------------------------------
# 签名策略：内核代码完整性（DSE）
#
# 自签证书不属于「微软认可的签名」，因此自签驱动能否加载，取决于启动配置：
#   · nointegritychecks on —— 关闭完整性检查（非测试模式、无水印）
#   · testsigning on       —— 测试模式（有水印）
# 两者都要求安全启动已关闭，且都必须重启一次才生效。
# --------------------------------------------------------------------------
SIGNING_OFF = "off"
SIGNING_NOINTEGRITY = "nointegritychecks"
SIGNING_TESTSIGN = "testsigning"

# --------------------------------------------------------------------------
# 实时代码完整性状态
#
# 为什么不能只看 bcdedit —— 它写入后**立刻就能读回 Yes**，但要**重启才生效**。
# 只看 bcdedit 会把「已设置、尚未重启」误判成「已放行」，接着 StartService 报 577，
# 让人以为驱动写坏了。NtQuerySystemInformation(SystemCodeIntegrityInformation)
# 返回的是**当前这一启动会话里真正生效**的选项位：完整性强制被关掉时，
# CODEINTEGRITY_OPTION_ENABLED 位会被清除 —— 这才是可靠的判据。
# --------------------------------------------------------------------------
NTDLL = ctypes.WinDLL("ntdll", use_last_error=True)

SystemCodeIntegrityInformation = 103
CODEINTEGRITY_OPTION_ENABLED = 0x0001
CODEINTEGRITY_OPTION_TESTSIGN = 0x0002
CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED = 0x0200


class SYSTEM_CODEINTEGRITY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint32),
        ("CodeIntegrityOptions", ctypes.c_uint32),
    ]


NTDLL.NtQuerySystemInformation.restype = ctypes.c_long
NTDLL.NtQuerySystemInformation.argtypes = [ctypes.c_ulong, ctypes.c_void_p,
                                           ctypes.c_ulong, ctypes.c_void_p]


def code_integrity_options() -> int | None:
    """返回当前生效的 CI 选项位；查询失败返回 None。"""
    info = SYSTEM_CODEINTEGRITY_INFORMATION()
    info.Length = ctypes.sizeof(info)
    status = NTDLL.NtQuerySystemInformation(
        SystemCodeIntegrityInformation, ctypes.byref(info), ctypes.sizeof(info), None)
    if status != 0:
        return None
    return info.CodeIntegrityOptions


def live_enforcement_disabled() -> bool | None:
    """当前启动会话里，自签/测试签名驱动能否直接加载（即签名强制是否已「放行」）。

    判定（区别于旧实现的关键）：
      · TESTSIGN 位 (0x2) 置位 = 测试模式 —— CI 接受本机信任根签过的测试签名镜像，
        对自签驱动而言**等于放行**，当前会话即可加载，**无需重启**；
      · ENABLED 位 (0x1) 清零 = nointegritychecks —— 完全不检查签名，放行；
      · 两者皆无 = 纯正常强制模式，自签驱动会被拒，需改 BCD 并重启。

    旧实现只看 `ENABLED == 0`，会把测试模式会话（ENABLED 仍为 1）误判成「未放行、
    需重启」——而测试模式本身并不需要重启即可加载 demand 驱动（实机 fltmc 已验证：
    测试模式会话下 Dragon-Drivers 已正常挂载）。None = 查询失败，按「放行」处理以免误拦。
    """
    options = code_integrity_options()
    if options is None:
        return None
    if options & CODEINTEGRITY_OPTION_TESTSIGN:
        return True
    return (options & CODEINTEGRITY_OPTION_ENABLED) == 0


def _find_any_driver_file() -> Path | None:
    """按优先级找一个真实存在的驱动镜像，用于签名类型判定。

    顺序：已安装服务的 ImagePath -> System32\drivers -> 交付/工程/out -> 工程 dist。
    """
    candidates: list[Path] = []
    try:
        import winreg as _wr
        _ik = _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE, SERVICE_KEY)
        _ip, _ = _wr.QueryValueEx(_ik, "ImagePath")
        _wr.CloseKey(_ik)
        candidates.append(Path(str(_ip).strip().strip('"')))
    except OSError:
        pass
    candidates += [
        DRIVERS_DIR / DRIVER_FILE,
        PROJECT_DIR.parent / "dist" / "Dragon_Drivers" / DRIVER_FILE,
        DELIVERY_DIR / SOURCE_FILE_NAMES[0],
        DELIVERY_DIR / SOURCE_FILE_NAMES[1],
        OUT_DIR / DRIVER_FILE,
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def driver_has_ms_cross_signature(path: Path) -> bool | None:
    """驱动是否带微软交叉签名（Microsoft Code Verification Root 签发 EV/代码签名 CA）。

    带交叉签名的驱动在**正常 DSE 模式**下（非测试模式、非 nointegritychecks）也能加载，
    不需要重启。这是 Partner Tech(Shanghai) 这类正规 EV 代码签名驱动的情况——与
    sign_dragon.py 文档里描述的「自签测试签名」完全是两回事。None = PE/签名解析失败。
    """
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7 as _pkcs7
        import struct as _struct
        data = open(path, "rb").read()
        if data[:2] != b"MZ":
            return None
        pe_off = _struct.unpack("<I", data[0x3C:0x40])[0]
        opt_off = pe_off + 24
        dd_off = opt_off + 0x70  # data directories array
        sec_rva, sec_size = _struct.unpack(
            "<II", data[dd_off + 4 * 8: dd_off + 4 * 8 + 8])
        if sec_rva == 0 or sec_size == 0:
            return None
        wc = data[sec_rva: sec_rva + sec_size]
        dw_length, _, w_type = _struct.unpack("<IHH", wc[:8])
        if w_type != 0x0002:  # WIN_CERT_TYPE_PKCS_SIGNED_DATA
            return None
        b_cert = wc[8:dw_length]
        certs = _pkcs7.load_der_pkcs7_certificates(b_cert)
        for c in certs:
            blob = (c.subject.rfc4514_string() + "|" + c.issuer.rfc4514_string()).lower()
            if "microsoft code verification root" in blob:
                return True
        return False
    except Exception:  # noqa: BLE001
        return None


def signing_readiness(driver_path: Path | None = None) -> tuple[bool, str]:
    """返回 (现在就能加载驱动吗, 说明)。

    关键修正：驱动能不能加载，不只取决于「本机启动配置」，还取决于**驱动自身的签名类型**：

      · 驱动带微软交叉签名（正规 EV/代码签名，如 Partner Tech 的 VeriSign 链
        经 Microsoft Code Verification Root 交叉签发）—— 在**正常 DSE 模式**下
        （ENABLED=1、TESTSIGN=0、无测试模式、Secure Boot/HVCI 开）StartService 直接
        加载，**不需要测试模式、不需要 nointegritychecks、不需要重启**；
      · 驱动是自签/测试签名（无微软交叉签名）—— 才需要 testsigning 或 nointegritychecks，
        且二者都需重启一次才生效；
      · 驱动完全未签名 —— 任何模式都拒（除非 nointegritychecks）。

    旧实现只认 testsigning/nointegritychecks 两种放行，对「正规交叉签名驱动在正常模式
    即可加载」毫无概念，于是把 ENABLED=1 且 TESTSIGN=0 的正常会话一律误报「需重启」。
    """
    drv = driver_path or _find_any_driver_file()
    if drv is not None:
        cross = driver_has_ms_cross_signature(drv)
        if cross is True:
            return True, ("驱动为微软交叉签名的正规代码签名，正常 DSE 模式下即可加载"
                          "，无需测试模式/重启")
        # cross is False / None：无法据此判定为生产签名，回退到启动配置判据

    state = signing_state()
    if state == SIGNING_OFF:
        if cross is False:
            return False, ("驱动非微软交叉签名（自签/未签名），DSE 开启下会被拒"
                           "——需 testsigning 或 nointegritychecks 并重启")
        return False, "DSE 开启且驱动签名类型未能确认，保守判定需放行配置"

    live = live_enforcement_disabled()
    if live is True:
        return True, f"已放行且已生效（{SIGNING_LABEL[state]}）"
    if live is False:
        return False, "放行配置已写入，但**尚未生效** —— 需要重启一次"
    return True, f"已放行（{SIGNING_LABEL[state]}；实时状态查询失败，按已生效处理）"

SIGNING_LABEL = {
    SIGNING_OFF: "DSE 开启（只允许微软认可签名的驱动）",
    SIGNING_NOINTEGRITY: "已关闭完整性检查（非测试模式，无水印）",
    SIGNING_TESTSIGN: "测试签名模式（桌面有水印）",
}


def read_signing_flags() -> dict:
    _, bcd = run(["bcdedit", "/enum", "{current}"])
    flags = {}
    for line in bcd.splitlines():
        stripped = line.strip().lower()
        for key in ("testsigning", "nointegritychecks"):
            if stripped.startswith(key):
                flags[key] = line.split()[-1].lower()
    return flags


def signing_state() -> str:
    flags = read_signing_flags()
    if flags.get("testsigning") == "yes":
        return SIGNING_TESTSIGN
    if flags.get("nointegritychecks") == "yes":
        return SIGNING_NOINTEGRITY
    return SIGNING_OFF


def secure_boot_on() -> bool | None:
    """True / False / None（传统 BIOS 或无固件信息时返回 None）。

    优先用 winreg 直接读（in-process，不 spawn powershell/reg.exe，受限环境也能跑）；
    失败再回退 powershell 的 Confirm-SecureBootUEFI。
    """
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
        )
        value, _ = winreg.QueryValueEx(key, "UEFISecureBootEnabled")
        winreg.CloseKey(key)
        return bool(value)
    except OSError:
        pass
    text = powershell("try{Confirm-SecureBootUEFI}catch{'unknown'}").strip().lower()
    if text.startswith("true"):
        return True
    if text.startswith("false"):
        return False
    return None


def hvci_on() -> bool:
    """内存完整性（HVCI）是否开启。优先 winreg 直接读，失败回退 reg.exe。"""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios"
            r"\HypervisorEnforcedCodeIntegrity",
        )
        value, _ = winreg.QueryValueEx(key, "Enabled")
        winreg.CloseKey(key)
        return bool(value)
    except OSError:
        pass
    _, out = run(["reg", "query",
                  r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios"
                  r"\HypervisorEnforcedCodeIntegrity", "/v", "Enabled"])
    return "0x1" in out


def driver_signature_status(path: Path) -> str:
    if not path.is_file():
        return "(文件不存在)"
    return powershell(
        f"$s=Get-AuthenticodeSignature '{path}';"
        "'{0} | 签名者: {1}' -f $s.Status,$s.SignerCertificate.Subject"
    ).strip()


def enable_nointegritychecks() -> None:
    code, output = run(["bcdedit", "/set", "nointegritychecks", "on"])
    print(output or f"bcdedit 返回 {code}")
    if code != 0:
        print("[ERR] 设置失败。若提示「该值受安全引导策略保护」，需先在固件（BIOS/UEFI）里关闭安全启动。")
        return
    print("[INFO] 已关闭内核完整性检查（**不是**测试模式，桌面不会出现水印）。")
    print("[INFO] 该设置**必须重启一次**才生效 —— 签名策略在开机时读取，运行期无法改变。")


def revert_signing() -> None:
    run(["bcdedit", "/set", "nointegritychecks", "off"])
    run(["bcdedit", "/set", "testsigning", "off"])
    print("[ OK ] 已撤销 nointegritychecks 与 testsigning（需重启后恢复默认强制签名）")


# --------------------------------------------------------------------------
# 安装源
# --------------------------------------------------------------------------
def find_driver_file(directory: Path) -> Path | None:
    for name in SOURCE_FILE_NAMES:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def resolve_source_dir(explicit: str | None) -> Path | None:
    """安装源目录：显式 --from 优先，其次交付目录，最后工程 out\\。"""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser().resolve())
    candidates.extend([DELIVERY_DIR, OUT_DIR])

    tried: list[str] = []
    for directory in candidates:
        tried.append(str(directory))
        if directory.is_dir() and find_driver_file(directory) is not None:
            return directory

    print("[ERR] 未在任何候选目录找到驱动镜像，已尝试：")
    for item in tried:
        print(f"        {item}  （需包含 {' 或 '.join(SOURCE_FILE_NAMES)}）")
    return None


def doctor() -> None:
    """实机预检：把「自签驱动能否加载」的前置条件逐条列出来，并给出结论。"""
    print("=" * 70)
    print("Dragon-Drivers 加载前置条件预检")
    print("=" * 70)

    blockers: list[str] = []

    import platform as _platform
    os_info = _platform.platform(aliased=True, terse=True)
    print(f"[环境] {os_info}")

    # --- 1. 签名策略：决定自签驱动能否加载 ---
    flags = read_signing_flags()
    state = signing_state()
    options = code_integrity_options()
    print(f"[INFO] 启动配置 testsigning       = {flags.get('testsigning', '未设置(=off)')}")
    print(f"[INFO] 启动配置 nointegritychecks = {flags.get('nointegritychecks', '未设置(=off)')}")
    if options is not None:
        # 只解读有公开定义的两个位；高位未公开，不做猜测（HVCI 另用注册表判定）
        print(f"[INFO] 当前生效的完整性选项        = 0x{options:X}"
              f"  (ENABLED={'是' if options & CODEINTEGRITY_OPTION_ENABLED else '否'}"
              f", TESTSIGN={'是' if options & CODEINTEGRITY_OPTION_TESTSIGN else '否'})")

    ready, reason = signing_readiness()
    print(f"[{'OK  ' if ready else 'FAIL'}] 自签驱动可加载：{ready}  —— {reason}")
    if not ready:
        blockers.append(reason)
        if state == SIGNING_OFF:
            print("       -> 自签驱动加载会被拒（错误码 577）。二选一，**都必须重启一次**：")
            print("          A) python deploy_dragon.py --enable-nointegritychecks --yes   （非测试模式、无水印）")
            print("          B) python deploy_dragon.py --enable-testsigning --yes         （测试模式、有水印）")
        else:
            print("       -> 启动配置已经改好了，**现在只差重启**。重启后直接重新运行本脚本。")

    # --- 2. 安全启动（开着就无法启用上述任一项）---
    sb = secure_boot_on()
    if sb is True:
        blockers.append("安全启动已开启")
        print("[FAIL] 安全启动 SecureBoot = True  -> 必须在固件设置里关闭，否则 bcdedit 改不动")
    elif sb is False:
        print("[OK  ] 安全启动 SecureBoot = False")
    else:
        print("[INFO] 安全启动 = 查询不到（传统 BIOS 引导，通常等于未启用）")

    # --- 3. 内存完整性 HVCI（开着会拒绝加载非微软签名驱动）---
    if hvci_on():
        blockers.append("HVCI 已开启")
        print("[FAIL] 内存完整性 HVCI = 已开启  -> 在「Windows 安全中心 > 设备安全性 > 内核隔离」里关闭")
    else:
        print("[OK  ] 内存完整性 HVCI = 未开启")

    # --- 3b. BitLocker（改启动配置前必须确认，否则重启可能索要恢复密钥）---
    bl = powershell(
        "try{(Get-BitLockerVolume -ErrorAction Stop |"
        " Where-Object {$_.ProtectionStatus -eq 'On'} |"
        " ForEach-Object {$_.MountPoint}) -join ','}catch{''}"
    ).strip()
    if bl:
        blockers.append("BitLocker 已开启")
        print(f"[FAIL] BitLocker 保护已开启（{bl}）-> 改启动配置前必须先暂停保护并备份恢复密钥")
    else:
        print("[OK  ] BitLocker = 未开启（改启动配置无恢复密钥风险）")

    try:
        import winreg as _wr
        _vk = _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,
                          r"SYSTEM\CurrentControlSet\Control\DeviceGuard")
        _val, _ = _wr.QueryValueEx(_vk, "EnableVirtualizationBasedSecurity")
        _wr.CloseKey(_vk)
        print(f"[INFO] VBS = {'已开启' if _val else '未开启/未设置'}")
    except OSError:
        print("[INFO] VBS = 查询不到（未设置）")

    # --- 4. 过滤器 altitude 自检：与加载顺序组是否自洽、是否与已加载过滤器冲突 ---
    band = ALTITUDE_RANGES.get(LOAD_ORDER_GROUP)
    try:
        numeric_altitude = int(ALTITUDE)
    except ValueError:
        numeric_altitude = None

    if band and numeric_altitude is not None:
        low, high = band
        inside = low <= numeric_altitude <= high
        print(f"[{'OK  ' if inside else 'WARN'}] Altitude {ALTITUDE} 是否落在「{LOAD_ORDER_GROUP}」"
              f"区间 {low}-{high}：{inside}")
        if not inside:
            print("       -> 微软文档要求 altitude 必须取自**所在加载顺序组的区间**。")
            print("          这通常不阻断加载（FltMgr 主要用它排序），但属于配置不自洽：")
            print("          要么把 LoadOrderGroup 改成与该 altitude 匹配的组，")
            print("          要么把 Altitude 改到该组区间内 —— 两者必须对应。")

    _, filters = run(["fltmc", "filters"])
    occupied: set[str] = set()
    for line in filters.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-2].replace(".", "", 1).isdigit():
            if parts[0].lower().startswith(SERVICE_NAME.split("-")[0].lower()):
                continue        # 本驱动自己，不算冲突
            occupied.add(parts[-2])

    taken = ALTITUDE in occupied
    print(f"[{'FAIL' if taken else 'OK  '}] Altitude {ALTITUDE} 未被其它已加载过滤器占用：{not taken}"
          + (f"  -> 已被占用（同一 altitude 只能加载一个过滤器）" if taken else ""))

    # --- 5. KMDF 运行时版本（驱动要求 >= 1.31）---
    kmdf = powershell(
        "$p='C:\\Windows\\System32\\Drivers\\Wdf01000.sys';"
        "if(Test-Path $p){(Get-Item $p).VersionInfo.FileVersion}else{'缺失'}"
    )
    print(f"[INFO] KMDF 运行时 Wdf01000.sys = {kmdf.strip()}  (本驱动要求 >= 1.31)")

    # --- 6. 驱动镜像与签名状态 ---
    # 用 _find_any_driver_file() 覆盖 ImagePath / System32\drivers / dist / out 全候选，
    # 避免 inplace 场景只在 System32\drivers 找导致误报「未找到」。
    sys_file = _find_any_driver_file() or (DRIVERS_DIR / DRIVER_FILE)
    if sys_file.is_file():
        sig = powershell(
            f"$s=Get-AuthenticodeSignature '{sys_file}';"
            "'{0} | 签名者: {1}' -f $s.Status,$s.SignerCertificate.Subject"
        )
        good = "Valid" in sig
        if sig.strip():
            print(f"[{'OK  ' if good else 'FAIL'}] {DRIVER_FILE} 签名状态: {sig.strip()}")
        else:
            print(f"[INFO] 签名状态查询受限（powershell 不可用），以 PE 交叉签名解析为准")
        # 微软交叉签名判定（不依赖 powershell，直接解析 PE）—— 决定正常模式能否加载
        cross = driver_has_ms_cross_signature(sys_file)
        if cross is True:
            print("[OK  ] 驱动含微软交叉签名（Microsoft Code Verification Root 签发链）"
                  "—— 正规 EV 代码签名，正常 DSE 模式下即可加载，不需要测试模式/重启")
        elif cross is False:
            print("[INFO] 驱动无微软交叉签名（自签/测试签名）—— 正常模式会被拒，"
                  "需 testsigning 或 nointegritychecks 并重启一次")
        else:
            print("[INFO] 交叉签名解析失败，无法判定签名类型（不影响其它检查）")
    else:
        # inplace 安装的镜像在内存中仍被 FltMgr 挂载，磁盘源文件可能已被移动，
        # 这种情况下不应判为阻塞——以 fltmc 实际挂载为准。
        _, _flt = run(["fltmc", "filters"])
        if "dragon" in (_flt or "").lower():
            print(f"[INFO] 磁盘未找到 {sys_file}，但 fltmc 显示 Dragon-Drivers 已挂载"
                  f"（inplace 安装，镜像在内存，驱动在运行）")
        else:
            print(f"[FAIL] 未找到 {sys_file}")

    # --- 7. 规则文件 ---
    rule = RULE_DIR / RULE_FILE_NAME
    print(f"[{'OK  ' if rule.is_file() else 'WARN'}] 规则文件 {rule}")

    # --- 8. 主程序 / 外置文件保护清单 ---
    import winreg

    guard_items = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            SERVICE_KEY.replace("HKLM\\", "") + r"\Parameters",
                            0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, "GuardPaths")
            guard_items = [value] if isinstance(value, str) else [x for x in value if x]
    except OSError:
        guard_items = []

    if guard_items:
        print(f"[OK  ] 主程序/外置文件保护清单 GuardPaths：{len(guard_items)} 条")
        for item in guard_items[:8]:
            print(f"        {item}")
        if len(guard_items) > 8:
            print(f"        ...（其余 {len(guard_items) - 8} 条）")
    else:
        print("[WARN] 未配置 GuardPaths —— 主程序与主程序外置文件不受自保护")
        print("       配置：python deploy_dragon.py --set-guard-paths \"<主程序路径>;<外置目录>\\*\" --yes")

    # --- 9. 处理器与调试输出 ---
    _, flt = run(["fltmc", "filters"])
    print("[INFO] 已加载的微过滤器:")
    for line in flt.splitlines():
        print(f"        {line.rstrip()}")

    print("-" * 70)
    if blockers:
        print(f"[结论] 尚不具备加载条件，共 {len(blockers)} 项阻塞：")
        for item in blockers:
            print(f"        · {item}")
        print("       处理完后重新运行 --doctor 复查；签名策略的更改需要重启。")
    else:
        print("[结论] 前置条件全部满足 —— 可以直接 --install 并 --start。")
    print("-" * 70)
    print("[提示] 内核 DbgPrint 默认被系统过滤掉。要看驱动日志，先执行：")
    print(r'       reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter"'
          r" /v DEFAULT /t REG_DWORD /d 0xFFFFFFFF /f")
    print("       然后重启，并用 DebugView（管理员 + Capture Kernel）查看。")


def confirm(flag: bool, what: str) -> bool:
    if flag:
        return True
    print(f"[SKIP] {what} 需要显式确认，请追加 --yes")
    return False


# --------------------------------------------------------------------------
# 动作
# --------------------------------------------------------------------------
def status() -> None:
    print("=" * 70)
    print(f"[签名策略] {SIGNING_LABEL[signing_state()]}")

    state_name, state_code = service_state()
    print(f"[服务状态] {state_name}" + (f"  (0x{state_code:X})" if state_code else ""))

    code, output = run(["sc", "qc", SERVICE_NAME])
    print(output or "(无服务配置)")

    print("-" * 70)
    _, image = run(["reg", "query", SERVICE_KEY, "/v", "ImagePath"])
    print(image or "(未设置 ImagePath)")

    _, client = run(["reg", "query", SERVICE_KEY + r"\Parameters", "/v", "ClientImagePath"])
    print(client or "(未设置 ClientImagePath —— 驱动会拒绝一切端口连接)")

    # 驱动镜像与规则目录的实际位置由 ImagePath 推导，可能不是 System32\drivers
    installed = None
    for line in image.splitlines():
        if "ImagePath" in line and "REG_" in line:
            raw = line.split("REG_", 1)[1].split(None, 1)
            if len(raw) == 2:
                installed = Path(raw[1].strip().strip('"'))
    print("-" * 70)
    if installed is not None:
        print(f"驱动镜像: {installed} {'存在' if installed.is_file() else '不存在（已被删除？）'}")
        print(f"规则目录: {installed.parent / 'Rules'} "
              f"{'存在' if (installed.parent / 'Rules').is_dir() else '不存在（零动态规则运行）'}")
    else:
        print(f"驱动镜像: (未安装)  默认源目录: {resolve_source_dir(None)}")

    _, flt = run(["fltmc", "filters"])
    for line in (flt or "").splitlines():
        if SERVICE_NAME.split("-")[0].lower() in line.lower():
            print(f"FltMgr 视图: {line.strip()}")


def enable_testsigning() -> None:
    code, output = run(["bcdedit", "/set", "testsigning", "on"])
    print(output or f"bcdedit 返回 {code}")
    print("[INFO] 需要重启后生效；重启后任务栏右下角会显示「测试模式」水印。")


def install(source: str | None = None, inplace: bool = False, with_rules: bool = True) -> None:
    source_dir = resolve_source_dir(source)
    if source_dir is None:
        return

    driver_src = find_driver_file(source_dir)
    if driver_src is None:
        print(f"[ERR] {source_dir} 下未找到驱动镜像")
        return

    print(f"[INFO] 安装源：{driver_src}")

    # 驱动运行期间，内置自保护会拦下对自身镜像与规则目录的写入。
    # 这里先拦一道，避免出现「复制了一半」的中间状态。
    if service_is_running():
        print("[ERR] 服务正在 RUNNING，内置自保护会拒绝覆盖驱动镜像与规则文件。")
        print("      请先停驱动再安装：")
        print("        python dragon_client.py --authorize-unload")
        print("        python deploy_dragon.py --stop")
        print("        python deploy_dragon.py --install --yes")
        return

    if inplace:
        target = driver_src
        rule_dir = source_dir / "Rules"
        print(f"[ OK ] 就地安装：ImagePath 直接指向 {target}（不复制）")
        print("[WARN] 就地安装会把驱动留在用户可写目录 —— 只要能改这一个文件，自保护就等于没有。")
        print("       只在隔离的测试机上这样做；正式部署请用默认路径 C:\\Windows\\System32\\drivers。")
    else:
        DRIVERS_DIR.mkdir(parents=True, exist_ok=True)
        target = DRIVERS_DIR / INSTALLED_FILE_NAME
        rule_dir = RULE_DIR

        try:
            shutil.copy2(driver_src, target)
            print(f"[ OK ] 已复制 {driver_src.name} -> {target}")
        except PermissionError as exc:
            print(f"[ERR] 复制驱动镜像被拒绝（{exc}）。若驱动仍在运行，请先授权并停止服务。")
            return

    if with_rules:
        rules_src = source_dir / "Rules"
        if rules_src.is_dir():
            rule_dir.mkdir(parents=True, exist_ok=True)
            copied = 0
            for item in rules_src.glob("*.json"):
                try:
                    shutil.copy2(item, rule_dir / item.name)
                    print(f"[ OK ] 已复制规则 {item.name} -> {rule_dir}")
                    copied += 1
                except PermissionError as exc:
                    print(f"[WARN] 规则 {item.name} 复制被拒绝（{exc}），跳过")
            if copied == 0:
                print(f"[WARN] {rules_src} 下没有可用的 .json，驱动将以零动态规则启动")
        else:
            print(f"[WARN] {rules_src} 不存在 —— 驱动将以**零动态规则**启动")
            print("       此时只有硬编码自保护生效：拦截对本驱动镜像 / 规则目录 / 服务键 /")
            print("       GuardPaths 清单的写入，并剥离其它进程对客户端的处置权限。不会拦任何行为。")
    else:
        print("[INFO] --no-rules：不部署规则文件，驱动以零动态规则启动（只跑硬编码自保护）")

    if not inplace:
        inf_src = source_dir / f"{SERVICE_NAME}.inf"
        if inf_src.is_file():
            shutil.copy2(inf_src, DRIVERS_DIR / inf_src.name)

    bin_path = f'"{target}"' if " " in str(target) else str(target)

    svc_delete()   # 清理可能存在的旧服务（走 SCM API），失败忽略
    code, output = run(
        [
            "sc", "create", SERVICE_NAME,
            # 注意：sc 的合法关键字是 filesys / kernel / rec / own / share ...
            # 没有 "filesystem" 这种写法，写错会直接报「未知的服务类型」。
            "type=", "filesys",
            "binPath=", bin_path,
            "start=", "demand",
            "error=", "normal",
            "group=", LOAD_ORDER_GROUP,
            "depend=", "FltMgr",
            "DisplayName=", SERVICE_NAME,
        ]
    )
    print(output or f"sc create 返回 {code}")
    if code != 0:
        print("[ERR] 创建服务失败")
        return

    # Minifilter 必须提供实例键（DefaultInstance + Altitude / Flags），
    # 仅 sc create 不会写入这部分，FltMgr 会拒绝加载。
    #
    # 实例位置随系统版本变化（微软官方文档「Creating an INF File for a
    # Minifilter Driver」）：
    #   · Windows 11 24H2 起：<服务键>\Parameters\Instances\...
    #   · Windows 11 23H2 及更早（本机若为 22H2 走这一套）：<服务键>\Instances\...
    # 两处都写，FltMgr 读它自己那一套，多余的一处被忽略。
    for base in (SERVICE_KEY + r"\Instances",
                 SERVICE_KEY + r"\Parameters\Instances"):
        instance = base + r"\Dragon Instance"
        run(["reg", "add", base, "/v", "DefaultInstance", "/t", "REG_SZ",
             "/d", "Dragon Instance", "/f"])
        run(["reg", "add", instance, "/v", "Altitude", "/t", "REG_SZ",
             "/d", ALTITUDE, "/f"])
        run(["reg", "add", instance, "/v", "Flags", "/t", "REG_DWORD",
             "/d", "0", "/f"])

    run(["reg", "add", SERVICE_KEY + r"\Parameters", "/v", "SupportedFeatures", "/t", "REG_DWORD",
         "/d", "3", "/f"])
    print("[ OK ] 已写入 Instances / Parameters 注册表项")

    run(["reg", "query", SERVICE_KEY + r"\Instances", "/s"])
    run(["reg", "query", SERVICE_KEY + r"\Parameters\Instances", "/s"])

    print("[INFO] 启动服务前请先用 --set-client 登记客户端镜像路径，否则通信端口拒绝连接。")


FILE_NAME_NT_PATH = 0x00000002


def dos_to_nt_path(path: str) -> str | None:
    """把 DOS 路径（C:\\...）转成进程映像名所用的 NT 设备路径。

    为什么必须转换 —— 驱动侧用 `SeLocateProcessImageName` 取发起连接进程的映像名，
    并用 `RtlEqualUnicodeString` 与登记值**全等比较**。该例程返回的是**设备路径形式**
    （数据来自 `EPROCESS->SeAuditProcessCreationInfo.ImageFileName`），形如：

        \\Device\\HarddiskVolume3\\Users\\Administrator\\...\\python.exe

    若把 `C:\\Users\\...\\python.exe` 直接写进 ClientImagePath，两侧永远不相等 →
    通信端口拒绝一切连接，**连「授权卸载」都做不了**（只能重启）。

    实现用文档化的 `GetFinalPathNameByHandleW(..., FILE_NAME_NT_PATH)`：
    先按只读属性打开文件拿到句柄，再问它的 NT 路径。
    """
    if path.startswith("\\Device\\"):
        return path                       # 已经是设备路径形式

    raw = path[4:] if path.startswith("\\??\\") else path

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                ctypes.c_void_p]
    k32.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
    k32.GetFinalPathNameByHandleW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                              ctypes.c_uint32, ctypes.c_uint32]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]

    handle = k32.CreateFileW(raw, 0, 0x7, None, 3, 0x80, None)   # 0 访问权 = 只查属性
    if not handle or handle == ctypes.c_void_p(-1).value:
        return None

    try:
        buffer = ctypes.create_unicode_buffer(1024)
        length = k32.GetFinalPathNameByHandleW(handle, buffer, 1024, FILE_NAME_NT_PATH)
        if length == 0 or length >= 1024:
            return None
        return buffer.value
    finally:
        k32.CloseHandle(handle)


def set_client(path: str) -> None:
    _warn_if_running("写入 ClientImagePath")

    nt_path = dos_to_nt_path(path)
    if nt_path is None:
        print(f"[WARN] 无法把 {path} 转换成 NT 设备路径（文件不存在？）。")
        print("       直接登记原值；若客户端连不上端口，原因就在这里。")
        nt_path = path
    elif nt_path != path:
        print("[INFO] 路径形式转换（驱动按 NT 设备路径做全等比较）：")
        print(f"       输入  {path}")
        print(f"       登记  {nt_path}")

    code, output = run(
        ["reg", "add", SERVICE_KEY + r"\Parameters", "/v", "ClientImagePath",
         "/t", "REG_SZ", "/d", nt_path, "/f"]
    )
    print(output or f"reg add 返回 {code}")

    if code == 0:
        print("[ OK ] 已登记客户端镜像路径")
        print("[INFO] 客户端必须以**这一个文件**运行才能连上端口：")
        print(f"       {nt_path}")


def _warn_if_running(what: str) -> bool:
    """驱动运行时内置自保护会拒绝写自己的服务键，先提醒以免被误判为脚本 Bug。"""
    running = service_is_running()

    if running:
        print(f"[WARN] 服务当前为 RUNNING：内置自保护会拒绝{what}（写入服务键），")
        print("       本次操作大概率失败（这不是权限问题）。正确做法：")
        print("       1) 先停驱动：--authorize-unload -> --stop -> 改配置 -> --start")
        print("       2) 首次部署时在 --start 之前就完成配置（推荐）")
        print()

    return running


def set_guard_paths(spec: str) -> None:
    """写入主程序 / 主程序外置文件保护清单（REG_MULTI_SZ）。"""
    import winreg

    items = [item.strip() for item in spec.replace(";", "\n").splitlines() if item.strip()]
    if not items:
        print("[ERR] 清单为空")
        return

    _warn_if_running("更新 GuardPaths")

    try:
        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                                 SERVICE_KEY.replace("HKLM\\", "") + r"\Parameters",
                                 0, winreg.KEY_SET_VALUE)
    except OSError as exc:
        print(f"[ERR] 打开服务键失败: {exc}")
        return

    try:
        winreg.SetValueEx(key, "GuardPaths", 0, winreg.REG_MULTI_SZ, items)
    except OSError as exc:
        print(f"[ERR] 写入 GuardPaths 失败: {exc}")
        return
    finally:
        winreg.CloseKey(key)

    print(f"[ OK ] 已写入 GuardPaths（{len(items)} 条）：")
    for item in items:
        print(f"       {item}")
    print("[INFO] 清单在驱动启动时读取；若驱动已在运行，需要先停再启动才会生效。")


def service_action(action: str) -> None:
    """start / stop 走 SCM API（不派发 sc.exe）。"""
    if action == "start":
        code = svc_start()
    elif action == "stop":
        code = svc_stop()
    else:
        print(f"[ERR] 未知动作 {action}")
        return

    if code == 0:
        return

    if action == "stop":
        print()
        print("[WARN] 停止失败。这不是权限问题，而是驱动的自保设计：")
        print("       非强制卸载必须先由用户态客户端授权（FilterUnloadCallback 返回")
        print("       STATUS_FLT_DO_NOT_DETACH）。")
        print()
        print("       正确顺序：")
        print("         1) python dragon_client.py --authorize-unload")
        print("         2) python deploy_dragon.py --stop")
        print("         3) python load_driver.py --unload --yes")
        print()
        print("       启用授权的前提：Parameters\\ClientImagePath 已登记、且由该镜像运行客户端。")
        print("       若客户端已不可用 —— 直接重启机器：本驱动 start=demand，重启后不会自动加载，")
        print("       此时再执行 --uninstall --yes 即可干净删除。")
        print()
        print("       ⚠️ 规则包 1005 会匹配 `sc stop / sc delete / fltmc unload Dragon-Drivers`")
        print("          这类命令行并终止发起进程 —— 所以带规则运行时**不要用 sc.exe 卸载**，")
        print("          本脚本已改走 SCM API，直接用本脚本即可。")


def uninstall() -> None:
    svc_stop(wait_seconds=10.0)
    code = svc_delete()

    if code != 0:
        print()
        print("[WARN] 删除服务失败。驱动仍在运行时会拦下对自己服务键的修改（自保规则）。")
        print("       请先授权并停止驱动，或重启后再删除（见 --stop 的提示）。")
        return

    run(["reg", "delete", SERVICE_KEY, "/f"])

    # 依次尝试各个可能的安装位置，避免只删 System32 那一份而留下残留
    removed = 0
    for candidate in (DRIVERS_DIR / INSTALLED_FILE_NAME,
                      *[DELIVERY_DIR / name for name in SOURCE_FILE_NAMES]):
        if candidate.is_file():
            try:
                candidate.unlink()
                print(f"[ OK ] 已删除 {candidate}")
                removed += 1
            except PermissionError as exc:
                print(f"[WARN] 删除 {candidate} 被拒绝（{exc}）—— 驱动可能仍在运行")
    if removed == 0:
        print("[INFO] 未发现残留的驱动镜像文件")


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="Dragon-Drivers 部署脚本")
    parser.add_argument("--doctor", action="store_true",
                        help="加载前置条件预检（测试签名 / 安全启动 / HVCI / 签名 / KMDF 运行时）")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--stop", action="store_true")
    parser.add_argument("--set-client", metavar="PATH")
    parser.add_argument("--set-guard-paths", metavar="PATTERNS",
                        help="写入主程序/外置文件保护清单（分号分隔，支持通配符）")
    parser.add_argument("--from", dest="source", metavar="DIR",
                        help="安装源目录（默认依次尝试交付目录 Dragon_Drivers\\ 与工程 out\\）")
    parser.add_argument("--inplace", action="store_true",
                        help="就地安装：ImagePath 直接指向源目录里的 .sys，不复制到 System32\\drivers")
    parser.add_argument("--no-rules", action="store_true",
                        help="不部署规则文件，让驱动以零动态规则启动（只跑硬编码自保护）")
    parser.add_argument("--enable-nointegritychecks", action="store_true",
                        help="bcdedit /set nointegritychecks on —— 非测试模式放行内核驱动（需重启）")
    parser.add_argument("--enable-testsigning", action="store_true",
                        help="bcdedit /set testsigning on —— 测试模式放行内核驱动（需重启，有水印）")
    parser.add_argument("--revert-signing", action="store_true",
                        help="撤销 nointegritychecks 与 testsigning（需重启）")
    parser.add_argument("--yes", action="store_true", help="确认执行系统级变更")
    args = parser.parse_args()

    if args.doctor:
        doctor()
        return 0

    if args.status:
        status()
        return 0

    if not require_admin():
        print("[ERR] 需要以管理员身份运行。")
        return 2

    if args.enable_nointegritychecks and confirm(args.yes, "关闭内核完整性检查（非测试模式）"):
        enable_nointegritychecks()

    if args.enable_testsigning and confirm(args.yes, "开启测试签名"):
        enable_testsigning()

    if args.revert_signing and confirm(args.yes, "撤销签名策略更改"):
        revert_signing()

    if args.install and confirm(args.yes, "安装内核驱动服务"):
        install(source=args.source, inplace=args.inplace, with_rules=not args.no_rules)

    if args.set_client and confirm(args.yes, "写入 ClientImagePath"):
        set_client(args.set_client)

    if args.set_guard_paths and confirm(args.yes, "写入 GuardPaths 保护清单"):
        set_guard_paths(args.set_guard_paths)

    if args.start:
        service_action("start")

    if args.stop:
        service_action("stop")

    if args.uninstall and confirm(args.yes, "卸载内核驱动服务并删除文件"):
        uninstall()

    return 0


if __name__ == "__main__":
    sys.exit(main())
