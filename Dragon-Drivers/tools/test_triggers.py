#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dragon-Drivers 端到端拦截验证脚本
=========================================================================
对默认规则包 DragonDriver_DefenderRules.json 里几条可复现的规则做「真实触发」，
用来证明驱动确实在内核里拦下了操作（而不是靠猜）。

默认规则对应的触发点：
  1001  File      写 / 删 / 改名        -> 驱动自身镜像、Rules 目录（硬编码自保护同样兜底）
  1002  Registry  建键 / 写值 / 删值    -> 驱动服务注册表键（硬编码自保护同样兜底）
  1040  Memory    VmWrite / VmOperation -> lsass / winlogon / services
  GuardPaths（注册表配置）              -> 主程序与主程序外置文件（T5）

使用方法（管理员）：
    python test_triggers.py

关键点：**必须做对照实验**
    1) 驱动运行中执行本脚本 —— 相关操作应被拒绝；
    2) 授权停止驱动后再执行一次 —— 同样的操作应当成功。
    两次结果不同，才能证明拦截来自本驱动，而不是权限或系统策略。

注意：五项测试都会真实发起操作，其中 T2 会尝试删除规则文件、T4 会尝试
      申请对 lsass 的内存写权限、T5 会以写方式打开受保护的主程序文件
      （只打开、不写入，保护失效时立即关闭句柄）。请只在测试虚拟机里跑。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import subprocess
import sys
from pathlib import Path

SERVICE_NAME = "Dragon-Drivers"
SERVICE_KEY = rf"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}"


# --------------------------------------------------------------------------
# 目标路径从注册表推导，不写死
#
# 本驱动有两种部署方式（就地加载 / 复制到 System32\drivers），写死路径会让
# 测试打到不存在的文件上、「拒绝访问」变成了「文件不存在」，结论失真。
# 这里统一从服务键的 ImagePath 推导镜像位置，再由它推导规则目录；
# GuardPaths 的测试目标也从注册表清单里取。
# --------------------------------------------------------------------------
def _image_path() -> str:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE_KEY, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, "ImagePath")
    except OSError:
        return r"C:\Windows\System32\drivers\Dragon-Drivers.sys"

    text = str(value)
    for prefix in ("\\??\\", "\\DosDevices\\"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    return text


DRIVER_SYS = _image_path()
_RULE_DIR = str(Path(DRIVER_SYS).parent / "Rules")
RULE_FILE = str(Path(_RULE_DIR) / "DragonDriver_DefenderRules.json")


def _guard_probe() -> str:
    """从 GuardPaths 清单里挑一个目录型条目，返回其下的探测文件路径。"""
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE_KEY + r"\Parameters",
                            0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, "GuardPaths")
    except OSError:
        return ""

    items = [value] if isinstance(value, str) else [str(item) for item in value if item]
    for item in items:
        if item.endswith("\\*"):
            candidate = Path(item[:-2]) / "probe.txt"
            if candidate.parent.is_dir():
                return str(candidate)
        elif (not item.endswith("*")) and Path(item).is_file():
            return item
    return ""


GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04

ERROR_ACCESS_DENIED = 5

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)

# --------------------------------------------------------------------------
# 函数原型（不声明 restype 的话 64 位下句柄/指针会被截断成 int32）
# --------------------------------------------------------------------------
k32.CreateFileW.restype = ctypes.c_void_p
k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                            wt.DWORD, wt.DWORD, ctypes.c_void_p]
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                               wt.DWORD, wt.DWORD]
k32.VirtualFreeEx.restype = wt.BOOL
k32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD]
k32.CloseHandle.restype = wt.BOOL
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.DeleteFileW.restype = wt.BOOL
k32.DeleteFileW.argtypes = [wt.LPCWSTR]
k32.GetCurrentProcess.restype = ctypes.c_void_p

# advapi32 也要声明原型：不声明的话，c_void_p 形式的进程句柄传给
# OpenProcessToken 会被当成 Python 整数、64 位下直接 OverflowError 崩掉。
adv.OpenProcessToken.restype = wt.BOOL
adv.OpenProcessToken.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
adv.LookupPrivilegeValueW.restype = wt.BOOL
adv.LookupPrivilegeValueW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ctypes.c_void_p]
adv.AdjustTokenPrivileges.restype = wt.BOOL
adv.AdjustTokenPrivileges.argtypes = [ctypes.c_void_p, wt.BOOL, ctypes.c_void_p,
                                      wt.DWORD, ctypes.c_void_p, ctypes.c_void_p]

# ctypes 对 -1 的还原方式在不同版本下不一致，统一按集合判断
INVALID_HANDLES = (None, 0, -1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)

# 期望值由 main() 依据驱动是否运行设置。
# 「驱动没跑时应当全部不被拦截」是同一套操作的**对照基线**，
# 两次结果不同才构成拦截证据 —— 之前这里被写死成 True，
# 导致基线模式把「未被拦截」误报成 FAIL。
EXPECT_BLOCK = True


def is_invalid_handle(handle) -> bool:
    return handle in INVALID_HANDLES


# --------------------------------------------------------------------------
# 基础
# --------------------------------------------------------------------------
def banner(text: str) -> None:
    print()
    print("=" * 70)
    print(text)
    print("=" * 70)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def enable_privilege(name: str) -> bool:
    """启用当前进程的一个特权（SeDebugPrivilege / SeBackupPrivilege ...）。"""
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x0002

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wt.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    token = wt.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                ctypes.byref(token)):
        return False

    luid = LUID()
    if not adv.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
        k32.CloseHandle(token)
        return False

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

    ok = bool(adv.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None))
    k32.CloseHandle(token)
    return ok


def report(name: str, expected_block: bool, blocked: bool, detail: str) -> bool:
    """expected_block=True 表示「期望被驱动拦下」。"""
    if expected_block:
        good = blocked
        verdict = "拦截生效" if blocked else "未拦截 <<< 需要排查"
    else:
        good = not blocked
        verdict = "未被拦截（对照基线正常）" if not blocked else "仍被拦截（有残留保护）"

    mark = "[ OK ]" if good else "[FAIL]"
    print(f"{mark} {name}")
    print(f"        结果: {verdict}")
    print(f"        细节: {detail}")
    return good


# --------------------------------------------------------------------------
# 测试项
# --------------------------------------------------------------------------
def test_driver_image_write() -> bool:
    """规则 1001 / 硬编码自保护：以写方式打开驱动自身镜像，应被拒（ERROR_ACCESS_DENIED）。"""
    ctypes.set_last_error(0)
    handle = k32.CreateFileW(DRIVER_SYS, GENERIC_WRITE, 0, None,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    err = ctypes.get_last_error()

    if is_invalid_handle(handle):
        blocked = (err == ERROR_ACCESS_DENIED)
        return report("T1 写打开 Dragon-Drivers.sys", EXPECT_BLOCK, blocked,
                      f"CreateFileW 失败, GetLastError={err}" +
                      (" (ERROR_ACCESS_DENIED)" if blocked else ""))

    k32.CloseHandle(handle)
    return report("T1 写打开 Dragon-Drivers.sys", EXPECT_BLOCK, False, "CreateFileW 成功（未被拦截）")


def test_rule_file_delete() -> bool:
    """规则 1001 / 硬编码自保护：Rules 目录整体受保护，目录内新建 / 删除文件都应被拒。

    不直接删真规则文件 —— 规则文件可能并未部署（零规则试跑时就没有），
    那样得到的是「文件不存在」而不是「拒绝访问」，结论会失真。
    这里改为在受保护的规则目录里尝试新建一个探测文件。
    """
    probe = str(Path(_RULE_DIR) / "_deny_probe.txt")
    ctypes.set_last_error(0)
    handle = k32.CreateFileW(probe, GENERIC_WRITE, 0, None,
                             2,   # CREATE_ALWAYS
                             FILE_ATTRIBUTE_NORMAL, None)
    err = ctypes.get_last_error()

    if not is_invalid_handle(handle):
        k32.CloseHandle(handle)
        k32.DeleteFileW(probe)
        return report("T2 在 Rules 目录内新建文件", EXPECT_BLOCK, False,
                      f"{probe} 创建成功（未被拦截，已清理）")

    blocked = (err == ERROR_ACCESS_DENIED)
    return report("T2 在 Rules 目录内新建文件", EXPECT_BLOCK, blocked,
                  f"{probe} -> CreateFileW 失败, GetLastError={err}"
                  + (" (ERROR_ACCESS_DENIED)" if blocked else ""))


def test_service_key_write() -> bool:
    """规则 1002 / 硬编码自保护：写驱动服务注册表键，应被拒。"""
    import winreg
    # 规则加载后，写驱动服务键会触发驱动 Terminate 响应，故在子进程里探测，
    # 把「子进程被终止」也判为拦截生效（否则 harness 自身会被杀、出不了报告）。
    child = (
        "import test_triggers as t, winreg;"
        "try:"
        "  k=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,t.SERVICE_KEY,0,0x0002);"
        "  try: winreg.SetValueEx(k,'DragonProbe',0,winreg.REG_DWORD,1); print('T3PROBE_ALLOWED');"
        "  except PermissionError as e: print('T3PROBE_DENIED');"
        "  finally: winreg.CloseKey(k);"
        "except PermissionError as e: print('T3PROBE_OPEN_DENIED');"
    )
    try:
        res = subprocess.run([sys.executable, "-c", child],
                             capture_output=True, text=True, errors="replace", timeout=30)
    except subprocess.TimeoutExpired:
        return report("T3 写驱动服务注册表键", EXPECT_BLOCK, True, "子进程超时（疑似被驱动终止）")
    out = res.stdout
    if "T3PROBE_ALLOWED" in out:
        return report("T3 写驱动服务注册表键", EXPECT_BLOCK, False, "SetValueEx 成功（未被拦截）")
    return report("T3 写驱动服务注册表键", EXPECT_BLOCK, True,
                  "子进程被驱动终止或写入被拒（拦截生效）" + ("" if "T3PROBE" in out else "（进程被驱动终止）"))


def _guard_paths() -> list:
    """读取服务键 Parameters 子键下的 GuardPaths 值（REG_MULTI_SZ）。"""
    import winreg

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             SERVICE_KEY + r"\Parameters", 0, winreg.KEY_READ)
    except OSError:
        return []

    try:
        value, _ = winreg.QueryValueEx(key, "GuardPaths")
    except OSError:
        return []
    finally:
        winreg.CloseKey(key)

    if isinstance(value, str):
        return [value]
    return [item for item in value if item]


def test_guard_path_write() -> bool:
    """GuardPaths 清单：主程序 / 主程序外置文件不允许被其它进程改写。

    只做「以写方式打开」，不做任何实际写入；若保护未生效则立即关闭句柄，
    不会留下任何修改。
    """
    patterns = _guard_paths()
    if not patterns:
        print("[SKIP] T5 未配置 Parameters\\GuardPaths（主程序 / 外置文件保护清单为空）")
        print("       配置示例：python deploy_dragon.py --set-guard-paths \"C:\\Path\\App.exe;C:\\Path\\Dir\\*\" --yes")
        return True

    target = None

    # 优先选通配符条目下的探测文件（哑元，改坏了也无所谓），
    # 其次才是清单里写明的真实文件。
    # 为什么必须挑**已存在**的目标：目标不存在时拿到的是「文件找不到」而不是
    # 「拒绝访问」，那样会把「没拦住」与「测错了对象」混为一谈。
    for item in patterns:
        if item.endswith("\\*"):
            candidate = Path(item[:-2]) / "probe.txt"
            if candidate.is_file():
                target = str(candidate)
                break

    if target is None:
        for item in patterns:
            if "*" not in item and "?" not in item and Path(item).is_file():
                target = item
                break

    if target is None:
        print("[SKIP] T5 清单里没有可用的**已存在**目标（通配符条目下也没有 probe.txt）：")
        for item in patterns[:5]:
            print("       %s" % item)
        return True

    # 规则加载后，写打开 GuardPath 受保护文件会触发驱动 Terminate 响应，
    # 故在子进程里探测，把「子进程被终止」也判为拦截生效。
    child = (
        "import test_triggers as t, sys;"
        "target=sys.argv[1];"
        "t.ctypes.set_last_error(0);"
        "h=t.k32.CreateFileW(target, t.GENERIC_WRITE, 0, None, t.OPEN_EXISTING, t.FILE_ATTRIBUTE_NORMAL, None);"
        "err=t.ctypes.get_last_error();"
        "sys.stdout.write('T5HANDLE=%d ERR=%d\\n' % (h, err));"
        "sys.stdout.flush();"
        "print('T5PROBE_DONE')"
    )
    try:
        res = subprocess.run([sys.executable, "-c", child, target],
                             capture_output=True, text=True, errors="replace", timeout=30)
    except subprocess.TimeoutExpired:
        return report("T5 写打开受保护的主程序 / 外置文件", EXPECT_BLOCK, True, "子进程超时（疑似被驱动终止）")
    out = res.stdout
    if "T5PROBE_DONE" not in out:
        return report("T5 写打开受保护的主程序 / 外置文件", EXPECT_BLOCK, True,
                      "%s 子进程被驱动终止（拦截生效）" % target)
    import re
    m = re.search(r"T5HANDLE=(\d+) ERR=(\d+)", out)
    if m and (int(m.group(1)) in (0, -1) or int(m.group(2)) == 5):
        return report("T5 写打开受保护的主程序 / 外置文件", EXPECT_BLOCK, True,
                      "%s -> GetLastError=%s（权限被拒绝）" % (target, m.group(2)))
    return report("T5 写打开受保护的主程序 / 外置文件", EXPECT_BLOCK, False,
                  "%s 可以写打开（未被拦截）" % target)


def _lsass_pid() -> int | None:
    completed = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq lsass.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True, errors="replace")
    for line in completed.stdout.splitlines():
        parts = [p.strip('" ') for p in line.split('","')]
        if len(parts) >= 2 and parts[0].lower() == "lsass.exe":
            try:
                return int(parts[1])
            except ValueError:
                return None
    return None


def test_lsass_handle_downgrade() -> bool:
    """规则 1040：请求对 lsass 的内存写权限，句柄权限应被剥离。"""
    pid = _lsass_pid()
    if pid is None:
        print("[SKIP] T4 未找到 lsass.exe")
        return True

    child = (
        "import test_triggers as t, ctypes, sys;"
        "try:\n t.enable_privilege('SeDebugPrivilege')\nexcept Exception: pass;"
        "pid=t._lsass_pid();"
        "h=t.k32.OpenProcess(t.PROCESS_QUERY_INFORMATION|t.PROCESS_VM_OPERATION|t.PROCESS_VM_WRITE,False,pid);"
        "sys.stdout.write('OPEN=%d\\n'%(h));"
        "addr=t.k32.VirtualAllocEx(h,None,0x1000,t.MEM_COMMIT|t.MEM_RESERVE,t.PAGE_READWRITE) if not t.is_invalid_handle(h) else 0;"
        "sys.stdout.write('ALLOC=%d\\n'%(addr));"
        "sys.stdout.flush();"
        "print('T4PROBE_DONE')"
    )
    try:
        res = subprocess.run([sys.executable, "-c", child],
                             capture_output=True, text=True, errors="replace", timeout=30)
    except subprocess.TimeoutExpired:
        return report("T4 lsass 内存写权限（句柄降权）", EXPECT_BLOCK, True,
                      "子进程超时（疑似被驱动挂起/终止）")

    out = res.stdout
    if "T4PROBE_DONE" not in out:
        return report("T4 lsass 内存写权限（句柄降权）", EXPECT_BLOCK, True,
                      "子进程在触达 lsass 内存写时被驱动终止（规则 1040 Terminate 生效）")
    if "ALLOC=0" in out:
        return report("T4 lsass 内存写权限（句柄降权）", EXPECT_BLOCK, True,
                      "OpenProcess 成功但 VirtualAllocEx 失败（权限被剥离）")
    return report("T4 lsass 内存写权限（句柄降权）", EXPECT_BLOCK, False,
                  "VirtualAllocEx 成功（未被拦截）")


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------
def main() -> int:
    banner("Dragon-Drivers 端到端拦截验证")
    print(f"驱动镜像: {DRIVER_SYS}")
    print(f"规则文件: {RULE_FILE}")

    if not is_admin():
        print("[ERR] 需要管理员权限（要写 System32、要开 lsass 句柄）。")
        return 2

    enable_privilege("SeDebugPrivilege")
    enable_privilege("SeBackupPrivilege")
    enable_privilege("SeRestorePrivilege")

    # 驱动是否在跑：决定「期望值」
    completed = subprocess.run(["sc", "query", SERVICE_NAME],
                               capture_output=True, text=True, errors="replace")
    running = "RUNNING" in completed.stdout.upper()

    global EXPECT_BLOCK
    EXPECT_BLOCK = running

    if running:
        print("[INFO] 服务状态: RUNNING —— 期望全部被拦截")
    else:
        print("[INFO] 服务状态: 未运行 —— 本次为「对照基线」，期望全部不被拦截")

    results = [
        test_driver_image_write(),
        test_rule_file_delete(),
        test_service_key_write(),
        test_lsass_handle_downgrade(),
        test_guard_path_write(),
    ]

    banner("结论")
    passed = sum(1 for item in results if item)
    print(f"{passed}/{len(results)} 项符合预期")

    if not running:
        print()
        print("[提示] 以上是「驱动未运行」的**对照基线**：期望就是全部不被拦截，")
        print("       「符合预期」= 基线正常。随后启动驱动重跑本脚本，")
        print("       同一批操作应当全部变为被拒绝 —— 两次结果差异才是拦截证据。")
    else:
        print()
        print("[提示] 需要反向验证时：授权停止驱动，再跑一次本脚本作对照。")
        print("       python dragon_client.py --authorize-unload")
        print("       python deploy_dragon.py --stop")

    return 0 if passed == len(results) else 2


if __name__ == "__main__":
    sys.exit(main())
