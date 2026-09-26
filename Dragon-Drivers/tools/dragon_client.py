#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dragon-Drivers 用户态客户端（ctypes）
=========================================================================
对应内核侧 inc/DragonProtocol.h 的数据契约，实现：

  · 连接通信端口 \\DragonGuard_Event_Port（带 ConnectionContext 握手）
  · 下发命令：白名单增删 / 加载规则文件 / 清空规则 / 授权卸载 / 查询状态
  · 异步监听内核上报事件（消息码 / 进程号 / 目标路径）

依赖：ctypes 标准库 + 系统 fltlib.dll（Filter Manager 用户态接口）。

用法：
    python dragon_client.py --state
    python dragon_client.py --add-whitelist "*\\MyApp\\*"
    python dragon_client.py --load-rules  D:\\Rules\\extra.json
    python dragon_client.py --listen        # 前台监听事件
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wintypes
import os
import sys
from typing import Optional

# --------------------------------------------------------------------------
# 协议常量（与 inc/DragonProtocol.h 保持一致）
# --------------------------------------------------------------------------
PORT_NAME = "\\DragonGuard_Event_Port"

CONNECTION_MAGIC = 0x4E475244      # 'DRGN'
CONNECTION_VERSION = 1
PATH_CHARS = 1024

FLT_PORT_FLAG_SYNC_HANDLE = 0x00000001
HRESULT_IO_PENDING = 0x800703E5    # HRESULT_FROM_WIN32(ERROR_IO_PENDING)

CMD_ADD_WHITELIST = 1
CMD_REMOVE_WHITELIST = 2
CMD_LOAD_RULE_FILE = 3
CMD_CLEAR_RULES = 4
CMD_AUTHORIZE_UNLOAD = 5
CMD_REVOKE_UNLOAD = 6
CMD_QUERY_STATE = 7
CMD_QUERY_RANSOM = 8
CMD_RESTORE_FILES = 9
CMD_QUERY_METRICS = 10

RESTORE_MODE_ROLLBACK = 0
RESTORE_MODE_RELEASE = 1

# 处置动作（与 inc/DragonProtocol.h 的 DRG_ACTION_* 一致）
ACTION_UNSET = 0xFFFFFFFF
ACTION_REPORT = 0
ACTION_TERMINATE = 1

ACTION_NAMES = {
    ACTION_REPORT: "Report",
    ACTION_TERMINATE: "Terminate",
}

# 内置自保护事件码（驱动硬编码，不受规则增删影响）
SELF_CODE_NAMES = {
    9001: "SELF-IMAGE(驱动镜像被改写)",
    9002: "SELF-RULE-DIR(规则目录被改写)",
    9003: "SELF-SERVICE-KEY(服务注册表键被改写)",
    9004: "SELF-CLIENT(客户端进程被终止 / 处置权限被剥夺)",
    9005: "PROTECTED-TARGET(受保护进程被操作)",
    9006: "SELF-GUARD(主程序/外置文件被改写)",
    9007: "SELF-BACKUP(勒索备份区被非内核发起者写入)",
}

FLAG_RULES_LOADED = 0x00000001
FLAG_CLIENT_ATTACHED = 0x00000002

STATE_NAMES = {
    0: "Cold",
    1: "Starting",
    2: "Running",
    3: "Stopping",
    4: "StopRetry",
    5: "Stopped",
}


# --------------------------------------------------------------------------
# 结构体
# --------------------------------------------------------------------------
class ConnectionContext(ctypes.Structure):
    _fields_ = [
        ("Size", wintypes.ULONG),
        ("Version", wintypes.ULONG),
        ("Magic", wintypes.ULONG),
        ("ProcessId", wintypes.ULONG),
    ]


class CommandMessage(ctypes.Structure):
    """与 inc/DragonProtocol.h 的 DRG_COMMAND_MESSAGE 逐字段对应（协议 v3）。

    Argument 是 v3 新增的通用参数位，目前用于区分恢复命令的两种模式；
    不使用它的命令必须传 0。注意字段顺序与内核侧严格一致，改动必须同步。
    """

    _fields_ = [
        ("Command", wintypes.ULONG),
        ("Argument", wintypes.ULONG),
        ("Path", wintypes.WCHAR * PATH_CHARS),
    ]


class RansomStatus(ctypes.Structure):
    """与 DRG_RANSOM_STATUS 逐字段对应。"""

    _fields_ = [
        ("Blocking", wintypes.ULONG),
        ("BlockedProcesses", wintypes.ULONG),
        ("TrackedProcesses", wintypes.ULONG),
        ("MaxScore", wintypes.ULONG),
        ("DetectionFlags", wintypes.ULONG),
        ("BlockedPid", wintypes.ULONG),
        ("BackupsCreated", wintypes.ULONG),
        ("RestoredFiles", wintypes.ULONG),
        ("Records", wintypes.ULONG),
        ("BackingOff", wintypes.ULONG),
        ("Reserved", wintypes.ULONG * 6),
    ]


class RestoreReply(ctypes.Structure):
    """与 DRG_RESTORE_REPLY 对应。"""

    _fields_ = [
        ("Requested", wintypes.ULONG),
        ("Restored", wintypes.ULONG),
        ("Failed", wintypes.ULONG),
        ("Released", wintypes.ULONG),
    ]


class Metrics(ctypes.Structure):
    """与 DRG_METRICS 逐字段对应。"""

    _fields_ = [
        ("ProtocolVersion", wintypes.ULONG),
        ("DriverState", wintypes.ULONG),
        ("RuleCount", wintypes.ULONG),
        ("GuardPathCount", wintypes.ULONG),
        ("ProcessCreateCalls", ctypes.c_ulonglong),
        ("ProcessAccessCalls", ctypes.c_ulonglong),
        ("ThreadCreateCalls", ctypes.c_ulonglong),
        ("ImageLoadCalls", ctypes.c_ulonglong),
        ("FileCreateCalls", ctypes.c_ulonglong),
        ("FileWriteCalls", ctypes.c_ulonglong),
        ("FileSetInfoCalls", ctypes.c_ulonglong),
        ("RegistryCalls", ctypes.c_ulonglong),
        ("DeviceIoctlCalls", ctypes.c_ulonglong),
        ("RulesEvaluated", ctypes.c_ulonglong),
        ("RulesHit", ctypes.c_ulonglong),
        ("Blocked", ctypes.c_ulonglong),
        ("Terminated", ctypes.c_ulonglong),
        ("SelfProtectHits", ctypes.c_ulonglong),
        ("RansomBlocks", ctypes.c_ulonglong),
        ("RansomBackups", ctypes.c_ulonglong),
        ("RansomRestores", ctypes.c_ulonglong),
        ("TrustCacheHits", ctypes.c_ulonglong),
        ("EventsReported", ctypes.c_ulonglong),
        ("EventsDropped", ctypes.c_ulonglong),
        ("LastCallbackKind", wintypes.ULONG),
        ("LastRuleCode", wintypes.ULONG),
        ("LastAction", wintypes.ULONG),
        ("LastProcessId", wintypes.ULONG),
        ("LastPath", wintypes.WCHAR * 520),
    ]


RANSOM_SIGNAL_NAMES = {
    0x01: "大量修改",
    0x02: "大量删除",
    0x04: "大量重命名",
    0x08: "扩展名变更",
    0x10: "高随机性写入",
    0x20: "类型多样性",
    0x40: "目录多样性",
    0x80: "写入过频",
}

METRIC_CALLBACK_NAMES = {
    0: "-",
    1: "进程创建",
    2: "句柄访问",
    3: "线程创建",
    4: "映像加载",
    5: "文件创建",
    6: "文件写入",
    7: "文件改名/删除",
    8: "注册表",
    9: "设备IOCTL",
}


class EventPayload(ctypes.Structure):
    """与 inc/DragonProtocol.h 的 DRG_EVENT 逐字段对应。

    Action 是本条事件对应的处置动作（Report / Terminate），供审计与呈现；
    内核侧的处置在内核完成，用户态只读取与记录。
    """
    _fields_ = [
        ("MessageCode", wintypes.ULONG),
        ("Action", wintypes.ULONG),
        ("ProcessId", wintypes.ULONG),
        ("Path", wintypes.WCHAR * PATH_CHARS),
    ]


# 布局守卫：必须与 inc/DragonProtocol.h 的 DRG_EVENT 逐字段一致，
# 否则事件里的 Action / ProcessId 会整体错位（驱动侧也有同尺寸的编译期断言）。
_EVENT_EXPECTED_BYTES = 3 * 4 + PATH_CHARS * 2
assert ctypes.sizeof(EventPayload) == _EVENT_EXPECTED_BYTES, (
    "EventPayload(%d 字节) 与内核 DRG_EVENT(%d 字节) 不一致，请同步 inc/DragonProtocol.h"
    % (ctypes.sizeof(EventPayload), _EVENT_EXPECTED_BYTES)
)


class FilterMessageHeader(ctypes.Structure):
    _fields_ = [
        ("ReplyLength", wintypes.ULONG),
        ("MessageId", ctypes.c_ulonglong),
    ]


class FullMessage(ctypes.Structure):
    _fields_ = [
        ("Header", FilterMessageHeader),
        ("Data", EventPayload),
    ]


class StateReply(ctypes.Structure):
    _fields_ = [
        ("State", wintypes.ULONG),
        ("Flags", wintypes.ULONG),
    ]


class Overlapped(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_ulonglong),
        ("InternalHigh", ctypes.c_ulonglong),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


# --------------------------------------------------------------------------
# fltlib 绑定
# --------------------------------------------------------------------------
FLTLIB = ctypes.WinDLL("fltlib.dll")

FLTLIB.FilterConnectCommunicationPort.restype = ctypes.c_long
FLTLIB.FilterConnectCommunicationPort.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.WORD,
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.HANDLE),
]

FLTLIB.FilterSendMessage.restype = ctypes.c_long
FLTLIB.FilterSendMessage.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]

FLTLIB.FilterGetMessage.restype = ctypes.c_long
FLTLIB.FilterGetMessage.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(Overlapped),
]

KERNEL32 = ctypes.WinDLL("kernel32.dll")
KERNEL32.CreateEventW.restype = wintypes.HANDLE
KERNEL32.CreateEventW.argtypes = [
    ctypes.c_void_p,
    wintypes.BOOL,
    wintypes.BOOL,
    wintypes.LPCWSTR,
]
KERNEL32.WaitForSingleObject.restype = wintypes.DWORD
KERNEL32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
KERNEL32.GetOverlappedResult.restype = wintypes.BOOL
KERNEL32.GetOverlappedResult.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(Overlapped),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
]
KERNEL32.CancelIo.restype = wintypes.BOOL
KERNEL32.CancelIo.argtypes = [wintypes.HANDLE]
KERNEL32.CloseHandle.restype = wintypes.BOOL
KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]


def _hr(status: int) -> int:
    """把 Filter Manager 返回的 NTSTATUS 规范成无符号 32 位。"""
    return status & 0xFFFFFFFF


# --------------------------------------------------------------------------
# 连接失败时的身份诊断
#
# 驱动侧用 SeLocateProcessImageName 取发起连接的进程映像名，与注册表
# Parameters\ClientImagePath 做**全等比较**；该例程返回的是**设备路径形式**
# （\Device\HarddiskVolumeN\...）。两侧形式不一致时端口会一律拒绝，
# 而且现象只是「连不上」，很难猜。这里直接把两个值并排打出来。
# --------------------------------------------------------------------------
def _to_nt_path(path: str) -> str:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p]
    k32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    k32.GetFinalPathNameByHandleW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                              wintypes.DWORD, wintypes.DWORD]
    k32.CloseHandle.argtypes = [ctypes.c_void_p]

    handle = k32.CreateFileW(path, 0, 0x7, None, 3, 0x80, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        return path
    try:
        buffer = ctypes.create_unicode_buffer(1024)
        length = k32.GetFinalPathNameByHandleW(handle, buffer, 1024, 0x2)
        return buffer.value if 0 < length < 1024 else path
    finally:
        k32.CloseHandle(handle)


def _explain_identity() -> None:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    buffer = ctypes.create_unicode_buffer(1024)
    k32.GetModuleFileNameW(None, buffer, 1024)

    print("[诊断] 端口连接被拒时，先核对下面两个值是否**完全一致**：")
    print(f"       本进程映像（驱动看到的）: {_to_nt_path(buffer.value)}")

    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\Dragon-Drivers\Parameters",
                            0, winreg.KEY_READ) as key:
            registered, _ = winreg.QueryValueEx(key, "ClientImagePath")
        print(f"       驱动登记值（注册表）    : {registered}")
    except OSError:
        print("       驱动登记值（注册表）    : (未登记 —— 端口会拒绝一切连接)")
        print("       登记命令：python tools\\deploy_dragon.py --set-client \"<python.exe 完整路径>\" --yes")
        return

    print("       若两者不一致：客户端必须用登记的那一个镜像运行；")
    print("       或在驱动停止状态下重新登记：deploy_dragon.py --set-client ... --yes")


# --------------------------------------------------------------------------
# 客户端
# --------------------------------------------------------------------------
class DragonClient:
    def __init__(self, port_name: str = PORT_NAME) -> None:
        self.port_name = port_name
        self.port: Optional[int] = None

    # ---------------------------------------------------------------- 连接
    def connect(self, asynchronous: bool = False) -> bool:
        if self.port is not None:
            return True

        context = ConnectionContext()
        context.Size = ctypes.sizeof(ConnectionContext)
        context.Version = CONNECTION_VERSION
        context.Magic = CONNECTION_MAGIC
        context.ProcessId = os.getpid()

        handle = wintypes.HANDLE()
        status = _hr(
            FLTLIB.FilterConnectCommunicationPort(
                self.port_name,
                0 if asynchronous else FLT_PORT_FLAG_SYNC_HANDLE,
                ctypes.byref(context),
                ctypes.sizeof(context),
                None,
                ctypes.byref(handle),
            )
        )

        if status != 0:
            print(f"[ERR] FilterConnectCommunicationPort 失败: 0x{status:08X}")
            self._explain(status)
            _explain_identity()
            return False

        self.port = handle.value
        print(f"[ OK ] 已连接到 {self.port_name} (handle={self.port:#x})")
        return True

    @staticmethod
    def _explain(status: int) -> None:
        hints = {
            0xC0000022: "访问被拒绝 —— 驱动 Parameters\\ClientImagePath 未登记为本进程镜像路径",
            0xC00000AC: "设备忙 —— 已有客户端占用该端口（MaxConnections = 1）",
            0xC00000E5: "设备未就绪 —— 驱动不在 Running / StopRetry 状态",
            0xC0000101: "目录非空/端口不存在 —— 服务未启动或端口名不匹配",
        }
        hint = hints.get(status)
        if hint:
            print(f"       可能原因: {hint}")

    def disconnect(self) -> None:
        if self.port is not None:
            KERNEL32.CloseHandle(self.port)
            self.port = None

    # ---------------------------------------------------------------- 命令
    def send_command(self, command: int, path: str = "", argument: int = 0,
                     want_reply: bool = False, reply_type=None):
        """下发命令并可选地解析回复。

        reply_type 指定输出缓冲区的 ctypes 结构体：
          · 不传 —— 按旧版 StateReply 处理并打印一行状态；
          · 传入 —— 直接返回解析好的结构体，由调用方决定怎么呈现。
        """
        if not self.connect():
            return None

        message = CommandMessage()
        message.Command = command
        message.Argument = argument
        message.Path = path

        reply_cls = reply_type or StateReply
        reply = reply_cls() if want_reply else None
        returned = wintypes.DWORD(0)

        status = _hr(
            FLTLIB.FilterSendMessage(
                self.port,
                ctypes.byref(message),
                ctypes.sizeof(message),
                ctypes.byref(reply) if reply is not None else None,
                ctypes.sizeof(reply_cls) if reply is not None else 0,
                ctypes.byref(returned),
            )
        )

        if status != 0:
            print(f"[ERR] 命令 {command} 失败: 0x{status:08X}")
            return None

        if reply is None:
            print(f"[ OK ] 命令 {command} 已下发" + (f" path={path}" if path else ""))
            return True

        if reply_type is not None:
            return reply

        flags = []
        if reply.Flags & FLAG_RULES_LOADED:
            flags.append("RulesLoaded")
        if reply.Flags & FLAG_CLIENT_ATTACHED:
            flags.append("ClientAttached")

        print(f"[ OK ] 状态 = {reply.State} ({STATE_NAMES.get(reply.State, '?')}) "
              f"flags = {reply.Flags:#x} [{', '.join(flags) if flags else '-'}]")
        return reply

    # ---------------------------------------------------------------- 事件
    def listen(self, stop_flag=lambda: False, on_event=None) -> None:
        """异步接收内核上报事件，直到 stop_flag 为真。

        on_event: 可选回调，签名为 (code, action, pid, path)；传入后内核事件不再
        打印，而是交给该回调（供主程序接入主动防御逻辑）。省略则沿用原命令行打印。
        """
        self._on_event = on_event
        port = self.port if self.port is not None else None
        if port is None:
            if not self.connect():
                return
            port = self.port

        message = FullMessage()
        overlapped = Overlapped()
        event = KERNEL32.CreateEventW(None, True, False, None)
        if not event:
            print("[ERR] CreateEventW 失败")
            return

        overlapped.hEvent = event

        try:
            print("[INFO] 开始监听内核事件（Ctrl+C 退出）...")
            while not stop_flag():

                status = _hr(
                    FLTLIB.FilterGetMessage(
                        port,
                        ctypes.byref(message),
                        ctypes.sizeof(FullMessage),
                        ctypes.byref(overlapped),
                    )
                )

                if status == 0:
                    self._handle_event(message)
                    continue

                if status != HRESULT_IO_PENDING:
                    print(f"[ERR] FilterGetMessage 失败: 0x{status:08X}")
                    return

                while True:
                    if stop_flag():
                        KERNEL32.CancelIo(port)
                        return

                    wait = KERNEL32.WaitForSingleObject(event, 200)
                    if wait == 0x00000102:      # WAIT_TIMEOUT
                        continue
                    if wait != 0:
                        print("[ERR] 等待事件失败")
                        return

                    transferred = wintypes.DWORD(0)
                    if KERNEL32.GetOverlappedResult(
                        port, ctypes.byref(overlapped), ctypes.byref(transferred), False
                    ):
                        self._handle_event(message)
                    break
        finally:
            KERNEL32.CloseHandle(event)

    def _handle_event(self, message: FullMessage) -> None:
        data = message.Data
        code = data.MessageCode
        action = data.Action
        pid = data.ProcessId
        path = data.Path

        if self._on_event is not None:
            try:
                self._on_event(code, action, pid, path)
                return
            except Exception:
                pass

        code_name = SELF_CODE_NAMES.get(code, "rule=%d" % code)
        action_name = ACTION_NAMES.get(action, "0x%X" % action)
        print(
            "[EVENT] %s action=%s pid=%d target=%s"
            % (code_name, action_name, pid, path)
        )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="Dragon-Drivers 用户态客户端")
    parser.add_argument("--port", default=PORT_NAME)
    parser.add_argument("--state", action="store_true", help="查询驱动状态")
    parser.add_argument("--add-whitelist", metavar="PATTERN")
    parser.add_argument("--remove-whitelist", metavar="PATTERN")
    parser.add_argument("--load-rules", metavar="PATH", help="加载规则 JSON（自动补 \\??\\ 前缀）")
    parser.add_argument("--clear-rules", action="store_true")
    parser.add_argument("--authorize-unload", action="store_true")
    parser.add_argument("--revoke-unload", action="store_true")
    parser.add_argument("--listen", action="store_true")
    parser.add_argument("--ransom", action="store_true", help="查询勒索防护状态")
    parser.add_argument(
        "--ransom-restore", metavar="PATH", nargs="?", const="",
        help="从备份恢复并解除阻断（省略 PATH = 恢复全部）",
    )
    parser.add_argument("--ransom-release", action="store_true", help="仅解除阻断，不恢复文件")
    parser.add_argument("--metrics", action="store_true", help="查询诊断统计")
    args = parser.parse_args()

    client = DragonClient(args.port)

    if args.state:
        client.send_command(CMD_QUERY_STATE, want_reply=True)
    if args.add_whitelist:
        client.send_command(CMD_ADD_WHITELIST, args.add_whitelist)
    if args.remove_whitelist:
        client.send_command(CMD_REMOVE_WHITELIST, args.remove_whitelist)
    if args.load_rules:
        path = os.path.abspath(args.load_rules)
        if not path.startswith("\\\\?\\"):
            path = "\\??\\" + path
        client.send_command(CMD_LOAD_RULE_FILE, path)
    if args.clear_rules:
        client.send_command(CMD_CLEAR_RULES)
    if args.authorize_unload:
        client.send_command(CMD_AUTHORIZE_UNLOAD)
    if args.revoke_unload:
        client.send_command(CMD_REVOKE_UNLOAD)

    if args.ransom:
        # 驱动状态来自独立的状态查询；DRG_RANSOM_STATUS 协议体本身不含 State 字段
        state_reply = client.send_command(
            CMD_QUERY_STATE, want_reply=True, reply_type=StateReply)
        state_name = STATE_NAMES.get(state_reply.State, "-") if state_reply is not None else "-"
        reply = client.send_command(
            CMD_QUERY_RANSOM, want_reply=True, reply_type=RansomStatus)
        if reply is not None:
            print_ransom_status(reply, state_name)

    if args.ransom_restore is not None:
        reply = client.send_command(
            CMD_RESTORE_FILES, args.ransom_restore, RESTORE_MODE_ROLLBACK,
            want_reply=True, reply_type=RestoreReply)
        if reply is not None:
            print(f"[ OK ] 恢复：目标 {reply.Requested} 个 / 成功 {reply.Restored} 个 / "
                  f"失败 {reply.Failed} 个 / 解除阻断 {reply.Released} 个进程")

    if args.ransom_release:
        reply = client.send_command(
            CMD_RESTORE_FILES, "", RESTORE_MODE_RELEASE,
            want_reply=True, reply_type=RestoreReply)
        if reply is not None:
            print(f"[ OK ] 已解除 {reply.Released} 个进程的勒索阻断")

    if args.metrics:
        reply = client.send_command(
            CMD_QUERY_METRICS, want_reply=True, reply_type=Metrics)
        if reply is not None:
            print_metrics(reply)

    if args.listen:
        try:
            client.listen()
        except KeyboardInterrupt:
            print("\n[INFO] 已停止监听")
    elif not any(
        [
            args.state,
            args.add_whitelist,
            args.remove_whitelist,
            args.load_rules,
            args.clear_rules,
            args.authorize_unload,
            args.revoke_unload,
            args.ransom,
            args.ransom_restore is not None,
            args.ransom_release,
            args.metrics,
        ]
    ):
        parser.print_help()

    client.disconnect()
    return 0


def print_ransom_status(reply, state_name: str = "-") -> None:
    """呈现勒索防护状态。"""
    signals = [
        name for bit, name in RANSOM_SIGNAL_NAMES.items()
        if reply.DetectionFlags & bit
    ]

    print("[勒索防护]")
    print(f"  驱动状态        : {state_name}")
    print(f"  正在阻断        : {'是' if reply.Blocking else '否'}"
          f"（阻断 {reply.BlockedProcesses} 个 / 跟踪 {reply.TrackedProcesses} 个进程）")
    print(f"  最高评分        : {reply.MaxScore}"
          + (f"（进程 {reply.BlockedPid}）" if reply.BlockedPid else ""))
    print(f"  命中的信号      : {', '.join(signals) if signals else '-'}")
    print(f"  已创建备份      : {reply.BackupsCreated} 个")
    print(f"  已恢复文件      : {reply.RestoredFiles} 个")
    print(f"  受影响记录      : {reply.Records} 条")
    print("  备份目录        : 见驱动服务键 Parameters\\RansomBackupDir"
          "（未配置时为驱动镜像同级的 RansomBackup\\）")


def print_metrics(reply) -> None:
    """呈现诊断统计。"""
    print("[诊断统计]")
    print(f"  协议版本        : {reply.ProtocolVersion}")
    print(f"  动态规则条数    : {reply.RuleCount}")
    print(f"  自保护清单条数  : {reply.GuardPathCount}")
    print()
    print("  回调调用次数")
    print(f"    进程创建      : {reply.ProcessCreateCalls}")
    print(f"    句柄访问      : {reply.ProcessAccessCalls}")
    print(f"    线程创建      : {reply.ThreadCreateCalls}")
    print(f"    映像加载      : {reply.ImageLoadCalls}")
    print(f"    文件创建      : {reply.FileCreateCalls}")
    print(f"    文件写入      : {reply.FileWriteCalls}")
    print(f"    文件改名/删除 : {reply.FileSetInfoCalls}")
    print(f"    注册表        : {reply.RegistryCalls}")
    print(f"    设备IOCTL     : {reply.DeviceIoctlCalls}")
    print()
    print("  判定与处置")
    print(f"    进入规则评估  : {reply.RulesEvaluated}")
    print(f"    规则命中      : {reply.RulesHit}")
    print(f"    拦截          : {reply.Blocked}")
    print(f"    终止作业      : {reply.Terminated}")
    print(f"    自保护命中    : {reply.SelfProtectHits}")
    print(f"    勒索阻断      : {reply.RansomBlocks}")
    print(f"    勒索备份      : {reply.RansomBackups}")
    print(f"    备份恢复      : {reply.RansomRestores}")
    print(f"    信任缓存命中  : {reply.TrustCacheHits}")
    print()
    print(f"  事件上报        : {reply.EventsReported}（丢弃 {reply.EventsDropped}）")
    print(f"  最近一次动作    : 回调={METRIC_CALLBACK_NAMES.get(reply.LastCallbackKind, '?')} "
          f"规则={reply.LastRuleCode} 动作={reply.LastAction} PID={reply.LastProcessId}")
    print(f"                    路径={reply.LastPath or '-'}")


if __name__ == "__main__":
    sys.exit(main())
