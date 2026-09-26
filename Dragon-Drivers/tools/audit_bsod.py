#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""临时脚本：驱动蓝屏（bugcheck）隐患审计。

与上一版的区别：扫描前先**剥离注释与字符串字面量**。上一版把注释里出现的
API 名、以及互斥释放路径都算成了问题，产生大量误报；先剥离再扫可以消除这
一类噪声，让「FAIL」只剩真正需要处理的东西。
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
INC = ROOT / "inc"

results = []


def check(label, ok, detail=""):
    results.append((label, ok, detail))


def strip_comments(text: str) -> str:
    """去掉 C 注释与字符串字面量内容，保留换行以维持行号。"""
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("\n" * text.count("\n", i, j))
            i = j
        elif ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            i = j
        elif ch in "\"'":
            quote = ch
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                if text[j] == "\n":
                    break
                j += 1
            out.append(" " * (j - i))
            i = j
        else:
            out.append(ch)
            i += 1
    return "".join(out)


raw = {p.name: p.read_text(encoding="utf-8") for p in sorted(SRC.glob("*.c"))}
raw_h = {p.name: p.read_text(encoding="utf-8") for p in sorted(INC.glob("*.h"))}
code = {n: strip_comments(t) for n, t in raw.items()}
all_code = "\n".join(code.values())

print("=" * 74)
print("Dragon-Drivers 蓝屏隐患审计（已剥离注释）")
print("=" * 74)

# --------------------------------------------------------------------------
print("\n[A] PASSIVE-only API：调用点必须有 IRQL 守卫")
# --------------------------------------------------------------------------
# 注意：ExAllocatePool2 不在此列 —— 它的文档上限是 DISPATCH_LEVEL
# （只有分页池标志才要求 <= APC_LEVEL），当作 PASSIVE-only 是错的。
# PsLookupProcessByProcessId / PsLookupThreadByThreadId 同理（<= APC_LEVEL）。
PASSIVE_ONLY = [
    "SeLocateProcessImageName", "KeStackAttachProcess", "KeDelayExecutionThread",
    "ZwTerminateProcess", "ZwCreateFile", "ZwReadFile", "ZwWriteFile",
    "ZwQueryVirtualMemory", "ZwQueryValueKey",
]
def enclosing_function(lines, line_no):
    """line_no 为 1-based。本工程风格：函数名单独一行，其上一行是返回类型。"""
    for i in range(line_no - 1, -1, -1):
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\($", lines[i])
        if m and i > 0 and re.match(r"^(static\s+)?[A-Za-z_][A-Za-z0-9_]*$",
                                   lines[i - 1].strip()):
            return m.group(1)
    return "?"


# 白名单分两类，每类都必须写明依据，避免变成「无脑忽略」。

# 1) 只在 DriverEntry 初始化链上被调用 —— 已逐个核对调用点，不含回调路径。
INIT_ONLY_FUNCTIONS = {
    "DragonRansomInitialize", "DragonRansomEnsureDirectory",
    "DragonRulesLoadFromDisk", "DragonReadClientImageValue",
    "DragonSelfReadImagePath", "DragonSelfLoadGuardPaths",
}

# 2) 由回调 / 命令路径进入，但入口侧已有守卫或由框架保证。
CALLBACK_CHAIN_VERIFIED = {
    "DragonRansomBackup":
        "唯一调用点 DragonFileGuard.c:271 带 KeGetCurrentIrql()==PASSIVE_LEVEL 守卫",
    "DragonRansomBackupExists": "经 DragonRansomBackup，同上",
    "DragonRansomCopyToBackup": "经 DragonRansomBackup，同上",
    "DragonRansomRestore":
        "入口是通信端口消息回调，FltMgr 文档保证 PFLT_MESSAGE_NOTIFY IRQL=PASSIVE_LEVEL",
    "DragonRansomRestoreOne": "仅由 DragonRansomRestore 调用，同上",
    "DragonRansomCanonPath":
        "仅由 DragonRansomRestoreOne 调用；入口是通信端口消息回调，"
        "FltMgr 文档保证 PFLT_MESSAGE_NOTIFY IRQL=PASSIVE_LEVEL，"
        "故其内部的 ZwCreateFile / ZwQueryInformationFile / ZwClose 均处于 PASSIVE_LEVEL",
    "DragonRulesLoadFile":
        "入口有二：DriverEntry 启动期加载、命令通道下发，均 PASSIVE_LEVEL",
}

unguarded = []
verified_hits = set()
for name, text in code.items():
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        for api in PASSIVE_ONLY:
            if api + "(" not in line:
                continue
            window = "\n".join(lines[max(0, i - 60):i])
            if "KeGetCurrentIrql()" in window or "PassiveLevel" in window:
                continue
            fn = enclosing_function(lines, i)
            if fn in INIT_ONLY_FUNCTIONS or fn in CALLBACK_CHAIN_VERIFIED:
                verified_hits.add(fn)
            else:
                unguarded.append(f"{name}:{i} {api} @{fn}")

check(f"PASSIVE-only 调用点守卫（{len(PASSIVE_ONLY)} 个 API）",
      not unguarded,
      "; ".join(unguarded[:6])
      or (f"另有 {len(verified_hits)} 个函数经调用链/框架保证："
          + ", ".join(sorted(verified_hits)) if verified_hits else ""))

# --------------------------------------------------------------------------
print("\n[B] 自旋锁：释放次数不得少于获取次数；临界区内无阻塞调用")
# --------------------------------------------------------------------------
BLOCKING = [
    "ZwCreateFile", "ZwReadFile", "ZwWriteFile", "ZwClose", "FltSendMessage",
    "FltGetFileNameInformation", "SeLocateProcessImageName",
    "PsLookupProcessByProcessId", "PsLookupThreadByThreadId",
    "ObReferenceObjectByHandle", "ObDereferenceObject",
    "KeWaitForSingleObject", "KeDelayExecutionThread", "KeStackAttachProcess",
    "ExAllocatePool", "ExFreePool", "WdfObjectDelete", "WdfWorkItemFlush",
    "ZwTerminateProcess", "DbgPrintEx", "ExWaitForRundownProtectionRelease",
]
pairing_bad = []
heavy_in_lock = []
for name, text in code.items():
    acq = len(re.findall(r"\bKeAcquireSpinLock\s*\(", text)) + \
          len(re.findall(r"\bWdfSpinLockAcquire\s*\(", text))
    rel = len(re.findall(r"\bKeReleaseSpinLock\s*\(", text)) + \
          len(re.findall(r"\bWdfSpinLockRelease\s*\(", text))
    # 一个 acquire 可以对应多个互斥的 release（错误分支），因此只禁止 rel < acq
    if rel < acq:
        pairing_bad.append(f"{name} acq={acq} rel={rel}")

    lines = text.splitlines()
    depth = 0
    for i, line in enumerate(lines, 1):
        if depth == 0 and re.search(r"KeAcquireSpinLock|WdfSpinLockAcquire", line) \
                and "Release" not in line:
            depth = 1
            continue
        if depth:
            for api in BLOCKING:
                if api + "(" in line:
                    heavy_in_lock.append(f"{name}:{i} {api}")
            if re.search(r"KeReleaseSpinLock|WdfSpinLockRelease", line):
                depth = 0

check("自旋锁释放不少于获取（rel >= acq）", not pairing_bad, "; ".join(pairing_bad))
check("自旋锁临界区内无阻塞调用", not heavy_in_lock, "; ".join(heavy_in_lock[:6]))

# --------------------------------------------------------------------------
print("\n[C] 未文档化 API 与动态解析")
# --------------------------------------------------------------------------
FORBIDDEN = [
    "PsSuspendProcess", "PsResumeProcess", "ZwSuspendProcess", "ZwResumeProcess",
    "ZwSuspendThread", "ZwResumeThread", "NtSuspendProcess", "NtResumeProcess",
    "PsGetProcessInheritedFromUniqueProcessId", "MmGetSystemRoutineAddress",
    "PsGetProcessImageFileName", "KeSuspendThread", "KeResumeThread",
]
hits = [api for api in FORBIDDEN if api in all_code]
check(f"代码中零未文档化 API（{len(FORBIDDEN)} 个）", not hits, ", ".join(hits))

# --------------------------------------------------------------------------
print("\n[D] 本轮新增：豁免目录代码专项")
# --------------------------------------------------------------------------
sp = code["DragonSelfProtect.c"]
ransom = code["DragonRansom.c"]
fileguard = code["DragonFileGuard.c"]

body = sp[sp.index("DragonSelfProtectFile("):]
check("豁免判定排在 GuardPaths 之前",
      body.index("g_Self.ExemptCount") < body.index("g_Self.GuardPathCount"))

add_body = sp[sp.index("DragonSelfProtectAddExemptDir("):]
add_body = add_body[:add_body.index("\nULONG\n")]
check("追加前检查槽位上限", "g_Self.ExemptCount >= DRG_SELF_EXEMPT_SLOTS" in add_body)
check("槽位索引只来自 ExemptCount 范围内的 Index",
      set(re.findall(r"ExemptDirs\[(\w+)\]", add_body)) <= {"Index"})
check("ExemptCount 自增发生在写入之后",
      add_body.index("RtlCopyMemory(g_Self.ExemptDirs[Index]") < add_body.index("g_Self.ExemptCount++"))
check("归一化失败时提前返回不污染表",
      add_body.index("DragonSelfNormalize") < add_body.index("g_Self.ExemptCount++"))
# 字符串字面量的内容在剥离注释时已被清空，这一项必须用原始文本查
add_raw = raw["DragonSelfProtect.c"]
add_raw = add_raw[add_raw.index("DragonSelfProtectAddExemptDir("):]
add_raw = add_raw[:add_raw.index("\nULONG\n")]
check("登记前检查自保护就绪（日志字符串存在）",
      "before self-protect ready" in add_raw)

call_sites = []
for n, t in code.items():
    for i, l in enumerate(t.splitlines(), 1):
        if "DragonSelfProtectAddExemptDir(" not in l:
            continue
        if l.rstrip().endswith("(") or "#define" in l:   # 函数定义行
            continue
        call_sites.append(f"{n}:{i}")
check("AddExemptDir 调用点唯一且在初始化路径",
      len(call_sites) == 1 and "DragonRansom" in call_sites[0], str(call_sites))
check("文件回调传入 ProcessId", "DragonSelfProtectFile(ProcessId," in fileguard)

proto = strip_comments(raw_h["DragonProtocol.h"])
check("9007 事件码已定义", "DRG_CODE_SELF_BACKUP       9007u" in proto)
check("System PID 常量 = 4", "DRG_SELF_SYSTEM_PID  4u" in sp)
client = (ROOT / "tools" / "dragon_client.py").read_text(encoding="utf-8")
check("客户端事件码表含 9007", "9007:" in client)
check("豁免表随 Teardown 清零", "RtlZeroMemory(&g_Self, sizeof(g_Self))" in sp)

# --------------------------------------------------------------------------
print("\n[E] 勒索模块的 IRQL 面（本轮修复点）")
# --------------------------------------------------------------------------
sysproc = ransom[ransom.index("DragonRansomIsSystemProcess("):]
sysproc = sysproc[:sysproc.index("ExFreePool(ImagePath);")]
check("IsSystemProcess 在非 PASSIVE 时不调用 SeLocateProcessImageName",
      sysproc.index("KeGetCurrentIrql() != PASSIVE_LEVEL") < sysproc.index("SeLocateProcessImageName"))

evaluate = ransom[ransom.index("DragonRansomEvaluate("):]
check("备份调用点在文件回调侧有 PASSIVE 守卫",
      "KeGetCurrentIrql() == PASSIVE_LEVEL" in fileguard[
          fileguard.index("DragonRansomBackup(") - 900:
          fileguard.index("DragonRansomBackup(") + 100])

# --------------------------------------------------------------------------
print("\n[F] WDF 句柄使用前判空")
# --------------------------------------------------------------------------
HANDLES = ["DrainWorkItem", "ControlDevice", "ConnectionLock"]
# 工作项回调内部对自身的重新入队：句柄即当前正在执行的那个工作项，必然有效；
# 生命周期由 EnqueueActive 计数 + WdfWorkItemFlush 保证（见 DragonResponse.c 排空流程）。
SELF_HANDLE_OK = {"DragonDrainEvtWorkItem"}
unguarded_handle = []
for name, text in code.items():
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        for h in HANDLES:
            if re.search(rf"Wdf\w+\(\s*g_Dragon\.{h}\s*[,)]", line):
                window = "\n".join(lines[max(0, i - 80):i])
                if f"g_Dragon.{h}" in window.replace(line, ""):
                    continue
                if enclosing_function(lines, i) in SELF_HANDLE_OK:
                    continue
                unguarded_handle.append(f"{name}:{i} {h}")
check("WDF 句柄调用前有 80 行内的判空/就绪检查", not unguarded_handle,
      "; ".join(unguarded_handle[:6]))

# --------------------------------------------------------------------------
print("\n[G] SEH：__except 块内不得有 goto")
# --------------------------------------------------------------------------
seh_bad = []
for name, text in code.items():
    for m in re.finditer(r"__except\s*\(([^)]*)\)\s*\{", text):
        i = m.end()
        depth = 1
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        if re.search(r"\bgoto\b", text[m.end():i - 1]):
            seh_bad.append(f"{name}:{text[:m.start()].count(chr(10)) + 1}")
check("__except 块内无 goto", not seh_bad, "; ".join(seh_bad))

# --------------------------------------------------------------------------
print("\n" + "=" * 74)
failed = [r for r in results if not r[1]]
for label, ok, detail in results:
    print(f"{'[ OK  ]' if ok else '[FAIL ]'} {label}")
    if detail:
        print(f"         {detail}")
print("=" * 74)
print(f"结论：{len(results) - len(failed)}/{len(results)} 项通过"
      + ("" if not failed else f" —— {len(failed)} 项需处理"))
print("=" * 74)
