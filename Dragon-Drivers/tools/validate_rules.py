#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验自写规则包：键名与枚举字面量必须能被驱动解析器识别，
否则规则会被静默丢弃（未知键走 SkipValue，非法值置 Invalid）。"""

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

SUPPORTED_KEYS = {
    "Action", "Category", "Code", "CommandLine", "CommandLineExclude",
    "Creator", "CreatorExclude", "Extensions", "FileOpenNameAvailable",
    "HandleTypes", "Initiator", "InitiatorExclude", "InitiatorParent",
    "InitiatorParentExclude", "InitiatorProcessTree", "InitiatorProcessTreeExclude",
    "Kill", "MaximumRegionSize", "MaximumRiskScore", "MinimumRegionSize",
    "MinimumRiskScore", "ObjectTypes", "OperationMatch", "Operations", "Parent",
    "ParentExclude", "ParentMismatch", "Priority", "SubsystemProcess", "Target",
    "TargetExclude", "TargetProcessTree", "TargetProcessTreeExclude",
    "ThreadMemoryProtections", "ThreadMemoryTypes", "Threshold", "TimeWindow",
    "Note", "ValueNames",
}
OPERATIONS = {
    "Write", "Delete", "Create", "Execute", "Rename", "Ioctl",
    "VmRead", "VmWrite", "WriteMemory", "VmOperation",
    "CreateThread", "CreateRemoteThread", "SetThreadContext",
    "SetThreadToken", "Terminate", "SuspendResume", "DuplicateHandle",
    "SetInformation", "CreateProcess", "ImageLoad", "Impersonate",
}
CATEGORIES = {"Process", "File", "Registry", "Device", "Memory", "Thread"}
ACTIONS = {"Report", "Terminate"}
HANDLE_TYPES = {"Create", "Duplicate"}
OBJECT_TYPES = {"Process", "Thread"}
MEM_TYPES = {"Private", "Mapped", "Image"}
MEM_PROTECTIONS = {"Execute", "ExecuteWrite"}

REQUIRED_OPS = {
    "Process": {"Execute", "ImageLoad"},
    "Device": {"Ioctl"},
    "Thread": {"Execute"},
    "Memory": {"VmWrite", "VmOperation", "CreateThread", "CreateRemoteThread",
               "WriteMemory", "Terminate", "SuspendResume", "DuplicateHandle",
               "SetThreadContext", "SetThreadToken", "Impersonate", "VmRead"},
    "File": {"Write", "Delete", "Rename", "Create", "SetInformation"},
    "Registry": {"Write", "Delete", "Create"},
}

doc = json.loads((ROOT / "Rules" / "DragonDriver_DefenderRules.json").read_text(encoding="utf-8"))
rules = doc["DynamicRules"]
problems = []
seen = set()

for r in rules:
    code = r.get("Code")
    tag = "rule %s" % code

    if code in seen:
        problems.append("%s 编号重复" % tag)
    seen.add(code)

    for key in r:
        if key not in SUPPORTED_KEYS:
            problems.append("%s 含解析器不认识的键 %r（会被静默忽略）" % (tag, key))

    category = r.get("Category")
    if category not in CATEGORIES:
        problems.append("%s Category=%r 非法（会导致规则无效）" % (tag, category))
        continue

    action = r.get("Action")
    if action not in ACTIONS:
        problems.append("%s Action=%r 非法（会导致规则无效）" % (tag, action))

    ops = set(r.get("Operations", []))
    unknown = ops - OPERATIONS
    if unknown:
        problems.append("%s Operations 含非法取值 %s（会导致规则无效）" % (tag, sorted(unknown)))
    if not (ops & REQUIRED_OPS[category]):
        problems.append("%s Category=%s 的 Operations %s 与该类别事件的操作位不相交，规则永不命中"
                        % (tag, category, sorted(ops)))

    for key, allowed in (("HandleTypes", HANDLE_TYPES), ("ObjectTypes", OBJECT_TYPES),
                         ("ThreadMemoryTypes", MEM_TYPES),
                         ("ThreadMemoryProtections", MEM_PROTECTIONS)):
        if key in r:
            bad = set(r[key]) - allowed
            if bad:
                problems.append("%s %s 含非法取值 %s" % (tag, key, sorted(bad)))

    if not r.get("Target") and category in ("File", "Registry", "Memory", "Thread") and not r.get("TargetExclude"):
        problems.append("%s 没有 Target 也没有 TargetExclude，等于对全系统生效" % tag)

    # 命令行模式本来就需要多个 * 串起关键字（如 *vssadmin*delete*shadows*），
    # 因此只对路径类模式做「通配符过多」提醒。
    for key in ("Initiator", "Target"):
        for pattern in r.get(key, []):
            if pattern == "*":
                continue
            if pattern.count("*") > 3:
                problems.append("%s %s 的模式 %r 通配符过多，易误判" % (tag, key, pattern))

print("规则数：%d" % len(rules))
print("动作分布：%s" % {a: sum(1 for x in rules if x.get("Action") == a) for a in ACTIONS})
print("类别分布：%s" % {c: sum(1 for x in rules if x.get("Category") == c) for c in sorted(CATEGORIES)})

if problems:
    print("\n发现 %d 处问题：" % len(problems))
    for item in problems:
        print("  - " + item)
else:
    print("\n[ OK ] 全部规则通过解析器兼容性校验")
