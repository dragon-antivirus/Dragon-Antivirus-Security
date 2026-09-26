#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dragon-Drivers 构建核验工具
=========================================================================
用途：回答一个问题 —— 「手上这个 Dragon-Drivers.sys 是不是当前源码编出来的最新版？」

判定依据（逐级降级，不依赖单一手段）：
  1. 构建清单比对：out\\build_manifest.json 里记录了构建时全部源文件的 SHA256
     与产物 SHA256。重算当前源码哈希与之比对，即可机器判定「产物是否对应当前源码」。
     这是最可靠的判据，因为它不受时间戳被复制/解压改写的影响。
  2. 时间戳兜底：清单缺失时，比较链接产物与各源文件的修改时间。
  3. 内容自证：PE 版本资源、关键功能字符串、工程源文件完整性。

用法：
    python verify_build.py                # 完整核验
    python verify_build.py --json         # 额外输出机器可读结果
    python verify_build.py --quiet        # 只输出结论行

退出码：0 = 最新且完整；3 = 源码已改动（产物过期）；4 = 产物被替换或损坏；2 = 无法核验
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
OUT_DIR = PROJECT_DIR / "out"
SYS_FILE = OUT_DIR / "Dragon-Drivers.sys"
MANIFEST_FILE = OUT_DIR / "build_manifest.json"
LINK_OUTPUT = PROJECT_DIR / "x64" / "Release" / "Dragon-Drivers.sys"
PROJECT_FILE = PROJECT_DIR / "Dragon-Drivers.vcxproj"

SOURCE_PATTERNS = ("src/*.c", "inc/*.h", "*.inf", "*.rc", "*.vcxproj", "Rules/*.json")

# 这些字符串必须存在于镜像中，用于证明「最新一轮功能已编进去」。
# 每个都必须是源码里真实引用的字面量 —— 只定义未使用的宏不会被编译器保留。
REQUIRED_MARKERS = {
    "DragonGuard_Event_Port": "通信端口名（协议 v3）",
    "DragonDriver_DefenderRules.json": "启动期自动加载的规则文件",
    "GuardPaths": "主程序 / 外置文件保护清单",
    "RansomBackupDir": "勒索备份目录配置项",
    "RansomBackupMaxBytes": "勒索备份单文件上限配置项",
    "ValueNames": "值级注册表判定（规则键名）",
    "self-protect exempt dir": "自保护豁免目录（备份区不被自身拦截）",
    "ransom backup directory": "启动期备份目录日志（便于实机确认）",
}

# 一旦出现在产物里就说明引入了不该有的依赖
FORBIDDEN_MARKERS = {
    "PsSuspendProcess": "未文档化的进程冻结例程",
    "ZwSuspendThread": "未文档化的线程冻结例程",
    "NtSuspendProcess": "未文档化的进程冻结例程",
    "MmGetSystemRoutineAddress": "动态解析（规避静态导入）手法",
    "PYAS": "参考实现痕迹",
}


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def combined_source_hash(mapping: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for name in sorted(mapping):
        digest.update(name.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(mapping[name].encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def collect_source_hashes() -> dict[str, str]:
    files: list[Path] = []
    for pattern in SOURCE_PATTERNS:
        files.extend(PROJECT_DIR.glob(pattern))

    result: dict[str, str] = {}
    for item in sorted(set(files)):
        if item.is_file():
            result[item.relative_to(PROJECT_DIR).as_posix()] = sha256_file(item)
    return result


def _ps_utf8(script_body: str) -> str:
    """执行 PowerShell（UTF-16LE/Base64 传参），结果经 UTF-8 文件读回。

    控制台输出走本机 OEM 代码页，中文（证书主题）会乱码，因此必须落盘再读。
    """
    tag = hashlib.md5(script_body.encode("utf-8")).hexdigest()[:10]
    result_file = Path(tempfile.gettempdir()) / f"dragon_verify_{tag}.txt"
    result_file.unlink(missing_ok=True)

    full = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$__out=New-Object System.Collections.ArrayList;"
        + script_body
        + ";[IO.File]::WriteAllLines('" + str(result_file) + "',[string[]]$__out,"
        "(New-Object Text.UTF8Encoding($false)))"
    )
    encoded = base64.b64encode(full.encode("utf-16-le")).decode("ascii")
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, text=True, errors="replace",
    )

    if not result_file.is_file():
        return ""

    text = result_file.read_text(encoding="utf-8", errors="replace")
    result_file.unlink(missing_ok=True)
    return text


# --------------------------------------------------------------------------
# 产物结构
# --------------------------------------------------------------------------
def inspect_pe(path: Path) -> dict:
    """读取 PE 关键字段。"""
    info: dict = {"ok": False}
    try:
        with path.open("rb") as handle:
            head = handle.read(0x40)
            if head[:2] != b"MZ":
                return info

            pe_offset = int.from_bytes(head[0x3C:0x40], "little")
            handle.seek(pe_offset)
            if handle.read(4) != b"PE\x00\x00":
                return info

            handle.seek(pe_offset + 4)
            machine = int.from_bytes(handle.read(2), "little")

            handle.seek(pe_offset + 0x5C)
            subsystem = int.from_bytes(handle.read(2), "little")
            dll_chars = int.from_bytes(handle.read(2), "little")

            handle.seek(pe_offset + 24)
            magic = int.from_bytes(handle.read(2), "little")

            data_dir_offset = 112 if magic == 0x20B else 96
            handle.seek(pe_offset + 24 + data_dir_offset + 4 * 8)
            security_entry = handle.read(8)
            cert_size = int.from_bytes(security_entry[4:8], "little") if len(security_entry) == 8 else 0

        info.update({
            "ok": True,
            "machine": machine,
            "subsystem": subsystem,
            "integrity_check": bool(dll_chars & 0x0080),
            "embedded_signature": cert_size > 0,
            "cert_size": cert_size,
        })
    except OSError:
        pass
    return info


def read_version_info(path: Path) -> dict:
    """读 PE 版本资源（走 PowerShell 的 FileVersionInfo，最省事且准确）。"""
    body = (
        "$v=(Get-Item '" + str(path) + "').VersionInfo;"
        "foreach($k in 'FileVersion','ProductVersion','CompanyName','ProductName',"
        "'FileDescription','OriginalFilename','InternalName','LegalCopyright'){"
        "[void]$__out.Add($k + '=' + [string]$v.$k)}"
    )
    text = _ps_utf8(body)

    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" in line:
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


def read_signature(path: Path) -> dict:
    body = (
        "$s=Get-AuthenticodeSignature '" + str(path) + "';"
        "[void]$__out.Add('Status=' + [string]$s.Status);"
        "if($s.SignerCertificate){"
        "[void]$__out.Add('Subject=' + $s.SignerCertificate.Subject);"
        "[void]$__out.Add('Thumbprint=' + $s.SignerCertificate.Thumbprint);"
        "[void]$__out.Add('NotAfter=' + $s.SignerCertificate.NotAfter.ToString('yyyy-MM-dd'))}"
        "else{[void]$__out.Add('Subject=');[void]$__out.Add('Thumbprint=')}"
    )
    text = _ps_utf8(body)

    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" in line:
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


def project_source_list() -> list[str]:
    """从 vcxproj 里读出参与编译的源文件（ClCompile Include）。"""
    if not PROJECT_FILE.is_file():
        return []

    text = PROJECT_FILE.read_text(encoding="utf-8", errors="replace")
    items: list[str] = []
    for chunk in text.split("<ClCompile Include=\"")[1:]:
        value = chunk.split("\"", 1)[0].strip()
        if value.lower().endswith(".c"):
            items.append(value.replace("\\", "/"))
    return sorted(items)


def search_markers(data: bytes, markers: dict[str, str]) -> list[tuple[str, str, int]]:
    """在二进制里同时按窄字符与 UTF-16LE 搜索（内核代码里字符串多为宽字符）。"""
    found: list[tuple[str, str, int]] = []
    for token, desc in markers.items():
        count = data.count(token.encode("ascii")) + data.count(token.encode("utf-16-le"))
        if count > 0:
            found.append((token, desc, count))
    return found


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="Dragon-Drivers 构建核验")
    parser.add_argument("--json", action="store_true", help="额外输出机器可读结果")
    parser.add_argument("--quiet", action="store_true", help="只输出结论")
    args = parser.parse_args()

    quiet = args.quiet
    verdict = "unknown"
    exit_code = 2
    report: dict = {}

    def say(text: str = "") -> None:
        if not quiet:
            print(text)

    say("=" * 74)
    say("Dragon-Drivers 构建核验")
    say("=" * 74)
    say(f"产物: {SYS_FILE}")
    say()

    if not SYS_FILE.is_file():
        print("[ERR] 未找到 out\\Dragon-Drivers.sys，请先运行 build\\build_dragon.py")
        return 2

    data = SYS_FILE.read_bytes()
    size = len(data)
    report["artifact"] = {"path": str(SYS_FILE), "size": size, "sha256": sha256_file(SYS_FILE)}

    # ---- 一、产物文件 ----
    say("[一] 产物文件")
    pe = inspect_pe(SYS_FILE)
    say(f"  大小          {size:,} 字节")
    if not pe.get("ok"):
        say("  [FAIL] PE 结构异常")
        print("\n[结论] 产物损坏，无法核验")
        return 4

    machine_name = {0x8664: "x64 (AMD64)", 0xAA64: "ARM64"}.get(pe["machine"], hex(pe["machine"]))
    subsystem_name = {1: "NATIVE (内核驱动)", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI"}.get(
        pe["subsystem"], str(pe["subsystem"])
    )
    say(f"  架构          {machine_name}")
    say(f"  子系统        {subsystem_name}")
    say(f"  /INTEGRITYCHECK  {'已设置' if pe['integrity_check'] else '未设置'}")

    sig = read_signature(SYS_FILE)
    say(f"  嵌入签名      {'是' if pe['embedded_signature'] else '否'}"
        f"（属性证书表 {pe['cert_size']:,} 字节）")
    status = sig.get("Status") or "(未签名)"
    say(f"  签名状态      {status}")
    if status == "UnknownError" and pe["embedded_signature"]:
        say("                自签名证书未导入本机受信任根时的正常返回值，")
        say("                测试机导入 .cer 后即变为 Valid —— 不影响加载（配合测试模式）。")
    if sig.get("Subject"):
        say(f"  签名者        {sig['Subject']}")
    if sig.get("NotAfter"):
        say(f"  证书有效期至  {sig['NotAfter']}")
    report["signature"] = sig
    report["pe"] = pe

    # ---- 二、版本资源 ----
    say()
    say("[二] 版本资源")
    version = read_version_info(SYS_FILE)
    for key in ("FileVersion", "ProductVersion", "CompanyName", "ProductName",
                "FileDescription", "OriginalFilename"):
        say(f"  {key:<18}{version.get(key, '(空)')}")
    report["version_info"] = version

    # ---- 三、与构建清单比对 ----
    say()
    say("[三] 与构建清单比对（判定「是否最新版」的核心依据）")
    current_sources = collect_source_hashes()
    current_combined = combined_source_hash(current_sources)
    report["current_source_count"] = len(current_sources)
    report["current_combined_source_hash"] = current_combined

    manifest: dict = {}
    if MANIFEST_FILE.is_file():
        try:
            manifest = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:  # noqa: BLE001
            say(f"  [WARN] 构建清单损坏: {exc}")

    if manifest:
        recorded = manifest.get("sources", {})
        recorded_combined = manifest.get("combined_source_hash", "")
        built_at = manifest.get("built_at", "(未知)")
        artifact = manifest.get("artifact", {})

        say(f"  清单构建时间  {built_at}")
        say(f"  清单源文件数  {len(recorded)}   当前 {len(current_sources)}")
        say(f"  清单总哈希    {recorded_combined[:24]}…")
        say(f"  当前总哈希    {current_combined[:24]}…")

        report["manifest_built_at"] = built_at
        report["manifest_combined_source_hash"] = recorded_combined

        changed = sorted(
            name for name in set(recorded) | set(current_sources)
            if recorded.get(name) != current_sources.get(name)
        )
        report["changed_sources"] = changed

        if recorded_combined == current_combined:
            say("  [ OK ] 源码集合与构建时逐字节一致")
            source_state = "current"
        else:
            say(f"  [CHK] 有 {len(changed)} 个源文件在构建后被改动或增删：")
            for name in changed[:12]:
                if name not in recorded:
                    say(f"         + 新增 {name}")
                elif name not in current_sources:
                    say(f"         - 移除 {name}")
                else:
                    say(f"         ~ 改动 {name}")
            if len(changed) > 12:
                say(f"         … 其余 {len(changed) - 12} 个")
            source_state = "stale"

        recorded_sha = artifact.get("sha256", "")
        actual_sha = report["artifact"]["sha256"]
        if recorded_sha and recorded_sha == actual_sha:
            say("  [ OK ] 产物 sha256 与构建时一致（未被替换或篡改）")
            artifact_state = "current"
        elif recorded_sha:
            say("  [CHK] 产物 sha256 与构建时不一致 —— 文件被替换、重新签名或修改过")
            say(f"         构建时 {recorded_sha[:24]}…")
            say(f"         当前   {actual_sha[:24]}…")
            artifact_state = "replaced"
        else:
            artifact_state = "unknown"

        report["source_state"] = source_state
        report["artifact_state"] = artifact_state
    else:
        say("  [WARN] 未找到 out\\build_manifest.json —— 退化为按时间戳判断")
        if LINK_OUTPUT.is_file():
            link_mtime = LINK_OUTPUT.stat().st_mtime
            newest = max(
                (PROJECT_DIR / name).stat().st_mtime for name in current_sources
            ) if current_sources else 0
            say(f"  链接产物时间  {link_mtime:.0f}")
            say(f"  最新源文件    {newest:.0f}")
            if newest > link_mtime:
                say("  [CHK] 有源文件比链接产物更新 —— 产物已过期")
                source_state = "stale"
            else:
                say("  [ OK ] 没有源文件比链接产物更新（时间戳判断，不如哈希可靠）")
                source_state = "unknown"
        else:
            source_state = "unknown"
        artifact_state = "unknown"
        report["source_state"] = source_state
        report["artifact_state"] = artifact_state
        say("  [提示] 重新运行 build\\build_dragon.py --sign 生成清单后再核验更可靠")

    # ---- 四、功能集核对 ----
    say()
    say("[四] 功能集核对（证明最新一轮功能确已编入）")
    missing: list[str] = []
    required_hits = {token: count for token, _, count in search_markers(data, REQUIRED_MARKERS)}

    for token, desc in REQUIRED_MARKERS.items():
        if required_hits.get(token):
            say(f"  [ OK ] {token:<34}{desc}")
        else:
            missing.append(token)
            say(f"  [FAIL] {token:<34}{desc} —— 镜像中未找到")
    report["missing_markers"] = missing

    say()
    forbidden_hits = search_markers(data, FORBIDDEN_MARKERS)
    for token, desc, _ in forbidden_hits:
        say(f"  [FAIL] 检出 {token}（{desc}）")
    if not forbidden_hits:
        say("  [ OK ] 无禁用依赖（未文档化例程 / 动态解析 / 参考实现痕迹）")
    forbidden = [token for token, _, _ in forbidden_hits]
    report["forbidden_markers"] = forbidden

    # ---- 五、工程源文件完整性 ----
    say()
    say("[五] 工程源文件完整性")
    in_project = project_source_list()
    on_disk = sorted(f"src/{p.name}" for p in (PROJECT_DIR / "src").glob("*.c"))
    say(f"  工程收录 {len(in_project)} 个 .c，磁盘 {len(on_disk)} 个 .c")
    only_disk = [name for name in on_disk if name not in in_project]
    only_project = [name for name in in_project if name not in on_disk]
    if only_disk:
        say(f"  [CHK] 磁盘上有但未加入工程: {', '.join(only_disk)}")
    if only_project:
        say(f"  [CHK] 工程引用但磁盘缺失: {', '.join(only_project)}")
    if not only_disk and not only_project:
        say("  [ OK ] 源码集合与工程一致，无遗漏编译单元")
    report["sources_not_in_project"] = only_disk
    report["project_missing_sources"] = only_project

    # ---- 六、规则包 ----
    say()
    say("[六] 规则包（随驱动一同交付，已计入源码哈希）")
    rule_file = PROJECT_DIR / "Rules" / "DragonDriver_DefenderRules.json"
    if rule_file.is_file():
        try:
            rule_data = json.loads(rule_file.read_text(encoding="utf-8"))
            rules = rule_data.get("DynamicRules", [])
            actions: dict[str, int] = {}
            for item in rules:
                key = item.get("Action", "(未指定)")
                actions[key] = actions.get(key, 0) + 1
            say(f"  文件          {rule_file.name}")
            say(f"  规则条数      {len(rules)}")
            say("  动作分布      " + "  ".join(f"{k}={v}" for k, v in sorted(actions.items())))
            say(f"  含 ValueNames {sum(1 for i in rules if i.get('ValueNames'))} 条")
            report["rule_count"] = len(rules)
            report["rule_actions"] = actions
        except (OSError, json.JSONDecodeError) as exc:  # noqa: BLE001
            say(f"  [CHK] 规则包解析失败: {exc}")
    else:
        say(f"  [WARN] 未找到 {rule_file}")

    # ---- 结论 ----
    say()
    say("=" * 74)

    if forbidden:
        verdict = "tampered"
        exit_code = 4
        print("[结论] 产物包含禁用依赖，不可用于测试或交付")
    elif missing:
        verdict = "incomplete"
        exit_code = 4
        say(f"[结论] 产物缺少 {len(missing)} 项必需特征 —— 不是最新版本，请重新构建")
    elif source_state == "current" and artifact_state == "current":
        verdict = "latest"
        exit_code = 0
        print("[结论] 这是最新版：源码逐字节一致，产物未被替换")
    elif source_state == "stale":
        verdict = "stale"
        exit_code = 3
        print("[结论] 产物已过期：构建之后源码有改动，请重新运行 build\\build_dragon.py --sign")
    elif artifact_state == "replaced":
        verdict = "replaced"
        exit_code = 4
        print("[结论] 产物与构建记录不符：文件被替换或修改过（重新签名也会触发此判定）")
    else:
        verdict = "unknown"
        exit_code = 2
        print("[结论] 无法确定：缺少构建清单，建议重新构建以生成核验依据")

    if not pe["embedded_signature"] and verdict == "latest":
        print("[提示] 该产物尚未签名 —— 测试机加载前必须执行 tools\\sign_dragon.py")

    report["verdict"] = verdict
    say("=" * 74)

    if args.json:
        report_file = OUT_DIR / "verify_report.json"
        try:
            report_file.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            if not quiet:
                print()
                print(f"[INFO] 机器可读结果: {report_file}")
        except OSError as exc:  # noqa: BLE001
            print(f"[WARN] 写入核验报告失败: {exc}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
