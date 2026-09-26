#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dragon-Drivers 测试签名工具
=========================================================================
用途：给 out\\Dragon-Drivers.sys 打测试签名，并导出公钥证书供测试机导入。

签名主体：CN=WindX工作室（WindX 工作室自签发的代码签名证书）

为什么必须签名：
  1. 内核驱动镜像的特征位里带了 /INTEGRITYCHECK（ObRegisterCallbacks 的前置
     要求），加载时内核一定做签名校验；
  2. 即使开了测试模式（testsigning），**完全没有签名的镜像一样会被拒绝**——
     测试模式放行的是「用本机受信任根证书签过的镜像」，不是「任意镜像」。

因此流程是：
  开发机：本脚本生成自签名代码签名证书 -> 签名 .sys -> 导出 .cer
  测试机：导入 .cer 到「受信任的根证书颁发机构」+「受信任的发布者」
        -> bcdedit /set testsigning on -> 重启

用法：
    python sign_dragon.py                       # 建证书（如无）+ 签名 + 导出 cer + 校验
    python sign_dragon.py --rebuild-cert        # 重建证书后再签（旧签名会失效）
    python sign_dragon.py --install-cert --yes  # 顺便把证书装到本机（管理员）
    python sign_dragon.py --verify-only         # 只看当前产物签名状态

注意：每次重新编译覆盖 out\\Dragon-Drivers.sys 之后，都必须重新跑一次签名。
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
OUT_DIR = PROJECT_DIR / "out"
SYS_FILE = OUT_DIR / "Dragon-Drivers.sys"
CER_FILE = OUT_DIR / "WindXTestSigning.cer"

# 签名主体。证书主题里含中文，所有 PowerShell 交互都必须走 UTF-16LE/Base64，
# 否则主题会经控制台代码页被替换成问号。
DEFAULT_SUBJECT = "CN=WindX工作室"


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


def _temp_path(name: str) -> Path:
    return Path(tempfile.gettempdir()) / f"dragon_sign_{name}_{os.getpid()}.txt"


def _ps_encode(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _ps(script: str) -> tuple[int, str]:
    """执行 PowerShell 脚本片段。

    统一使用 -EncodedCommand（UTF-16LE + Base64）传参：脚本里含中文主题
    （CN=WindX工作室）时，若走 -Command + 命令行，字符串会经控制台代码页
    转换，实际落到证书里的主题会变成问号。
    """
    return run(["powershell", "-NoProfile", "-NonInteractive",
                "-EncodedCommand", _ps_encode(script)])


def _ps_utf8(script_body: str, name: str) -> str:
    """执行脚本并读回结果行。

    script_body 向 $__out 追加字符串，函数负责以 UTF-8（无 BOM）落盘再读回。

    为什么不直接读控制台输出：PowerShell 的控制台输出走本机 OEM 代码页，
    中文经管道后无法可靠还原（表现为「CN=WindX?????」）。凡是要读含中文的
    结果（证书主题、签名者），都必须走文件。
    """
    result_file = _temp_path(name)
    result_file.unlink(missing_ok=True)

    full = (
        "$ErrorActionPreference='Stop';"
        "$__out=New-Object System.Collections.ArrayList;"
        + script_body
        + ";[IO.File]::WriteAllLines('" + str(result_file) + "',[string[]]$__out,"
        "(New-Object Text.UTF8Encoding($false)))"
    )
    _ps(full)

    if not result_file.is_file():
        return ""

    text = result_file.read_text(encoding="utf-8", errors="replace")
    try:
        result_file.unlink()
    except OSError:
        pass
    return text


def _plate(lines: list[str]) -> list[str]:
    return [f"[void]$__out.Add('{item}')" for item in lines]


def find_signtool() -> str | None:
    """在已安装的 SDK / WDK 里找最新版本的 signtool.exe。"""
    candidates: list[Path] = []
    for root in (Path(r"C:\Program Files (x86)\Windows Kits\10\bin"),
                 Path(r"C:\Program Files\Windows Kits\10\bin")):
        if not root.is_dir():
            continue
        for exe in root.glob("*/x64/signtool.exe"):
            candidates.append(exe)
        direct = root / "x64" / "signtool.exe"
        if direct.is_file():
            candidates.append(direct)

    if not candidates:
        return None

    def version_key(path: Path) -> str:
        return path.parent.parent.name

    candidates.sort(key=version_key, reverse=True)
    return str(candidates[0])


# --------------------------------------------------------------------------
# 证书
# --------------------------------------------------------------------------
def find_cert_thumbprint(subject: str) -> str | None:
    body = (
        "$s='" + subject + "';"
        "$c=Get-ChildItem Cert:\\CurrentUser\\My |"
        " Where-Object {$_.Subject -eq $s} |"
        " Sort-Object NotAfter -Descending | Select-Object -First 1;"
        "if($c){" + ";".join(_plate(["THUMB=" + "' + $c.Thumbprint + '"])) + "}"
        "else{[void]$__out.Add('THUMB=MISSING')}"
    )
    text = _ps_utf8(body, "thumb")

    # 结果行形如 THUMB=<40 位十六进制>；必须按前缀剥离后再判长度，
    # 否则 "THUMB=" 这 6 个字符会让长度变成 46，永远匹配不上，
    # 表现为「明明有证书却每次新建一个」。
    for line in text.splitlines():
        line = line.strip()
        if not line.upper().startswith("THUMB="):
            continue
        candidate = line[len("THUMB="):].strip()
        if len(candidate) == 40 and all(ch in "0123456789ABCDEFabcdef" for ch in candidate):
            return candidate.upper()
    return None


def create_cert(subject: str) -> str | None:
    body = (
        "$s='" + subject + "';"
        "$c=New-SelfSignedCertificate -Type CodeSigningCert -Subject $s"
        " -CertStoreLocation Cert:\\CurrentUser\\My"
        " -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048"
        " -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(5);"
        "if($c){"
        + ";".join(_plate(["THUMB=' + $c.Thumbprint + '", "SUBJ=' + $c.Subject + '",
                           "AFTER=' + $c.NotAfter.ToString('yyyy-MM-dd') + '"]))
        + "}else{[void]$__out.Add('THUMB=FAILED')}"
    )
    text = _ps_utf8(body, "newcert")

    thumbprint: str | None = None
    subject_shown = ""
    not_after = ""

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("THUMB="):
            candidate = line[len("THUMB="):].strip()
            if len(candidate) == 40 and all(ch in "0123456789ABCDEFabcdef" for ch in candidate):
                thumbprint = candidate.upper()
        elif line.startswith("SUBJ="):
            subject_shown = line[len("SUBJ="):].strip()
        elif line.startswith("AFTER="):
            not_after = line[len("AFTER="):].strip()

    if thumbprint is None:
        print("[ERR] 创建自签名证书失败，原始输出：")
        print(text)
        return None

    print(f"[ OK ] 已创建代码签名证书")
    print(f"       主题   {subject_shown}")
    print(f"       指纹   {thumbprint}")
    print(f"       有效期至 {not_after}")
    return thumbprint


def remove_cert(subject: str) -> None:
    # 证书提供程序不支持管道输入（Remove-Item 会报「输入对象无法绑定到参数」），
    # 必须为每个证书显式构造 Cert:\CurrentUser\My\<指纹> 路径。
    body = (
        "$s='" + subject + "';"
        "$list=Get-ChildItem Cert:\\CurrentUser\\My | Where-Object {$_.Subject -eq $s};"
        "foreach($c in $list){"
        "Remove-Item -Path ('Cert:\\CurrentUser\\My\\' + $c.Thumbprint) -Force};"
        "[void]$__out.Add('REMOVED=' + [string](@($list).Count))"
    )
    text = _ps_utf8(body, "rmcert")

    removed = "0"
    for line in text.splitlines():
        line = line.strip()
        if line.upper().startswith("REMOVED="):
            removed = line[len("REMOVED="):].strip() or "0"

    print(f"[ OK ] 已清除同名旧证书 {removed} 张: {subject}")


def export_cert(thumbprint: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    CER_FILE.unlink(missing_ok=True)

    _ps(
        "$tp='" + thumbprint + "';"
        "$c=Get-ChildItem Cert:\\CurrentUser\\My |"
        " Where-Object {$_.Thumbprint -eq $tp} | Select-Object -First 1;"
        "if(-not $c){throw 'cert not found'};"
        "$b=$c.Export('Cert');"
        "[IO.File]::WriteAllBytes('" + str(CER_FILE) + "',$b)"
    )

    if CER_FILE.is_file():
        print(f"[ OK ] 已导出公钥证书 -> {CER_FILE}  ({CER_FILE.stat().st_size} 字节)")
    else:
        print("[ERR] 导出证书失败")


def install_cert_locally() -> None:
    """把证书装到本机「受信任的根」+「受信任的发布者」（需要管理员）。"""
    if not CER_FILE.is_file():
        print(f"[ERR] 未找到 {CER_FILE}，请先执行签名")
        return

    for store, label in (("Root", "受信任的根证书颁发机构"),
                         ("TrustedPublisher", "受信任的发布者")):
        code, output = run(["certutil", "-addstore", "-f", store, str(CER_FILE)])
        mark = "[ OK ]" if code == 0 else "[ERR ]"
        print(f"{mark} 导入 {label} (store={store}) rc={code}")
        if output:
            print(f"       {output.splitlines()[-1] if output.splitlines() else ''}")


# --------------------------------------------------------------------------
# 签名
# --------------------------------------------------------------------------
def sign(signtool: str, thumbprint: str) -> bool:
    if not SYS_FILE.is_file():
        print(f"[ERR] 未找到 {SYS_FILE}，请先运行 build\\build_dragon.py")
        return False

    code, output = run([
        signtool, "sign",
        "/v",
        "/fd", "sha256",
        "/s", "My",
        "/sha1", thumbprint,
        str(SYS_FILE),
    ])
    print(output or f"signtool sign 返回 {code}")
    return code == 0


def report_signature(path: Path) -> None:
    """打印产物的 Authenticode 签名者信息（中文主题必须走文件读回）。"""
    body = (
        "$s=Get-AuthenticodeSignature '" + str(path) + "';"
        "[void]$__out.Add('STATUS=' + [string]$s.Status);"
        "if($s.SignerCertificate){[void]$__out.Add('SUBJECT=' + $s.SignerCertificate.Subject);"
        "[void]$__out.Add('THUMB=' + $s.SignerCertificate.Thumbprint)}"
        "else{[void]$__out.Add('SUBJECT=(无签名)');[void]$__out.Add('THUMB=(无)')}"
    )
    text = _ps_utf8(body, "sig")

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("STATUS="):
            print(f"       签名状态  {line[len('STATUS='):]}")
        elif line.startswith("SUBJECT="):
            print(f"       签名者    {line[len('SUBJECT='):]}")
        elif line.startswith("THUMB="):
            print(f"       证书指纹  {line[len('THUMB='):]}")


def verify(signtool: str) -> bool:
    """校验签名。

    注意：/pa 会走完整的信任链校验。证书还没导入本机受信任根时，
    这里会报「证书链不信任」——那属于预期结果，测试机导入 .cer 后即通过，
    所以把「已签名」与「链可信」分开判断。
    """
    code, output = run([signtool, "verify", "/pa", "/v", str(SYS_FILE)])
    print(output or f"signtool verify 返回 {code}")

    signed = ("Successfully verified" in output) or ("Number of files successfully Verified" in output)
    untrusted = ("not trusted" in output.lower()) or ("不受信任" in output)

    print("       实际签名信息:")
    report_signature(SYS_FILE)

    if code == 0 and signed:
        print("\n[ OK ] 签名有效且信任链完整")
        return True

    if "0x800B0109" in output or untrusted:
        print("\n[WARN] 已签名，但根证书尚未进入本机受信任根 —— 这是自签名证书的预期状态。")
        print(f"       测试机上导入 {CER_FILE.name} 到「受信任的根」+「受信任的发布者」即可通过。")
        return True

    print("\n[ERR] 签名校验未通过")
    return False


def print_vm_steps() -> None:
    print()
    print("=" * 70)
    print("测试机（Windows 11 22H2 虚拟机 / 实体机）侧需要做的事")
    print("=" * 70)
    print("1) 把这四样拷进测试机（例如 C:\\DragonTest\\）：")
    print(f"     {SYS_FILE.name}")
    print(f"     {CER_FILE.name}          <-- 换成 WindX 证书后必须重新导入")
    print("     tools\\deploy_dragon.py  +  tools\\dragon_client.py")
    print("     Rules\\DragonDriver_DefenderRules.json")
    print()
    print("2) 管理员 CMD / PowerShell 导入证书（两个存储都要）：")
    print(f"     certutil -addstore -f Root             {CER_FILE.name}")
    print(f"     certutil -addstore -f TrustedPublisher {CER_FILE.name}")
    print()
    print("   开发机也建议导入一次（本脚本加 --install-cert --yes 可直接做）。证书未导入时，")
    print("   资源管理器里会显示红叉「不受信任的根证书」、签名时间「不可用」—— 那是自签名")
    print("   证书未进入受信任根的常态，不是签名坏了；导入后签名状态即变为 Valid。")
    print()
    print("3) 开机进入测试模式（关掉安全启动后执行）：")
    print("     bcdedit /set testsigning on")
    print("     重启，桌面右下角出现「测试模式」水印")
    print()
    print("4) 后续按《VM测试指南.md》走：--doctor -> --install -> --set-client -> --start")


# --------------------------------------------------------------------------
# 入口
# --------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="Dragon-Drivers 测试签名工具（WindX 工作室）")
    parser.add_argument("--subject", default=DEFAULT_SUBJECT, help="证书主题（默认 CN=WindX工作室）")
    parser.add_argument("--rebuild-cert", action="store_true", help="删除同名旧证书后重建")
    parser.add_argument("--install-cert", action="store_true", help="把导出的证书装到本机（需管理员）")
    parser.add_argument("--verify-only", action="store_true", help="只校验当前产物签名")
    parser.add_argument("--yes", action="store_true", help="确认执行系统级变更（导入证书）")
    args = parser.parse_args()

    signtool = find_signtool()
    if signtool is None:
        print("[ERR] 未找到 signtool.exe。请确认已安装 Windows SDK / WDK。")
        return 2
    print(f"[INFO] signtool: {signtool}")
    print(f"[INFO] 证书主题: {args.subject}")

    if args.verify_only:
        if not SYS_FILE.is_file():
            print(f"[ERR] 未找到 {SYS_FILE}")
            return 2
        verify(signtool)
        return 0

    if not SYS_FILE.is_file():
        print(f"[ERR] 未找到 {SYS_FILE}，请先运行 build\\build_dragon.py")
        return 2

    # 1. 证书
    thumbprint: str | None = None
    if args.rebuild_cert:
        remove_cert(args.subject)
    else:
        thumbprint = find_cert_thumbprint(args.subject)

    if thumbprint is None:
        thumbprint = create_cert(args.subject)
    else:
        print(f"[ OK ] 复用已有证书: {args.subject}")
        print(f"       指纹 {thumbprint}")

    if thumbprint is None:
        return 2

    # 2. 签名
    print("-" * 70)
    if not sign(signtool, thumbprint):
        print("[ERR] 签名失败")
        return 2

    # 3. 导出公钥证书
    print("-" * 70)
    export_cert(thumbprint)

    # 4. 校验
    print("-" * 70)
    ok = verify(signtool)

    # 5. 可选：装到本机
    if args.install_cert:
        print("-" * 70)
        if not args.yes:
            print("[SKIP] 导入本机证书存储需要显式确认，请追加 --yes")
        elif not require_admin():
            print("[ERR] 导入本机证书存储需要管理员权限")
        else:
            install_cert_locally()

    print_vm_steps()
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
