#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dragon-Drivers 一键加载器
=========================================================================
一条命令完成：预检 -> 按需放行签名 -> 安装服务 -> 登记客户端 -> 启动 -> 校验。

-------------------------------------------------------------------------
关于「无需测试模式加载」—— 先说实话
-------------------------------------------------------------------------
x64 Windows 的内核代码完整性（DSE/CI）只允许**微软认可签名**的驱动加载。
自签证书不在其列，证书导进受信任根也没用（那只对测试模式有效）。

所以「加载自签驱动」只有两条路，**都必须改启动配置、重启一次**：

  A) nointegritychecks   —— 关闭完整性检查，**不是测试模式、桌面无水印**（本脚本默认）
  B) testsigning         —— 测试模式，放行受信任根签过的镜像（有水印）

签名策略是**开机时读取**的，运行期没有任何用户态接口能改变它。
因此「零重启加载」在不借助内核漏洞（BYOVD / 直接改内核 CI 变量）的前提下
不存在 —— 那属于绕过内核代码完整性的攻击手法，本脚本不做，也不提供。

如果 A 在不重启时被拒（错误码 577），说明策略尚未生效，重启是唯一正解。

-------------------------------------------------------------------------
用法
-------------------------------------------------------------------------
    # 一键（默认用 A 方式、安装源自动找 Dragon_Drivers\\ 或 out\\）
    python tools\\load_driver.py --yes

    # 就地加载（ImagePath 直接指向 Dragon_Drivers\\Dragon_Drivers.sys）
    python tools\\load_driver.py --inplace --yes

    # 零规则试跑（只跑硬编码自保护，不拦任何行为）
    python tools\\load_driver.py --no-rules --yes

    # 指定安装源 / 主程序保护清单
    python tools\\load_driver.py --from "D:\\App\\Dragon" --guard "D:\\App\\Dragon-Antivirus.exe;D:\\App\\Dragon\\*" --yes

    # 查看状态 / 卸载 / 撤销签名策略
    python tools\\load_driver.py --status
    python tools\\load_driver.py --unload --yes
    python tools\\load_driver.py --revert --yes
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import deploy_dragon as dep  # noqa: E402

EXIT_OK = 0
EXIT_NEED_REBOOT = 10
EXIT_NO_ADMIN = 2
EXIT_LOAD_FAILED = 3

ALTITUDE = dep.ALTITUDE

# StartService 失败码解读（都是实机上会被误判成"驱动写坏了"的那几个）
START_ERROR_HINTS = {
    577: "ERROR_INVALID_IMAGE_HASH —— 数字签名未被接受：签名策略没生效（需重启）或本就未放行。",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND —— 服务键或**过滤器实例未注册**。官方 FltRegisterFilter "
                "文档原文列出的就是这一条；检查 Instances\\DefaultInstance + Altitude 是否写入。",
    0xC01C0001: "STATUS_FLT_INVALID_NAME_REQUEST —— FltMgr 拒绝注册，常见于 altitude 缺失或格式非法。",
    0xC000036B: "STATUS_IMAGE_ALREADY_LOADED —— 镜像已在内存中，先停止服务再启。",
    1058: "ERROR_SERVICE_DISABLED —— 服务被禁用（Start 值被改成 4）。",
    1053: "ERROR_SERVICE_REQUEST_TIMEOUT —— 服务未及时响应，多为 DriverEntry 卡住或提前失败"
          "（真实 NTSTATUS 通常在下面的事件日志里）。",
    1066: "ERROR_SERVICE_SPECIFIC_ERROR —— 服务报了自己的错误码，看 dwServiceSpecificExitCode。",
}


def explain_start_failure(code: int) -> None:
    hint = START_ERROR_HINTS.get(code)
    print()
    print("[诊断] StartService 失败原因解读：")
    if hint:
        print(f"        0x{code:X} ({code}): {hint}")
    else:
        print(f"        0x{code:X} ({code}): 未收录的错误码")

    state = dep.service_state()
    print(f"        当前服务状态：{state[0]}")
    print()
    print("        逐项排查顺序：")
    print("          1) python tools\\load_driver.py --status        # 服务配置与 ImagePath")
    print("          2) reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dragon-Drivers\\Instances /s")
    print("          3) python tools\\load_driver.py --doctor        # 签名策略 / 安全启动 / HVCI")
    print("          4) 看下面的事件日志 —— 驱动 DriverEntry 失败时 NTSTATUS 就写在那里")
    print("          5) DebugView（管理员 + Capture Kernel）看 DriverEntry 有没有打日志")

    notes = recent_scm_events()
    print()
    if notes:
        print("[事件日志] Service Control Manager 中与本驱动相关的最近记录：")
        for line in notes:
            print(f"        {line}")
    else:
        print("[事件日志] 未找到与本驱动相关的 Service Control Manager 记录。")


def recent_scm_events(limit: int = 6) -> list:
    """读取系统日志里与本驱动相关的服务控制管理器事件。

    驱动 DriverEntry 返回失败时，真正的 NTSTATUS 会记在这里（事件 7000/7026/7001），
    而 StartService 只回一个笼统的 1053 —— 不看日志基本没法定位。
    """
    script = (
        "Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Service Control Manager'} "
        f"-MaxEvents {limit} -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Message -match 'Dragon' } | "
        "ForEach-Object { '{0} [{1}] {2}' -f $_.TimeCreated.ToString('HH:mm:ss'), $_.Id, "
        "($_.Message -replace '\\r?\\n', ' ') }"
    )
    return [line.strip() for line in dep.powershell(script).splitlines() if line.strip()]


def check_loaded() -> bool:
    _, flt = dep.run(["fltmc", "filters"])
    for line in (flt or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-2] == ALTITUDE:
            print(f"[ OK ] FltMgr 已挂载实例：{line.strip()}")
            return True
        if "dragon" in line.lower():
            print(f"[INFO] FltMgr 视图：{line.strip()}")
    return False


def do_unload() -> int:
    print("=" * 70)
    print("卸载流程（顺序不可颠倒）")
    print("=" * 70)
    print("[1/3] 授权卸载 —— 驱动对非授权卸载返回 STATUS_FLT_DO_NOT_DETACH（自保设计）")

    client = dep.SCRIPT_DIR / "dragon_client.py"
    py = sys.executable
    if client.is_file():
        code, output = dep.run([py, str(client), "--authorize-unload"])
        print(output or f"退出码 {code}")
        if code != 0:
            print("[WARN] 授权失败。若客户端连不上（未登记 ClientImagePath 或驱动未运行），")
            print("       直接跳到第 2 步；若仍被拒 —— 重启机器后驱动不会自动加载（start=demand），")
            print("       那时再执行 --uninstall --yes 即可干净删除。")
    else:
        print(f"[WARN] 未找到 {client}，跳过授权")

    print("[2/3] 停止服务")
    dep.service_action("stop")

    print("[3/3] 删除服务与文件")
    dep.uninstall()
    return EXIT_OK


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Dragon-Drivers 一键加载器（默认走 nointegritychecks，不进入测试模式）"
    )
    parser.add_argument("--status", action="store_true", help="查看服务与签名策略状态")
    parser.add_argument("--doctor", action="store_true", help="只做加载前置条件预检（只读，不改任何东西）")
    parser.add_argument("--unload", action="store_true", help="授权 -> 停止 -> 卸载 全流程")
    parser.add_argument("--revert", action="store_true", help="撤销 nointegritychecks 与 testsigning（需重启）")
    parser.add_argument("--from", dest="source", metavar="DIR",
                        help="安装源目录（默认依次尝试交付目录 Dragon_Drivers\\ 与工程 out\\）")
    parser.add_argument("--inplace", action="store_true",
                        help="就地加载：ImagePath 直接指向源目录里的 .sys")
    parser.add_argument("--no-rules", action="store_true",
                        help="不部署规则文件 —— 驱动以零动态规则启动，只跑硬编码自保护")
    parser.add_argument("--client", metavar="PATH",
                        help="登记为可连接通信端口的客户端镜像（默认当前 python.exe）")
    parser.add_argument("--guard", metavar="PATTERNS",
                        help="主程序 / 外置文件保护清单（分号分隔，支持通配符）")
    parser.add_argument("--signing", choices=("nointegritychecks", "testsigning"),
                        default="nointegritychecks",
                        help="放行方式：nointegritychecks（默认，非测试模式）/ testsigning（有水印）")
    parser.add_argument("--no-auto-signing", action="store_true",
                        help="不自动修改启动配置，只报告需要做什么")
    parser.add_argument("--yes", action="store_true", help="确认执行系统级变更")
    args = parser.parse_args()

    if args.status:
        dep.status()
        return EXIT_OK

    if args.doctor:
        dep.doctor()
        return EXIT_OK

    if not dep.require_admin():
        print("[ERR] 需要以管理员身份运行。")
        return EXIT_NO_ADMIN

    if args.revert:
        if dep.confirm(args.yes, "撤销签名策略更改"):
            dep.revert_signing()
        return EXIT_OK

    if args.unload:
        if not dep.confirm(args.yes, "停止并卸载内核驱动服务"):
            return EXIT_OK
        return do_unload()

    # ----------------------------------------------------------------------
    # 一键流程
    # ----------------------------------------------------------------------
    dep.doctor()
    print()

    state = dep.signing_state()
    ready, reason = dep.signing_readiness()

    if not ready:
        print("=" * 70)
        print(f"尚未具备加载条件 —— {reason}")
        print("=" * 70)

        # 配置已写入但还没重启：不需要再改任何东西，只差重启
        if state != dep.SIGNING_OFF and dep.live_enforcement_disabled() is False:
            print("启动配置已经改好了，**现在只差一次重启**。")
            print("重启后直接重新运行本脚本，它会自动跳过这一步继续安装并启动。")
            print("         重启命令：  shutdown /r /t 5")
            return EXIT_NEED_REBOOT

        if args.signing == "testsigning":
            action = dep.enable_testsigning
            what = "开启测试签名（测试模式，桌面有水印）"
            bcd = "bcdedit /set testsigning on"
        else:
            action = dep.enable_nointegritychecks
            what = "关闭内核完整性检查（**非**测试模式，无水印）"
            bcd = "bcdedit /set nointegritychecks on"

        print(f"将要执行：{bcd}")
        print(f"含义：{what}")
        print()

        if args.no_auto_signing:
            print("[SKIP] --no-auto-signing：不修改启动配置。请手动执行上面的命令后重启，再运行本脚本。")
            return EXIT_NEED_REBOOT

        if not dep.confirm(args.yes, "修改启动配置（需要重启一次）"):
            return EXIT_NEED_REBOOT

        print("-" * 70)
        action()
        print("-" * 70)
        print()
        print("[下一步] **现在必须重启**。签名策略在开机时读取，运行期无法生效。")
        print("         重启后直接重新运行本脚本，它会自动跳过这一步继续安装。")
        print(f"         重启命令：  shutdown /r /t 5")
        return EXIT_NEED_REBOOT

    print(f"[ OK ] {reason}，可以安装。")
    print()

    # ---- 安装 ----
    if not dep.confirm(args.yes, "安装内核驱动服务并写入注册表"):
        return EXIT_OK

    print("=" * 70)
    print("安装")
    print("=" * 70)
    dep.install(source=args.source, inplace=args.inplace, with_rules=not args.no_rules)

    # ---- 登记客户端（必须在 start 之前）----
    print()
    print("=" * 70)
    print("登记客户端（不登记则通信端口拒绝一切连接）")
    print("=" * 70)
    client_image = args.client or sys.executable
    dep.set_client(client_image)

    if args.guard:
        print()
        dep.set_guard_paths(args.guard)

    # ---- 启动 ----
    print()
    print("=" * 70)
    print("启动")
    print("=" * 70)
    code = dep.svc_start()

    if code != 0:
        explain_start_failure(code)
        return EXIT_LOAD_FAILED

    # ---- 校验 ----
    print()
    print("=" * 70)
    print("校验")
    print("=" * 70)
    state_name, state_code = dep.service_state()
    print(f"[INFO] 服务状态：{state_name}")
    if state_code != dep.SERVICE_RUNNING:
        print("[WARN] 服务不在 RUNNING —— 驱动很可能已自行退出（DriverEntry 失败）")
        for line in recent_scm_events():
            print(f"       {line}")

    mounted = check_loaded()
    if not mounted:
        print(f"[WARN] 未在 fltmc 中看到 altitude {ALTITUDE} 的实例。")
        print("       服务已启动但过滤器未挂载时，用 DebugView 看 DriverEntry 日志。")

    print()
    print("-" * 70)
    print("[ OK ] 加载流程完成。")
    print("       看事件：  python tools\\dragon_client.py --listen")
    print("       看统计：  python tools\\dragon_client.py --metrics")
    print("       看状态：  python tools\\load_driver.py --status")
    print("       卸载：    python tools\\load_driver.py --unload --yes")
    print("-" * 70)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
