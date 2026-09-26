# -*- coding: utf-8 -*-
"""天龙神盾安全中心 —— PyInstaller 单文件 exe 打包规格。

onefile 模式（无 _internal/ 目录，单 exe）。

【2026-09-26 修复】前端文件（Dragon_UI.html + 3 个 UI 素材）从「内置进 exe PKG」改为
  「外置到 dist/ 与 exe 同级」，通过修改 frontend_dir() 让 frozen 态直接从 BASE_DIR
  读取，**彻底规避 bootloader 阶段解压时报 "decompression resulted in return code -1"
  启动即崩**（PyInstaller 6.x 实机踩坑：内置 .png/.html 条目偶尔触发 zlib -1，弹 Error
  对话框后进程直接退出）。代码侧语义零变化——非冻结态完全不变。

内置进 exe（datas 解包到 _MEIPASS 根目录，运行期不直接依赖）：
  - 仅保留 PEfeature 推导函数等极少量 .py 资源（如果用到）

外置（exe 同级 dist/，运行时按 BASE_DIR 加载）：
  - Dragon_UI.html（前端）
  - 3 个 UI 素材（Logo / 图标 png / 图标 ico）
  - Dragon_AIModels/（LightGBM .pda 模型，由 SevenEngine LightGBMScanner 通过 pda_store 加载）
  - Dragon_VirusDB/（malware_hashes.tsv 等）
  - Dragon_CoreRules/（*.yar + compiled.bin）
  - Dragon-Drivers/（*.sys + Rules/*.json）

外置资源缺失时给出友好提示，不让程序启动失败。
"""

import os
import sys

block_cipher = None

BASE = SPECPATH


def _rel(p):
    src = os.path.join(BASE, p)
    if os.path.exists(src):
        # 注意：datas 的第二个元素是「目标目录」，不是文件路径。
        # 文件在包内保留自身文件名，因此这里取 p 的目录部分；
        # 根目录放置用 "."，子目录（如 Data/baseline）保留其目录前缀。
        return src, (os.path.dirname(p) or ".")
    return None


datas = []

# 注意：Dragon_UI.html + 3 个 UI 素材（Logo / 图标 png / 图标 ico）已经**不再**放进 datas。
# 这些文件改为外置到 dist/ 与 exe 同级，由 frontend_dir() 在 frozen 态下从 BASE_DIR 直接读取，
# 完全绕开 bootloader 的 PKG 解压流程，从而规避 "decompression resulted in return code -1" 启动崩溃。
# —— 这一变更要求 dist/Dragon_UI.html 与 dist/天龙神盾Logo.png 等必须存在；
# 见文件末尾 _copy_ui_files()。

# 驱动用户态客户端（内核通信端口）：打包进 exe 根目录，冻结态可直接 import dragon_client。
_dd_client = os.path.join(BASE, "Dragon-Drivers", "tools", "dragon_client.py")
if os.path.isfile(_dd_client):
    datas.append((_dd_client, "."))

baseline = _rel("Data/baseline")
if baseline:
    datas.append(baseline)

# pywebview 的 edgechromium/winforms 两个后端硬性依赖 pythonnet(clr) 的原生运行时；
# PyInstaller 的 modulegraph 只收集了 python 代码，不会自动收集这些原生 DLL，
# 必须手动作为 datas 打进 exe，否则冻结环境 import clr 直接失败、主界面起不来。
import importlib.util as _ilu

for _mod in ("pythonnet", "clr_loader"):
    _sp = _ilu.find_spec(_mod)
    if _sp and _sp.origin:
        _mod_dir = os.path.dirname(_sp.origin)
        if _mod == "pythonnet":
            _rt = os.path.join(_mod_dir, "runtime")
            if os.path.isdir(_rt):
                datas.append((_rt, "pythonnet/runtime"))
        else:
            _dlls = os.path.join(_mod_dir, "ffi", "dlls")
            if os.path.isdir(_dlls):
                datas.append((_dlls, "clr_loader/ffi/dlls"))

icon_path = os.path.join(BASE, "天龙神盾图标.ico")
if not os.path.isfile(icon_path):
    icon_path = None

# lightgbm 的 Python 包用 ctypes 加载 lightgbm/bin/lib_lightgbm.dll（普通 DLL，非 .pyd 扩展模块），
# hiddenimports 只收 Python 代码、modulegraph 探测不到这个 DLL；缺它则冻结版 import lightgbm 成功
# 但 Booster 初始化即失败 -> L4 永远不就绪（表现为"引擎部分就绪（LightGBM 树模型）"）。
# 必须用 collect_dynamic_libs 把原生 DLL 显式打进 exe。
from PyInstaller.utils.hooks import collect_dynamic_libs as _cdl
from PyInstaller.utils.hooks import collect_data_files as _cdf

lightgbm_binaries = _cdl("lightgbm")
# lightgbm/__init__.py 读取包内 VERSION.txt 数据文件（缺失只影响 __version__ 属性，不影响功能）
lightgbm_datas = _cdf("lightgbm")


a = Analysis(
    [os.path.join(BASE, "Dragon_Antivirus.py")],
    pathex=[BASE],    binaries=lightgbm_binaries,
    datas=datas + lightgbm_datas,
    hiddenimports=[
        "Dragon_Engine",
        "Dragon_Tools",
        "Dragon_scanner",
        "Dragon_Defender",
        "Dragon_PEfeature",
        "dragon_paths",
        # 引擎重构后 vendor 进来的 SevenEngine 本地检测模块（买断源码直抄，仅改 import/常量）
        "dragon_pda_features",
        "dragon_pda_store",
        "dragon_lightgbm_scanner",
        "dragon_custom_rules",
        # L4 运行期延迟 import lightgbm（lightgbm_scanner / pda_store 内）；
        # 必须显式 hiddenimport，否则 modulegraph 把它当 orphan 丢弃、冻结版 L4 加载 .pda 时报缺失。
        "lightgbm",
        # lightgbm 4.x 的 basic.py 顶层硬 import narwhals 和 scipy.sparse —— 这两个【绝不能进
        # excludes】，否则冻结态 import lightgbm 直接 ImportError（被 scanner 吞掉，表现为
        # "LightGBM 不可用（lightgbm 未安装或 .pda 解析失败）"，2026-09-25 实机踩坑）。
        "narwhals",
        "scipy.sparse",
        "wmi",
        "win32api",
        "win32com",
        "win32con",
        "win32gui",
        "win32process",
        "win32security",
        "winreg",
        "ctypes",
        "json",
        # pywebview 的 edgechromium/winforms 两个后端都硬性依赖 pythonnet(clr)，
        # 必须打进 exe，否则主界面起不来（WebViewException: You must have pythonnet installed）。
        "pythonnet",
        "clr_loader",
        # 驱动用户态客户端（内核通信端口），Dragon_Defender 运行时动态 import；
        # 不显式收集会触发 orphan 丢弃、冻结态 driver_connected 报 missing。
        "dragon_client",
        # 驱动对接主模块：Dragon_Antivirus.bind_module_push 运行时 __import__ 它，
        # 必须显式收集，否则冻结态触发 orphan 丢弃、driver 状态推送契约失效。
        "Dragon_Drivers",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PySide6",
        "PyQt5",
        "PyQt6",
        "tkinter",
        # —— 以下均为「模型训练 / 评估」专用，运行期只做 ONNX 推理，绝不调用 ——
        # Dragon_Engine.py 把训练与推理混在同一模块，PyInstaller 静态分析会误把整条
        # sklearn -> scipy -> matplotlib -> polars -> onnx -> onnxmltools 依赖链打进 exe。
        "sklearn",
        # 注意：scipy / narwhals 绝不能排除 —— lightgbm basic.py 顶层硬 import 它们，
        # 排除则冻结态 import lightgbm 直接失败（见上方 hiddenimports 注释）。
        "matplotlib",
        "polars",
        "pyarrow",
        "onnx",            # 注意：保留 onnxruntime（推理用），只排除 onnx 模型定义包
        "onnxmltools",
        "joblib",
        "fsspec",
        "requests",
        "urllib3",
    ],
    win_private_assemblies=False,
    noarchive=True,
)


########################################
# 剔除 dist-info 下的 licenses 镜像树（2026-09-26 实机踩坑修复）
# PyInstaller 6 自动收集各包 dist-info 时会把仓库内的 license 镜像文件一起打进
# datas（本包共 20 个，如 numpy-2.5.3.dist-info\licenses\numpy\random\src\splitmix64\LICENSE.md）。
# 这些纯文本运行期无任何代码读取；且 onefile 解包时该条目在实机上偶发
# "failed to open target file! fopen: Permission denied"，启动器弹 Error 对话框直接退出。
# 只剔 licenses 子树，保留 METADATA / entry_points（不影响 importlib.metadata）。
########################################
def _is_distinfo_license(dest):
    norm = str(dest).replace("\\", "/").lower()
    if ".dist-info/" not in norm:
        return False
    rest = norm.split(".dist-info/", 1)[1]
    return rest == "licenses" or rest.startswith("licenses/")


a.datas = [t for t in a.datas if not _is_distinfo_license(t[1])]
print("[SPEC] 剔除 dist-info licenses 死重后 datas 条目数:", len(a.datas))

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="DragonAntivirus",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)


########################################
# 运行期可变数据（隔离区 / 信任区 / 配置 / 日志 / 基线 / 诱捕 等）统一落在用户级
# %LOCALAPPDATA%\天龙神盾\Data（由 dragon_paths.data_root() 解析），该目录不会被打包流程
# `rmdir /s /q dist build` 清空，重建 / 重启后数据持续保留。dist\Data 不再预置任何运行数据。
#
# 仍然需要外置到 exe 同级的只读资源（模型 / 哈希库 / YARA 规则 / 驱动）见下方 _copy_external_dirs。
########################################
import shutil


def _copy_external_dirs():
    """把运行期必需的外部目录（onefile 不会自动外置）拷贝到 exe 同级 dist/。

    这些目录代码侧以 BASE_DIR（冻结态 = exe 所在目录）加载，必须与 DragonAntivirus.exe
    同目录；否则冻结后引擎/驱动找不到模型、哈希库、YARA 规则、驱动文件。
    """
    for name in ("Dragon_AIModels", "Dragon_VirusDB", "Dragon_CoreRules", "Dragon_Drivers"):
        src = os.path.join(BASE, name)
        if not os.path.isdir(src):
            print("[WARN] 外部目录缺失，跳过:", name)
            continue
        dst = os.path.join(BASE, "dist", name)
        # 用 dirs_exist_ok 覆盖而非先删除，避免触发环境「批量删除守卫」终止进程
        if os.path.isdir(dst):
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            shutil.copytree(src, dst)
        print("[OK] 已外置目录:", name)


# 【2026-09-26】前端 UI 文件不再内置进 PKG，改为外置到 dist/ 与 exe 同级，
# 由 frontend_dir() 走 BASE_DIR 直接读，规避 bootloader 解压失败。
_UI_FILES = ("Dragon_UI.html", "天龙神盾Logo.png", "天龙神盾图标.png", "天龙神盾图标.ico")


def _copy_ui_files():
    """把前端 UI 文件拷贝到 dist/，与 DragonAntivirus.exe 同级。"""
    dst_dir = os.path.join(BASE, "dist")
    os.makedirs(dst_dir, exist_ok=True)
    for fn in _UI_FILES:
        src = os.path.join(BASE, fn)
        if not os.path.isfile(src):
            print("[WARN] UI 文件缺失，跳过:", fn)
            continue
        dst = os.path.join(dst_dir, fn)
        shutil.copy2(src, dst)
        print("[OK] 已外置 UI 文件:", fn)


_copy_external_dirs()
_copy_ui_files()
