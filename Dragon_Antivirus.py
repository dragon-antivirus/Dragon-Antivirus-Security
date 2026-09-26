# -*- coding: utf-8 -*-
"""天龙神盾安全中心 —— UI 外壳模块

职责：
    1. 用 pywebview（WebView2）装载前端 Dragon_UI.html，前端经本地回环 HTTP 服务提供
    2. 提供全局原生右下角通知 toast(弹窗标题, 弹窗内容)
    3. pystray 任务栏托盘图标与菜单
    4. 前端与后端之间的桥接（dragon_* 接口）
    5. 应用级配置持久化、开机启动、诊断日志

说明：
    本文件只负责界面外壳与桥接；安全日志、隔离区、信任区、系统工具、扫描引擎、
    主动防御等能力由 Dragon_* 系列的其它模块提供，未接入前对应接口返回空数据或
    明确的未接入提示，界面显示为空状态。
"""

import ctypes
import ctypes.wintypes
import json
import logging
import os
import sys
import threading
import time
import traceback
import subprocess
from concurrent.futures import ThreadPoolExecutor
from http.server import SimpleHTTPRequestHandler
from socketserver import ThreadingTCPServer
from urllib.parse import unquote

import pystray
import webview
from PIL import Image
import Dragon_Tools as T

########################################常量与路径########################################

APP_NAME = "天龙神盾"
APP_TITLE = "天龙神盾安全中心"
APP_VERSION = "1.0.0.0"
ENGINE_TEXT = "天龙神盾第五代AI智能防护引擎 Dragon AiSmartEngine Gen5 · 四层快速短路式判定，签名 / 哈希模糊匹配 / YARA规则匹配 / AI深度学习，兼顾速度与性能"

FRONTEND_FILE = "Dragon_UI.html"
ASSET_FILES = (
    "天龙神盾Logo.png",
    "天龙神盾图标.png",
    "天龙神盾图标.ico",
)

WINDOW_WIDTH = 1080
WINDOW_HEIGHT = 760

CONFIG_FILE_NAME = "config.json"
BOOT_LOG_NAME = "boot.log"

MUTEX_NAME = "Global\\DragonAntivirus_SingleInstance"
WEBVIEW2_ARGS = "--proxy-bypass-list=<-loopback>;localhost;127.0.0.1"

APP_AUMID = "Dragon-Antivirus.SecurityCenter.1"
AUMID_KEY = "Software\\Classes\\AppUserModelId\\" + APP_AUMID

AUTORUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTORUN_VALUE = APP_TITLE

DEFAULT_CONFIG = {
    "lang": "简体中文",
    "theme": "blue",
    "level": "medium",
    "switches": {
        "driver": True,
        "userMode": True,
        "engineScan": False,
        "realtime": True,
        "keyPositions": False,
        "staticPoll": False,
    },
    "enhancedMode": False,
    "cloudEngine": False,
    "autoStart": True,
    "virusDb": "",
    "installDate": "",
    "firstRun": True,
}


PROT_LEVELS = {
    "low": {
        "driver": False,
        "userMode": True,
        "engineScan": False,
        "realtime": False,
        "keyPositions": False,
        "staticPoll": False,
    },
    "medium": {
        "driver": True,
        "userMode": True,
        "engineScan": False,
        "realtime": True,
        "keyPositions": False,
        "staticPoll": False,
    },
    "high": {
        "driver": True,
        "userMode": True,
        "engineScan": True,
        "realtime": True,
        "keyPositions": True,
        "staticPoll": True,
    },
}


def base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def frontend_dir():
    """前端资源所在目录。

    onefile 下前端文件（Dragon_UI.html + 3 个 UI 素材）一律放在 exe 同级 dist/ 目录，
    **不**走 sys._MEIPASS —— 2026-09-26 实机踩坑：bootloader 在解压某些 .png/.html
    条目时 zlib 返回 -1（PyInstaller 6.x 偶发），导致启动时弹 "Failed to extract
    天龙神盾Logo.png: decompression resulted in return code -1" 错误对话框后进程
    直接退出。改成纯外置后，bootloader 完全不碰这些文件，问题消失。
    非冻结态下回退到 base_dir()（项目根目录），行为不变。
    """
    return base_dir()


def data_dir():
    from dragon_paths import data_root, ensure_persistent_data
    try:
        ensure_persistent_data()
    except Exception:
        pass
    return data_root()


def asset_path(name):
    return os.path.join(frontend_dir(), name)


def now_text():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def today_text():
    return time.strftime("%Y-%m-%d", time.localtime())


########################################诊断日志########################################

_LOG_LOCK = threading.RLock()


def log_write(tag, detail="", level="INFO"):
    line = "{} [{}] {} {}".format(now_text(), level, tag, detail)
    try:
        with _LOG_LOCK:
            with open(os.path.join(data_dir(), BOOT_LOG_NAME), "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass


def log_exception(tag):
    try:
        log_write(tag, traceback.format_exc().replace("\n", " | "), "ERROR")
    except Exception:
        pass


########################################应用配置########################################

class DragonConfig(object):

    def __init__(self):
        self.path = os.path.join(data_dir(), CONFIG_FILE_NAME)
        self.lock = threading.RLock()
        self.data = json.loads(json.dumps(DEFAULT_CONFIG))
        self.load()

    def load(self):
        with self.lock:
            try:
                if os.path.isfile(self.path):
                    with open(self.path, "r", encoding="utf-8") as f:
                        raw = json.load(f)
                    if isinstance(raw, dict):
                        for key in DEFAULT_CONFIG:
                            if key in raw:
                                self.data[key] = raw[key]
                        if not isinstance(self.data.get("switches"), dict):
                            self.data["switches"] = dict(DEFAULT_CONFIG["switches"])
                        else:
                            merged = dict(DEFAULT_CONFIG["switches"])
                            merged.update(self.data["switches"])
                            self.data["switches"] = merged
            except Exception:
                log_exception("config.load")
            if not self.data.get("installDate"):
                self.data["installDate"] = today_text()
            self.data["firstRun"] = False
            self.save()

    def save(self):
        with self.lock:
            try:
                with open(self.path, "w", encoding="utf-8") as f:
                    json.dump(self.data, f, ensure_ascii=False, indent=2)
            except Exception:
                log_exception("config.save")

    def get(self, key, default=None):
        with self.lock:
            return self.data.get(key, default)

    def set(self, key, value):
        with self.lock:
            self.data[key] = value
            self.save()

    def set_switch(self, key, value):
        with self.lock:
            switches = dict(self.data.get("switches") or {})
            switches[str(key)] = bool(value)
            self.data["switches"] = switches
            self.save()

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.data))

    def protect_days(self):
        start = self.get("installDate") or today_text()
        try:
            begin = time.mktime(time.strptime(start, "%Y-%m-%d"))
            return max(1, int((time.time() - begin) // 86400) + 1)
        except Exception:
            return 1


########################################前端静态服务########################################

_ALLOWED_FILES = set([FRONTEND_FILE.lower()] + [name.lower() for name in ASSET_FILES])

WEBVIEW_LOG_NAME = "webview.log"


def configure_webview_logging():
    try:
        handler = logging.FileHandler(os.path.join(data_dir(), WEBVIEW_LOG_NAME), encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger = logging.getLogger("pywebview")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.ERROR)
    except Exception:
        log_exception("webview.logging")


class DragonRequestHandler(SimpleHTTPRequestHandler):

    server_version = "DragonUI/1.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=frontend_dir(), **kwargs)

    def log_message(self, fmt, *args):
        return

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def send_head(self):
        raw = self.path.split("?")[0].rstrip("/")
        name = os.path.basename(unquote(raw))
        if not name:
            name = FRONTEND_FILE
        if name.lower() not in _ALLOWED_FILES:
            self.send_error(404, "Not Found")
            return None
        return super().send_head()


class DragonHTTPServer(ThreadingTCPServer):

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
            return
        log_write("http.error", "{} {}".format(client_address, exc), "WARN")


def start_frontend_server():
    ThreadingTCPServer.allow_reuse_address = True
    ThreadingTCPServer.daemon_threads = True
    server = DragonHTTPServer(("127.0.0.1", 0), DragonRequestHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log_write("http.start", "http://127.0.0.1:{}".format(port))
    return server, port


########################################窗口位置########################################

def center_position(width, height):
    try:
        user32 = ctypes.windll.user32
        screen_w = user32.GetSystemMetrics(0)
        screen_h = user32.GetSystemMetrics(1)
        return int((screen_w - width) / 2), int((screen_h - height) / 2)
    except Exception:
        return 60, 60


########################################托盘图标资源########################################

def load_tray_image():
    png = asset_path("天龙神盾图标.png")
    try:
        if os.path.isfile(png):
            with Image.open(png) as image:
                return image.convert("RGBA").resize((64, 64), Image.LANCZOS)
    except Exception:
        log_exception("tray.icon")
    ico = asset_path("天龙神盾图标.ico")
    try:
        if os.path.isfile(ico):
            with Image.open(ico) as image:
                return image.convert("RGBA").resize((64, 64), Image.LANCZOS)
    except Exception:
        log_exception("tray.icon.ico")
    return Image.new("RGBA", (64, 64), (28, 110, 200, 255))


########################################后端接口########################################

class DragonAPI(object):

    def __init__(self, config, pools):
        self._config = config
        self._pools = pools
        self._window = None
        self._tray = None
        self._ui_ready = threading.Event()
        self._drag_lock = threading.RLock()
        self._drag_origin = (0, 0)
        self._drag_total = (0, 0)
        self._quitting = threading.Event()
        self._fatal_event = threading.Event()
        self._fatal_choice = ""

    ########################################绑定########################################

    def set_window(self, window):
        self._window = window

    def set_tray(self, tray):
        self._tray = tray

    def _wait_ui_ready(self, timeout):
        return self._ui_ready.wait(timeout)

    def _reload_frontend(self):
        try:
            if self._window is not None:
                self._window.reload()
        except Exception:
            log_exception("frontend.reload")

    ########################################工具########################################

    def _delegate(self, module_name, func_name, *args):
        try:
            module = __import__(module_name)
        except Exception as exc:
            log_write("delegate.missing", "{} -> {}".format(module_name, exc), "WARN")
            return {"ok": False, "items": [], "error": "{} 模块未接入".format(module_name)}
        func = getattr(module, func_name, None)
        if not callable(func):
            return {"ok": False, "items": [], "error": "{} 未提供 {}".format(module_name, func_name)}
        try:
            result = func(*args)
            if isinstance(result, dict):
                log_write("api.call", "{}.{} items={}".format(
                    module_name, func_name, len(result.get("items") or [])))
                return result
            return {"ok": True, "result": result}
        except Exception as exc:
            log_exception("delegate.call")
            return {"ok": False, "error": str(exc)}

    def _dialog(self, mode, multiple=False, folder=False):
        if self._window is None:
            return []
        try:
            kind = "FOLDER" if folder else "OPEN"
            dialog_type = getattr(getattr(webview, "FileDialog", None), kind, None)
            if dialog_type is None:
                legacy = "FOLDER_DIALOG" if folder else "OPEN_DIALOG"
                dialog_type = getattr(webview, legacy, None)
            if dialog_type is None:
                return []
            result = self._window.create_file_dialog(dialog_type, allow_multiple=multiple)
            if not result:
                return []
            if isinstance(result, (list, tuple)):
                return [str(item) for item in result]
            return [str(result)]
        except Exception:
            log_exception("dialog")
            return []

    def _window_pos(self):
        try:
            return int(self._window.x), int(self._window.y)
        except Exception:
            pass
        try:
            hwnd = int(self._window.native.Handle)
            rect = ctypes.wintypes.RECT()
            ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(rect))
            return int(rect.left), int(rect.top)
        except Exception:
            return 0, 0

    def _window_move(self, x, y):
        try:
            self._window.move(int(x), int(y))
            return True
        except Exception:
            pass
        try:
            hwnd = int(self._window.native.Handle)
            ctypes.windll.user32.SetWindowPos(hwnd, 0, int(x), int(y), 0, 0, 0x0001 | 0x0004)
            return True
        except Exception:
            log_exception("window.move")
            return False

    def _push(self, channel, data):
        if self._window is None:
            return
        if channel == "driver_status":
            # 驱动连接态变化：同步主动防御底部『启动驱动』弹窗的显隐
            try:
                self._sync_driver_banner(connected=bool((data or {}).get("connected")))
            except Exception:
                pass
        try:
            payload = json.dumps({"channel": channel, "data": data}, ensure_ascii=False)
        except Exception:
            return
        win = self._window
        script = "window.__push__ && window.__push__({});".format(payload)
        # 后台监控线程（文件/进程/网络监控、扫描进度等）会同步调用本函数；
        # pywebview 的 evaluate_js 在 edgechromium 下跨线程同步调用可能死锁/静默失败，
        # 故统一在独立线程执行，避免阻塞防御逻辑且确保推送可靠到达前端。
        threading.Thread(target=self._push_run, args=(win, script), daemon=True).start()

    def _push_run(self, win, script):
        try:
            win.evaluate_js(script)
        except Exception:
            log_exception("push")

    ########################################基础接口########################################

    def dragon_ui_ready(self):
        self._ui_ready.set()
        log_write("ui.ready")
        threading.Thread(target=self._log_page_state, daemon=True).start()
        return {"ok": True}

    def dragon_fatal_choice(self, choice):
        self._fatal_choice = str(choice or "")
        self._fatal_event.set()
        return {"ok": True}

    def wait_fatal_choice(self, timeout_sec):
        self._fatal_event.wait(timeout_sec)
        return self._fatal_choice

    def _log_page_state(self):
        time.sleep(1.5)
        if self._window is None:
            return
        script = (
            "(function(){"
            "var page=document.querySelector('.page.active');"
            "var nav=document.querySelector('.snav.active');"
            "var title=document.querySelector('.page-title');"
            "return [page?page.id:'',nav?nav.dataset.page:'',"
            "String(document.querySelectorAll('.page').length),"
            "String(document.querySelectorAll('.tool-panel').length),"
            "title?title.textContent:'',"
            "document.title].join('|');"
            "})()"
        )
        try:
            log_write("ui.page", str(self._window.evaluate_js(script)))
        except Exception:
            log_exception("ui.page")

    def dragon_product_info(self):
        data = self._config.snapshot()
        return {
            "ok": True,
            "version": APP_VERSION,
            "engine": ENGINE_TEXT,
            "virusDb": data.get("virusDb") or "未更新",
            "installDate": data.get("installDate") or today_text(),
            "protectDays": self._config.protect_days(),
            "lang": data.get("lang") or "简体中文",
            "theme": data.get("theme") or "blue",
            "enhancedMode": bool(data.get("enhancedMode")),
            "cloudEngine": bool(data.get("cloudEngine")),
            "autoStart": bool(auto_start_enabled()),
        }

    def dragon_engine_status(self):
        missing = []
        for name in ("pefile", "yara"):
            try:
                __import__(name)
            except Exception:
                missing.append(name)
        try:
            module = __import__("Dragon_Engine")
        except Exception:
            return {"status": "partial", "detail": "引擎模块未接入", "missing_dependencies": missing}
        try:
            status = module.engine_prepare()
        except Exception:
            log_exception("engine.prepare")
            return {"status": "partial", "detail": "引擎初始化失败", "missing_dependencies": missing}
        layers = status.get("layers") or []
        ready = [item for item in layers if item.get("ready")]
        pending = [str(item.get("title")) for item in layers if not item.get("ready")]
        # 把 L4 的具体失败原因（如 lightgbm 原生库缺失 / .pda 未找到）带进 detail，便于真机排障
        ai_info = status.get("ai") or {}
        if not ai_info.get("ready") and ai_info.get("error"):
            pending.append(str(ai_info.get("error")))
        if len(ready) >= 4 and not missing:
            status["status"] = "ready"
        elif ready:
            status["status"] = "partial"
        else:
            status["status"] = "down"
        status["detail"] = "、".join(missing + pending)
        status["missing_dependencies"] = missing
        return status

    def dragon_lang_set(self, lang):
        self._config.set("lang", str(lang))
        return {"ok": True}

    def dragon_theme_set(self, theme):
        """保存界面主题色（orange/blue/green/purple/cyan）。"""
        theme = str(theme)
        if theme not in ("orange", "blue", "green", "purple", "cyan"):
            theme = "blue"
        self._config.set("theme", theme)
        self._push("theme", {"name": theme})
        return {"ok": True, "theme": theme}

    ########################################窗口接口########################################

    def dragon_window_minimize(self):
        try:
            if self._window is not None:
                self._window.minimize()
            return {"ok": True}
        except Exception as exc:
            log_exception("window.minimize")
            return {"error": str(exc)}

    def dragon_window_close(self):
        try:
            if self._window is not None:
                self._window.hide()
            T.toast(APP_TITLE, "已最小化到托盘，天龙神盾继续保护您的电脑")
            return {"ok": True}
        except Exception as exc:
            log_exception("window.close")
            return {"error": str(exc)}

    def _on_closing(self):
        if self._quitting.is_set():
            return True
        try:
            if self._window is not None:
                self._window.hide()
        except Exception:
            log_exception("window.closing")
        T.toast(APP_TITLE, "已最小化到托盘，天龙神盾继续保护您的电脑")
        log_write("window.closing", "关闭已被拦截，改为最小化到托盘")
        return False

    def dragon_window_drag(self, dx, dy, phase):
        try:
            if self._window is None:
                return {"error": "窗口未就绪"}
            dx = int(dx or 0)
            dy = int(dy or 0)
            with self._drag_lock:
                if phase == "start":
                    self._drag_origin = self._window_pos()
                    self._drag_total = (0, 0)
                elif phase == "move":
                    self._drag_total = (self._drag_total[0] + dx, self._drag_total[1] + dy)
                else:
                    self._drag_total = (0, 0)
                    return {"ok": True}
                self._window_move(self._drag_origin[0] + self._drag_total[0],
                                  self._drag_origin[1] + self._drag_total[1])
            return {"ok": True}
        except Exception as exc:
            log_exception("window.drag")
            return {"error": str(exc)}

    ########################################文件选择########################################

    def dragon_select_path(self):
        picked = self._dialog("open", multiple=False)
        if not picked:
            return {"error": "未选择路径"}
        return {"ok": True, "path": picked[0]}

    def dragon_select_folder(self):
        picked = self._dialog("open", multiple=False, folder=True)
        if not picked:
            return {"error": "未选择目录"}
        return {"ok": True, "path": picked[0]}

    def dragon_select_files(self):
        picked = self._dialog("open", multiple=True)
        if not picked:
            return {"error": "未选择文件"}
        return {"ok": True, "paths": picked}

    ########################################防护配置########################################

    def dragon_protection_config(self):
        data = self._config.snapshot()
        blocked = 0
        try:
            defender = __import__("Dragon_Defender")
            g = getattr(defender, "defense_get_blocked", None)
            if callable(g):
                blocked = (g() or {}).get("count", 0)
        except Exception:
            pass
        return {
            "level": data.get("level") or "medium",
            "switches": data.get("switches") or dict(DEFAULT_CONFIG["switches"]),
            "blocked_today": blocked,
        }

    def dragon_protection_level(self, level):
        level = str(level)
        if level not in ("low", "medium", "high"):
            level = "medium"
        self._config.set("level", level)
        mapping = PROT_LEVELS.get(level, PROT_LEVELS["medium"])
        for key, value in mapping.items():
            self._config.set_switch(key, value)
        try:
            defender = __import__("Dragon_Defender")
            sync = getattr(defender, "defense_set_levels", None)
            if callable(sync):
                sync(mapping)
        except Exception:
            pass
        return {"ok": True, "level": level, "switches": mapping}

    def dragon_protection_switch(self, key, enabled):
        self._config.set_switch(key, bool(enabled))
        try:
            defender = __import__("Dragon_Defender")
            setter = getattr(defender, "defense_set_level", None)
            if callable(setter):
                setter(key, bool(enabled))
            levels = getattr(defender, "defense_get_level", None)
            running = getattr(defender, "defense_status", None)
            live = levels() if callable(levels) else None
            rstate = running() if callable(running) else None
        except Exception:
            live = None
            rstate = None
        # 立刻把权威状态推给前端，杜绝"开关玄学"（前端据此回填，而非乐观翻转）
        self._push("protection", self.dragon_protection_config())
        return {"ok": True, "key": key, "value": bool(enabled),
                "levels": live, "running": (rstate or {}).get("running")}

    def dragon_protection_push(self):
        self._push("protection", self.dragon_protection_config())
        return {"ok": True}

    ########################################驱动启动弹窗########################################

    def _sync_driver_banner(self, connected=None):
        """计算主动防御底部『启动驱动』弹窗的显示状态并推给前端。

        show = 需要内核驱动（总开关开启且已开启驱动防护）但当前未连接。
        驱动连接成功后由 Dragon_Drivers 推送 driver_status(connected=True) 自动触发本函数隐藏弹窗。
        """
        try:
            import Dragon_Defender as defender
            st = defender.defense_status()
        except Exception:
            return
        if connected is None:
            connected = bool(st.get("driver_connected"))
        levels = st.get("levels") or {}
        need = bool(st.get("running")) and bool(levels.get(defender.LEVEL_DRIVER))
        show = bool(need) and (not connected)
        reboot = bool(st.get("driver_reboot_required"))
        if show:
            message = ("内核驱动加载失败。若已开启安全启动(Secure Boot)或 Windows 内存完整性"
                       "（内核隔离），驱动会被拒绝加载。请先在主板固件中关闭安全启动，并在"
                       "「Windows 安全中心 → 设备安全性 → 内核隔离」关闭内存完整性，然后重启"
                       "系统后点击『启动驱动』重试。")
        else:
            message = ""
        self._push("driver_failed", {
            "show": show,
            "connected": connected,
            "need_driver": need,
            "reboot_required": reboot,
            "message": message,
        })

    def dragon_driver_start(self):
        """主动防御底部『启动驱动』弹窗的『重试』入口：尝试安装并连接内核驱动。"""
        try:
            import Dragon_Defender as defender
            res = defender.defense_set_driver_enabled(True)
        except Exception as exc:
            res = {"ok": False, "connected": False, "error": str(exc)}
        connected = bool(res.get("connected"))
        self._sync_driver_banner(connected=connected)
        return {
            "ok": res.get("ok", False),
            "connected": connected,
            "error": res.get("error"),
            "reboot_required": res.get("reboot_required"),
        }

    def dragon_defense_blocked(self):
        try:
            defender = __import__("Dragon_Defender")
            g = getattr(defender, "defense_get_blocked", None)
            if callable(g):
                return g()
        except Exception:
            pass
        return {"ok": True, "count": 0}

    ########################################设置接口########################################

    def dragon_enhanced_mode(self, enabled):
        enabled = bool(enabled)
        self._config.set("enhancedMode", enabled)
        # 即时重配引擎（L4 阈值下调更激进），无需重启
        try:
            engine = __import__("Dragon_Engine")
            cfg = getattr(engine, "set_engine_config", None)
            if callable(cfg):
                cfg(enhanced_mode=enabled)
        except Exception:
            log_exception("enhanced.apply")
        return {"ok": True}

    def dragon_cloud_engine(self, enabled):
        enabled = bool(enabled)
        self._config.set("cloudEngine", enabled)
        try:
            engine = __import__("Dragon_Engine")
            cfg = getattr(engine, "set_engine_config", None)
            if callable(cfg):
                cfg(cloud_enabled=enabled)
        except Exception:
            log_exception("cloud.apply")
        T.toast(APP_TITLE, "云引擎已{}".format("开启" if enabled else "关闭"))
        return {"ok": True, "enabled": enabled}

    def dragon_auto_start(self, enabled):
        enabled = bool(enabled)
        result = set_auto_start(enabled)
        if result.get("ok"):
            self._config.set("autoStart", enabled)
            T.toast(APP_TITLE, "开机启动已{}".format("开启" if enabled else "关闭"))
        else:
            T.toast(APP_TITLE, "开机启动设置失败：{}".format(result.get("error", "")))
        return result

    ########################################安全日志########################################

    def dragon_log_list(self):
        return self._delegate("Dragon_Tools", "dragon_log_list")

    ########################################隔离区########################################

    def dragon_quarantine_list(self):
        return self._delegate("Dragon_Tools", "dragon_quarantine_list")

    def dragon_quarantine_add(self, path):
        return self._delegate("Dragon_Tools", "dragon_quarantine_add", path)

    def dragon_quarantine_restore(self, paths):
        return self._delegate("Dragon_Tools", "dragon_quarantine_restore", paths)

    def dragon_quarantine_remove(self, paths):
        return self._delegate("Dragon_Tools", "dragon_quarantine_remove", paths)

    def dragon_quarantine_to_trusted(self, paths):
        return self._delegate("Dragon_Tools", "dragon_quarantine_to_trusted", paths)

    def dragon_quarantine_restore_to_trusted(self, paths):
        return self._delegate("Dragon_Tools", "dragon_quarantine_restore_to_trusted", paths)

    ########################################信任区########################################

    def dragon_trusted_list(self):
        return self._delegate("Dragon_Tools", "dragon_trusted_list")

    def dragon_trusted_add(self, path):
        return self._delegate("Dragon_Tools", "dragon_trusted_add", path)

    def dragon_trusted_remove(self, paths):
        return self._delegate("Dragon_Tools", "dragon_trusted_remove", paths)

    ########################################系统工具########################################

    def dragon_clean_scan(self):
        return self._delegate("Dragon_Tools", "dragon_clean_scan")

    def dragon_clean_run(self, names):
        return self._delegate("Dragon_Tools", "dragon_clean_run", names)

    def dragon_repair_list(self):
        return self._delegate("Dragon_Tools", "dragon_repair_list")

    def dragon_repair_run(self, names):
        return self._delegate("Dragon_Tools", "dragon_repair_run", names)

    def dragon_startup_list(self):
        return self._delegate("Dragon_Tools", "dragon_startup_list")

    def dragon_startup_set(self, name, enabled):
        return self._delegate("Dragon_Tools", "dragon_startup_set", name, enabled)

    def dragon_contextmenu_list(self):
        return self._delegate("Dragon_Tools", "dragon_contextmenu_list")

    def dragon_contextmenu_set(self, name, enabled):
        return self._delegate("Dragon_Tools", "dragon_contextmenu_set", name, enabled)

    def dragon_shred_files(self, paths):
        return self._delegate("Dragon_Tools", "dragon_shred_files", paths)

    ########################################扫描########################################

    def dragon_scan_start(self, mode, target):
        result = self._delegate("Dragon_scanner", "dragon_scan_start", mode, target, self._push)
        if not result.get("ok"):
            return {"error": result.get("error") or "扫描模块未接入"}
        return {"ok": True}

    def dragon_scan_stop(self):
        result = self._delegate("Dragon_scanner", "dragon_scan_stop")
        if not result.get("ok"):
            return {"error": result.get("error") or "扫描模块未接入"}
        return {"ok": True}

    def dragon_scan_handle(self, action, paths):
        result = self._delegate("Dragon_scanner", "dragon_scan_handle", action, paths)
        if not result.get("ok"):
            return {"error": result.get("error") or "扫描模块未接入"}
        return {"ok": True}

    ########################################托盘动作########################################

    def tray_open_page(self, page, panel=None):
        try:
            if self._window is not None:
                self._window.show()
                self._window.restore()
            script = "switchPage('{}');".format(page)
            if panel:
                script += "openPanel('{}');".format(panel)
            if self._window is not None:
                self._window.evaluate_js(script)
        except Exception:
            log_exception("tray.open")
        return {"ok": True}

    def tray_quick_scan(self):
        self._tray_open_page("scan")
        try:
            if self._window is not None:
                self._window.evaluate_js("startScan('智能扫描');")
        except Exception:
            log_exception("tray.quick_scan")
        return {"ok": True}

    def tray_language(self, lang):
        try:
            if self._window is not None:
                self._window.show()
                self._window.evaluate_js("applyLang('{}');".format(lang))
        except Exception:
            log_exception("tray.lang")
        self._config.set("lang", lang)
        return {"ok": True}

    def quit_app(self):
        if self._quitting.is_set():
            return
        self._quitting.set()
        log_write("app.quit")
        try:
            if self._tray is not None:
                self._tray.stop()
        except Exception:
            log_exception("quit.tray")
        try:
            if self._window is not None:
                self._window.destroy()
        except Exception:
            log_exception("quit.window")


########################################开机启动########################################

def auto_start_command():
    if getattr(sys, "frozen", False):
        return '"{}"'.format(os.path.abspath(sys.executable))
    script = os.path.join(base_dir(), "Dragon_Antivirus.py")
    return '"{}" "{}"'.format(os.path.abspath(sys.executable), script)


def auto_start_enabled():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTORUN_KEY) as key:
            value, _ = winreg.QueryValueEx(key, AUTORUN_VALUE)
            return bool(value)
    except Exception:
        return False


def set_auto_start(enabled):
    try:
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, AUTORUN_KEY) as key:
            if enabled:
                winreg.SetValueEx(key, AUTORUN_VALUE, 0, winreg.REG_SZ, auto_start_command())
            else:
                try:
                    winreg.DeleteValue(key, AUTORUN_VALUE)
                except FileNotFoundError:
                    pass
        log_write("autostart", str(enabled))
        return {"ok": True}
    except Exception as exc:
        log_exception("autostart")
        return {"error": str(exc)}


########################################应用标识########################################

def register_app_identity():
    try:
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, AUMID_KEY) as key:
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, APP_TITLE)
            icon = asset_path("天龙神盾图标.ico")
            if os.path.isfile(icon):
                winreg.SetValueEx(key, "IconUri", 0, winreg.REG_SZ, icon)
    except Exception:
        log_exception("app.identity.registry")
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_AUMID)
        log_write("app.identity", APP_AUMID)
    except Exception:
        log_exception("app.identity.aumid")


########################################托盘########################################

class DragonTray(object):

    def __init__(self, api):
        self.api = api
        self.icon = None
        self.thread = None

    def build_menu(self):
        return pystray.Menu(
            pystray.MenuItem("打开界面", self.on_open, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("智能扫描", self.on_scan),
            pystray.MenuItem("隔离区", self.on_quarantine),
            pystray.MenuItem("信任区", self.on_trusted),
            pystray.MenuItem("防护日志", self.on_log),
            pystray.MenuItem("防护等级", pystray.Menu(
                pystray.MenuItem("低（仅用户态）", self.on_level_low),
                pystray.MenuItem("中（驱动+用户态）", self.on_level_medium),
                pystray.MenuItem("高（驱动+用户态+引擎扫描）", self.on_level_high),
            )),
            pystray.MenuItem("小工具", self.on_tools),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出", self.on_quit),
        )

    def start(self):
        self.icon = pystray.Icon(APP_NAME, load_tray_image(), APP_TITLE, self.build_menu())
        T.set_tray_icon(self.icon)
        self.thread = threading.Thread(target=self.icon.run, daemon=True)
        self.thread.start()
        return self.icon

    def stop(self):
        try:
            if self.icon is not None:
                self.icon.stop()
        except Exception:
            log_exception("tray.stop")

    def notify(self, title, message):
        try:
            if self.icon is not None:
                self.icon.notify(message, title)
        except Exception:
            log_exception("tray.notify")

    ########################################菜单动作########################################

    def on_open(self, icon=None, item=None):
        self.api.tray_open_page("home")

    def on_scan(self, icon=None, item=None):
        self.api.tray_quick_scan()

    def on_quarantine(self, icon=None, item=None):
        self.api.tray_open_page("tools", "panel-geli")

    def on_trusted(self, icon=None, item=None):
        self.api.tray_open_page("tools", "panel-xinren")

    def on_log(self, icon=None, item=None):
        self.api.tray_open_page("tools", "panel-rizhi")

    def on_level_low(self, icon=None, item=None):
        self.api.dragon_protection_level("low")
        self.api.dragon_protection_push()

    def on_level_medium(self, icon=None, item=None):
        self.api.dragon_protection_level("medium")
        self.api.dragon_protection_push()

    def on_level_high(self, icon=None, item=None):
        self.api.dragon_protection_level("high")
        self.api.dragon_protection_push()

    def on_tools(self, icon=None, item=None):
        self.api.tray_open_page("tools")

    def on_quit(self, icon=None, item=None):
        self.api.quit_app()


########################################单实例########################################

_MUTEX_HANDLE = None


def take_single_instance():
    global _MUTEX_HANDLE
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
        if not handle:
            return True
        if kernel32.GetLastError() == 183:
            return False
        _MUTEX_HANDLE = handle
        return True
    except Exception:
        return True


########################################启动看门狗########################################

def start_watchdog(api):
    def worker():
        if api._wait_ui_ready(30.0):
            log_write("watchdog", "前端已就绪")
            return
        log_write("watchdog", "前端 30 秒未就绪，执行一次重新加载", "WARN")
        api._reload_frontend()
        if not api._wait_ui_ready(30.0):
            log_write("watchdog", "前端重新加载后仍未就绪", "ERROR")

    threading.Thread(target=worker, daemon=True).start()


def bind_module_push(api):
    for module_name in ("Dragon_Tools", "Dragon_scanner", "Dragon_Defender", "Dragon_Drivers"):
        try:
            module = __import__(module_name)
        except Exception:
            continue
        setter = getattr(module, "dragon_set_push", None)
        if callable(setter):
            try:
                setter(api._push)
                log_write("push.bind", module_name)
            except Exception:
                log_exception("push.bind")


########################################初始化播报########################################

def start_init_report(api):
    """前端就绪后播报引擎/主动防御初始化状态；加载失败弹中央对话框。"""

    def worker():
        if not api._wait_ui_ready(40.0):
            log_write("init.report", "前端 40 秒未就绪，跳过初始化播报", "WARN")
            return
        time.sleep(1.0)
        fatal = []
        try:
            import Dragon_Defender as defender
        except Exception:
            defender = None
            fatal.append("主动防御模块加载失败")
        engine_ok = False
        try:
            status = api.dragon_engine_status()
            state = status.get("status")
            detail = status.get("detail") or ""
            if state == "ready":
                engine_ok = True
                engine_state = "就绪"
            elif state == "partial":
                engine_ok = True
                engine_state = "部分就绪（{}）".format(detail)
            else:
                engine_state = "初始化失败（{}）".format(detail or "未知原因")
        except Exception:
            log_exception("init.report")
            engine_state = "初始化失败"
        T.safe_log("引擎初始化", "核心杀毒引擎,状态:{}".format(engine_state))
        T.toast("引擎初始化", "核心杀毒引擎,状态:{}".format(engine_state))
        if not engine_ok:
            fatal.append("核心杀毒引擎加载失败")
        if defender is not None:
            try:
                running = bool(defender._STATE.get("running"))
            except Exception:
                running = False
            try:
                master_on = bool(defender._STATE.get("levels", {}).get(defender.LEVEL_USERMODE))
            except Exception:
                master_on = True
            try:
                driver_ok = bool(defender.driver_connected())
            except Exception:
                driver_ok = False
            state_text = "运行中" if running else ("未运行" if master_on else "未运行(总开关已关闭)")
            defense_text = "R3防御,状态:{}｜驱动防护,状态:{}".format(
                state_text,
                "已连接" if driver_ok else "未连接")
            T.safe_log("主动防御初始化", defense_text)
            T.toast("主动防御初始化", defense_text)
            # 同步主动防御底部『启动驱动』弹窗状态（驱动需启用却未连接时弹出）
            try:
                api._sync_driver_banner()
            except Exception:
                pass
            # 仅当总开关已开启却仍未运行才视为真实加载失败；总开关被用户关闭属正常状态。
            if not running and master_on:
                fatal.append("主动防御（R3）加载失败")
        if not fatal:
            return
        message = "{}，请尝试以管理员身份运行，或联系客服。".format("、".join(fatal))
        log_write("init.report", "fatal {}".format(message), "ERROR")
        try:
            api._window.evaluate_js("window.__dragonFatal__ && window.__dragonFatal__({})".format(
                json.dumps(message, ensure_ascii=False)))
        except Exception:
            log_exception("init.report")
            return
        choice = api.wait_fatal_choice(300)
        log_write("init.report", "fatal choice={}".format(choice or "timeout"))
        if choice == "ok":
            T.safe_log("初始化", "用户确认退出")
            try:
                if api._window is not None:
                    api._window.destroy()
            except Exception:
                log_exception("init.report")
            time.sleep(0.5)
            os._exit(0)

    threading.Thread(target=worker, daemon=True).start()


########################################引擎预热########################################

def start_engine_warmup(api):
    def worker():
        if not api._wait_ui_ready(30.0):
            log_write("engine.warmup", "前端未就绪，跳过预热", "WARN")
            return
        try:
            status = api.dragon_engine_status()
            log_write("engine.warmup", "引擎状态 {} {}".format(status.get("status"), status.get("detail") or ""))
        except Exception:
            log_exception("engine.warmup")

    threading.Thread(target=worker, daemon=True).start()


########################################界面自检钩子########################################

def start_ui_selftest(api):
    script = (os.environ.get("DRAGON_UI_SELFTEST") or "").strip()
    if not script:
        return

    def worker():
        if not api._wait_ui_ready(30.0):
            log_write("ui.selftest", "前端未就绪，跳过自检", "WARN")
            return
        time.sleep(3.0)
        try:
            api._window.evaluate_js(script)
            log_write("ui.selftest", script)
        except Exception:
            log_exception("ui.selftest")

    threading.Thread(target=worker, daemon=True).start()


########################################主入口########################################

def _context_scan_target():
    """读取 Windows 右键扫描传入的单个文件或目录路径。"""
    args = list(sys.argv[1:])
    for index, arg in enumerate(args):
        if arg == "--dragon-context-scan" and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith("--dragon-context-scan="):
            return arg.split("=", 1)[1]
    return ""


def run_context_scan(target):
    """右键菜单入口：不启动窗口，直接扫描并给出系统通知。"""
    target = os.path.abspath(os.path.expandvars(str(target or "").strip().strip('"')))
    try:
        scanner = __import__("Dragon_scanner")
        result = scanner.dragon_scan_once(target)
        if result.get("ok"):
            return 0
        T.toast(APP_TITLE, "右键扫描失败：{}".format(result.get("error", "未知错误")))
        log_write("context.scan", result.get("error", "未知错误"), "ERROR")
        return 1
    except Exception as exc:
        log_exception("context.scan")
        T.toast(APP_TITLE, "右键扫描失败：{}".format(exc))
        return 1


def apply_saved_engine_config(config):
    """启动时恢复增强模式和云引擎，避免重启后只恢复 UI 不恢复引擎。"""
    try:
        engine = __import__("Dragon_Engine")
        cfg = getattr(engine, "set_engine_config", None)
        if callable(cfg):
            cfg(enhanced_mode=bool(config.get("enhancedMode")),
                cloud_enabled=bool(config.get("cloudEngine")))
    except Exception:
        log_exception("engine.config")


def main():
    # 安装程序驱动加载入口：仅尝试连接内核驱动，输出 JSON 结果后立即退出（不启动界面）。
    # 安装向导在「启动驱动」步骤调用 `DragonAntivirus.exe --start-driver`，失败不阻塞安装。
    if "--start-driver" in sys.argv:
        import json
        try:
            _def = __import__("Dragon_Defender")
            res = _def.defense_set_driver_enabled(True)
        except Exception as exc:
            import traceback as _tb
            _tb.print_exc()
            res = {"ok": False, "connected": False, "error": "{}".format(exc)}
        # 结果落盘：主程序是 GUI 子系统（console=False），stdout 通常不可用，
        # 安装向导以该文件为准显示加载失败的真实原因。
        try:
            _res_path = os.path.join(data_dir(), "driver_start_result.json")
            os.makedirs(os.path.dirname(_res_path), exist_ok=True)
            with open(_res_path, "w", encoding="utf-8") as _fh:
                _fh.write(json.dumps(res, ensure_ascii=False))
        except Exception:
            pass
        try:
            print(json.dumps(res, ensure_ascii=False))
        except Exception:
            pass
        os._exit(0 if res.get("connected") else 1)

    context_target = _context_scan_target()
    if context_target:
        return run_context_scan(context_target)
    if not take_single_instance():
        log_write("app.instance", "程序已在运行", "WARN")
        return 1

    os.environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = WEBVIEW2_ARGS

    if not os.path.isfile(os.path.join(frontend_dir(), FRONTEND_FILE)):
        log_write("app.frontend", "缺少前端文件 {}".format(FRONTEND_FILE), "ERROR")
        return 1

    log_write("app.start", "{} {}".format(APP_TITLE, APP_VERSION))
    configure_webview_logging()
    register_app_identity()

    config = DragonConfig()
    apply_saved_engine_config(config)
    try:
        # 让配置与 Windows 启动项真实状态保持一致，而不是只在 UI 里显示开。
        set_auto_start(bool(config.get("autoStart")))
    except Exception:
        log_exception("autostart.sync")
    try:
        tools = __import__("Dragon_Tools")
        menu_result = tools.install_context_scan_menu()
        if menu_result.get("error"):
            log_write("contextmenu.install", menu_result.get("error"), "WARN")
    except Exception:
        log_exception("contextmenu.install")
    pools = {
        "scan": ThreadPoolExecutor(max_workers=2),
        "protect": ThreadPoolExecutor(max_workers=8),
        "proc": ThreadPoolExecutor(max_workers=16),
    }

    api = DragonAPI(config, pools)
    bind_module_push(api)
    start_engine_warmup(api)

    server, port = start_frontend_server()
    storage = os.path.join(data_dir(), "WebView2")
    try:
        os.makedirs(storage, exist_ok=True)
    except Exception:
        log_exception("webview.storage")

    x, y = center_position(WINDOW_WIDTH, WINDOW_HEIGHT)
    url = "http://127.0.0.1:{}/{}".format(port, FRONTEND_FILE)

    window = webview.create_window(
        APP_TITLE,
        url,
        js_api=api,
        width=WINDOW_WIDTH,
        height=WINDOW_HEIGHT,
        x=x,
        y=y,
        resizable=False,
        frameless=True,
        easy_drag=False,
        background_color="#eef2f7",
        min_size=(WINDOW_WIDTH, WINDOW_HEIGHT),
    )
    api.set_window(window)

    def on_loaded():
        log_write("window.loaded", url)

    try:
        window.events.loaded += on_loaded
        window.events.closing += api._on_closing
    except Exception:
        log_exception("window.events")

    tray = DragonTray(api)
    api.set_tray(tray)
    tray.start()

    # 应用已保存的防护开关并启动主动防御监控线程
    try:
        defender = __import__("Dragon_Defender")
        _switches = config.data.get("switches") or dict(DEFAULT_CONFIG["switches"])
        try:
            defender.defense_set_levels(_switches)
        except Exception:
            log_exception("defense.set_levels")
        _install_res = defender.defense_install_hooks()
        log_write("defense.install", str(_install_res))
        # 接上 defense_event 推送通道（此前从未接线，导致今日拦截等实时事件无法到达前端）
        try:
            defender.defense_register_push(lambda payload: api._push("defense_event", payload))
        except Exception:
            log_exception("defense.register_push")
    except Exception:
        log_exception("defense.install")

    start_watchdog(api)
    start_ui_selftest(api)
    start_init_report(api)

    T.toast(APP_TITLE, "天龙神盾已启动，正在保护您的电脑")

    try:
        webview.start(gui="edgechromium", private_mode=False, storage_path=storage)
    except Exception:
        log_exception("webview.start")
    finally:
        log_write("app.exit")
        try:
            server.shutdown()
        except Exception:
            pass
        for pool in pools.values():
            try:
                pool.shutdown(wait=False)
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
