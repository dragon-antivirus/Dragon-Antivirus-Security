# -*- coding: utf-8 -*-
"""天龙神盾安全中心 —— 病毒扫描引擎（五层串行短路架构 V2）

五层快速短路式判定：
  L1 数字签名验证（用户 WinVerifyTrust 路径，契约兼容）
  L2 哈希病毒库 + 宏规则（哈希=AdvancedSignature 思路；宏规则=SevenEngine CustomRuleScanner 直抄）
  L3 YARA 规则匹配（用户 Dragon_CoreRules 单文件库）
  L4 LightGBM 树模型（SevenEngine LightGBMScanner 直抄，加载 .pda，512 维特征）
  L5 云查杀（自研 CFTQ 反病毒云，默认关闭，不降级）

判定顺序严格串行，前一层判定为恶意即返回，不再进入后续层。
L4 永远在线（买断引擎本体）；L5 仅在开启云查杀且 L4 判恶意时做二次确认（不降级本地结论）。
"""

import ctypes
import ctypes.wintypes
import hashlib
import json
import os
import re
import struct
import sys
import threading
import time
import urllib.request
import urllib.error
import ssl

try:
    import pefile
except Exception:
    pefile = None

try:
    import yara
except Exception:
    yara = None

try:
    import numpy as np
except Exception:
    np = None

# SevenEngine 买断本地检测能力（授权可直抄，仅改 import 路径）
from dragon_lightgbm_scanner import LightGBMScanner   # L4：PDA1 + LightGBM booster
from dragon_custom_rules import CustomRuleScanner       # L2b：宏规则 DSL (.srule)

########################################常量与路径########################################

BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
from dragon_paths import data_root
DATA_DIR = data_root()  # 持久化根：%LOCALAPPDATA%\天龙神盾\Data，重建/重启不丢失
MODEL_DIR = os.path.join(BASE_DIR, "Dragon_AIModels")
HASHDB_DIR = os.path.join(BASE_DIR, "Dragon_VirusDB")
YARA_DIR = os.path.join(BASE_DIR, "Dragon_CoreRules")
PDA_PATH = os.path.join(MODEL_DIR, "Dragon_AIModels.pda")

ENGINE_VERSION = "1.0.0.0"

HASHDB_FILE = os.path.join(HASHDB_DIR, "malware_hashes.tsv")
YARA_CACHE_FILE = os.path.join(DATA_DIR, "yara_rules.bin")
ENGINE_LOG_FILE = os.path.join(DATA_DIR, "engine.log")

# L4 LightGBM 运行阈值：普通模式 0.5，增强模式 0.4。
# 这里以引擎策略为准，不再被 .pda 文件头中的旧阈值覆盖。
MALICIOUS_THRESHOLD = 0.5
ENHANCED_THRESHOLD = 0.4
GRAY_ZONE_LOW = 0.4
GRAY_ZONE_HIGH = 0.7

LAYER_SIGNATURE = 1
LAYER_HASHDB = 2
LAYER_YARA = 3
LAYER_AI = 4

LAYER_TITLES = {
    1: "数字签名",
    2: "哈希库+宏规则",
    3: "YARA 规则",
    4: "LightGBM 树模型",
}

VERDICT_MALICIOUS = "malicious"
VERDICT_SAFE = "safe"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_SKIPPED = "skipped"
VERDICT_ERROR = "error"

CHUNK_SIZE = 1024 * 1024
TRUNC_HASH_BYTES = 64 * 1024
SECTION_HASH_LIMIT = 1024 * 1024
SECTION_HASH_SECTIONS = 16
SIGNATURE_CACHE_LIMIT = 4096
RESULT_CACHE_LIMIT = 8192

ESCALATE_MAX_BYTES = 256 * 1024 * 1024
ESCALATE_TIER = 6

HASHDB_TYPES = ("sha256", "md5", "imphash", "section", "trunc")
HASHDB_EXTENSIONS = (".tsv", ".txt", ".hash", ".hdb")
FUZZY_VOTE_REQUIRED = 2

YARA_CORE_SOURCES = ("Dragon_CoreRules.yar",)
YARA_HEAVY_SOURCES = ("ThreatHunting-Keywords-yara-rules",)
YARA_EXTENSIONS = (".yar", ".yara")
YARA_MATCH_TIMEOUT = 30

WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"

SIGNATURE_MESSAGES = {
    0x00000000: "签名有效且证书链受信任",
    0x800B0100: "文件未签名",
    0x800B0001: "未知的信任提供程序",
    0x800B0003: "签名主体格式未知",
    0x800B0004: "签名主体不受信任",
    0x800B0101: "证书已过期",
    0x800B0109: "证书链根不受信任",
    0x800B010C: "证书已被吊销",
    0x800B0111: "证书被显式不信任",
    0x800B0112: "证书链处理中",
    0x80096010: "数字签名摘要不匹配",
    0x80096005: "时间戳签名无效",
    0x80092003: "读取文件时出错",
    0x80092026: "签名无效",
}

########################################通用工具########################################


def ensure_dirs():
    for path in (DATA_DIR, MODEL_DIR, HASHDB_DIR, YARA_DIR):
        try:
            os.makedirs(path, exist_ok=True)
        except Exception:
            pass


def engine_log(event, detail="", level="INFO"):
    line = "{}\t{}\t{}\t{}\n".format(time.strftime("%Y-%m-%d %H:%M:%S"), level, event, detail)
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(ENGINE_LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(line)
    except Exception:
        pass
    return line


def safe_log(event, detail=""):
    try:
        module = __import__("Dragon_Tools")
        function = getattr(module, "safe_log", None)
        if callable(function):
            function(event, detail)
            return True
    except Exception:
        pass
    return False


def format_bytes(size):
    try:
        size = float(size)
    except Exception:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            return "{:.2f} {}".format(size, unit) if unit != "B" else "{} B".format(int(size))
        size /= 1024.0
    return "{} B".format(int(size))


def file_fingerprint(path):
    try:
        info = os.stat(path)
    except Exception:
        return None
    return (os.path.abspath(path), int(info.st_size), int(info.st_mtime))


class LruCache:
    def __init__(self, limit):
        self._limit = max(16, int(limit))
        self._data = {}
        self._order = []
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def get(self, key):
        with self._lock:
            if key in self._data:
                self._hits += 1
                try:
                    self._order.remove(key)
                except ValueError:
                    pass
                self._order.append(key)
                return True, self._data[key]
            self._misses += 1
            return False, None

    def put(self, key, value):
        with self._lock:
            if key in self._data:
                try:
                    self._order.remove(key)
                except ValueError:
                    pass
            self._data[key] = value
            self._order.append(key)
            while len(self._order) > self._limit:
                oldest = self._order.pop(0)
                self._data.pop(oldest, None)

    def clear(self):
        with self._lock:
            self._data.clear()
            self._order = []
            self._hits = 0
            self._misses = 0

    def stats(self):
        with self._lock:
            return {"size": len(self._data), "limit": self._limit, "hits": self._hits, "misses": self._misses}


########################################层 1 数字签名########################################


class Guid(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.wintypes.DWORD),
        ("Data2", ctypes.wintypes.WORD),
        ("Data3", ctypes.wintypes.WORD),
        ("Data4", ctypes.c_byte * 8),
    ]


class WintrustFileInfo(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pcwszFilePath", ctypes.wintypes.LPCWSTR),
        ("hFile", ctypes.wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(Guid)),
    ]


class WintrustData(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", ctypes.wintypes.DWORD),
        ("fdwRevocationChecks", ctypes.wintypes.DWORD),
        ("dwUnionChoice", ctypes.wintypes.DWORD),
        ("pFile", ctypes.POINTER(WintrustFileInfo)),
        ("dwStateAction", ctypes.wintypes.DWORD),
        ("hWVTStateData", ctypes.wintypes.HANDLE),
        ("pwszURLReference", ctypes.wintypes.LPWSTR),
        ("dwProvFlags", ctypes.wintypes.DWORD),
        ("dwUIContext", ctypes.wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_REVOCATION_CHECK_NONE = 0x00000010
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000

_SIGNATURE_CACHE = LruCache(SIGNATURE_CACHE_LIMIT)
_ENGINE_LOCK = threading.RLock()


def certificate_table(pe):
    if pe is None:
        return 0, 0
    try:
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        return int(directory.VirtualAddress or 0), int(directory.Size or 0)
    except Exception:
        return 0, 0


def verify_signature(path):
    try:
        handle = ctypes.windll.wintrust
    except Exception:
        return {"valid": False, "code": None, "status": "unavailable", "message": "当前系统不支持签名验证接口"}
    file_info = WintrustFileInfo()
    file_info.cbStruct = ctypes.sizeof(WintrustFileInfo)
    file_info.pcwszFilePath = str(path)
    file_info.hFile = None
    file_info.pgKnownSubject = None
    trust_data = WintrustData()
    trust_data.cbStruct = ctypes.sizeof(WintrustData)
    trust_data.dwUIChoice = WTD_UI_NONE
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
    trust_data.dwUnionChoice = WTD_CHOICE_FILE
    trust_data.pFile = ctypes.pointer(file_info)
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY
    trust_data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
    action = Guid()
    try:
        ctypes.wintll.ole32.CLSIDFromString(WINTRUST_ACTION_GENERIC_VERIFY_V2, ctypes.byref(action))
    except Exception:
        return {"valid": False, "code": None, "status": "unavailable", "message": "无法构造校验动作标识"}
    code = None
    try:
        code = int(handle.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(trust_data)))
    except Exception:
        code = None
    finally:
        try:
            trust_data.dwStateAction = WTD_STATEACTION_CLOSE
            handle.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(trust_data))
        except Exception:
            pass
    if code is None:
        return {"valid": False, "code": None, "status": "error", "message": "签名验证调用失败"}
    unsigned = code & 0xFFFFFFFF
    message = SIGNATURE_MESSAGES.get(unsigned)
    if message is None:
        message = "签名验证未通过（代码 0x{:08X}）".format(unsigned)
    return {
        "valid": unsigned == 0,
        "code": "0x{:08X}".format(unsigned),
        "status": "valid" if unsigned == 0 else "invalid",
        "message": message,
    }


def signature_state(path, pe):
    fingerprint = file_fingerprint(path)
    if fingerprint is not None:
        hit, cached = _SIGNATURE_CACHE.get(fingerprint)
        if hit:
            return cached
    table_va, table_size = certificate_table(pe)
    if not table_va or not table_size:
        state = {
            "present": False,
            "valid": False,
            "verified": False,
            "status": "absent",
            "message": "无证书表，判定为无有效签名",
            "table_va": table_va,
            "table_size": table_size,
        }
    else:
        detail = verify_signature(path)
        state = {
            "present": True,
            "valid": bool(detail.get("valid")),
            "verified": True,
            "status": detail.get("status"),
            "code": detail.get("code"),
            "message": detail.get("message"),
            "table_va": table_va,
            "table_size": table_size,
        }
    if fingerprint is not None:
        _SIGNATURE_CACHE.put(fingerprint, state)
    return state


_CATALOG_GUID_STR = "{f750e6c3-38ee-11d1-85e5-00c04fc295ee}"


def catalog_signed(path):
    """目录签名（catalog）查询：使用文档化 CryptCATAdmin* 接口。"""
    try:
        wt = ctypes.windll.wintrust
        k32 = ctypes.windll.kernel32
    except Exception:
        return False
    guid = Guid()
    try:
        ctypes.windll.ole32.CLSIDFromString(_CATALOG_GUID_STR, ctypes.byref(guid))
    except Exception:
        return False
    k32.CreateFileW.restype = ctypes.c_void_p
    k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.wintypes.DWORD,
                                ctypes.wintypes.DWORD, ctypes.c_void_p,
                                ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
                                ctypes.c_void_p]
    wt.CryptCATAdminAcquireContext.restype = ctypes.wintypes.BOOL
    wt.CryptCATAdminAcquireContext.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                                               ctypes.POINTER(Guid), ctypes.wintypes.DWORD]
    wt.CryptCATAdminCalcHashFromFileHandle.restype = ctypes.wintypes.BOOL
    wt.CryptCATAdminCalcHashFromFileHandle.argtypes = [ctypes.c_void_p,
                                                       ctypes.POINTER(ctypes.wintypes.DWORD),
                                                       ctypes.POINTER(ctypes.c_ubyte),
                                                       ctypes.wintypes.DWORD]
    wt.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
    wt.CryptCATAdminEnumCatalogFromHash.argtypes = [ctypes.c_void_p,
                                                    ctypes.POINTER(ctypes.c_ubyte),
                                                    ctypes.wintypes.DWORD,
                                                    ctypes.wintypes.DWORD,
                                                    ctypes.POINTER(ctypes.c_void_p)]
    wt.CryptCATAdminReleaseCatalogContext.restype = ctypes.wintypes.BOOL
    wt.CryptCATAdminReleaseCatalogContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                                      ctypes.wintypes.DWORD]
    wt.CryptCATAdminReleaseContext.restype = ctypes.wintypes.BOOL
    wt.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, ctypes.wintypes.DWORD]
    admin = ctypes.c_void_p()
    if not wt.CryptCATAdminAcquireContext(ctypes.byref(admin), ctypes.byref(guid), 0):
        return False
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    file_handle = k32.CreateFileW(str(path), GENERIC_READ, FILE_SHARE_READ,
                                  None, OPEN_EXISTING, 0, None)
    try:
        if not file_handle or file_handle == ctypes.c_void_p(-1).value:
            return False
        needed = ctypes.wintypes.DWORD(0)
        wt.CryptCATAdminCalcHashFromFileHandle(file_handle, ctypes.byref(needed), None, 0)
        if needed.value == 0:
            return False
        buffer = (ctypes.c_ubyte * needed.value)()
        if not wt.CryptCATAdminCalcHashFromFileHandle(file_handle, ctypes.byref(needed), buffer, 0):
            return False
        catalog = wt.CryptCATAdminEnumCatalogFromHash(
            admin, ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.wintypes.DWORD(needed.value), 0, None)
        if catalog:
            wt.CryptCATAdminReleaseCatalogContext(admin, catalog, 0)
            return True
        return False
    finally:
        try:
            k32.CloseHandle(file_handle)
        except Exception:
            pass
        try:
            wt.CryptCATAdminReleaseContext(admin, 0)
        except Exception:
            pass


_FILE_SIGNED_CACHE = {}


def file_signed(path):
    """独立签名查询入口：嵌入签名 + 目录签名双通道，供主动防御做前置校验。"""
    try:
        stat = os.stat(path)
    except Exception:
        return False
    key = (str(path).lower(), stat.st_size, int(stat.st_mtime))
    cached = _FILE_SIGNED_CACHE.get(key)
    if cached is not None:
        return cached
    valid = bool(verify_signature(path).get("valid"))
    if not valid:
        valid = catalog_signed(path)
    if len(_FILE_SIGNED_CACHE) > 2048:
        _FILE_SIGNED_CACHE.clear()
    _FILE_SIGNED_CACHE[key] = valid
    return valid


########################################层 2a 哈希病毒库########################################


def stream_hashes(path):
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    head = b""
    total = 0
    try:
        with open(path, "rb", buffering=0) as handle:
            while True:
                block = handle.read(CHUNK_SIZE)
                if not block:
                    break
                if len(head) < TRUNC_HASH_BYTES:
                    head += block[: TRUNC_HASH_BYTES - len(head)]
                sha256.update(block)
                md5.update(block)
                total += len(block)
    except Exception:
        return None
    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "trunc": hashlib.blake2b(head, digest_size=16).hexdigest(),
        "trunc_bytes": len(head),
        "size": total,
    }


def section_hash(pe):
    if pe is None:
        return ""
    digest = hashlib.sha256()
    count = 0
    try:
        sections = list(getattr(pe, "sections", []) or [])
    except Exception:
        return ""
    for section in sections[:SECTION_HASH_SECTIONS]:
        try:
            data = section.get_data()
        except Exception:
            continue
        if not data:
            continue
        digest.update(data[:SECTION_HASH_LIMIT])
        count += 1
    if not count:
        return ""
    return digest.hexdigest()


def partial_hashes(path, pe=None):
    streams = stream_hashes(path)
    if streams is None:
        return None
    own_pe = False
    if pe is None and pefile is not None:
        try:
            pe = pefile.PE(path, fast_load=True)
            own_pe = True
        except Exception:
            pe = None
    imphash = ""
    if pe is not None:
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        except Exception:
            pass
        try:
            imphash = str(pe.get_imphash() or "").lower()
        except Exception:
            imphash = ""
    sections = section_hash(pe) if pe is not None else ""
    if own_pe and pe is not None:
        try:
            pe.close()
        except Exception:
            pass
    return {
        "sha256": streams.get("sha256") or "",
        "md5": streams.get("md5") or "",
        "size": streams.get("size") or 0,
        "imphash": imphash,
        "section": sections,
        "trunc": streams.get("trunc") or "",
    }


def _detect_hash_type(token):
    text = str(token or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return "sha256"
    if re.fullmatch(r"[0-9a-f]{32}", text):
        return "md5"
    return ""


class HashDB:
    def __init__(self):
        self._sets = {name: set() for name in HASHDB_TYPES}
        self._enabled = list(HASHDB_TYPES)
        self._loaded = False
        self._stats = {"files": 0, "lines": 0, "invalid": 0, "elapsed": 0.0, "counts": {}}

    def enabled_types(self):
        return list(self._enabled)

    def set_enabled(self, types):
        wanted = [name for name in (types or []) if name in HASHDB_TYPES]
        self._enabled = wanted or list(HASHDB_TYPES)
        return self._enabled

    def loaded(self):
        return self._loaded

    def counts(self):
        return dict(self._stats.get("counts") or {})

    def stats(self):
        return dict(self._stats)

    def total(self):
        return sum(len(self._sets[name]) for name in HASHDB_TYPES)

    def add(self, hash_type, value, label=""):
        if hash_type not in self._sets:
            return False
        text = str(value or "").strip().lower()
        if not text:
            return False
        self._sets[hash_type].add(text)
        return True

    def contains(self, hash_type, value):
        if hash_type not in self._sets:
            return False
        return str(value or "").strip().lower() in self._sets[hash_type]

    def load(self, root=None, force=False):
        with _ENGINE_LOCK:
            if self._loaded and not force:
                return self._stats
            target = root or HASHDB_DIR
            for name in HASHDB_TYPES:
                self._sets[name] = set()
            start = time.time()
            files = 0
            lines = 0
            invalid = 0
            if os.path.isdir(target):
                for current, _dirs, names in os.walk(target):
                    for name in sorted(names):
                        if not name.lower().endswith(HASHDB_EXTENSIONS):
                            continue
                        files += 1
                        full = os.path.join(current, name)
                        try:
                            with open(full, "r", encoding="utf-8", errors="ignore") as handle:
                                for line in handle:
                                    line = line.strip()
                                    if not line or line.startswith("#"):
                                        continue
                                    lines += 1
                                    parts = [item.strip() for item in line.split("\t") if item.strip()]
                                    if not parts:
                                        parts = line.split()
                                    if not parts:
                                        continue
                                    if len(parts) == 1:
                                        detected = _detect_hash_type(parts[0])
                                        if detected and self.add(detected, parts[0]):
                                            continue
                                        invalid += 1
                                        continue
                                    hash_type = parts[0].lower()
                                    if hash_type in self._sets:
                                        if self.add(hash_type, parts[1]):
                                            continue
                                    detected = _detect_hash_type(parts[0])
                                    if detected and self.add(detected, parts[0]):
                                        continue
                                    invalid += 1
                        except Exception:
                            invalid += 1
            counts = {name: len(self._sets[name]) for name in HASHDB_TYPES}
            self._stats = {
                "root": target,
                "files": files,
                "lines": lines,
                "invalid": invalid,
                "elapsed": round(time.time() - start, 3),
                "counts": counts,
            }
            self._loaded = True
            engine_log("hashdb.load", "文件 {} 行 {} 有效 {} 无效 {} 用时 {}s".format(
                files, lines, counts, invalid, self._stats["elapsed"]))
            return self._stats

    def match_all(self, hashes):
        found = []
        if not hashes:
            return found
        for hash_type in ("sha256", "md5", "imphash", "section", "trunc"):
            if hash_type not in self._enabled:
                continue
            value = hashes.get(hash_type)
            if value and self.contains(hash_type, value):
                found.append({"type": hash_type, "value": value})
        return found

    def match(self, hashes):
        found = self.match_all(hashes)
        if not found:
            return None
        exact = [item for item in found if item["type"] in ("sha256", "md5")]
        if exact:
            return exact[0]
        required = FUZZY_VOTE_REQUIRED
        if len(found) >= required:
            return {"type": "投票", "value": "、".join(item["type"] for item in found), "votes": found}
        return None


HASHDB = HashDB()


def hashdb_build(paths, target=None, label=None, progress=None):
    target = target or HASHDB_FILE
    directory = os.path.dirname(target)
    if directory:
        os.makedirs(directory, exist_ok=True)
    accepted = 0
    failed = 0
    written = 0
    with open(target, "w", encoding="utf-8") as handle:
        handle.write("# type\thash\tlabel\n")
        for path in paths:
            try:
                hashes = partial_hashes(path)
            except Exception:
                hashes = None
            if not hashes:
                failed += 1
                continue
            accepted += 1
            name = label if label else os.path.basename(path)
            for hash_type in HASHDB_TYPES:
                value = hashes.get(hash_type)
                if value:
                    handle.write("{}\t{}\t{}\n".format(hash_type, value, name))
                    written += 1
            if progress and accepted % 200 == 0:
                progress(accepted, failed, len(paths))
    return {"ok": True, "target": target, "files": accepted, "failed": failed, "lines": written}


########################################层 2b 宏规则（SevenEngine CustomRuleScanner 直抄）########################################


class MacroRuleScanner:
    """L2b 宏规则层：直接复用 SevenEngine 的 CustomRuleScanner（.srule DSL）。"""

    def __init__(self):
        self._scanner = None
        self._rules = 0

    def ready(self):
        return self._scanner is not None and self._scanner.available

    def load(self, force=False):
        with _ENGINE_LOCK:
            if self._scanner is not None and not force:
                return self.info()
            try:
                self._scanner = CustomRuleScanner(HASHDB_DIR, cap=16 * 1024 * 1024)
            except Exception as exc:
                self._scanner = None
                engine_log("macro.load", "加载失败：{}".format(exc), "ERROR")
                return self.info()
            self._rules = len(getattr(self._scanner, "rules", []) or [])
            engine_log("macro.load", "已加载 {} 条宏规则".format(self._rules))
            return self.info()

    def scan(self, path):
        if not self.ready():
            return None
        try:
            name, conf, _reason = self._scanner.scan(path)
        except Exception:
            return None
        return name if name else None

    def info(self):
        return {
            "ready": self.ready(),
            "rules": self._rules,
            "available": self._scanner is not None and getattr(self._scanner, "available", False),
        }


MACRO = MacroRuleScanner()


########################################层 3 YARA 规则########################################


def yara_rule_files(include_heavy=False, sources=None):
    if sources is None:
        sources = list(YARA_CORE_SOURCES)
        if include_heavy:
            sources.extend(YARA_HEAVY_SOURCES)
    collected = []
    for name in sources:
        root = name if os.path.isabs(name) else os.path.join(YARA_DIR, name)
        if os.path.isfile(root) and root.lower().endswith(YARA_EXTENSIONS):
            collected.append(root)
            continue
        if not os.path.isdir(root):
            continue
        for current, _dirs, files in os.walk(root):
            for item in sorted(files):
                if item.lower().endswith(YARA_EXTENSIONS):
                    collected.append(os.path.join(current, item))
    collected.sort()
    return collected


def yara_fingerprint(files):
    digest = hashlib.sha256()
    for path in files:
        try:
            info = os.stat(path)
            digest.update("{}\t{}\t{}\n".format(path, info.st_size, int(info.st_mtime)).encode("utf-8", "ignore"))
        except Exception:
            continue
    return digest.hexdigest()


class YaraEngine:
    def __init__(self):
        self._rules = None
        self._files = []
        self._fingerprint = ""
        self._include_heavy = False
        self._last_error = ""
        self._last_elapsed = 0.0
        self._cache_used = False
        self._source = ""

    def ready(self):
        return self._rules is not None

    def info(self):
        counts = {}
        for path in self._files:
            head = os.path.relpath(path, YARA_DIR).split(os.sep)
            key = head[0] if head else "unknown"
            counts[key] = counts.get(key, 0) + 1
        return {
            "ready": self._rules is not None,
            "rules_files": len(self._files),
            "rules_by_source": counts,
            "include_heavy": self._include_heavy,
            "cache_used": self._cache_used,
            "compile_source": self._source,
            "elapsed": round(self._last_elapsed, 3),
            "error": self._last_error,
            "available": yara is not None,
        }

    def load(self, include_heavy=False, force=False):
        with _ENGINE_LOCK:
            if self._rules is not None and not force and self._include_heavy == include_heavy:
                return self.info()
            if yara is None:
                self._last_error = "未安装 yara-python"
                self._rules = None
                return self.info()
            files = yara_rule_files(include_heavy)
            self._files = files
            self._include_heavy = include_heavy
            self._last_error = ""
            if not files:
                self._rules = None
                self._last_error = "未找到任何 YARA 规则文件"
                engine_log("yara.load", self._last_error, "WARN")
                return self.info()
            fingerprint = yara_fingerprint(files)
            self._fingerprint = fingerprint
            start = time.time()
            self._cache_used = False
            self._source = "compile"
            if not force:
                cached = self._load_cache(fingerprint)
                if cached is not None:
                    self._rules = cached
                    self._cache_used = True
                    self._source = "cache"
                    self._last_elapsed = time.time() - start
                    self._last_error = ""
                    engine_log("yara.load", "命中编译缓存 规则文件 {} 用时 {}s".format(len(files), round(self._last_elapsed, 3)))
                    return self.info()
            try:
                self._rules = yara.compile(filepaths={str(index): path for index, path in enumerate(files)})
                self._last_error = ""
            except Exception as exc:
                self._rules = None
                self._last_error = "规则编译失败：{}".format(exc)
                engine_log("yara.load", self._last_error, "ERROR")
                return self.info()
            self._last_elapsed = time.time() - start
            self._save_cache(fingerprint)
            engine_log("yara.load", "编译完成 规则文件 {} 用时 {}s".format(len(files), round(self._last_elapsed, 3)))
            return self.info()

    def _cache_meta_file(self):
        return YARA_CACHE_FILE + ".json"

    def _load_cache(self, fingerprint):
        try:
            if not os.path.isfile(YARA_CACHE_FILE):
                return None
            with open(self._cache_meta_file(), "r", encoding="utf-8") as handle:
                meta = json.load(handle)
            if meta.get("fingerprint") != fingerprint:
                return None
            return yara.load(YARA_CACHE_FILE)
        except Exception:
            return None

    def _save_cache(self, fingerprint):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            self._rules.save(YARA_CACHE_FILE)
            with open(self._cache_meta_file(), "w", encoding="utf-8") as handle:
                json.dump({"fingerprint": fingerprint, "files": len(self._files), "saved": time.strftime("%Y-%m-%d %H:%M:%S")}, handle)
        except Exception as exc:
            engine_log("yara.cache", "编译产物落盘失败：{}".format(exc), "WARN")

    def match(self, path):
        if self._rules is None:
            return []
        try:
            matches = self._rules.match(path, timeout=YARA_MATCH_TIMEOUT)
        except Exception as exc:
            engine_log("yara.match", "{} -> {}".format(path, exc), "WARN")
            return []
        result = []
        for item in matches:
            result.append({
                "rule": str(getattr(item, "rule", "")),
                "namespace": str(getattr(item, "namespace", "")),
                "tags": [str(tag) for tag in (getattr(item, "tags", []) or [])],
            })
        return result


YARA_ENGINE = YaraEngine()


########################################层 4 LightGBM 树模型（SevenEngine LightGBMScanner 直抄）########################################


class AiEngine:
    """L4：永远在线。直接复用 SevenEngine LightGBMScanner（PDA1 + LightGBM booster + 512 维特征）。"""

    def __init__(self):
        self._scanner = None
        self._load_elapsed = 0.0
        self._last_error = ""

    def ready(self):
        return self._scanner is not None and self._scanner.available

    def threshold(self):
        # 运行阈值由引擎统一控制，避免旧 .pda 头部阈值让产品行为漂移。
        return MALICIOUS_THRESHOLD

    def feature_size(self):
        if self._scanner is not None:
            try:
                return int(self._scanner.feature_size)
            except Exception:
                pass
        return 512

    def info(self):
        return {
            "ready": self.ready(),
            "model_file": PDA_PATH,
            "model_exists": os.path.isfile(PDA_PATH),
            "feature_size": self.feature_size(),
            "threshold": self.threshold(),
            "available": self._scanner is not None and getattr(self._scanner, "available", False),
            "load_elapsed": round(self._load_elapsed, 3),
            "error": self._last_error,
        }

    def load(self, force=False):
        with _ENGINE_LOCK:
            if self._scanner is not None and not force:
                return self.info()
            self._scanner = None
            self._last_error = ""
            if not os.path.isfile(PDA_PATH):
                self._last_error = "模型文件未找到：{}".format(os.path.basename(PDA_PATH))
                return self.info()
            start = time.time()
            try:
                self._scanner = LightGBMScanner(PDA_PATH)
            except Exception as exc:
                self._scanner = None
                self._last_error = "模型载入失败：{}".format(exc)
                engine_log("ai.load", self._last_error, "ERROR")
                return self.info()
            self._load_elapsed = time.time() - start
            if not self.ready():
                _detail = getattr(self._scanner, "last_error", "") or "未知原因"
                self._last_error = "LightGBM 不可用（lightgbm 未安装或 .pda 解析失败）：{}".format(_detail)
                engine_log("ai.load", self._last_error, "ERROR")
            else:
                engine_log("ai.load", "模型载入完成 特征 {} 阈值 {} 用时 {}s".format(
                    self.feature_size(), self.threshold(), round(self._load_elapsed, 3)))
            return self.info()

    def score(self, path):
        """返回 [0,1] 恶意概率；不可用或非 PE 返回 None。"""
        if not self.ready():
            return None
        try:
            s = self._scanner.score(path)
        except Exception:
            return None
        if s is None or s < 0:
            return None
        return float(s)


AI_ENGINE = AiEngine()


########################################层 5 云查杀（自研 CFTQ 反病毒云）########################################

CFTQ_ENDPOINT = "https://starlight-v3.ternaryop.top/scan"
CFTQ_API_KEY = "d96c15eeae628df49e44c13ba39ad2608c7138813c60cd6287c0bfea9270be79"
_CFTQ_TIMEOUT = 8.0
_CFTQ_MAX_UPLOAD = 200 * 1024 * 1024


class CftqCloud:
    """L5：可选云查杀二次确认层。默认关闭；离线/超时/网络失败 → 跳过，不阻断本地结论；永不降级本地恶意结论。"""

    def __init__(self):
        self.enabled = False
        self.api_key = CFTQ_API_KEY
        self.available = True

    def configure(self, enabled=None, api_key=None, timeout=None):
        if enabled is not None:
            self.enabled = bool(enabled)
        if api_key:
            self.api_key = api_key
        if timeout:
            global _CFTQ_TIMEOUT
            _CFTQ_TIMEOUT = float(timeout)

    def enabled_state(self):
        return self.enabled

    def scan(self, path):
        """返回 dict {code, type, confidence} 或 None（关闭/失败/超时）。"""
        if not self.enabled:
            return None
        if not os.path.isfile(path):
            return None
        try:
            size = os.path.getsize(path)
        except Exception:
            return None
        if size <= 0 or size > _CFTQ_MAX_UPLOAD:
            return None
        try:
            return self._post(path)
        except Exception as exc:
            engine_log("cftq.scan", "云查杀跳过：{}".format(exc), "WARN")
            return None

    def _post(self, path):
        boundary = "----DragonCFTQBoundary7Q"
        body = bytearray()
        with open(path, "rb") as f:
            data = f.read()
        body += ("--%s\r\n" % boundary).encode("utf-8")
        body += b'Content-Disposition: form-data; name="file"; filename="sample"\r\n'
        body += b"Content-Type: application/octet-stream\r\n\r\n"
        body += data
        body += b"\r\n"
        body += ("--%s--\r\n" % boundary).encode("utf-8")
        req = urllib.request.Request(CFTQ_ENDPOINT, data=bytes(body), method="POST")
        req.add_header("Content-Type", "multipart/form-data; boundary=%s" % boundary)
        req.add_header("X-API-Key", self.api_key)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=_CFTQ_TIMEOUT, context=ctx) as resp:
            payload = resp.read().decode("utf-8", "ignore")
        obj = json.loads(payload)
        code = obj.get("code")
        res = obj.get("result") or {}
        return {"code": code, "type": res.get("type"), "confidence": res.get("confidence")}


CFTQ = CftqCloud()


########################################引擎运行配置（供 UI/主动防御注入）########################################

ENGINE_CONFIG = {
    "enhanced_mode": False,   # 增强模式：下调 L4 判定阈值（更激进）
    "l4_to_l5": False,       # L4 判恶意后是否继续进 L5 云查杀
    "cloud_enabled": False,   # 云查杀总开关（默认关）
    "cloud_api_key": CFTQ_API_KEY,
    "cloud_timeout": _CFTQ_TIMEOUT,
}


def set_engine_config(enhanced_mode=None, l4_to_l5=None, cloud_enabled=None, cloud_api_key=None, cloud_timeout=None):
    if enhanced_mode is not None:
        ENGINE_CONFIG["enhanced_mode"] = bool(enhanced_mode)
    if l4_to_l5 is not None:
        ENGINE_CONFIG["l4_to_l5"] = bool(l4_to_l5)
    if cloud_enabled is not None:
        ENGINE_CONFIG["cloud_enabled"] = bool(cloud_enabled)
        # 云引擎开关就是 L4 → L5 复核开关，避免 UI 打开后只是保存状态却不执行。
        ENGINE_CONFIG["l4_to_l5"] = bool(cloud_enabled)
    if cloud_api_key:
        ENGINE_CONFIG["cloud_api_key"] = cloud_api_key
    if cloud_timeout:
        ENGINE_CONFIG["cloud_timeout"] = float(cloud_timeout)
    CFTQ.configure(
        enabled=ENGINE_CONFIG["cloud_enabled"],
        api_key=ENGINE_CONFIG["cloud_api_key"],
        timeout=ENGINE_CONFIG["cloud_timeout"],
    )
    return dict(ENGINE_CONFIG)


########################################引擎状态########################################


def is_pe_file(path, head=None):
    if head is None:
        try:
            with open(path, "rb") as handle:
                head = handle.read(2)
        except Exception:
            return False
    return head[:2] == b"MZ"


def model_ready():
    return AI_ENGINE.ready()


def engine_status():
    macro_info = MACRO.info()
    _layers = [
            {"id": LAYER_SIGNATURE, "title": LAYER_TITLES[1], "ready": True},
            {"id": LAYER_HASHDB, "title": LAYER_TITLES[2],
             "ready": HASHDB.loaded() and HASHDB.total() > 0 and macro_info.get("ready"),
             "counts": HASHDB.counts(), "macro_rules": macro_info.get("rules")},
            {"id": LAYER_YARA, "title": LAYER_TITLES[3], "ready": YARA_ENGINE.ready()},
            {"id": LAYER_AI, "title": LAYER_TITLES[4], "ready": AI_ENGINE.ready()},
        ]
    return {
        "ok": True,
        "engine_version": ENGINE_VERSION,
        "ready": all(L["ready"] for L in _layers),
        "layers": _layers,

        "hashdb": HASHDB.stats(),
        "hashdb_enabled": HASHDB.enabled_types(),
        "macro": macro_info,
        "yara": YARA_ENGINE.info(),
        "ai": AI_ENGINE.info(),
        "cloud": {
            "enabled": CFTQ.enabled,
            "available": CFTQ.available,
            "endpoint": CFTQ_ENDPOINT,
        },
        "threshold": AI_ENGINE.threshold(),
        "enhanced_mode": ENGINE_CONFIG["enhanced_mode"],
        "l4_to_l5": ENGINE_CONFIG["l4_to_l5"],
        "signature_cache": _SIGNATURE_CACHE.stats(),
    }


def engine_prepare(load_hashdb=True, load_yara=True, load_ai=True, load_macro=True, include_heavy=False):
    if load_hashdb:
        HASHDB.load()
    if load_macro:
        MACRO.load()
    if load_yara:
        YARA_ENGINE.load(include_heavy)
    if load_ai:
        AI_ENGINE.load()
    # L5 云查杀按配置就绪（不阻塞）
    CFTQ.configure(enabled=ENGINE_CONFIG["cloud_enabled"],
                   api_key=ENGINE_CONFIG["cloud_api_key"],
                   timeout=ENGINE_CONFIG["cloud_timeout"])
    return engine_status()


########################################单文件扫描########################################


def scan_file(path, options=None):
    options = options or {}
    use_signature = options.get("use_signature", True)
    use_hashdb = options.get("use_hashdb", True)
    use_macro = options.get("use_macro", True)
    use_yara = options.get("use_yara", True)
    use_ai = options.get("use_ai", True)
    enhanced_mode = options.get("enhanced_mode", ENGINE_CONFIG["enhanced_mode"])
    l4_to_l5 = options.get("l4_to_l5", ENGINE_CONFIG["l4_to_l5"])
    cloud_enabled = options.get("cloud_enabled", ENGINE_CONFIG["cloud_enabled"])

    start = time.time()
    result = {
        "ok": False,
        "path": path,
        "name": os.path.basename(path),
        "size": 0,
        "verdict": VERDICT_ERROR,
        "layer": 0,
        "layer_title": "",
        "reason": "",
        "score": None,
        "hashes": None,
        "detail": {},
        "elapsed": 0.0,
        "tier": None,
    }
    try:
        result["size"] = os.path.getsize(path)
    except Exception as exc:
        result["reason"] = "无法读取文件：{}".format(exc)
        result["elapsed"] = time.time() - start
        return result
    if result["size"] <= 0:
        result["verdict"] = VERDICT_SKIPPED
        result["reason"] = "空文件，跳过扫描"
        result["elapsed"] = time.time() - start
        return result

    pe = None
    if pefile is not None:
        try:
            pe = pefile.PE(path, fast_load=True)
        except Exception:
            pe = None
    is_pe = is_pe_file(path)

    try:
        # L1 数字签名
        if use_signature and is_pe:
            state = signature_state(path, pe)
            result["detail"]["signature"] = state
            if state.get("valid"):
                result["ok"] = True
                result["verdict"] = VERDICT_SAFE
                result["layer"] = LAYER_SIGNATURE
                result["layer_title"] = LAYER_TITLES[LAYER_SIGNATURE]
                result["reason"] = "数字签名有效（{}）".format(state.get("message") or "")
                result["elapsed"] = time.time() - start
                return result

        # L2a 哈希病毒库
        if use_hashdb:
            hashes = partial_hashes(path, pe)
            result["hashes"] = hashes
            hit = HASHDB.match(hashes)
            if hit is not None:
                result["ok"] = True
                result["verdict"] = VERDICT_MALICIOUS
                result["layer"] = LAYER_HASHDB
                result["layer_title"] = LAYER_TITLES[LAYER_HASHDB]
                result["reason"] = "命中哈希库（{}：{}）".format(hit["type"], hit["value"])
                result["detail"]["hashdb"] = hit
                result["elapsed"] = time.time() - start
                return result

        # L2b 宏规则（非 PE 威胁主防线）
        if use_macro and MACRO.ready():
            mhit = MACRO.scan(path)
            if mhit is not None:
                result["ok"] = True
                result["verdict"] = VERDICT_MALICIOUS
                result["layer"] = LAYER_HASHDB
                result["layer_title"] = LAYER_TITLES[LAYER_HASHDB]
                result["reason"] = "命中宏规则（{}）".format(mhit)
                result["detail"]["macro"] = mhit
                result["elapsed"] = time.time() - start
                return result

        # L3 YARA
        if use_yara and YARA_ENGINE.ready():
            matches = YARA_ENGINE.match(path)
            if matches:
                names = [item["rule"] for item in matches]
                result["ok"] = True
                result["verdict"] = VERDICT_MALICIOUS
                result["layer"] = LAYER_YARA
                result["layer_title"] = LAYER_TITLES[LAYER_YARA]
                result["reason"] = "命中 YARA 规则：{}".format("、".join(names[:3]))
                result["detail"]["yara"] = matches
                result["elapsed"] = time.time() - start
                return result

        # L4 LightGBM（仅 PE；永远在线）
        if use_ai and is_pe:
            score = AI_ENGINE.score(path)
            if score is not None:
                result["detail"]["ai"] = {"score": score}
                result["score"] = score
                result["tier"] = LAYER_AI
                eff = ENHANCED_THRESHOLD if enhanced_mode else MALICIOUS_THRESHOLD
                if score > eff:
                    # 恶意：可选继续进 L5 云查杀二次确认（不降级）
                    if cloud_enabled:
                        cres = CFTQ.scan(path)
                        result["detail"]["cloud"] = cres
                    result["ok"] = True
                    result["verdict"] = VERDICT_MALICIOUS
                    result["layer"] = LAYER_AI
                    result["layer_title"] = LAYER_TITLES[LAYER_AI]
                    result["reason"] = "LightGBM 判定为恶意（置信度 {:.2%}）".format(score)
                    result["elapsed"] = time.time() - start
                    return result
                else:
                    # LightGBM-White：高置信干净，短路为安全
                    result["ok"] = True
                    result["verdict"] = VERDICT_SAFE
                    result["layer"] = LAYER_AI
                    result["layer_title"] = LAYER_TITLES[LAYER_AI]
                    result["reason"] = "LightGBM 判定为安全（恶意置信度 {:.2%}）".format(score)
                    result["elapsed"] = time.time() - start
                    return result
            # L4 不可用：不短路，落到最终结论

        result["ok"] = True
        result["verdict"] = VERDICT_SAFE
        result["layer"] = 0
        result["layer_title"] = ""
        result["reason"] = "未发现威胁" if AI_ENGINE.ready() else "部分检测层不可用，未发现命中"
        result["elapsed"] = time.time() - start
        return result
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass


def score_file(path, forced_tier=None):
    if not AI_ENGINE.ready():
        return {"ok": False, "error": "LightGBM 模型未就绪"}
    score = AI_ENGINE.score(path)
    if score is None:
        return {"ok": False, "error": "非 PE 文件或模型不可用"}
    return {
        "ok": True,
        "path": path,
        "score": score,
        "threshold": AI_ENGINE.threshold(),
        "malicious": score > AI_ENGINE.threshold(),
        "tier": LAYER_AI,
        "enhanced_mode": ENGINE_CONFIG["enhanced_mode"],
    }


########################################目录扫描########################################


def iter_directory(root, max_depth=None, extensions=None, should_stop=None):
    root = os.path.abspath(root)
    base_depth = root.rstrip(os.sep).count(os.sep)
    for current, dirs, files in os.walk(root):
        if should_stop and should_stop():
            return
        if max_depth is not None:
            depth = current.rstrip(os.sep).count(os.sep) - base_depth
            if depth >= max_depth:
                dirs[:] = []
        dirs.sort()
        for name in sorted(files):
            if should_stop and should_stop():
                return
            if extensions:
                if os.path.splitext(name)[1].lower() not in extensions:
                    continue
            yield os.path.join(current, name)


def iter_scan_directory(root, options=None, max_depth=None, extensions=None, should_stop=None):
    for path in iter_directory(root, max_depth, extensions, should_stop):
        if should_stop and should_stop():
            return
        if not os.path.isfile(path):
            continue
        yield scan_file(path, options)


def scan_directory(root, options=None, max_depth=None, extensions=None, progress=None, should_stop=None):
    summary = {"root": root, "total": 0, "malicious": 0, "safe": 0, "skipped": 0, "error": 0, "elapsed": 0.0, "detections": []}
    start = time.time()
    for item in iter_scan_directory(root, options, max_depth, extensions, should_stop):
        summary["total"] += 1
        verdict = item.get("verdict")
        if verdict == VERDICT_MALICIOUS:
            summary["malicious"] += 1
            summary["detections"].append({
                "path": item.get("path"),
                "name": item.get("name"),
                "layer": item.get("layer"),
                "reason": item.get("reason"),
                "score": item.get("score"),
            })
        elif verdict == VERDICT_SAFE:
            summary["safe"] += 1
        elif verdict == VERDICT_SKIPPED:
            summary["skipped"] += 1
        else:
            summary["error"] += 1
        if progress:
            progress(item, summary)
    summary["elapsed"] = round(time.time() - start, 3)
    return summary


########################################对外接口########################################


def dragon_engine_status():
    return engine_status()


def dragon_engine_init(reload=False, include_heavy=False):
    if reload:
        HASHDB.load(force=True)
        MACRO.load(force=True)
        YARA_ENGINE.load(include_heavy, force=False)
        AI_ENGINE.load(force=True)
    else:
        engine_prepare(include_heavy=include_heavy)
    return engine_status()


def dragon_engine_reload_hashdb():
    HASHDB.load(force=True)
    return {"ok": True, "hashdb": HASHDB.stats()}


def dragon_engine_reload_yara(include_heavy=False):
    YARA_ENGINE.load(include_heavy, force=True)
    return {"ok": True, "yara": YARA_ENGINE.info()}


def dragon_engine_reload_model():
    AI_ENGINE.load(force=True)
    return {"ok": True, "ai": AI_ENGINE.info()}


def dragon_engine_reload_macro():
    MACRO.load(force=True)
    return {"ok": True, "macro": MACRO.info()}


def dragon_engine_scan_file(path):
    if not path or not os.path.isfile(path):
        return {"ok": False, "error": "文件不存在：{}".format(path)}
    return scan_file(path)


def dragon_engine_score_file(path):
    if not path or not os.path.isfile(path):
        return {"ok": False, "error": "文件不存在：{}".format(path)}
    return score_file(path)


def dragon_engine_hashdb_match(path):
    hashes = partial_hashes(path)
    if not hashes:
        return {"ok": False, "error": "无法计算文件哈希"}
    return {"ok": True, "hashes": hashes, "hit": HASHDB.match(hashes)}


def dragon_engine_yara_match(path):
    matches = YARA_ENGINE.match(path)
    return {"ok": True, "items": matches, "count": len(matches)}


def dragon_engine_signature(path):
    pe = None
    if pefile is not None:
        try:
            pe = pefile.PE(path, fast_load=True)
        except Exception:
            pe = None
    try:
        return {"ok": True, "signature": signature_state(path, pe)}
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass


if __name__ == "__main__":
    ensure_dirs()
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    if not target:
        print(json.dumps(engine_status(), ensure_ascii=False, indent=2))
    elif target == "init":
        print(json.dumps(engine_prepare(), ensure_ascii=False, indent=2))
    elif target == "hashdb":
        roots = sys.argv[2:] or []
        paths = []
        for root in roots:
            if os.path.isdir(root):
                paths.extend(iter_directory(root))
            elif os.path.isfile(root):
                paths.append(root)
        if not paths:
            print(json.dumps({"error": "请提供至少一个目录或文件"}, ensure_ascii=False))
        else:
            print(json.dumps(hashdb_build(paths, progress=lambda a, f, t: sys.stderr.write("哈希库构建 {}/{} 失败 {}\n".format(a + f, t, f))), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(scan_file(target), ensure_ascii=False, indent=2))
