# -*- coding: utf-8 -*-
# 买断 SevenEngine 自定义规则引擎（CustomRuleScanner / _CustomRule）直抄，仅改 import/常量。
import os
import re

_re = re.compile(r'rule\s+([A-Za-z0-9_.\-]+)\s*{')

def _parse_hex_pattern(tok):
    """Parse a hex token (with optional spaces / ':' / wildcards) -> (bytes, mask)."""
    t = tok.strip().lower().replace(':', '').replace(' ', '')
    if not t or len(t) % 2 != 0:
        return None
    out = bytearray()
    mask = bytearray()
    for i in range(0, len(t), 2):
        pair = t[i:i + 2]
        if pair in ('??', '**', '*'):
            out.append(0)
            mask.append(0)
        else:
            try:
                b = int(pair, 16)
            except ValueError:
                return None
            out.append(b)
            mask.append(1)
    return bytes(out), bytes(mask)

def _match_at(data, pattern, mask, i):
    for j in range(len(pattern)):
        if mask[j] and data[i + j] != pattern[j]:
            return False
    return True

def _hex_search(data, pattern, mask, at=None):
    """Return first offset where pattern matches (mask: 1=exact, 0=wildcard)."""
    n = len(pattern)
    dlen = len(data)
    if at is not None:
        if at < 0:
            at = dlen + at
        if at < 0 or at + n > dlen:
            return -1
        return at if _match_at(data, pattern, mask, at) else -1
    if n > dlen:
        return -1
    anchor = mask.find(1)
    if anchor < 0:
        anchor = 0
    aval = pattern[anchor]
    last = dlen - n
    i = 0
    while i <= last:
        if data[i + anchor] != aval:
            i += 1
            continue
        if _match_at(data, pattern, mask, i):
            return i
        i += 1
    return -1

class _CustomRule:
    __slots__ = ('name', 'rtype', 'severity', 'hexes', 'strs', 'wides', 'magic', 'at')
    def __init__(self, name, rtype, severity, hexes, strs, wides, magic, at):
        self.name = name
        self.rtype = rtype
        self.severity = severity
        self.hexes = hexes
        self.strs = strs
        self.wides = wides
        self.magic = magic
        self.at = at
    def match(self, data):
        if self.magic and data[:len(self.magic)] != self.magic:
            return False
        for k, (pattern, mask) in enumerate(self.hexes):
            off = self.at if k == 0 else None
            if _hex_search(data, pattern, mask, off) < 0:
                return False
        if self.strs or self.wides:
            found = False
            for s in self.strs:
                if s in data:
                    found = True
                    break
            if not found:
                for w in self.wides:
                    if w in data:
                        found = True
                        break
            if not found:
                return False
        return True

class CustomRuleScanner:
    def __init__(self, rules_dir, cap=None):
        self.rules_dir = rules_dir
        self.cap = cap if cap is not None else 16 * 1024 * 1024
        self.rules = []
        self.available = False
        self.load_rules(rules_dir)
    def load_rules(self, rules_dir):
        self.rules = []
        if not os.path.isdir(rules_dir):
            return
        for fn in sorted(os.listdir(rules_dir)):
            if not fn.endswith('.srule'):
                continue
            full = os.path.join(rules_dir, fn)
            try:
                with open(full, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
            except Exception:
                continue
            self.rules.extend(self._parse_srule(text, fn))
        self.available = len(self.rules) > 0
        if self.available:
            print(f"[CUSTOM] 已加载 {len(self.rules)} 条自定义规则 (来自 {rules_dir})")
    def _parse_srule(self, text, srcname):
        rules = []
        idx = 0
        while True:
            m = _re.search(text[idx:])
            if not m:
                break
            name = m.group(1)
            start = idx + m.end()
            end = text.find('}', start)
            if end < 0:
                break
            body = text[start:end]
            idx = end + 1
            rtype = 'virus'
            severity = 90
            hexes = []
            strs = []
            wides = []
            magic = None
            at = None
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip().lower()
                v = v.strip()
                if k == 'type':
                    rtype = v
                elif k == 'severity':
                    try:
                        severity = int(float(v))
                    except ValueError:
                        severity = 90
                elif k == 'hex':
                    p = _parse_hex_pattern(v)
                    if p:
                        hexes.append(p)
                    else:
                        print(f"[CUSTOM] 警告: 规则 {name} ({srcname}) 的 hex 值 '{v}' 不是合法十六进制，已忽略")
                elif k == 'magic':
                    p = _parse_hex_pattern(v)
                    if p:
                        magic = p[0]
                    else:
                        print(f"[CUSTOM] 警告: 规则 {name} ({srcname}) 的 magic 值 '{v}' 不是合法十六进制，已忽略(规则退化为无头约束!)")
                elif k == 'str':
                    strs.append(v.encode('latin-1', 'ignore'))
                elif k == 'wide':
                    wides.append(v.encode('utf-16-le'))
                elif k == 'at':
                    try:
                        at = int(v)
                    except ValueError:
                        at = None
            if hexes or strs or wides or magic:
                rules.append(_CustomRule(name, rtype, severity, hexes, strs, wides, magic, at))
            else:
                print(f"[CUSTOM] 规则 {name} ({srcname}) 无有效匹配条件，跳过")
        return rules
    def scan(self, filepath):
        if not self.rules:
            return None, 0, ""
        try:
            sz = os.path.getsize(filepath)
        except Exception:
            return None, 0, ""
        if sz == 0:
            return None, 0, ""
        try:
            with open(filepath, 'rb') as f:
                if sz <= self.cap:
                    data = f.read()
                else:
                    head = f.read(self.cap)
                    f.seek(max(0, sz - 524288))
                    tail = f.read()
                    data = head + tail
        except Exception:
            return None, 0, ""
        for r in self.rules:
            if r.match(data):
                return r.name, r.severity, r.name
        return None, 0, ""
