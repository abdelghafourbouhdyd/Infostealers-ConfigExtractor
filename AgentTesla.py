import argparse
import csv
import datetime
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from urllib.parse import quote


class MetadataError(Exception):
    pass


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


# ECMA-335 II.24.2.6 coded indexes: (tag bits, tables)
CODED = {
    "TypeDefOrRef": (2, (0x02, 0x01, 0x1B)),
    "HasConstant": (2, (0x04, 0x08, 0x17)),
    "HasCustomAttribute": (5, (0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11,
                               0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B)),
    "HasFieldMarshal": (1, (0x04, 0x08)),
    "HasDeclSecurity": (2, (0x02, 0x06, 0x20)),
    "MemberRefParent": (3, (0x02, 0x01, 0x1A, 0x06, 0x1B)),
    "HasSemantics": (1, (0x14, 0x17)),
    "MethodDefOrRef": (1, (0x06, 0x0A)),
    "MemberForwarded": (1, (0x04, 0x06)),
    "Implementation": (2, (0x26, 0x23, 0x27)),
    "CustomAttributeType": (3, (0x06, 0x0A)),
    "ResolutionScope": (2, (0x00, 0x1A, 0x23, 0x01)),
    "TypeOrMethodDef": (1, (0x02, 0x06)),
}

# Column layout per table. 2/4 = fixed width, S/G/B = heap index, T(n) = table index, str = coded index.


def T(n):
    return ("T", n)


SCHEMA = {
    0x00: (2, "S", "G", "G", "G"),
    0x01: ("ResolutionScope", "S", "S"),
    0x02: (4, "S", "S", "TypeDefOrRef", T(0x04), T(0x06)),
    0x03: (T(0x04),),
    0x04: (2, "S", "B"),
    0x05: (T(0x06),),
    0x06: (4, 2, 2, "S", "B", T(0x08)),
    0x07: (T(0x08),),
    0x08: (2, 2, "S"),
    0x09: (T(0x02), "TypeDefOrRef"),
    0x0A: ("MemberRefParent", "S", "B"),
    0x0B: (2, "HasConstant", "B"),
    0x0C: ("HasCustomAttribute", "CustomAttributeType", "B"),
    0x0D: ("HasFieldMarshal", "B"),
    0x0E: (2, "HasDeclSecurity", "B"),
    0x0F: (2, 4, T(0x02)),
    0x10: (4, T(0x04)),
    0x11: ("B",),
    0x12: (T(0x02), T(0x14)),
    0x13: (T(0x14),),
    0x14: (2, "S", "TypeDefOrRef"),
    0x15: (T(0x02), T(0x17)),
    0x16: (T(0x17),),
    0x17: (2, "S", "B"),
    0x18: (2, T(0x06), "HasSemantics"),
    0x19: (T(0x02), "MethodDefOrRef", "MethodDefOrRef"),
    0x1A: ("S",),
    0x1B: ("B",),
    0x1C: (2, "MemberForwarded", "S", T(0x1A)),
    0x1D: (4, T(0x04)),
    0x1E: (4, 4),
    0x1F: (4,),
    0x20: (4, 2, 2, 2, 2, 4, "B", "S", "S"),
    0x21: (4,),
    0x22: (4, 4, 4),
    0x23: (2, 2, 2, 2, 4, "B", "S", "S", "B"),
    0x24: (4, T(0x23)),
    0x25: (4, 4, 4, T(0x23)),
    0x26: (4, "S", "B"),
    0x27: (4, 4, "S", "S", "Implementation"),
    0x28: (4, 4, "S", "Implementation"),
    0x29: (T(0x02), T(0x02)),
    0x2A: (2, 2, "TypeOrMethodDef", "S"),
    0x2B: ("MethodDefOrRef", "B"),
    0x2C: (T(0x2A), "TypeDefOrRef"),
}


class DotNet:
    """Just enough of a .NET metadata reader: TypeDef, Field, MethodDef, #Strings, #US, method bodies."""

    def __init__(self, data):
        self.data = data
        if data[:2] != b"MZ":
            raise MetadataError("not a PE")
        pe = _u32(data, 0x3C)
        if data[pe:pe + 4] != b"PE\0\0":
            raise MetadataError("bad PE header")
        nsec = _u16(data, pe + 6)
        opt = pe + 24
        magic = _u16(data, opt)
        ddir = opt + (96 if magic == 0x10B else 112)
        clr_rva = _u32(data, ddir + 14 * 8) if ddir + 14 * 8 + 4 <= len(data) else 0
        sec = opt + _u16(data, pe + 20)
        self.sections = []
        for i in range(nsec):
            s = sec + i * 40
            vsize, va, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
            self.sections.append((va, max(vsize, rsize), raw, rsize))
        self.mapped = False
        md = None
        if clr_rva:
            # CAPE dumps can be in mapped layout; pick whichever layout puts BSJB where the CLR header says.
            for mapped in (False, True):
                self.mapped = mapped
                try:
                    cli = self.off(clr_rva)
                    cand = self.off(_u32(data, cli + 8))
                except (MetadataError, struct.error):
                    continue
                if data[cand:cand + 4] == b"BSJB":
                    md = cand
                    break
        if md is None:
            # Anti-dump builds zero the CLR directory once loaded: find the metadata root by its signature
            # and pick the layout from the method bodies.
            self._find_root_by_signature()
        else:
            self._parse_root(md)

    def _find_root_by_signature(self):
        p = self.data.find(b"BSJB")
        while p != -1:
            try:
                if _u16(self.data, p + 4) == 1 and self.data[p + 16:p + 17] == b"v":
                    self._parse_root(p)
                    self.mapped = self._guess_layout()
                    return
            except (MetadataError, struct.error, ValueError, IndexError, KeyError):
                pass
            p = self.data.find(b"BSJB", p + 4)
        raise MetadataError("metadata root not found")

    def _guess_layout(self):
        """True if method RVAs point at valid IL headers when read as file offsets (mapped dump)."""
        score = {False: 0, True: 0}
        for mapped in (False, True):
            self.mapped = mapped
            for i in range(1, min(self.nrows(0x06), 200) + 1):
                rva = self.row(0x06, i)[0]
                if not rva:
                    continue
                try:
                    h = self.data[self.off(rva)]
                except (MetadataError, IndexError):
                    continue
                if h & 3 == 2 or (h & 3 == 3 and _u16(self.data, self.off(rva)) >> 12 == 3):
                    score[mapped] += 1
        return score[True] > score[False]

    def off(self, rva):
        if self.mapped:
            if rva >= len(self.data):
                raise MetadataError("rva out of range")
            return rva
        for va, size, raw, rsize in self.sections:
            if va <= rva < va + size:
                o = raw + rva - va
                if rva - va >= rsize or o >= len(self.data):
                    raise MetadataError("rva in virtual-only part of section")
                return o
        raise MetadataError("rva %#x not in a section" % rva)

    def _parse_root(self, md):
        d = self.data
        vlen = _u32(d, md + 12)
        p = md + 16 + vlen + 2
        nstreams = _u16(d, p)
        p += 2
        self.streams = {}
        for _ in range(nstreams):
            so, ss = struct.unpack_from("<II", d, p)
            p += 8
            end = d.index(b"\0", p)
            name = d[p:end].decode("latin1")
            p = (end + 4) & ~3
            self.streams.setdefault(name, (md + so, ss))
        tbl = self.streams.get("#~") or self.streams.get("#-")
        if not tbl or "#Strings" not in self.streams:
            raise MetadataError("missing #~ / #Strings stream")
        self._parse_tables(tbl[0])

    def _parse_tables(self, t):
        d = self.data
        heap_sizes = d[t + 6]
        valid = struct.unpack_from("<Q", d, t + 8)[0]
        p = t + 24
        self.rows = {}
        for i in range(64):
            if valid >> i & 1:
                self.rows[i] = _u32(d, p)
                p += 4
        if heap_sizes & 0x40:  # extra data dword (seen in some obfuscated files)
            p += 4
        self.str_w = 4 if heap_sizes & 1 else 2
        self.guid_w = 4 if heap_sizes & 2 else 2
        self.blob_w = 4 if heap_sizes & 4 else 2
        self.tables = {}
        for i in range(0x2D):
            n = self.rows.get(i, 0)
            if not n:
                continue
            cols = [self._width(c) for c in SCHEMA[i]]
            self.tables[i] = (p, sum(cols), cols, n)
            p += sum(cols) * n
        if p > len(d):
            raise MetadataError("tables run past end of file")

    def _width(self, col):
        if isinstance(col, int):
            return col
        if isinstance(col, tuple):
            return 2 if self.rows.get(col[1], 0) < 0x10000 else 4
        if col == "S":
            return self.str_w
        if col == "G":
            return self.guid_w
        if col == "B":
            return self.blob_w
        bits, tables = CODED[col]
        big = max(self.rows.get(x, 0) for x in tables)
        return 2 if big < (1 << (16 - bits)) else 4

    def row(self, table, idx):
        """1-based row -> tuple of column values."""
        p, size, cols, n = self.tables[table]
        if not 1 <= idx <= n:
            raise MetadataError("row out of range")
        p += (idx - 1) * size
        out = []
        for w in cols:
            out.append(_u16(self.data, p) if w == 2 else _u32(self.data, p))
            p += w
        return out

    def nrows(self, table):
        return self.rows.get(table, 0)

    def string(self, idx):
        base, size = self.streams["#Strings"]
        if idx >= size:
            return ""
        end = self.data.find(b"\0", base + idx)
        return self.data[base + idx:end].decode("utf-8", "replace")

    def user_string(self, idx):
        base, size = self.streams.get("#US", (0, 0))
        if not size or idx >= size:
            return None
        p = base + idx
        b = self.data[p]
        if b & 0x80 == 0:
            n, p = b, p + 1
        elif b & 0xC0 == 0x80:
            n, p = ((b & 0x3F) << 8) | self.data[p + 1], p + 2
        else:
            n, p = ((b & 0x1F) << 24) | (self.data[p + 1] << 16) | (self.data[p + 2] << 8) | self.data[p + 3], p + 4
        n -= 1 if n & 1 else 0  # trailing flag byte
        return self.data[p:p + n].decode("utf-16-le", "replace")

    def types(self):
        """Yield (namespace, name, field_range, method_range) for each TypeDef."""
        n = self.nrows(0x02)
        nf, nm = self.nrows(0x04), self.nrows(0x06)
        for i in range(1, n + 1):
            r = self.row(0x02, i)
            nxt = self.row(0x02, i + 1) if i < n else None
            fend = nxt[4] if nxt else nf + 1
            mend = nxt[5] if nxt else nm + 1
            yield self.string(r[2]), self.string(r[1]), range(r[4], fend), range(r[5], mend)

    def field_name(self, idx):
        return self.string(self.row(0x04, idx)[1])

    def method_body(self, idx):
        rva, _, _, name, _, _ = self.row(0x06, idx)
        if not rva:
            return self.string(name), b""
        p = self.off(rva)
        h = self.data[p]
        if h & 3 == 2:  # tiny header
            return self.string(name), self.data[p + 1:p + 1 + (h >> 2)]
        flags_size = _u16(self.data, p)
        code_size = _u32(self.data, p + 4)
        hdr = (flags_size >> 12) * 4
        return self.string(name), self.data[p + hdr:p + hdr + code_size]


# ----------------------------------------------------------------------------- IL walking

# operand size per one-byte opcode (0x45 switch handled separately); unknown opcodes are 0
_OPERAND = {}
for _op in range(0x00, 0x100):
    _OPERAND[_op] = 0
for _op in (0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x1F, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
            0x33, 0x34, 0x35, 0x36, 0x37, 0xDE):
    _OPERAND[_op] = 1
for _op in (0x20, 0x22, 0x28, 0x29, 0x27, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41,
            0x42, 0x43, 0x44, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x79, 0x7B, 0x7C, 0x7D, 0x7E,
            0x7F, 0x80, 0x81, 0x8C, 0x8D, 0x8F, 0xA3, 0xA4, 0xA5, 0xC2, 0xC6, 0xD0, 0xDD):
    _OPERAND[_op] = 4
_OPERAND[0x21] = _OPERAND[0x23] = 8
_OPERAND_FE = {0x06: 4, 0x07: 4, 0x09: 2, 0x0A: 2, 0x0B: 2, 0x0C: 2, 0x0D: 2, 0x0E: 2, 0x12: 1, 0x15: 4,
               0x16: 4, 0x19: 1, 0x1C: 4, 0x1D: 4}


def static_assignments(code, dn):
    """Walk IL and return [(field_name, value)] for every `const ; [call conv] ; stsfld` pattern."""
    out = []
    last = None
    i = 0
    n = len(code)
    while i < n:
        op = code[i]
        i += 1
        if op == 0xFE:
            if i >= n:
                break
            i += 1 + _OPERAND_FE.get(code[i], 0)
            last = None
            continue
        if op == 0x45:  # switch
            cnt = _u32(code, i) if i + 4 <= n else 0
            i += 4 + 4 * cnt
            last = None
            continue
        size = _OPERAND[op]
        arg = code[i:i + size]
        i += size
        if op == 0x72 and size == 4:  # ldstr
            tok = _u32(arg, 0)
            last = dn.user_string(tok & 0xFFFFFF) if tok >> 24 == 0x70 else None
        elif 0x16 <= op <= 0x1E:  # ldc.i4.0 .. ldc.i4.8
            last = op - 0x16
        elif op == 0x15:
            last = -1
        elif op == 0x1F and size == 1:
            last = struct.unpack("<b", arg)[0]
        elif op == 0x20 and size == 4:
            last = struct.unpack("<i", arg)[0]
        elif op == 0x28:  # call Convert::ToXxx(string) keeps the constant
            pass
        elif op == 0x80 and size == 4:  # stsfld
            tok = _u32(arg, 0)
            if tok >> 24 == 0x04 and last is not None:
                try:
                    out.append((dn.field_name(tok & 0xFFFFFF), last))
                except MetadataError:
                    pass
            last = None
        elif op in (0x00,):  # nop
            pass
        else:
            last = None
    return out


# ----------------------------------------------------------------------------- config recovery

# field names the builder uses, by channel
SMTP = ("SmtpServer", "SmtpSender", "SmtpPassword", "SmtpReceiver", "SmtpPort", "SmtpSSL", "SmtpAttach")
TELEGRAM = ("TelegramApi", "ChatId")
FTP = ("FtpHost", "FtpUser", "FtpPassword", "FtpUserName", "FtpPass", "FtpPort", "FtpUrl")
HTTP = ("PanelUrl", "PanelURL", "WebPanelUrl", "PostURL", "PostUrl", "HttpUrl", "TorPanelUrl", "PanelHost")
DISCORD = ("DiscordWebhook", "WebhookUrl", "DiscordUrl")
GENERIC = ("PublicUserAgent", "LogType", "KeyloggerInterval", "ScreenInterval", "EnableKeylogger",
           "EnableScreenLogger", "EnableClipboardLogger", "EnableTorPanel", "EnableCookies", "EnableContacts",
           "StartupInstallationName", "StartupRegName", "StartupDirectoryName", "StartupEnvName",
           "AppAddStartup", "HideFileStartup", "PublicIpAddressGrab", "IpApi", "DeleteBackspace")
KNOWN = set(SMTP + TELEGRAM + FTP + HTTP + DISCORD + GENERIC)
LOGTYPE = {1: "SMTP", 2: "FTP", 3: "Telegram"}  # all three seen on samples

EMAIL = re.compile(r"^[\w.+-]+@[\w-]+(\.[\w-]+)+$")
TG = re.compile(r"https?://api\.telegram\.org/bot(\d+:[\w-]{30,})/?", re.I)
URL = re.compile(r"^(https?|ftp)://\S+$", re.I)


def find_config_class(dn):
    """Return (type_name, [(field, value)], score) of the best config-class .cctor."""
    best = None
    for ns, name, _, methods in dn.types():
        for m in methods:
            try:
                mname, code = dn.method_body(m)
            except (MetadataError, struct.error, IndexError):
                continue
            if mname != ".cctor" or not code:
                continue
            assigns = static_assignments(code, dn)
            if not assigns:
                continue
            score = sum(1 for f, _ in assigns if f in KNOWN)
            ua = any(isinstance(v, str) and v.startswith("Mozilla/") for _, v in assigns)
            if score < 3 and not (ua and len(assigns) >= 8):
                continue
            key = (score, ua, len(assigns))
            if best is None or key > best[0]:
                best = (key, (ns + "." if ns else "") + name, assigns)
    if not best:
        return None
    return best[1], best[2], best[0][0]


def _boolish(v):
    if isinstance(v, str) and v.lower() in ("true", "false"):
        return v.lower() == "true"
    return v


def _intish(v):
    if isinstance(v, str) and re.fullmatch(r"-?\d{1,9}", v):
        return int(v)
    return v


def _cred_url(scheme, user, pw, host, port=None):
    """scheme://user:pw@host[:port] with the credentials percent-encoded (users are often e-mail addresses)."""
    host = re.sub(r"^[a-z]+://", "", str(host), flags=re.I).rstrip("/")
    auth = quote(str(user), safe="") + (":" + quote(str(pw), safe="") if pw else "") + "@" if user else ""
    return "%s://%s%s%s" % (scheme, auth, host, ":%s" % port if port else "")


def _build_named(fields):
    """Config from a class whose field names survived."""
    f = {k: _intish(_boolish(v)) for k, v in fields.items()}
    present = set(k for k, v in f.items() if v not in ("", None))
    cfg = {}
    c2 = []
    if present & set(TELEGRAM):
        cfg["Protocol"] = "Telegram"
        api = f.get("TelegramApi", "")
        m = TG.search(api or "")
        cfg["TelegramToken"] = m.group(1) if m else api
        cfg["TelegramChatId"] = str(f.get("ChatId", ""))
        if api:
            c2.append(api)
    if present & set(SMTP):
        cfg["Protocol"] = cfg.get("Protocol") or "SMTP"
        host, port = f.get("SmtpServer", ""), f.get("SmtpPort", 587)
        user, pw = f.get("SmtpSender", ""), f.get("SmtpPassword", "")
        cfg.update({"SmtpServer": host, "SmtpPort": port, "SmtpSSL": f.get("SmtpSSL"),
                    "SmtpUser": user, "SmtpPassword": pw, "SmtpReceiver": f.get("SmtpReceiver", "")})
        if host:
            c2.append(_cred_url("smtp", user, pw, host, port))
    if present & set(FTP):
        cfg["Protocol"] = cfg.get("Protocol") or "FTP"
        host = f.get("FtpHost") or f.get("FtpUrl", "")
        user = f.get("FtpUser") or f.get("FtpUserName", "")
        pw = f.get("FtpPassword") or f.get("FtpPass", "")
        cfg.update({"FtpHost": host, "FtpUser": user, "FtpPassword": pw})
        if host:
            c2.append(_cred_url("ftp", user, pw, host))
    for k in HTTP + DISCORD:
        if f.get(k):
            cfg["Protocol"] = cfg.get("Protocol") or ("Discord" if k in DISCORD else "HTTP")
            c2.append(f[k])
    if "Protocol" not in cfg and isinstance(f.get("LogType"), int):
        cfg["Protocol"] = LOGTYPE.get(f["LogType"], "unknown (LogType %d)" % f["LogType"])
    # any other non-empty value that looks like an exfil endpoint, for fields we do not know yet
    for k, v in f.items():
        if k not in KNOWN and isinstance(v, str) and URL.match(v) and v not in c2:
            c2.append(v)
    cfg["C2"] = c2
    if f.get("PublicUserAgent"):
        cfg["UserAgent"] = f["PublicUserAgent"]
    inst = f.get("StartupInstallationName")
    if inst:
        cfg["Persistence"] = {"file": inst, "dir_env": f.get("StartupEnvName", ""),
                              "dir": f.get("StartupDirectoryName", ""), "run_key": f.get("StartupRegName", ""),
                              "enabled": f.get("AppAddStartup")}
    cfg["Features"] = {k: f[k] for k in ("EnableKeylogger", "EnableScreenLogger", "EnableClipboardLogger",
                                         "EnableTorPanel", "EnableCookies", "EnableContacts",
                                         "PublicIpAddressGrab") if k in f}
    if "LogType" in f:
        cfg["LogType"] = f["LogType"]
    return cfg


def _build_heuristic(values):
    """Config from a class with obfuscated field names: classify the constants themselves."""
    strs = [v for v in values if isinstance(v, str) and v]
    cfg = {"C2": []}
    for v in strs:
        m = TG.search(v)
        if m:
            cfg["Protocol"] = "Telegram"
            cfg["TelegramToken"] = m.group(1)
            cfg["C2"].append(v)
            i = strs.index(v)
            if i + 1 < len(strs) and re.fullmatch(r"-?\d{5,}", strs[i + 1]):
                cfg["TelegramChatId"] = strs[i + 1]
    emails = [v for v in strs if EMAIL.match(v)]
    if emails and "Protocol" not in cfg:
        # builder order: port, ssl, attach, server, sender, password, receiver
        i = strs.index(emails[0])
        host = strs[i - 1] if i and "." in strs[i - 1] and "@" not in strs[i - 1] else ""
        pw = strs[i + 1] if i + 1 < len(strs) and not EMAIL.match(strs[i + 1]) else ""
        port = next((int(v) for v in strs[max(0, i - 6):i] if re.fullmatch(r"\d{2,5}", v) and int(v) in
                     (25, 465, 587, 2525, 26, 1025)), 587)
        cfg.update({"Protocol": "SMTP", "SmtpServer": host, "SmtpPort": port, "SmtpUser": emails[0],
                    "SmtpPassword": pw, "SmtpReceiver": emails[1] if len(emails) > 1 else ""})
        if host:
            cfg["C2"].append(_cred_url("smtp", emails[0], pw, host, port))
    for v in strs:
        if URL.match(v) and not TG.search(v) and not v.startswith("Mozilla"):
            cfg.setdefault("Protocol", "FTP" if v.lower().startswith("ftp") else "HTTP")
            cfg["C2"].append(v)
    ua = next((v for v in strs if v.startswith("Mozilla/")), None)
    if ua:
        cfg["UserAgent"] = ua
    exe = next((v for v in strs if v.lower().endswith(".exe")), None)
    if exe:
        cfg["Persistence"] = {"file": exe}
    return cfg


def find_config(data):
    try:
        dn = DotNet(data)
    except (MetadataError, struct.error, ValueError, IndexError):
        return None
    try:
        hit = find_config_class(dn)
    except (MetadataError, struct.error, IndexError):
        return None
    if not hit:
        return None
    cls, assigns, score = hit
    fields = {}
    for k, v in assigns:
        fields.setdefault(k, v)
    if score >= 3:
        cfg = _build_named(fields)
        mode = "named"
    else:
        cfg = _build_heuristic([v for _, v in assigns])
        mode = "heuristic"
    if not cfg.get("C2") and not cfg.get("Protocol"):
        return None
    cfg["raw"] = {"config_class": cls, "mode": mode, "fields": fields}
    return cfg


def extract_config(data):
    """CAPEv2 entry point. Returns a config dict or None."""
    cfg = find_config(data)
    if not cfg:
        return _community_fallback(data)
    out = {"family": "AgentTesla"}
    out.update(cfg)
    return out


def _community_fallback(data):
    """Inside CAPE this file replaces the community parser; keep it as a last resort (strings dumps etc.)."""
    try:
        from cape_parsers.CAPE.community import AgentTesla as community
    except Exception:
        return None
    try:
        cfg = community.extract_config(data)
    except Exception:
        return None
    if not cfg:
        return None
    cfg = _rename_c2_keys(cfg)
    cfg.setdefault("raw", {})
    if isinstance(cfg["raw"], dict):
        cfg["raw"]["mode"] = "community-fallback"
    return cfg


def _rename_c2_keys(obj):
    """The community parser reports endpoints under its own key name; report them as C2 like the rest."""
    if isinstance(obj, dict):
        return {("C2" if k.upper().startswith("CNC") else k): _rename_c2_keys(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_rename_c2_keys(v) for v in obj]
    return obj


# ----------------------------------------------------------------------------- IOCs

# shared providers: report/block the account, never the domain
SHARED_PROVIDERS = {
    "smtp.yandex.com": "Yandex mail",
    "smtp.gmail.com": "Gmail",
    "smtp.office365.com": "Microsoft 365",
    "smtp-mail.outlook.com": "Outlook.com",
    "smtp.zoho.com": "Zoho mail",
    "server356.web-hosting.com": "Namecheap shared hosting",
}


def iocs(cfg, payload_sha256=None, sample_sha256=None):
    """Turn one config into IOC rows: high = literal builder value, low = shared provider or weak artefact."""
    rows = []

    def add(kind, value, role, confidence, notes=""):
        if value:
            rows.append({"type": kind, "value": value, "role": role, "confidence": confidence, "notes": notes,
                         "payload_sha256": payload_sha256 or "", "sample_sha256": sample_sha256 or ""})

    def server(host, role, port=None):
        shared = SHARED_PROVIDERS.get(host.lower())
        notes = ("%s: do NOT block the domain, report the account" % shared) if shared else ""
        if port:
            notes = "; ".join(filter(None, [notes, "port %s" % port]))
        add("domain", host, role, "low" if shared else "high", notes)

    proto = cfg.get("Protocol")
    if proto == "SMTP" and cfg.get("SmtpServer"):
        server(cfg["SmtpServer"], "exfil_smtp_server", cfg.get("SmtpPort"))
        add("email", cfg.get("SmtpUser"), "exfil_smtp_account", "high", "sender mailbox")
        add("email", cfg.get("SmtpReceiver"), "exfil_receiver", "high", "mailbox receiving the logs")
    elif proto == "FTP" and cfg.get("FtpHost"):
        server(cfg["FtpHost"].split("://")[-1].split("/")[0], "exfil_ftp_server")
        add("account", cfg.get("FtpUser"), "exfil_ftp_account", "high", "FTP login")
    elif proto == "Telegram":
        add("telegram_bot", cfg.get("TelegramToken"), "exfil_telegram", "high", "bot token, report to Telegram")
        add("telegram_chat", cfg.get("TelegramChatId"), "exfil_telegram", "high", "chat receiving the logs")
    for url in cfg.get("C2") or []:
        add("url", url, "c2", "high", "contains credentials" if "@" in url.split("://")[-1] else "")
    pers = cfg.get("Persistence")
    if isinstance(pers, dict) and pers.get("file"):
        add("filename", pers["file"], "persistence", "low",
            "%%%s%%\\%s\\%s, Run key '%s' (startup %s); names repeat across builds"
            % (pers.get("dir_env", "appdata").upper(), pers.get("dir", ""), pers["file"], pers.get("run_key", ""),
               "on" if pers.get("enabled") else "off"))
    add("sha256", payload_sha256, "payload", "high", "AgentTesla .NET payload")
    if sample_sha256 and sample_sha256 != payload_sha256:
        add("sha256", sample_sha256, "sample", "high", "original sample")
    return rows


def write_reports(results, out_dir):
    """configs JSON + IOC CSV + Markdown table. Returns the file stem."""
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.join(out_dir, "AgentTesla_%s" % datetime.date.today().isoformat())
    rows, seen = [], set()
    for r in results:
        for row in r.get("iocs", []):
            if (row["type"], row["value"]) not in seen:
                seen.add((row["type"], row["value"]))
                rows.append(row)
    with open(stem + "_configs.json", "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)
    with open(stem + "_iocs.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["type", "value", "role", "confidence", "notes", "payload_sha256", "sample_sha256"])
        w.writeheader()
        w.writerows(rows)
    md = ["# AgentTesla IOCs (%s)" % datetime.date.today().isoformat(), "",
          "%d payload(s) with a config. Static extraction, not traffic-confirmed. "
          "**high** = literal builder config value, **low** = shared provider or weak artefact." % len(results), "",
          "| Type | Value | Role | Confidence | Notes |", "|---|---|---|---|---|"]
    # credential-bearing URLs stay in the CSV/JSON only
    md += ["| %s | `%s` | %s | %s | %s |" % (r["type"], r["value"], r["role"], r["confidence"], r["notes"])
           for r in rows if not (r["type"] == "url" and r["notes"] == "contains credentials")]
    with open(stem + "_iocs.md", "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")
    return stem


# ----------------------------------------------------------------------------- CLI


def _unzip(path, password):
    """Yield (name, bytes) from a zip. CAPE's web UI packs downloads with AES (pw "infected"), which zipfile
    can't decrypt, so fall back to 7z for those."""
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    yield "%s:%s" % (path, info.filename), zf.read(info, pwd=password.encode())
        return
    except (NotImplementedError, RuntimeError):
        pass
    except zipfile.BadZipFile as e:
        print("%s: %s" % (path, e), file=sys.stderr)
        return
    seven = shutil.which("7z") or shutil.which("7za")
    if not seven:
        print("%s: AES-encrypted zip, install 7-Zip (7z) to open it" % path, file=sys.stderr)
        return
    with tempfile.TemporaryDirectory() as td:
        r = subprocess.run([seven, "x", "-y", "-p" + password, "-o" + td, path], capture_output=True, text=True)
        if r.returncode:
            print("%s: 7z failed: %s" % (path, (r.stderr or r.stdout).strip()[-200:]), file=sys.stderr)
            return
        for root, _, files in os.walk(td):
            for f in sorted(files):
                with open(os.path.join(root, f), "rb") as fh:
                    yield "%s:%s" % (path, os.path.relpath(os.path.join(root, f), td)), fh.read()


def _iter_inputs(args, password):
    for a in args:
        paths = [os.path.join(r, f) for r, _, fs in os.walk(a) for f in sorted(fs)] if os.path.isdir(a) else [a]
        for p in paths:
            try:
                with open(p, "rb") as fh:
                    data = fh.read()
            except OSError as e:
                print("%s: %s" % (p, e), file=sys.stderr)
                continue
            if data[:4] == b"PK\x03\x04":
                for item in _unzip(p, password):
                    yield item
            else:
                yield p, data


def main():
    ap = argparse.ArgumentParser(description="AgentTesla static config extractor (unpacked .NET payloads)")
    ap.add_argument("paths", nargs="+", help="payload files, folders (e.g. CAPE analyses/<id>/CAPE/) or zips "
                                             "downloaded from the CAPE web UI")
    ap.add_argument("-a", "--all", action="store_true", help="also list files with no config")
    ap.add_argument("--raw", action="store_true", help="keep every field of the config class in the output")
    ap.add_argument("--iocs", action="store_true", help="add IOC rows (servers, accounts, bot, hashes) to the output")
    ap.add_argument("-o", "--out", metavar="DIR", help="also write configs JSON + IOC CSV + Markdown into DIR")
    ap.add_argument("--sample", metavar="SHA256", help="hash of the original sample, added to the IOC rows")
    ap.add_argument("--zip-password", default="infected", help="password for zips (default: infected)")
    args = ap.parse_args()
    results = []
    for name, data in _iter_inputs(args.paths, args.zip_password):
        cfg = extract_config(data)
        sha = hashlib.sha256(data).hexdigest()
        if cfg and not args.raw and isinstance(cfg.get("raw"), dict):
            cfg["raw"] = {k: v for k, v in cfg["raw"].items() if k != "fields"}
        rec = {"file": name, "sha256": sha, "config": cfg}
        if cfg and (args.iocs or args.out):
            rec["iocs"] = iocs(cfg, sha, args.sample)
        if cfg or args.all:
            print(json.dumps(rec, indent=4, ensure_ascii=False))
        if cfg:
            results.append(rec)
    if args.out and results:
        stem = write_reports(results, args.out)
        print("wrote %s_configs.json, _iocs.csv, _iocs.md" % stem, file=sys.stderr)
    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
