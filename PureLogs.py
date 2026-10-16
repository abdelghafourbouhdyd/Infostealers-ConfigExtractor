"""
PureLogs config extractor - offline, read-only, Python stdlib only.

Input : CAPE process memory dumps (memory/<pid>.dmp, task submitted with procmemdump=1),
        or the whole memory/ folder.
Usage : python3 -I PureLogs.py [--defang] <memory folder | file.dmp ...>

Author: abdelghafour bouhdyd 
"""

import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys

DESCRIPTION = "PureLogs config extractor (CLR heap walk over CAPE process dumps)"
AUTHOR = "abdelghafour bouhdyd"

# a base64 X.509 DER cert as a UTF-16LE CLR string: "MII" + >= 600 b64 chars
CERT_RE = re.compile(rb"M\x00I\x00I\x00(?:[A-Za-z0-9+/]\x00){600,}(?:=\x00){0,2}")
URL_RE = re.compile(rb"h\x00t\x00t\x00p\x00s?\x00:\x00/\x00/\x00(?:[A-Za-z0-9.\-:]\x00){3,120}(?![A-Za-z0-9.\-:/]\x00)")
BUILD_RE = re.compile(r"^[A-Za-z0-9_\-]{4,64}$")
APIKEY_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{12,128}$")
HOST_RE = re.compile(r"^(?=.{3,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9\-]{1,63})*$")
ENV_DIRS = {"APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "USERPROFILE", "PROGRAMDATA", "PUBLIC", "ALLUSERSPROFILE", "WINDIR"}


class Dump:
    """CAPE procdump format: repeated [u64 va][u32 size][u32 state][u32 type][u32 prot] + data."""

    def __init__(self, data):
        self.d = data
        self.regs = []
        o = 0
        while o + 24 <= len(data):
            va, sz = struct.unpack_from("<QI", data, o)
            if sz == 0 or o + 24 + sz > len(data):
                break
            self.regs.append((va, sz, o + 24))
            o += 24 + sz
        self._starts = [r[2] for r in self.regs]

    @classmethod
    def looks_like(cls, data):
        if len(data) < 24 or data[:2] == b"MZ":
            return False
        va, sz = struct.unpack_from("<QI", data, 0)
        return 0 < sz <= len(data) - 24 and va & 0xFFF == 0 and sz & 0xFFF == 0

    def _reg_by_off(self, off):
        lo, hi = 0, len(self.regs) - 1
        while lo <= hi:
            m = (lo + hi) // 2
            va, sz, fo = self.regs[m]
            if off < fo:
                hi = m - 1
            elif off >= fo + sz:
                lo = m + 1
            else:
                return self.regs[m]

    def off2va(self, off):
        r = self._reg_by_off(off)
        return None if r is None else r[0] + off - r[2]

    def va2off(self, va):
        for v, sz, fo in self.regs:
            if v <= va < v + sz:
                return fo + va - v

    def read(self, va, n):
        o = self.va2off(va)
        if o is None:
            return None
        b = self.d[o:o + n]
        return b if len(b) == n else None

    def ptr(self, va, ps):
        b = self.read(va, ps)
        return None if b is None else int.from_bytes(b, "little")

    def u32(self, va):
        b = self.read(va, 4)
        return None if b is None else struct.unpack("<I", b)[0]


class Heap:
    """Typed reads of CLR objects. ps = pointer size (4 or 8)."""

    def __init__(self, dump, ps, string_mt):
        self.m, self.ps, self.string_mt = dump, ps, string_mt

    def mt(self, obj):
        return self.m.ptr(obj, self.ps) if obj else None

    def string(self, obj, limit=0x10000):
        if not obj or self.mt(obj) != self.string_mt:
            return None
        n = self.m.u32(obj + self.ps)
        if n is None or n > limit:
            return None
        b = self.m.read(obj + self.ps + 4, n * 2)
        if b is None:
            return None
        try:
            return b.decode("utf-16le")
        except UnicodeDecodeError:
            return None

    def array(self, arr, n):
        # SZArray: MT | u32 length (+pad on x64) | elements
        if not arr:
            return None
        length = self.m.u32(arr + self.ps)
        if length is None or length > 0x10000 or n > length:
            return None
        return arr + 2 * self.ps, length

    def list_of(self, obj):
        """List<T>: MT | _items | _syncRoot | int _size | int _version (refs first). Returns (items_va, size)."""
        if not obj:
            return None
        items = self.m.ptr(obj + self.ps, self.ps)
        size = self.m.u32(obj + 3 * self.ps)
        if items is None or size is None or size > 256:
            return None
        a = self.array(items, size)
        return None if a is None else (a[0], size)

    def list_strings(self, obj):
        lst = self.list_of(obj)
        if not lst:
            return None
        out = []
        for k in range(lst[1]):
            s = self.string(self.m.ptr(lst[0] + k * self.ps, self.ps), 512)
            if s is None:
                return None
            out.append(s)
        return out

    def list_ints(self, obj):
        lst = self.list_of(obj)
        if not lst:
            return None
        b = self.m.read(lst[0], 4 * lst[1])
        return None if b is None else list(struct.unpack("<%di" % lst[1], b))


def _der_len(b, i):
    n = b[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    return n, i


def _der_children(b, i, end):
    while i < end:
        tag = b[i]
        n, j = _der_len(b, i + 1)
        yield tag, j, j + n
        i = j + n


def cert_info(der):
    """Minimal X.509 parse: subject/issuer CN, validity, sha1/sha256 thumbprints."""
    info = {"sha1": hashlib.sha1(der).hexdigest(), "sha256": hashlib.sha256(der).hexdigest()}
    try:
        _, s, e = next(_der_children(der, 0, len(der)))
        _, s, e = next(_der_children(der, s, e))  # tbsCertificate
        parts = list(_der_children(der, s, e))
        if parts and parts[0][0] == 0xA0:
            parts = parts[1:]
        serial, issuer, validity, subject = parts[0], parts[2], parts[3], parts[4]
        info["serial"] = der[serial[1]:serial[2]].hex()

        def cn(node):
            names = []
            for _, rs, re_ in _der_children(der, node[1], node[2]):
                for _, as_, ae in _der_children(der, rs, re_):
                    kids = list(_der_children(der, as_, ae))
                    if len(kids) == 2 and der[kids[0][1]:kids[0][2]] == b"\x55\x04\x03":
                        names.append(der[kids[1][1]:kids[1][2]].decode("utf-8", "replace"))
            return ", ".join(names)

        info["subject_cn"], info["issuer_cn"] = cn(subject), cn(issuer)
        t = [der[a:b].decode() for _, a, b in _der_children(der, validity[1], validity[2])]
        info["not_before"], info["not_after"] = t[0], t[1]
    except Exception:
        pass
    return info


def _classify(heap, obj, cert_obj, nslots=12):
    """Read the fields of a candidate config object and classify them by content."""
    ps, m = heap.ps, heap.m
    cfg = {"hosts": None, "ports": None, "strings": [], "flags": None}
    cert_seen = False
    last_ref = 0
    for k in range(1, nslots + 1):
        p = m.ptr(obj + k * ps, ps)
        if p is None:
            break
        if p == cert_obj:
            cert_seen = True
            last_ref = k
            continue
        if p == 0:
            continue
        s = heap.string(p, 1024)
        if s is not None:
            cfg["strings"].append(s)
            last_ref = k
            continue
        hs = heap.list_strings(p)
        if hs is not None and cfg["hosts"] is None and hs and all(HOST_RE.match(h) for h in hs):
            cfg["hosts"] = hs
            last_ref = k
            continue
        ints = heap.list_ints(p)
        if ints is not None and cfg["ports"] is None and ints and all(0 < x < 65536 for x in ints):
            cfg["ports"] = ints
            last_ref = k
            continue
        if last_ref and k > last_ref:  # past the reference block -> value-type fields (bools)
            break
    if not (cert_seen and cfg["hosts"] and cfg["ports"]):
        return None
    flags = m.read(obj + (last_ref + 1) * ps, 4)
    if flags is not None:
        cfg["flags"] = [b for b in flags[:3]]
    return cfg


def _name_strings(strings):
    """build tag first; then install file name, install env var, mutex (Path.Combine(%env%, file))."""
    out = {}
    rest = list(strings)
    if rest:
        out["build"] = rest.pop(0)
    env = next((s for s in rest if s.upper() in ENV_DIRS), None)
    if env is not None:
        i = rest.index(env)
        out["install_env"] = env
        before, after = rest[:i], rest[i + 1:]
        if before:
            out["install_file"] = before[-1]
        if after:
            out["mutex"] = after[0]
        rest = before[:-1] + after[1:]
    if rest:
        out["other_strings"] = rest
    return out


def _https_config(heap, owner):
    """stealer_https layout: refs url, api_key, build_id, tag, byte[] key; then int port, bool, bool."""
    m, ps = heap.m, heap.ps
    mt = m.ptr(owner, ps)
    if not mt or mt == heap.string_mt:
        return None
    strings, blobs, k = [], [], 1
    while k <= 8:
        p = m.ptr(owner + k * ps, ps)
        if p is None:
            return None
        s = heap.string(p, 1024) if p else None
        if s is not None:
            strings.append(s)
        elif p == 0:
            strings.append(None)
        else:
            n = m.u32(p + ps) if heap.mt(p) else None
            if n is not None and n in (16, 24, 32, 48, 64) and m.ptr(p, ps) != heap.string_mt:
                blobs.append(m.read(p + 2 * ps, n))
            else:
                break
        k += 1
    if len(strings) < 3 or not strings[0]:
        return None
    url, api_key, build = strings[0], strings[1], strings[2]
    # api_key may be empty (builder option); the build id is a short token in every build seen
    if api_key is None or (api_key and not APIKEY_RE.match(api_key)) or not (build and BUILD_RE.match(build)):
        return None
    tail = m.read(owner + k * ps, 8)
    if tail is None:
        return None
    port = struct.unpack_from("<i", tail)[0]
    if not 0 < port < 65536:
        return None
    cfg = {"url": url, "port": port, "api_key": api_key, "build_id": build}
    if len(strings) > 3 and strings[3] is not None:
        cfg["tag"] = strings[3]
    if blobs and blobs[0]:
        cfg["key"] = blobs[0].hex()
    cfg["flags"] = list(tail[4:6])
    return cfg


def find_https_configs(dump):
    d = dump.d
    results, seen = [], set()
    for mo in URL_RE.finditer(d):
        url = mo.group().decode("utf-16le")
        chars_va = dump.off2va(mo.start())
        if chars_va is None:
            continue
        for ps in (8, 4):
            obj = chars_va - ps - 4
            if obj >> (8 * ps) or dump.u32(obj + ps) != len(url):
                continue
            heap = Heap(dump, ps, dump.ptr(obj, ps))
            needle = obj.to_bytes(ps, "little")
            i = d.find(needle)
            while i != -1:
                ref_va = dump.off2va(i) if i % ps == 0 else None
                if ref_va is not None:
                    owner = ref_va - ps  # url is the first reference field
                    cfg = _https_config(heap, owner)
                    if cfg:
                        key = (cfg["url"], cfg["port"], cfg["api_key"])
                        if key not in seen:
                            seen.add(key)
                            cfg.update({"variant": "stealer_https", "arch": "x64" if ps == 8 else "x86", "object_va": hex(owner)})
                            results.append(cfg)
                i = d.find(needle, i + 1)
    return results


def find_configs(dump):
    return find_tls_configs(dump) + find_https_configs(dump)


def find_tls_configs(dump):
    d = dump.d
    results, seen = [], set()
    for mo in CERT_RE.finditer(d):
        chars_va = dump.off2va(mo.start())
        if chars_va is None:
            continue
        b64 = mo.group().decode("utf-16le")
        for ps in (4, 8):
            obj = chars_va - ps - 4
            if obj >> (8 * ps) or dump.u32(obj + ps) != len(b64):
                continue
            string_mt = dump.ptr(obj, ps)
            heap = Heap(dump, ps, string_mt)
            needle = obj.to_bytes(ps, "little")
            i = d.find(needle)
            while i != -1:
                ref_va = dump.off2va(i) if i % ps == 0 else None
                if ref_va is not None:
                    # the cert is one of the first few reference slots of the owner
                    for slot in range(1, 8):
                        owner = ref_va - slot * ps
                        cfg = _classify(heap, owner, obj)
                        if cfg:
                            key = (tuple(cfg["hosts"]), tuple(cfg["ports"]), b64)
                            if key not in seen:
                                seen.add(key)
                                try:
                                    der = base64.b64decode(b64)
                                except Exception:
                                    der = b""
                                c = {"variant": "client_tls", "hosts": cfg["hosts"], "ports": cfg["ports"]}
                                c.update(_name_strings(cfg["strings"]))
                                if cfg["flags"] is not None:
                                    c["flags"] = cfg["flags"]
                                c["certificate"] = cert_info(der) if der else {}
                                c["certificate_b64"] = b64
                                c["arch"] = "x64" if ps == 8 else "x86"
                                c["object_va"] = hex(owner)
                                results.append(c)
                            break
                i = d.find(needle, i + 1)
    return results


def _c2_of(c):
    if c["variant"] == "client_tls":
        return [f"{h}:{p}" for h in c["hosts"] for p in c["ports"]]
    url = c["url"].rstrip("/")
    host = url.split("://", 1)[1]
    return [url if ":" in host else f"{url}:{c['port']}"]


def extract_config(data):
    """CAPE parser entry point. Only CAPE process memory dumps carry the config."""
    if not Dump.looks_like(data):
        return {}
    cfgs = find_configs(Dump(data))
    if not cfgs:
        return {}
    out = {"CNCs": []}
    for c in cfgs:
        for c2 in _c2_of(c):
            if c2 not in out["CNCs"]:
                out["CNCs"].append(c2)
    first = cfgs[0]
    out["variant"] = first["variant"]
    for k in ("build", "build_id", "api_key", "tag", "install_env", "install_file", "mutex"):
        if first.get(k) is not None:
            out[k] = first[k]
    cert = first.get("certificate", {})
    if cert:
        out["cert_sha1"] = cert.get("sha1")
        out["cert_subject"] = cert.get("subject_cn")
    out["raw"] = cfgs
    return out


def _iter_paths(args):
    for a in args:
        if os.path.isdir(a):
            for name in sorted(os.listdir(a)):
                p = os.path.join(a, name)
                if name.endswith(".dmp") and os.path.isfile(p):
                    yield p
        else:
            yield a


def _defang(v):
    if isinstance(v, str):
        v = v.replace("https://", "hxxps://").replace("http://", "hxxp://")
        head, sep, tail = v.rpartition(".")
        return f"{head}[.]{tail}" if sep and "://" not in tail else v
    if isinstance(v, list):
        return [_defang(x) for x in v]
    return v


def main():
    ap = argparse.ArgumentParser(
        description="PureLogs config extractor. Input: CAPE memory/<pid>.dmp files or a memory/ folder.")
    ap.add_argument("paths", nargs="+", help="CAPE memory/<pid>.dmp file(s) or memory/ folder(s)")
    ap.add_argument("--defang", action="store_true", help="defang C2s/hosts/URLs in the output")
    ap.add_argument("--full-path", action="store_true", help="show full input paths (default: file name only)")
    ap.add_argument("-v", "--verbose", action="store_true", help="also report files with no config")
    args = ap.parse_args()

    rc, seen = 1, 0
    for path in _iter_paths(args.paths):
        seen += 1
        shown = path if args.full_path else os.path.basename(path)
        try:
            with open(path, "rb") as f:
                data = f.read()
            cfg = extract_config(data)
        except (OSError, MemoryError) as e:
            print(f"[!] {shown}: cannot read ({e.__class__.__name__})", file=sys.stderr)
            continue
        except Exception as e:  # malformed / hostile input must not kill the run
            print(f"[!] {shown}: skipped, parse error ({e.__class__.__name__})", file=sys.stderr)
            continue
        if not cfg:
            if data[:2] == b"MZ" or data[:64].lstrip()[:1] in (b"/", b"v", b"f", b"<"):
                print(f"[!] {shown}: not a memory dump", file=sys.stderr)
            elif args.verbose:
                print(f"[-] {shown}: no config", file=sys.stderr)
            continue
        for c in cfg["raw"]:
            c.pop("certificate_b64", None)
        if args.defang:
            cfg["CNCs"] = _defang(cfg["CNCs"])
            for c in cfg["raw"]:
                for k in ("hosts", "url"):
                    if k in c:
                        c[k] = _defang(c[k])
        rc = 0
        print(json.dumps({"file": shown, "config": cfg}, indent=2))
    if not seen:
        print("[!] no .dmp input", file=sys.stderr)
    elif rc:
        print("[-] no config found", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
