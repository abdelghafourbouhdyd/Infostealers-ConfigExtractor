
import argparse
import base64
import json
import os
import re
import struct
import sys
import urllib.request
from collections import Counter

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM
from unicorn import UC_ARCH_X86, UC_MODE_32, Uc, UcError
from unicorn.x86_const import UC_X86_REG_ESP

DESCRIPTION = "ACRStealer configuration parser"
AUTHOR = "abdelghafour bouhdyd"

STACK, STACK_SZ = 0x00100000, 0x00100000
SCRATCH, SCRATCH_SZ = 0x00300000, 0x00010000
RET_MAGIC = 0x00DEAD00
MAX_INSNS = 2_000_000
MAX_LEN = 0x400

DEAD_DROP_HOSTS = ("telegra.ph", "steamcommunity.com", "pastebin.com", "t.me", "docs.google.com")
BENIGN_HOSTS = ("dns.google", "cloudflare-dns.com", "telegra.ph", "steamcommunity.com", "microsoft.com",
                "windowsupdate.com", "google.com", "api.telegra.ph")
FILE_EXTS = ("js", "key", "json", "txt", "log", "db", "sqlite", "ldb", "dat", "vdf", "ini", "bin", "tmp", "lnk", "exe",
             "dll", "sys", "cfg", "xml", "html", "htm", "png", "jpg", "zip", "wallet", "localstorage", "lock",
             "old", "bak", "conf", "ps1", "bat", "cmd", "vbs", "cookies", "sqlite3", "leveldb", "indexeddb", "manifest")
GTLDS = {"com", "net", "org", "info", "biz", "xyz", "top", "site", "online", "store", "shop", "club", "live", "life",
         "pro", "app", "dev", "io", "cloud", "tech", "space", "website", "fun", "icu", "buzz", "monster", "click",
         "link", "today", "world", "digital", "network", "services", "solutions", "support", "host", "press",
         "run", "page", "best", "rest", "bar", "cyou", "sbs", "lol", "quest", "pics", "mom", "beauty", "hair",
         "skin", "boats", "autos", "yachts", "homes", "motorcycles", "bond", "work", "agency", "email", "group",
         "media", "news", "blog", "zone", "center", "systems", "software", "codes", "global", "plus", "one",
         "vip", "win", "bid", "loan", "date", "racing", "download", "stream", "trade", "party", "review",
         "science", "cricket", "faith", "accountant", "men", "gdn", "kim", "ltd", "inc", "llc", "asia", "mobi",
         "name", "tel", "travel", "aero", "coop", "museum", "jobs", "cat", "edu", "gov", "mil", "int", "arpa"}
HOST_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
URL_RE = re.compile(r"^https?://[\x21-\x7e]{4,}$")
# x86 -> x64 transition that reads TEB32 through TEB64+0x2000 (same bytes the YARA rule keys on)
GATE_RE = re.compile(rb"\x6a\x23\x59\x83\xc1\x10\x51\xe8\x00\x00\x00\x00\x83\x04\x24\x05\xcb"
                     rb"\x65\x48\x8b\x04\x25\x30\x00\x00\x00\x48\x05\x00\x20\x00\x00")
DEAD_DROP_RE = re.compile(r"r\.\]([A-Za-z0-9+/=]{4,})\)0\(")


class Image:
    def __init__(self, data):
        pe = pefile.PE(data=data, fast_load=True)
        if pe.FILE_HEADER.Machine != 0x14C:
            raise ValueError("not an x86 PE")
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.img = pe.get_memory_mapped_image()
        self.size = (len(self.img) + 0xFFF) & ~0xFFF
        self.sections = [(self.base + s.VirtualAddress, self.base + s.VirtualAddress + s.Misc_VirtualSize,
                          s.Name.rstrip(b"\0")) for s in pe.sections]
        text = next((s for s in self.sections if s[2] == b".text"), self.sections[0])
        self.text = text

    def in_data(self, va):
        return any(lo <= va < hi and name != b".text" for lo, hi, name in self.sections)


def _linear(im):
    """One linear capstone pass over .text (good enough for this compiler's output)."""
    lo, hi, _ = im.text
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    md.skipdata = True
    return list(md.disasm(im.img[lo - im.base:hi - im.base], lo))


def _push_args(insns, i):
    """Immediates of the 4 pushes before insns[i] (a call): [dst, src, len, flag]; None = not an immediate."""
    vals = []
    for j in range(i - 1, max(-1, i - 16), -1):
        ins = insns[j]
        m = ins.mnemonic
        if m == "push":
            op = ins.operands[0]
            vals.append(op.imm & 0xFFFFFFFF if op.type == X86_OP_IMM else None)
            if len(vals) == 4:
                return vals
        elif m in ("call", "ret", "jmp") or m.startswith("j") or m == "int3":
            break
    return None


def find_decryptor(im):
    """Return (decryptor_va, [(site, src, len, flag), ...])."""
    insns = _linear(im)
    lo, hi, _ = im.text
    votes, sites = Counter(), {}
    for i, ins in enumerate(insns):
        if ins.mnemonic != "call" or ins.operands[0].type != X86_OP_IMM:
            continue
        dst = ins.operands[0].imm & 0xFFFFFFFF
        if not lo <= dst < hi:
            continue
        args = _push_args(insns, i)
        if not args:
            continue
        _, src, length, flag = args
        if src is None or length is None or flag is None:
            continue
        if not (0 < length <= MAX_LEN and flag < 0x100 and im.in_data(src)):
            continue
        votes[dst] += 1
        sites.setdefault(dst, []).append((ins.address, src, length, flag))
    if not votes:
        return None, []
    func, n = votes.most_common(1)[0]
    if n < 20:
        return None, []
    return func, sites[func]


class Emulator:
    def __init__(self, im):
        self.im = im
        self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
        self.mu.mem_map(im.base, im.size)
        self.mu.mem_map(STACK, STACK_SZ)
        self.mu.mem_map(SCRATCH, SCRATCH_SZ)
        self.mu.mem_map(0, 0x10000)                 # fs base 0: zeroed fake TEB
        self.mu.mem_map(RET_MAGIC & ~0xFFF, 0x1000)
        self.pristine = bytes(im.img)

    def decrypt(self, func, src, length, flag):
        mu = self.mu
        mu.mem_write(self.im.base, self.pristine)  # decryption may cache state in .data
        mu.mem_write(SCRATCH, b"\0" * 0x1000)
        sp = STACK + STACK_SZ - 0x1000
        mu.mem_write(sp, struct.pack("<IIIII", RET_MAGIC, SCRATCH, src, length, flag))
        mu.reg_write(UC_X86_REG_ESP, sp)
        try:
            mu.emu_start(func, RET_MAGIC, count=MAX_INSNS)
        except UcError:
            return None
        return bytes(mu.mem_read(SCRATCH, length))


def _text(raw):
    if len(raw) > 2 and raw[1:2] == b"\0":
        raw = raw.decode("utf-16le", "ignore").encode("latin-1", "ignore")
    raw = raw.rstrip(b"\0")
    if raw and all(0x20 <= c < 0x7F for c in raw):
        return raw.decode()
    return None


def decrypt_strings(data):
    im = Image(data)
    func, sites = find_decryptor(im)
    if not func:
        return None, []
    emu = Emulator(im)
    out = []
    for site, src, length, flag in sites:
        raw = emu.decrypt(func, src, length, flag)
        s = _text(raw) if raw else None
        if s:
            out.append((site, s))
    return func, out


def _is_host(s):
    low = s.lower()
    if not HOST_RE.match(low):
        return False
    tld = low.rsplit(".", 1)[1]
    return tld not in FILE_EXTS and (len(tld) == 2 or tld in GTLDS)


def build_config(strings):
    """strings: [(site, text)]. Sorted by call site, the CDN front host is decrypted right before the dead drop."""
    strings = sorted(strings)
    c2, drops, fronts = [], [], []
    for i, (_, s) in enumerate(strings):
        low = s.lower()
        if URL_RE.match(low):
            host = low.split("/", 3)[2]
            if host in DEAD_DROP_HOSTS:
                if s not in drops:
                    drops.append(s)
                prev = strings[i - 1][1].lower() if i else ""
                if _is_host(prev) and prev not in fronts and not URL_RE.match(prev):
                    fronts.append(prev)
            elif host not in BENIGN_HOSTS and _is_host(host) and s not in c2:
                c2.append(s)
    for _, s in strings:
        low = s.lower()
        if _is_host(low) and low not in BENIGN_HOSTS and low not in fronts:
            url = f"https://{low}/"
            if url not in c2:
                c2.append(url)
    cfg = {}
    if c2:
        cfg["C2"] = c2
    if drops:
        cfg["dead_drops"] = drops
    if fronts:
        cfg["front_domains"] = fronts
    return cfg


def decode_dead_drop(text):
    """Fallback C2 list from a dead-drop page (HTML or api.telegra.ph JSON)."""
    out = []
    for m in DEAD_DROP_RE.finditer(text):
        try:
            v = base64.b64decode(m.group(1)).decode()
        except Exception:
            continue
        if v not in out:
            out.append(v)
    return out


def extract_config(data):
    if not GATE_RE.search(data):
        return {}
    try:
        func, strings = decrypt_strings(data)
    except Exception:
        return {}
    if not func:
        return {}
    cfg = build_config(strings)
    if cfg:
        cfg["source"] = "static"
        cfg["decryptor"] = hex(func)
        cfg["strings_decrypted"] = len(strings)
    return cfg


def fetch_dead_drop(url, proxy=None, timeout=30):
    """Read a telegra.ph page through its public API and return the decoded fallback C2s."""
    path = url.rstrip("/").rsplit("/", 1)[-1]
    api = f"https://api.telegra.ph/getPage/{path}?return_content=true"
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(api, headers={"User-Agent": "Mozilla/5.0"})
    with opener.open(req, timeout=timeout) as r:
        return decode_dead_drop(r.read().decode("utf-8", "replace"))


def _files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    yield os.path.join(root, n)
        else:
            yield p


def analyse(path, data, offline=False, proxy=None):
    """Config for one file plus the decoded dead drops; None when the file is not an ACR build."""
    cfg = extract_config(data)
    if not cfg:
        return None
    res = {"file": path, "config": cfg, "resolved": []}
    if not offline:
        for url in cfg.get("dead_drops", []):
            try:
                res["resolved"].append({"url": url, "c2": fetch_dead_drop(url, proxy)})
            except Exception as e:
                res["resolved"].append({"url": url, "error": str(e)})
    return res


def iocs(results):
    """Flat, de-duplicated list: C2 domains, fallback IPs, dead-drop URLs."""
    out = []
    for r in results:
        for c2 in r["config"].get("C2", []):
            out.append(c2.split("/", 3)[2] if "://" in c2 else c2)
        for item in r["resolved"]:
            out.extend(item.get("c2", []))
        out.extend(r["config"].get("dead_drops", []))
    return list(dict.fromkeys(out))


def _print_text(r):
    cfg = r["config"]
    print(f"[+] {os.path.basename(r['file'])}")
    for c2 in cfg.get("C2", []):
        print(f"    C2           {c2}")
    for url in cfg.get("dead_drops", []):
        print(f"    dead drop    {url}")
    for item in r["resolved"]:
        if "error" in item:
            print(f"    fallback C2  (fetch failed: {item['error']})")
        for ip in item.get("c2", []):
            print(f"    fallback C2  {ip}")
    for front in cfg.get("front_domains", []):
        print(f"    front domain {front}  (legit CDN, do not block)")
    print(f"    strings decrypted: {cfg.get('strings_decrypted')}, decryptor at {cfg.get('decryptor')}")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="ACRStealer / Amatera config extractor: give it the sample(s), get C2, dead drop, fallback C2 "
                    "and an IOC list.")
    ap.add_argument("paths", nargs="*", help="sample files or folders")
    ap.add_argument("--offline", action="store_true",
                    help="do not fetch the dead-drop page (by default it is read via api.telegra.ph)")
    ap.add_argument("--proxy", help="proxy for the dead-drop fetch, e.g. http://127.0.0.1:8080")
    ap.add_argument("--json", action="store_true", help="JSON output instead of text")
    ap.add_argument("-o", "--output", help="also write the IOC list to this file")
    ap.add_argument("-a", "--all", action="store_true", help="also list files with no config")
    ap.add_argument("--strings", action="store_true", help="dump every decrypted string instead")
    ap.add_argument("--decode", metavar="TEXT", help="decode dead-drop page text offline")
    a = ap.parse_args(argv)

    if a.decode:
        print(json.dumps(decode_dead_drop(a.decode)))
        return 0
    if not a.paths:
        ap.print_help()
        return 1

    results = []
    for path in _files(a.paths):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            print(f"{path}: {e}", file=sys.stderr)
            continue
        if a.strings:
            try:
                _, strings = decrypt_strings(data) if GATE_RE.search(data) else (None, [])
            except Exception:
                strings = []
            for site, s in sorted(strings):
                print(f"{path}\t{site:#x}\t{s}")
            if strings:
                results.append(path)
            continue
        r = analyse(path, data, a.offline, a.proxy)
        if r is None:
            if a.all and not a.json:
                print(f"[-] {os.path.basename(path)}: no ACRStealer config")
            continue
        results.append(r)
        if not a.json:
            _print_text(r)
    if a.strings:
        return 0 if results else 1

    found = iocs(results)
    if a.json:
        print(json.dumps({"results": results, "iocs": found}, indent=4))
    elif results:
        print("\n[IOCs]")
        print("\n".join(found))
    else:
        print("no ACRStealer config found", file=sys.stderr)
    if a.output and found:
        with open(a.output, "w") as f:
            f.write("\n".join(found) + "\n")
        if not a.json:
            print(f"\n[+] IOC list written to {a.output}")
    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
