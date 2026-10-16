#!/usr/bin/env python3
"""Vidar stealer config extractor (x64 builds, 2025-2026: versions 1.8, 2.2-2.7, 3.2-3.8).

Author: abdelghafour bouhdyd

Works on an unpacked Vidar payload: a PE dump (file or memory layout) from CAPE, x64dbg,
pe-sieve and similar tools, or a raw memory region holding the config.
"""

import argparse
import html as htmlmod
import json
import os
import re
import sys
import urllib.request

AUTHOR = "abdelghafour bouhdyd"
DESCRIPTION = "Vidar config extractor (version, build id, C2s, dead drops, user agents)"

KEYLEN = 0x10
VER_LEN = 0x30
BID_OFF, BID_LEN = 0x31, 0x71
RECS = 0x72
URL_LEN = 0x100
TAG_OFF, TAG_LEN = 0x101, 0x141
UA_OFF, UA_LEN = 0x142, 0x242
REC_SIZE = 0x243
MAX_RECORDS = 32

VERSION_RE = re.compile(rb"^\d{1,3}(?:\.\d{1,3}){1,3}$")

# Dead-drop key: 32 bytes, repeated. Same in every build tested (2.2 - 3.8).
DEADDROP_KEY = bytes.fromhex("2de380c59a6f48a8d0589bc0ffd64a5cc8faa01c87a69e5a9f1ec9777eb74cbe")


# --------------------------------------------------------------------------- static config

def _field(buf, base, ct_off, len_off, key):
    n = buf[base + len_off]
    if base + ct_off + n > len(buf):
        return None
    ct = buf[base + ct_off:base + ct_off + n]
    return bytes(c ^ key[i % KEYLEN] for i, c in enumerate(ct))


def _printable(b):
    return all(0x20 <= c < 0x7F for c in b)


def _candidates(data):
    """Offsets where key[0:4] ^ first_url[0:4] == b'http' (XOR of the buffer with itself shifted)."""
    n = len(data) - RECS
    if n <= 0:
        return
    mixed = (int.from_bytes(data[RECS:], "big") ^ int.from_bytes(data[:n], "big")).to_bytes(n, "big")
    i = mixed.find(b"http")
    while i != -1:
        if i + RECS + REC_SIZE <= len(data):
            yield i
        i = mixed.find(b"http", i + 1)


def _parse_blob(data, off):
    if not 3 <= data[off + VER_LEN] <= 15:
        return None
    key = data[off:off + KEYLEN]
    version = _field(data, off, KEYLEN, VER_LEN, key)
    if not version or not VERSION_RE.match(version):
        return None
    build_id = _field(data, off, BID_OFF, BID_LEN, key)
    if build_id is None or not _printable(build_id):
        return None
    records = []
    for k in range(MAX_RECORDS):
        rb = off + RECS + k * REC_SIZE
        if rb + REC_SIZE > len(data):
            break
        url = _field(data, rb, 0, URL_LEN, key)
        if not url or not url.startswith(b"http") or not _printable(url):
            break
        tag = _field(data, rb, TAG_OFF, TAG_LEN, key) or b""
        ua = _field(data, rb, UA_OFF, UA_LEN, key) or b""
        records.append({"url": url.decode(), "marker": tag.decode("latin1"), "user_agent": ua.decode("latin1")})
    if not records:
        return None
    return {"offset": off, "key": key, "version": version.decode(), "build_id": build_id.decode(), "records": records}


def find_config(data):
    for off in _candidates(data):
        blob = _parse_blob(data, off)
        if blob:
            return blob
    return None


def extract_config(data):
    """CAPEv2 entry point. Returns a config dict or None."""
    blob = find_config(data)
    if not blob:
        return None
    recs = blob["records"]
    c2s = [r["url"] for r in recs if not r["marker"]]
    drops = [r for r in recs if r["marker"]]
    config = {
        "version": blob["version"],
        "botnet": blob["build_id"],
        "CNCs": c2s + [d["url"] for d in drops],
        "cryptokey": blob["key"].hex(),
        "cryptokey_type": "XOR",
        "user_agent": list(dict.fromkeys(r["user_agent"] for r in recs if r["user_agent"])),
        "raw": {
            "direct_c2": c2s,
            "dead_drops": drops,
            "config_offset": hex(blob["offset"]),
        },
    }
    return config


# --------------------------------------------------------------------------- dead drops

PAYLOAD_RE = r"(?<![\w]){m}\s+([^\s<\"'|]+)"
HOST_RE = re.compile(r"^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,24}(?::\d{1,5})?(?:/\S*)?$|"
                     r"^(?:https?://)?\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?(?:/\S*)?$", re.I)


def decode_payload(payload):
    """Decode the text that follows the marker word. Returns (c2_url, note)."""
    payload = payload.strip().rstrip("|")
    note = ""
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}){4,}", payload):
        ct = bytes.fromhex(payload)
        host = bytes(c ^ DEADDROP_KEY[i % len(DEADDROP_KEY)] for i, c in enumerate(ct)).decode("latin1")
        if not HOST_RE.match(host):
            note = "decoded text does not look like a host"
    elif HOST_RE.match(payload):
        host = payload
    else:
        return None, "payload is neither hex nor a host name"
    url = host if host.lower().startswith("http") else "https://" + host
    return url, note


def decode_text(text, marker):
    """Find '<marker> <payload>' in page text and decode every hit."""
    out = []
    for m in re.finditer(PAYLOAD_RE.format(m=re.escape(marker)), text or ""):
        url, note = decode_payload(m.group(1))
        out.append({"payload": m.group(1), "c2": url, "note": note})
    return out


def _fetch(url, ua, proxy=None, timeout=20):
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept-Language": "en-US,en;q=0.8"})
    with urllib.request.build_opener(*handlers).open(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _page_texts(url, page):
    """Pull the fields Vidar reads (name, description, summary, bio) out of a dead-drop page."""
    texts = []
    pats = [
        r'<meta property="og:(?:title|description)" content="(.*?)"',
        r'class="tgme_page_(?:title|description)"[^>]*>(.*?)</div>',
        r'class="actual_persona_name"[^>]*>(.*?)</span>',
        r'"personaname":"(.*?)"',
        r'"summary":"(.*?)"',
        r'"bio":"(.*?)"',
        r'"name":"(.*?)"',
    ]
    for p in pats:
        for m in re.finditer(p, page, re.S | re.I):
            t = htmlmod.unescape(re.sub(r"<[^>]+>", " ", m.group(1)))
            try:
                t = json.loads('"' + t + '"') if "\\" in t else t
            except ValueError:
                pass
            texts.append(t.strip())
    texts.append(htmlmod.unescape(re.sub(r"<[^>]+>", " ", page)))
    return texts


def resolve(drop, ua, proxy=None):
    """Fetch a dead drop and decode its C2. Contacts the dead-drop host from this machine."""
    url, marker = drop["url"], drop["marker"]
    res = {"url": url, "marker": marker, "c2": [], "history": []}
    fetch_url = url
    m = re.search(r"fandom\.com/.*userId=(\d+)", url)
    if m:  # same data without Cloudflare
        fetch_url = f"https://services.fandom.com/user-attribute/user/{m.group(1)}"
    try:
        page = _fetch(fetch_url, ua, proxy)
    except Exception as e:
        res["error"] = str(e)
        return res
    seen = set()
    for t in _page_texts(url, page):
        for hit in decode_text(t, marker):
            if hit["payload"] not in seen:
                seen.add(hit["payload"])
                res["c2"].append(hit)
    if "steamcommunity.com" in url:
        try:
            for a in json.loads(_fetch(url.rstrip("/") + "/ajaxaliases", ua, proxy)):
                for hit in decode_text(a.get("newname", ""), marker):
                    res["history"].append(dict(hit, changed=a.get("timechanged")))
        except Exception:
            pass
    return res


# --------------------------------------------------------------------------- CLI

def _files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in sorted(names):
                    yield os.path.join(root, n)
        else:
            yield p


def main():
    ap = argparse.ArgumentParser(description=DESCRIPTION, epilog=f"Author: {AUTHOR}")
    ap.add_argument("paths", nargs="*", help="unpacked payloads or folders (e.g. CAPE analyses/<id>/CAPE/)")
    ap.add_argument("-a", "--all", action="store_true", help="also list files with no config")
    ap.add_argument("-d", "--debug", action="store_true", help="raise errors instead of skipping the file")
    ap.add_argument("-r", "--resolve", action="store_true",
                    help="fetch the dead drops and decode the live C2 (contacts Telegram/Steam/... from your IP, see --proxy)")
    ap.add_argument("--proxy", help="proxy for --resolve, e.g. http://127.0.0.1:8080")
    ap.add_argument("--decode", nargs=2, metavar=("MARKER", "TEXT"),
                    help='decode dead-drop text offline, e.g. --decode s90m "s90m 5d84aef6a95d3cc7a437b5ae9aa2"')
    a = ap.parse_args()

    if a.decode:
        print(json.dumps(decode_text(a.decode[1], a.decode[0]), indent=4))
        return 0
    if not a.paths:
        ap.print_help()
        return 1

    found = 0
    for f in _files(a.paths):
        try:
            with open(f, "rb") as fh:
                cfg = extract_config(fh.read())
        except Exception as e:
            if a.debug:
                raise
            cfg, err = None, str(e)
        else:
            err = None
        if not cfg:
            if a.all:
                print(json.dumps({"file": f, "config": None, **({"error": err} if err else {})}))
            continue
        found += 1
        if a.resolve:
            cfg["resolved"] = [resolve(d, d["user_agent"] or "Mozilla/5.0", a.proxy)
                               for d in cfg["raw"]["dead_drops"]]
        print(json.dumps({"file": f, "config": cfg}, indent=4))
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main())
