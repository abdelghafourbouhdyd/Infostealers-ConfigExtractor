
import logging
import re
import struct
from contextlib import suppress

import pefile

log = logging.getLogger(__name__)

DESCRIPTION = "Remus stealer config extractor"
AUTHOR = "local (CAPE task 65)"

# lea rcx,[rip+state]; lea rdx,[rip+key]; lea r8,[rip+nonce]; xor r9d,r9d; jmp/call chacha_init
RE_INIT = re.compile(rb"\x48\x8D\x0D(.{4})\x48\x8D\x15(.{4})\x4C\x8D\x05(.{4})\x45\x31\xC9[\xE8\xE9]", re.S)
# 65/68: lea rdx,[rip+table]; shl rax,6; add rdx,rax; lea rcx,[rip+state]; lea r8,[rsp+X]; call decrypt
RE_TABLE = re.compile(rb"\x48\x8D\x15(.{4})\x48\xC1\xE0\x06\x48\x01\xC2\x48\x8D\x0D.{4}\x4C\x8D\x84\x24.{4}\xE8.{4}", re.S)
# 71:    shl eax,6; lea rdx,[rip+table]; add rdx,rax; lea rcx,[rip+state]; lea rsi,[rsp+X]; mov r8,rsi; call decrypt
RE_TABLE_V1 = re.compile(rb"\xC1\xE0\x06\x48\x8D\x15(.{4})\x48\x01\xC2\x48\x8D\x0D.{4}\x48\x8D\xB4\x24.{4}\x49\x89\xF0\xE8.{4}", re.S)
# lea rcx,[rsp+X]; call set_xor_seed  (right after the decrypt call)
RE_SEED_CALL = re.compile(rb"\x48\x8D\x4C\x24.\xE8(.{4})", re.S)
RE_TAG = re.compile(rb"(?<![0-9a-f])([0-9a-f]{32})\x00")
RE_URL = re.compile(rb"^https?://[\x21-\x7e]{4,}$")

MAX_SLOTS = 16


def _rotl(v, c):
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF


def _qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl(x[b] ^ x[c], 7)


def chacha20_block(key, nonce, counter):
    st = list(struct.unpack("<4I", b"expand 32-byte k"))
    st += list(struct.unpack("<8I", key))
    st += [counter & 0xFFFFFFFF, counter >> 32]
    st += list(struct.unpack("<2I", nonce))
    x = list(st)
    for _ in range(10):
        _qr(x, 0, 4, 8, 12)
        _qr(x, 1, 5, 9, 13)
        _qr(x, 2, 6, 10, 14)
        _qr(x, 3, 7, 11, 15)
        _qr(x, 0, 5, 10, 15)
        _qr(x, 1, 6, 11, 12)
        _qr(x, 2, 7, 8, 13)
        _qr(x, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(x, st)])


def _xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _cstr(data):
    return data.split(b"\x00", 1)[0]


def _xor_key_from_code(img, call_end_rva):
    """Follow `lea rcx,[rsp+X]; call seed` after the decrypt call and fold the obfuscated dword."""
    m = RE_SEED_CALL.match(img, call_end_rva)
    if not m:
        return None
    seed_fn = m.end() + struct.unpack("<i", m.group(1))[0]
    if img[seed_fn : seed_fn + 2] != b"\xC7\x01" or img[seed_fn + 6] != 0xC3:
        return None
    seed = struct.unpack_from("<I", img, seed_fn + 2)[0]
    # loop runs once with i=1: dword = (d ^ i*K) | (d ^ i*K)  -> d ^ K
    tail = img[m.end() : m.end() + 0x60]
    imul = re.search(rb"\x69\xC9(.{4})", tail, re.S)
    if not imul:
        return None
    return struct.pack("<I", seed ^ struct.unpack("<I", imul.group(1))[0])


def extract_static(data):
    pe = pefile.PE(data=data, fast_load=True)
    img = pe.get_memory_mapped_image()

    m_init = RE_INIT.search(img)
    m_tab = RE_TABLE.search(img) or RE_TABLE_V1.search(img)
    if not m_init or not m_tab:
        return None

    key_rva = m_init.start(2) + 4 + struct.unpack("<i", m_init.group(2))[0]
    nonce_rva = m_init.start(3) + 4 + struct.unpack("<i", m_init.group(3))[0]
    table_rva = m_tab.start(1) + 4 + struct.unpack("<i", m_tab.group(1))[0]
    key = img[key_rva : key_rva + 32]
    nonce = img[nonce_rva : nonce_rva + 8]

    xor_key = _xor_key_from_code(img, m_tab.end())
    slot0 = _xor(img[table_rva : table_rva + 64], chacha20_block(key, nonce, 0))
    if xor_key is None or not RE_URL.match(_cstr(_xor(slot0, xor_key))):
        # fallback: known plaintext, slots are dword-aligned URLs
        xor_key = _xor(slot0[:4], b"http")
        if not RE_URL.match(_cstr(_xor(slot0, xor_key))):
            return None

    cncs = []
    for i in range(MAX_SLOTS):
        off = table_rva + i * 64
        enc = img[off : off + 64]
        if len(enc) < 64:
            break
        url = _cstr(_xor(_xor(enc, chacha20_block(key, nonce, i)), xor_key))
        if not RE_URL.match(url):
            break
        cncs.append(url.decode())

    if not cncs:
        return None

    config = {
        "CNCs": cncs,
        "cryptokey": key.hex(),
        "cryptokey_type": "ChaCha20",
        "raw": {
            "chacha20_nonce": nonce.hex(),
            "c2_table_rva": hex(table_rva),
        },
    }
    if any(xor_key):
        config["raw"]["xor_key"] = xor_key.hex()

    for sec in pe.sections:
        if sec.Name.rstrip(b"\x00") == b".rdata":
            tags = set(RE_TAG.findall(sec.get_data()))
            if len(tags) == 1:
                config["botnet"] = tags.pop().decode()
            break

    return config


def extract_strings(data):
    """Debugger dump (typestring 'Remus Config'): one decrypted string per line."""
    config = {}
    for line in data.decode(errors="ignore").splitlines():
        line = line.strip()
        if line.startswith(("http://", "https://")):
            config.setdefault("CNCs", []).append(line)
    return config or None


def extract_config(data):
    with suppress(Exception):
        if data[:2] == b"MZ":
            return extract_static(data)
        return extract_strings(data)


if __name__ == "__main__":
    import json
    import sys

    with open(sys.argv[1], "rb") as f:
        print(json.dumps(extract_config(f.read()), indent=4))
