"""
Remus stealer configuration extractor (x64).

Input
  * unpacked Remus payload (PE file layout)
  * process / memory dump: a Remus image in loaded (mapped) layout, at any offset inside the dump and
    relocated to any base (the load base is recovered from the relocation table)
  * plain text with one URL per line (e.g. a debugger string dump) -> runtime_C2

Configuration layout
  C2 table     N x 64-byte slots; slot i = ChaCha20(key, nonce, counter=i), optionally XORed with a
               4-byte key. Key/nonce are referenced by the CRT initializer:
               lea rcx,[state]; lea rdx,[key32]; lea r8,[nonce8]; xor r9d,r9d; jmp|call init
  build tag    NUL-terminated 32-hex string in .rdata (check-in field "tag=")
  build date   check-in field "exp=" = <midnight-UTC constant> + (MT19937() & 0xffff)
  strings      User-Agent, Host header, Ethereum dead drop (RPC / contract / selector), check-in fields,
               HTTP headers, anti-analysis markers: stack strings decoded in place by inline loops,
               recovered by emulating each loop (unicorn + capstone; optional).

Usage:  python Remus.py <file>      (also usable as a CAPEv2 config parser)
"""

import datetime
import json
import logging
import re
import struct
from contextlib import suppress

import pefile

try:
    import capstone
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP, X86_REG_RSP
    from unicorn import UC_ARCH_X86, UC_MODE_64, Uc, UcError
    from unicorn import x86_const as ucx

    HAVE_EMU = True
except ImportError:  # strings-based keys are skipped; C2/tag/keys/build date still work
    HAVE_EMU = False

log = logging.getLogger(__name__)

DESCRIPTION = "Remus stealer config extractor"
AUTHOR = "abdelghafour bouhdyd"

# ---------------------------------------------------------------- C2 table
RE_INIT = re.compile(rb"\x48\x8D\x0D(.{4})\x48\x8D\x15(.{4})\x4C\x8D\x05(.{4})\x45\x31\xC9[\xE8\xE9]", re.S)
# CFF builds: lea rdx,[table]; shl rax,6; add rdx,rax; lea rcx,[state]; lea r8,[rsp+X]; call decrypt
RE_TABLE = re.compile(rb"\x48\x8D\x15(.{4})\x48\xC1\xE0\x06\x48\x01\xC2\x48\x8D\x0D.{4}\x4C\x8D\x84\x24.{4}\xE8.{4}", re.S)
# plain builds: shl eax,6; lea rdx,[table]; add rdx,rax; lea rcx,[state]; lea rsi,[rsp+X]; mov r8,rsi; call decrypt
RE_TABLE_V1 = re.compile(rb"\xC1\xE0\x06\x48\x8D\x15(.{4})\x48\x01\xC2\x48\x8D\x0D.{4}\x48\x8D\xB4\x24.{4}\x49\x89\xF0\xE8.{4}", re.S)
# lea rcx,[rsp+X]; call set_xor_seed  (right after the decrypt call, CFF builds)
RE_SEED_CALL = re.compile(rb"\x48\x8D\x4C\x24.\xE8(.{4})", re.S)
# build tag: last 32 hex chars before a NUL; up to 2 stray hex bytes may precede it (random .rdata bytes
# that happen to be ASCII hex), longer runs (hashes etc.) are rejected
RE_TAG = re.compile(rb"(?<![0-9a-f])[0-9a-f]{0,2}([0-9a-f]{32})\x00")
RE_URL = re.compile(rb"^https?://[\x21-\x7e]{4,}$")
# add r32, imm32 (incl. r8d-r15d and the eax short form) followed by the decimal conversion:
#   call form:    ... mov r8d,0x10 ; mov r9d,10 ; call itoa
#   inline form:  ... mov edx,0xCCCCCCCD (divide-by-10 magic)      
#   mov form:     mov eax,<base> ; xor edx,edx ; div ecx ; ... mov r8d,0x10 ; mov r9d,10
RE_EXP = re.compile(rb"(?:\x41?\x81[\xC0-\xC7]|\x05|\x41?[\xB8-\xBF])(.{4})"
                    rb"(?:.{0,40}?\x41\xB8\x10\x00\x00\x00.{0,8}?\x41\xB9\x0A\x00\x00\x00"
                    rb"|.{0,40}?[\xB8-\xBF]\xCD\xCC\xCC\xCC)", re.S)
TS_MIN, TS_MAX = 1704067200, 1893456000  # 2024-01-01 .. 2030-01-01
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


def _rel(img, m, group):
    return m.start(group) + 4 + struct.unpack("<i", m.group(group))[0]


def _xor_key_from_code(img, call_end_rva):
    """Follow `lea rcx,[rsp+X]; call seed` after the decrypt call and fold the obfuscated dword."""
    m = RE_SEED_CALL.match(img, call_end_rva)
    if not m:
        return None
    seed_fn = m.end() + struct.unpack("<i", m.group(1))[0]
    if img[seed_fn : seed_fn + 2] != b"\xC7\x01" or img[seed_fn + 6] != 0xC3:
        return None
    seed = struct.unpack_from("<I", img, seed_fn + 2)[0]
    imul = re.search(rb"\x69\xC9(.{4})", img[m.end() : m.end() + 0x60], re.S)
    if not imul:
        return None
    return struct.pack("<I", seed ^ struct.unpack("<I", imul.group(1))[0])


RE_LEA_RCX = re.compile(rb"\x48\x8D\x0D(.{4})", re.S)
RE_LEA_RDX = re.compile(rb"\x48\x8D\x15(.{4})", re.S)
RE_CALL = re.compile(rb"\xE8.{4}", re.S)


def _find_table_generic(img, state_rva, init_off):
    """Layout-independent: the decrypt call site is the other `lea rcx,[state]`; the table pointer is
    the `lea rdx,[rip+X]` (+ shl 6 / add rdx,rax) a few bytes before it."""
    for m in RE_LEA_RCX.finditer(img):
        if m.start() == init_off or _rel(img, m, 1) != state_rva:
            continue
        window_lo = max(0, m.start() - 24)
        cands = [d for d in RE_LEA_RDX.finditer(img, window_lo, m.start())]
        if not cands:
            continue
        d = cands[-1]
        call = RE_CALL.search(img, m.end(), m.end() + 24)
        return _rel(img, d, 1), (call.end() if call else m.end())
    return None, None


def extract_c2_table(img):
    m_init = RE_INIT.search(img)
    if not m_init:
        return None
    key_rva, nonce_rva, state_rva = _rel(img, m_init, 2), _rel(img, m_init, 3), _rel(img, m_init, 1)
    m_tab = RE_TABLE.search(img) or RE_TABLE_V1.search(img)
    if m_tab:
        table_rva, after_call = _rel(img, m_tab, 1), m_tab.end()
    else:
        table_rva, after_call = _find_table_generic(img, state_rva, m_init.start())
        if table_rva is None:
            return None
    key, nonce = img[key_rva : key_rva + 32], img[nonce_rva : nonce_rva + 8]

    slot0 = _xor(img[table_rva : table_rva + 64], chacha20_block(key, nonce, 0))
    xor_key = _xor_key_from_code(img, after_call)
    if xor_key is None or not RE_URL.match(_cstr(_xor(slot0, xor_key))):
        xor_key = _xor(slot0[:4], b"http")  # known plaintext; 00000000 on ChaCha-only builds
        if not RE_URL.match(_cstr(_xor(slot0, xor_key))):
            return None

    c2s = []
    for i in range(MAX_SLOTS):
        enc = img[table_rva + i * 64 : table_rva + i * 64 + 64]
        if len(enc) < 64:
            break
        url = _cstr(_xor(_xor(enc, chacha20_block(key, nonce, i)), xor_key))
        if not RE_URL.match(url):
            break
        c2s.append(url.decode())
    return {"c2": c2s, "key": key, "nonce": nonce, "xor_key": xor_key, "table_rva": table_rva}


def extract_build_date(img):
    """exp = base + (MT() & 0xffff); base is midnight UTC of the build/campaign date."""
    pos = 0
    while True:  # overlapping scan: a stray 05/81 byte inside a preceding call must not hide the real add
        m = RE_EXP.search(img, pos)
        if not m:
            return None
        v = struct.unpack("<I", m.group(1))[0]
        if TS_MIN <= v <= TS_MAX and v % 3600 == 0:
            return v
        pos = m.start() + 1


# ---------------------------------------------------------------- stack strings (emulated)
STACK, STACK_SZ = 0x7000_0000, 0x40000
SETUP_MNEMS = {"movups", "movaps", "movdqa", "movdqu", "movq", "movd", "movsd", "movss"}
STOP = ("ret", "int3", "hlt")


def _is_setup(i):
    if i.mnemonic == "movabs" or i.mnemonic in SETUP_MNEMS:
        return True
    if i.mnemonic != "mov" or len(i.operands) != 2:
        return False
    dst, src = i.operands
    if dst.type == X86_OP_MEM and dst.mem.base == X86_REG_RSP and dst.mem.index == 0:
        return src.type in (X86_OP_IMM, X86_OP_REG)
    return dst.type == X86_OP_REG and src.type == X86_OP_IMM


def _buf_mem(op):
    """[base + idx*s + X] with a 1/2-byte operand: a stack buffer (base rsp) or an alloca'd/pointer buffer
    (base = some register holding the buffer address, 10-13 builds)."""
    return (op.type == X86_OP_MEM and op.size in (1, 2) and op.mem.index != 0
            and op.mem.base not in (0, X86_REG_RIP))


def _same_slot(a, b):
    return a.mem.base == b.mem.base and a.mem.disp == b.mem.disp


def _find_loops(insns):
    """Decode-loop cores = in-place transform of a stack buffer indexed by a register:
         xor [rsp+i*s+X], r                                  (CFF builds)
         xor r, [rsp+i*s+X] ; mov [rsp+i*s+X], r             (plain builds)
         mov/movzx r, [rsp+i*s+X] ; <xor | MBA a+b-2(a&b)> ; mov [rsp+i*s+X], r
    The buffer base is usually rsp; some builds decode through a pointer register (alloca'd buffers).
    Returns (index_of_anchor, base_reg, buf_disp, width)."""
    out, seen = [], set()
    for k, a in enumerate(insns):
        if len(a.operands) != 2:
            continue
        dst, src = a.operands
        hit = None
        if a.mnemonic == "xor" and _buf_mem(dst) and src.type == X86_OP_REG:
            hit = dst
        elif a.mnemonic == "xor" and dst.type == X86_OP_REG and _buf_mem(src):
            hit = src
        elif a.mnemonic == "mov" and _buf_mem(dst) and src.type == X86_OP_REG:
            # store back: require a read of the same buffer slot shortly before
            for b in insns[max(0, k - 32) : k]:
                if b.mnemonic in ("xor", "mov", "movzx", "movsx", "add", "sub") and len(b.operands) == 2 \
                        and _buf_mem(b.operands[1]) and _same_slot(b.operands[1], dst):
                    hit = dst
                    break
        if hit is None:
            continue
        key = (a.address, hit.mem.base, hit.mem.disp, hit.size)
        if key not in seen:
            seen.add(key)
            out.append((k, hit.mem.base, hit.mem.disp, hit.size))
    return out


def _loop_bounds(insns, k, addr_idx):
    for j in range(k, min(k + 14, len(insns))):
        i = insns[j]
        if not i.mnemonic.startswith("j") or not i.operands or i.operands[0].type != X86_OP_IMM:
            continue
        tgt = i.operands[0].imm
        if tgt >= insns[k].address:
            continue
        if i.mnemonic != "jmp":
            return tgt, i.address + i.size
        h = addr_idx.get(tgt)
        if h is None:
            return None
        for x in insns[h:k]:  # unconditional back-edge: exit is the header's forward jcc
            if x.mnemonic.startswith("j") and x.mnemonic != "jmp" and x.operands \
                    and x.operands[0].type == X86_OP_IMM and x.operands[0].imm > i.address:
                return tgt, x.operands[0].imm
        return None
    return None


def _candidate_starts(insns, head, loop_top):
    s, writes = head, 0  # tight: only buffer setup
    while s > 0 and (_is_setup(insns[s - 1]) or insns[s - 1].mnemonic in ("nop", "cmp", "ja", "jae", "jmp")
                     or (insns[s - 1].mnemonic == "mov" and "ptr [rsp" in insns[s - 1].op_str)):
        s -= 1
        writes += _is_setup(insns[s])
        if loop_top - insns[s].address > 0x400:
            break
    if writes:
        yield s
    b, last = head, s  # broad: every basic-block start (passes memcpy/init calls, neighbouring loops)
    for _ in range(128):
        p = insns[b - 1] if b > 0 else None
        if p is None or p.mnemonic in STOP:
            break
        if p.mnemonic == "call" and p.operands and p.operands[0].type != X86_OP_IMM:
            break
        if (p.mnemonic.startswith("j") or p.mnemonic == "call") and b < last:
            last = b
            yield b
        b -= 1
    if b < last:
        yield b


_GPRS = None
HEAP, HEAP_SZ = 0x7800_0000, 0x40000
FRAME_SPAN = 0x800  # rbp-relative slots pre-filled with heap pointers (pointer-buffer fallback)
# first bytes of the buffer-setup instructions (movabs r64 / mov [rsp+X],imm|reg / movups|movaps / lea r,[rip])
RE_SETUP_START = re.compile(
    rb"[\x48\x49][\xB8-\xBF]|\xC7[\x44\x84]\x24|\x66\xC7[\x44\x84]\x24|\xC6[\x44\x84]\x24|"
    rb"[\x48\x4C]\x89[\x44\x84\x4C\x8C\x54\x94\x5C\x9C]\x24|\x0F[\x10\x11\x28\x29]|\x48\x8D[\x05\x0D\x15]", re.S)


def _resync_starts(md, img, base, loop_top_rva, span=0x180):
    """Desync-proof candidates: byte offsets before the loop that start with a setup opcode and
    disassemble cleanly onto the loop head (nearest first)."""
    lo = max(0, loop_top_rva - span)
    window = img[lo:loop_top_rva]
    starts = sorted((lo + m.start() for m in RE_SETUP_START.finditer(window)), reverse=True)
    for s in starts:
        pos = s
        for i in md.disasm(img[s:loop_top_rva], base + s):
            pos = i.address - base + i.size
            if i.mnemonic in STOP:
                break
        if pos == loop_top_rva:
            yield base + s


def _emulate(uc, start, end, base_reg, disp, width, prefill=False):
    rsp = STACK + STACK_SZ // 2
    rbp = rsp + 0x4000  # frame above the stack pointer: rbp-relative locals stay inside the mapping
    uc.mem_write(STACK, b"\x00" * STACK_SZ)
    if prefill:
        # every rbp-relative qword slot points to its own zeroed scratch area, so a buffer pointer the code
        # loads from its frame resolves to valid memory even though its alloca happened out of view
        uc.mem_write(HEAP, b"\x00" * HEAP_SZ)
        slots = (2 * FRAME_SPAN) // 8
        step = HEAP_SZ // slots
        uc.mem_write(rbp - FRAME_SPAN, b"".join(struct.pack("<Q", HEAP + i * step) for i in range(slots)))
    for r in _GPRS:
        uc.reg_write(r, 0)
    uc.reg_write(ucx.UC_X86_REG_RSP, rsp)
    uc.reg_write(ucx.UC_X86_REG_RBP, rbp)
    try:
        uc.emu_start(start, end, count=200000)
    except UcError:
        return None
    if uc.reg_read(ucx.UC_X86_REG_RIP) != end:
        return None
    try:
        raw = bytes(uc.mem_read(uc.reg_read(base_reg) + disp, 0x800))
    except UcError:
        return None
    if width == 2:
        end_w = next((i for i in range(0, len(raw) - 1, 2) if raw[i] == 0 and raw[i + 1] == 0), len(raw))
        try:
            raw = raw[:end_w].decode("utf-16le").encode("latin1")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return None
    text = raw.split(b"\x00", 1)[0]
    if len(text) >= 2 and all(0x20 <= c < 0x7F or c in (9, 10, 13) for c in text):
        return text.decode()
    return None


def decode_stack_strings(pe, img, base=None):
    """[(rva, string)] for every inline-decoded stack string. `img` is the mapped image, `base` its load
    address (absolute pointers in a process dump are relocated to it)."""
    global _GPRS
    if not HAVE_EMU:
        return []
    _GPRS = [getattr(ucx, f"UC_X86_REG_{r}") for r in ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "R8", "R9",
                                                         "R10", "R11", "R12", "R13", "R14", "R15")]
    if base is None:
        base = pe.OPTIONAL_HEADER.ImageBase
    text = next((s for s in pe.sections if s.Name.startswith(b".text")), None)
    if text is None:
        return []
    t0, t1 = text.VirtualAddress, text.VirtualAddress + text.Misc_VirtualSize

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    insns, off = [], t0
    while off < t1:  # linear sweep with byte resync
        got = False
        for i in md.disasm(img[off : min(off + 15, t1)], base + off, count=1):
            insns.append(i)
            off += i.size
            got = True
        if not got:
            off += 1
    addr_idx = {i.address: n for n, i in enumerate(insns)}

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(base, (len(img) + 0xFFF) & ~0xFFF)
    uc.mem_write(base, bytes(img))
    uc.mem_map(STACK, STACK_SZ)
    uc.mem_map(HEAP, HEAP_SZ)
    md_plain = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    out, done = [], set()
    for k, breg, disp, width in _find_loops(insns):
        lb = _loop_bounds(insns, k, addr_idx)
        if lb is None or (lb, breg, disp) in done:
            continue
        done.add((lb, breg, disp))
        loop_top, loop_end = lb
        try:
            uc_breg = getattr(ucx, "UC_X86_REG_" + md.reg_name(breg).upper())
        except AttributeError:
            continue
        # plain stack buffers first; pointer buffers additionally get the pre-filled frame
        modes = (False,) if breg == X86_REG_RSP else (False, True)
        t = None
        for prefill in modes:
            for s in _candidate_starts(insns, addr_idx.get(loop_top, k), loop_top):
                t = _emulate(uc, insns[s].address, loop_end, uc_breg, disp, width, prefill)
                if t is not None:
                    break
            if t is None:  # linear sweep may be desynced right before the setup code
                for tries, start in enumerate(_resync_starts(md_plain, img, base, loop_top - base)):
                    if tries >= 24:
                        break
                    t = _emulate(uc, start, loop_end, uc_breg, disp, width, prefill)
                    if t is not None:
                        break
            if t is not None:
                break
        if t is not None:
            out.append((insns[k].address - base, t))
    return out


def config_from_strings(strings, c2s):
    """Map decoded stack strings to config keys."""
    cfg, raw = {}, {}
    vals = [s for _, s in strings]
    c2_hosts = {re.sub(r"^https?://", "", c).split("/")[0] for c in c2s}

    ua = next((s for s in vals if s.startswith("Mozilla/")), None)
    if ua:
        cfg["user_agent"] = ua

    rpc, contracts, selectors = [], [], []
    for s in vals:
        if s.startswith("{") and '"jsonrpc"' in s:
            raw.setdefault("jsonrpc_body", s)
            with suppress(ValueError, KeyError, IndexError, TypeError):
                p = json.loads(s)["params"][0]
                contracts.append(p["to"])
                selectors.append(p["data"])
        elif re.match(r"^https?://[\w.-]+(:\d+)?/?$", s) and s.split("//", 1)[1].split("/")[0] not in c2_hosts:
            rpc.append(s)
    if rpc or contracts:
        dd = {"type": "ethereum eth_call"}
        if rpc:
            dd["rpc_urls"] = sorted(set(rpc))
        if contracts:
            dd["contract"] = sorted(set(contracts))
            dd["selector"] = sorted(set(selectors))
        cfg["dead_drop"] = dd

    fields = [f.strip("&=") for f in vals if re.fullmatch(r"&?[a-z_]{2,16}=", f)]
    if fields:
        raw["checkin_fields"] = sorted(set(fields))
    methods = sorted({s for s in vals if s in ("GET", "POST", "PUT")})
    if methods:
        raw["http_methods"] = methods
    ctypes = sorted({s.split(":", 1)[1].strip() for s in vals if s.startswith("Content-Type:")})
    if ctypes:
        raw["content_types"] = ctypes
    decoys = sorted({s for s in vals if "@" in s and s.endswith(".pst")})
    if decoys:
        raw["decoy_files"] = decoys
    vm = sorted({s for s in vals if re.search(r"vmware|virtualbox|qemu|virtio|spice guest|hyper-v|parallels", s, re.I)
                 and len(s) <= 40})
    if vm:
        raw["anti_vm_markers"] = vm
    banners = sorted({s for s in vals if s.isupper() and len(s) >= 12 and " " in s})
    if banners:  # e.g. geofence "THIS COUNTRY IS NOT ALLOWED", debug "CANCEL THE RUN TO PREVENT ..."
        raw["banners"] = banners
    headers = sorted({s for s in vals if re.fullmatch(r"Host: [\w.-]+", s)})
    if headers:
        cfg["http_host_header"] = headers[0].split(": ", 1)[1]
    raw["stack_strings"] = len(vals)
    return cfg, raw


# ---------------------------------------------------------------- image discovery (files and dumps)
MAX_IMAGES = 64
IMAGE_REL_BASED_DIR64 = 10


def _pe_headers(data, off):
    """Parsed headers of an x64 PE starting at `off`, or None."""
    if data[off : off + 2] != b"MZ" or off + 0x40 > len(data):
        return None
    e_lfanew = struct.unpack_from("<I", data, off + 0x3C)[0]
    if not 0x40 <= e_lfanew <= 0x1000 or data[off + e_lfanew : off + e_lfanew + 4] != b"PE\x00\x00":
        return None
    if struct.unpack_from("<H", data, off + e_lfanew + 4)[0] != 0x8664:  # AMD64
        return None
    try:
        return pefile.PE(data=bytes(data[off : off + 0x1000]), fast_load=True)
    except pefile.PEFormatError:
        return None


def _load_base(img, pe):
    """Actual load base of a mapped image: absolute pointers listed in the relocation table point into
    [base, base + SizeOfImage). Falls back to the header ImageBase."""
    hdr = pe.OPTIONAL_HEADER.ImageBase
    size = pe.OPTIONAL_HEADER.SizeOfImage
    rd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]]
    ptrs, pos, end = [], rd.VirtualAddress, min(rd.VirtualAddress + rd.Size, len(img))
    while rd.VirtualAddress and pos + 8 <= end and len(ptrs) < 4096:
        page, blk = struct.unpack_from("<II", img, pos)
        if blk < 8:
            break
        for i in range(pos + 8, min(pos + blk, end) - 1, 2):
            ent = struct.unpack_from("<H", img, i)[0]
            if ent >> 12 == IMAGE_REL_BASED_DIR64 and page + (ent & 0xFFF) + 8 <= len(img):
                ptrs.append(struct.unpack_from("<Q", img, page + (ent & 0xFFF))[0])
        pos += blk
    if not ptrs or all(hdr <= v < hdr + size for v in ptrs):
        return hdr
    cand = min(v for v in ptrs if v > 0x10000) & ~0xFFFF
    inside = sum(1 for v in ptrs if cand <= v < cand + size)
    return cand if inside >= 0.9 * len(ptrs) else hdr


def iter_images(data):
    """Yield (pe, img, base, layout, offset) for every x64 PE image in `data`: the file itself (file layout)
    and images embedded in process / memory dumps (mapped layout, possibly relocated)."""
    offsets, pos = [], 0
    while len(offsets) < MAX_IMAGES:
        pos = data.find(b"MZ", pos)
        if pos < 0:
            break
        if _pe_headers(data, pos) is not None:
            offsets.append(pos)
        pos += 2
    for off in offsets:
        hpe = _pe_headers(data, off)
        size = hpe.OPTIONAL_HEADER.SizeOfImage
        # file layout (unpacked payload, rebuilt dump)
        with suppress(Exception):
            pe = pefile.PE(data=bytes(data[off:]), fast_load=True)
            yield pe, pe.get_memory_mapped_image(), pe.OPTIONAL_HEADER.ImageBase, "file", off
        # mapped layout (raw memory dump)
        img = bytes(data[off : off + size]).ljust(size, b"\x00")
        yield hpe, img, _load_base(img, hpe), "mapped", off


def _section(pe, img, name):
    for sec in pe.sections:
        if sec.Name.rstrip(b"\x00") == name:
            return img[sec.VirtualAddress : sec.VirtualAddress + max(sec.Misc_VirtualSize, sec.SizeOfRawData)]
    return b""


# ---------------------------------------------------------------- entry points
def _layout_score(pe, img):
    """A wrong layout can still decode the C2 table (code and data shifted by the same delta), but
    section-based reads (tag) and absolute constants (build date) only line up in the right one."""
    return 2 * (len(set(RE_TAG.findall(_section(pe, img, b".rdata")))) == 1) + (extract_build_date(img) is not None)


def extract_static(data, with_strings=True):
    best = None
    for pe, img, base, layout, off in iter_images(data):
        t = extract_c2_table(img)
        if not (t and t["c2"]):
            continue
        score = _layout_score(pe, img)
        if best is None or score > best[0]:
            best = (score, pe, img, base, layout, off, t)
        if score == 3:
            break
    if best is None:
        return None
    _, pe, img, base, layout, off, t = best
    return _build_config(pe, img, base, layout, off, t, with_strings)


def _build_config(pe, img, base, layout, off, t, with_strings):
    config = {
        "C2": t["c2"],
        "cryptokey": t["key"].hex(),
        "cryptokey_type": "ChaCha20",
        "raw": {"chacha20_nonce": t["nonce"].hex(), "c2_table_rva": hex(t["table_rva"])},
    }
    if any(t["xor_key"]):
        config["raw"]["xor_key"] = t["xor_key"].hex()

    if layout == "mapped" or off:
        config["raw"]["image_layout"] = layout
        config["raw"]["image_offset"] = hex(off)
        config["raw"]["load_base"] = hex(base)

    tags = set(RE_TAG.findall(_section(pe, img, b".rdata")))
    if len(tags) == 1:
        config["botnet"] = tags.pop().decode()

    bd = extract_build_date(img)
    if bd:
        config["build_date"] = datetime.datetime.fromtimestamp(bd, datetime.timezone.utc).strftime("%Y-%m-%d")
        config["raw"]["exp_base"] = bd

    if with_strings:
        try:
            strings = decode_stack_strings(pe, img, base)
        except Exception as e:  # emulation must never cost the C2 config
            log.debug("Remus stack-string decoding failed: %s", e)
            strings = []
        if strings:
            cfg, raw = config_from_strings(strings, t["c2"])
            config.update(cfg)
            config["raw"].update(raw)
    return config


def extract_strings(data):
    """Plain-text input (one decrypted string per line, e.g. a debugger string dump).

    Reported as `runtime_C2`, not `C2`, so a partial runtime capture never overwrites the full static
    C2 list when a sandbox merges several configs of the same family."""
    if len(data) > 1 << 20 or sum(32 <= c < 127 or c in (9, 10, 13) for c in data) < 0.95 * len(data):
        return None  # binary input (dump without a Remus image) is not a text capture
    urls = []
    for line in data.decode(errors="ignore").splitlines():
        line = line.strip()
        if line.startswith(("http://", "https://")) and line not in urls:
            urls.append(line)
    return {"runtime_C2": urls} if urls else None


def extract_config(data):
    with suppress(Exception):
        cfg = extract_static(data) if b"MZ" in data else None
        if cfg:
            return cfg
        if data[:2] != b"MZ":
            return extract_strings(data)
    return None


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(json.dumps(extract_config(f.read()), indent=4))
