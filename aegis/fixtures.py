"""Inert, structurally-realistic test fixtures.

These build *valid, parseable* PE files with real import tables and (for the
injector) a packed, W^X section -- but they contain NO working payload and are
never executed. They exist so the detectors can be exercised on malware-SHAPED
input without shipping real malware. The same files are the template for a real
corpus: replace them with real labeled samples to train the learned extension.
"""

from __future__ import annotations

import os
import struct


def _build_pe(imports, text_section=b"\x90" * 64, text_exec=True, text_write=False):
    """Construct a minimal but parseable PE32 with the given imports.

    imports: list of (dll_name, [func, ...])
    We use the convention VirtualAddress == PointerToRawData per section, so an
    RVA equals a file offset inside its section -- which keeps the builder (and
    the parser's rva->offset mapping) simple.
    """
    FILE_ALIGN = 0x200
    headers_size = 0x400
    text_rva = 0x1000
    text_ptr = headers_size
    text_raw = (len(text_section) + FILE_ALIGN - 1) // FILE_ALIGN * FILE_ALIGN

    idata_rva = 0x2000
    idata_ptr = text_ptr + text_raw

    # --- build the .idata contents (import descriptors + ILT + names) ---
    # layout inside idata (local offsets, rva = idata_rva + local):
    descr_count = len(imports) + 1
    descr_size = descr_count * 20
    cursor = descr_size

    # reserve ILT arrays
    ilt_offsets = []
    for dll, funcs in imports:
        ilt_offsets.append(cursor)
        cursor += (len(funcs) + 1) * 4  # 4-byte thunks (PE32), null-terminated

    # hint/name entries
    name_rva_of = {}
    for dll, funcs in imports:
        for fn in funcs:
            name_rva_of[(dll, fn)] = idata_rva + cursor
            entry = struct.pack("<H", 0) + fn.encode() + b"\x00"
            if len(entry) % 2:
                entry += b"\x00"
            cursor += len(entry)

    # dll name strings
    dll_name_rva = {}
    for dll, funcs in imports:
        dll_name_rva[dll] = idata_rva + cursor
        s = dll.encode() + b"\x00"
        if len(s) % 2:
            s += b"\x00"
        cursor += len(s)

    idata = bytearray(cursor)

    # write descriptors
    for i, (dll, funcs) in enumerate(imports):
        off = i * 20
        ilt_rva = idata_rva + ilt_offsets[i]
        struct.pack_into("<IIIII", idata, off,
                         ilt_rva, 0, 0, dll_name_rva[dll], ilt_rva)
    # terminating null descriptor already zero

    # write ILTs
    for i, (dll, funcs) in enumerate(imports):
        base = ilt_offsets[i]
        for j, fn in enumerate(funcs):
            struct.pack_into("<I", idata, base + j * 4, name_rva_of[(dll, fn)])
        # null terminator already zero

    # write hint/name entries
    for dll, funcs in imports:
        for fn in funcs:
            local = name_rva_of[(dll, fn)] - idata_rva
            entry = struct.pack("<H", 0) + fn.encode() + b"\x00"
            idata[local:local + len(entry)] = entry

    # write dll names
    for dll in dll_name_rva:
        local = dll_name_rva[dll] - idata_rva
        s = dll.encode() + b"\x00"
        idata[local:local + len(s)] = s

    idata_raw = (len(idata) + FILE_ALIGN - 1) // FILE_ALIGN * FILE_ALIGN

    # --- optional header + data directories ---
    num_dirs = 16
    opt = bytearray(96 + num_dirs * 8)
    struct.pack_into("<H", opt, 0, 0x10B)              # PE32 magic
    struct.pack_into("<I", opt, 16, text_rva)          # entry point
    struct.pack_into("<I", opt, 20, text_rva)          # base of code
    struct.pack_into("<I", opt, 28, 0x400000)          # image base
    struct.pack_into("<I", opt, 32, 0x1000)            # section alignment
    struct.pack_into("<I", opt, 36, FILE_ALIGN)        # file alignment
    struct.pack_into("<I", opt, 92, num_dirs)          # NumberOfRvaAndSizes
    # data directory index 1 = import table
    struct.pack_into("<II", opt, 96 + 8 * 1, idata_rva, descr_size)

    # --- section headers ---
    def sec_header(name, vsize, rva, raw_size, raw_ptr, chars):
        h = bytearray(40)
        h[0:len(name)] = name
        struct.pack_into("<I", h, 8, vsize)
        struct.pack_into("<I", h, 12, rva)
        struct.pack_into("<I", h, 16, raw_size)
        struct.pack_into("<I", h, 20, raw_ptr)
        struct.pack_into("<I", h, 36, chars)
        return bytes(h)

    text_chars = 0x20000000 if text_exec else 0  # MEM_EXECUTE
    text_chars |= 0x80000000 if text_write else 0  # MEM_WRITE
    text_chars |= 0x00000020                       # CNT_CODE
    idata_chars = 0x40000000 | 0xC0000000          # readable/initialized

    sections = (
        sec_header(b".text", len(text_section), text_rva, text_raw, text_ptr, text_chars)
        + sec_header(b".idata", len(idata), idata_rva, idata_raw, idata_ptr, idata_chars)
    )

    # --- COFF header ---
    coff = struct.pack("<HHIIIHH",
                       0x14C,          # Machine i386
                       2,              # NumberOfSections
                       0, 0, 0,        # timestamp, symtab ptr, num symbols
                       len(opt),       # SizeOfOptionalHeader
                       0x102)          # Characteristics EXECUTABLE_IMAGE|32BIT

    pe_header = b"PE\x00\x00" + coff + bytes(opt) + sections

    # --- DOS header ---
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)   # e_lfanew -> PE header at 0x40

    out = bytearray(headers_size)
    out[0:len(dos)] = dos
    out[0x40:0x40 + len(pe_header)] = pe_header

    # section bodies
    body = bytearray()
    tsec = text_section + b"\x00" * (text_raw - len(text_section))
    body += tsec
    isec = bytes(idata) + b"\x00" * (idata_raw - len(idata))
    body += isec
    return bytes(out) + bytes(body)


def clean_pe() -> bytes:
    """A benign-looking PE: ordinary imports, non-packed, not W^X."""
    return _build_pe(
        imports=[("KERNEL32.dll", ["GetProcAddress", "LoadLibraryA", "ExitProcess"]),
                 ("USER32.dll", ["MessageBoxA"])],
        text_section=b"\x90" * 128,     # low-entropy "code"
        text_exec=True, text_write=False,
    )


def injector_pe() -> bytes:
    """A process-injection-shaped PE: injection imports + packed W^X section."""
    return _build_pe(
        imports=[("KERNEL32.dll", ["VirtualAllocEx", "WriteProcessMemory",
                                    "CreateRemoteThread", "OpenProcess"])],
        text_section=os.urandom(4096),   # high-entropy "packed" code
        text_exec=True, text_write=True,  # W^X
    )


def _moderate_body(n: int = 4096) -> bytes:
    """A realistic (>3 KB, moderate-entropy) code section: real malware is not a
    tiny stub, and a file this size lets the learned detectors actually run
    (they abstain below 3 KB). Half machine-code-like, half 0x90 padding."""
    return bytes(os.urandom(1)[0] if (i % 2) else 0x90 for i in range(n))


def ransomware_pe() -> bytes:
    return _build_pe(
        imports=[("ADVAPI32.dll", ["CryptAcquireContextA", "CryptEncrypt", "CryptGenKey"]),
                 ("KERNEL32.dll", ["FindFirstFileW", "FindNextFileW"])],
        text_section=_moderate_body(),
        text_exec=True, text_write=False,
    )


def rat_pe() -> bytes:
    """A remote-access-trojan shape: injection + network (download/exec + C2)."""
    return _build_pe(
        imports=[("KERNEL32.dll", ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]),
                 ("WININET.dll", ["InternetOpenW", "InternetOpenUrlW"]),
                 ("WS2_32.dll", ["connect", "send", "recv"])],
        text_section=_moderate_body(),
        text_exec=True, text_write=True,
    )


def keylogger_pe() -> bytes:
    """A keylogger shape: keystroke hooks + a file/network exfiltration import."""
    return _build_pe(
        imports=[("USER32.dll", ["GetAsyncKeyState", "SetWindowsHookExW", "GetForegroundWindow"]),
                 ("KERNEL32.dll", ["CreateFileW", "WriteFile"])],
        text_section=_moderate_body(),
        text_exec=True, text_write=False,
    )
