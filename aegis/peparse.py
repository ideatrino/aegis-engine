"""A tiny, defensive, dependency-free structural parser for PE and ELF.

The point is NOT to be a full loader. It is to extract the few structural facts
the detectors actually reason about -- section entropies, W^X violations, the
import table, and (for PE) the presence of an Authenticode signature and the
Mandiant imphash -- while treating every field as hostile input that may be
truncated or lying. Any parse error degrades to "unknown structure", never a
crash.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .entropy import shannon_entropy


@dataclass
class Section:
    name: str
    entropy: float
    executable: bool
    writable: bool

    @property
    def wx(self) -> bool:
        return self.executable and self.writable


@dataclass
class BinaryInfo:
    fmt: str                              # "pe" | "elf" | "unknown"
    sections: List[Section] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)      # "dll.func" / symbol
    signed: bool = False                 # PE: Authenticode block present
    imphash: Optional[str] = None        # PE: Mandiant import hash
    elf_type: Optional[int] = None       # ELF e_type (2=EXEC, 3=DYN, 1=REL)

    @property
    def is_relocatable_object(self) -> bool:
        return self.fmt == "elf" and self.elf_type == 1  # ET_REL -> compiler output

    @property
    def max_section_entropy(self) -> float:
        return max((s.entropy for s in self.sections), default=0.0)

    @property
    def has_wx(self) -> bool:
        return any(s.wx for s in self.sections)


def identify(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    # Mach-O (macOS) -- thin only; CAFEBABE fat is ambiguous with Java .class
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    return "unknown"


def looks_native(data: bytes) -> bool:
    """True for a PE/ELF/Mach-O image -- worth structural parsing."""
    return identify(data) != "unknown"


def parse(data: bytes) -> BinaryInfo:
    fmt = identify(data)
    try:
        if fmt == "pe":
            return _parse_pe(data)
        if fmt == "elf":
            return _parse_elf(data)
        if fmt == "macho":
            return _parse_macho(data)
    except Exception:
        return BinaryInfo(fmt=fmt)      # hostile/truncated input -> unknown structure
    return BinaryInfo(fmt="unknown")


# ------------------------------------------------------------------------ Mach-O
def _parse_macho(data: bytes) -> BinaryInfo:
    info = BinaryInfo(fmt="macho")
    if len(data) < 28:
        return info
    le = data[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
    is64 = data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    en = "<" if le else ">"
    try:
        ncmds = struct.unpack_from(en + "I", data, 16)[0]
        off = 32 if is64 else 28
        sections = []
        for _ in range(min(ncmds, 256)):
            if off + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(en + "II", data, off)
            if cmdsize == 0:
                break
            if cmd in (0x1, 0x19):                # LC_SEGMENT / LC_SEGMENT_64
                wide = cmd == 0x19
                name = data[off + 8:off + 24].rstrip(b"\x00").decode("latin-1", "replace")
                if wide:
                    foff = struct.unpack_from(en + "Q", data, off + 40)[0]
                    fsz = struct.unpack_from(en + "Q", data, off + 48)[0]
                    maxprot = struct.unpack_from(en + "i", data, off + 56)[0]
                else:
                    foff = struct.unpack_from(en + "I", data, off + 32)[0]
                    fsz = struct.unpack_from(en + "I", data, off + 36)[0]
                    maxprot = struct.unpack_from(en + "i", data, off + 44)[0]
                body = data[foff:foff + fsz] if fsz and foff else b""
                sections.append(Section(
                    name=name,
                    entropy=shannon_entropy(body[:1 << 20]) if body else 0.0,
                    executable=bool(maxprot & 0x4),
                    writable=bool(maxprot & 0x2),
                ))
            off += cmdsize
        info.sections = sections
    except Exception:
        pass
    return info


# --------------------------------------------------------------------------- PE
def _parse_pe(data: bytes) -> BinaryInfo:
    info = BinaryInfo(fmt="pe")
    if len(data) < 0x40:
        return info
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return info
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    if opt + 2 > len(data):
        return info
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32plus = magic == 0x20B

    # Authenticode lives in data directory index 4 (certificate table).
    # Directory offset differs between PE32 and PE32+.
    num_dir_off = opt + (108 if pe32plus else 92)
    dir_base = opt + (112 if pe32plus else 96)
    num_dirs = 0
    try:
        num_dirs = struct.unpack_from("<I", data, num_dir_off)[0]
        if num_dirs > 4:
            sec_rva, sec_sz = struct.unpack_from("<II", data, dir_base + 8 * 4)
            info.signed = sec_rva != 0 and sec_sz != 0
    except struct.error:
        pass

    # Sections
    sec_table = opt + opt_size
    sections = []
    for i in range(num_sections):
        off = sec_table + i * 40
        if off + 40 > len(data):
            break
        raw_name = data[off:off + 8].rstrip(b"\x00")
        name = raw_name.decode("latin-1", "replace")
        vsize = struct.unpack_from("<I", data, off + 8)[0]
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
        chars = struct.unpack_from("<I", data, off + 36)[0]
        body = data[raw_ptr:raw_ptr + raw_size] if raw_ptr and raw_size else b""
        sections.append(Section(
            name=name,
            entropy=shannon_entropy(body) if body else 0.0,
            executable=bool(chars & 0x20000000),   # IMAGE_SCN_MEM_EXECUTE
            writable=bool(chars & 0x80000000),      # IMAGE_SCN_MEM_WRITE
        ))
    info.sections = sections

    imports, imphash = _pe_imports(data, opt, pe32plus, num_dirs)
    info.imports = imports
    info.imphash = imphash
    return info


def _rva_to_off(data: bytes, rva: int, sections_raw: List[Tuple[int, int, int]]) -> Optional[int]:
    for va, vsz, ptr in sections_raw:
        if va <= rva < va + max(vsz, 1):
            return ptr + (rva - va)
    return None


def _pe_imports(data: bytes, opt: int, pe32plus: bool, num_dirs: int):
    """Extract imported symbols and compute the Mandiant imphash.

    imphash = md5 of the ordered, lower-cased 'dll.func' list (ordinals as
    'ord<n>', dll extension stripped) -- a family fingerprint: every sample
    built from one source shares it even after a recompile.
    """
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        coff = e_lfanew + 4
        num_sections = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        if num_dirs <= 1:
            num_dir_off = opt + (108 if pe32plus else 92)
            num_dirs = struct.unpack_from("<I", data, num_dir_off)[0]
        dir_base = opt + (112 if pe32plus else 96)
        imp_rva, imp_sz = struct.unpack_from("<II", data, dir_base + 8 * 1)  # index 1 = imports
        if not imp_rva:
            return [], None
        sec_table = opt + opt_size
        sections_raw = []
        for i in range(num_sections):
            off = sec_table + i * 40
            if off + 40 > len(data):
                break
            va = struct.unpack_from("<I", data, off + 12)[0]
            vsz = struct.unpack_from("<I", data, off + 8)[0]
            ptr = struct.unpack_from("<I", data, off + 20)[0]
            sections_raw.append((va, vsz, ptr))

        imports: List[str] = []
        imphash_parts: List[str] = []
        idt = _rva_to_off(data, imp_rva, sections_raw)
        if idt is None:
            return [], None
        for n in range(256):                       # bounded: never trust the count
            ent = idt + n * 20
            if ent + 20 > len(data):
                break
            orig_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, ent)
            if name_rva == 0 and first_thunk == 0:
                break
            dll_off = _rva_to_off(data, name_rva, sections_raw)
            if dll_off is None:
                continue
            dll = _cstr(data, dll_off).lower()
            dll_base = dll.rsplit(".", 1)[0] if "." in dll else dll
            thunk_rva = orig_thunk or first_thunk
            toff = _rva_to_off(data, thunk_rva, sections_raw)
            if toff is None:
                continue
            ptr_size = 8 if pe32plus else 4
            high_bit = (1 << (ptr_size * 8 - 1))
            for k in range(1024):
                te = toff + k * ptr_size
                if te + ptr_size > len(data):
                    break
                val = int.from_bytes(data[te:te + ptr_size], "little")
                if val == 0:
                    break
                if val & high_bit:                 # import by ordinal
                    ordn = val & 0xFFFF
                    fn = f"ord{ordn}"
                else:
                    foff = _rva_to_off(data, (val & 0x7FFFFFFF) + 2, sections_raw)
                    if foff is None:
                        continue
                    fn = _cstr(data, foff)
                if fn:
                    imports.append(f"{dll}.{fn}")
                    imphash_parts.append(f"{dll_base}.{fn.lower()}")
        imphash = hashlib.md5(",".join(imphash_parts).encode()).hexdigest() if imphash_parts else None
        return imports, imphash
    except Exception:
        return [], None


def _cstr(data: bytes, off: int, limit: int = 256) -> str:
    end = data.find(b"\x00", off, off + limit)
    if end == -1:
        end = min(off + limit, len(data))
    return data[off:end].decode("latin-1", "replace")


# -------------------------------------------------------------------------- ELF
def _parse_elf(data: bytes) -> BinaryInfo:
    info = BinaryInfo(fmt="elf")
    if len(data) < 20:
        return info
    is64 = data[4] == 2
    le = data[5] == 1
    endian = "<" if le else ">"
    try:
        e_type = struct.unpack_from(endian + "H", data, 16)[0]
    except struct.error:
        return info
    info.elf_type = e_type

    # Section headers -> per-section entropy + W^X.
    try:
        if is64:
            e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
            e_shentsize = struct.unpack_from(endian + "H", data, 58)[0]
            e_shnum = struct.unpack_from(endian + "H", data, 60)[0]
            e_shstrndx = struct.unpack_from(endian + "H", data, 62)[0]
        else:
            e_shoff = struct.unpack_from(endian + "I", data, 32)[0]
            e_shentsize = struct.unpack_from(endian + "H", data, 46)[0]
            e_shnum = struct.unpack_from(endian + "H", data, 48)[0]
            e_shstrndx = struct.unpack_from(endian + "H", data, 50)[0]

        # locate the section-header string table
        strtab_off = None
        if 0 <= e_shstrndx < e_shnum:
            sh = e_shoff + e_shstrndx * e_shentsize
            strtab_off = struct.unpack_from(endian + ("Q" if is64 else "I"),
                                            data, sh + (24 if is64 else 16))[0]

        sections = []
        for i in range(min(e_shnum, 128)):
            sh = e_shoff + i * e_shentsize
            if sh + e_shentsize > len(data):
                break
            name_idx = struct.unpack_from(endian + "I", data, sh)[0]
            if is64:
                flags = struct.unpack_from(endian + "Q", data, sh + 8)[0]
                offset = struct.unpack_from(endian + "Q", data, sh + 24)[0]
                size = struct.unpack_from(endian + "Q", data, sh + 32)[0]
            else:
                flags = struct.unpack_from(endian + "I", data, sh + 8)[0]
                offset = struct.unpack_from(endian + "I", data, sh + 16)[0]
                size = struct.unpack_from(endian + "I", data, sh + 20)[0]
            name = ""
            if strtab_off is not None:
                name = _cstr(data, strtab_off + name_idx, 64)
            body = data[offset:offset + size] if size and offset else b""
            sections.append(Section(
                name=name,
                entropy=shannon_entropy(body) if body else 0.0,
                executable=bool(flags & 0x4),   # SHF_EXECINSTR
                writable=bool(flags & 0x1),      # SHF_WRITE
            ))
        info.sections = sections
    except Exception:
        pass
    return info
