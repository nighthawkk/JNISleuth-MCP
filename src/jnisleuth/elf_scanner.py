"""Pure-Python 32/64-bit ELF shared object (.so) parser for JNI symbol, section, and relocation analysis."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct

ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFCLASS64 = 2

PT_LOAD = 1
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_REL = 9
SHT_DYNSYM = 11
SHT_INIT_ARRAY = 14

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183

R_AARCH64_RELATIVE = 1027
R_X86_64_RELATIVE = 8
R_ARM_RELATIVE = 23
R_386_RELATIVE = 8


@dataclass
class ElfSection:
    name: str
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_entsize: int


@dataclass
class ElfSegment:
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_filesz: int
    p_memsz: int


@dataclass
class ElfSymbol:
    name: str
    st_value: int
    st_size: int
    st_info: int
    st_shndx: int

    @property
    def is_defined_function(self) -> bool:
        return self.st_shndx != 0 and self.st_value != 0


class ElfBinary:
    """Parses an Android NDK ELF `.so` binary for JNI exports, sections, and relocations."""

    def __init__(self, data: bytes, name: str = "libunknown.so", path: str = "") -> None:
        self.data = data
        self.name = name
        self.path = path or name
        if len(data) < 64 or data[:4] != ELF_MAGIC:
            raise ValueError(f"{name}: Invalid ELF magic header")

        self.ei_class = data[4]
        self.is_64 = self.ei_class == ELFCLASS64
        self.ptr_size = 8 if self.is_64 else 4
        self.endian = "<" if data[5] == 1 else ">"

        self.e_machine = 0
        self.e_entry = 0
        self.segments: list[ElfSegment] = []
        self.sections: list[ElfSection] = []
        self.symbols: list[ElfSymbol] = []
        self.relocations: dict[int, int] = {}

        self._parse_elf()

    @classmethod
    def from_file(cls, file_path: str | Path) -> ElfBinary:
        p = Path(file_path)
        return cls(p.read_bytes(), name=p.name, path=str(p))

    @property
    def arch_abi(self) -> str:
        return {
            EM_AARCH64: "arm64-v8a",
            EM_ARM: "armeabi-v7a",
            EM_X86_64: "x86_64",
            EM_386: "x86",
        }.get(self.e_machine, f"unknown({self.e_machine})")

    def _parse_elf(self) -> None:
        if self.is_64:
            (
                _e_type,
                self.e_machine,
                _e_version,
                self.e_entry,
                e_phoff,
                e_shoff,
                _e_flags,
                _e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
            ) = struct.unpack_from(f"{self.endian}HHIQQQIHHHHHH", self.data, 16)
        else:
            (
                _e_type,
                self.e_machine,
                _e_version,
                self.e_entry,
                e_phoff,
                e_shoff,
                _e_flags,
                _e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
            ) = struct.unpack_from(f"{self.endian}HHIIIIIHHHHHH", self.data, 16)

        # Parse Program Headers
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + e_phentsize > len(self.data):
                break
            if self.is_64:
                p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = (
                    struct.unpack_from(f"{self.endian}IIQQQQQQ", self.data, off)
                )
            else:
                p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags, _p_align = (
                    struct.unpack_from(f"{self.endian}IIIIIIII", self.data, off)
                )
            self.segments.append(
                ElfSegment(
                    p_type=p_type,
                    p_flags=p_flags,
                    p_offset=p_offset,
                    p_vaddr=p_vaddr,
                    p_filesz=p_filesz,
                    p_memsz=p_memsz,
                )
            )

        # Parse Section Headers
        raw_sections: list[tuple[int, int, int, int, int, int, int, int]] = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if off + e_shentsize > len(self.data):
                break
            if self.is_64:
                (
                    sh_name,
                    sh_type,
                    sh_flags,
                    sh_addr,
                    sh_offset,
                    sh_size,
                    sh_link,
                    _sh_info,
                    _sh_addralign,
                    sh_entsize,
                ) = struct.unpack_from(f"{self.endian}IIQQQQIIQQ", self.data, off)
            else:
                (
                    sh_name,
                    sh_type,
                    sh_flags,
                    sh_addr,
                    sh_offset,
                    sh_size,
                    sh_link,
                    _sh_info,
                    _sh_addralign,
                    sh_entsize,
                ) = struct.unpack_from(f"{self.endian}IIIIIIIIII", self.data, off)
            raw_sections.append(
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_entsize)
            )

        shstrtab = b""
        if 0 <= e_shstrndx < len(raw_sections):
            _, _, _, _, str_off, str_sz, _, _ = raw_sections[e_shstrndx]
            shstrtab = self.data[str_off : str_off + str_sz]

        for (
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_entsize,
        ) in raw_sections:
            sec_name = self._read_cstr_from_buf(shstrtab, sh_name)
            self.sections.append(
                ElfSection(
                    name=sec_name,
                    sh_type=sh_type,
                    sh_flags=sh_flags,
                    sh_addr=sh_addr,
                    sh_offset=sh_offset,
                    sh_size=sh_size,
                    sh_link=sh_link,
                    sh_entsize=sh_entsize,
                )
            )

        # Parse Symbols (.dynsym and .symtab)
        for sec in self.sections:
            if sec.sh_type in (SHT_DYNSYM, SHT_SYMTAB) and 0 <= sec.sh_link < len(self.sections):
                str_sec = self.sections[sec.sh_link]
                str_buf = self.data[str_sec.sh_offset : str_sec.sh_offset + str_sec.sh_size]
                ent_size = sec.sh_entsize or (24 if self.is_64 else 16)
                count = sec.sh_size // ent_size if ent_size else 0
                for idx in range(count):
                    ent_off = sec.sh_offset + idx * ent_size
                    if ent_off + ent_size > len(self.data):
                        break
                    if self.is_64:
                        st_name, st_info, _st_other, st_shndx, st_value, st_size = (
                            struct.unpack_from(f"{self.endian}IBBHQQ", self.data, ent_off)
                        )
                    else:
                        st_name, st_value, st_size, st_info, _st_other, st_shndx = (
                            struct.unpack_from(f"{self.endian}IIIBBH", self.data, ent_off)
                        )
                    sym_name = self._read_cstr_from_buf(str_buf, st_name)
                    if sym_name:
                        self.symbols.append(
                            ElfSymbol(
                                name=sym_name,
                                st_value=st_value,
                                st_size=st_size,
                                st_info=st_info,
                                st_shndx=st_shndx,
                            )
                        )

        # Parse Relocations (.rela.dyn, .rel.dyn)
        for sec in self.sections:
            if sec.sh_type == SHT_RELA:
                if self.is_64:
                    ent_size = sec.sh_entsize or 24
                    count = sec.sh_size // ent_size
                    for idx in range(count):
                        ent_off = sec.sh_offset + idx * ent_size
                        if ent_off + 24 > len(self.data):
                            break
                        r_offset, r_info, r_addend = struct.unpack_from(
                            f"{self.endian}QQq", self.data, ent_off
                        )
                        r_type = r_info & 0xFFFFFFFF
                        if r_type in (R_AARCH64_RELATIVE, R_X86_64_RELATIVE) and r_addend > 0:
                            self.relocations[r_offset] = r_addend
                else:
                    ent_size = sec.sh_entsize or 12
                    count = sec.sh_size // ent_size
                    for idx in range(count):
                        ent_off = sec.sh_offset + idx * ent_size
                        if ent_off + 12 > len(self.data):
                            break
                        r_offset, r_info, r_addend = struct.unpack_from(
                            f"{self.endian}IIi", self.data, ent_off
                        )
                        r_type = r_info & 0xFF
                        if r_type in (R_ARM_RELATIVE, R_386_RELATIVE) and r_addend > 0:
                            self.relocations[r_offset] = r_addend

    @staticmethod
    def _read_cstr_from_buf(buf: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(buf):
            return ""
        end = buf.find(b"\x00", offset)
        if end == -1:
            end = len(buf)
        return buf[offset:end].decode("utf-8", errors="replace")

    def va_to_offset(self, va: int) -> int | None:
        """Translates a virtual address (VA) to a file offset using PT_LOAD segments or sections."""
        for seg in self.segments:
            if seg.p_type == PT_LOAD and seg.p_vaddr <= va < seg.p_vaddr + seg.p_filesz:
                off = seg.p_offset + (va - seg.p_vaddr)
                if 0 <= off < len(self.data):
                    return off
        for sec in self.sections:
            if sec.sh_addr > 0 and sec.sh_addr <= va < sec.sh_addr + sec.sh_size:
                off = sec.sh_offset + (va - sec.sh_addr)
                if 0 <= off < len(self.data):
                    return off
        return None

    def offset_to_va(self, file_offset: int) -> int:
        """Translates a file offset to its loaded virtual address."""
        for seg in self.segments:
            if seg.p_type == PT_LOAD and seg.p_offset <= file_offset < seg.p_offset + seg.p_filesz:
                return seg.p_vaddr + (file_offset - seg.p_offset)
        for sec in self.sections:
            if sec.sh_offset <= file_offset < sec.sh_offset + sec.sh_size:
                return sec.sh_addr + (file_offset - sec.sh_offset)
        return file_offset

    def is_executable_va(self, va: int) -> bool:
        """Returns True if `va` points inside an executable PT_LOAD segment or `.text` section."""
        if va <= 0:
            return False
        clean_va = va & ~1 if self.e_machine == EM_ARM else va
        for sec in self.sections:
            if (sec.sh_flags & SHF_EXECINSTR) and sec.sh_addr <= clean_va < sec.sh_addr + sec.sh_size:
                return True
        for seg in self.segments:
            if (
                seg.p_type == PT_LOAD
                and (seg.p_flags & PF_X)
                and seg.p_vaddr <= clean_va < seg.p_vaddr + seg.p_filesz
            ):
                return True
        return False

    def read_pointer_at(self, file_offset: int, va: int | None = None) -> int:
        """Reads a pointer at `file_offset`, applying `.rela.dyn` relative relocation if present."""
        if va is None:
            va = self.offset_to_va(file_offset)
        if va in self.relocations:
            return self.relocations[va]
        fmt = f"{self.endian}Q" if self.is_64 else f"{self.endian}I"
        if file_offset < 0 or file_offset + self.ptr_size > len(self.data):
            return 0
        return struct.unpack_from(fmt, self.data, file_offset)[0]

    def read_cstring_at_va(self, va: int, max_len: int = 512) -> str | None:
        """Reads a null-terminated printable ASCII/UTF-8 string at virtual address `va`."""
        off = self.va_to_offset(va)
        if off is None or off < 0 or off >= len(self.data):
            return None
        end = self.data.find(b"\x00", off, min(len(self.data), off + max_len))
        if end == -1 or end == off:
            return None
        raw = self.data[off:end]
        if any(b < 0x20 or b > 0x7E for b in raw):
            return None
        return raw.decode("ascii", errors="strict")

    def get_section_by_name(self, name: str) -> ElfSection | None:
        for sec in self.sections:
            if sec.name == name:
                return sec
        return None

    def get_exported_jni_symbols(self) -> list[ElfSymbol]:
        """Returns all defined `Java_*` exported symbols in the ELF binary."""
        seen: set[str] = set()
        out: list[ElfSymbol] = []
        for sym in self.symbols:
            if sym.is_defined_function and sym.name.startswith("Java_") and sym.name not in seen:
                seen.add(sym.name)
                out.append(sym)
        return out

    def find_symbol(self, name: str) -> ElfSymbol | None:
        for sym in self.symbols:
            if sym.name == name and sym.is_defined_function:
                return sym
        return None
