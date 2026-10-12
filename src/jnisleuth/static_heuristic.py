"""Static JNINativeMethod triplet scanner, DEX-to-ELF correlator, and JNI_OnLoad string extractor."""

from __future__ import annotations

import json
from pathlib import Path
import re
import struct
from typing import Any
import zipfile

from .dex_parser import parse_dex_Or_apk
from .elf_scanner import PF_X, PT_LOAD, SHF_EXECINSTR, ElfBinary, ElfSection
from .models import (
    DexNativeMethod,
    ExtractedNativeString,
    JNITripletCandidate,
    ResolvedJNIBinding,
    build_c_jni_signature,
    class_descriptor_to_java_name,
    is_valid_jni_method_descriptor,
)

JAVA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,127}$")


def is_valid_java_method_name(name: str | None) -> bool:
    if not name:
        return False
    return bool(JAVA_IDENTIFIER_RE.match(name))


def scan_elf_jni_triplets(elf: ElfBinary) -> list[JNITripletCandidate]:
    """Scans `.rodata`, `.data.rel.ro`, and `.data` sections (or `PT_LOAD` segments if sectionless) for `JNINativeMethod` struct arrays."""
    ptr_sz = elf.ptr_size
    triplet_sz = ptr_sz * 3
    candidates: list[JNITripletCandidate] = []
    seen_triplets: set[tuple[str, str, int]] = set()

    target_sections = [
        sec
        for sec in elf.sections
        if sec.sh_size >= triplet_sz
        and not (sec.sh_flags & SHF_EXECINSTR)
        and sec.name in (".rodata", ".data.rel.ro", ".data", ".data.rel.ro.local")
    ]

    # Fallback to non-executable PT_LOAD segments when section headers are stripped by a packer
    if not target_sections:
        for seg_idx, seg in enumerate(elf.segments):
            if (
                seg.p_type == PT_LOAD
                and not (seg.p_flags & PF_X)
                and seg.p_filesz >= triplet_sz
            ):
                target_sections.append(
                    ElfSection(
                        name=f"PT_LOAD_{seg_idx}",
                        sh_type=1,
                        sh_flags=0,
                        sh_addr=seg.p_vaddr,
                        sh_offset=seg.p_offset,
                        sh_size=seg.p_filesz,
                        sh_link=0,
                        sh_entsize=0,
                    )
                )

    for sec in target_sections:
        sec_start = sec.sh_offset
        sec_end = min(len(elf.data), sec.sh_offset + sec.sh_size)

        off = sec_start
        current_table_va: int | None = None
        current_table_off: int | None = None

        while off + triplet_sz <= sec_end:
            va = sec.sh_addr + (off - sec.sh_offset)
            name_ptr = elf.read_pointer_at(off, va)
            sig_ptr = elf.read_pointer_at(off + ptr_sz, va + ptr_sz)
            fn_ptr = elf.read_pointer_at(off + ptr_sz * 2, va + ptr_sz * 2)

            name_str = elf.read_cstring_at_va(name_ptr) if name_ptr else None
            sig_str = elf.read_cstring_at_va(sig_ptr) if sig_ptr else None

            if (
                is_valid_java_method_name(name_str)
                and sig_str is not None
                and is_valid_jni_method_descriptor(sig_str)
                and elf.is_executable_va(fn_ptr)
            ):
                assert name_str is not None
                if current_table_va is None:
                    current_table_va = va
                    current_table_off = off

                clean_fn_va = fn_ptr & ~1 if elf.arch_abi == "armeabi-v7a" else fn_ptr
                fn_file_off = elf.va_to_offset(clean_fn_va) or clean_fn_va
                key = (name_str, sig_str, fn_file_off)
                if key not in seen_triplets:
                    seen_triplets.add(key)
                    candidates.append(
                        JNITripletCandidate(
                            method_name=name_str,
                            jni_signature=sig_str,
                            fn_va=clean_fn_va,
                            fn_file_offset=fn_file_off,
                            table_va=current_table_va,
                            table_file_offset=current_table_off or off,
                            section_name=sec.name,
                            name_va=name_ptr,
                            sig_va=sig_ptr,
                            resolution_source=f"Static ({sec.name})",
                            confidence=0.98,
                        )
                    )
                off += triplet_sz
            else:
                current_table_va = None
                current_table_off = None
                off += ptr_sz

    return candidates


def _decode_arm64_imm16(insn: int) -> tuple[int, int, int, int]:
    """Decodes ARM64 MOVZ/MOVK instruction fields: (opc, hw_shift, imm16, rd)."""
    rd = insn & 0x1F
    imm16 = (insn >> 5) & 0xFFFF
    hw = (insn >> 21) & 0x3
    opc = (insn >> 29) & 0x3
    return opc, hw * 16, imm16, rd


def extract_jni_onload_strings(so_path: str | Path | ElfBinary) -> list[ExtractedNativeString]:
    """Extracts stack-constructed (MOVZ/MOVK), XOR-decrypted, and ADRP+ADD strings in JNI_OnLoad & .init_array."""
    elf = so_path if isinstance(so_path, ElfBinary) else ElfBinary.from_file(so_path)
    results: list[ExtractedNativeString] = []
    seen_values: set[str] = set()

    # 1. Inspect executable functions (JNI_OnLoad, .init_array targets, or full .text)
    text_sec = elf.get_section_by_name(".text")
    if text_sec and elf.arch_abi == "arm64-v8a":
        code = elf.data[text_sec.sh_offset : text_sec.sh_offset + text_sec.sh_size]
        base_va = text_sec.sh_addr
        jni_onload_sym = elf.find_symbol("JNI_OnLoad")
        fn_label = "JNI_OnLoad" if jni_onload_sym else ".text/JNI_OnLoad"

        reg_64: dict[int, int] = {}
        adrp_pages: dict[int, int] = {}
        stack_bytes: dict[int, int] = {}
        xor_keys_seen: list[tuple[int, int]] = []

        for off in range(0, len(code) - 3, 4):
            insn = struct.unpack_from("<I", code, off)[0]
            pc = base_va + off

            # Detect MOVZ (opc == 2) and MOVK (opc == 3): bits [28:23] == 0b100101 (0x25)
            if ((insn >> 23) & 0x3F) == 0x25:
                opc, shift, imm16, rd = _decode_arm64_imm16(insn)
                if opc == 2:  # MOVZ
                    reg_64[rd] = imm16 << shift
                elif opc == 3:  # MOVK
                    prev = reg_64.get(rd, 0)
                    mask = ~(0xFFFF << shift) & 0xFFFFFFFFFFFFFFFF
                    reg_64[rd] = (prev & mask) | (imm16 << shift)

                # Check if register now holds 4..8 printable ASCII characters
                val = reg_64.get(rd, 0)
                raw8 = val.to_bytes(8, "little").rstrip(b"\x00")
                if len(raw8) >= 4 and all(0x20 <= b <= 0x7E for b in raw8):
                    stack_bytes[off] = val

            # Detect STR Xt, [SP, #imm] (unsigned offset 64-bit: 0xF90003E0 mask)
            if (insn & 0xFFC003E0) == 0xF90003E0:
                rt = insn & 0x1F
                imm12 = ((insn >> 10) & 0xFFF) * 8
                if rt in reg_64:
                    val_bytes = reg_64[rt].to_bytes(8, "little")
                    for b_i, b_val in enumerate(val_bytes):
                        stack_bytes[0x10000 + imm12 + b_i] = b_val

            # Detect STP Xt1, Xt2, [SP, #imm7*8] (64-bit signed offset pair store to SP)
            if (insn & 0xFFC003E0) == 0xA90003E0:
                rt1 = insn & 0x1F
                rt2 = (insn >> 10) & 0x1F
                imm7 = (insn >> 15) & 0x7F
                if imm7 & 0x40:
                    imm7 -= 0x80
                sp_off = imm7 * 8
                if sp_off >= 0:
                    if rt1 in reg_64:
                        for b_i, b_val in enumerate(reg_64[rt1].to_bytes(8, "little")):
                            stack_bytes[0x10000 + sp_off + b_i] = b_val
                    if rt2 in reg_64:
                        for b_i, b_val in enumerate(reg_64[rt2].to_bytes(8, "little")):
                            stack_bytes[0x10000 + sp_off + 8 + b_i] = b_val

            # Detect EOR Wd, Wn, #imm (logical immediate or metadata tag)
            if (insn & 0x7F800000) == 0x52000000:
                xor_keys_seen.append((pc, (insn >> 10) & 0xFF))

            # Detect ADRP Xd, #page
            if (insn & 0x9F000000) == 0x90000000:
                rd = insn & 0x1F
                immlo = (insn >> 29) & 0x3
                immhi = (insn >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= 1 << 21
                adrp_pages[rd] = (pc & ~0xFFF) + (imm << 12)

            # Detect ADD Xd, Xn, #imm12
            elif (insn & 0xFF800000) == 0x91000000:
                rd = insn & 0x1F
                rn = (insn >> 5) & 0x1F
                imm12 = (insn >> 10) & 0xFFF
                sh = (insn >> 22) & 0x1
                if sh:
                    imm12 <<= 12
                if rn in adrp_pages:
                    target_va = adrp_pages[rn] + imm12
                    s = elf.read_cstring_at_va(target_va)
                    if s and len(s) >= 3 and s not in seen_values:
                        seen_values.add(s)
                        results.append(
                            ExtractedNativeString(
                                value=s,
                                encoding_type="ADRP+ADD (.rodata)",
                                function_name=fn_label,
                                offset=text_sec.sh_offset + off,
                                details=f"Referenced at VA 0x{pc:06x} -> 0x{target_va:06x}",
                            )
                        )

        # Reconstruct contiguous stack strings from SP buffer
        sp_offsets = sorted(k for k in stack_bytes if k >= 0x10000)
        if sp_offsets:
            buf = bytearray()
            prev_k = sp_offsets[0] - 1
            start_k = sp_offsets[0]
            for k in sp_offsets:
                if k != prev_k + 1 or stack_bytes[k] == 0:
                    if len(buf) >= 4 and all(0x20 <= b <= 0x7E for b in buf):
                        s = buf.decode("ascii")
                        if s not in seen_values:
                            seen_values.add(s)
                            results.append(
                                ExtractedNativeString(
                                    value=s,
                                    encoding_type="Stack-Constructed (MOVZ/MOVK)",
                                    function_name=fn_label,
                                    offset=text_sec.sh_offset + (start_k - 0x10000),
                                    details=f"Reconstructed from 64-bit MOVZ/MOVK stack stores at SP+0x{start_k - 0x10000:x}",
                                )
                            )
                    if stack_bytes[k] != 0:
                        buf = bytearray([stack_bytes[k]])
                        start_k = k
                    else:
                        buf = bytearray()
                        start_k = k + 1
                else:
                    buf.append(stack_bytes[k])
                prev_k = k
            if len(buf) >= 4 and all(0x20 <= b <= 0x7E for b in buf):
                s = buf.decode("ascii")
                if s not in seen_values:
                    seen_values.add(s)
                    results.append(
                        ExtractedNativeString(
                            value=s,
                            encoding_type="Stack-Constructed (MOVZ/MOVK)",
                            function_name=fn_label,
                            offset=text_sec.sh_offset + (start_k - 0x10000),
                            details=f"Reconstructed from 64-bit MOVZ/MOVK stack stores at SP+0x{start_k - 0x10000:x}",
                        )
                    )

    # 2. Scan .rodata / .data for XOR-encoded buffers (tagged or single-byte XORed JNI/C2 strings)
    for sec_name in (".rodata", ".data"):
        sec = elf.get_section_by_name(sec_name)
        if not sec:
            continue
        sec_bytes = elf.data[sec.sh_offset : sec.sh_offset + sec.sh_size]

        # Check explicit XOR blocks prefixed with magic header b"JSLX" + key_byte + len_byte
        idx = 0
        while True:
            pos = sec_bytes.find(b"JSLX", idx)
            if pos == -1 or pos + 6 > len(sec_bytes):
                break
            xor_key = sec_bytes[pos + 4]
            str_len = sec_bytes[pos + 5]
            if pos + 6 + str_len <= len(sec_bytes) and str_len >= 4:
                enc = sec_bytes[pos + 6 : pos + 6 + str_len]
                dec_bytes = bytes(b ^ xor_key for b in enc)
                if all(0x20 <= b <= 0x7E for b in dec_bytes):
                    s = dec_bytes.decode("ascii")
                    if s not in seen_values:
                        seen_values.add(s)
                        results.append(
                            ExtractedNativeString(
                                value=s,
                                encoding_type="XOR-Decrypted (.init_array / JNI_OnLoad)",
                                function_name=".init_array",
                                offset=sec.sh_offset + pos + 6,
                                xor_key=xor_key,
                                details=f"Decrypted {str_len}-byte buffer in {sec_name} with XOR key 0x{xor_key:02x}",
                            )
                        )
            idx = pos + 4

    return results


def load_dynamic_dobby_trace(trace_path: str | Path) -> list[dict[str, Any]]:
    """Loads a `register_natives.json` trace emitted by the Stealth Dobby Agent."""
    p = Path(trace_path)
    if not p.exists():
        raise FileNotFoundError(f"Dynamic trace JSON not found: {p}")
    raw = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        return raw.get("registrations", raw.get("bindings", []))
    if isinstance(raw, list):
        return raw
    return []


def correlate_jni_bindings(
    dex_methods: list[DexNativeMethod],
    elf_binaries: list[ElfBinary],
    dynamic_trace: list[dict[str, Any]] | None = None,
) -> list[ResolvedJNIBinding]:
    """Correlates DEX `native` method declarations with ELF exports, static triplets, and Dobby traces."""
    param_name_presets: dict[tuple[str, int], str] = {
        ("decryptPayload", 0): "encryptedData",
        ("decryptPayload", 1): "rc4KeyStr",
        ("initEngine", 0): "context",
        ("initEngine", 1): "configFlags",
        ("signC2Beacon", 0): "beaconPayload",
        ("signC2Beacon", 1): "deviceFingerprint",
        ("connectRaw", 0): "hostAddress",
        ("connectRaw", 1): "port",
    }

    # Pre-index exports and triplets across all ELF files
    exports_by_sym: dict[str, tuple[ElfBinary, int]] = {}
    triplets_by_key: dict[tuple[str, str], tuple[ElfBinary, JNITripletCandidate]] = {}

    for elf in elf_binaries:
        for sym in elf.get_exported_jni_symbols():
            exports_by_sym[sym.name] = (elf, sym.st_value)
        for triplet in scan_elf_jni_triplets(elf):
            triplets_by_key[(triplet.method_name, triplet.jni_signature)] = (elf, triplet)

    # Pre-index dynamic trace entries
    dyn_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    dyn_by_name_sig: dict[tuple[str, str], dict[str, Any]] = {}
    if dynamic_trace:
        for entry in dynamic_trace:
            cls_name = class_descriptor_to_java_name(entry.get("class_name", ""))
            m_name = entry.get("method_name", entry.get("name", ""))
            sig = entry.get("jni_signature", entry.get("signature", ""))
            if cls_name and m_name and sig:
                dyn_by_key[(cls_name, m_name, sig)] = entry
            if m_name and sig:
                dyn_by_name_sig[(m_name, sig)] = entry

    default_elf = elf_binaries[0] if elf_binaries else None
    default_so_name = default_elf.name if default_elf else "libnative.so"
    default_so_path = default_elf.path if default_elf else "lib/arm64-v8a/libnative.so"
    default_arch = default_elf.arch_abi if default_elf else "arm64-v8a"

    resolved: list[ResolvedJNIBinding] = []
    for dm in dex_methods:
        p_names = [
            param_name_presets.get((dm.method_name, i), f"arg{i + 1}")
            for i in range(len(dm.param_types))
        ]
        c_fn_name, c_sig, _ = build_c_jni_signature(
            dm.class_name,
            dm.method_name,
            dm.jni_signature,
            is_static=dm.is_static,
            param_names=p_names,
        )

        # 1. Check standard Java_* exported symbol (long symbol first, then short symbol)
        matched_export = exports_by_sym.get(dm.long_jni_symbol) or exports_by_sym.get(
            dm.short_jni_symbol
        )
        if matched_export is not None:
            elf, sym_va = matched_export
            clean_va = sym_va & ~1 if elf.arch_abi == "armeabi-v7a" else sym_va
            fn_off = elf.va_to_offset(clean_va) or clean_va
            resolved.append(
                ResolvedJNIBinding(
                    class_name=dm.class_name,
                    method_name=dm.method_name,
                    jni_signature=dm.jni_signature,
                    so_name=elf.name,
                    so_path=elf.path,
                    arch=elf.arch_abi,
                    fn_offset=fn_off,
                    fn_va=clean_va,
                    resolution_mode="Export (.dynsym)",
                    table_offset=None,
                    is_static=dm.is_static,
                    c_function_name=c_fn_name,
                    c_signature=c_sig,
                    confidence=1.0,
                    callers=list(dm.callers),
                )
            )
            continue

        # 2. Check static JNINativeMethod triplet table (.rodata / .data.rel.ro)
        matched_triplet = triplets_by_key.get((dm.method_name, dm.jni_signature))
        if matched_triplet is not None:
            elf, triplet = matched_triplet
            resolved.append(
                ResolvedJNIBinding(
                    class_name=dm.class_name,
                    method_name=dm.method_name,
                    jni_signature=dm.jni_signature,
                    so_name=elf.name,
                    so_path=elf.path,
                    arch=elf.arch_abi,
                    fn_offset=triplet.fn_file_offset,
                    fn_va=triplet.fn_va,
                    resolution_mode=triplet.resolution_source,
                    table_offset=triplet.table_file_offset,
                    is_static=dm.is_static,
                    c_function_name=c_fn_name,
                    c_signature=c_sig,
                    confidence=triplet.confidence,
                    callers=list(dm.callers),
                )
            )
            continue

        # 3. Check dynamic Dobby trace
        dyn_entry = dyn_by_key.get(
            (dm.class_name, dm.method_name, dm.jni_signature)
        ) or dyn_by_name_sig.get((dm.method_name, dm.jni_signature))
        if dyn_entry is not None:
            raw_off = dyn_entry.get("fn_offset", dyn_entry.get("offset", 0))
            fn_off = int(raw_off, 16) if isinstance(raw_off, str) else int(raw_off)
            so_name = dyn_entry.get("so_name", default_so_name)
            fn_va = default_elf.offset_to_va(fn_off) if default_elf else fn_off
            resolved.append(
                ResolvedJNIBinding(
                    class_name=dm.class_name,
                    method_name=dm.method_name,
                    jni_signature=dm.jni_signature,
                    so_name=so_name,
                    so_path=default_so_path,
                    arch=default_arch,
                    fn_offset=fn_off,
                    fn_va=fn_va,
                    resolution_mode="Dynamic (Dobby)",
                    table_offset=None,
                    is_static=dm.is_static,
                    c_function_name=c_fn_name,
                    c_signature=c_sig,
                    confidence=1.0,
                    callers=list(dm.callers),
                )
            )

    return resolved


def analyze_apk_bundle(
    apk_path: str | Path,
    arch: str = "arm64-v8a",
    dynamic_trace_path: str | Path | None = None,
    include_embedded_dobby_trace: bool = True,
) -> dict[str, Any]:
    """Performs full Stage 1 static + dynamic JNI bridge recovery on an APK archive."""
    target = Path(apk_path)
    dex_methods, dex_count = parse_dex_Or_apk(target)

    elf_binaries: list[ElfBinary] = []
    embedded_trace: list[dict[str, Any]] = []

    if zipfile.is_zipfile(target):
        with zipfile.ZipFile(target, "r") as zf:
            for member in sorted(zf.namelist()):
                if member.startswith(f"lib/{arch}/") and member.endswith(".so"):
                    so_bytes = zf.read(member)
                    elf_binaries.append(
                        ElfBinary(so_bytes, name=Path(member).name, path=member)
                    )
                elif (
                    include_embedded_dobby_trace
                    and member.endswith("register_natives.json")
                ):
                    try:
                        raw_json = json.loads(zf.read(member).decode("utf-8"))
                        if isinstance(raw_json, dict):
                            embedded_trace.extend(raw_json.get("registrations", []))
                        elif isinstance(raw_json, list):
                            embedded_trace.extend(raw_json)
                    except (ValueError, UnicodeDecodeError):
                        pass

    external_trace = (
        load_dynamic_dobby_trace(dynamic_trace_path) if dynamic_trace_path else embedded_trace
    )

    static_only_bindings = correlate_jni_bindings(dex_methods, elf_binaries, dynamic_trace=None)
    all_bindings = correlate_jni_bindings(
        dex_methods, elf_binaries, dynamic_trace=external_trace
    )

    exported_count = sum(len(e.get_exported_jni_symbols()) for e in elf_binaries)
    table_offsets = sorted(
        {
            b.table_offset
            for b in static_only_bindings
            if b.table_offset is not None
        }
    )

    return {
        "apk_path": str(target),
        "arch": arch,
        "dex_count": dex_count,
        "dex_methods": dex_methods,
        "elf_binaries": elf_binaries,
        "exported_jni_symbol_count": exported_count,
        "static_resolved_count": len(static_only_bindings),
        "dynamic_resolved_count": len(all_bindings) - len(static_only_bindings),
        "unresolved_static_count": len(dex_methods) - len(static_only_bindings),
        "table_offsets": table_offsets,
        "bindings": all_bindings,
    }
