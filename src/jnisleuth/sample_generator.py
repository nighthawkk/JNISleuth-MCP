"""Synthetic multi-DEX APK, stripped ARM64 ELF (.so), and Dobby trace generator for JNISleuth-MCP."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import zlib
import zipfile

from .elf_scanner import (
    ELF_MAGIC,
    ELFCLASS64,
    EM_AARCH64,
    PF_R,
    PF_W,
    PF_X,
    PT_LOAD,
    SHF_ALLOC,
    SHF_EXECINSTR,
    SHF_WRITE,
    SHT_DYNSYM,
    SHT_PROGBITS,
    SHT_STRTAB,
)
from .models import parse_jni_method_descriptor


def encode_uleb128(val: int) -> bytes:
    """Encodes a non-negative integer into unsigned LEB128 format."""
    out = bytearray()
    while True:
        byte = val & 0x7F
        val >>= 7
        if val != 0:
            byte |= 0x80
        out.append(byte)
        if val == 0:
            break
    return bytes(out)


def _shorty_from_type(jni_type: str) -> str:
    if jni_type.startswith(("L", "[")):
        return "L"
    return jni_type[0]


def build_dex_bytes(
    class_methods_spec: list[tuple[str, list[tuple[str, str, int]]]],
) -> bytes:
    """Builds a valid Dalvik Executable (`dex\\n035\\x00`) binary from class/method definitions.

    Also adds a synthetic Java caller method per class that executes `invoke-virtual` or
    `invoke-static` against each declared `native` method so cross-reference analysis works.
    """
    string_set: set[str] = {"V", "Ljava/lang/Object;", "SourceFile.java"}
    type_set: set[str] = {"V", "Ljava/lang/Object;"}
    proto_keys: set[tuple[str, tuple[str, ...], str]] = {("V", (), "V")}

    # Expand method list with synthetic Java caller methods
    expanded_classes: list[tuple[str, list[tuple[str, str, int, str | None]]]] = []
    for cls_desc, methods in class_methods_spec:
        type_set.add(cls_desc)
        string_set.add(cls_desc)
        cls_items: list[tuple[str, str, int, str | None]] = []
        for m_name, jni_sig, flags in methods:
            params, ret = parse_jni_method_descriptor(jni_sig)
            shorty = _shorty_from_type(ret) + "".join(_shorty_from_type(p) for p in params)
            string_set.add(m_name)
            string_set.add(shorty)
            type_set.add(ret)
            string_set.add(ret)
            for p in params:
                type_set.add(p)
                string_set.add(p)
            proto_keys.add((shorty, tuple(params), ret))
            cls_items.append((m_name, jni_sig, flags, None))

            # Add a non-native caller wrapper `call_<m_name>` that invokes `<m_name>`
            caller_name = f"invoke_{m_name}"
            string_set.add(caller_name)
            cls_items.append((caller_name, jni_sig, 0x0001, m_name))
        expanded_classes.append((cls_desc, cls_items))

    sorted_strings = sorted(string_set)
    str_to_idx = {s: i for i, s in enumerate(sorted_strings)}

    sorted_types = sorted(type_set, key=lambda t: str_to_idx[t])
    type_to_idx = {t: i for i, t in enumerate(sorted_types)}

    sorted_protos = sorted(
        proto_keys,
        key=lambda pk: (
            type_to_idx[pk[2]],
            tuple(type_to_idx[p] for p in pk[1]),
        ),
    )
    proto_to_idx = {pk: i for i, pk in enumerate(sorted_protos)}

    # Collect method_id tuples: (class_idx, proto_idx, name_idx)
    method_tuples: list[tuple[int, int, int, str, str, int, str | None]] = []
    for cls_desc, cls_items in expanded_classes:
        c_idx = type_to_idx[cls_desc]
        for m_name, jni_sig, flags, target_native in cls_items:
            params, ret = parse_jni_method_descriptor(jni_sig)
            shorty = _shorty_from_type(ret) + "".join(_shorty_from_type(p) for p in params)
            p_idx = proto_to_idx[(shorty, tuple(params), ret)]
            n_idx = str_to_idx[m_name]
            method_tuples.append((c_idx, p_idx, n_idx, cls_desc, m_name, flags, target_native))

    method_tuples.sort(key=lambda x: (x[0], x[2], x[1]))
    method_lookup: dict[tuple[str, str], int] = {
        (item[3], item[4]): idx for idx, item in enumerate(method_tuples)
    }

    # Layout fixed header & index tables
    header_size = 0x70
    string_ids_off = header_size
    type_ids_off = string_ids_off + len(sorted_strings) * 4
    proto_ids_off = type_ids_off + len(sorted_types) * 4
    field_ids_off = proto_ids_off + len(sorted_protos) * 12
    method_ids_off = field_ids_off
    class_defs_off = method_ids_off + len(method_tuples) * 8
    data_off = class_defs_off + len(expanded_classes) * 32

    data_buf = bytearray()

    def align4() -> None:
        while (len(data_buf) % 4) != 0:
            data_buf.append(0)

    # 1. Write string_data_items into data_buf
    string_data_offsets: list[int] = []
    for s in sorted_strings:
        string_data_offsets.append(data_off + len(data_buf))
        utf8_bytes = s.encode("utf-8")
        data_buf.extend(encode_uleb128(len(s)))
        data_buf.extend(utf8_bytes)
        data_buf.append(0)

    # 2. Write type_list items for protos with parameters
    proto_param_offsets: dict[tuple[str, tuple[str, ...], str], int] = {}
    for pk in sorted_protos:
        _, params_tup, _ = pk
        if not params_tup:
            proto_param_offsets[pk] = 0
        else:
            align4()
            proto_param_offsets[pk] = data_off + len(data_buf)
            data_buf.extend(struct.pack("<I", len(params_tup)))
            for p_desc in params_tup:
                data_buf.extend(struct.pack("<H", type_to_idx[p_desc]))

    # 3. Write code_items for synthetic Java caller methods
    caller_code_offsets: dict[int, int] = {}
    for m_idx, (_c_idx, _p_idx, _n_idx, cls_desc, _m_name, _flags, target_native) in enumerate(
        method_tuples
    ):
        if target_native is not None:
            align4()
            code_item_off = data_off + len(data_buf)
            caller_code_offsets[m_idx] = code_item_off
            target_idx = method_lookup[(cls_desc, target_native)]
            # Dalvik instructions: invoke-virtual {v0}, method@target_idx (0x00106e, target_idx, 0x0000) + return-void (0x000e)
            insns = struct.pack("<HHHH", 0x106E, target_idx, 0x0000, 0x000E)
            data_buf.extend(
                struct.pack(
                    "<HHHHII",
                    2,  # registers_size
                    1,  # ins_size
                    1,  # outs_size
                    0,  # tries_size
                    0,  # debug_info_off
                    4,  # insns_size (in 16-bit units)
                )
            )
            data_buf.extend(insns)

    # 4. Write class_data_items
    class_data_offsets: dict[str, int] = {}
    for cls_desc, _ in expanded_classes:
        cls_methods = [
            (idx, item[5], caller_code_offsets.get(idx, 0))
            for idx, item in enumerate(method_tuples)
            if item[3] == cls_desc
        ]
        direct_methods = [m for m in cls_methods if (m[1] & 0x0008)]
        virtual_methods = [m for m in cls_methods if not (m[1] & 0x0008)]

        class_data_offsets[cls_desc] = data_off + len(data_buf)
        data_buf.extend(encode_uleb128(0))  # static_fields_size
        data_buf.extend(encode_uleb128(0))  # instance_fields_size
        data_buf.extend(encode_uleb128(len(direct_methods)))
        data_buf.extend(encode_uleb128(len(virtual_methods)))

        for group in (direct_methods, virtual_methods):
            prev_idx = 0
            for m_idx, flags, code_off in group:
                data_buf.extend(encode_uleb128(m_idx - prev_idx))
                data_buf.extend(encode_uleb128(flags))
                data_buf.extend(encode_uleb128(code_off))
                prev_idx = m_idx

    align4()
    total_file_size = data_off + len(data_buf)

    # Assemble index tables
    tables_buf = bytearray()
    for s_off in string_data_offsets:
        tables_buf.extend(struct.pack("<I", s_off))
    for t_str in sorted_types:
        tables_buf.extend(struct.pack("<I", str_to_idx[t_str]))
    for pk in sorted_protos:
        shorty, _, ret = pk
        tables_buf.extend(
            struct.pack(
                "<3I",
                str_to_idx[shorty],
                type_to_idx[ret],
                proto_param_offsets[pk],
            )
        )
    for c_idx, p_idx, n_idx, _, _, _, _ in method_tuples:
        tables_buf.extend(struct.pack("<HHI", c_idx, p_idx, n_idx))

    obj_type_idx = type_to_idx["Ljava/lang/Object;"]
    src_str_idx = str_to_idx["SourceFile.java"]
    for cls_desc, _ in expanded_classes:
        tables_buf.extend(
            struct.pack(
                "<8I",
                type_to_idx[cls_desc],
                0x0001,
                obj_type_idx,
                0,
                src_str_idx,
                0,
                class_data_offsets[cls_desc],
                0,
            )
        )

    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into(
        "<20I",
        header,
        0x20,
        total_file_size,
        0x70,
        0x12345678,
        0,
        0,
        0,
        len(sorted_strings),
        string_ids_off,
        len(sorted_types),
        type_ids_off,
        len(sorted_protos),
        proto_ids_off,
        0,
        0,
        len(method_tuples),
        method_ids_off,
        len(expanded_classes),
        class_defs_off,
        len(data_buf),
        data_off,
    )

    full_dex = header + tables_buf + data_buf
    sha1_digest = hashlib.sha1(bytes(full_dex[32:])).digest()
    full_dex[12:32] = sha1_digest
    adler = zlib.adler32(bytes(full_dex[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", full_dex, 8, adler)
    return bytes(full_dex)


# ARM64 instruction encoders for building realistic native functions
def _arm64_mov_reg(rd: int, rm: int) -> int:
    return 0xAA0003E0 | ((rm & 0x1F) << 16) | (rd & 0x1F)


def _arm64_ldr_uimm64(rt: int, rn: int, byte_offset: int) -> int:
    imm12 = (byte_offset // 8) & 0xFFF
    return 0xF9400000 | (imm12 << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)


def _arm64_str_uimm64(rt: int, rn: int, byte_offset: int) -> int:
    imm12 = (byte_offset // 8) & 0xFFF
    return 0xF9000000 | (imm12 << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)


def _arm64_blr(rn: int) -> int:
    return 0xD63F0000 | ((rn & 0x1F) << 5)


def _arm64_bl(pc: int, target: int) -> int:
    imm26 = ((target - pc) // 4) & 0x03FFFFFF
    return 0x94000000 | imm26


def _arm64_adrp(rd: int, pc: int, target_va: int) -> int:
    page_diff = ((target_va & ~0xFFF) - (pc & ~0xFFF)) >> 12
    immlo = page_diff & 0x3
    immhi = (page_diff >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | (rd & 0x1F)


def _arm64_add_imm(rd: int, rn: int, imm12: int) -> int:
    return 0x91000000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)


def _arm64_movz(rd: int, imm16: int, shift: int = 0) -> int:
    hw = (shift // 16) & 0x3
    return 0xD2800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)


def _arm64_movk(rd: int, imm16: int, shift: int = 0) -> int:
    hw = (shift // 16) & 0x3
    return 0xF2800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | (rd & 0x1F)


ARM64_RET = 0xD65F03C0


def _encode_stack_string_arm64(text: str, sp_offset: int) -> list[int]:
    """Encodes a string into ARM64 MOVZ/MOVK + STR Xt, [SP, #off] instructions."""
    padded = text.encode("ascii") + b"\x00"
    while len(padded) % 8 != 0:
        padded += b"\x00"
    insns: list[int] = []
    for chunk_i in range(0, len(padded), 8):
        qword = int.from_bytes(padded[chunk_i : chunk_i + 8], "little")
        insns.append(_arm64_movz(10, qword & 0xFFFF, 0))
        insns.append(_arm64_movk(10, (qword >> 16) & 0xFFFF, 16))
        insns.append(_arm64_movk(10, (qword >> 32) & 0xFFFF, 32))
        insns.append(_arm64_movk(10, (qword >> 48) & 0xFFFF, 48))
        insns.append(_arm64_str_uimm64(10, 31, sp_offset + chunk_i))
    return insns


def build_stripped_arm64_so() -> tuple[bytes, list[dict[str, object]]]:
    """Builds `libcore-crypto.so`: a valid stripped 64-bit ARM64 ELF shared library.

    Layout:
      - `0x001000..0x006000`: `.text` (executable ARM64 code with real JNIEnv* vtable calls)
      - `0x04c000..0x04f000`: `.rodata` (C-strings, XOR buffers, and 11 JNINativeMethod triplets @ `0x04d210`)
      - `0x050000..0x051000`: `.data.rel.ro`
    """
    file_size = 0x054000
    image = bytearray(file_size)

    text_off = 0x001000
    text_sz = 0x005000
    rodata_off = 0x04C000
    rodata_sz = 0x003000
    datarel_off = 0x050000
    datarel_sz = 0x001000

    # 1. Populate strings in .rodata starting at 0x04C100
    str_cursor = rodata_off + 0x100
    str_va_map: dict[str, int] = {}

    def add_rodata_str(s: str) -> int:
        nonlocal str_cursor
        if s in str_va_map:
            return str_va_map[s]
        va = str_cursor
        b = s.encode("ascii") + b"\x00"
        image[str_cursor : str_cursor + len(b)] = b
        str_cursor += len(b)
        while str_cursor % 8 != 0:
            str_cursor += 1
        str_va_map[s] = va
        return va

    # Strings for reflection upcalls inside native functions
    va_cls_act_thread = add_rodata_str("android/app/ActivityThread")
    va_m_cur_app = add_rodata_str("currentApplication")
    va_sig_cur_app = add_rodata_str("()Landroid/app/Application;")
    va_cls_core = add_rodata_str("com/dropper/Core")
    va_cls_cipher = add_rodata_str("javax/crypto/Cipher")
    va_m_get_inst = add_rodata_str("getInstance")
    va_sig_get_inst = add_rodata_str("(Ljava/lang/String;)Ljavax/crypto/Cipher;")

    # 11 Static (.rodata) JNI methods + 3 Dynamic (Dobby) JNI methods = 14 total
    static_methods_spec = [
        ("com.dropper.Core", "initEngine", "(Landroid/content/Context;I)Z", 0x001A40),
        ("com.dropper.Core", "decryptPayload", "([BLjava/lang/String;)[B", 0x0023C8),
        ("com.dropper.Core", "deriveSessionKey", "([B[BI)[B", 0x002640),
        ("com.dropper.Core", "packTelemetry", "(Ljava/lang/String;J)[B", 0x002880),
        ("com.dropper.net.SocketBridge", "sendFrame", "(I[BII)I", 0x002B00),
        ("com.dropper.net.SocketBridge", "closeChannel", "(I)V", 0x002D40),
        ("com.dropper.crypto.KeyVault", "unsealMasterSeed", "(Ljava/lang/String;)[B", 0x003020),
        ("com.dropper.crypto.KeyVault", "hmacSha256", "([B[B)[B", 0x003280),
        ("com.dropper.crypto.KeyVault", "wipeKeyMaterial", "(J)V", 0x0034C0),
        ("com.dropper.env.AntiAnalysis", "checkTracerPid", "()Z", 0x003700),
        ("com.dropper.env.AntiAnalysis", "verifyApkSignature", "(Landroid/content/Context;)I", 0x003980),
    ]

    dynamic_methods_spec = [
        ("com.dropper.Core", "signC2Beacon", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", 0x003F10),
        ("com.dropper.net.SocketBridge", "connectRaw", "(Ljava/lang/String;I)I", 0x004890),
        ("com.dropper.env.AntiAnalysis", "detectFridaMaps", "()Z", 0x004B20),
    ]

    # Write the 11 static JNINativeMethod triplets at exact file offset 0x0004d210
    triplet_table_off = 0x0004D210
    for idx, (_cls, m_name, jni_sig, fn_off) in enumerate(static_methods_spec):
        n_va = add_rodata_str(m_name)
        s_va = add_rodata_str(jni_sig)
        entry_off = triplet_table_off + idx * 24
        struct.pack_into("<QQQ", image, entry_off, n_va, s_va, fn_off)

    # Write XOR-encoded strings in .rodata at 0x04DC00 for extract_jni_onload_strings
    xor_cursor = 0x04DC00
    for xor_key, plain_str in [
        (0x5A, "https://c2.dropper-gate.net/api/v2/checkin"),
        (0x3C, "dalvik.system.InMemoryDexClassLoader"),
        (0x71, "com/dropper/net/SocketBridge"),
    ]:
        enc_bytes = bytes(b ^ xor_key for b in plain_str.encode("ascii"))
        block = b"JSLX" + bytes([xor_key, len(enc_bytes)]) + enc_bytes
        image[xor_cursor : xor_cursor + len(block)] = block
        xor_cursor += len(block) + 8

    # 2. Write ARM64 machine code into .text
    def write_insns(fn_off: int, insns: list[int]) -> None:
        for i, word in enumerate(insns):
            struct.pack_into("<I", image, fn_off + i * 4, word)

    # Function @ 0x0023c8: com.dropper.Core#decryptPayload
    # Calls GetStringUTFChars (+0x548), GetByteArrayElements (+0x5c0), sub_00014a00, ReleaseStringUTFChars (+0x550)
    write_insns(
        0x0023C8,
        [
            _arm64_mov_reg(19, 0),  # mov x19, x0 (JNIEnv*)
            _arm64_ldr_uimm64(8, 19, 0),  # ldr x8, [x19] (vtable)
            _arm64_ldr_uimm64(9, 8, 0x548),  # ldr x9, [x8, #0x548] (GetStringUTFChars)
            _arm64_blr(9),  # blr x9
            _arm64_ldr_uimm64(8, 19, 0),  # ldr x8, [x19]
            _arm64_ldr_uimm64(9, 8, 0x5C0),  # ldr x9, [x8, #0x5c0] (GetByteArrayElements)
            _arm64_blr(9),  # blr x9
            _arm64_bl(0x0023C8 + 28, 0x004A00),  # bl rc4_crypt_buffer
            _arm64_ldr_uimm64(8, 19, 0),  # ldr x8, [x19]
            _arm64_ldr_uimm64(9, 8, 0x550),  # ldr x9, [x8, #0x550] (ReleaseStringUTFChars)
            _arm64_blr(9),  # blr x9
            ARM64_RET,
        ],
    )

    # Function @ 0x001a40: com.dropper.Core#initEngine
    # Calls FindClass (+0x030), GetStaticMethodID (+0x388), CallStaticObjectMethod (+0x390)
    pc_1a40 = 0x001A40
    write_insns(
        pc_1a40,
        [
            _arm64_mov_reg(19, 0),
            _arm64_ldr_uimm64(8, 19, 0),
            _arm64_adrp(1, pc_1a40 + 8, va_cls_act_thread),
            _arm64_add_imm(1, 1, va_cls_act_thread & 0xFFF),
            _arm64_ldr_uimm64(9, 8, 0x030),  # FindClass
            _arm64_blr(9),
            _arm64_adrp(2, pc_1a40 + 24, va_m_cur_app),
            _arm64_add_imm(2, 2, va_m_cur_app & 0xFFF),
            _arm64_adrp(3, pc_1a40 + 32, va_sig_cur_app),
            _arm64_add_imm(3, 3, va_sig_cur_app & 0xFFF),
            _arm64_ldr_uimm64(9, 8, 0x388),  # GetStaticMethodID
            _arm64_blr(9),
            _arm64_ldr_uimm64(9, 8, 0x390),  # CallStaticObjectMethod
            _arm64_blr(9),
            ARM64_RET,
        ],
    )

    # Function @ 0x003f10: com.dropper.Core#signC2Beacon
    # Calls GetStringUTFChars (+0x548), ReleaseStringUTFChars (+0x550), NewStringUTF (+0x538)
    write_insns(
        0x003F10,
        [
            _arm64_mov_reg(19, 0),
            _arm64_ldr_uimm64(8, 19, 0),
            _arm64_ldr_uimm64(9, 8, 0x548),  # GetStringUTFChars
            _arm64_blr(9),
            _arm64_ldr_uimm64(9, 8, 0x550),  # ReleaseStringUTFChars
            _arm64_blr(9),
            _arm64_ldr_uimm64(9, 8, 0x538),  # NewStringUTF
            _arm64_blr(9),
            ARM64_RET,
        ],
    )

    # Function @ 0x004890: com.dropper.net.SocketBridge#connectRaw
    write_insns(
        0x004890,
        [
            _arm64_mov_reg(19, 0),
            _arm64_ldr_uimm64(8, 19, 0),
            _arm64_ldr_uimm64(9, 8, 0x548),  # GetStringUTFChars
            _arm64_blr(9),
            _arm64_ldr_uimm64(9, 8, 0x550),  # ReleaseStringUTFChars
            _arm64_blr(9),
            ARM64_RET,
        ],
    )

    # Populate remaining static/dynamic functions with valid ARM64 JNIEnv* vtable sequences
    for _, _, _, fn_off in static_methods_spec[2:]:
        write_insns(
            fn_off,
            [
                _arm64_mov_reg(19, 0),
                _arm64_ldr_uimm64(8, 19, 0),
                _arm64_adrp(1, fn_off + 8, va_cls_cipher),
                _arm64_add_imm(1, 1, va_cls_cipher & 0xFFF),
                _arm64_ldr_uimm64(9, 8, 0x030),  # FindClass
                _arm64_blr(9),
                _arm64_adrp(2, fn_off + 24, va_m_get_inst),
                _arm64_add_imm(2, 2, va_m_get_inst & 0xFFF),
                _arm64_adrp(3, fn_off + 32, va_sig_get_inst),
                _arm64_add_imm(3, 3, va_sig_get_inst & 0xFFF),
                _arm64_ldr_uimm64(9, 8, 0x388),  # GetStaticMethodID
                _arm64_blr(9),
                _arm64_ldr_uimm64(9, 8, 0x680),  # SetByteArrayRegion
                _arm64_blr(9),
                ARM64_RET,
            ],
        )

    write_insns(
        0x004B20,
        [
            _arm64_mov_reg(19, 0),
            _arm64_ldr_uimm64(8, 19, 0),
            _arm64_ldr_uimm64(9, 8, 0x720),  # ExceptionCheck
            _arm64_blr(9),
            ARM64_RET,
        ],
    )

    # Function @ 0x005200: JNI_OnLoad constructing stack strings via MOVZ/MOVK and calling RegisterNatives (+0x6b8)
    onload_insns = [
        _arm64_mov_reg(19, 0),
        _arm64_ldr_uimm64(8, 19, 0),
        _arm64_adrp(1, 0x005200 + 8, va_cls_core),
        _arm64_add_imm(1, 1, va_cls_core & 0xFFF),
    ]
    onload_insns.extend(_encode_stack_string_arm64("signC2Beacon", 0x20))
    onload_insns.extend(_encode_stack_string_arm64("connectRaw", 0x40))
    onload_insns.extend(
        [
            _arm64_ldr_uimm64(9, 8, 0x6B8),  # RegisterNatives (+0x6b8)
            _arm64_blr(9),
            ARM64_RET,
        ]
    )
    write_insns(0x005200, onload_insns)

    # 3. Write ELF64 Header, Program Headers, and Section Headers
    shstrtab = b"\x00.text\x00.rodata\x00.data.rel.ro\x00.dynsym\x00.dynstr\x00.shstrtab\x00"
    shstr_off = 0x052000
    image[shstr_off : shstr_off + len(shstrtab)] = shstrtab

    phoff = 64
    phentsize = 56
    phnum = 3

    shoff = 0x052200
    shentsize = 64
    shnum = 5
    shstrndx = 4

    # ELF64 header
    e_ident = bytearray(16)
    e_ident[0:4] = ELF_MAGIC
    e_ident[4] = ELFCLASS64
    e_ident[5] = 1  # little-endian
    e_ident[6] = 1  # EV_CURRENT
    image[0:16] = e_ident

    struct.pack_into(
        "<HHIQQQIHHHHHH",
        image,
        16,
        3,  # ET_DYN
        EM_AARCH64,
        1,
        text_off,
        phoff,
        shoff,
        0,
        64,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx,
    )

    # Program headers (PT_LOAD)
    segments = [
        (PT_LOAD, PF_R | PF_X, text_off, text_off, text_sz, text_sz),
        (PT_LOAD, PF_R, rodata_off, rodata_off, rodata_sz, rodata_sz),
        (PT_LOAD, PF_R | PF_W, datarel_off, datarel_off, datarel_sz, datarel_sz),
    ]
    for i, (p_type, p_flags, p_off, p_vaddr, p_filesz, p_memsz) in enumerate(segments):
        struct.pack_into(
            "<IIQQQQQQ",
            image,
            phoff + i * phentsize,
            p_type,
            p_flags,
            p_off,
            p_vaddr,
            p_vaddr,
            p_filesz,
            p_memsz,
            0x1000,
        )

    # Section headers: 0=NULL, 1=.text, 2=.rodata, 3=.data.rel.ro, 4=.shstrtab
    sec_defs = [
        (0, 0, 0, 0, 0, 0, 0, 0),
        (1, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, text_off, text_off, text_sz, 0, 0),
        (7, SHT_PROGBITS, SHF_ALLOC, rodata_off, rodata_off, rodata_sz, 0, 0),
        (15, SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, datarel_off, datarel_off, datarel_sz, 0, 0),
        (44, SHT_STRTAB, 0, 0, shstr_off, len(shstrtab), 0, 0),
    ]
    for i, (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_entsize) in enumerate(
        sec_defs
    ):
        struct.pack_into(
            "<IIQQQQIIQQ",
            image,
            shoff + i * shentsize,
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            0,
            8,
            sh_entsize,
        )

    dobby_registrations = [
        {
            "class_name": cls,
            "method_name": m_name,
            "jni_signature": jni_sig,
            "so_name": "libcore-crypto.so",
            "so_path": "/data/app/com.dropper/lib/arm64/libcore-crypto.so",
            "base_address": "0x7b44100000",
            "fn_ptr": f"0x{0x7B44100000 + fn_off:x}",
            "fn_offset": f"0x{fn_off:06x}",
            "resolution_mode": "Dynamic (Dobby)",
        }
        for cls, m_name, jni_sig, fn_off in dynamic_methods_spec
    ]

    return bytes(image), dobby_registrations


def generate_all_samples(repo_root: str | Path | None = None) -> dict[str, str]:
    """Generates all synthetic APK, ELF `.so`, and Dobby trace fixtures in `examples/` and `samples/`."""
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[2]
    examples_dir = root / "examples"
    samples_dir = root / "samples"
    examples_dir.mkdir(parents=True, exist_ok=True)
    samples_dir.mkdir(parents=True, exist_ok=True)

    # 3 DEX files with 14 declared native methods across 4 classes
    dex1_bytes = build_dex_bytes(
        [
            (
                "Lcom/dropper/Core;",
                [
                    ("initEngine", "(Landroid/content/Context;I)Z", 0x0101),
                    ("decryptPayload", "([BLjava/lang/String;)[B", 0x0101),
                    ("signC2Beacon", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", 0x0101),
                    ("deriveSessionKey", "([B[BI)[B", 0x0109),
                    ("packTelemetry", "(Ljava/lang/String;J)[B", 0x0101),
                ],
            ),
        ]
    )

    dex2_bytes = build_dex_bytes(
        [
            (
                "Lcom/dropper/net/SocketBridge;",
                [
                    ("connectRaw", "(Ljava/lang/String;I)I", 0x0101),
                    ("sendFrame", "(I[BII)I", 0x0101),
                    ("closeChannel", "(I)V", 0x0101),
                ],
            ),
            (
                "Lcom/dropper/crypto/KeyVault;",
                [
                    ("unsealMasterSeed", "(Ljava/lang/String;)[B", 0x0101),
                    ("hmacSha256", "([B[B)[B", 0x0109),
                    ("wipeKeyMaterial", "(J)V", 0x0101),
                ],
            ),
        ]
    )

    dex3_bytes = build_dex_bytes(
        [
            (
                "Lcom/dropper/env/AntiAnalysis;",
                [
                    ("checkTracerPid", "()Z", 0x0109),
                    ("verifyApkSignature", "(Landroid/content/Context;)I", 0x0109),
                    ("detectFridaMaps", "()Z", 0x0109),
                ],
            ),
        ]
    )

    so_bytes, dobby_registrations = build_stripped_arm64_so()
    trace_doc = {
        "agent": "jnisleuth-dobby",
        "device": "emulator-5554",
        "package": "com.dropper",
        "registrations": dobby_registrations,
    }
    trace_json_bytes = json.dumps(trace_doc, indent=2).encode("utf-8")

    so_path = examples_dir / "libcore-crypto.so"
    so_path.write_bytes(so_bytes)

    trace_path = examples_dir / "register_natives_trace.json"
    trace_path.write_bytes(trace_json_bytes)

    for apk_out in (
        examples_dir / "obfuscated_jni_sample.apk",
        samples_dir / "banker_dropper.apk",
    ):
        with zipfile.ZipFile(apk_out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("classes.dex", dex1_bytes)
            zf.writestr("classes2.dex", dex2_bytes)
            zf.writestr("classes3.dex", dex3_bytes)
            zf.writestr("lib/arm64-v8a/libcore-crypto.so", so_bytes)
            zf.writestr("assets/register_natives.json", trace_json_bytes)

    return {
        "obfuscated_jni_sample_apk": str(examples_dir / "obfuscated_jni_sample.apk"),
        "banker_dropper_apk": str(samples_dir / "banker_dropper.apk"),
        "libcore_crypto_so": str(so_path),
        "register_natives_trace_json": str(trace_path),
    }


if __name__ == "__main__":
    generated = generate_all_samples()
    print(json.dumps(generated, indent=2))
