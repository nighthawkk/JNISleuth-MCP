"""Pure-Python Dalvik Executable (DEX) and APK parser for extracting `native` methods and callers."""

from __future__ import annotations

from pathlib import Path
import struct
import zipfile

from .models import (
    DexNativeMethod,
    class_descriptor_to_java_name,
    jni_type_to_java_type,
    mangle_jni_symbol,
)

ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_SYNCHRONIZED = 0x0020
ACC_NATIVE = 0x0100


def read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """Reads an unsigned LEB128 integer from `data` at `offset`."""
    result = 0
    shift = 0
    cur = offset
    while True:
        if cur >= len(data):
            raise ValueError(f"Truncated ULEB128 at offset 0x{offset:x}")
        byte = data[cur]
        cur += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
        if shift > 35:
            raise ValueError(f"ULEB128 too large at offset 0x{offset:x}")
    return result, cur


class DexParser:
    """Parses a single DEX binary buffer to extract declared `native` methods and Java callers."""

    def __init__(self, data: bytes, dex_name: str = "classes.dex") -> None:
        self.data = data
        self.dex_name = dex_name
        self.strings: list[str] = []
        self.types: list[str] = []
        self.protos: list[tuple[str, str, list[str]]] = []
        self.methods: list[tuple[str, str, str, list[str], str]] = []
        self._parse_header_and_tables()

    def _parse_header_and_tables(self) -> None:
        if len(self.data) < 0x70 or not self.data.startswith(b"dex\n"):
            raise ValueError(f"{self.dex_name}: Invalid DEX magic header")

        (
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            _field_ids_size,
            _field_ids_off,
            method_ids_size,
            method_ids_off,
            self.class_defs_size,
            self.class_defs_off,
        ) = struct.unpack_from("<12I", self.data, 0x38)

        # 1. Parse string_ids
        self.strings = []
        for i in range(string_ids_size):
            (str_data_off,) = struct.unpack_from("<I", self.data, string_ids_off + i * 4)
            _, pos = read_uleb128(self.data, str_data_off)
            end = self.data.find(b"\x00", pos)
            if end == -1:
                end = len(self.data)
            self.strings.append(self.data[pos:end].decode("utf-8", errors="replace"))

        # 2. Parse type_ids
        self.types = []
        for i in range(type_ids_size):
            (desc_idx,) = struct.unpack_from("<I", self.data, type_ids_off + i * 4)
            self.types.append(self.strings[desc_idx] if desc_idx < len(self.strings) else "")

        # 3. Parse proto_ids
        self.protos = []
        for i in range(proto_ids_size):
            shorty_idx, return_type_idx, parameters_off = struct.unpack_from(
                "<3I", self.data, proto_ids_off + i * 12
            )
            ret_type = self.types[return_type_idx] if return_type_idx < len(self.types) else "V"
            param_types: list[str] = []
            if parameters_off != 0 and parameters_off + 4 <= len(self.data):
                (param_count,) = struct.unpack_from("<I", self.data, parameters_off)
                for p_idx in range(param_count):
                    (t_idx,) = struct.unpack_from(
                        "<H", self.data, parameters_off + 4 + p_idx * 2
                    )
                    if t_idx < len(self.types):
                        param_types.append(self.types[t_idx])
            jni_sig = f"({''.join(param_types)}){ret_type}"
            self.protos.append((jni_sig, ret_type, param_types))

        # 4. Parse method_ids
        self.methods = []
        for i in range(method_ids_size):
            class_idx, proto_idx, name_idx = struct.unpack_from(
                "<HHI", self.data, method_ids_off + i * 8
            )
            cls_desc = self.types[class_idx] if class_idx < len(self.types) else ""
            m_name = self.strings[name_idx] if name_idx < len(self.strings) else ""
            if proto_idx < len(self.protos):
                jni_sig, ret_type, param_types = self.protos[proto_idx]
            else:
                jni_sig, ret_type, param_types = "()V", "V", []
            self.methods.append((cls_desc, m_name, jni_sig, param_types, ret_type))

    def _dalvik_insn_byte_length(self, pc: int, insns_end: int) -> int:
        """Returns the exact byte length of the Dalvik instruction at `pc`."""
        word0 = struct.unpack_from("<H", self.data, pc)[0]
        opcode = word0 & 0xFF

        # Handle pseudo-instruction payloads (packed-switch, sparse-switch, fill-array-data)
        if opcode == 0x00:
            if word0 == 0x0100 and pc + 4 <= insns_end:
                size = struct.unpack_from("<H", self.data, pc + 2)[0]
                return 8 + size * 4
            if word0 == 0x0200 and pc + 4 <= insns_end:
                size = struct.unpack_from("<H", self.data, pc + 2)[0]
                return 4 + size * 8
            if word0 == 0x0300 and pc + 8 <= insns_end:
                elem_width = struct.unpack_from("<H", self.data, pc + 2)[0]
                num_elems = struct.unpack_from("<I", self.data, pc + 4)[0]
                total_bytes = num_elems * elem_width
                return 8 + ((total_bytes + 1) & ~1)
            return 2

        # 5-unit (10-byte) instruction: const-wide (51l)
        if opcode == 0x18:
            return 10

        # 4-unit (8-byte) instructions: invoke-polymorphic{/range} (45cc, 4rcc)
        if opcode in (0xFA, 0xFB):
            return 8

        # 3-unit (6-byte) instructions: 30t, 32x, 31i, 31t, 31c, 35c, 3rc
        if (
            opcode in (0x03, 0x06, 0x09, 0x14, 0x17, 0x1B)
            or (0x24 <= opcode <= 0x26)
            or (0x2A <= opcode <= 0x2C)
            or (0x6E <= opcode <= 0x72)
            or (0x74 <= opcode <= 0x78)
            or opcode in (0xFC, 0xFD)
        ):
            return 6

        # 2-unit (4-byte) instructions: 20t, 22x, 21t, 21s, 21h, 21c, 23x, 22b, 22t, 22s, 22c
        if (
            opcode in (0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C, 0x1F, 0x20, 0x22, 0x23, 0x29, 0xFE, 0xFF)
            or (0x2D <= opcode <= 0x3D)
            or (0x44 <= opcode <= 0x6D)
            or (0x90 <= opcode <= 0xAF)
            or (0xD0 <= opcode <= 0xE2)
        ):
            return 4

        return 2

    def _scan_code_item_invocations(self, code_off: int) -> list[int]:
        """Scans a Dalvik `code_item` for `invoke-*` instructions and returns target `method_idx`s."""
        if code_off == 0 or code_off + 16 > len(self.data):
            return []
        insns_size = struct.unpack_from("<I", self.data, code_off + 12)[0]
        insns_start = code_off + 16
        insns_end = min(len(self.data), insns_start + insns_size * 2)
        called_method_indices: list[int] = []

        pc = insns_start
        while pc + 2 <= insns_end:
            word0 = struct.unpack_from("<H", self.data, pc)[0]
            opcode = word0 & 0xFF
            # invoke-virtual..invoke-interface (0x6e..0x72) or invoke-virtual/range.. (0x74..0x78)
            if (0x6E <= opcode <= 0x72 or 0x74 <= opcode <= 0x78) and pc + 6 <= insns_end:
                method_idx = struct.unpack_from("<H", self.data, pc + 2)[0]
                called_method_indices.append(method_idx)
                pc += 6
            else:
                step = self._dalvik_insn_byte_length(pc, insns_end)
                pc += max(2, step)
        return called_method_indices

    def extract_native_methods(self) -> list[DexNativeMethod]:
        """Extracts all `ACC_NATIVE` methods and populates their Java caller cross-references."""
        native_by_method_idx: dict[int, DexNativeMethod] = {}
        caller_edges: list[tuple[str, int]] = []

        for i in range(self.class_defs_size):
            off = self.class_defs_off + i * 32
            if off + 32 > len(self.data):
                break
            (
                class_idx,
                _access_flags,
                _superclass_idx,
                _interfaces_off,
                _source_file_idx,
                _annotations_off,
                class_data_off,
                _static_values_off,
            ) = struct.unpack_from("<8I", self.data, off)

            if class_data_off == 0 or class_data_off >= len(self.data):
                continue

            pos = class_data_off
            static_fields_size, pos = read_uleb128(self.data, pos)
            instance_fields_size, pos = read_uleb128(self.data, pos)
            direct_methods_size, pos = read_uleb128(self.data, pos)
            virtual_methods_size, pos = read_uleb128(self.data, pos)

            for _ in range(static_fields_size + instance_fields_size):
                _, pos = read_uleb128(self.data, pos)
                _, pos = read_uleb128(self.data, pos)

            for method_group_size in (direct_methods_size, virtual_methods_size):
                method_idx = 0
                for _ in range(method_group_size):
                    diff, pos = read_uleb128(self.data, pos)
                    m_flags, pos = read_uleb128(self.data, pos)
                    code_off, pos = read_uleb128(self.data, pos)
                    method_idx += diff

                    if method_idx >= len(self.methods):
                        continue
                    cls_desc, m_name, jni_sig, param_types, ret_type = self.methods[method_idx]
                    cls_java = class_descriptor_to_java_name(
                        cls_desc or self.types[class_idx]
                    )

                    if m_flags & ACC_NATIVE:
                        short_sym, long_sym = mangle_jni_symbol(cls_java, m_name, jni_sig)
                        native_by_method_idx[method_idx] = DexNativeMethod(
                            class_descriptor=cls_desc,
                            class_name=cls_java,
                            method_name=m_name,
                            jni_signature=jni_sig,
                            return_type=ret_type,
                            param_types=list(param_types),
                            access_flags=m_flags,
                            is_static=bool(m_flags & ACC_STATIC),
                            short_jni_symbol=short_sym,
                            long_jni_symbol=long_sym,
                            dex_file=self.dex_name,
                        )
                    elif code_off != 0:
                        caller_name = f"{cls_java}#{m_name}{jni_sig}"
                        for target_idx in self._scan_code_item_invocations(code_off):
                            caller_edges.append((caller_name, target_idx))

        for caller_name, target_idx in caller_edges:
            if target_idx in native_by_method_idx:
                nm = native_by_method_idx[target_idx]
                if caller_name not in nm.callers:
                    nm.callers.append(caller_name)

        return list(native_by_method_idx.values())


def parse_dex_or_apk(path: str | Path) -> tuple[list[DexNativeMethod], int]:
    """Parses either a raw `.dex` file or all `classes*.dex` entries inside an `.apk` archive.

    Returns:
        (list_of_native_methods, number_of_dex_files_parsed)
    """
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"DEX or APK path not found: {target}")

    raw_head = target.read_bytes()[:8]
    if raw_head.startswith(b"dex\n"):
        parser = DexParser(target.read_bytes(), dex_name=target.name)
        return parser.extract_native_methods(), 1

    if zipfile.is_zipfile(target):
        all_methods: list[DexNativeMethod] = []
        dex_count = 0
        with zipfile.ZipFile(target, "r") as zf:
            dex_names = sorted(
                name
                for name in zf.namelist()
                if name.endswith(".dex") and ("/" not in name)
            )
            for dex_name in dex_names:
                dex_bytes = zf.read(dex_name)
                if dex_bytes.startswith(b"dex\n"):
                    dex_count += 1
                    parser = DexParser(dex_bytes, dex_name=dex_name)
                    all_methods.extend(parser.extract_native_methods())
        return all_methods, dex_count

    raise ValueError(f"Unsupported file format (expected .apk or .dex): {target}")


# Backwards-compatible alias
parse_dex_Or_apk = parse_dex_or_apk


def synthesize_java_caller_view(method: DexNativeMethod, so_name: str = "core-crypto") -> str:
    """Synthesizes a Jadx-style Java decompilation view for a native method and its callers."""
    pkg, _, simple_cls = method.class_name.rpartition(".")
    ret_java = jni_type_to_java_type(method.return_type)

    # Provide descriptive parameter names matching common JNI patterns
    default_param_names = {
        ("decryptPayload", 0): "encryptedData",
        ("decryptPayload", 1): "rc4KeyStr",
        ("initEngine", 0): "context",
        ("initEngine", 1): "configFlags",
        ("signC2Beacon", 0): "beaconPayload",
        ("signC2Beacon", 1): "deviceFingerprint",
        ("connectRaw", 0): "hostAddress",
        ("connectRaw", 1): "port",
    }

    params_rendered: list[str] = []
    arg_call_names: list[str] = []
    for idx, p_type in enumerate(method.param_types):
        p_java = jni_type_to_java_type(p_type)
        p_name = default_param_names.get((method.method_name, idx), f"arg{idx + 1}")
        params_rendered.append(f"{p_java} {p_name}")
        arg_call_names.append(p_name)

    static_kw = "static " if method.is_static else ""
    lib_clean = so_name.removeprefix("lib").removesuffix(".so")

    caller_block = ""
    if method.callers:
        caller_sig = method.callers[0]
        caller_cls_and_m = caller_sig.split("(")[0]
        _, _, caller_m_name = caller_cls_and_m.partition("#")
        call_target = simple_cls if method.is_static else "this"
        ret_stmt = "return " if ret_java != "void" else ""
        caller_block = (
            f"\n    // Cross-referenced Java caller: {caller_sig}\n"
            f"    public {ret_java} {caller_m_name}({', '.join(params_rendered)}) {{\n"
            f"        {ret_stmt}{call_target}.{method.method_name}({', '.join(arg_call_names)});\n"
            f"    }}\n"
        )

    pkg_line = f"package {pkg};\n\n" if pkg else ""
    return (
        f"{pkg_line}"
        f"public class {simple_cls} {{\n"
        f"    static {{\n"
        f'        System.loadLibrary("{lib_clean}");\n'
        f"    }}\n\n"
        f"    public {static_kw}native {ret_java} {method.method_name}({', '.join(params_rendered)});\n"
        f"{caller_block}"
        f"}}"
    )
