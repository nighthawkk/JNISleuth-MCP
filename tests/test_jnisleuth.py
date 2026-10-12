"""Comprehensive unit and integration test suite for JNISleuth-MCP."""

from __future__ import annotations

import ctypes
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from jnisleuth.cli import main as cli_main
from jnisleuth.dex_parser import DexParser, parse_dex_Or_apk, parse_dex_or_apk
from jnisleuth.elf_scanner import (
    ELF_MAGIC,
    ELFCLASS32,
    EM_ARM,
    PF_R,
    PF_X,
    PT_LOAD,
    R_ARM_RELATIVE,
    SHF_ALLOC,
    SHF_EXECINSTR,
    SHT_PROGBITS,
    SHT_RELA,
    SHT_STRTAB,
    ElfBinary,
)
from jnisleuth.ghidra_bridge import sync_ghidra_jni_types
from jnisleuth.mcp_server import (
    deobfuscate_jni_strings,
    extract_jni_onload_strings,
    get_cross_boundary_callgraph,
    get_cross_boundary_slice,
    import_dynamic_trace,
    list_jni_methods,
    mcp,
    resolve_apk_jni_map,
    trace_jni_callbacks,
    trace_jni_upcalls,
)
from jnisleuth.models import (
    build_c_jni_signature,
    is_valid_jni_method_descriptor,
    jni_type_to_c_type,
    mangle_jni_symbol,
    parse_jni_method_descriptor,
)
from jnisleuth.sample_generator import (
    ARM64_RET,
    _arm64_add_imm,
    _arm64_bl,
    _arm64_blr,
    _arm64_ldr_uimm64,
    _arm64_movk,
    _arm64_movz,
    _arm64_str_uimm64,
    build_dex_bytes,
    generate_all_samples,
)
from jnisleuth.static_heuristic import (
    analyze_apk_bundle,
    correlate_jni_bindings,
    extract_jni_onload_strings as raw_extract_onload_strings,
    scan_elf_jni_triplets,
)
from jnisleuth.vtable_analyzer import (
    JNI_NATIVE_INTERFACE_ENTRIES,
    lookup_jni_vtable_offset,
    trace_jni_upcalls as raw_trace_jni_upcalls,
)
import struct


class TestJNISleuthMCP(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sample_paths = generate_all_samples(REPO_ROOT)
        cls.apk_path = Path(cls.sample_paths["banker_dropper_apk"])
        cls.so_path = Path(cls.sample_paths["libcore_crypto_so"])
        cls.trace_path = Path(cls.sample_paths["register_natives_trace_json"])

    def test_jni_descriptor_and_mangling(self) -> None:
        params, ret = parse_jni_method_descriptor("([BLjava/lang/String;)[B")
        self.assertEqual(params, ["[B", "Ljava/lang/String;"])
        self.assertEqual(ret, "[B")
        self.assertEqual(jni_type_to_c_type("[B"), "jbyteArray")
        self.assertEqual(jni_type_to_c_type("Ljava/lang/String;"), "jstring")
        self.assertTrue(is_valid_jni_method_descriptor("(Landroid/content/Context;I)Z"))
        self.assertFalse(is_valid_jni_method_descriptor("not_a_signature"))
        self.assertFalse(is_valid_jni_method_descriptor("(V)V"))
        self.assertFalse(is_valid_jni_method_descriptor("()"))

        short_sym, long_sym = mangle_jni_symbol(
            "com.dropper.Core", "decrypt_payload", "([BLjava/lang/String;)[B"
        )
        self.assertEqual(short_sym, "Java_com_dropper_Core_decrypt_1payload")
        self.assertEqual(
            long_sym,
            "Java_com_dropper_Core_decrypt_1payload___3BLjava_lang_String_2",
        )

        c_name, c_proto, _ = build_c_jni_signature(
            "com.dropper.Core",
            "decryptPayload",
            "([BLjava/lang/String;)[B",
            is_static=False,
            param_names=["encryptedData", "rc4KeyStr"],
        )
        self.assertEqual(c_name, "Java_com_dropper_Core_decryptPayload")
        self.assertEqual(
            c_proto,
            "jbyteArray Java_com_dropper_Core_decryptPayload(JNIEnv *env, jobject thiz, jbyteArray encryptedData, jstring rc4KeyStr)",
        )

    def test_multi_dex_parsing_and_callers(self) -> None:
        methods, dex_count = parse_dex_or_apk(self.apk_path)
        methods_alias, dex_count_alias = parse_dex_Or_apk(self.apk_path)
        self.assertEqual(dex_count, 3)
        self.assertEqual(dex_count_alias, 3)
        self.assertEqual(len(methods), 14)
        self.assertEqual(len(methods_alias), 14)
        classes = {m.class_name for m in methods}
        self.assertEqual(
            classes,
            {
                "com.dropper.Core",
                "com.dropper.net.SocketBridge",
                "com.dropper.crypto.KeyVault",
                "com.dropper.env.AntiAnalysis",
            },
        )
        decrypt_m = next(m for m in methods if m.method_name == "decryptPayload")
        self.assertEqual(decrypt_m.jni_signature, "([BLjava/lang/String;)[B")
        self.assertTrue(
            any("invoke_decryptPayload" in caller for caller in decrypt_m.callers)
        )

    def test_elf_triplet_scanner_and_bundle_correlation(self) -> None:
        elf = ElfBinary.from_file(self.so_path)
        self.assertEqual(elf.arch_abi, "arm64-v8a")
        self.assertEqual(len(elf.get_exported_jni_symbols()), 0)

        triplets = scan_elf_jni_triplets(elf)
        self.assertEqual(len(triplets), 11)
        self.assertEqual(triplets[0].table_file_offset, 0x0004D210)

        bundle = analyze_apk_bundle(self.apk_path)
        self.assertEqual(bundle["static_resolved_count"], 11)
        self.assertEqual(bundle["dynamic_resolved_count"], 3)
        self.assertEqual(len(bundle["bindings"]), 14)

    def test_sectionless_and_32bit_arm_elf_scanning(self) -> None:
        # 1. Test section-header-stripped 64-bit ELF (e_shnum = 0, PT_LOAD fallback)
        raw_so = bytearray(self.so_path.read_bytes())
        # Zero out e_shoff and e_shnum in ELF64 header (offset 40 is e_shoff, offset 60 is e_shnum)
        struct.pack_into("<Q", raw_so, 40, 0)
        struct.pack_into("<H", raw_so, 60, 0)
        sectionless_elf = ElfBinary(bytes(raw_so), name="libsectionless.so")
        self.assertEqual(len(sectionless_elf.sections), 0)
        triplets_fallback = scan_elf_jni_triplets(sectionless_elf)
        self.assertEqual(len(triplets_fallback), 11)

        # 2. Test 32-bit armeabi-v7a ELF with Thumb bit (fnPtr | 1) and SHT_RELA relocation
        img32 = bytearray(0x4000)
        img32[0:4] = ELF_MAGIC
        img32[4] = ELFCLASS32
        img32[5] = 1  # little-endian
        img32[6] = 1
        # ELF32 header: e_type=3, e_machine=EM_ARM(40), e_version=1, e_entry=0x1000,
        # e_phoff=52, e_shoff=0x3000, e_flags=0, e_ehsize=52, e_phentsize=32, e_phnum=2,
        # e_shentsize=40, e_shnum=4, e_shstrndx=3
        struct.pack_into(
            "<HHIIIIIHHHHHH",
            img32,
            16,
            3,
            EM_ARM,
            1,
            0x1000,
            52,
            0x3000,
            0,
            52,
            32,
            2,
            40,
            4,
            3,
        )
        # Program headers: PT_LOAD .text (0x1000..0x1800, R|X) and .rodata (0x2000..0x2800, R)
        struct.pack_into("<8I", img32, 52, PT_LOAD, 0x1000, 0x1000, 0x1000, 0x800, 0x800, PF_R | PF_X, 0x1000)
        struct.pack_into("<8I", img32, 84, PT_LOAD, 0x2000, 0x2000, 0x2000, 0x800, 0x800, PF_R, 0x1000)
        # Strings in .rodata at 0x2100 and 0x2120
        img32[0x2100 : 0x2100 + 15] = b"decryptPayload\x00"
        img32[0x2120 : 0x2120 + 23] = b"([BLjava/lang/String;)[B\x00"
        # 32-bit JNINativeMethod triplet at 0x2200 with Thumb fnPtr (0x1234 | 1 = 0x1235)
        struct.pack_into("<III", img32, 0x2200, 0x2100, 0x2120, 0x1235)
        # Section headers + .shstrtab
        shstr = b"\x00.text\x00.rodata\x00.shstrtab\x00"
        img32[0x2700 : 0x2700 + len(shstr)] = shstr
        struct.pack_into("<10I", img32, 0x3000 + 40, 1, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0x1000, 0x1000, 0x800, 0, 0, 4, 0)
        struct.pack_into("<10I", img32, 0x3000 + 80, 7, SHT_PROGBITS, SHF_ALLOC, 0x2000, 0x2000, 0x800, 0, 0, 4, 0)
        struct.pack_into("<10I", img32, 0x3000 + 120, 15, SHT_STRTAB, 0, 0, 0x2700, len(shstr), 0, 0, 1, 0)

        elf32 = ElfBinary(bytes(img32), name="libarm32.so")
        self.assertEqual(elf32.arch_abi, "armeabi-v7a")
        triplets32 = scan_elf_jni_triplets(elf32)
        self.assertEqual(len(triplets32), 1)
        self.assertEqual(triplets32[0].method_name, "decryptPayload")
        # Thumb bit must be stripped for fn_va / fn_file_offset
        self.assertEqual(triplets32[0].fn_va, 0x1234)
        self.assertEqual(triplets32[0].fn_file_offset, 0x1234)

    def test_vtable_offsets_and_upcall_tracer(self) -> None:
        self.assertEqual(len(JNI_NATIVE_INTERFACE_ENTRIES), 233)
        expected_offsets = {
            0x030: "FindClass",
            0x108: "GetMethodID",
            0x110: "CallObjectMethod",
            0x388: "GetStaticMethodID",
            0x538: "NewStringUTF",
            0x548: "GetStringUTFChars",
            0x550: "ReleaseStringUTFChars",
            0x5C0: "GetByteArrayElements",
            0x680: "SetByteArrayRegion",
            0x6B8: "RegisterNatives",
        }
        for byte_off, expected_name in expected_offsets.items():
            info = lookup_jni_vtable_offset(byte_off, is_64=True)
            self.assertIsNotNone(info)
            assert info is not None
            self.assertEqual(info[1], expected_name)
            info32 = lookup_jni_vtable_offset(byte_off // 2, is_64=False)
            self.assertIsNotNone(info32)
            assert info32 is not None
            self.assertEqual(info32[1], expected_name)

        # Verify both string and int offsets work on raw_trace_jni_upcalls
        raw_sites = raw_trace_jni_upcalls(self.so_path, "0x23c8")
        self.assertEqual(len(raw_sites), 3)

        upcall_res = trace_jni_upcalls(str(self.so_path), "0x23c8")
        api_names = [u["jni_api_name"] for u in upcall_res["upcalls"]]
        self.assertEqual(
            api_names,
            ["GetStringUTFChars", "GetByteArrayElements", "ReleaseStringUTFChars"],
        )

        init_upcalls = trace_jni_upcalls(str(self.so_path), "0x1a40")
        self.assertEqual(
            [u["jni_api_name"] for u in init_upcalls["upcalls"]],
            ["FindClass", "GetStaticMethodID", "CallStaticObjectMethod"],
        )
        self.assertEqual(
            init_upcalls["upcalls"][0]["resolved_args"].get("arg1"),
            "android/app/ActivityThread",
        )
        self.assertEqual(
            init_upcalls["upcalls"][1]["resolved_args"].get("member_name"),
            "currentApplication",
        )

    def test_vtable_tracer_stack_spill_and_callee_following(self) -> None:
        # Build a modified ELF with a wrapper at 0x001500 that spills X0 to [SP, #16],
        # reloads it into X20, calls GetVersion (+0x020), and then BLs to 0x004B20 (which calls ExceptionCheck +0x720)
        raw_so = bytearray(self.so_path.read_bytes())
        insns = [
            _arm64_str_uimm64(0, 31, 16),       # str x0, [sp, #16]
            _arm64_ldr_uimm64(20, 31, 16),      # ldr x20, [sp, #16]
            _arm64_add_imm(21, 20, 0),          # mov x21, x20 (via add #0)
            _arm64_ldr_uimm64(8, 21, 0),        # ldr x8, [x21]
            _arm64_ldr_uimm64(9, 8, 0x020),     # ldr x9, [x8, #0x20] (GetVersion)
            _arm64_blr(9),                      # blr x9
            _arm64_bl(0x001500 + 24, 0x004B20), # bl 0x4b20 (callee invokes ExceptionCheck)
            ARM64_RET,
        ]
        for i, word in enumerate(insns):
            struct.pack_into("<I", raw_so, 0x001500 + i * 4, word)

        elf = ElfBinary(bytes(raw_so), name="libcallee.so")
        sites = raw_trace_jni_upcalls(elf, 0x001500)
        self.assertEqual([s.jni_api_name for s in sites], ["GetVersion", "ExceptionCheck"])

    def test_cross_boundary_slice_before_and_after(self) -> None:
        slice_data = get_cross_boundary_slice(
            "com.dropper.Core#decryptPayload", apk_path=str(self.apk_path)
        )
        self.assertIn("System.loadLibrary(\"core-crypto\")", slice_data["java_caller_source"])
        self.assertIn("(**(code **)(*param_1 + 0x548))", slice_data["decompiled_c_before"])
        self.assertIn("(*env)->GetStringUTFChars(env, rc4KeyStr, NULL)", slice_data["decompiled_c_after"])
        self.assertIn("(*env)->GetByteArrayElements(env, encryptedData, NULL)", slice_data["decompiled_c_after"])

    def test_extract_jni_onload_strings_and_stp(self) -> None:
        res = extract_jni_onload_strings(str(self.so_path))
        extracted_vals = {s["value"] for s in res["strings"]}
        self.assertIn("signC2Beacon", extracted_vals)
        self.assertIn("connectRaw", extracted_vals)
        self.assertIn("https://c2.dropper-gate.net/api/v2/checkin", extracted_vals)
        self.assertIn("dalvik.system.InMemoryDexClassLoader", extracted_vals)
        self.assertIn("com/dropper/Core", extracted_vals)

        # Also test STP Xt1, Xt2, [SP, #offset] 16-byte stack string reconstruction
        raw_so = bytearray(self.so_path.read_bytes())
        q1 = int.from_bytes(b"stpStack", "little")
        q2 = int.from_bytes(b"Secret!\x00", "little")
        # STP X11, X12, [SP, #0x60] -> 0xA90003E0 | (imm7 << 15) | (rt2 << 10) | rt1, imm7 = 0x60 // 8 = 12
        stp_insn = 0xA90003E0 | (12 << 15) | (12 << 10) | 11
        stp_seq = [
            _arm64_movz(11, q1 & 0xFFFF, 0),
            _arm64_movk(11, (q1 >> 16) & 0xFFFF, 16),
            _arm64_movk(11, (q1 >> 32) & 0xFFFF, 32),
            _arm64_movk(11, (q1 >> 48) & 0xFFFF, 48),
            _arm64_movz(12, q2 & 0xFFFF, 0),
            _arm64_movk(12, (q2 >> 16) & 0xFFFF, 16),
            _arm64_movk(12, (q2 >> 32) & 0xFFFF, 32),
            _arm64_movk(12, (q2 >> 48) & 0xFFFF, 48),
            stp_insn,
            ARM64_RET,
        ]
        for i, word in enumerate(stp_seq):
            struct.pack_into("<I", raw_so, 0x005400 + i * 4, word)
        stp_elf = ElfBinary(bytes(raw_so), name="libstp.so")
        stp_strings = {s.value for s in raw_extract_onload_strings(stp_elf)}
        self.assertIn("stpStackSecret!", stp_strings)

    def test_ghidra_sync_and_mcp_jsonrpc(self) -> None:
        sync_res = sync_ghidra_jni_types(str(self.trace_path), project_name="test_proj.gpr")
        self.assertEqual(sync_res["status"], "synced")
        self.assertEqual(sync_res["jni_vtable_slots_applied"], 233)
        self.assertEqual(sync_res["synced_function_count"], 3)

        # Verify blueprint alias tools work identically
        self.assertEqual(list_jni_methods(str(self.apk_path))["declared_native_count"], 14)
        self.assertEqual(
            get_cross_boundary_callgraph("decryptPayload", str(self.apk_path))["qualified_method"],
            "com.dropper.Core#decryptPayload",
        )
        self.assertEqual(trace_jni_callbacks(str(self.so_path), "0x23c8")["upcall_count"], 3)
        self.assertEqual(import_dynamic_trace(str(self.trace_path))["synced_function_count"], 3)
        self.assertGreaterEqual(deobfuscate_jni_strings(str(self.so_path))["string_count"], 5)

        # Verify MCP JSON-RPC 2.0 protocol handler
        if hasattr(mcp, "handle_jsonrpc_request"):
            init_resp = mcp.handle_jsonrpc_request(
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
            )
            self.assertEqual(init_resp["result"]["serverInfo"]["name"], "jnisleuth-mcp")

            list_resp = mcp.handle_jsonrpc_request(
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            )
            tool_names = {t["name"] for t in list_resp["result"]["tools"]}
            self.assertTrue(
                {
                    "resolve_apk_jni_map",
                    "get_cross_boundary_slice",
                    "trace_jni_upcalls",
                    "sync_ghidra_jni_types",
                    "extract_jni_onload_strings",
                }.issubset(tool_names)
            )

            call_resp = mcp.handle_jsonrpc_request(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "resolve_apk_jni_map",
                        "arguments": {"apk_path": str(self.apk_path)},
                    },
                }
            )
            self.assertFalse(call_resp["result"]["isError"])
            payload = json.loads(call_resp["result"]["content"][0]["text"])
            self.assertEqual(payload["declared_native_count"], 14)

    def test_cli_commands(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["scan", "--apk", str(self.apk_path)])
        self.assertEqual(rc, 0)
        output = buf.getvalue()
        self.assertIn("Found 14 declared `native` methods across 4 classes.", output)
        self.assertIn("Resolved 11/14 methods via static struct table @ 0x0004d210", output)
        self.assertIn("com.dropper.Core#decryptPayload", output)
        self.assertIn("libcore.so+0x0023c8", output)

        # Test slice CLI
        buf_slice = io.StringIO()
        with redirect_stdout(buf_slice):
            rc_s = cli_main(["slice", "--method", "com.dropper.Core#decryptPayload", "--apk", str(self.apk_path)])
        self.assertEqual(rc_s, 0)
        self.assertIn("Java_com_dropper_Core_decryptPayload", buf_slice.getvalue())

    def test_native_dobby_agent_compilation_and_execution(self) -> None:
        gcc = shutil.which("gcc")
        if not gcc:
            self.skipTest("gcc not available on host")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            so_out = tmp_path / "libjnisleuth_agent_test.so"
            trace_out1 = tmp_path / "dobby_captured_1.json"
            trace_out2 = tmp_path / "dobby_captured_2.json"
            unpacked_dex_out = tmp_path / "unpacked_dump.dex"

            cmd = [
                gcc,
                "-x",
                "c",
                "-std=c11",
                "-O2",
                "-shared",
                "-fPIC",
                "-I",
                str(REPO_ROOT / "agent-native" / "include"),
                str(REPO_ROOT / "agent-native" / "src" / "elf_utils.cpp"),
                str(REPO_ROOT / "agent-native" / "src" / "jni_hook.cpp"),
                "-ldl",
                "-lpthread",
                "-o",
                str(so_out),
            ]
            subprocess.run(cmd, check=True)
            self.assertTrue(so_out.exists())

            lib = ctypes.CDLL(str(so_out))
            lib.jnisleuth_set_trace_output_path.argtypes = [ctypes.c_char_p]
            lib.jnisleuth_set_trace_output_path(str(trace_out1).encode("utf-8"))

            class JNINativeMethodC(ctypes.Structure):
                _fields_ = [
                    ("name", ctypes.c_char_p),
                    ("signature", ctypes.c_char_p),
                    ("fnPtr", ctypes.c_void_p),
                ]

            fn_addr = ctypes.cast(lib.jnisleuth_hooked_RegisterNatives, ctypes.c_void_p).value
            methods_arr = (JNINativeMethodC * 1)(
                JNINativeMethodC(
                    b"signC2Beacon",
                    b"(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                    ctypes.c_void_p(fn_addr),
                )
            )
            lib.jnisleuth_hooked_RegisterNatives.argtypes = [
                ctypes.c_void_p,
                ctypes.c_char_p,
                ctypes.POINTER(JNINativeMethodC),
                ctypes.c_int,
            ]
            lib.jnisleuth_hooked_RegisterNatives.restype = ctypes.c_int

            # Test slash-formatted JNI class descriptor normalization (`Lcom/dropper/Core;` -> `com.dropper.Core`)
            rc = lib.jnisleuth_hooked_RegisterNatives(
                None,
                b"Lcom/dropper/Core;",
                methods_arr,
                1,
            )
            self.assertEqual(rc, 0)
            self.assertTrue(trace_out1.exists())

            captured = json.loads(trace_out1.read_text(encoding="utf-8"))
            self.assertEqual(captured["agent"], "jnisleuth-dobby")
            self.assertEqual(len(captured["registrations"]), 1)
            reg = captured["registrations"][0]
            self.assertEqual(reg["class_name"], "com.dropper.Core")
            self.assertEqual(reg["method_name"], "signC2Beacon")
            self.assertEqual(reg["so_name"], "libjnisleuth_agent_test.so")
            self.assertTrue(int(reg["fn_offset"], 16) > 0)

            # Switch trace output path and verify fresh JSON trace is written cleanly
            lib.jnisleuth_set_trace_output_path(str(trace_out2).encode("utf-8"))
            rc2 = lib.jnisleuth_hooked_RegisterNatives(
                None,
                b"com/dropper/net/SocketBridge",
                methods_arr,
                1,
            )
            self.assertEqual(rc2, 0)
            captured2 = json.loads(trace_out2.read_text(encoding="utf-8"))
            self.assertEqual(len(captured2["registrations"]), 1)
            self.assertEqual(captured2["registrations"][0]["class_name"], "com.dropper.net.SocketBridge")

            # Test DexFile::OpenCommon unpacker hook
            lib.jnisleuth_hooked_DexFile_OpenCommon.argtypes = [
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.c_char_p,
                ctypes.c_char_p,
            ]
            lib.jnisleuth_hooked_DexFile_OpenCommon.restype = ctypes.c_int
            dex_sample = build_dex_bytes([("Lcom/dropper/Unpacked;", [("hiddenNative", "()V", 0x0101)])])
            rc_dex = lib.jnisleuth_hooked_DexFile_OpenCommon(
                dex_sample,
                len(dex_sample),
                b"memory://classes.dex",
                str(unpacked_dex_out).encode("utf-8"),
            )
            self.assertEqual(rc_dex, 0)
            unpacked_methods, _ = parse_dex_or_apk(unpacked_dex_out)
            self.assertEqual(len(unpacked_methods), 1)
            self.assertEqual(unpacked_methods[0].qualified_name, "com.dropper.Unpacked#hiddenNative")


if __name__ == "__main__":
    unittest.main()

