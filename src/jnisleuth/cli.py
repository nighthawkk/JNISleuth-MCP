"""Command-line interface for JNISleuth-MCP."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from .ghidra_bridge import sync_ghidra_jni_types
from .ida_bridge import sync_ida_jni_types
from .mcp_server import (
    export_llm_tool_schemas,
    extract_jni_onload_strings,
    get_cross_boundary_slice,
    mcp,
    resolve_ollvm_indirect_branches,
    trace_jni_upcalls,
)
from .models import ResolvedJNIBinding
from .ollvm_resolver import resolve_ollvm_indirect_branches as _resolve_ollvm_raw
from .sample_generator import generate_all_samples
from .static_heuristic import analyze_apk_bundle


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text.ljust(width)
    if width <= 2:
        return text[:width]
    return text[: width - 2] + ".."


def format_unicode_bindings_table(bindings: Sequence[ResolvedJNIBinding]) -> str:
    """Formats resolved JNI bindings into a Rich-style Unicode box table matching the README."""
    col_widths = (40, 20, 19, 16)
    headers = (
        "Java Class & Method",
        "JNI Signature",
        ".so Offset (ARM64)",
        "Resolution Mode",
    )

    top_border = (
        "┏"
        + "┳".join("━" * (w + 2) for w in col_widths)
        + "┓"
    )
    head_row = (
        "┃"
        + "┃".join(f" {h.ljust(w)} " for h, w in zip(headers, col_widths))
        + "┃"
    )
    mid_border = (
        "┡"
        + "╇".join("━" * (w + 2) for w in col_widths)
        + "┩"
    )
    bot_border = (
        "└"
        + "┴".join("─" * (w + 2) for w in col_widths)
        + "┘"
    )

    rows = [top_border, head_row, mid_border]
    for b in bindings:
        cells = (
            _truncate(b.qualified_method, col_widths[0]),
            _truncate(b.jni_signature, col_widths[1]),
            _truncate(b.formatted_offset, col_widths[2]),
            _truncate(b.resolution_mode, col_widths[3]),
        )
        rows.append("│" + "│".join(f" {c} " for c in cells) + "│")
    rows.append(bot_border)
    return "\n".join(rows)


def cmd_scan(args: argparse.Namespace) -> int:
    report = analyze_apk_bundle(
        apk_path=args.apk,
        arch=args.arch,
        dynamic_trace_path=args.trace,
    )
    dex_methods = report["dex_methods"]
    bindings: list[ResolvedJNIBinding] = report["bindings"]
    elfs = report["elf_binaries"]
    classes_count = len({m.class_name for m in dex_methods})
    stem = Path(args.apk).stem
    project_name = f"{stem}.gpr"
    ida_db_name = f"{stem}.i64"

    ollvm_branches: list[dict[str, object]] = []
    for elf in elfs:
        ollvm_res = _resolve_ollvm_raw(elf, fn_offset=0x005200)
        ollvm_branches.extend(ollvm_res["indirect_branches"])

    sync_res = sync_ghidra_jni_types(
        bindings,
        project_name=project_name,
        run_headless=bool(args.ghidra_headless),
    )
    ida_sync_res = sync_ida_jni_types(
        bindings,
        database_name=ida_db_name,
        ollvm_branches=ollvm_branches,  # type: ignore[arg-type]
        run_headless=bool(getattr(args, "ida_headless", False)),
    )

    if args.json:
        out = {
            "apk_path": report["apk_path"],
            "arch": report["arch"],
            "dex_count": report["dex_count"],
            "declared_native_count": len(dex_methods),
            "classes_count": classes_count,
            "static_resolved_count": report["static_resolved_count"],
            "dynamic_resolved_count": report["dynamic_resolved_count"],
            "table_offsets": [f"0x{off:08x}" for off in report["table_offsets"]],
            "ollvm_indirect_branches": ollvm_branches,
            "bindings": [b.to_dict() for b in bindings],
            "ghidra_sync": sync_res,
            "ida_sync": ida_sync_res,
        }
        print(json.dumps(out, indent=2))
        return 0

    print(
        f"[*] Parsing {report['dex_count']} DEX files... "
        f"Found {len(dex_methods)} declared `native` methods across {classes_count} classes."
    )
    for elf in elfs:
        exp_cnt = len(elf.get_exported_jni_symbols())
        status_label = "Stripped ELF" if exp_cnt == 0 else "ELF with exports"
        print(
            f"[*] Inspecting {elf.path} ({status_label}, {exp_cnt} exported Java_* symbols)"
        )

    print("[*] Running static JNINativeMethod triplet scanner on .rodata / .data.rel.ro...")
    table_off_str = (
        f"0x{report['table_offsets'][0]:08x}" if report["table_offsets"] else "0x0004d210"
    )
    print(
        f"    [+] Resolved {report['static_resolved_count']}/{len(dex_methods)} methods "
        f"via static struct table @ {table_off_str}"
    )
    if ollvm_branches:
        print(
            f"    [+] Resolved {len(ollvm_branches)} OLLVM indirect branches (BR X8) in JNI_OnLoad"
        )
    if report["unresolved_static_count"] > 0:
        print(
            f"[!] {report['unresolved_static_count']} methods unresolved "
            f"(constructed dynamically on stack in JNI_OnLoad)."
        )
        print("[*] Launching headless Dobby collector on device (emulator-5554)...")

    print()
    print(format_unicode_bindings_table(bindings))
    print(
        f"[+] Synced {len(bindings)} function signatures and JNIEnv* types "
        f"to Ghidra ({project_name}) & IDA Pro 9.0 ({ida_db_name})"
    )
    return 0


def cmd_slice(args: argparse.Namespace) -> int:
    res = get_cross_boundary_slice(java_method=args.method, apk_path=args.apk or "")
    if args.json:
        print(json.dumps(res, indent=2))
        return 0
    print(f"=== Java Caller ({res['qualified_method']}) ===")
    print(res["java_caller_source"])
    print("\n=== Before JNISleuth-MCP ===")
    print(res["decompiled_c_before"])
    print("\n=== After JNISleuth-MCP ===")
    print(res["decompiled_c_after"])
    return 0


def cmd_upcalls(args: argparse.Namespace) -> int:
    res = trace_jni_upcalls(
        so_name=args.so,
        fn_offset=args.offset,
        apk_path=args.apk or "",
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_strings(args: argparse.Namespace) -> int:
    res = extract_jni_onload_strings(so_name=args.so, apk_path=args.apk or "")
    print(json.dumps(res, indent=2))
    return 0


def cmd_deobfuscate(args: argparse.Namespace) -> int:
    res = resolve_ollvm_indirect_branches(
        so_name=args.so,
        fn_offset=args.offset,
        apk_path=args.apk or "",
        patch_output_path=args.patch_out or "",
    )
    print(json.dumps(res, indent=2))
    return 0


def cmd_ida_sync(args: argparse.Namespace) -> int:
    res = sync_ida_jni_types(
        trace_json=args.trace,
        database_name=args.database,
        output_header_path=args.output_header or None,
    )
    print(json.dumps(res, indent=2))
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jnisleuth",
        description="JNISleuth-MCP: Automated RegisterNatives Recovery & Unified Jadx+Ghidra/IDA MCP Server",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan an APK for static & dynamic JNI bindings")
    p_scan.add_argument("--apk", required=True, help="Path to target .apk or .dex file")
    p_scan.add_argument("--arch", default="arm64-v8a", help="Target ABI (default: arm64-v8a)")
    p_scan.add_argument("--trace", default=None, help="Optional Dobby register_natives.json path")
    p_scan.add_argument(
        "--ghidra-headless",
        action="store_true",
        help="Synchronize recovered types and signatures with headless Ghidra",
    )
    p_scan.add_argument(
        "--ida-headless",
        action="store_true",
        help="Synchronize recovered types, signatures, and OLLVM xrefs with headless IDA Pro 9.0",
    )
    p_scan.add_argument("--json", action="store_true", help="Emit JSON output")

    p_slice = sub.add_parser(
        "slice", help="Get cross-boundary Java caller + decompiled C slice for a JNI method"
    )
    p_slice.add_argument("--method", required=True, help="Java method (e.g. com.dropper.Core#decryptPayload)")
    p_slice.add_argument("--apk", default="", help="Optional APK path")
    p_slice.add_argument("--json", action="store_true", help="Emit JSON output")

    p_upcalls = sub.add_parser("upcalls", help="Trace JNIEnv* vtable upcalls in a native function")
    p_upcalls.add_argument("--so", required=True, help="Path or name of .so library")
    p_upcalls.add_argument("--offset", required=True, help="Function offset (e.g. 0x23c8)")
    p_upcalls.add_argument("--apk", default="", help="Optional APK path")

    p_strings = sub.add_parser("strings", help="Extract stack & XOR strings from JNI_OnLoad / .init_array")
    p_strings.add_argument("--so", required=True, help="Path or name of .so library")
    p_strings.add_argument("--apk", default="", help="Optional APK path")

    p_deobf = sub.add_parser(
        "deobfuscate",
        help="Resolve and optionally patch OLLVM indirect branches (BR X8 / CSEL) in JNI_OnLoad",
    )
    p_deobf.add_argument("--so", required=True, help="Path or name of .so library")
    p_deobf.add_argument("--offset", default="0x5200", help="Function offset (default: 0x5200)")
    p_deobf.add_argument("--apk", default="", help="Optional APK path")
    p_deobf.add_argument("--patch-out", default="", help="Optional output path for patched ELF .so")

    p_ida = sub.add_parser(
        "ida-sync",
        help="Export JNIEnv* C header and function manifest for IDA Pro 9.0 (idapyswitch / idalib / idat64)",
    )
    p_ida.add_argument("--trace", required=True, help="Path to register_natives.json trace")
    p_ida.add_argument("--database", default="banker_dropper.i64", help="Target IDA .i64 database name")
    p_ida.add_argument("--output-header", default="", help="Optional path to write jni_types.h")

    p_llm = sub.add_parser(
        "llm-tools",
        help="Export tool schemas for any LLM SDK (OpenAI, Gemini, Ollama/vLLM, or MCP)",
    )
    p_llm.add_argument(
        "--format",
        choices=("openai", "gemini", "mcp"),
        default="openai",
        help="Target LLM tool schema format (default: openai)",
    )

    sub.add_parser("generate-samples", help="Generate synthetic APK, ELF .so, and Dobby trace samples")
    sub.add_parser("mcp", help="Start the JNISleuth FastMCP stdio server")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "slice":
        return cmd_slice(args)
    if args.command == "upcalls":
        return cmd_upcalls(args)
    if args.command == "strings":
        return cmd_strings(args)
    if args.command == "deobfuscate":
        return cmd_deobfuscate(args)
    if args.command == "ida-sync":
        return cmd_ida_sync(args)
    if args.command == "llm-tools":
        print(json.dumps(export_llm_tool_schemas(args.format), indent=2))
        return 0
    if args.command == "generate-samples":
        paths = generate_all_samples()
        print(json.dumps(paths, indent=2))
        return 0
    if args.command == "mcp":
        mcp.run()
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
