"""Command-line interface for JNISleuth-MCP."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from .ghidra_bridge import sync_ghidra_jni_types
from .mcp_server import (
    extract_jni_onload_strings,
    get_cross_boundary_slice,
    mcp,
    trace_jni_upcalls,
)
from .models import ResolvedJNIBinding
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
    project_name = f"{Path(args.apk).stem}.gpr"

    sync_res = sync_ghidra_jni_types(
        bindings,
        project_name=project_name,
        run_headless=bool(args.ghidra_headless),
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
            "bindings": [b.to_dict() for b in bindings],
            "ghidra_sync": sync_res,
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
        f"to Ghidra project: {project_name}"
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


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jnisleuth",
        description="JNISleuth-MCP: Automated RegisterNatives Recovery & Unified Jadx+Ghidra MCP Server",
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
