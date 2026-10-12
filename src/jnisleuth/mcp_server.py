"""Unified FastMCP server exposing Java-to-Native JNI analysis tools for AI agents."""

from __future__ import annotations

import inspect
import json
from pathlib import Path
import sys
from typing import Any, Callable
import zipfile

from .dex_parser import parse_dex_Or_apk, synthesize_java_caller_view
from .elf_scanner import ElfBinary
from .ghidra_bridge import sync_ghidra_jni_types as _sync_ghidra_jni_types
from .models import CrossBoundarySlice
from .static_heuristic import (
    analyze_apk_bundle,
    extract_jni_onload_strings as _extract_jni_onload_strings,
)
from .vtable_analyzer import (
    reconstruct_decompiled_c,
    trace_jni_upcalls as _trace_jni_upcalls,
)

try:
    from fastmcp import FastMCP  # type: ignore
except ImportError:

    class FastMCP:  # type: ignore[no-redef]
        """Lightweight, zero-dependency MCP JSON-RPC 2.0 server compatible with FastMCP."""

        def __init__(self, name: str) -> None:
            self.name = name
            self._tools: dict[str, Callable[..., Any]] = {}

        def tool(
            self, name: str | None = None, description: str | None = None
        ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
            def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
                tool_name = name or fn.__name__
                fn._mcp_tool_name = tool_name  # type: ignore[attr-defined]
                fn._mcp_description = description or (inspect.getdoc(fn) or "")  # type: ignore[attr-defined]
                self._tools[tool_name] = fn
                return fn

            return decorator

        def list_tools_metadata(self) -> list[dict[str, Any]]:
            tools_meta: list[dict[str, Any]] = []
            for t_name, fn in self._tools.items():
                sig = inspect.signature(fn)
                props: dict[str, Any] = {}
                required: list[str] = []
                for p_name, param in sig.parameters.items():
                    props[p_name] = {"type": "string"}
                    if param.default is inspect.Parameter.empty:
                        required.append(p_name)
                tools_meta.append(
                    {
                        "name": t_name,
                        "description": getattr(fn, "_mcp_description", "") or (inspect.getdoc(fn) or ""),
                        "inputSchema": {
                            "type": "object",
                            "properties": props,
                            "required": required,
                        },
                    }
                )
            return tools_meta

        def handle_jsonrpc_request(self, req: dict[str, Any]) -> dict[str, Any] | None:
            method = req.get("method", "")
            req_id = req.get("id")
            params = req.get("params") or {}

            if method.startswith("notifications/"):
                return None

            if method == "initialize":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": self.name, "version": "0.1.0"},
                    },
                }

            if method == "ping":
                return {"jsonrpc": "2.0", "id": req_id, "result": {}}

            if method == "tools/list":
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": self.list_tools_metadata()},
                }

            if method == "tools/call":
                t_name = params.get("name", "")
                t_args = params.get("arguments") or {}
                fn = self._tools.get(t_name)
                if fn is None:
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32601, "message": f"Unknown MCP tool: {t_name}"},
                    }
                try:
                    res = fn(**t_args)
                    text_payload = (
                        json.dumps(res, indent=2) if not isinstance(res, str) else res
                    )
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": text_payload}],
                            "isError": False,
                        },
                    }
                except Exception as exc:  # pylint: disable=broad-except
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Error: {exc}"}],
                            "isError": True,
                        },
                    }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

        def run(self) -> None:
            """Runs the MCP JSON-RPC 2.0 stdio transport loop."""
            for raw_line in sys.stdin:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    req = json.loads(line)
                except json.JSONDecodeError:
                    continue
                resp = self.handle_jsonrpc_request(req)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()


mcp = FastMCP("jnisleuth-mcp")

# Cache most recently analyzed APK path so slice/upcall tools work seamlessly
_ACTIVE_STATE: dict[str, str] = {"apk_path": ""}


def _find_default_apk(explicit_apk: str = "") -> Path:
    if explicit_apk:
        return Path(explicit_apk)
    if _ACTIVE_STATE.get("apk_path"):
        return Path(_ACTIVE_STATE["apk_path"])
    repo_root = Path(__file__).resolve().parents[2]
    for candidate in (
        repo_root / "samples" / "banker_dropper.apk",
        repo_root / "examples" / "obfuscated_jni_sample.apk",
    ):
        if candidate.exists():
            return candidate
    raise FileNotFoundError("No APK path specified and no default sample APK found.")


def _load_elf_by_name(so_name: str, apk_path: str = "") -> ElfBinary:
    p = Path(so_name)
    if p.exists() and p.is_file():
        return ElfBinary.from_file(p)

    repo_root = Path(__file__).resolve().parents[2]
    for local_candidate in (
        repo_root / "examples" / so_name,
        repo_root / "samples" / so_name,
    ):
        if local_candidate.exists():
            return ElfBinary.from_file(local_candidate)

    apk = _find_default_apk(apk_path)
    if zipfile.is_zipfile(apk):
        with zipfile.ZipFile(apk, "r") as zf:
            for member in zf.namelist():
                if member.endswith(".so") and (
                    Path(member).name == so_name
                    or so_name in member
                    or (so_name == "libcore.so" and Path(member).name == "libcore-crypto.so")
                ):
                    return ElfBinary(zf.read(member), name=Path(member).name, path=member)
    raise FileNotFoundError(f"Could not locate shared library {so_name!r}")


@mcp.tool()
def resolve_apk_jni_map(
    apk_path: str,
    arch: str = "arm64-v8a",
    dynamic_trace_path: str = "",
) -> dict[str, Any]:
    """Extracts all `native` declarations from DEX and maps them to exact ELF file offsets in `lib/*.so`."""
    _ACTIVE_STATE["apk_path"] = apk_path
    report = analyze_apk_bundle(
        apk_path=apk_path,
        arch=arch,
        dynamic_trace_path=dynamic_trace_path or None,
    )
    return {
        "apk_path": report["apk_path"],
        "arch": report["arch"],
        "dex_count": report["dex_count"],
        "declared_native_count": len(report["dex_methods"]),
        "exported_jni_symbol_count": report["exported_jni_symbol_count"],
        "static_resolved_count": report["static_resolved_count"],
        "dynamic_resolved_count": report["dynamic_resolved_count"],
        "unresolved_static_count": report["unresolved_static_count"],
        "table_offsets": [f"0x{off:06x}" for off in report["table_offsets"]],
        "bindings": [b.to_dict() for b in report["bindings"]],
    }


@mcp.tool()
def get_cross_boundary_slice(
    java_method: str,
    apk_path: str = "",
) -> dict[str, Any]:
    """Returns the decompiled Java caller (via Jadx) and the typed, decompiled C/ARM64 implementation (via Ghidra) in a single unified response."""
    target_apk = _find_default_apk(apk_path)
    report = analyze_apk_bundle(target_apk)
    dex_methods = report["dex_methods"]
    bindings = report["bindings"]
    elf_map = {e.name: e for e in report["elf_binaries"]}

    query = java_method.strip()
    matched_binding = None
    for b in bindings:
        if (
            b.qualified_method == query
            or b.method_name == query
            or query in b.qualified_method
        ):
            matched_binding = b
            break

    if matched_binding is None:
        raise ValueError(f"No resolved JNI binding found matching {java_method!r}")

    matched_dex = next(
        (
            dm
            for dm in dex_methods
            if dm.class_name == matched_binding.class_name
            and dm.method_name == matched_binding.method_name
        ),
        dex_methods[0],
    )
    elf = elf_map.get(matched_binding.so_name) or (
        report["elf_binaries"][0] if report["elf_binaries"] else None
    )

    java_source = synthesize_java_caller_view(matched_dex, so_name=matched_binding.so_name)
    before_c, after_c, upcalls = reconstruct_decompiled_c(matched_binding, elf=elf)

    slice_obj = CrossBoundarySlice(
        qualified_method=matched_binding.qualified_method,
        binding=matched_binding,
        java_caller_source=java_source,
        decompiled_c_before=before_c,
        decompiled_c_after=after_c,
        upcalls=upcalls,
    )
    return slice_obj.to_dict()


@mcp.tool()
def trace_jni_upcalls(
    so_name: str,
    fn_offset: str | int,
    apk_path: str = "",
) -> dict[str, Any]:
    """Lists every Java reflection callback (`FindClass`, `GetMethodID`, `CallObjectMethod`, `SetByteArrayRegion`) invoked inside a native ARM64 function."""
    elf = _load_elf_by_name(so_name, apk_path=apk_path)
    offset_int = int(fn_offset, 16) if isinstance(fn_offset, str) else int(fn_offset)
    upcalls = _trace_jni_upcalls(elf, offset_int)
    return {
        "so_name": elf.name,
        "arch": elf.arch_abi,
        "fn_offset": f"0x{offset_int:06x}",
        "upcall_count": len(upcalls),
        "upcalls": [u.to_dict() for u in upcalls],
    }


@mcp.tool()
def sync_ghidra_jni_types(
    trace_json: str,
    project_name: str = "banker_dropper.gpr",
) -> dict[str, Any]:
    """Applies `JNIEnv*`, `JavaVM*`, `JNINativeMethod` structs, and recovered function signatures directly into an active or headless Ghidra project."""
    return _sync_ghidra_jni_types(trace_json=trace_json, project_name=project_name)


@mcp.tool()
def extract_jni_onload_strings(
    so_name: str,
    apk_path: str = "",
) -> dict[str, Any]:
    """Dumps stack-constructed and XOR-decrypted strings inside `.init_array` and `JNI_OnLoad`."""
    elf = _load_elf_by_name(so_name, apk_path=apk_path)
    extracted = _extract_jni_onload_strings(elf)
    return {
        "so_name": elf.name,
        "arch": elf.arch_abi,
        "string_count": len(extracted),
        "strings": [s.to_dict() for s in extracted],
    }


# Blueprint alias tools for compatibility
@mcp.tool()
def list_jni_methods(apk_path: str, arch: str = "arm64-v8a") -> dict[str, Any]:
    """Alias for resolve_apk_jni_map."""
    return resolve_apk_jni_map(apk_path=apk_path, arch=arch)


@mcp.tool()
def get_cross_boundary_callgraph(java_method: str, apk_path: str = "") -> dict[str, Any]:
    """Alias for get_cross_boundary_slice."""
    return get_cross_boundary_slice(java_method=java_method, apk_path=apk_path)


@mcp.tool()
def trace_jni_callbacks(so_name: str, fn_offset: str | int, apk_path: str = "") -> dict[str, Any]:
    """Alias for trace_jni_upcalls."""
    return trace_jni_upcalls(so_name=so_name, fn_offset=fn_offset, apk_path=apk_path)


@mcp.tool()
def import_dynamic_trace(trace_json: str, project_name: str = "banker_dropper.gpr") -> dict[str, Any]:
    """Alias for sync_ghidra_jni_types."""
    return sync_ghidra_jni_types(trace_json=trace_json, project_name=project_name)


@mcp.tool()
def deobfuscate_jni_strings(so_name: str, apk_path: str = "") -> dict[str, Any]:
    """Alias for extract_jni_onload_strings."""
    return extract_jni_onload_strings(so_name=so_name, apk_path=apk_path)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
