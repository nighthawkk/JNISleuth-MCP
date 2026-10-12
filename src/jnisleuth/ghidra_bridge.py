"""Ghidra headless bridge and type synchronization engine for JNISleuth-MCP."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from typing import Any

from .models import (
    ResolvedJNIBinding,
    build_c_jni_signature,
    class_descriptor_to_java_name,
)
from .vtable_analyzer import (
    JAVAVM_INVOKE_INTERFACE_ENTRIES,
    JNI_NATIVE_INTERFACE_ENTRIES,
)


def build_ghidra_type_spec() -> dict[str, Any]:
    """Builds the complete `/JNI` DataTypeManager specification for Ghidra."""
    return {
        "category": "/JNI",
        "typedefs": {
            "jboolean": "uchar",
            "jbyte": "char",
            "jchar": "ushort",
            "jshort": "short",
            "jint": "int",
            "jsize": "int",
            "jlong": "longlong",
            "jfloat": "float",
            "jdouble": "double",
            "jobject": "void *",
            "jclass": "void *",
            "jstring": "void *",
            "jarray": "void *",
            "jobjectArray": "void *",
            "jbooleanArray": "void *",
            "jbyteArray": "void *",
            "jcharArray": "void *",
            "jshortArray": "void *",
            "jintArray": "void *",
            "jlongArray": "void *",
            "jfloatArray": "void *",
            "jdoubleArray": "void *",
            "jthrowable": "void *",
            "jweak": "void *",
            "jfieldID": "void *",
            "jmethodID": "void *",
        },
        "structs": {
            "JNINativeMethod": [
                {"name": "name", "type": "char *", "offset": 0},
                {"name": "signature", "type": "char *", "offset": 8},
                {"name": "fnPtr", "type": "void *", "offset": 16},
            ],
            "JNINativeInterface_": [
                {
                    "index": idx,
                    "offset_64": f"0x{idx * 8:03x}",
                    "offset_32": f"0x{idx * 4:03x}",
                    "name": name,
                    "prototype": proto,
                }
                for idx, (name, proto) in enumerate(JNI_NATIVE_INTERFACE_ENTRIES)
            ],
            "JNIInvokeInterface_": [
                {
                    "index": idx,
                    "offset_64": f"0x{idx * 8:03x}",
                    "offset_32": f"0x{idx * 4:03x}",
                    "name": name,
                    "prototype": proto,
                }
                for idx, (name, proto) in enumerate(JAVAVM_INVOKE_INTERFACE_ENTRIES)
            ],
        },
    }


def normalize_bindings_input(
    trace_or_bindings: str | Path | dict[str, Any] | list[Any],
) -> list[dict[str, Any]]:
    """Normalizes a file path, JSON string, dict, or list of ResolvedJNIBinding into dict entries."""
    if isinstance(trace_or_bindings, list) and all(
        isinstance(x, ResolvedJNIBinding) for x in trace_or_bindings
    ):
        return [x.to_dict() for x in trace_or_bindings]

    raw_data: Any = trace_or_bindings
    if isinstance(trace_or_bindings, Path) or (
        isinstance(trace_or_bindings, str)
        and not trace_or_bindings.lstrip().startswith(("{", "["))
    ):
        p = Path(trace_or_bindings)
        if p.exists():
            raw_data = json.loads(p.read_text(encoding="utf-8"))
        else:
            raise FileNotFoundError(f"Trace JSON path does not exist: {p}")
    elif isinstance(trace_or_bindings, str):
        raw_data = json.loads(trace_or_bindings)

    if isinstance(raw_data, dict):
        items = raw_data.get(
            "bindings", raw_data.get("registrations", raw_data.get("functions", []))
        )
    elif isinstance(raw_data, list):
        items = raw_data
    else:
        items = []

    normalized: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, ResolvedJNIBinding):
            normalized.append(item.to_dict())
            continue
        cls_name = class_descriptor_to_java_name(item.get("class_name", "com.unknown.Native"))
        m_name = item.get("method_name", item.get("name", "unknownMethod"))
        jni_sig = item.get("jni_signature", item.get("signature", "()V"))
        is_static = bool(item.get("is_static", False))
        c_fn_name, c_sig, c_params = build_c_jni_signature(
            cls_name, m_name, jni_sig, is_static=is_static
        )
        raw_off = item.get("fn_offset", item.get("offset", "0x0"))
        off_int = int(raw_off, 16) if isinstance(raw_off, str) else int(raw_off)
        normalized.append(
            {
                "qualified_method": f"{cls_name}#{m_name}",
                "class_name": cls_name,
                "method_name": m_name,
                "jni_signature": jni_sig,
                "so_name": item.get("so_name", "libcore-crypto.so"),
                "fn_offset": f"0x{off_int:06x}",
                "fn_offset_int": off_int,
                "resolution_mode": item.get("resolution_mode", "Dynamic (Dobby)"),
                "is_static": is_static,
                "c_function_name": item.get("c_function_name") or c_fn_name,
                "c_signature": item.get("c_signature") or c_sig,
                "c_parameters": [
                    {"type": pt, "name": pn} for pt, pn in c_params
                ],
            }
        )
    return normalized


def sync_ghidra_jni_types(
    trace_json: str | Path | dict[str, Any] | list[Any],
    project_name: str = "banker_dropper.gpr",
    output_manifest_path: str | Path | None = None,
    run_headless: bool = False,
    binary_path: str | Path | None = None,
) -> dict[str, Any]:
    """Synchronizes JNIEnv*, JavaVM*, JNINativeMethod, and recovered function signatures to Ghidra."""
    functions = normalize_bindings_input(trace_json)
    type_spec = build_ghidra_type_spec()

    script_dir = Path(__file__).resolve().parents[2] / "ghidra_scripts"
    resolve_script = script_dir / "ResolveJNIBridge.py"

    manifest = {
        "project_name": project_name,
        "ghidra_script": str(resolve_script),
        "jni_vtable_slots": len(JNI_NATIVE_INTERFACE_ENTRIES),
        "javavm_vtable_slots": len(JAVAVM_INVOKE_INTERFACE_ENTRIES),
        "synced_function_count": len(functions),
        "types": type_spec,
        "functions": functions,
    }

    if output_manifest_path is not None:
        out_p = Path(output_manifest_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR", "")
    headless_bin = Path(ghidra_dir) / "support" / "analyzeHeadless" if ghidra_dir else None
    headless_executed = False
    headless_cmd: list[str] = []

    if run_headless and headless_bin and headless_bin.exists() and binary_path:
        manifest_tmp = Path(output_manifest_path or "/tmp/jnisleuth_ghidra_sync.json")
        manifest_tmp.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        headless_cmd = [
            str(headless_bin),
            "/tmp",
            project_name.removesuffix(".gpr"),
            "-import",
            str(binary_path),
            "-scriptPath",
            str(script_dir),
            "-postScript",
            "ResolveJNIBridge.py",
            str(manifest_tmp),
        ]
        try:
            subprocess.run(headless_cmd, check=True, capture_output=True, text=True, timeout=120)
            headless_executed = True
        except (subprocess.SubprocessError, OSError):
            headless_executed = False

    return {
        "status": "synced",
        "project_name": project_name,
        "synced_function_count": len(functions),
        "jni_vtable_slots_applied": len(JNI_NATIVE_INTERFACE_ENTRIES),
        "javavm_vtable_slots_applied": len(JAVAVM_INVOKE_INTERFACE_ENTRIES),
        "ghidra_script": str(resolve_script),
        "headless_executed": headless_executed,
        "functions": functions,
    }
