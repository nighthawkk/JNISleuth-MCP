"""IDAPython 9.0+ (idalib / idat64) script to import JNI types, rename stripped functions, and add OLLVM xrefs."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any


def apply_manifest_in_ida(manifest: dict[str, Any]) -> dict[str, Any]:
    """Applies JNI C header types, function prototypes, and OLLVM xrefs inside an active IDA session."""
    import ida_auto  # type: ignore
    import ida_bytes  # type: ignore
    import ida_funcs  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_nalt  # type: ignore
    import ida_name  # type: ignore
    import ida_typeinf  # type: ignore
    import ida_xref  # type: ignore
    import idc  # type: ignore

    ida_auto.auto_wait()

    # 1. Parse complete JNI C header into IDA Local Types (til)
    c_header = manifest.get("jni_c_header", "")
    parsed_type_errors = 0
    if c_header:
        parsed_type_errors = ida_typeinf.idc_parse_types(c_header, 0)

    image_base = ida_nalt.get_imagebase()
    renamed_count = 0
    typed_count = 0
    decompiled_functions: dict[str, str] = {}

    has_hexrays = False
    try:
        has_hexrays = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        has_hexrays = False

    # 2. Rename and type all recovered JNI functions
    for fn in manifest.get("functions", []):
        off_int = int(fn.get("fn_offset_int", 0))
        ea = image_base + off_int if off_int < image_base else off_int
        c_name = fn.get("c_function_name", f"jni_sub_{off_int:06x}")
        c_sig = fn.get("c_signature", "")

        if not ida_funcs.get_func(ea):
            ida_funcs.add_func(ea)

        if ida_name.set_name(ea, c_name, ida_name.SN_NOWARN | ida_name.SN_FORCE):
            renamed_count += 1

        if c_sig:
            decl = c_sig if c_sig.endswith(";") else c_sig + ";"
            if idc.SetType(ea, decl):
                typed_count += 1

        if has_hexrays:
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    decompiled_functions[c_name] = str(cfunc)
            except Exception:
                pass

    # 3. Annotate & add code cross-references (fl_JN) for resolved OLLVM indirect branches (BR X8)
    xrefs_added = 0
    for br in manifest.get("ollvm_indirect_branches", []):
        site_off = int(br.get("site_offset", "0x0"), 16)
        site_ea = image_base + site_off if site_off < image_base else site_off
        targets = [int(t, 16) for t in br.get("target_vas", [])]
        for t_va in targets:
            t_ea = image_base + t_va if t_va < image_base else t_va
            ida_xref.add_cref(site_ea, t_ea, ida_xref.fl_JN | ida_xref.XREF_USER)
            xrefs_added += 1
        comment = (
            f"[JNISleuth OLLVM] {br.get('pattern_type', 'Indirect Branch')} -> "
            + ", ".join(br.get("target_vas", []))
        )
        ida_bytes.set_cmt(site_ea, comment, False)

    ida_auto.auto_wait()
    return {
        "parsed_type_errors": parsed_type_errors,
        "renamed_count": renamed_count,
        "typed_count": typed_count,
        "ollvm_xrefs_added": xrefs_added,
        "decompiled_functions": decompiled_functions,
    }


def _cli_entry() -> None:
    try:
        import idc  # type: ignore

        argv = idc.ARGV if hasattr(idc, "ARGV") and len(idc.ARGV) > 1 else sys.argv
    except ImportError:
        argv = sys.argv

    if len(argv) < 2:
        print("Usage: ResolveJNIBridge_IDA.py <manifest.json>")
        return

    manifest_path = Path(argv[1])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    result = apply_manifest_in_ida(manifest)

    out_path = manifest_path.with_suffix(".ida_result.json")
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    try:
        import ida_pro  # type: ignore

        ida_pro.qexit(0)
    except ImportError:
        pass


if __name__ == "__main__":
    _cli_entry()
