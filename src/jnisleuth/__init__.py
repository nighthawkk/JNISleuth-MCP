"""JNISleuth-MCP: Automated RegisterNatives Recovery, Stripped ARM64 .so Type Reconstruction, and Unified Jadx + Ghidra MCP Server."""

from .dex_parser import DexParser, parse_dex_Or_apk, parse_dex_or_apk
from .elf_scanner import ElfBinary
from .ida_bridge import (
    detect_ida9_environment,
    generate_ida_jni_c_header,
    sync_ida_jni_types,
)
from .models import (
    CrossBoundarySlice,
    DexNativeMethod,
    ExtractedNativeString,
    JNITripletCandidate,
    JNIUpcallSite,
    ResolvedJNIBinding,
    build_c_jni_signature,
    jni_type_to_c_type,
    jni_type_to_java_type,
    mangle_jni_symbol,
    parse_jni_method_descriptor,
)
from .ollvm_resolver import (
    OLLVMStateTransition,
    ResolvedIndirectBranch,
    patch_ollvm_indirect_branches,
    resolve_ollvm_indirect_branches,
)
from .static_heuristic import (
    analyze_apk_bundle,
    correlate_jni_bindings,
    extract_jni_onload_strings,
    scan_elf_jni_triplets,
)
from .vtable_analyzer import lookup_jni_vtable_offset, reconstruct_decompiled_c, trace_jni_upcalls

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "CrossBoundarySlice",
    "DexNativeMethod",
    "DexParser",
    "ElfBinary",
    "ExtractedNativeString",
    "JNITripletCandidate",
    "JNIUpcallSite",
    "OLLVMStateTransition",
    "ResolvedIndirectBranch",
    "ResolvedJNIBinding",
    "analyze_apk_bundle",
    "build_c_jni_signature",
    "correlate_jni_bindings",
    "detect_ida9_environment",
    "extract_jni_onload_strings",
    "generate_ida_jni_c_header",
    "jni_type_to_c_type",
    "jni_type_to_java_type",
    "lookup_jni_vtable_offset",
    "mangle_jni_symbol",
    "parse_dex_Or_apk",
    "parse_dex_or_apk",
    "parse_jni_method_descriptor",
    "patch_ollvm_indirect_branches",
    "reconstruct_decompiled_c",
    "resolve_ollvm_indirect_branches",
    "scan_elf_jni_triplets",
    "sync_ida_jni_types",
    "trace_jni_upcalls",
]

