"""Core data models and JNI type descriptor utilities for JNISleuth-MCP."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


JNI_PRIMITIVE_TO_C: dict[str, str] = {
    "V": "void",
    "Z": "jboolean",
    "B": "jbyte",
    "C": "jchar",
    "S": "jshort",
    "I": "jint",
    "J": "jlong",
    "F": "jfloat",
    "D": "jdouble",
}

JNI_PRIMITIVE_TO_JAVA: dict[str, str] = {
    "V": "void",
    "Z": "boolean",
    "B": "byte",
    "C": "char",
    "S": "short",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
}

JNI_ARRAY_TO_C: dict[str, str] = {
    "[Z": "jbooleanArray",
    "[B": "jbyteArray",
    "[C": "jcharArray",
    "[S": "jshortArray",
    "[I": "jintArray",
    "[J": "jlongArray",
    "[F": "jfloatArray",
    "[D": "jdoubleArray",
}


def parse_single_type_descriptor(desc: str, idx: int = 0) -> tuple[str, int]:
    """Parses a single JNI field/parameter type descriptor starting at `idx`."""
    if idx >= len(desc):
        raise ValueError(f"Unexpected end of JNI descriptor: {desc!r}")
    ch = desc[idx]
    if ch in JNI_PRIMITIVE_TO_C:
        return ch, idx + 1
    if ch == "[":
        elem_type, next_idx = parse_single_type_descriptor(desc, idx + 1)
        return "[" + elem_type, next_idx
    if ch == "L":
        semi = desc.find(";", idx + 1)
        if semi == -1:
            raise ValueError(f"Unterminated class descriptor in {desc!r} at {idx}")
        body = desc[idx + 1 : semi]
        if not body or any(c in body for c in (" ", "\t", "\n", "\r", "(", ")")):
            raise ValueError(f"Invalid class descriptor body in {desc!r}")
        return desc[idx : semi + 1], semi + 1
    raise ValueError(f"Invalid JNI type character {ch!r} at index {idx} in {desc!r}")


def parse_jni_method_descriptor(descriptor: str) -> tuple[list[str], str]:
    """Parses a JNI method signature like `([BLjava/lang/String;)Ljava/lang/String;`.

    Returns:
        (param_types, return_type)
    """
    if not descriptor or not descriptor.startswith("("):
        raise ValueError(f"JNI method descriptor must start with '(': {descriptor!r}")
    close_paren = descriptor.find(")")
    if close_paren == -1:
        raise ValueError(f"JNI method descriptor missing ')': {descriptor!r}")

    params_str = descriptor[1:close_paren]
    ret_str = descriptor[close_paren + 1 :]
    if not ret_str:
        raise ValueError(f"JNI method descriptor missing return type: {descriptor!r}")

    params: list[str] = []
    idx = 0
    while idx < len(params_str):
        t, idx = parse_single_type_descriptor(params_str, idx)
        if t == "V":
            raise ValueError(f"Void 'V' is not allowed as a parameter type in {descriptor!r}")
        params.append(t)

    ret_type, ret_end = parse_single_type_descriptor(ret_str, 0)
    if ret_end != len(ret_str):
        raise ValueError(f"Trailing characters after return type in {descriptor!r}")

    return params, ret_type


def is_valid_jni_method_descriptor(descriptor: str) -> bool:
    """Returns True if `descriptor` is a syntactically valid JNI method signature."""
    try:
        parse_jni_method_descriptor(descriptor)
        return True
    except ValueError:
        return False


def jni_type_to_c_type(jni_type: str) -> str:
    """Converts a single JNI type descriptor to its Android NDK `<jni.h>` C type."""
    if jni_type in JNI_PRIMITIVE_TO_C:
        return JNI_PRIMITIVE_TO_C[jni_type]
    if jni_type in JNI_ARRAY_TO_C:
        return JNI_ARRAY_TO_C[jni_type]
    if jni_type.startswith("["):
        return "jobjectArray"
    if jni_type == "Ljava/lang/String;":
        return "jstring"
    if jni_type == "Ljava/lang/Class;":
        return "jclass"
    if jni_type == "Ljava/lang/Throwable;":
        return "jthrowable"
    if jni_type.startswith("L") and jni_type.endswith(";"):
        return "jobject"
    return "jobject"


def jni_type_to_java_type(jni_type: str) -> str:
    """Converts a single JNI type descriptor to a readable Java type name."""
    if jni_type in JNI_PRIMITIVE_TO_JAVA:
        return JNI_PRIMITIVE_TO_JAVA[jni_type]
    if jni_type.startswith("["):
        return f"{jni_type_to_java_type(jni_type[1:])}[]"
    if jni_type.startswith("L") and jni_type.endswith(";"):
        return jni_type[1:-1].replace("/", ".")
    return jni_type


def class_descriptor_to_java_name(class_desc: str) -> str:
    """Converts `Lcom/dropper/Core;` or `com/dropper/Core` to `com.dropper.Core`."""
    cleaned = class_desc.strip()
    if cleaned.startswith("L") and cleaned.endswith(";"):
        cleaned = cleaned[1:-1]
    return cleaned.replace("/", ".")


def _mangle_jni_piece(text: str) -> str:
    """Applies JNI specification name mangling rules (_ -> _1, ; -> _2, [ -> _3)."""
    out: list[str] = []
    for ch in text:
        if ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        elif ch in ("/", "."):
            out.append("_")
        elif ch.isalnum():
            out.append(ch)
        else:
            out.append(f"_0{ord(ch):04x}")
    return "".join(out)


def mangle_jni_symbol(
    class_name: str, method_name: str, jni_signature: str | None = None
) -> tuple[str, str]:
    """Returns `(short_symbol, long_symbol)` per the standard JNI export specification."""
    norm_class = class_descriptor_to_java_name(class_name)
    short_sym = f"Java_{_mangle_jni_piece(norm_class)}_{_mangle_jni_piece(method_name)}"
    if not jni_signature:
        return short_sym, short_sym
    close_paren = jni_signature.find(")")
    params_part = jni_signature[1:close_paren] if close_paren != -1 else ""
    long_sym = f"{short_sym}__{_mangle_jni_piece(params_part)}" if params_part else short_sym
    return short_sym, long_sym


def build_c_jni_signature(
    class_name: str,
    method_name: str,
    jni_signature: str,
    is_static: bool = False,
    param_names: list[str] | None = None,
) -> tuple[str, str, list[tuple[str, str]]]:
    """Constructs the C function name, full C prototype, and parameter list for Ghidra/C output."""
    params_jni, ret_jni = parse_jni_method_descriptor(jni_signature)
    ret_c = jni_type_to_c_type(ret_jni)
    c_fn_name = (
        f"Java_{class_descriptor_to_java_name(class_name).replace('.', '_')}_{method_name}"
    )

    c_params: list[tuple[str, str]] = [
        ("JNIEnv *", "env"),
        ("jclass" if is_static else "jobject", "clazz" if is_static else "thiz"),
    ]
    for i, p_jni in enumerate(params_jni):
        p_c = jni_type_to_c_type(p_jni)
        if param_names and i < len(param_names):
            p_name = param_names[i]
        else:
            p_name = f"arg{i + 1}"
        c_params.append((p_c, p_name))

    params_rendered = ", ".join(
        f"{ptype}{pname}" if ptype.endswith("*") else f"{ptype} {pname}"
        for ptype, pname in c_params
    )
    prototype = f"{ret_c} {c_fn_name}({params_rendered})"
    return c_fn_name, prototype, c_params


@dataclass
class DexNativeMethod:
    """Represents a `native` method declared inside an Android DEX file."""

    class_descriptor: str
    class_name: str
    method_name: str
    jni_signature: str
    return_type: str
    param_types: list[str]
    access_flags: int
    is_static: bool
    short_jni_symbol: str
    long_jni_symbol: str
    dex_file: str = "classes.dex"
    callers: list[str] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        return f"{self.class_name}#{self.method_name}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["qualified_name"] = self.qualified_name
        return d


@dataclass
class JNITripletCandidate:
    """Represents a recovered JNINativeMethod (name, signature, fnPtr) triplet in an ELF binary."""

    method_name: str
    jni_signature: str
    fn_va: int
    fn_file_offset: int
    table_va: int
    table_file_offset: int
    section_name: str
    name_va: int = 0
    sig_va: int = 0
    target_class: str | None = None
    resolution_source: str = "Static (.rodata)"
    confidence: float = 0.95

    def to_dict(self) -> dict[str, Any]:
        return {
            "method_name": self.method_name,
            "jni_signature": self.jni_signature,
            "fn_va": f"0x{self.fn_va:06x}",
            "fn_file_offset": f"0x{self.fn_file_offset:06x}",
            "table_va": f"0x{self.table_va:06x}",
            "table_file_offset": f"0x{self.table_file_offset:06x}",
            "section_name": self.section_name,
            "target_class": self.target_class,
            "resolution_source": self.resolution_source,
            "confidence": self.confidence,
        }


@dataclass
class ResolvedJNIBinding:
    """Represents a correlated DEX-to-ELF JNI method binding."""

    class_name: str
    method_name: str
    jni_signature: str
    so_name: str
    so_path: str
    arch: str
    fn_offset: int
    fn_va: int
    resolution_mode: str
    table_offset: int | None = None
    is_static: bool = False
    c_function_name: str = ""
    c_signature: str = ""
    confidence: float = 1.0
    callers: list[str] = field(default_factory=list)

    @property
    def qualified_method(self) -> str:
        return f"{self.class_name}#{self.method_name}"

    @property
    def formatted_offset(self) -> str:
        short_so = self.so_name
        if short_so == "libcore-crypto.so":
            short_so = "libcore.so"
        return f"{short_so}+0x{self.fn_offset:06x}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "qualified_method": self.qualified_method,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "jni_signature": self.jni_signature,
            "so_name": self.so_name,
            "so_path": self.so_path,
            "arch": self.arch,
            "fn_offset": f"0x{self.fn_offset:06x}",
            "fn_offset_int": self.fn_offset,
            "fn_va": f"0x{self.fn_va:06x}",
            "formatted_offset": self.formatted_offset,
            "resolution_mode": self.resolution_mode,
            "table_offset": f"0x{self.table_offset:06x}" if self.table_offset is not None else None,
            "is_static": self.is_static,
            "c_function_name": self.c_function_name,
            "c_signature": self.c_signature,
            "confidence": self.confidence,
            "callers": self.callers,
        }


@dataclass
class JNIUpcallSite:
    """Represents a resolved JNIEnv* or JavaVM* vtable call inside an ARM64 function."""

    instruction_va: int
    instruction_offset: int
    vtable_offset: int
    vtable_index: int
    jni_api_name: str
    c_prototype: str
    disasm: str
    resolved_args: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "instruction_va": f"0x{self.instruction_va:06x}",
            "instruction_offset": f"0x{self.instruction_offset:06x}",
            "vtable_offset": f"0x{self.vtable_offset:03x}",
            "vtable_index": self.vtable_index,
            "jni_api_name": self.jni_api_name,
            "c_prototype": self.c_prototype,
            "disasm": self.disasm,
            "resolved_args": self.resolved_args,
        }


@dataclass
class ExtractedNativeString:
    """Represents a static, stack-constructed, or XOR-decoded string in JNI_OnLoad / .init_array."""

    value: str
    encoding_type: str
    function_name: str
    offset: int
    xor_key: int | None = None
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "encoding_type": self.encoding_type,
            "function_name": self.function_name,
            "offset": f"0x{self.offset:06x}",
            "xor_key": f"0x{self.xor_key:02x}" if self.xor_key is not None else None,
            "details": self.details,
        }


@dataclass
class CrossBoundarySlice:
    """Represents the full Java -> JNI -> Native C/ARM64 cross-boundary code slice."""

    qualified_method: str
    binding: ResolvedJNIBinding
    java_caller_source: str
    decompiled_c_before: str
    decompiled_c_after: str
    upcalls: list[JNIUpcallSite] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "qualified_method": self.qualified_method,
            "binding": self.binding.to_dict(),
            "java_caller_source": self.java_caller_source,
            "decompiled_c_before": self.decompiled_c_before,
            "decompiled_c_after": self.decompiled_c_after,
            "upcalls": [u.to_dict() for u in self.upcalls],
        }
