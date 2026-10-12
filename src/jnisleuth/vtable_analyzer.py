"""JNIEnv* (JNINativeInterface) and JavaVM* (JNIInvokeInterface) vtable analyzer and ARM64 upcall tracer."""

from __future__ import annotations

from pathlib import Path
import struct

from .elf_scanner import ElfBinary
from .models import (
    JNIUpcallSite,
    ResolvedJNIBinding,
    build_c_jni_signature,
)

# Complete 233-slot (indices 0..232) Android NDK JNINativeInterface (JNIEnv*) table
JNI_NATIVE_INTERFACE_ENTRIES: list[tuple[str, str]] = [
    ("reserved0", "void *reserved0"),
    ("reserved1", "void *reserved1"),
    ("reserved2", "void *reserved2"),
    ("reserved3", "void *reserved3"),
    ("GetVersion", "jint (*GetVersion)(JNIEnv *env)"),
    ("DefineClass", "jclass (*DefineClass)(JNIEnv *env, const char *name, jobject loader, const jbyte *buf, jsize bufLen)"),
    ("FindClass", "jclass (*FindClass)(JNIEnv *env, const char *name)"),
    ("FromReflectedMethod", "jmethodID (*FromReflectedMethod)(JNIEnv *env, jobject method)"),
    ("FromReflectedField", "jfieldID (*FromReflectedField)(JNIEnv *env, jobject field)"),
    ("ToReflectedMethod", "jobject (*ToReflectedMethod)(JNIEnv *env, jclass cls, jmethodID methodID, jboolean isStatic)"),
    ("GetSuperclass", "jclass (*GetSuperclass)(JNIEnv *env, jclass clazz)"),
    ("IsAssignableFrom", "jboolean (*IsAssignableFrom)(JNIEnv *env, jclass clazz1, jclass clazz2)"),
    ("ToReflectedField", "jobject (*ToReflectedField)(JNIEnv *env, jclass cls, jfieldID fieldID, jboolean isStatic)"),
    ("Throw", "jint (*Throw)(JNIEnv *env, jthrowable obj)"),
    ("ThrowNew", "jint (*ThrowNew)(JNIEnv *env, jclass clazz, const char *message)"),
    ("ExceptionOccurred", "jthrowable (*ExceptionOccurred)(JNIEnv *env)"),
    ("ExceptionDescribe", "void (*ExceptionDescribe)(JNIEnv *env)"),
    ("ExceptionClear", "void (*ExceptionClear)(JNIEnv *env)"),
    ("FatalError", "void (*FatalError)(JNIEnv *env, const char *msg)"),
    ("PushLocalFrame", "jint (*PushLocalFrame)(JNIEnv *env, jint capacity)"),
    ("PopLocalFrame", "jobject (*PopLocalFrame)(JNIEnv *env, jobject result)"),
    ("NewGlobalRef", "jobject (*NewGlobalRef)(JNIEnv *env, jobject obj)"),
    ("DeleteGlobalRef", "void (*DeleteGlobalRef)(JNIEnv *env, jobject globalRef)"),
    ("DeleteLocalRef", "void (*DeleteLocalRef)(JNIEnv *env, jobject localRef)"),
    ("IsSameObject", "jboolean (*IsSameObject)(JNIEnv *env, jobject ref1, jobject ref2)"),
    ("NewLocalRef", "jobject (*NewLocalRef)(JNIEnv *env, jobject ref)"),
    ("EnsureLocalCapacity", "jint (*EnsureLocalCapacity)(JNIEnv *env, jint capacity)"),
    ("AllocObject", "jobject (*AllocObject)(JNIEnv *env, jclass clazz)"),
    ("NewObject", "jobject (*NewObject)(JNIEnv *env, jclass clazz, jmethodID methodID, ...)"),
    ("NewObjectV", "jobject (*NewObjectV)(JNIEnv *env, jclass clazz, jmethodID methodID, va_list args)"),
    ("NewObjectA", "jobject (*NewObjectA)(JNIEnv *env, jclass clazz, jmethodID methodID, const jvalue *args)"),
    ("GetObjectClass", "jclass (*GetObjectClass)(JNIEnv *env, jobject obj)"),
    ("IsInstanceOf", "jboolean (*IsInstanceOf)(JNIEnv *env, jobject obj, jclass clazz)"),
    ("GetMethodID", "jmethodID (*GetMethodID)(JNIEnv *env, jclass clazz, const char *name, const char *sig)"),
]

# Populate Call<Type>Method, Call<Type>MethodV, Call<Type>MethodA (indices 34..63)
for _type_label, _c_ret in [
    ("Object", "jobject"),
    ("Boolean", "jboolean"),
    ("Byte", "jbyte"),
    ("Char", "jchar"),
    ("Short", "jshort"),
    ("Int", "jint"),
    ("Long", "jlong"),
    ("Float", "jfloat"),
    ("Double", "jdouble"),
    ("Void", "void"),
]:
    JNI_NATIVE_INTERFACE_ENTRIES.extend(
        [
            (f"Call{_type_label}Method", f"{_c_ret} (*Call{_type_label}Method)(JNIEnv *env, jobject obj, jmethodID methodID, ...)"),
            (f"Call{_type_label}MethodV", f"{_c_ret} (*Call{_type_label}MethodV)(JNIEnv *env, jobject obj, jmethodID methodID, va_list args)"),
            (f"Call{_type_label}MethodA", f"{_c_ret} (*Call{_type_label}MethodA)(JNIEnv *env, jobject obj, jmethodID methodID, const jvalue *args)"),
        ]
    )

# Populate CallNonvirtual<Type>Method{,V,A} (indices 64..93)
for _type_label, _c_ret in [
    ("Object", "jobject"),
    ("Boolean", "jboolean"),
    ("Byte", "jbyte"),
    ("Char", "jchar"),
    ("Short", "jshort"),
    ("Int", "jint"),
    ("Long", "jlong"),
    ("Float", "jfloat"),
    ("Double", "jdouble"),
    ("Void", "void"),
]:
    JNI_NATIVE_INTERFACE_ENTRIES.extend(
        [
            (f"CallNonvirtual{_type_label}Method", f"{_c_ret} (*CallNonvirtual{_type_label}Method)(JNIEnv *env, jobject obj, jclass clazz, jmethodID methodID, ...)"),
            (f"CallNonvirtual{_type_label}MethodV", f"{_c_ret} (*CallNonvirtual{_type_label}MethodV)(JNIEnv *env, jobject obj, jclass clazz, jmethodID methodID, va_list args)"),
            (f"CallNonvirtual{_type_label}MethodA", f"{_c_ret} (*CallNonvirtual{_type_label}MethodA)(JNIEnv *env, jobject obj, jclass clazz, jmethodID methodID, const jvalue *args)"),
        ]
    )

# Index 94: GetFieldID
JNI_NATIVE_INTERFACE_ENTRIES.append(
    ("GetFieldID", "jfieldID (*GetFieldID)(JNIEnv *env, jclass clazz, const char *name, const char *sig)")
)

# Indices 95..103: Get<Type>Field
for _type_label, _c_ret in [
    ("Object", "jobject"),
    ("Boolean", "jboolean"),
    ("Byte", "jbyte"),
    ("Char", "jchar"),
    ("Short", "jshort"),
    ("Int", "jint"),
    ("Long", "jlong"),
    ("Float", "jfloat"),
    ("Double", "jdouble"),
]:
    JNI_NATIVE_INTERFACE_ENTRIES.append(
        (f"Get{_type_label}Field", f"{_c_ret} (*Get{_type_label}Field)(JNIEnv *env, jobject obj, jfieldID fieldID)")
    )

# Indices 104..112: Set<Type>Field
for _type_label, _c_val in [
    ("Object", "jobject"),
    ("Boolean", "jboolean"),
    ("Byte", "jbyte"),
    ("Char", "jchar"),
    ("Short", "jshort"),
    ("Int", "jint"),
    ("Long", "jlong"),
    ("Float", "jfloat"),
    ("Double", "jdouble"),
]:
    JNI_NATIVE_INTERFACE_ENTRIES.append(
        (f"Set{_type_label}Field", f"void (*Set{_type_label}Field)(JNIEnv *env, jobject obj, jfieldID fieldID, {_c_val} value)")
    )

# Index 113: GetStaticMethodID
JNI_NATIVE_INTERFACE_ENTRIES.append(
    ("GetStaticMethodID", "jmethodID (*GetStaticMethodID)(JNIEnv *env, jclass clazz, const char *name, const char *sig)")
)

# Indices 114..143: CallStatic<Type>Method{,V,A}
for _type_label, _c_ret in [
    ("Object", "jobject"),
    ("Boolean", "jboolean"),
    ("Byte", "jbyte"),
    ("Char", "jchar"),
    ("Short", "jshort"),
    ("Int", "jint"),
    ("Long", "jlong"),
    ("Float", "jfloat"),
    ("Double", "jdouble"),
    ("Void", "void"),
]:
    JNI_NATIVE_INTERFACE_ENTRIES.extend(
        [
            (f"CallStatic{_type_label}Method", f"{_c_ret} (*CallStatic{_type_label}Method)(JNIEnv *env, jclass clazz, jmethodID methodID, ...)"),
            (f"CallStatic{_type_label}MethodV", f"{_c_ret} (*CallStatic{_type_label}MethodV)(JNIEnv *env, jclass clazz, jmethodID methodID, va_list args)"),
            (f"CallStatic{_type_label}MethodA", f"{_c_ret} (*CallStatic{_type_label}MethodA)(JNIEnv *env, jclass clazz, jmethodID methodID, const jvalue *args)"),
        ]
    )

# Index 144: GetStaticFieldID
JNI_NATIVE_INTERFACE_ENTRIES.append(
    ("GetStaticFieldID", "jfieldID (*GetStaticFieldID)(JNIEnv *env, jclass clazz, const char *name, const char *sig)")
)

# Indices 145..153: GetStatic<Type>Field
for _type_label, _c_ret in [
    ("Object", "jobject"),
    ("Boolean", "jboolean"),
    ("Byte", "jbyte"),
    ("Char", "jchar"),
    ("Short", "jshort"),
    ("Int", "jint"),
    ("Long", "jlong"),
    ("Float", "jfloat"),
    ("Double", "jdouble"),
]:
    JNI_NATIVE_INTERFACE_ENTRIES.append(
        (f"GetStatic{_type_label}Field", f"{_c_ret} (*GetStatic{_type_label}Field)(JNIEnv *env, jclass clazz, jfieldID fieldID)")
    )

# Indices 154..162: SetStatic<Type>Field
for _type_label, _c_val in [
    ("Object", "jobject"),
    ("Boolean", "jboolean"),
    ("Byte", "jbyte"),
    ("Char", "jchar"),
    ("Short", "jshort"),
    ("Int", "jint"),
    ("Long", "jlong"),
    ("Float", "jfloat"),
    ("Double", "jdouble"),
]:
    JNI_NATIVE_INTERFACE_ENTRIES.append(
        (f"SetStatic{_type_label}Field", f"void (*SetStatic{_type_label}Field)(JNIEnv *env, jclass clazz, jfieldID fieldID, {_c_val} value)")
    )

# Indices 163..174: Strings and Object Arrays
JNI_NATIVE_INTERFACE_ENTRIES.extend(
    [
        ("NewString", "jstring (*NewString)(JNIEnv *env, const jchar *unicodeChars, jsize len)"),
        ("GetStringLength", "jsize (*GetStringLength)(JNIEnv *env, jstring string)"),
        ("GetStringChars", "const jchar *(*GetStringChars)(JNIEnv *env, jstring string, jboolean *isCopy)"),
        ("ReleaseStringChars", "void (*ReleaseStringChars)(JNIEnv *env, jstring string, const jchar *chars)"),
        ("NewStringUTF", "jstring (*NewStringUTF)(JNIEnv *env, const char *bytes)"),
        ("GetStringUTFLength", "jsize (*GetStringUTFLength)(JNIEnv *env, jstring string)"),
        ("GetStringUTFChars", "const char *(*GetStringUTFChars)(JNIEnv *env, jstring string, jboolean *isCopy)"),
        ("ReleaseStringUTFChars", "void (*ReleaseStringUTFChars)(JNIEnv *env, jstring string, const char *utf)"),
        ("GetArrayLength", "jsize (*GetArrayLength)(JNIEnv *env, jarray array)"),
        ("NewObjectArray", "jobjectArray (*NewObjectArray)(JNIEnv *env, jsize length, jclass elementClass, jobject initialElement)"),
        ("GetObjectArrayElement", "jobject (*GetObjectArrayElement)(JNIEnv *env, jobjectArray array, jsize index)"),
        ("SetObjectArrayElement", "void (*SetObjectArrayElement)(JNIEnv *env, jobjectArray array, jsize index, jobject value)"),
    ]
)

# Indices 175..182: New<Primitive>Array
for _type_label, _arr_c in [
    ("Boolean", "jbooleanArray"),
    ("Byte", "jbyteArray"),
    ("Char", "jcharArray"),
    ("Short", "jshortArray"),
    ("Int", "jintArray"),
    ("Long", "jlongArray"),
    ("Float", "jfloatArray"),
    ("Double", "jdoubleArray"),
]:
    JNI_NATIVE_INTERFACE_ENTRIES.append(
        (f"New{_type_label}Array", f"{_arr_c} (*New{_type_label}Array)(JNIEnv *env, jsize length)")
    )

# Indices 183..190: Get<Primitive>ArrayElements
for _type_label, _arr_c, _elem_c in [
    ("Boolean", "jbooleanArray", "jboolean"),
    ("Byte", "jbyteArray", "jbyte"),
    ("Char", "jcharArray", "jchar"),
    ("Short", "jshortArray", "jshort"),
    ("Int", "jintArray", "jint"),
    ("Long", "jlongArray", "jlong"),
    ("Float", "jfloatArray", "jfloat"),
    ("Double", "jdoubleArray", "jdouble"),
]:
    JNI_NATIVE_INTERFACE_ENTRIES.append(
        (f"Get{_type_label}ArrayElements", f"{_elem_c} *(*Get{_type_label}ArrayElements)(JNIEnv *env, {_arr_c} array, jboolean *isCopy)")
    )

# Indices 191..198: Release<Primitive>ArrayElements
for _type_label, _arr_c, _elem_c in [
    ("Boolean", "jbooleanArray", "jboolean"),
    ("Byte", "jbyteArray", "jbyte"),
    ("Char", "jcharArray", "jchar"),
    ("Short", "jshortArray", "jshort"),
    ("Int", "jintArray", "jint"),
    ("Long", "jlongArray", "jlong"),
    ("Float", "jfloatArray", "jfloat"),
    ("Double", "jdoubleArray", "jdouble"),
]:
    JNI_NATIVE_INTERFACE_ENTRIES.append(
        (f"Release{_type_label}ArrayElements", f"void (*Release{_type_label}ArrayElements)(JNIEnv *env, {_arr_c} array, {_elem_c} *elems, jint mode)")
    )

# Indices 199..206: Get<Primitive>ArrayRegion
for _type_label, _arr_c, _elem_c in [
    ("Boolean", "jbooleanArray", "jboolean"),
    ("Byte", "jbyteArray", "jbyte"),
    ("Char", "jcharArray", "jchar"),
    ("Short", "jshortArray", "jshort"),
    ("Int", "jintArray", "jint"),
    ("Long", "jlongArray", "jlong"),
    ("Float", "jfloatArray", "jfloat"),
    ("Double", "jdoubleArray", "jdouble"),
]:
    JNI_NATIVE_INTERFACE_ENTRIES.append(
        (f"Get{_type_label}ArrayRegion", f"void (*Get{_type_label}ArrayRegion)(JNIEnv *env, {_arr_c} array, jsize start, jsize len, {_elem_c} *buf)")
    )

# Indices 207..214: Set<Primitive>ArrayRegion
for _type_label, _arr_c, _elem_c in [
    ("Boolean", "jbooleanArray", "jboolean"),
    ("Byte", "jbyteArray", "jbyte"),
    ("Char", "jcharArray", "jchar"),
    ("Short", "jshortArray", "jshort"),
    ("Int", "jintArray", "jint"),
    ("Long", "jlongArray", "jlong"),
    ("Float", "jfloatArray", "jfloat"),
    ("Double", "jdoubleArray", "jdouble"),
]:
    JNI_NATIVE_INTERFACE_ENTRIES.append(
        (f"Set{_type_label}ArrayRegion", f"void (*Set{_type_label}ArrayRegion)(JNIEnv *env, {_arr_c} array, jsize start, jsize len, const {_elem_c} *buf)")
    )

# Indices 215..232: RegisterNatives through GetObjectRefType
JNI_NATIVE_INTERFACE_ENTRIES.extend(
    [
        ("RegisterNatives", "jint (*RegisterNatives)(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods)"),
        ("UnregisterNatives", "jint (*UnregisterNatives)(JNIEnv *env, jclass clazz)"),
        ("MonitorEnter", "jint (*MonitorEnter)(JNIEnv *env, jobject obj)"),
        ("MonitorExit", "jint (*MonitorExit)(JNIEnv *env, jobject obj)"),
        ("GetJavaVM", "jint (*GetJavaVM)(JNIEnv *env, JavaVM **vm)"),
        ("GetStringRegion", "void (*GetStringRegion)(JNIEnv *env, jstring str, jsize start, jsize len, jchar *buf)"),
        ("GetStringUTFRegion", "void (*GetStringUTFRegion)(JNIEnv *env, jstring str, jsize start, jsize len, char *buf)"),
        ("GetPrimitiveArrayCritical", "void *(*GetPrimitiveArrayCritical)(JNIEnv *env, jarray array, jboolean *isCopy)"),
        ("ReleasePrimitiveArrayCritical", "void (*ReleasePrimitiveArrayCritical)(JNIEnv *env, jarray array, void *carray, jint mode)"),
        ("GetStringCritical", "const jchar *(*GetStringCritical)(JNIEnv *env, jstring string, jboolean *isCopy)"),
        ("ReleaseStringCritical", "void (*ReleaseStringCritical)(JNIEnv *env, jstring string, const jchar *carray)"),
        ("NewWeakGlobalRef", "jweak (*NewWeakGlobalRef)(JNIEnv *env, jobject obj)"),
        ("DeleteWeakGlobalRef", "void (*DeleteWeakGlobalRef)(JNIEnv *env, jweak obj)"),
        ("ExceptionCheck", "jboolean (*ExceptionCheck)(JNIEnv *env)"),
        ("NewDirectByteBuffer", "jobject (*NewDirectByteBuffer)(JNIEnv *env, void *address, jlong capacity)"),
        ("GetDirectBufferAddress", "void *(*GetDirectBufferAddress)(JNIEnv *env, jobject buf)"),
        ("GetDirectBufferCapacity", "jlong (*GetDirectBufferCapacity)(JNIEnv *env, jobject buf)"),
        ("GetObjectRefType", "jobjectRefType (*GetObjectRefType)(JNIEnv *env, jobject obj)"),
    ]
)

assert len(JNI_NATIVE_INTERFACE_ENTRIES) == 233, (
    f"Expected 233 JNINativeInterface slots, got {len(JNI_NATIVE_INTERFACE_ENTRIES)}"
)

JNI_VTABLE_64: dict[int, tuple[int, str, str]] = {
    idx * 8: (idx, name, proto)
    for idx, (name, proto) in enumerate(JNI_NATIVE_INTERFACE_ENTRIES)
}

JNI_VTABLE_32: dict[int, tuple[int, str, str]] = {
    idx * 4: (idx, name, proto)
    for idx, (name, proto) in enumerate(JNI_NATIVE_INTERFACE_ENTRIES)
}

JAVAVM_INVOKE_INTERFACE_ENTRIES: list[tuple[str, str]] = [
    ("reserved0", "void *reserved0"),
    ("reserved1", "void *reserved1"),
    ("reserved2", "void *reserved2"),
    ("DestroyJavaVM", "jint (*DestroyJavaVM)(JavaVM *vm)"),
    ("AttachCurrentThread", "jint (*AttachCurrentThread)(JavaVM *vm, JNIEnv **p_env, void *thr_args)"),
    ("DetachCurrentThread", "jint (*DetachCurrentThread)(JavaVM *vm)"),
    ("GetEnv", "jint (*GetEnv)(JavaVM *vm, void **env, jint version)"),
    ("AttachCurrentThreadAsDaemon", "jint (*AttachCurrentThreadAsDaemon)(JavaVM *vm, JNIEnv **p_env, void *thr_args)"),
]


def lookup_jni_vtable_offset(byte_offset: int, is_64: bool = True) -> tuple[int, str, str] | None:
    """Looks up a `JNIEnv*` vtable byte offset (e.g. `0x548` -> `GetStringUTFChars`)."""
    table = JNI_VTABLE_64 if is_64 else JNI_VTABLE_32
    return table.get(byte_offset)


def trace_jni_upcalls(
    so_source: str | Path | ElfBinary,
    fn_offset: int | str,
    max_instructions: int = 128,
    max_callee_depth: int = 1,
    _visited: set[int] | None = None,
) -> list[JNIUpcallSite]:
    """Disassembles an ARM64 function at `fn_offset` (and its callees) and traces all `JNIEnv*` vtable upcalls."""
    elf = so_source if isinstance(so_source, ElfBinary) else ElfBinary.from_file(so_source)
    offset_int = int(fn_offset, 16) if isinstance(fn_offset, str) else int(fn_offset)
    file_off = elf.va_to_offset(offset_int) if offset_int >= 0x10000 else offset_int
    if file_off is None or file_off < 0 or file_off >= len(elf.data):
        file_off = offset_int
    fn_va = elf.offset_to_va(file_off)

    visited = _visited if _visited is not None else set()
    if file_off in visited or file_off < 0 or file_off >= len(elf.data):
        return []
    visited.add(file_off)

    code_end = min(len(elf.data), file_off + max_instructions * 4)
    code = elf.data[file_off:code_end]

    # Register and stack state tracking for ARM64
    env_regs: set[int] = {0}  # X0 holds JNIEnv* on entry
    sp_env_slots: set[int] = set()
    vtable_regs: set[int] = set()
    reg_vtable_slot: dict[int, int] = {}
    adrp_pages: dict[int, int] = {}
    reg_strings: dict[int, str] = {}

    upcalls: list[JNIUpcallSite] = []

    for step in range(0, len(code) - 3, 4):
        insn = struct.unpack_from("<I", code, step)[0]
        cur_off = file_off + step
        cur_va = fn_va + step

        # Stop at RET (0xD65F03C0) after at least one instruction
        if insn == 0xD65F03C0 and step > 0:
            break
        # Stop if we hit zero-padded space between functions
        if insn == 0x00000000 and step > 0:
            break

        # 1. MOV Xd, Xm (ORR Xd, XZR, Xm: 0xAA0003E0)
        if (insn & 0xFFE0FFE0) == 0xAA0003E0:
            rd = insn & 0x1F
            rm = (insn >> 16) & 0x1F
            if rm in env_regs:
                env_regs.add(rd)
            else:
                env_regs.discard(rd)
            if rm in vtable_regs:
                vtable_regs.add(rd)
            else:
                vtable_regs.discard(rd)
            if rm in reg_strings:
                reg_strings[rd] = reg_strings[rm]

        # 2. ADRP Xd, #page
        elif (insn & 0x9F000000) == 0x90000000:
            rd = insn & 0x1F
            immlo = (insn >> 29) & 0x3
            immhi = (insn >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= 1 << 21
            adrp_pages[rd] = (cur_va & ~0xFFF) + (imm << 12)

        # 3. ADD Xd, Xn, #imm12
        elif (insn & 0xFF800000) == 0x91000000:
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = (insn >> 10) & 0xFFF
            if (insn >> 22) & 0x1:
                imm12 <<= 12
            if imm12 == 0 and rn not in adrp_pages:
                if rn in env_regs:
                    env_regs.add(rd)
                if rn in vtable_regs:
                    vtable_regs.add(rd)
            elif rn in adrp_pages:
                str_va = adrp_pages[rn] + imm12
                s = elf.read_cstring_at_va(str_va)
                if s:
                    reg_strings[rd] = s

        # 4a. STR Xt, [SP, #imm12*8] (stack spill of JNIEnv*: 0xF90003E0)
        elif (insn & 0xFFC003E0) == 0xF90003E0:
            rt = insn & 0x1F
            byte_off = ((insn >> 10) & 0xFFF) * 8
            if rt in env_regs:
                sp_env_slots.add(byte_off)
            else:
                sp_env_slots.discard(byte_off)

        # 4b. LDR Xt, [Xn, #imm12*8] (64-bit unsigned offset: 0xF9400000)
        elif (insn & 0xFFC00000) == 0xF9400000:
            rt = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            byte_off = ((insn >> 10) & 0xFFF) * 8
            if rn == 31 and byte_off in sp_env_slots:
                env_regs.add(rt)
            elif rn in env_regs and byte_off == 0:
                vtable_regs.add(rt)
                reg_vtable_slot.pop(rt, None)
            elif rn in vtable_regs:
                reg_vtable_slot[rt] = byte_off

        # 5. BL <callee> (direct branch with link: 0x94000000..0x97FFFFFF)
        elif (insn & 0xFC000000) == 0x94000000 and max_callee_depth > 0:
            imm26 = insn & 0x03FFFFFF
            if imm26 & (1 << 25):
                imm26 -= 1 << 26
            callee_va = cur_va + (imm26 * 4)
            if elf.is_executable_va(callee_va):
                callee_off = elf.va_to_offset(callee_va)
                if callee_off is not None and callee_off not in visited:
                    upcalls.extend(
                        trace_jni_upcalls(
                            elf,
                            callee_off,
                            max_instructions=max_instructions,
                            max_callee_depth=max_callee_depth - 1,
                            _visited=visited,
                        )
                    )

        # 6. BLR Xn (0xD63F0000)
        elif (insn & 0xFFFFFC1F) == 0xD63F0000:
            rn = (insn >> 5) & 0x1F
            if rn in reg_vtable_slot:
                vt_off = reg_vtable_slot[rn]
                info = lookup_jni_vtable_offset(vt_off, is_64=True)
                if info is not None:
                    vt_idx, api_name, c_proto = info
                else:
                    vt_idx, api_name, c_proto = (
                        vt_off // 8,
                        f"JNIEnv_slot_0x{vt_off:x}",
                        f"void *(*slot_0x{vt_off:x})(JNIEnv *env, ...)",
                    )

                resolved_args: dict[str, str] = {}
                if api_name in ("FindClass", "NewStringUTF") and 1 in reg_strings:
                    resolved_args["arg1"] = reg_strings[1]
                elif api_name in (
                    "GetMethodID",
                    "GetStaticMethodID",
                    "GetFieldID",
                    "GetStaticFieldID",
                ):
                    if 2 in reg_strings:
                        resolved_args["member_name"] = reg_strings[2]
                    if 3 in reg_strings:
                        resolved_args["signature"] = reg_strings[3]

                disasm_str = (
                    f"ldr x{rn}, [x_vtable, #0x{vt_off:x}] ; blr x{rn}  // (*env)->{api_name}"
                )
                upcalls.append(
                    JNIUpcallSite(
                        instruction_va=cur_va,
                        instruction_offset=cur_off,
                        vtable_offset=vt_off,
                        vtable_index=vt_idx,
                        jni_api_name=api_name,
                        c_prototype=c_proto,
                        disasm=disasm_str,
                        resolved_args=resolved_args,
                    )
                )

    return upcalls


def reconstruct_decompiled_c(
    binding: ResolvedJNIBinding,
    elf: ElfBinary | None = None,
) -> tuple[str, str, list[JNIUpcallSite]]:
    """Generates both the raw untyped Ghidra C decompilation ('Before') and JNISleuth re-typed C ('After')."""
    upcalls = trace_jni_upcalls(elf, binding.fn_offset) if elf is not None else []

    param_name_presets: dict[tuple[str, int], str] = {
        ("decryptPayload", 0): "encryptedData",
        ("decryptPayload", 1): "rc4KeyStr",
        ("initEngine", 0): "context",
        ("initEngine", 1): "configFlags",
        ("signC2Beacon", 0): "beaconPayload",
        ("signC2Beacon", 1): "deviceFingerprint",
        ("connectRaw", 0): "hostAddress",
        ("connectRaw", 1): "port",
    }

    c_fn_name, _, c_params = build_c_jni_signature(
        binding.class_name,
        binding.method_name,
        binding.jni_signature,
        is_static=binding.is_static,
    )
    # Apply descriptive parameter names if known
    typed_params: list[tuple[str, str]] = list(c_params[:2])
    for i, (ptype, default_pname) in enumerate(c_params[2:]):
        pname = param_name_presets.get((binding.method_name, i), default_pname)
        typed_params.append((ptype, pname))

    ret_c = binding.c_signature.split(" ")[0] if binding.c_signature else "jobject"
    fun_va = binding.fn_va if binding.fn_va >= 0x10000 else (0x00010000 + binding.fn_offset)

    # Check if this is the canonical decryptPayload pattern (GetStringUTFChars + GetByteArrayElements + ReleaseStringUTFChars)
    api_sequence = [u.jni_api_name for u in upcalls]
    if binding.method_name == "decryptPayload" or api_sequence == [
        "GetStringUTFChars",
        "GetByteArrayElements",
        "ReleaseStringUTFChars",
    ]:
        arg_arr = typed_params[2][1] if len(typed_params) > 2 else "encryptedData"
        arg_key = typed_params[3][1] if len(typed_params) > 3 else "rc4KeyStr"
        before_c = (
            f"long FUN_{fun_va:08x}(long *param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4) {{\n"
            f"  char *pcVar1;\n"
            f"  long lVar2;\n"
            f"  pcVar1 = (char *)(**(code **)(*param_1 + 0x548))(param_1, param_4, 0);\n"
            f"  lVar2 = (**(code **)(*param_1 + 0x5c0))(param_1, param_3, 0);\n"
            f"  sub_00014a00(lVar2, pcVar1);\n"
            f"  (**(code **)(*param_1 + 0x550))(param_1, param_4, pcVar1);\n"
            f"  return param_3;\n"
            f"}}"
        )
        after_c = (
            f"{ret_c} {c_fn_name}(\n"
            f"    JNIEnv *env, {typed_params[1][0]} {typed_params[1][1]}, jbyteArray {arg_arr}, jstring {arg_key}) \n"
            f"{{\n"
            f"  const char *key_utf = (*env)->GetStringUTFChars(env, {arg_key}, NULL);\n"
            f"  jbyte *payload_bytes = (*env)->GetByteArrayElements(env, {arg_arr}, NULL);\n"
            f"  rc4_crypt_buffer(payload_bytes, key_utf);\n"
            f"  (*env)->ReleaseStringUTFChars(env, {arg_key}, key_utf);\n"
            f"  return {arg_arr};\n"
            f"}}"
        )
        return before_c, after_c, upcalls

    # Generic reconstruction for any native function using its traced upcalls
    raw_params = ["long *param_1", "undefined8 param_2"] + [
        f"undefined8 param_{i + 3}" for i in range(len(typed_params) - 2)
    ]
    before_lines = [f"long FUN_{fun_va:08x}({', '.join(raw_params)}) {{"]
    after_param_str = ", ".join(
        f"{pt}{pn}" if pt.endswith("*") else f"{pt} {pn}" for pt, pn in typed_params
    )
    after_lines = [f"{ret_c} {c_fn_name}({after_param_str}) {{"]

    for idx, u in enumerate(upcalls):
        before_lines.append(
            f"  (**(code **)(*param_1 + 0x{u.vtable_offset:x}))(param_1, ...);"
        )
        arg_comment = (
            f" /* {', '.join(f'{k}={v!r}' for k, v in u.resolved_args.items())} */"
            if u.resolved_args
            else ""
        )
        after_lines.append(
            f"  (*env)->{u.jni_api_name}(env, ...);{arg_comment}"
        )

    if ret_c != "void":
        before_lines.append("  return 0;")
        after_lines.append(f"  return ({ret_c})0;")
    before_lines.append("}")
    after_lines.append("}")

    return "\n".join(before_lines), "\n".join(after_lines), upcalls
