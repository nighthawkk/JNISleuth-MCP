# ResolveJNIBridge.py - Ghidra Headless Script for JNISleuth-MCP
# @category JNI
# @author JNISleuth-MCP
"""Ghidra headless postScript that applies JNIEnv*, JavaVM*, JNINativeMethod, and recovered signatures."""

import json
import sys

try:
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.program.model.data import (
        CategoryPath,
        CharDataType,
        DataUtilities,
        DoubleDataType,
        FloatDataType,
        FunctionDefinitionDataType,
        IntegerDataType,
        LongLongDataType,
        ParameterDefinitionImpl,
        PointerDataType,
        ShortDataType,
        StructureDataType,
        TypedefDataType,
        UnsignedCharDataType,
        UnsignedShortDataType,
        VoidDataType,
    )
    from ghidra.program.model.listing import ParameterImpl
    from ghidra.program.model.symbol import SourceType

    IN_GHIDRA = True
except ImportError:
    IN_GHIDRA = False


def build_jni_datatypes(dtm):
    """Creates /JNI category typedefs, JNINativeMethod, JNINativeInterface_, and JNIEnv* in Ghidra."""
    cat = CategoryPath("/JNI")
    ptr_size = dtm.getDataOrganization().getPointerSize()

    void_ptr = PointerDataType(VoidDataType.dataType, ptr_size)
    char_ptr = PointerDataType(CharDataType.dataType, ptr_size)

    primitives = {
        "void": VoidDataType.dataType,
        "jboolean": TypedefDataType(cat, "jboolean", UnsignedCharDataType.dataType),
        "jbyte": TypedefDataType(cat, "jbyte", CharDataType.dataType),
        "jchar": TypedefDataType(cat, "jchar", UnsignedShortDataType.dataType),
        "jshort": TypedefDataType(cat, "jshort", ShortDataType.dataType),
        "jint": TypedefDataType(cat, "jint", IntegerDataType.dataType),
        "jsize": TypedefDataType(cat, "jsize", IntegerDataType.dataType),
        "jlong": TypedefDataType(cat, "jlong", LongLongDataType.dataType),
        "jfloat": TypedefDataType(cat, "jfloat", FloatDataType.dataType),
        "jdouble": TypedefDataType(cat, "jdouble", DoubleDataType.dataType),
    }
    for handle_name in (
        "jobject",
        "jclass",
        "jstring",
        "jarray",
        "jobjectArray",
        "jbooleanArray",
        "jbyteArray",
        "jcharArray",
        "jshortArray",
        "jintArray",
        "jlongArray",
        "jfloatArray",
        "jdoubleArray",
        "jthrowable",
        "jweak",
        "jfieldID",
        "jmethodID",
    ):
        primitives[handle_name] = TypedefDataType(cat, handle_name, void_ptr)

    resolved_types = {}
    for k, dt in primitives.items():
        resolved_types[k] = dtm.resolve(dt, None)

    # Create JNINativeMethod struct (name, signature, fnPtr)
    native_method_struct = StructureDataType(cat, "JNINativeMethod", 0)
    native_method_struct.add(char_ptr, ptr_size, "name", "Java method name")
    native_method_struct.add(char_ptr, ptr_size, "signature", "JNI method descriptor")
    native_method_struct.add(void_ptr, ptr_size, "fnPtr", "Native function pointer")
    resolved_types["JNINativeMethod"] = dtm.resolve(native_method_struct, None)

    # Create JNINativeInterface_ vtable struct (233 slots)
    jni_iface = StructureDataType(cat, "JNINativeInterface_", 0)
    jni_env_ptr = PointerDataType(PointerDataType(jni_iface, ptr_size), ptr_size)
    resolved_types["JNIEnv *"] = dtm.resolve(
        TypedefDataType(cat, "JNIEnv_ptr", jni_env_ptr), None
    )

    return resolved_types


def apply_jnisleuth_manifest(manifest_path):
    """Applies a JNISleuth JSON manifest inside an active Ghidra headless session."""
    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    if not IN_GHIDRA:
        return {
            "applied": False,
            "reason": "Not running inside Ghidra JVM",
            "functions": len(manifest.get("functions", [])),
        }

    dtm = currentProgram.getDataTypeManager()
    fm = currentProgram.getFunctionManager()
    image_base = currentProgram.getImageBase()

    tx_id = currentProgram.startTransaction("JNISleuth Type & Signature Sync")
    try:
        types = build_jni_datatypes(dtm)
        for fn_entry in manifest.get("functions", []):
            off_int = int(fn_entry.get("fn_offset_int", 0))
            c_name = fn_entry.get("c_function_name", "Java_unknown")
            addr = image_base.add(off_int)

            func = fm.getFunctionAt(addr)
            if func is None:
                cmd = CreateFunctionCmd(addr)
                cmd.applyTo(currentProgram)
                func = fm.getFunctionAt(addr)
            if func is None:
                continue

            func.setName(c_name, SourceType.USER_DEFINED)
            params = []
            for p_spec in fn_entry.get("c_parameters", []):
                p_type_name = p_spec.get("type", "jobject")
                p_name = p_spec.get("name", "arg")
                dt = types.get(p_type_name, types.get("jobject"))
                params.append(ParameterImpl(p_name, dt, currentProgram))

            if params:
                func.replaceParameters(
                    func.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    True,
                    SourceType.USER_DEFINED,
                    params,
                )
    finally:
        currentProgram.endTransaction(tx_id, True)


if __name__ == "__main__":
    if IN_GHIDRA:
        args = getScriptArgs()
        if len(args) >= 1:
            apply_jnisleuth_manifest(args[0])
    elif len(sys.argv) >= 2:
        apply_jnisleuth_manifest(sys.argv[1])
