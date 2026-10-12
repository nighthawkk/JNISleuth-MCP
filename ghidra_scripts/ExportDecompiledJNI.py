# ExportDecompiledJNI.py - Ghidra Headless Decompiler Exporter for JNISleuth-MCP
# @category JNI
# @author JNISleuth-MCP
"""Exports decompiled C code and ARM64 assembly for resolved JNI functions via Ghidra DecompInterface."""

import json
import sys

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    IN_GHIDRA = True
except ImportError:
    IN_GHIDRA = False


def export_decompiled_functions(output_json_path):
    """Exports all Java_* functions in currentProgram to a JSON file."""
    if not IN_GHIDRA:
        return

    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    monitor = ConsoleTaskMonitor()
    fm = currentProgram.getFunctionManager()

    results = []
    for func in fm.getFunctions(True):
        name = func.getName()
        if not name.startswith("Java_") and name != "JNI_OnLoad":
            continue
        res = ifc.decompileFunction(func, 30, monitor)
        c_code = res.getDecompiledFunction().getC() if res.decompileCompleted() else ""
        results.append(
            {
                "name": name,
                "entry": str(func.getEntryPoint()),
                "signature": func.getPrototypeString(True, False),
                "decompiled_c": c_code,
            }
        )

    with open(output_json_path, "w") as f:
        json.dump({"functions": results}, f, indent=2)


if __name__ == "__main__":
    if IN_GHIDRA:
        args = getScriptArgs()
        if len(args) >= 1:
            export_decompiled_functions(args[0])
    elif len(sys.argv) >= 2:
        export_decompiled_functions(sys.argv[1])
