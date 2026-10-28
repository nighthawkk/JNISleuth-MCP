---
name: jnisleuth-mcp
description: >-
  Reverses stripped Android native libraries (lib*.so) and bridges Java/Kotlin
  DEX native method declarations to ARM64/ARMv7/x86_64 C/C++ implementations.
  Use when analyzing Android APKs or ELF .so binaries with `native` methods,
  recovering dynamically registered `RegisterNatives` (`JNINativeMethod`) tables
  from `.rodata`/`.data.rel.ro` or section-stripped `PT_LOAD` segments,
  deobfuscating ARM64 OLLVM indirect branches (`CSEL` + `BR X8` or jump tables)
  in `JNI_OnLoad`, reconstructing untyped `JNIEnv*` vtable calls (`+0x548` ->
  `GetStringUTFChars`), extracting stack/XOR strings, or syncing JNI types to
  Ghidra and IDA Pro 9.0. Don't use for pure Java-only APKs with no `lib/*.so`
  or `native` methods, or for iOS Mach-O binaries.
---

# JNISleuth-MCP: Android JNI & Stripped Native `.so` Reverse Engineering Skill

When an Android APK declares `native` methods in `classes*.dex`, standard static tools often lose the trail at the Java-to-Native boundary because production and malware `.so` binaries strip exported `Java_<pkg>_<Class>_<method>` symbols, wipe ELF section headers (`e_shnum == 0`), flatten `JNI_OnLoad` with OLLVM (`CSEL` + `BR X8`), and leave `JNIEnv*` vtable calls untyped (`(**(code **)(*param_1 + 0x548))`).

Follow this deterministic workflow instead of manually grepping strings or guessing `.so` offsets.

---

## 1. Decision Tree: Which Tool / Command to Run First

1. **You have an `.apk` or `.dex` + `.so` and need to map Java `native` methods to `.so` function offsets:**
   - **Why:** Running `nm -D` or `readelf -s` misses methods registered via `JNIEnv->RegisterNatives()` and fails completely if the packer stripped the ELF section header table (`e_shnum == 0`).
   - **MCP Tool:** `resolve_apk_jni_map(apk_path="<path.apk>", arch="arm64-v8a")`
   - **CLI Equivalent:**
     ```bash
     jnisleuth scan --apk <path.apk> --arch arm64-v8a
     ```
   - *If static resolution reports unresolved methods (constructed dynamically on the stack at runtime):* Pass `--trace <register_natives.json>` collected by the stealth Dobby agent (`agent-native/`).

2. **You want to understand what a specific `native` method does across Java and C/ARM64:**
   - **Why:** Raw decompiler output on a stripped `.so` shows unreadable vtable pointer arithmetic (`*param_1 + 0x548`, `*param_1 + 0x5c0`) because `param_1` is not typed as `JNIEnv*`.
   - **MCP Tool:** `get_cross_boundary_slice(java_method="com.pkg.Class#method", apk_path="<path.apk>")`
   - **CLI Equivalent:**
     ```bash
     jnisleuth slice --apk <path.apk> --method "com.pkg.Class#method"
     ```
   - Returns the synthesized Java caller alongside both the raw (`Before`) and `JNIEnv*`-typed (`After`) C decompilation, plus all resolved `JNIEnv*` reflection upcalls.

3. **`JNI_OnLoad` (or a native function) stops decompiling at an indirect jump (`BR X8` / `BLR X8`):**
   - **Why:** OLLVM Control-Flow Flattening uses `CMP Wstate, #imm` + `CSEL X8, Xtrue, Xfalse, <cond>` + `BR X8` or `.rodata` jump tables. Static decompilers (Ghidra/Hex-Rays) truncate the control-flow graph at unresolved indirect jumps.
   - **MCP Tool:** `resolve_ollvm_indirect_branches(so_name="<lib.so>", fn_offset="0x5200", patch_output_path="<lib.deobf.so>")`
   - **CLI Equivalent:**
     ```bash
     jnisleuth deobfuscate --so <lib.so> --offset 0x5200 --patch-out <lib.deobf.so>
     ```
   - Statically recovers the state register, compared state constants, and branch targets, and patches `CSEL` + `BR X8` in-place into direct `B.<cond>` + `B` instructions so Ghidra/IDA can decompile the full state machine.

4. **Strings (class names, method signatures, C2 URLs) are missing from `strings <lib.so>`:**
   - **Why:** Malware constructs sensitive strings on the stack using ARM64 `MOVZ`/`MOVK` + `STR`/`STP` sequences or decrypts XOR buffers inside `.init_array` / `JNI_OnLoad`.
   - **MCP Tool:** `extract_jni_onload_strings(so_name="<lib.so>")`
   - **CLI Equivalent:**
     ```bash
     jnisleuth strings --so <lib.so>
     ```

5. **You want to trace what Java APIs a native ARM64 function calls back into (Reflection Upcalls):**
   - **MCP Tool:** `trace_jni_upcalls(so_name="<lib.so>", fn_offset="0x1a40")`
   - **CLI Equivalent:**
     ```bash
     jnisleuth upcalls --so <lib.so> --offset 0x1a40
     ```
   - Tracks `JNIEnv*` (`X0`) across register moves, stack spills (`[SP, #imm]`), and 1-hop `BL` helper functions, resolving all 233 NDK `JNINativeInterface` vtable slots (`FindClass`, `GetStaticMethodID`, `CallStaticObjectMethod`, `GetStringUTFChars`, `SetByteArrayRegion`, etc.) and `ADRP`+`ADD` string arguments.

6. **You want to push recovered JNI signatures, `JNIEnv*` structs, and OLLVM xrefs into Ghidra or IDA Pro 9.0:**
   - **MCP Tools:** `sync_ghidra_jni_types(trace_json="<path_or_json>")` or `sync_ida_jni_types(trace_json="<path_or_json>")`
   - **CLI Equivalent:**
     ```bash
     jnisleuth scan --apk <path.apk> --ghidra-headless --ida-headless
     jnisleuth ida-sync --trace <register_natives.json> --output-header jni_types.h
     ```

---

## 2. Common Gotchas & Anti-Patterns to Avoid

* **Do NOT trust `e_shnum == 0` errors from standard ELF utilities:** Packers routinely zero out `e_shoff` and `e_shnum` in the ELF header because the Android Bionic linker (`ld-android.so`) only uses Program Headers (`PT_LOAD`). Always run `jnisleuth scan`, which automatically falls back to non-executable `PT_LOAD` segments and applies `.rela.dyn` relative relocations.
* **Do NOT assume `fnPtr` in 32-bit `armeabi-v7a` is the exact file offset:** On 32-bit ARM, Thumb functions have bit 0 set (`fnPtr | 1`). `jnisleuth` automatically masks `fnPtr & ~1` before computing file offsets and disassembling.
* **Do NOT attach default Frida to RASP/anti-tamper targets without checking for detections first:** If the target scans `/proc/self/maps` for `frida-agent.so` or checks `libc.so` function prologues, use `agent-native/` (which uses Dobby mid-function instrumentation at `RegisterNatives + 0x10` and hooks `art::DexFileLoader::OpenCommon`).
