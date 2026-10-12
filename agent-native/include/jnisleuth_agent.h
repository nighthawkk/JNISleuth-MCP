#ifndef JNISLEUTH_AGENT_H_
#define JNISLEUTH_AGENT_H_

#include <stddef.h>
#include <stdint.h>
#include "jni_stub.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char so_name[128];
    char so_path[256];
    uintptr_t base_addr;
    uintptr_t fn_offset;
    char symbol_name[128];
} JNISleuthModuleOffset;

/*
 * Normalizes a runtime function pointer `fn_ptr` by resolving its owning ELF
 * module via dladdr() and /proc/self/maps, returning the deterministic file
 * offset `fn_ptr - base_addr`.
 */
int jnisleuth_resolve_module_offset(const void *fn_ptr, JNISleuthModuleOffset *out_info);

/*
 * Sets the output JSON trace file path (defaults to /data/local/tmp/register_natives.json
 * on Android or ./register_natives.json on host).
 */
void jnisleuth_set_trace_output_path(const char *path);

/*
 * Installs stealth mid-function Dobby instrumentation and JNIEnv vtable hooks
 * for RegisterNatives on the given JNIEnv*.
 */
int jnisleuth_install_hooks(JNIEnv *env, int mid_function_offset_bytes);

/*
 * Directly records a batch of JNINativeMethod registrations and invokes the
 * original RegisterNatives implementation.
 */
jint jnisleuth_hooked_RegisterNatives(
    JNIEnv *env,
    jclass clazz,
    const JNINativeMethod *methods,
    jint nMethods
);

/*
 * Records or dumps an in-memory DEX buffer intercepted at Art's
 * DexFileLoader::OpenCommon / DexFile::OpenCommon during dynamic unpacking.
 */
int jnisleuth_hooked_DexFile_OpenCommon(
    const uint8_t *dex_base,
    size_t dex_size,
    const char *location,
    const char *dump_output_path
);

#ifdef __cplusplus
}
#endif

#endif /* JNISLEUTH_AGENT_H_ */

