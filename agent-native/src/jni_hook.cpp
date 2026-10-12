#define _GNU_SOURCE
#include "jnisleuth_agent.h"
#include "dobby_stub.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t g_trace_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_trace_path[512] = "/data/local/tmp/register_natives.json";
static pfn_RegisterNatives_t g_orig_RegisterNatives = NULL;
static int g_record_count = 0;

void jnisleuth_set_trace_output_path(const char *path) {
    pthread_mutex_lock(&g_trace_mutex);
    if (path && path[0] != '\0') {
        if (strcmp(g_trace_path, path) != 0) {
            g_record_count = 0;
        }
        snprintf(g_trace_path, sizeof(g_trace_path), "%s", path);
    }
    pthread_mutex_unlock(&g_trace_mutex);
}

static void normalize_class_descriptor(char *buf) {
    if (!buf || buf[0] == '\0') {
        return;
    }
    size_t len = strlen(buf);
    if (len > 2 && buf[0] == 'L' && buf[len - 1] == ';') {
        memmove(buf, buf + 1, len - 2);
        buf[len - 2] = '\0';
        len -= 2;
    }
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] == '/') {
            buf[i] = '.';
        }
    }
}

/*
 * Resolves the human-readable Java class name from a JNI `jclass` reference via
 * `Class.getName()` reflection, or reads a synthetic string class tag in host tests.
 */
static void resolve_jclass_name(JNIEnv *env, jclass clazz, char *out_buf, size_t out_len) {
    if (!out_buf || out_len == 0) {
        return;
    }
    snprintf(out_buf, out_len, "com.unknown.ObfuscatedClass");
    if (!clazz) {
        return;
    }

    if (env && (*env)) {
        const struct JNINativeInterface_ *vt = *env;
        pfn_GetObjectClass_t fn_get_obj_cls =
            (pfn_GetObjectClass_t)vt->reserved[JNI_SLOT_GET_OBJECT_CLASS];
        pfn_GetMethodID_t fn_get_mid =
            (pfn_GetMethodID_t)vt->reserved[JNI_SLOT_GET_METHOD_ID];
        pfn_CallObjectMethod_t fn_call_obj =
            (pfn_CallObjectMethod_t)vt->reserved[JNI_SLOT_CALL_OBJECT_METHOD];
        pfn_GetStringUTFChars_t fn_get_utf =
            (pfn_GetStringUTFChars_t)vt->reserved[JNI_SLOT_GET_STRING_UTF_CHARS];
        pfn_ReleaseStringUTFChars_t fn_rel_utf =
            (pfn_ReleaseStringUTFChars_t)vt->reserved[JNI_SLOT_RELEASE_STRING_UTF_CHARS];

        if (fn_get_obj_cls && fn_get_mid && fn_call_obj && fn_get_utf && fn_rel_utf) {
            jclass cls_of_class = fn_get_obj_cls(env, clazz);
            if (cls_of_class) {
                jmethodID mid_get_name =
                    fn_get_mid(env, cls_of_class, "getName", "()Ljava/lang/String;");
                if (mid_get_name) {
                    jstring jname = (jstring)fn_call_obj(env, clazz, mid_get_name);
                    if (jname) {
                        const char *utf = fn_get_utf(env, jname, NULL);
                        if (utf) {
                            snprintf(out_buf, out_len, "%s", utf);
                            fn_rel_utf(env, jname, utf);
                            normalize_class_descriptor(out_buf);
                            return;
                        }
                    }
                }
            }
        }
    }

    /* Fallback if clazz points directly to a C string descriptor during unit tests */
    const char *candidate = (const char *)clazz;
    if (candidate[0] >= 'A' && candidate[0] <= 'z') {
        snprintf(out_buf, out_len, "%s", candidate);
        normalize_class_descriptor(out_buf);
    }
}

static void record_registration_batch(
    const char *class_name,
    const JNINativeMethod *methods,
    jint nMethods
) {
    if (!methods || nMethods <= 0) {
        return;
    }

    pthread_mutex_lock(&g_trace_mutex);
    FILE *fp = fopen(g_trace_path, g_record_count == 0 ? "w" : "r+");
    if (!fp) {
        fp = fopen(g_trace_path, "w");
        g_record_count = 0;
    }
    if (!fp) {
        pthread_mutex_unlock(&g_trace_mutex);
        return;
    }

    if (g_record_count == 0) {
        fprintf(fp, "{\n  \"agent\": \"jnisleuth-dobby\",\n  \"registrations\": [\n");
    } else {
        /* Seek back before the closing "\n  ]\n}\n" to append more items */
        if (fseek(fp, -7, SEEK_END) != 0) {
            fseek(fp, 0, SEEK_END);
        }
    }

    for (jint i = 0; i < nMethods; ++i) {
        JNISleuthModuleOffset mod_info;
        jnisleuth_resolve_module_offset(methods[i].fnPtr, &mod_info);

        if (g_record_count > 0) {
            fprintf(fp, ",\n");
        }
        fprintf(
            fp,
            "    {\n"
            "      \"class_name\": \"%s\",\n"
            "      \"method_name\": \"%s\",\n"
            "      \"jni_signature\": \"%s\",\n"
            "      \"so_name\": \"%s\",\n"
            "      \"so_path\": \"%s\",\n"
            "      \"base_address\": \"0x%lx\",\n"
            "      \"fn_ptr\": \"0x%lx\",\n"
            "      \"fn_offset\": \"0x%06lx\",\n"
            "      \"resolution_mode\": \"Dynamic (Dobby)\"\n"
            "    }",
            class_name ? class_name : "com.unknown.Native",
            methods[i].name ? methods[i].name : "",
            methods[i].signature ? methods[i].signature : "",
            mod_info.so_name,
            mod_info.so_path,
            (unsigned long)mod_info.base_addr,
            (unsigned long)(uintptr_t)methods[i].fnPtr,
            (unsigned long)mod_info.fn_offset
        );
        g_record_count++;
    }

    fprintf(fp, "\n  ]\n}\n");
    fflush(fp);
    fclose(fp);
    pthread_mutex_unlock(&g_trace_mutex);
}

jint jnisleuth_hooked_RegisterNatives(
    JNIEnv *env,
    jclass clazz,
    const JNINativeMethod *methods,
    jint nMethods
) {
    char cls_name[256];
    resolve_jclass_name(env, clazz, cls_name, sizeof(cls_name));
    record_registration_batch(cls_name, methods, nMethods);

    if (g_orig_RegisterNatives) {
        return g_orig_RegisterNatives(env, clazz, methods, nMethods);
    }
    return JNI_OK;
}

int jnisleuth_hooked_DexFile_OpenCommon(
    const uint8_t *dex_base,
    size_t dex_size,
    const char *location,
    const char *dump_output_path
) {
    (void)location;
    if (!dex_base || dex_size < 0x70) {
        return -1;
    }
    if (memcmp(dex_base, "dex\n", 4) != 0 && memcmp(dex_base, "cdex", 4) != 0) {
        return -1;
    }
    const char *out_path = (dump_output_path && dump_output_path[0] != '\0')
        ? dump_output_path
        : "/data/local/tmp/unpacked_classes.dex";
    FILE *fp = fopen(out_path, "wb");
    if (!fp) {
        return -1;
    }
    size_t written = fwrite(dex_base, 1, dex_size, fp);
    fclose(fp);
    return written == dex_size ? 0 : -1;
}

/*
 * Mid-function Dobby instrument callback placed +8/+12 bytes inside
 * JNIEnvExt::RegisterNatives to bypass anti-hook prologue checksums.
 */
static void dobby_mid_func_register_natives_cb(void *address, DobbyRegisterContext *ctx) {
    (void)address;
    if (!ctx) {
        return;
    }
    JNIEnv *env = (JNIEnv *)(uintptr_t)ctx->general_regs[0];
    jclass clazz = (jclass)(uintptr_t)ctx->general_regs[1];
    const JNINativeMethod *methods = (const JNINativeMethod *)(uintptr_t)ctx->general_regs[2];
    jint nMethods = (jint)ctx->general_regs[3];

    char cls_name[256];
    resolve_jclass_name(env, clazz, cls_name, sizeof(cls_name));
    record_registration_batch(cls_name, methods, nMethods);
}

int jnisleuth_install_hooks(JNIEnv *env, int mid_function_offset_bytes) {
    if (!env || !(*env)) {
        return -1;
    }

    struct JNINativeInterface_ *mutable_vt = (struct JNINativeInterface_ *)(*env);
    void *reg_natives_fn = mutable_vt->reserved[JNI_SLOT_REGISTER_NATIVES];
    if (!reg_natives_fn) {
        return -1;
    }

    g_orig_RegisterNatives = (pfn_RegisterNatives_t)reg_natives_fn;

    if (mid_function_offset_bytes > 0) {
        uint8_t *mid_target = (uint8_t *)reg_natives_fn + mid_function_offset_bytes;
        DobbyInstrument((void *)mid_target, dobby_mid_func_register_natives_cb);
    }

    void *orig_trampoline = NULL;
    if (DobbyHook(
            reg_natives_fn,
            (void *)jnisleuth_hooked_RegisterNatives,
            &orig_trampoline
        ) == 0 &&
        orig_trampoline != NULL) {
        g_orig_RegisterNatives = (pfn_RegisterNatives_t)orig_trampoline;
    }

    /* Also hook ArtMethod::RegisterNative in libart.so if resolvable via Dobby */
    void *art_reg_sym = DobbySymbolResolver(
        "libart.so",
        "_ZN3art9ArtMethod14RegisterNativeEPKv"
    );
    if (art_reg_sym) {
        DobbyInstrument(art_reg_sym, dobby_mid_func_register_natives_cb);
    }

    return 0;
}
