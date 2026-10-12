/*
 * Synthetic obfuscated Android NDK sample (`libcore-crypto.so`) for JNISleuth-MCP.
 * Demonstrates:
 *  1. Static JNINativeMethod table registration in .rodata / .data.rel.ro
 *  2. Stack-constructed method names in JNI_OnLoad for dynamic RegisterNatives
 *  3. JNIEnv* vtable calls (GetStringUTFChars, GetByteArrayElements, ReleaseStringUTFChars)
 */

#include <jni.h>
#include <stdint.h>
#include <string.h>

static void rc4_crypt_buffer(jbyte *buf, const char *key) {
    if (!buf || !key) {
        return;
    }
    size_t key_len = strlen(key);
    if (key_len == 0) {
        return;
    }
    for (size_t i = 0; i < 32; ++i) {
        buf[i] ^= (jbyte)key[i % key_len];
    }
}

static jboolean native_initEngine(JNIEnv *env, jobject thiz, jobject context, jint configFlags) {
    (void)thiz;
    (void)context;
    jclass cls = env->FindClass("android/app/ActivityThread");
    if (!cls) {
        return JNI_FALSE;
    }
    jmethodID mid = env->GetStaticMethodID(cls, "currentApplication", "()Landroid/app/Application;");
    if (!mid) {
        return JNI_FALSE;
    }
    jobject app = env->CallStaticObjectMethod(cls, mid);
    return (app != nullptr && configFlags >= 0) ? JNI_TRUE : JNI_FALSE;
}

static jbyteArray native_decryptPayload(
    JNIEnv *env,
    jobject thiz,
    jbyteArray encryptedData,
    jstring rc4KeyStr
) {
    (void)thiz;
    const char *key_utf = env->GetStringUTFChars(rc4KeyStr, nullptr);
    jbyte *payload_bytes = env->GetByteArrayElements(encryptedData, nullptr);
    rc4_crypt_buffer(payload_bytes, key_utf);
    env->ReleaseStringUTFChars(rc4KeyStr, key_utf);
    return encryptedData;
}

static jstring native_signC2Beacon(
    JNIEnv *env,
    jobject thiz,
    jstring beaconPayload,
    jstring deviceFingerprint
) {
    (void)thiz;
    const char *payload_utf = env->GetStringUTFChars(beaconPayload, nullptr);
    const char *fp_utf = env->GetStringUTFChars(deviceFingerprint, nullptr);
    env->ReleaseStringUTFChars(deviceFingerprint, fp_utf);
    env->ReleaseStringUTFChars(beaconPayload, payload_utf);
    return env->NewStringUTF("v1:hmac:7f9a2c4b");
}

/* Static JNINativeMethod table placed in .rodata / .data.rel.ro */
static const JNINativeMethod kCoreStaticMethods[] = {
    {"initEngine", "(Landroid/content/Context;I)Z", (void *)native_initEngine},
    {"decryptPayload", "([BLjava/lang/String;)[B", (void *)native_decryptPayload},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass coreCls = env->FindClass("com/dropper/Core");
    if (!coreCls) {
        return JNI_ERR;
    }
    env->RegisterNatives(
        coreCls,
        kCoreStaticMethods,
        sizeof(kCoreStaticMethods) / sizeof(kCoreStaticMethods[0])
    );

    /* Stack-constructed method name ("signC2Beacon") registered dynamically */
    volatile char stack_name[16];
    stack_name[0] = 's'; stack_name[1] = 'i'; stack_name[2] = 'g'; stack_name[3] = 'n';
    stack_name[4] = 'C'; stack_name[5] = '2'; stack_name[6] = 'B'; stack_name[7] = 'e';
    stack_name[8] = 'a'; stack_name[9] = 'c'; stack_name[10] = 'o'; stack_name[11] = 'n';
    stack_name[12] = '\0';

    JNINativeMethod dynMethod = {
        const_cast<char *>(stack_name),
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        (void *)native_signC2Beacon
    };
    env->RegisterNatives(coreCls, &dynMethod, 1);

    return JNI_VERSION_1_6;
}
