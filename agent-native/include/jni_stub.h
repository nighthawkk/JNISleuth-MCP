#ifndef JNISLEUTH_JNI_STUB_H_
#define JNISLEUTH_JNI_STUB_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t jboolean;
typedef int8_t jbyte;
typedef uint16_t jchar;
typedef int16_t jshort;
typedef int32_t jint;
typedef int64_t jlong;
typedef float jfloat;
typedef double jdouble;
typedef jint jsize;

typedef void *jobject;
typedef jobject jclass;
typedef jobject jstring;
typedef jobject jarray;
typedef jobject jobjectArray;
typedef jobject jbyteArray;
typedef void *jmethodID;
typedef void *jfieldID;

#define JNI_FALSE 0
#define JNI_TRUE 1
#define JNI_OK 0
#define JNI_ERR (-1)
#define JNI_VERSION_1_6 0x00010006

typedef struct {
    const char *name;
    const char *signature;
    void *fnPtr;
} JNINativeMethod;

struct JNINativeInterface_;
typedef const struct JNINativeInterface_ *JNIEnv;

struct JNIInvokeInterface_;
typedef const struct JNIInvokeInterface_ *JavaVM;

/*
 * Exact 233-slot Android NDK JNINativeInterface vtable layout.
 * Slot 6   (+0x030 on 64-bit): FindClass
 * Slot 31  (+0x0f8 on 64-bit): GetObjectClass
 * Slot 33  (+0x108 on 64-bit): GetMethodID
 * Slot 34  (+0x110 on 64-bit): CallObjectMethod
 * Slot 169 (+0x548 on 64-bit): GetStringUTFChars
 * Slot 170 (+0x550 on 64-bit): ReleaseStringUTFChars
 * Slot 215 (+0x6b8 on 64-bit): RegisterNatives
 */
struct JNINativeInterface_ {
    void *reserved[233];
};

struct JNIInvokeInterface_ {
    void *reserved0;
    void *reserved1;
    void *reserved2;
    jint (*DestroyJavaVM)(JavaVM *vm);
    jint (*AttachCurrentThread)(JavaVM *vm, void **p_env, void *thr_args);
    jint (*DetachCurrentThread)(JavaVM *vm);
    jint (*GetEnv)(JavaVM *vm, void **env, jint version);
    jint (*AttachCurrentThreadAsDaemon)(JavaVM *vm, void **p_env, void *thr_args);
};

enum {
    JNI_SLOT_FIND_CLASS = 6,
    JNI_SLOT_GET_OBJECT_CLASS = 31,
    JNI_SLOT_GET_METHOD_ID = 33,
    JNI_SLOT_CALL_OBJECT_METHOD = 34,
    JNI_SLOT_GET_STRING_UTF_CHARS = 169,
    JNI_SLOT_RELEASE_STRING_UTF_CHARS = 170,
    JNI_SLOT_REGISTER_NATIVES = 215
};

typedef jclass (*pfn_GetObjectClass_t)(JNIEnv *env, jobject obj);
typedef jmethodID (*pfn_GetMethodID_t)(JNIEnv *env, jclass clazz, const char *name, const char *sig);
typedef jobject (*pfn_CallObjectMethod_t)(JNIEnv *env, jobject obj, jmethodID methodID, ...);
typedef const char *(*pfn_GetStringUTFChars_t)(JNIEnv *env, jstring str, jboolean *isCopy);
typedef void (*pfn_ReleaseStringUTFChars_t)(JNIEnv *env, jstring str, const char *utf);
typedef jint (*pfn_RegisterNatives_t)(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);

#ifdef __cplusplus
}
#endif

#endif /* JNISLEUTH_JNI_STUB_H_ */
