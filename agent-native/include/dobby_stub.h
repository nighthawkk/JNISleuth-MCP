#ifndef JNISLEUTH_DOBBY_STUB_H_
#define JNISLEUTH_DOBBY_STUB_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t general_regs[31];
    uint64_t sp;
    uint64_t pc;
} DobbyRegisterContext;

typedef void (*dobby_instrument_callback_t)(void *address, DobbyRegisterContext *ctx);

#ifdef JNISLEUTH_HAS_EXTERNAL_DOBBY
int DobbyHook(void *address, void *fake_func, void **out_origin_func);
int DobbyInstrument(void *address, dobby_instrument_callback_t pre_handler);
void *DobbySymbolResolver(const char *image_name, const char *symbol_name);
#else
static inline int DobbyHook(void *address, void *fake_func, void **out_origin_func) {
    if (out_origin_func && address) {
        *out_origin_func = address;
    }
    (void)fake_func;
    return 0;
}

static inline int DobbyInstrument(void *address, dobby_instrument_callback_t pre_handler) {
    (void)address;
    (void)pre_handler;
    return 0;
}

static inline void *DobbySymbolResolver(const char *image_name, const char *symbol_name) {
    (void)image_name;
    (void)symbol_name;
    return (void *)0;
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* JNISLEUTH_DOBBY_STUB_H_ */
