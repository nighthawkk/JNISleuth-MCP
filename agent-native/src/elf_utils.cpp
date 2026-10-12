#define _GNU_SOURCE
#include "jnisleuth_agent.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *extract_basename(const char *full_path) {
    if (!full_path) {
        return "libunknown.so";
    }
    const char *slash = strrchr(full_path, '/');
    return slash ? (slash + 1) : full_path;
}

static int resolve_via_proc_maps(uintptr_t target_pc, JNISleuthModuleOffset *out_info) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        return -1;
    }

    char line[512];
    uintptr_t module_first_base = 0;
    char matched_path[256];
    matched_path[0] = '\0';

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start_addr = 0;
        unsigned long end_addr = 0;
        unsigned long file_off = 0;
        char perms[8] = {0};
        char path_buf[256] = {0};

        int n = sscanf(
            line,
            "%lx-%lx %7s %lx %*s %*s %255[^\n]",
            &start_addr,
            &end_addr,
            perms,
            &file_off,
            path_buf
        );
        if (n >= 4 && target_pc >= (uintptr_t)start_addr && target_pc < (uintptr_t)end_addr) {
            uintptr_t computed_base = (uintptr_t)start_addr - (uintptr_t)file_off;
            out_info->base_addr = computed_base;
            out_info->fn_offset = target_pc - computed_base;
            if (n >= 5 && path_buf[0] != '\0') {
                snprintf(out_info->so_path, sizeof(out_info->so_path), "%s", path_buf);
                snprintf(
                    out_info->so_name,
                    sizeof(out_info->so_name),
                    "%s",
                    extract_basename(path_buf)
                );
            }
            fclose(fp);
            return 0;
        }
        (void)module_first_base;
        (void)matched_path;
    }

    fclose(fp);
    return -1;
}

int jnisleuth_resolve_module_offset(const void *fn_ptr, JNISleuthModuleOffset *out_info) {
    if (!out_info) {
        return -1;
    }
    memset(out_info, 0, sizeof(*out_info));
    snprintf(out_info->so_name, sizeof(out_info->so_name), "libunknown.so");
    snprintf(out_info->so_path, sizeof(out_info->so_path), "libunknown.so");

    uintptr_t raw_addr = (uintptr_t)fn_ptr;
#if defined(__arm__)
    raw_addr &= ~(uintptr_t)1;
#endif

    Dl_info dli;
    memset(&dli, 0, sizeof(dli));
    if (dladdr((const void *)raw_addr, &dli) != 0 && dli.dli_fbase != NULL) {
        uintptr_t base = (uintptr_t)dli.dli_fbase;
        out_info->base_addr = base;
        out_info->fn_offset = raw_addr >= base ? (raw_addr - base) : raw_addr;
        if (dli.dli_fname) {
            snprintf(out_info->so_path, sizeof(out_info->so_path), "%s", dli.dli_fname);
            snprintf(
                out_info->so_name,
                sizeof(out_info->so_name),
                "%s",
                extract_basename(dli.dli_fname)
            );
        }
        if (dli.dli_sname) {
            snprintf(out_info->symbol_name, sizeof(out_info->symbol_name), "%s", dli.dli_sname);
        }
        return 0;
    }

    /* Fallback to /proc/self/maps when packer strips or unlinks dynamic phdrs */
    if (resolve_via_proc_maps(raw_addr, out_info) == 0) {
        return 0;
    }

    out_info->base_addr = 0;
    out_info->fn_offset = raw_addr;
    return -1;
}
