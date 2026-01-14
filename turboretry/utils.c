/*
 * Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include <rte_cycles.h>

#include <doca_log.h>
#include <doca_version.h>

#include "utils.h"

DOCA_LOG_REGISTER(UTILS);

static uint64_t initial_tsc = 0;
static uint64_t initial_time = 0;
static uint64_t tsc_hz = 0;

void init_timestamp() {
    // Initialize at the first time
    initial_tsc = rte_rdtsc(); // 获取当前 TSC 值
    tsc_hz = rte_get_tsc_hz(); // 获取 TSC 频率（Hz）

    // 获取初始系统时间（需要临时调用系统函数）
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    initial_time = ts.tv_sec;
}

// Get current unix timestamp
uint64_t get_unix_timestamp() {
    uint64_t current_tsc = rte_rdtsc();
    return initial_time + (current_tsc - initial_tsc) / tsc_hz;
}

/* Generate random bytes according to the given length. */
doca_error_t generate_random_bytes(uint8_t *buffer, size_t length) {
    ssize_t result = getrandom(buffer, length, 0);
    if (result < 0) {
        DOCA_LOG_ERR("getrandom failed");
        return DOCA_ERROR_OPERATING_SYSTEM;
    }
    if ((size_t)result != length) {
        DOCA_LOG_ERR("getrandom returned fewer bytes than requested");
        return DOCA_ERROR_OPERATING_SYSTEM;
    }
    return DOCA_SUCCESS;
}

void print_n_hex_bytes(uint8_t *data, uint32_t len, const char *prefix) {
    printf("%s: 0x", prefix);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * Parse the variable-length encoding for non-negative integer values.
 *
 * @varint [in]: rte buffer
 * @varint_bytes [out]: the bytes of the value occupies (1,2,4 or 8)
 * @return: the parsed actual value
 */
size_t parse_varint(uint8_t *varint, uint8_t *varint_bytes) {
    size_t res = 0;
    uint8_t prefix = (*varint) >> 6;
    uint8_t length = 1 << prefix;
    *varint_bytes = length;
    res = (*varint) & 0x3f;
    for (int i = 1; i < length; i++) {
        res = (res << 8) + *(varint + i);
    }
    return res;
}

noreturn doca_error_t sdk_version_callback(void *param, void *doca_config) {
    (void)(param);
    (void)(doca_config);

    printf("DOCA SDK     Version (Compilation): %s\n", doca_version());
    printf("DOCA Runtime Version (Runtime):     %s\n", doca_version_runtime());
    /* We assume that when printing DOCA's versions there is no need to continue
     * the program's execution */
    exit(EXIT_SUCCESS);
}

doca_error_t read_file(char const *path, char **out_bytes,
                       size_t *out_bytes_len) {
    FILE *file;
    char *bytes;

    file = fopen(path, "rb");
    if (file == NULL)
        return DOCA_ERROR_NOT_FOUND;

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return DOCA_ERROR_IO_FAILED;
    }

    long const nb_file_bytes = ftell(file);

    if (nb_file_bytes == -1) {
        fclose(file);
        return DOCA_ERROR_IO_FAILED;
    }

    if (nb_file_bytes == 0) {
        fclose(file);
        return DOCA_ERROR_INVALID_VALUE;
    }

    bytes = malloc(nb_file_bytes);
    if (bytes == NULL) {
        fclose(file);
        return DOCA_ERROR_NO_MEMORY;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        free(bytes);
        fclose(file);
        return DOCA_ERROR_IO_FAILED;
    }

    size_t const read_byte_count = fread(bytes, 1, nb_file_bytes, file);

    fclose(file);

    if (read_byte_count != (size_t)nb_file_bytes) {
        free(bytes);
        return DOCA_ERROR_IO_FAILED;
    }

    *out_bytes = bytes;
    *out_bytes_len = read_byte_count;

    return DOCA_SUCCESS;
}

void linear_array_init_u16(uint16_t *array, uint16_t n) {
    for (uint16_t i = 0; i < n; i++) {
        array[i] = i;
    }
}

#ifndef DOCA_USE_LIBBSD

#ifndef strlcpy

#include <string.h>

size_t strlcpy(char *dst, const char *src, size_t size) {
    size_t trimmed_size;
    size_t src_len = strlen(src);

    if (size > 0) {
        trimmed_size = MIN(src_len, (size - 1));

        memcpy(dst, src, trimmed_size);
        dst[trimmed_size] = '\0';
    }

    return src_len;
}

#endif /* strlcpy */

#ifndef strlcat

#include <string.h>

size_t strlcat(char *dst, const char *src, size_t size) {
    size_t dst_len = strnlen(dst, size);

    if (dst_len >= size)
        return size;

    return dst_len + strlcpy(dst + dst_len, src, size - dst_len);
}

#endif /* strlcat */

#endif /* ! DOCA_USE_LIBBSD */
