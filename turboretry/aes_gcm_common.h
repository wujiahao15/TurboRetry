/*
 * Copyright (c) 2023 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *     * Neither the name of the NVIDIA CORPORATION nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TOR
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef AES_GCM_COMMON_H_
#define AES_GCM_COMMON_H_

#include <doca_aes_gcm.h>

#define AES_GCM_KEY_128_SIZE_IN_BYTES 16 /* AES-GCM 128 bits key size */
#define AES_GCM_KEY_256_SIZE_IN_BYTES 32 /* AES-GCM 256 bits key size */
#define MAX_AES_GCM_KEY_SIZE                                                   \
    AES_GCM_KEY_256_SIZE_IN_BYTES /* Max AES-GCM key size in bytes */

#define AES_GCM_KEY_128_STR_SIZE                                               \
    (AES_GCM_KEY_128_SIZE_IN_BYTES * 2) /* AES-GCM 128 bits key string size */
#define AES_GCM_KEY_256_STR_SIZE                                               \
    (AES_GCM_KEY_256_SIZE_IN_BYTES * 2) /* AES-GCM 256 bits key string size */
#define MAX_AES_GCM_KEY_STR_SIZE                                               \
    (AES_GCM_KEY_256_STR_SIZE + 1) /* Max AES-GCM key string size */

#define AES_GCM_AUTH_TAG_96_SIZE_IN_BYTES                                      \
    12 /* AES-GCM 96 bits authentication tag size */
#define AES_GCM_AUTH_TAG_128_SIZE_IN_BYTES                                     \
    16 /* AES-GCM 128 bits authentication tag size */

#define MAX_AES_GCM_IV_LENGTH 12 /* Max IV length in bytes */
#define MAX_AES_GCM_IV_STR_LENGTH                                              \
    ((MAX_AES_GCM_IV_LENGTH * 2) + 1) /* Max IV string length */

#define SLEEP_IN_NANOS (10 * 1000) /* Sample the task every 10 microseconds */
#define NUM_AES_GCM_TASKS (1)      /* Number of AES-GCM tasks */

/* AES-GCM modes */
enum aes_gcm_mode {
    AES_GCM_MODE_ENCRYPT, /* Encrypt mode */
    AES_GCM_MODE_DECRYPT, /* Decrypt mode */
};

#endif