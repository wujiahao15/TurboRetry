/*
 * Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#ifndef COMMON_H_
#define COMMON_H_

// system lib
#include <time.h>

// dpdk lib
#include <rte_build_config.h>

// doca lib
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_mmap.h>
#include <doca_pe.h>
#include <doca_types.h>

// my lib
#include "aes_gcm_common.h"
#include "quic.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Function to check if a given device is capable of executing some task */
typedef doca_error_t (*tasks_check)(struct doca_devinfo *);

/* DOCA core objects used by the samples / applications */
struct program_core_objects {
    struct doca_dev *dev;               /* doca device */
    struct doca_mmap *src_mmap;         /* doca mmap for source buffer */
    struct doca_mmap *dst_mmap;         /* doca mmap for destination buffer */
    struct doca_buf_inventory *buf_inv; /* doca buffer inventory */
    struct doca_ctx *ctx;               /* doca context */
    struct doca_pe *pe;                 /* doca progress engine */
};

/* Crypto task type in the application */
enum crypto_task_type {
    TASK_CALC_AUTH_TAG = 0,
    TASK_ENCODE_TOKEN,
    TASK_DECODE_TOKEN,
    /* Above are tiny tasks */
    /* Below are huge tasks */
    TASK_DECRYPT_PKT,
    TASK_ENCRYPT_PKT,
    /* Below is magic count */
    TASK_TYPE_COUNT
};
/* Number of threads to process packets (excluding the main thread) */
#define NUM_THREADS RTE_MAX_LCORE
/* Number of crypto task type in the application */
#define NUM_TASK_TYPES TASK_TYPE_COUNT
#define NUM_HUGE_TASK_TYPES 2
#define NUM_TINY_TASK_TYPES (NUM_TASK_TYPES - NUM_HUGE_TASK_TYPES)
/* Max number of tasks to allocate */
#define NUM_TINY_TASKS (NUM_THREADS * NUM_TINY_TASK_TYPES)
#define NUM_HUGE_TASKS (NUM_THREADS * NUM_HUGE_TASK_TYPES)
#define NUM_TASKS (NUM_THREADS * NUM_TASK_TYPES)
/* Buffer size of each tiny crypto tasks:
 *   - token encrypt, token decrypt, and integrity tag computation
 */
#define CRYPTO_BUFFER_SIZE (512)
/* Buffer size of each crypto task */
#define PACKET_CRYPTO_BUFFER_SIZE (1024)
/* Total buffer size of all the tasks */
#define BUFFER_SIZE                                                            \
    (CRYPTO_BUFFER_SIZE * (NUM_TINY_TASKS << 1) +                              \
     PACKET_CRYPTO_BUFFER_SIZE * (NUM_HUGE_TASKS << 1))

/* Map of task type to its name string */
#define MAX_NAME_STR_LEN 16
extern const char task_type_to_name[NUM_TASK_TYPES][MAX_NAME_STR_LEN];

/* Crypto task static parameters (key, iv, mode...) */
struct crypto_task_params {
    enum crypto_task_type type; /* Crypto task type */
    enum aes_gcm_mode mode;     /* AES-GCM mode (encrypt/decrypt) */
    enum doca_aes_gcm_key_type raw_key_type; /* Raw key type */
    uint8_t raw_key[MAX_AES_GCM_KEY_SIZE];   /* Raw key */
    uint8_t iv[MAX_AES_GCM_IV_LENGTH];       /* Initialization vector */
    uint32_t iv_length;                      /* Initialization vector length */
    uint32_t tag_size;                       /* Authentication tag size */
    uint32_t aad_size; /* Additional authenticated data size */
};

enum crypto_task_status { CTASK_WAITING, CTASK_RUNNING, CTASK_FAILED };

struct crypto_task_result {
    enum crypto_task_type type; /* Crypto task type */
    doca_error_t result;
    enum crypto_task_status status;
};

/* Crypto task dynamic resources */
struct crypto_task_resources {
    // struct crypto_task_params *params; /* Task constant parameters */
    struct doca_aes_gcm_key *key;     /* Key connected with DOCA */
    struct doca_task *task;           /* doca task instance */
    struct doca_buf *src_doca_buf;    /* Source memory connected to DOCA */
    struct doca_buf *dst_doca_buf;    /* Destination memory connected to DOCA */
    struct crypto_task_result result; /* task result */
    uint8_t *dst_buffer;
    uint8_t *src_buffer;
    uint16_t lcore_rank;
};

/* DOCA core resources in the program */
struct app_core_resources {
    struct doca_dev *device;              /* doca device */
    struct doca_mmap *mmap;               /* doca mmap for source buffer */
    struct doca_buf_inventory *inventory; /* doca buffer inventory */
    // struct doca_ctx *ctx;                 /* doca context */
    // struct doca_pe *pe;                   /* doca progress engine */
    // struct doca_aes_gcm *aes_gcm;         /* doca aes gcm context */

    /**
     * Buffer parameters
     */
    uint8_t *buffer;           /* buffer for the source and destination */
    size_t buffer_size;        /* allocated memory size (bytes) */
    size_t buf_inventory_size; /* the number of doca_bufs */
};

struct app_per_core_resources {
    struct doca_ctx *ctx;         /* doca context */
    struct doca_pe *pe;           /* doca progress engine */
    struct doca_aes_gcm *aes_gcm; /* doca aes gcm context */
    struct crypto_task_params *params[NUM_TASK_TYPES];
    struct crypto_task_resources *task_rscs[NUM_TASK_TYPES];
    struct quic_pkt_info *qp_info;
};

/* Program resources of all cores */
struct app_resources {
    uint32_t nb_cores; /* Number of all avaliable cores */
    struct app_core_resources *state;
    // struct crypto_task_params *task_params[NUM_TASK_TYPES];
    struct app_per_core_resources *apcrs[NUM_THREADS];
};

// /* Program resource for one core */
// struct app_lcore_resources {
//     struct app_core_resources *state;
//     struct crypto_task_resources *tasks[NUM_TASK_TYPES];
// };

/* Function declarations */
doca_error_t allocate_buffer(struct app_core_resources *state);
doca_error_t open_device(struct app_core_resources *state);
doca_error_t create_mmap(struct app_core_resources *state);
doca_error_t create_buf_inventory(struct app_core_resources *state);
// doca_error_t create_pe(struct app_core_resources *state);
// doca_error_t create_and_start_aes_gcm(struct app_core_resources *state);

doca_error_t program_resources_cleanup(struct app_resources *resources);
doca_error_t program_resources_init(struct app_resources *resources);

doca_error_t program_core_resources_cleanup(struct app_core_resources *state);
doca_error_t program_core_resources_init(struct app_core_resources *state);

doca_error_t crypto_task_params_cleanup(struct crypto_task_params *params);
doca_error_t crypto_task_params_init(struct crypto_task_params **params,
                                     int task_id);

doca_error_t
program_per_core_resources_cleanup(struct app_resources *resources);
doca_error_t program_per_core_resources_init(struct app_resources *resources);

void encrypt_completed_callback(struct doca_aes_gcm_task_encrypt *encrypt_task,
                                union doca_data task_user_data,
                                union doca_data ctx_user_data);
void encrypt_error_callback(struct doca_aes_gcm_task_encrypt *encrypt_task,
                            union doca_data task_user_data,
                            union doca_data ctx_user_data);
void decrypt_completed_callback(struct doca_aes_gcm_task_decrypt *decrypt_task,
                                union doca_data task_user_data,
                                union doca_data ctx_user_data);
void decrypt_error_callback(struct doca_aes_gcm_task_decrypt *decrypt_task,
                            union doca_data task_user_data,
                            union doca_data ctx_user_data);
doca_error_t submit_aes_gcm_crypto_task(struct app_per_core_resources *apcr,
                                        int task_id);

/*
 * Open a DOCA device according to a given PCI address
 *
 * @pci_addr [in]: PCI address
 * @func [in]: pointer to a function that checks if the device have some task
 * capabilities (Ignored if set to NULL)
 * @retval [out]: pointer to doca_dev struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_with_pci(const char *pci_addr, tasks_check func,
                                       struct doca_dev **retval);

/*
 * Open a DOCA device according to a given IB device name
 *
 * @value [in]: IB device name
 * @val_size [in]: input length, in bytes
 * @func [in]: pointer to a function that checks if the device have some task
 * capabilities (Ignored if set to NULL)
 * @retval [out]: pointer to doca_dev struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_with_ibdev_name(const uint8_t *value,
                                              size_t val_size, tasks_check func,
                                              struct doca_dev **retval);

/*
 * Open a DOCA device according to a given interface name
 *
 * @value [in]: interface name
 * @val_size [in]: input length, in bytes
 * @func [in]: pointer to a function that checks if the device have some task
 * capabilities (Ignored if set to NULL)
 * @retval [out]: pointer to doca_dev struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_with_iface_name(const uint8_t *value,
                                              size_t val_size, tasks_check func,
                                              struct doca_dev **retval);

/*
 * Open a DOCA device with a custom set of capabilities
 *
 * @func [in]: pointer to a function that checks if the device have some task
 * capabilities
 * @retval [out]: pointer to doca_dev struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_with_capabilities(tasks_check func,
                                                struct doca_dev **retval);

/*
 * Open a DOCA device representor according to a given VUID string
 *
 * @local [in]: queries represtors of the given local doca device
 * @filter [in]: bitflags filter to narrow the represetors in the search
 * @value [in]: IB device name
 * @val_size [in]: input length, in bytes
 * @retval [out]: pointer to doca_dev_rep struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_rep_with_vuid(struct doca_dev *local,
                                            enum doca_devinfo_rep_filter filter,
                                            const uint8_t *value,
                                            size_t val_size,
                                            struct doca_dev_rep **retval);

/*
 * Open a DOCA device according to a given PCI address
 *
 * @local [in]: queries representors of the given local doca device
 * @filter [in]: bitflags filter to narrow the representors in the search
 * @pci_addr [in]: PCI address
 * @retval [out]: pointer to doca_dev_rep struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_rep_with_pci(struct doca_dev *local,
                                           enum doca_devinfo_rep_filter filter,
                                           const char *pci_addr,
                                           struct doca_dev_rep **retval);

/*
 * Initialize a series of DOCA Core objects needed for the program's execution
 *
 * @state [in]: struct containing the set of initialized DOCA Core objects
 * @max_bufs [in]: maximum number of buffers for DOCA Inventory
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_core_objects(struct program_core_objects *state,
                                 uint32_t max_bufs);

/*
 * Request to stop context
 *
 * @pe [in]: DOCA progress engine
 * @ctx [in]: DOCA context added to the progress engine
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t request_stop_ctx(struct doca_pe *pe, struct doca_ctx *ctx);

/*
 * Cleanup the series of DOCA Core objects created by create_core_objects
 *
 * @state [in]: struct containing the set of initialized DOCA Core objects
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t destroy_core_objects(struct program_core_objects *state);

/*
 * Create a string Hex dump representation of the given input buffer
 *
 * @data [in]: Pointer to the input buffer
 * @size [in]: Number of bytes to be analyzed
 * @return: pointer to the string representation, or NULL if an error was
 * encountered
 */
char *hex_dump(const void *data, size_t size);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
