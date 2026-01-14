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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_pe.h>

#include "common.h"
#include "quic.h"
#include "utils.h"

DOCA_LOG_REGISTER(COMMON);

const char task_type_to_name[NUM_TASK_TYPES][MAX_NAME_STR_LEN] = {
    "CalcAuthTag",   "EncodeToken",   "DecodeToken",
    "DecryptPacket", "EncryptPacket",
};

doca_error_t open_doca_device_with_pci(const char *pci_addr, tasks_check func,
                                       struct doca_dev **retval) {
    struct doca_devinfo **dev_list;
    uint32_t nb_devs;
    uint8_t is_addr_equal = 0;
    int res;
    size_t i;

    /* Set default return value */
    *retval = NULL;

    res = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to load doca devices list: %s",
                     doca_error_get_descr(res));
        return res;
    }

    /* Search */
    for (i = 0; i < nb_devs; i++) {
        res = doca_devinfo_is_equal_pci_addr(dev_list[i], pci_addr,
                                             &is_addr_equal);
        if (res == DOCA_SUCCESS && is_addr_equal) {
            /* If any special capabilities are needed */
            if (func != NULL && func(dev_list[i]) != DOCA_SUCCESS)
                continue;

            /* if device can be opened */
            res = doca_dev_open(dev_list[i], retval);
            if (res == DOCA_SUCCESS) {
                doca_devinfo_destroy_list(dev_list);
                return res;
            }
        }
    }

    DOCA_LOG_WARN("Matching device not found");
    res = DOCA_ERROR_NOT_FOUND;

    doca_devinfo_destroy_list(dev_list);
    return res;
}

doca_error_t open_doca_device_with_ibdev_name(const uint8_t *value,
                                              size_t val_size, tasks_check func,
                                              struct doca_dev **retval) {
    struct doca_devinfo **dev_list;
    uint32_t nb_devs;
    char buf[DOCA_DEVINFO_IBDEV_NAME_SIZE] = {};
    char val_copy[DOCA_DEVINFO_IBDEV_NAME_SIZE] = {};
    int res;
    size_t i;

    /* Set default return value */
    *retval = NULL;

    /* Setup */
    if (val_size > DOCA_DEVINFO_IBDEV_NAME_SIZE) {
        DOCA_LOG_ERR("Value size too large. Failed to locate device");
        return DOCA_ERROR_INVALID_VALUE;
    }
    memcpy(val_copy, value, val_size);

    res = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to load doca devices list: %s",
                     doca_error_get_descr(res));
        return res;
    }

    /* Search */
    for (i = 0; i < nb_devs; i++) {
        res = doca_devinfo_get_ibdev_name(dev_list[i], buf,
                                          DOCA_DEVINFO_IBDEV_NAME_SIZE);
        if (res == DOCA_SUCCESS && strncmp(buf, val_copy, val_size) == 0) {
            /* If any special capabilities are needed */
            if (func != NULL && func(dev_list[i]) != DOCA_SUCCESS)
                continue;

            /* if device can be opened */
            res = doca_dev_open(dev_list[i], retval);
            if (res == DOCA_SUCCESS) {
                doca_devinfo_destroy_list(dev_list);
                return res;
            }
        }
    }

    DOCA_LOG_WARN("Matching device not found");
    res = DOCA_ERROR_NOT_FOUND;

    doca_devinfo_destroy_list(dev_list);
    return res;
}

doca_error_t open_doca_device_with_iface_name(const uint8_t *value,
                                              size_t val_size, tasks_check func,
                                              struct doca_dev **retval) {
    struct doca_devinfo **dev_list;
    uint32_t nb_devs;
    char buf[DOCA_DEVINFO_IFACE_NAME_SIZE] = {};
    char val_copy[DOCA_DEVINFO_IFACE_NAME_SIZE] = {};
    int res;
    size_t i;

    /* Set default return value */
    *retval = NULL;

    /* Setup */
    if (val_size > DOCA_DEVINFO_IFACE_NAME_SIZE) {
        DOCA_LOG_ERR("Value size too large. Failed to locate device");
        return DOCA_ERROR_INVALID_VALUE;
    }
    memcpy(val_copy, value, val_size);

    res = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to load doca devices list: %s",
                     doca_error_get_descr(res));
        return res;
    }

    /* Search */
    for (i = 0; i < nb_devs; i++) {
        res = doca_devinfo_get_iface_name(dev_list[i], buf,
                                          DOCA_DEVINFO_IFACE_NAME_SIZE);
        if (res == DOCA_SUCCESS && strncmp(buf, val_copy, val_size) == 0) {
            /* If any special capabilities are needed */
            if (func != NULL && func(dev_list[i]) != DOCA_SUCCESS)
                continue;

            /* if device can be opened */
            res = doca_dev_open(dev_list[i], retval);
            if (res == DOCA_SUCCESS) {
                doca_devinfo_destroy_list(dev_list);
                return res;
            }
        }
    }

    DOCA_LOG_WARN("Matching device not found");
    res = DOCA_ERROR_NOT_FOUND;

    doca_devinfo_destroy_list(dev_list);
    return res;
}

doca_error_t open_doca_device_with_capabilities(tasks_check func,
                                                struct doca_dev **retval) {
    struct doca_devinfo **dev_list;
    uint32_t nb_devs;
    doca_error_t result;
    size_t i;

    /* Set default return value */
    *retval = NULL;

    result = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to load doca devices list: %s",
                     doca_error_get_descr(result));
        return result;
    }

    /* Search */
    for (i = 0; i < nb_devs; i++) {
        /* If any special capabilities are needed */
        if (func(dev_list[i]) != DOCA_SUCCESS)
            continue;

        /* If device can be opened */
        if (doca_dev_open(dev_list[i], retval) == DOCA_SUCCESS) {
            doca_devinfo_destroy_list(dev_list);
            return DOCA_SUCCESS;
        }
    }

    DOCA_LOG_WARN("Matching device not found");
    doca_devinfo_destroy_list(dev_list);
    return DOCA_ERROR_NOT_FOUND;
}

doca_error_t open_doca_device_rep_with_vuid(struct doca_dev *local,
                                            enum doca_devinfo_rep_filter filter,
                                            const uint8_t *value,
                                            size_t val_size,
                                            struct doca_dev_rep **retval) {
    uint32_t nb_rdevs = 0;
    struct doca_devinfo_rep **rep_dev_list = NULL;
    char val_copy[DOCA_DEVINFO_REP_VUID_SIZE] = {};
    char buf[DOCA_DEVINFO_REP_VUID_SIZE] = {};
    doca_error_t result;
    size_t i;

    /* Set default return value */
    *retval = NULL;

    /* Setup */
    if (val_size > DOCA_DEVINFO_REP_VUID_SIZE) {
        DOCA_LOG_ERR("Value size too large. Ignored");
        return DOCA_ERROR_INVALID_VALUE;
    }
    memcpy(val_copy, value, val_size);

    /* Search */
    result =
        doca_devinfo_rep_create_list(local, filter, &rep_dev_list, &nb_rdevs);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create devinfo representor list. Representor "
                     "devices are available only on DPU, do not run on Host");
        return DOCA_ERROR_INVALID_VALUE;
    }

    for (i = 0; i < nb_rdevs; i++) {
        result = doca_devinfo_rep_get_vuid(rep_dev_list[i], buf,
                                           DOCA_DEVINFO_REP_VUID_SIZE);
        if (result == DOCA_SUCCESS &&
            strncmp(buf, val_copy, DOCA_DEVINFO_REP_VUID_SIZE) == 0 &&
            doca_dev_rep_open(rep_dev_list[i], retval) == DOCA_SUCCESS) {
            doca_devinfo_rep_destroy_list(rep_dev_list);
            return DOCA_SUCCESS;
        }
    }

    DOCA_LOG_WARN("Matching device not found");
    doca_devinfo_rep_destroy_list(rep_dev_list);
    return DOCA_ERROR_NOT_FOUND;
}

doca_error_t open_doca_device_rep_with_pci(struct doca_dev *local,
                                           enum doca_devinfo_rep_filter filter,
                                           const char *pci_addr,
                                           struct doca_dev_rep **retval) {
    uint32_t nb_rdevs = 0;
    struct doca_devinfo_rep **rep_dev_list = NULL;
    uint8_t is_addr_equal = 0;
    doca_error_t result;
    size_t i;

    *retval = NULL;

    /* Search */
    result =
        doca_devinfo_rep_create_list(local, filter, &rep_dev_list, &nb_rdevs);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create devinfo representors list. Representor "
                     "devices are available only on DPU, do not run on Host");
        return DOCA_ERROR_INVALID_VALUE;
    }

    for (i = 0; i < nb_rdevs; i++) {
        result = doca_devinfo_rep_is_equal_pci_addr(rep_dev_list[i], pci_addr,
                                                    &is_addr_equal);
        if (result == DOCA_SUCCESS && is_addr_equal &&
            doca_dev_rep_open(rep_dev_list[i], retval) == DOCA_SUCCESS) {
            doca_devinfo_rep_destroy_list(rep_dev_list);
            return DOCA_SUCCESS;
        }
    }

    DOCA_LOG_WARN("Matching device not found");
    doca_devinfo_rep_destroy_list(rep_dev_list);
    return DOCA_ERROR_NOT_FOUND;
}

doca_error_t create_core_objects(struct program_core_objects *state,
                                 uint32_t max_bufs) {
    doca_error_t res;

    res = doca_mmap_create(&state->src_mmap);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to create source mmap: %s",
                     doca_error_get_descr(res));
        return res;
    }
    res = doca_mmap_add_dev(state->src_mmap, state->dev);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to add device to source mmap: %s",
                     doca_error_get_descr(res));
        goto destroy_src_mmap;
    }

    res = doca_mmap_create(&state->dst_mmap);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to create destination mmap: %s",
                     doca_error_get_descr(res));
        goto destroy_src_mmap;
    }
    res = doca_mmap_add_dev(state->dst_mmap, state->dev);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to add device to destination mmap: %s",
                     doca_error_get_descr(res));
        goto destroy_dst_mmap;
    }

    if (max_bufs != 0) {
        res = doca_buf_inventory_create(max_bufs, &state->buf_inv);
        if (res != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to create buffer inventory: %s",
                         doca_error_get_descr(res));
            goto destroy_dst_mmap;
        }

        res = doca_buf_inventory_start(state->buf_inv);
        if (res != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to start buffer inventory: %s",
                         doca_error_get_descr(res));
            goto destroy_buf_inv;
        }
    }

    res = doca_pe_create(&state->pe);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to create progress engine: %s",
                     doca_error_get_descr(res));
        goto destroy_buf_inv;
    }

    return DOCA_SUCCESS;

destroy_buf_inv:
    if (state->buf_inv != NULL) {
        doca_buf_inventory_destroy(state->buf_inv);
        state->buf_inv = NULL;
    }

destroy_dst_mmap:
    doca_mmap_destroy(state->dst_mmap);
    state->dst_mmap = NULL;

destroy_src_mmap:
    doca_mmap_destroy(state->src_mmap);
    state->src_mmap = NULL;

    return res;
}

doca_error_t request_stop_ctx(struct doca_pe *pe, struct doca_ctx *ctx) {
    doca_error_t tmp_result, result = DOCA_SUCCESS;

    tmp_result = doca_ctx_stop(ctx);
    if (tmp_result == DOCA_ERROR_IN_PROGRESS) {
        enum doca_ctx_states ctx_state;

        do {
            (void)doca_pe_progress(pe);
            tmp_result = doca_ctx_get_state(ctx, &ctx_state);
            if (tmp_result != DOCA_SUCCESS) {
                DOCA_ERROR_PROPAGATE(result, tmp_result);
                DOCA_LOG_ERR("Failed to get state from ctx: %s",
                             doca_error_get_descr(tmp_result));
                break;
            }
        } while (ctx_state != DOCA_CTX_STATE_IDLE);
    } else if (tmp_result != DOCA_SUCCESS) {
        DOCA_ERROR_PROPAGATE(result, tmp_result);
        DOCA_LOG_ERR("Failed to stop ctx: %s",
                     doca_error_get_descr(tmp_result));
    }

    return result;
}

doca_error_t destroy_core_objects(struct program_core_objects *state) {
    doca_error_t tmp_result, result = DOCA_SUCCESS;

    if (state->pe != NULL) {
        tmp_result = doca_pe_destroy(state->pe);
        if (tmp_result != DOCA_SUCCESS) {
            DOCA_ERROR_PROPAGATE(result, tmp_result);
            DOCA_LOG_ERR("Failed to destroy pe: %s",
                         doca_error_get_descr(tmp_result));
        }
        state->pe = NULL;
    }

    if (state->buf_inv != NULL) {
        tmp_result = doca_buf_inventory_destroy(state->buf_inv);
        if (tmp_result != DOCA_SUCCESS) {
            DOCA_ERROR_PROPAGATE(result, tmp_result);
            DOCA_LOG_ERR("Failed to destroy buf inventory: %s",
                         doca_error_get_descr(tmp_result));
        }
        state->buf_inv = NULL;
    }

    if (state->dst_mmap != NULL) {
        tmp_result = doca_mmap_destroy(state->dst_mmap);
        if (tmp_result != DOCA_SUCCESS) {
            DOCA_ERROR_PROPAGATE(result, tmp_result);
            DOCA_LOG_ERR("Failed to destroy destination mmap: %s",
                         doca_error_get_descr(tmp_result));
        }
        state->dst_mmap = NULL;
    }

    if (state->src_mmap != NULL) {
        tmp_result = doca_mmap_destroy(state->src_mmap);
        if (tmp_result != DOCA_SUCCESS) {
            DOCA_ERROR_PROPAGATE(result, tmp_result);
            DOCA_LOG_ERR("Failed to destroy source mmap: %s",
                         doca_error_get_descr(tmp_result));
        }
        state->src_mmap = NULL;
    }

    if (state->dev != NULL) {
        tmp_result = doca_dev_close(state->dev);
        if (tmp_result != DOCA_SUCCESS) {
            DOCA_ERROR_PROPAGATE(result, tmp_result);
            DOCA_LOG_ERR("Failed to close device: %s",
                         doca_error_get_descr(tmp_result));
        }
        state->dev = NULL;
    }

    return result;
}

char *hex_dump(const void *data, size_t size) {
    /*
     * <offset>:     <Hex bytes: 1-8>        <Hex bytes: 9-16>         <Ascii>
     * 00000000: 31 32 33 34 35 36 37 38  39 30 61 62 63 64 65 66
     * 1234567890abcdef 8     2         8 * 3          1          8 * 3 1 16 1
     */
    const size_t line_size = 8 + 2 + 8 * 3 + 1 + 8 * 3 + 1 + 16 + 1;
    size_t i, j, r, read_index;
    size_t num_lines, buffer_size;
    char *buffer, *write_head;
    unsigned char cur_char, printable;
    char ascii_line[17];
    const unsigned char *input_buffer;

    /* Allocate a dynamic buffer to hold the full result */
    num_lines = (size + 16 - 1) / 16;
    buffer_size = num_lines * line_size + 1;
    buffer = (char *)malloc(buffer_size);
    if (buffer == NULL)
        return NULL;
    write_head = buffer;
    input_buffer = (unsigned char *)data;
    read_index = 0;

    for (i = 0; i < num_lines; i++) {
        /* Offset */
        snprintf(write_head, buffer_size, "%08lX: ", i * 16);
        write_head += 8 + 2;
        buffer_size -= 8 + 2;
        /* Hex print - 2 chunks of 8 bytes */
        for (r = 0; r < 2; r++) {
            for (j = 0; j < 8; j++) {
                /* If there is content to print */
                if (read_index < size) {
                    cur_char = input_buffer[read_index++];
                    snprintf(write_head, buffer_size, "%02X ", cur_char);
                    /* Printable chars go "as-is" */
                    if (' ' <= cur_char && cur_char <= '~')
                        printable = cur_char;
                    /* Otherwise, use a '.' */
                    else
                        printable = '.';
                    /* Else, just use spaces */
                } else {
                    snprintf(write_head, buffer_size, "   ");
                    printable = ' ';
                }
                ascii_line[r * 8 + j] = printable;
                write_head += 3;
                buffer_size -= 3;
            }
            /* Spacer between the 2 hex groups */
            snprintf(write_head, buffer_size, " ");
            write_head += 1;
            buffer_size -= 1;
        }
        /* Ascii print */
        ascii_line[16] = '\0';
        snprintf(write_head, buffer_size, "%s\n", ascii_line);
        write_head += 16 + 1;
        buffer_size -= 16 + 1;
    }
    /* No need for the last '\n' */
    write_head[-1] = '\0';
    return buffer;
}

void encrypt_completed_callback(struct doca_aes_gcm_task_encrypt *encrypt_task,
                                union doca_data task_user_data,
                                union doca_data ctx_user_data) {
    struct app_per_core_resources *apcr =
        (struct app_per_core_resources *)ctx_user_data.ptr;
    (void)apcr; // avoid warning

    struct crypto_task_result *result =
        (struct crypto_task_result *)task_user_data.ptr;

    /* Assign success to the result */
    result->status = CTASK_WAITING;
    result->result = DOCA_SUCCESS;

    /* Free task */
    // if (result->type == TASK_ENCRYPT_PKT) {
    doca_task_free(doca_aes_gcm_task_encrypt_as_task(encrypt_task));
    apcr->task_rscs[result->type]->task = NULL;
    // }
}

void encrypt_error_callback(struct doca_aes_gcm_task_encrypt *encrypt_task,
                            union doca_data task_user_data,
                            union doca_data ctx_user_data) {
    struct app_per_core_resources *apcr =
        (struct app_per_core_resources *)ctx_user_data.ptr;
    (void)apcr; // avoid warning

    struct doca_task *task = doca_aes_gcm_task_encrypt_as_task(encrypt_task);
    struct crypto_task_result *task_result =
        (struct crypto_task_result *)task_user_data.ptr;

    /* Assign failure to the result */
    /* Get the result of the task */
    task_result->status = CTASK_FAILED;
    task_result->result = doca_task_get_status(task);
    DOCA_LOG_ERR("Encrypt task failed: %s",
                 doca_error_get_descr(task_result->result));

    /* Free task */
    // doca_task_free(task);
    // if (task_result->type == TASK_ENCRYPT_PKT) {
    doca_task_free(task);
    apcr->task_rscs[task_result->type]->task = NULL;
    // }

    // /* Decrement number of remaining tasks */
    // --resources->num_remaining_tasks;
    // /* Stop context once all tasks are completed */
    // if (resources->num_remaining_tasks == 0)
    //     (void)doca_ctx_stop(resources->state->ctx);
}

void decrypt_completed_callback(struct doca_aes_gcm_task_decrypt *decrypt_task,
                                union doca_data task_user_data,
                                union doca_data ctx_user_data) {
    struct app_per_core_resources *apcr =
        (struct app_per_core_resources *)ctx_user_data.ptr;
    (void)apcr; // avoid warning

    struct crypto_task_result *result =
        (struct crypto_task_result *)task_user_data.ptr;

    /* Assign success to the result */
    result->status = CTASK_WAITING;
    result->result = DOCA_SUCCESS;

    /* Free task */
    // doca_task_free(doca_aes_gcm_task_encrypt_as_task(encrypt_task));
    // if (result->type == TASK_DECRYPT_PKT) {
    doca_task_free(doca_aes_gcm_task_decrypt_as_task(decrypt_task));
    apcr->task_rscs[result->type]->task = NULL;
    // }
}

void decrypt_error_callback(struct doca_aes_gcm_task_decrypt *decrypt_task,
                            union doca_data task_user_data,
                            union doca_data ctx_user_data) {
    struct app_per_core_resources *apcr =
        (struct app_per_core_resources *)ctx_user_data.ptr;
    (void)apcr; // avoid warning

    struct doca_task *task = doca_aes_gcm_task_decrypt_as_task(decrypt_task);
    struct crypto_task_result *task_result =
        (struct crypto_task_result *)task_user_data.ptr;

    /* Assign failure to the result */
    /* Get the result of the task */
    task_result->status = CTASK_FAILED;
    task_result->result = doca_task_get_status(task);
    DOCA_LOG_ERR("Decrypt task failed: %s",
                 doca_error_get_descr(task_result->result));

    /* Free task */
    // doca_task_free(task);

    // if (task_result->type == TASK_DECRYPT_PKT) {
    doca_task_free(task);
    apcr->task_rscs[task_result->type]->task = NULL;
    // }

    // /* Decrement number of remaining tasks */
    // --resources->num_remaining_tasks;
    // /* Stop context once all tasks are completed */
    // if (resources->num_remaining_tasks == 0)
    //     (void)doca_ctx_stop(resources->state->ctx);
}

doca_error_t submit_aes_gcm_crypto_task(struct app_per_core_resources *apcr,
                                        int task_id) {
    doca_error_t result = DOCA_SUCCESS;
    struct crypto_task_resources *task_rsc = apcr->task_rscs[task_id];
    struct crypto_task_result *task_result = &(task_rsc->result);
    // struct timespec ts = {
    //     .tv_sec = 0,
    //     .tv_nsec = SLEEP_IN_NANOS,
    // };
    // struct doca_aes_gcm_task_encrypt *encrypt_task = NULL;
    // union doca_data task_user_data = {0};

#ifdef DEBUG
    struct timespec start = {0}, end = {0};
    long duration_ns = 0;
#endif

/* Submit encrypt task */
#ifdef DEBUG
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    DOCA_LOG_DBG("[core=%02d] task(%p) state(%d) to submit",
                 task_rsc->lcore_rank, task_rsc->task, task_rsc->result.status);
    // if (task_rsc->task == NULL) {
    //     task_user_data.ptr = task_result;
    //     EXIT_ON_FAILURE(doca_aes_gcm_task_encrypt_alloc_init(
    //         state->aes_gcm, task_rsc->src_doca_buf, task_rsc->dst_doca_buf,
    //         task_rsc->key, task_rsc->params->iv, task_rsc->params->iv_length,
    //         task_rsc->params->tag_size, task_rsc->params->aad_size,
    //         task_user_data, &encrypt_task));
    //     task_rsc->task = doca_aes_gcm_task_encrypt_as_task(encrypt_task);
    // }
    result = doca_task_submit(task_rsc->task);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to submit encrypt task: %s",
                     doca_error_get_descr(result));
        doca_task_free(task_rsc->task);
        return result;
    }
    task_result->status = CTASK_RUNNING;

#ifdef DEBUG
    clock_gettime(CLOCK_MONOTONIC, &end);
    duration_ns =
        (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    DOCA_LOG_DBG("doca_task_submit took %.3f us", duration_ns / 1e3);
#endif

/*
 * Wait for the task to be completed.
 */
#ifdef DEBUG
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif
    DOCA_LOG_DBG("Wait for task to finish");
    while (task_result->status == CTASK_RUNNING) {
        doca_pe_progress(apcr->pe);
        // nanosleep(&ts, &ts);
        result = task_result->result;
    }
    result = task_result->result;

#ifdef DEBUG
    clock_gettime(CLOCK_MONOTONIC, &end);
    duration_ns =
        (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    DOCA_LOG_DBG("wait aes-gcm-128 encrypt task took %.3f us",
                 duration_ns / 1e3);
#endif

    return result;
}

/**
 * Allocates a buffer that will be used for the source and destination buffers.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t allocate_buffer(struct app_core_resources *state) {
    DOCA_LOG_INFO("Allocating buffer with size of %zu", state->buffer_size);

    state->buffer = (uint8_t *)malloc(state->buffer_size);
    if (state->buffer == NULL)
        return DOCA_ERROR_NO_MEMORY;

    return DOCA_SUCCESS;
}

/**
 * Create MMAP, initialize and start it.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_mmap(struct app_core_resources *state) {
    DOCA_LOG_INFO("Creating MMAP");

    EXIT_ON_FAILURE(doca_mmap_create(&state->mmap));
    EXIT_ON_FAILURE(
        doca_mmap_set_memrange(state->mmap, state->buffer, state->buffer_size));
    EXIT_ON_FAILURE(doca_mmap_add_dev(state->mmap, state->device));
    EXIT_ON_FAILURE(doca_mmap_set_permissions(
        state->mmap, DOCA_ACCESS_FLAG_LOCAL_READ_WRITE));
    EXIT_ON_FAILURE(doca_mmap_start(state->mmap));

    return DOCA_SUCCESS;
}

doca_error_t check_dev_encrypt_capable(struct doca_devinfo *devinfo) {
    return doca_aes_gcm_cap_task_encrypt_is_supported(devinfo);
}

doca_error_t check_dev_crypto_capable(struct doca_devinfo *devinfo) {
    doca_error_t result = DOCA_SUCCESS;

    result = doca_aes_gcm_cap_task_encrypt_is_supported(devinfo);
    if (result != DOCA_SUCCESS)
        return result;

    result = doca_aes_gcm_cap_task_decrypt_is_supported(devinfo);
    if (result != DOCA_SUCCESS)
        return result;

    uint64_t max_buf_size = 0;
    doca_aes_gcm_cap_task_decrypt_get_max_buf_size(devinfo, &max_buf_size);
    DOCA_LOG_INFO("Decrypt max buffer size = %lu", max_buf_size);

    return result;
}

/**
 * Opens a device that supports encrypt/decrypt.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_device(struct app_core_resources *state) {
    DOCA_LOG_INFO("Opening device");

    EXIT_ON_FAILURE(open_doca_device_with_capabilities(check_dev_crypto_capable,
                                                       &state->device));

    return DOCA_SUCCESS;
}

/**
 * Create buffer inventory, initialize and start it.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_buf_inventory(struct app_core_resources *state) {
    DOCA_LOG_INFO("Creating buf inventory");

    EXIT_ON_FAILURE(doca_buf_inventory_create(state->buf_inventory_size,
                                              &state->inventory));
    EXIT_ON_FAILURE(doca_buf_inventory_start(state->inventory));

    return DOCA_SUCCESS;
}

// /**
//  * Creates a progress engine
//  *
//  * @state [in]: sample state
//  * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
//  */
// doca_error_t create_pe(struct app_core_resources *state) {
//     DOCA_LOG_INFO("Creating PE");

//     EXIT_ON_FAILURE(doca_pe_create(&state->pe));

//     return DOCA_SUCCESS;
// }

// doca_error_t create_and_start_aes_gcm(struct app_core_resources *state) {
//     union doca_data ctx_user_data = {0};

//     /* Create aes gcm context */
//     EXIT_ON_FAILURE(doca_aes_gcm_create(state->device, &state->aes_gcm));

//     /* Convert aes gcm context to doca context */
//     state->ctx = doca_aes_gcm_as_ctx(state->aes_gcm);

//     /* Set user data in callback */
//     ctx_user_data.ptr = state;
//     EXIT_ON_FAILURE(doca_ctx_set_user_data(state->ctx, ctx_user_data));

//     /* Connect pe with context */
//     EXIT_ON_FAILURE(doca_pe_connect_ctx(state->pe, state->ctx));

//     /* Set encrypt configuration
//      * (complete callback, error callback and # of tasks)
//      */
//     EXIT_ON_FAILURE(doca_aes_gcm_task_encrypt_set_conf(
//         state->aes_gcm, encrypt_completed_callback, encrypt_error_callback,
//         NUM_TASKS));

//     /* Start the aes gcm context */
//     EXIT_ON_FAILURE(doca_ctx_start(state->ctx));

//     return DOCA_SUCCESS;
// }

doca_error_t crypto_task_params_init(struct crypto_task_params **params,
                                     int task_id) {
    enum crypto_task_type task_type;
    struct crypto_task_params *task_params;

    /* map task id to task aes gcm mode */
    const enum aes_gcm_mode task_type_to_mode[NUM_TASK_TYPES] = {
        AES_GCM_MODE_ENCRYPT, AES_GCM_MODE_ENCRYPT, AES_GCM_MODE_DECRYPT,
        AES_GCM_MODE_DECRYPT, AES_GCM_MODE_ENCRYPT,
    };

    /* initialize params of tasks */
    task_params = CALLOC_WITH_TYPE(struct crypto_task_params);
    if (task_params == NULL) {
        return DOCA_ERROR_NO_MEMORY;
    }
    *params = task_params;
    DOCA_LOG_DBG("Task %s params allocated", task_type_to_name[task_id]);

    task_type = (enum crypto_task_type)task_id;
    task_params->mode = task_type_to_mode[task_id];
    task_params->type = task_type;
    task_params->raw_key_type = RETRY_AEAD_KEY_TYPE;
    task_params->iv_length = RETRY_AEAD_NONCE_LEN;
    task_params->tag_size = RETRY_INTEGRITY_TAG_SIZE;
    task_params->aad_size = UINT32_MAX; // dynamically set before task creation

    if (task_type == TASK_CALC_AUTH_TAG) {
        memcpy(task_params->raw_key, retry_aead_key, RETRY_AEAD_KEY_LEN);
        memcpy(task_params->iv, retry_aead_nonce, RETRY_AEAD_NONCE_LEN);

    } else {
        memset(task_params->raw_key, 0, RETRY_AEAD_KEY_LEN);
        memset(task_params->iv, 0, RETRY_AEAD_NONCE_LEN);
    }

    DOCA_LOG_DBG("Task %s params all set", task_type_to_name[task_id]);

    return DOCA_SUCCESS;
}

doca_error_t crypto_task_params_cleanup(struct crypto_task_params *params) {
    if (params != NULL)
        free(params);
    return DOCA_SUCCESS;
}

doca_error_t program_core_resources_init(struct app_core_resources *state) {
    EXIT_ON_FAILURE(allocate_buffer(state));
    EXIT_ON_FAILURE(open_device(state));
    EXIT_ON_FAILURE(create_mmap(state));
    EXIT_ON_FAILURE(create_buf_inventory(state));
    // EXIT_ON_FAILURE(create_pe(state));
    // EXIT_ON_FAILURE(create_and_start_aes_gcm(state));

    return DOCA_SUCCESS;
}

/**
 * This method cleans up the sample resources in reverse order of their
 * creation. This method does not check for destroy return values for simplify.
 * Real code should check the return value and act accordingly (e.g. if
 * doca_ctx_stop failed with DOCA_ERROR_IN_PROGRESS it means that some contexts
 * are still added or even that there are still in flight tasks in the progress
 * engine).
 * @state [in]: sample state
 */
doca_error_t program_core_resources_cleanup(struct app_core_resources *state) {
    DOCA_LOG_DBG("Cleaning program core resources.");

    if (state->inventory != NULL) {
        DOCA_LOG_DBG("Stopping buf_inventory.");
        (void)doca_buf_inventory_stop(state->inventory);
        DOCA_LOG_DBG("Destroying buf_inventory.");
        (void)doca_buf_inventory_destroy(state->inventory);
    }

    if (state->mmap != NULL) {
        DOCA_LOG_DBG("Stopping mmap.");
        (void)doca_mmap_stop(state->mmap);
        DOCA_LOG_DBG("Destroying mmap.");
        (void)doca_mmap_destroy(state->mmap);
    }

    if (state->device != NULL) {
        DOCA_LOG_DBG("Closing device.");
        (void)doca_dev_close(state->device);
    }

    if (state->buffer != NULL) {
        DOCA_LOG_DBG("Freeing buffer.");
        free(state->buffer);
    }

    free(state);

    DOCA_LOG_DBG("Cleaning program core resources all done.");

    return DOCA_SUCCESS;
}

/**
 *
 */
doca_error_t program_resources_init(struct app_resources *resources) {
    struct app_core_resources *state;

    // allocate memory for state
    state = CALLOC_WITH_TYPE(struct app_core_resources);
    if (state == NULL) {
        return DOCA_ERROR_NO_MEMORY;
    }
    resources->state = state;

    state->buffer_size = BUFFER_SIZE;
    state->buf_inventory_size = NUM_TASKS << 1; // each task has two bufs

    // init dynamic resources
    EXIT_ON_FAILURE(program_core_resources_init(state));
    EXIT_ON_FAILURE(program_per_core_resources_init(resources));
    init_openssl();
    init_timestamp();

    return DOCA_SUCCESS;
}

/**
 * This method cleans up the program resources in reverse order of their
 * creation. This method does not check for destroy return values for simplify.
 * Real code should check the return value and act accordingly (e.g. if
 * doca_ctx_stop failed with DOCA_ERROR_IN_PROGRESS it means that some contexts
 * are still added or even that there are still in flight tasks in the progress
 * engine).
 *
 * @state [in]: program resources
 */
doca_error_t program_resources_cleanup(struct app_resources *resources) {

    /* Clean up per core resources*/
    (void)program_per_core_resources_cleanup(resources);

    /* Clean up program core resources. */
    (void)program_core_resources_cleanup(resources->state);

    DOCA_LOG_DBG("Cleaning program resources is all done.");

    return DOCA_SUCCESS;
}

doca_error_t program_per_core_resources_init(struct app_resources *resources) {
    int lcore = 0;
    int task_id = 0;
    size_t buffer_size = 0;
    union doca_data ctx_user_data = {0};
    // union doca_data task_user_data = {0};
    struct doca_buf *source = NULL;
    struct doca_buf *destination = NULL;
    struct app_core_resources *state = resources->state;
    struct app_per_core_resources *apcr = NULL;
    enum crypto_task_type task_type;
    struct crypto_task_resources *task_rsc = NULL;
    struct crypto_task_params *params = NULL;
    uint8_t *buffer = state->buffer;

    DOCA_LOG_INFO("Creating per core resources.");
    /* start from core 1, as core 0 is the main core */
    for (lcore = 1; lcore < resources->nb_cores; lcore++) {
        apcr = CALLOC_WITH_TYPE(struct app_per_core_resources);
        if (apcr == NULL) {
            return DOCA_ERROR_NO_MEMORY;
        }
        resources->apcrs[lcore] = apcr;

        /* Create progress engine */
        EXIT_ON_FAILURE(doca_pe_create(&apcr->pe));

        /* Create aes gcm context */
        EXIT_ON_FAILURE(doca_aes_gcm_create(state->device, &apcr->aes_gcm));

        /* Convert aes gcm context to doca context */
        apcr->ctx = doca_aes_gcm_as_ctx(apcr->aes_gcm);

        /* Set user data in callback */
        ctx_user_data.ptr = apcr;
        EXIT_ON_FAILURE(doca_ctx_set_user_data(apcr->ctx, ctx_user_data));

        /* Connect pe with context */
        EXIT_ON_FAILURE(doca_pe_connect_ctx(apcr->pe, apcr->ctx));

        /* Set encrypt configuration
         * (complete callback, error callback and # of tasks)
         */
        EXIT_ON_FAILURE(doca_aes_gcm_task_encrypt_set_conf(
            apcr->aes_gcm, encrypt_completed_callback, encrypt_error_callback,
            NUM_TASK_TYPES));

        /* Set decrypt configuration
         * (complete callback, error callback and # of tasks)
         */
        EXIT_ON_FAILURE(doca_aes_gcm_task_decrypt_set_conf(
            apcr->aes_gcm, decrypt_completed_callback, decrypt_error_callback,
            NUM_TASK_TYPES));

        /* Start the aes gcm context */
        EXIT_ON_FAILURE(doca_ctx_start(apcr->ctx));

        /* Allocate memory for quic packet information */
        apcr->qp_info = CALLOC_WITH_TYPE(struct quic_pkt_info);
        if (apcr->qp_info == NULL) {
            return DOCA_ERROR_NO_MEMORY;
        }

        /* Create crypto task resources */
        for (task_id = 0; task_id < NUM_TASK_TYPES; task_id++) {
            EXIT_ON_FAILURE(
                crypto_task_params_init(&(apcr->params[task_id]), task_id));
        }

        /* Create crypto task resources */
        for (task_id = 0; task_id < NUM_TASK_TYPES; task_id++) {
            DOCA_LOG_DBG("lcore=%d [Task %d] resources to be allocated", lcore,
                         task_id);
            task_rsc = CALLOC_WITH_TYPE(struct crypto_task_resources);
            if (task_rsc == NULL) {
                return DOCA_ERROR_NO_MEMORY;
            }

            DOCA_LOG_DBG("lcore=%d [Task %d] resources are allocated", lcore,
                         task_id);
            apcr->task_rscs[task_id] = task_rsc;
            // task_rsc->params = apcr->params[task_id];
            task_rsc->lcore_rank = lcore;
            task_type = (enum crypto_task_type)task_id;
            task_rsc->result.type = task_type;
            task_rsc->result.result = DOCA_SUCCESS;
            task_rsc->result.status = CTASK_WAITING;
            // task_user_data.ptr = &(task_rsc->result);
            buffer_size = (task_id < NUM_TINY_TASK_TYPES)
                              ? CRYPTO_BUFFER_SIZE
                              : PACKET_CRYPTO_BUFFER_SIZE;
            /* Initialize the source buffer */
            EXIT_ON_FAILURE(doca_buf_inventory_buf_get_by_data(
                state->inventory, state->mmap, buffer, buffer_size, &source));
            task_rsc->src_buffer = buffer;
            task_rsc->src_doca_buf = source;
            memset(buffer, 0, buffer_size);
            buffer += buffer_size;
            DOCA_LOG_DBG(
                "Task %d [lcore=%d] src doca buf allocated with size %ld",
                task_id, lcore, buffer_size);

            /* Initialize the destination buffer */
            EXIT_ON_FAILURE(doca_buf_inventory_buf_get_by_addr(
                state->inventory, state->mmap, buffer, buffer_size,
                &destination));
            task_rsc->dst_buffer = buffer;
            task_rsc->dst_doca_buf = destination;
            memset(buffer, 0, buffer_size);
            buffer += buffer_size;
            DOCA_LOG_DBG(
                "Task %d [lcore=%d] dst doca buf allocated with size %ld",
                task_id, lcore, buffer_size);

            if (task_id == TASK_CALC_AUTH_TAG) {
                /* Create AES GCM key */
                params = apcr->params[task_id];
                EXIT_ON_FAILURE(doca_aes_gcm_key_create(
                    apcr->aes_gcm, params->raw_key, params->raw_key_type,
                    &(task_rsc->key)));
                DOCA_LOG_DBG("Task key created (%p)", task_rsc->key);
            }

            DOCA_LOG_DBG("Task %d [lcore=%02d] task allocated", task_id, lcore);
        }
    }

    return DOCA_SUCCESS;
}

doca_error_t
program_per_core_resources_cleanup(struct app_resources *resources) {
    int lcore = 0, task_id = 0;
    struct app_per_core_resources *apcr = NULL;
    struct crypto_task_resources *task_rsc = NULL;
    doca_error_t result = DOCA_SUCCESS;

    for (lcore = 1; lcore < resources->nb_cores; lcore++) {
        apcr = resources->apcrs[lcore];

        if (apcr == NULL) {
            continue;
        }

        if (apcr->qp_info != NULL) {
            free(apcr->qp_info);
        }

        // delete task resources
        for (task_id = 0; task_id < NUM_TASK_TYPES; task_id++) {
            task_rsc = apcr->task_rscs[task_id];
            if (task_rsc == NULL) {
                continue;
            }
            DOCA_LOG_DBG("Task [%d][%d]: Cleaning doca task.", lcore, task_id);
            // delete task
            if (task_rsc->task != NULL)
                doca_task_free(task_rsc->task);

            // delete key
            if (task_rsc->key != NULL) {
                DOCA_LOG_DBG("Task [%d][%d]: Destroying aes gcm key.", lcore,
                             task_id);
                result = doca_aes_gcm_key_destroy(task_rsc->key);
                DOCA_LOG_DBG("Task [%d][%d]: AES GCM key destroyed.", lcore,
                             task_id);
            }

            // delete dst buf
            DOCA_LOG_DBG("Task [%d][%d]: Cleaning dst doca buf.", lcore,
                         task_id);
            (void)doca_buf_dec_refcount(task_rsc->dst_doca_buf, NULL);

            // delete src buf
            DOCA_LOG_DBG("Task [%d][%d]: Cleaning src doca buf.", lcore,
                         task_id);
            (void)doca_buf_dec_refcount(task_rsc->src_doca_buf, NULL);
            DOCA_LOG_DBG("Task [%d][%d]: DOCA buf cleaned.", lcore, task_id);

            // free allocated memory
            free(task_rsc);
            DOCA_LOG_DBG("Task [%d][%d]: Cleaning resources all done.", lcore,
                         task_id);
        }

        // delete task resources
        for (task_id = 0; task_id < NUM_TASK_TYPES; task_id++) {
            DOCA_LOG_DBG("Cleaning crypto task params of task id %d.", task_id);
            crypto_task_params_cleanup(apcr->params[task_id]);
            DOCA_LOG_DBG("Cleaning crypto task params of task id %d is done.",
                         task_id);
        }

        if (apcr->aes_gcm != NULL) {
            DOCA_LOG_DBG("Stopping context %d.", lcore);
            result = doca_ctx_stop(apcr->ctx);
            apcr->ctx = NULL;

            DOCA_LOG_DBG("Destroying aes gcm context %d.", lcore);
            result = doca_aes_gcm_destroy(apcr->aes_gcm);
        }

        if (apcr->pe != NULL) {
            DOCA_LOG_DBG("Destroying progress engine %d.", lcore);
            result = doca_pe_destroy(apcr->pe);
        }
    }

    return result;
}
