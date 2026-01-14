#include <signal.h>
#include <stdbool.h>
#include <sys/time.h>
#include <time.h>

#include <doca_argp.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_flow_net.h>
#include <doca_log.h>

#include <rte_build_config.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_net.h>
#include <rte_udp.h>

#include "retry_fwd_core.h"
#include "utils.h"

DOCA_LOG_REGISTER(RETRY_FWD::CORE);

/* Burst size of packets to read, RX burst read size */
#define APP_RX_BURST_SIZE (32)

/* A marco that points to the start of the data in the mbuf */
#define APP_PKT_L2(M) rte_pktmbuf_mtod(M, struct rte_ether_hdr *)

/* A marco that returns the length of the packet */
#define APP_PKT_LEN(M) rte_pktmbuf_pkt_len(M)

/* Flag for forcing lcores to stop processing packets,
 * and gracefully terminate the application */
static volatile bool force_quit;

/* Quit application */
void app_quit(void) { force_quit = true; }

/*
 * Signal handler
 *
 * @signum [in]: The signal received to handle
 */
void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        DOCA_LOG_INFO("Signal %d received, preparing to exit", signum);
        app_quit();
    }
}

/* Statistics of each thread */
static struct retry_fwd_statistics stats[NUM_THREADS] = {0};

/* Parameters used by each core */
struct app_per_core_params {
    int ports[NUM_OF_DPDK_PORTS];  /* Ports identifiers */
    int queues[NUM_OF_DPDK_PORTS]; /* Queue mapped for the core running */
    bool used;                     /* Whether the core is used or not */
};

/* per core parameters */
static struct app_per_core_params core_params_arr[NUM_THREADS];

/* print the statistic result */
void retry_fwd_show_stats(uint32_t nb_cores) {
    DOCA_LOG_INFO("# of working cores = %d", nb_cores);

    int cord_id = 0;
    uint64_t total_rx_pkts = 0;
    uint64_t total_tx_pkts = 0;
    uint64_t nic_rx_pkts = 0;
    double pkt_loss_rate = 0.0;
    struct rte_eth_stats rte_stats = {0};
#ifdef PROFILE
    double avg_latency = 0.0;
#endif

    /* start from core 1, skipping core 0 (main core) */
    for (cord_id = 1; cord_id <= nb_cores; cord_id++) {
        total_rx_pkts += stats[cord_id].rx_pkts;
        total_tx_pkts += stats[cord_id].tx_pkts;
#ifdef PROFILE
        avg_latency += stats[cord_id].latency;
#endif
    }
#ifdef PROFILE
    avg_latency = avg_latency / total_rx_pkts;
#endif

    if (total_rx_pkts == 0) {
        printf("\nRx packets is zero, nothing to show.\n");
        return;
    }

    pkt_loss_rate =
        ((double)(total_rx_pkts - total_tx_pkts) / total_rx_pkts) * 100;

    rte_eth_stats_get(0, &rte_stats);

    printf("\n************* Forward statistics *************\n");
    printf("Application stats:\n");
    printf("# of total received packets = %lu\n", total_rx_pkts);
    printf("    # of total sent packets = %lu\n", total_tx_pkts);
    printf("                Packet loss = %.2f %%\n", pkt_loss_rate);
#ifdef PROFILE
    printf("            Average latency = %.2f us\n", avg_latency);
#endif
    nic_rx_pkts = rte_stats.ipackets + rte_stats.imissed + rte_stats.ierrors;
    pkt_loss_rate =
        ((double)(nic_rx_pkts - rte_stats.opackets) / nic_rx_pkts) * 100;
    printf("\nDPDK stats:\n");
    printf("                 # rx packets = %lu\n", rte_stats.ipackets);
    printf("                 # tx packets = %lu\n", rte_stats.opackets);
    printf("         # rx dropped packets = %lu\n", rte_stats.imissed);
    printf("      # errorneous rx packets = %lu\n", rte_stats.ierrors);
    printf("      # errorneous tx packets = %lu\n", rte_stats.oerrors);
    printf("# Rx mbuf allocation failures = %lu\n", rte_stats.rx_nombuf);
    printf("                  Packet loss = %.2f %%\n", pkt_loss_rate);
    printf("**********************************************\n");
}

/*
 * Map queues to port and logic cores.
 *
 * @param nb_queues the number of queues
 * @param nb_ports the number of ports
 */
void retry_fwd_map_queue(uint16_t nb_queues, int nb_ports) {
    int i, port, queue_idx = 0;
    DOCA_LOG_INFO("nb_queues = %d, nb_ports = %d", nb_queues, nb_ports);
    // Reset the statistics
    memset(stats, 0, sizeof(stats));
    // Reset the parameters
    memset(core_params_arr, 0, sizeof(core_params_arr));
    for (i = 0; i < RTE_MAX_LCORE; i++) {
        if (!rte_lcore_is_enabled(i)) {
            continue;
        }
        if (i == rte_get_main_lcore()) {
            continue;
        }
        for (port = 0; port < nb_ports; port++) {
            core_params_arr[i].ports[port] = port;
            core_params_arr[i].queues[port] = queue_idx;
        }
        core_params_arr[i].used = true;
        queue_idx++;
        if (queue_idx >= nb_queues)
            break;
    }
}

/*
 * Compute retry integrity tag.
 */
doca_error_t compute_integrity_tag(struct app_per_core_resources *apcr,
                                   size_t pseudo_retry_len,
                                   struct quic_pkt_info *info) {
    doca_error_t result = DOCA_SUCCESS;
    uint8_t *resp_head = NULL;
    size_t data_len = 0;
    size_t offset = 0;
    union doca_data task_user_data = {0};
    struct doca_aes_gcm_task_encrypt *task = NULL;
    struct crypto_task_params *params = NULL;
    struct crypto_task_resources *task_rsc = NULL;
#ifdef DEBUG
    struct timespec start = {0}, end = {0};
    long duration_ns = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    /* Register aes gcm params */
    params = apcr->params[TASK_CALC_AUTH_TAG];
    params->aad_size = pseudo_retry_len; /* no plain txt */

    /* Register aes gcm key and decrypt task */
    task_rsc = apcr->task_rscs[TASK_CALC_AUTH_TAG];
    task_rsc->result.type = TASK_CALC_AUTH_TAG;
    task_rsc->result.result = DOCA_SUCCESS;
    task_rsc->result.status = CTASK_WAITING;
    task_user_data.ptr = &(task_rsc->result);

    /* Register the doca task */
    EXIT_ON_FAILURE(doca_aes_gcm_task_encrypt_alloc_init(
        apcr->aes_gcm, task_rsc->src_doca_buf, task_rsc->dst_doca_buf,
        task_rsc->key, params->iv, params->iv_length, params->tag_size,
        params->aad_size, task_user_data, &task));
    task_rsc->task = doca_aes_gcm_task_encrypt_as_task(task);
    DOCA_LOG_INFO("TASK_CALC_AUTH_TAG task created (%p)", task_rsc->task);

    /* Manipulate doca_buf before submit encrypt task
     *   1. set data address and length of source doca_buf
     *      (see DOCA Core#Buffer-as-Source for details)
     *   2. reset data length of destination doca_buf
     *      (see DOCA Core#Buffer-as-Destination for details)
     */
    // memset(task_rsc->dst_buffer, 0, CRYPTO_BUFFER_SIZE);
    // src buffer has been filled with the pseudo retry packet
    // memset(task->src_buffer, 0, CRYPTO_BUFFER_SIZE);
    // memcpy(task->src_buffer, pseudo_retry_pkt, pseudo_retry_len);
    doca_buf_set_data(task_rsc->src_doca_buf, task_rsc->src_buffer,
                      pseudo_retry_len);
    doca_buf_reset_data_len(task_rsc->dst_doca_buf);

    /* Submit AES-GCM encrypt task */
#ifdef DEBUG
    clock_gettime(CLOCK_MONOTONIC, &end);
    duration_ns =
        (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    DOCA_LOG_INFO("prepare buffer took %.3f us", duration_ns / 1e3);
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif
    result = submit_aes_gcm_crypto_task(apcr, TASK_CALC_AUTH_TAG);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("AES-GCM encrypt task failed of task %s [lcore=%d]: %s",
                     task_type_to_name[TASK_CALC_AUTH_TAG],
                     task_rsc->lcore_rank, doca_error_get_descr(result));
        return result;
    }
#ifdef DEBUG
    clock_gettime(CLOCK_MONOTONIC, &end);
    duration_ns =
        (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    DOCA_LOG_INFO("Compute auth tag took %.3f us", duration_ns / 1e3);
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    /* Get the result */
    doca_buf_get_head(task_rsc->dst_doca_buf, (void **)&resp_head);
    doca_buf_get_data_len(task_rsc->dst_doca_buf, &data_len);

    /*
     * We only need the last 128 bit auth tag,
     * and pass it to retry_info structure.
     */
    offset = data_len - RETRY_INTEGRITY_TAG_SIZE;
    if (offset < 0) {
        result = DOCA_ERROR_UNEXPECTED;
        DOCA_LOG_ERR("Auth tag longer than result: %s",
                     doca_error_get_descr(result));
        return result;
    }

    /* FIXME: maybe need memcpy here */
    /* make retry_info points to the integrity tag */
    info->rty_auth_tag = resp_head + offset;

#ifdef DEBUG
    clock_gettime(CLOCK_MONOTONIC, &end);
    duration_ns =
        (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    DOCA_LOG_INFO("Compute auth tag post process took %.3f us",
                  duration_ns / 1e3);
#endif

    return result;
}

/*
 * Encode retry token.
 */
doca_error_t encode_retry_token(struct app_per_core_resources *apcr,
                                struct quic_pkt_info *info) {
    size_t data_len = 0;
    size_t offset = 0;
    doca_error_t result = DOCA_SUCCESS;
    uint8_t *resp_head = NULL;
    uint8_t *buffer = NULL;
    uint8_t *ptr = NULL;
    union doca_data task_user_data = {0};
    struct doca_aes_gcm_task_encrypt *task = NULL;
    struct crypto_task_resources *task_rsc = NULL;
    struct crypto_task_params *params = NULL;

#ifdef DEBUG
    struct timespec start = {0}, end = {0};
    long duration_ns = 0;
#endif

    /* Get current timestamp */
    uint64_t tstamp = get_unix_timestamp();
    uint64_t current_time = rte_cpu_to_be_64(tstamp);
    DOCA_LOG_INFO("Unix timestamp: %ld", tstamp);

    /* Register aes gcm params */
    params = apcr->params[TASK_ENCODE_TOKEN];
    // result = quic_derive_token_secrets(info->rty_scid, info->rty_scid_len,
    result = quic_derive_token_secrets(info->init_scid, info->init_scid_len,
                                       params->raw_key, params->iv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to generate secrets for token encryption");
        return DOCA_ERROR_INITIALIZATION;
    }

    // XOR `hkdf expand iv` with timestamp to make nonce unique
    ptr = (uint8_t *)&current_time;
    for (int i = 0; i < RETRY_AEAD_NONCE_LEN; i++) {
        if (i < sizeof(current_time)) {
            params->iv[i] ^= ptr[i];
        } else {
            params->iv[i] ^= 0;
        }
    }
    params->aad_size = RETRY_TOKEN_AAD_SIZE; // Token aad size

    /* Register aes gcm key and decrypt task */
    task_rsc = apcr->task_rscs[TASK_ENCODE_TOKEN];
    task_rsc->result.type = TASK_ENCODE_TOKEN;
    task_rsc->result.result = DOCA_SUCCESS;
    task_rsc->result.status = CTASK_WAITING;
    task_user_data.ptr = &(task_rsc->result);

    /* Create AES GCM key */
    if (task_rsc->key != NULL) {
        result = doca_aes_gcm_key_destroy(task_rsc->key);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to destroy formal aes gcm key");
            return result;
        }
    }
    EXIT_ON_FAILURE(doca_aes_gcm_key_create(apcr->aes_gcm, params->raw_key,
                                            params->raw_key_type,
                                            &(task_rsc->key)));
    DOCA_LOG_INFO("%s key created (%p)", task_type_to_name[TASK_ENCODE_TOKEN],
                  task_rsc->key);

    /* Register the doca task */
    EXIT_ON_FAILURE(doca_aes_gcm_task_encrypt_alloc_init(
        apcr->aes_gcm, task_rsc->src_doca_buf, task_rsc->dst_doca_buf,
        task_rsc->key, params->iv, params->iv_length, params->tag_size,
        params->aad_size, task_user_data, &task));
    task_rsc->task = doca_aes_gcm_task_encrypt_as_task(task);
    DOCA_LOG_INFO("%s task created (%p)", task_type_to_name[TASK_ENCODE_TOKEN],
                  task_rsc->task);

    /*
     * Manipulate doca_buf before submit encrypt task
     *   1. set data address and length of source doca_buf
     *      (see DOCA Core#Buffer-as-Source for details)
     *   2. reset data length of destination doca_buf
     *      (see DOCA Core#Buffer-as-Destination for details)
     */
    // clean the buffer
    // memset(task_rsc->dst_buffer, 0, CRYPTO_BUFFER_SIZE);
    // memset(task_rsc->src_buffer, 0, CRYPTO_BUFFER_SIZE);

    /* Set the content to be encoded
     *  +------------------------------------+----------------+
     *  |           Token Type (1)           |   Additional   |
     *  | Original Destination ID Length (7) | Authentication |
     *  |           Timestamp (64)           |     Data       |
     *  +------------------------------------+----------------+
     *  |  Original Destination ID (0..160)  |   Encrypted    |
     *  |       Source IP Address (32)       |      Data      |
     *  |         Source Port (16)           |      Part      |
     *  +------------------------------------+----------------+
     *  |      Authentication Tag (128)      |                |
     *  +------------------------------------+----------------+
     */
    buffer = task_rsc->src_buffer;
    // token type (1) | original destination id length (7)
    *buffer = info->init_dcid_len & 0x7f; // [7] is zero
    offset++;
    // timestamp
    *((uint64_t *)(buffer + offset)) = current_time;
    offset += 8;
    // original destination id
    memcpy(buffer + offset, info->init_dcid, info->init_dcid_len);
    offset += info->init_dcid_len;
    // source ip address
    *((uint32_t *)(buffer + offset)) = info->sip;
    offset += 4;
    // source port
    *((uint16_t *)(buffer + offset)) = info->sport;
    offset += 2;
    // memcpy(task_rsc->src_buffer + offset, info->rty_scid,
    // info->rty_scid_len); offset += info->rty_scid_len;
    doca_buf_set_data(task_rsc->src_doca_buf, task_rsc->src_buffer, offset);
    doca_buf_reset_data_len(task_rsc->dst_doca_buf);

/* Submit AES-GCM encrypt task */
#ifdef DEBUG
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif
    result = submit_aes_gcm_crypto_task(apcr, TASK_ENCODE_TOKEN);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("AES-GCM encrypt task failed of task %s [lcore=%d]: %s",
                     task_type_to_name[TASK_ENCODE_TOKEN], task_rsc->lcore_rank,
                     doca_error_get_descr(result));
        return result;
    }
#ifdef DEBUG
    clock_gettime(CLOCK_MONOTONIC, &end);
    duration_ns =
        (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    DOCA_LOG_INFO("Compute auth tag took %.3f ms", duration_ns / 1e6);
#endif

    /* Get the result */
    doca_buf_get_head(task_rsc->dst_doca_buf, (void **)&resp_head);
    doca_buf_get_data_len(task_rsc->dst_doca_buf, &data_len);

    /* Check data length */
    // #ifdef DEBUG
    if (data_len != offset + AES_GCM_AUTH_TAG_128_SIZE_IN_BYTES) {
        DOCA_LOG_ERR("Token length got %ld, expected %ld.", data_len,
                     offset + AES_GCM_AUTH_TAG_128_SIZE_IN_BYTES);
        return DOCA_ERROR_UNEXPECTED;
    }
    // #endif

    /*
     * Set the whole encoded result as token.
     * Make retry_info points to the integrity tag
     */
    info->rty_token = resp_head;
    info->rty_token_len = data_len;

#ifdef DEBUG
    print_n_hex_bytes(resp_head, data_len, "Token");
    if (data_len != QUIC_RETRY_TOKEN_LEN) {
        printf("token length should be %d, got %ld\n", QUIC_RETRY_TOKEN_LEN,
               data_len);
    } else {
        printf("token length is correct, got %ld\n", data_len);
    }
#endif

    return result;
}

/*
 * Decode retry token.
 */
doca_error_t decode_retry_token(struct app_per_core_resources *apcr,
                                struct quic_pkt_info *info) {
    doca_error_t result = DOCA_SUCCESS;
    // uint8_t *retry_scid = NULL;
    uint8_t *resp_head = NULL;
    uint8_t *ptr = NULL;
    uint16_t sport = 0;
    uint32_t sip = 0;
    size_t data_len = 0;
    union doca_data task_user_data = {0};
    struct doca_aes_gcm_task_decrypt *task = NULL;
    struct crypto_task_resources *task_rsc = NULL;
    struct crypto_task_params *params = NULL;

#ifdef DEBUG
    struct timespec start = {0}, end = {0};
    long duration_ns = 0;
#endif

    /* Get current timestamp */
    uint64_t tstamp = get_unix_timestamp();
    DOCA_LOG_INFO("Unix timestamp: %ld", tstamp);

    /* Register aes gcm params */
    params = apcr->params[TASK_DECODE_TOKEN];
    result = quic_derive_token_secrets(info->init_scid, info->init_scid_len,
                                       params->raw_key, params->iv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to generate secrets for token encryption");
        return DOCA_ERROR_INITIALIZATION;
    }

    // XOR `hkdf expand iv` with timestamp to make nonce unique
    ptr = info->init_token + 1;
    for (int i = 0; i < RETRY_AEAD_NONCE_LEN; i++) {
        if (i < sizeof(tstamp)) {
            params->iv[i] ^= ptr[i];
        } else {
            params->iv[i] ^= 0;
        }
    }
    params->aad_size = RETRY_TOKEN_AAD_SIZE; // Token aad size
                                             // #ifdef DEBUG
    print_hex("Key", params->raw_key, RETRY_AEAD_KEY_LEN);
    print_hex("Nonce", params->iv, params->iv_length);
    print_hex("Token", info->init_token, info->init_token_len);
    // #endif

    /* Register aes gcm key and decrypt task */
    task_rsc = apcr->task_rscs[TASK_DECODE_TOKEN];
    task_rsc->result.type = TASK_DECODE_TOKEN;
    task_rsc->result.result = DOCA_SUCCESS;
    task_rsc->result.status = CTASK_WAITING;
    task_user_data.ptr = &(task_rsc->result);

    /* Create AES GCM key */
    if (task_rsc->key != NULL) {
        result = doca_aes_gcm_key_destroy(task_rsc->key);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to destroy formal aes gcm key");
            return result;
        }
    }
    EXIT_ON_FAILURE(doca_aes_gcm_key_create(apcr->aes_gcm, params->raw_key,
                                            params->raw_key_type,
                                            &(task_rsc->key)));
    DOCA_LOG_INFO("%s key created (%p)", task_type_to_name[TASK_DECODE_TOKEN],
                  task_rsc->key);

    /* Register the doca task */
    EXIT_ON_FAILURE(doca_aes_gcm_task_decrypt_alloc_init(
        apcr->aes_gcm, task_rsc->src_doca_buf, task_rsc->dst_doca_buf,
        task_rsc->key, params->iv, params->iv_length, params->tag_size,
        params->aad_size, task_user_data, &task));
    task_rsc->task = doca_aes_gcm_task_decrypt_as_task(task);
    DOCA_LOG_INFO("%s task created (%p)", task_type_to_name[TASK_DECODE_TOKEN],
                  task_rsc->task);

    // clean the buffer
    // memset(task_rsc->dst_buffer, 0, CRYPTO_BUFFER_SIZE);
    // memset(task_rsc->src_buffer, 0, CRYPTO_BUFFER_SIZE);

    // copy token to the src_doca_buf
    memcpy(task_rsc->src_buffer, info->init_token, info->init_token_len);

    // set the content to be decoded
    doca_buf_set_data(task_rsc->src_doca_buf, task_rsc->src_buffer,
                      info->init_token_len);
    doca_buf_reset_data_len(task_rsc->dst_doca_buf);

/* Submit AES-GCM encrypt task */
#ifdef DEBUG
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif
    // submit decrypt task
    result = submit_aes_gcm_crypto_task(apcr, TASK_DECODE_TOKEN);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("AES-GCM decrypt failed in task %s [lcore=%d]: %s",
                     task_type_to_name[TASK_DECODE_TOKEN], task_rsc->lcore_rank,
                     doca_error_get_descr(result));
        return result;
    }
#ifdef DEBUG
    clock_gettime(CLOCK_MONOTONIC, &end);
    duration_ns =
        (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    DOCA_LOG_INFO("Decode retry token took %.3f ms", duration_ns / 1e6);
#endif

    /* Get the result */
    doca_buf_get_head(task_rsc->dst_doca_buf, (void **)&resp_head);
    doca_buf_get_data_len(task_rsc->dst_doca_buf, &data_len);

    /*
     * Parse the information from decoded token.
     *  1. aad (odcidl + timestamp)
     *  2. odcid
     *  3. sip
     *  4. sport
     *  // 3. retry scid
     */
    uint8_t odcidl = (*resp_head) & 0x7f;
    // offset += params->aad_size + odcidl;
    resp_head += params->aad_size + odcidl;
    sip = *((uint32_t *)(resp_head));
    resp_head += 4;
    sport = *((uint16_t *)(resp_head));
    resp_head += 2;
    // retry_scid = (uint8_t *)(resp_head + 4 + 2);

    /*
     * Validate the token.
     */
    if (sip != info->sip) {
        result = DOCA_ERROR_UNEXPECTED;
        DOCA_LOG_ERR(
            "Failed to validate token: sip is not identical, got 0x%x, "
            "expected 0x%x",
            info->sip, sip);
        goto validate_error;
    }
    if (sport != info->sport) {
        result = DOCA_ERROR_UNEXPECTED;
        DOCA_LOG_ERR(
            "Failed to validate token: sport is not identical, got 0x%x, "
            "expected 0x%x",
            info->sport, sport);
        goto validate_error;
    }
    //     if (strncmp((char *)retry_scid, (char *)info->init_dcid,
    //                 QUIC_CONNECTION_ID_LEN) != 0) {
    //         result = DOCA_ERROR_UNEXPECTED;
    //         DOCA_LOG_ERR(
    //             "Failed to validate token: connection id is not identical.");
    // #ifdef DEBUG
    //         print_n_hex_bytes((uint8_t *)retry_scid, QUIC_CONNECTION_ID_LEN,
    //                           "Retry scid");
    //         print_n_hex_bytes((uint8_t *)(info->init_dcid),
    //         QUIC_CONNECTION_ID_LEN,
    //                           "Retry scid in reply");
    // #endif
    //         goto validate_error;
    //     }
    DOCA_LOG_DBG("Source address validation passed.");

validate_error:
    return result;
}

/*
 * Parse quic packet and generate forward packet.
 *
 * @param mbuf [in]: dpdk packet buf
 * @param resources [in]: program resources
 * @param lcore [in]: core id to run the function
 * @return 0 on success and non-zero value on failure
 */
doca_error_t process_quic_packets(struct rte_mbuf *mbuf,
                                  struct app_per_core_resources *apcr,
                                  uint32_t *dst_port) {
    doca_error_t result = DOCA_SUCCESS;
    size_t pseudo_retry_len = 0;
    struct packet_headers pkt_hdrs = {0};
    struct crypto_task_resources *task_rsc = NULL;
    // struct crypto_task_resources **tasks = apcr->task_rscs[lcore];
    struct quic_pkt_info *info = apcr->qp_info;

#ifdef PROCESS_PROFILE
    struct timespec start = {0}, end = {0};
    long duration_ns = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    result = parse_packet_headers(mbuf, &pkt_hdrs);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_DBG("Parse l2,l3,l4 packet header failed: %s",
                     doca_error_get_descr(result));
        return result;
    }

    /* parse quic initial packet header */
#ifdef PROCESS_PROFILE
    clock_gettime(CLOCK_MONOTONIC, &end);
    duration_ns =
        (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    DOCA_LOG_INFO("Parse l2,l3,l4 packet headers took %.3f us",
                  duration_ns / 1e3);
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    result = quic_parse_initial_pkt_hdr(pkt_hdrs.quic_hdr,
                                        pkt_hdrs.udp_payload_len, info);
    // other quic packet sent to host
    if (result == DOCA_ERROR_IN_PROGRESS) {
        *dst_port = 1;
        return DOCA_SUCCESS;
    } else if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Parse quic packet header failed: %s",
                     doca_error_get_descr(result));
        return result;
    }

    // save sip and sport for token encoding
    info->sip = rte_be_to_cpu_32(pkt_hdrs.ip_hdr->src_addr);
    info->sport = rte_be_to_cpu_16(pkt_hdrs.udp_hdr->src_port);

#ifdef PROCESS_PROFILE
    clock_gettime(CLOCK_MONOTONIC, &end);
    duration_ns =
        (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
    DOCA_LOG_INFO("Parse quic initial packet header took %.3f us",
                  duration_ns / 1e3);
#endif

    /* Process branch:
     *   1. If it is a INITIAL packet without token,
     *      we will set up a RETRY packet and send it back to client;
     *   2. If it is a INITIAL packet with token,
     *      we will decode the token to validate the address.
     *         If it is valid, send it to host.
     *         Otherwise, we will drop it.
     */
    if (info->init_token_len == 0) {
        /*
         * INITIAL packet without token!
         * Build pseudo retry packet to get retry auth tag.
         */

#ifdef PROCESS_PROFILE
        clock_gettime(CLOCK_MONOTONIC, &start);
#endif
        task_rsc = apcr->task_rscs[TASK_CALC_AUTH_TAG];
        EXIT_ON_FAILURE(quic_build_pseudo_retry_packet(
            info, task_rsc->src_buffer, &pseudo_retry_len));

        DOCA_LOG_INFO("Retry pseudo packet length = %lu", pseudo_retry_len);

#ifdef PROCESS_PROFILE
        clock_gettime(CLOCK_MONOTONIC, &end);
        duration_ns =
            (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
        DOCA_LOG_INFO("Build pseudo retry packet took %.3f us",
                      duration_ns / 1e3);
        clock_gettime(CLOCK_MONOTONIC, &start);
#endif

        /* Encode retry token */
        EXIT_ON_FAILURE(encode_retry_token(apcr, info));

#ifdef PROCESS_PROFILE
        clock_gettime(CLOCK_MONOTONIC, &end);
        duration_ns =
            (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
        DOCA_LOG_INFO("Encoding retry token took %.3f us", duration_ns / 1e3);
        clock_gettime(CLOCK_MONOTONIC, &start);
#endif
        /* Append the encoded token to the pseudo retry packet */

        memcpy(info->rty_scid + QUIC_CONNECTION_ID_LEN, info->rty_token,
               info->rty_token_len);
        // memcpy(task_rsc->src_buffer + pseudo_retry_len -
        // QUIC_RETRY_TOKEN_LEN,
        //        info->rty_token, info->rty_token_len);

#ifdef PROCESS_PROFILE
        clock_gettime(CLOCK_MONOTONIC, &end);
        duration_ns =
            (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
        DOCA_LOG_INFO("memcpy after encoding retry token took %.3f us",
                      duration_ns / 1e3);
        clock_gettime(CLOCK_MONOTONIC, &start);
#endif

        /* Compute retry integrity tag */
        EXIT_ON_FAILURE(compute_integrity_tag(apcr, pseudo_retry_len, info));

#ifdef PROCESS_PROFILE
        clock_gettime(CLOCK_MONOTONIC, &end);
        duration_ns =
            (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
        DOCA_LOG_INFO("Computing integrity tag took %.3f us",
                      duration_ns / 1e3);
        clock_gettime(CLOCK_MONOTONIC, &start);
#endif

        /* Build the real retry packet */
        EXIT_ON_FAILURE(quic_build_real_retry_packet(mbuf, &pkt_hdrs, info));

#ifdef PROCESS_PROFILE
        clock_gettime(CLOCK_MONOTONIC, &end);
        duration_ns =
            (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
        DOCA_LOG_INFO("Build the real retry packet took %.3f us",
                      duration_ns / 1e3);
#endif
        *dst_port = 0;
    } else {
        /*
         * INITIAL packet with token!
         *   1. Decode the token to validate the address.
         *   2. Route the packet:
         *        1. If it is valid, send it to host.
         *        2. Otherwise, we will drop it.
         */
        result = decode_retry_token(apcr, info);
        if (result == DOCA_SUCCESS) {
            DOCA_LOG_INFO("Retry passed!");
            *dst_port = 1;
            // clip_initial_token(mbuf, apcr, &pkt_hdrs, info);
            // add entry
        } else if (result == DOCA_ERROR_UNEXPECTED) {
            DOCA_LOG_INFO("Retry token error!");
            // add drop entry
        } else {
            DOCA_LOG_INFO("Internal server error!");
        }
        return result;
    }

    return DOCA_SUCCESS;
}

/*
 * Encrypt QUIC Initial Packet Payload.
 *
 * @apcr [in]: pointer of application runtime resources
 * @quic_retry_pkt_info [out]: retry information (modify token related field)
 *
 * @return: 0 on success and non-zero value on failure
 */
doca_error_t encrypt_quic_initial_payload(struct app_per_core_resources *apcr,
                                          struct crypto_task_params *params,
                                          uint8_t *quic_init_hdr,
                                          uint8_t *decrypted_payload,
                                          uint16_t decrypted_payload_len,
                                          uint16_t padding_len,
                                          uint8_t **encrypted_payload) {
    uint8_t *resp_head = NULL;
    uint16_t offset = 0;
    int task_id = TASK_ENCRYPT_PKT;
    size_t data_len = 0;
    doca_error_t result = DOCA_SUCCESS;
    union doca_data task_user_data = {0};
    struct doca_aes_gcm_task_encrypt *encrypt_task = NULL;
    struct crypto_task_resources *task_rsc = NULL;

    print_hex("Key", params->raw_key, RETRY_AEAD_KEY_LEN);
    print_hex("IV", params->iv, RETRY_AEAD_NONCE_LEN);
    DOCA_LOG_INFO("iv size = %d", params->iv_length);
    DOCA_LOG_INFO("tag size = %d", params->tag_size);
    DOCA_LOG_INFO("aad size = %d", params->aad_size);
    DOCA_LOG_INFO("decrypted payload size = %d", decrypted_payload_len);
    DOCA_LOG_INFO("padding size = %d", padding_len);

    /* Register aes gcm key and encrypt task */
    task_rsc = apcr->task_rscs[task_id];
    task_rsc->result.type = (enum crypto_task_type)task_id;
    task_rsc->result.result = DOCA_SUCCESS;
    task_rsc->result.status = CTASK_WAITING;
    task_user_data.ptr = &(task_rsc->result);

    /* Create AES GCM key */
    EXIT_ON_FAILURE(doca_aes_gcm_key_create(apcr->aes_gcm, params->raw_key,
                                            params->raw_key_type,
                                            &(task_rsc->key)));
    DOCA_LOG_INFO("%s key created (%p)", task_type_to_name[task_id],
                  task_rsc->key);

    /* Register the doca task */
    EXIT_ON_FAILURE(doca_aes_gcm_task_encrypt_alloc_init(
        apcr->aes_gcm, task_rsc->src_doca_buf, task_rsc->dst_doca_buf,
        task_rsc->key, params->iv, params->iv_length, params->tag_size,
        params->aad_size, task_user_data, &encrypt_task));
    task_rsc->task = doca_aes_gcm_task_encrypt_as_task(encrypt_task);
    DOCA_LOG_INFO("%s task created (%p)", task_type_to_name[task_id],
                  task_rsc->task);

    /*
     * Manipulate doca_buf before submit encrypt task
     * 1. copy quic header to source buffer as assosiated data
     * 2. append decrypted payload to source buffer
     * 3. reset destination buffer
     */
    rte_memcpy(task_rsc->src_buffer, quic_init_hdr, params->aad_size);
    offset += params->aad_size;
    rte_memcpy(task_rsc->src_buffer + offset, decrypted_payload,
               decrypted_payload_len);
    offset += decrypted_payload_len;
    memset(task_rsc->src_buffer + offset, 0, padding_len);
    offset += padding_len;
    doca_buf_set_data(task_rsc->src_doca_buf, task_rsc->src_buffer, offset);
    doca_buf_reset_data_len(task_rsc->dst_doca_buf);

    DOCA_LOG_INFO("total size = %d", offset);

#ifdef DEBUG
    DOCA_LOG_INFO("Data to encrypt:\n%s", dump);
    free(dump);
    result = DOCA_ERROR_BAD_STATE;
    DOCA_LOG_INFO("free task");
    doca_task_free(task_rsc->task);
    DOCA_LOG_INFO("free key");
    doca_aes_gcm_key_destroy(task_rsc->key);
    return DOCA_ERROR_BAD_STATE;
#endif

    /* Submit and run the task */
    result = submit_aes_gcm_crypto_task(apcr, task_id);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("AES-GCM encrypt task failed of task %s [lcore=%d]: %s",
                     task_type_to_name[TASK_DECRYPT_PKT], task_rsc->lcore_rank,
                     doca_error_get_descr(result));
        return result;
    }

    /* Get the encrypt result */
    doca_buf_get_head(task_rsc->dst_doca_buf, (void **)&resp_head);
    doca_buf_get_data_len(task_rsc->dst_doca_buf, &data_len);
    *encrypted_payload = resp_head;

    DOCA_LOG_INFO("Encrypted data len = %lu", data_len);
    // char *dump = hex_dump(resp_head, data_len);
    // DOCA_LOG_INFO("Encrypted data:\n%s", dump);
    // free(dump);
    char *dump = hex_dump(resp_head + data_len - RETRY_INTEGRITY_TAG_SIZE,
                          RETRY_INTEGRITY_TAG_SIZE);
    DOCA_LOG_INFO("Tag: %s", dump);
    free(dump);

    // DOCA_LOG_INFO("Decrypted data len = %lu", decrypted_payload_len);
    // dump = hex_dump(decrypted_payload, decrypted_payload_len);
    // DOCA_LOG_INFO("Decrypted data:\n%s", dump);
    // free(dump);

    /* free key */
    doca_aes_gcm_key_destroy(task_rsc->key);

    return result;
}

/*
 * Decrypt QUIC Initial Packet Payload.
 *
 * @apcr [in]: pointer of application runtime resources
 * @quic_pkt_info [in]: client initial information
 *
 * @return: 0 on success and non-zero value on failure
 */
doca_error_t decrypt_quic_initial_payload(struct app_per_core_resources *apcr,
                                          struct crypto_task_params *params,
                                          uint8_t *quic_init_hdr,
                                          uint16_t total_len,
                                          uint8_t **decrypted_payload) {
    uint8_t *resp_head = NULL;
    size_t data_len = 0;
    doca_error_t result = DOCA_SUCCESS;
    union doca_data task_user_data = {0};
    struct crypto_task_resources *task_rsc = NULL;
    struct doca_aes_gcm_task_decrypt *decrypt_task = NULL;

    print_hex("Key", params->raw_key, RETRY_AEAD_KEY_LEN);
    print_hex("IV", params->iv, RETRY_AEAD_NONCE_LEN);
    DOCA_LOG_INFO("iv size = %d", params->iv_length);
    DOCA_LOG_INFO("tag size = %d", params->tag_size);
    DOCA_LOG_INFO("aad size = %d", params->aad_size);

    /* Register aes gcm key and decrypt task */
    task_rsc = apcr->task_rscs[TASK_DECRYPT_PKT];
    task_rsc->result.type = TASK_DECRYPT_PKT;
    task_rsc->result.result = DOCA_SUCCESS;
    task_rsc->result.status = CTASK_WAITING;
    task_user_data.ptr = &(task_rsc->result);

    /* Create AES GCM key */
    EXIT_ON_FAILURE(doca_aes_gcm_key_create(apcr->aes_gcm, params->raw_key,
                                            params->raw_key_type,
                                            &(task_rsc->key)));
    DOCA_LOG_INFO("TASK_DECRYPT_PKT key created (%p)", task_rsc->key);

    /* Register the doca task */
    EXIT_ON_FAILURE(doca_aes_gcm_task_decrypt_alloc_init(
        apcr->aes_gcm, task_rsc->src_doca_buf, task_rsc->dst_doca_buf,
        task_rsc->key, params->iv, params->iv_length, params->tag_size,
        params->aad_size, task_user_data, &decrypt_task));
    task_rsc->task = doca_aes_gcm_task_decrypt_as_task(decrypt_task);
    DOCA_LOG_INFO("TASK_DECRYPT_PKT task created (%p)", task_rsc->task);

    /*
     * Manipulate doca_buf before submit encrypt task
     *   1. set data address and length of source doca_buf
     *      1) copy quic header (aad) to source buffer\
     *      2) copy encrypted payload to source buffer/
     *      which is equal to copy the whole quic packet to buffer
     *   2. reset data length of destination doca_buf
     *      (see DOCA Core#Buffer-as-Destination for details)
     */

    DOCA_LOG_INFO("source buffer length = %d", total_len);
    memcpy(task_rsc->src_buffer, quic_init_hdr, total_len);
    doca_buf_set_data(task_rsc->src_doca_buf, task_rsc->src_buffer, total_len);
    doca_buf_reset_data_len(task_rsc->dst_doca_buf);

#ifdef DEBUG
    char *dump = hex_dump(task_rsc->src_buffer, total_len);
    if (dump == NULL) {
        DOCA_LOG_ERR("Failed to allocate memory for printing buffer content");
        result = DOCA_ERROR_NO_MEMORY;
    }
    DOCA_LOG_INFO("Data to decrypt:\n%s", dump);
    free(dump);
    result = DOCA_ERROR_BAD_STATE;
    DOCA_LOG_INFO("free task");
    doca_task_free(task_rsc->task);
    DOCA_LOG_INFO("free key");
    doca_aes_gcm_key_destroy(task_rsc->key);
    return DOCA_ERROR_BAD_STATE;
#endif

    /* Submit and run the task */
    result = submit_aes_gcm_crypto_task(apcr, TASK_DECRYPT_PKT);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("AES-GCM decrypt task failed of task %s [lcore=%d]: %s",
                     task_type_to_name[TASK_DECRYPT_PKT], task_rsc->lcore_rank,
                     doca_error_get_descr(result));
        return result;
    }

    /* Get the decrypt result */
    doca_buf_get_head(task_rsc->dst_doca_buf, (void **)&resp_head);
    doca_buf_get_data_len(task_rsc->dst_doca_buf, &data_len);
    *decrypted_payload = resp_head;
    DOCA_LOG_INFO("Decrypt data len is %lu", data_len);

    /* free key */
    doca_aes_gcm_key_destroy(task_rsc->key);

    return result;
}

/*
 * Clip token in QUIC INITIAL packet
 *
 * @mbuf [inout]: rte buffer
 * @pkt_hdrs [in]: struct packet_headers parsed
 * @info [in]: struct quic_pkt_info parsed
 * @return: 0 on success and 1/-1 otherwise
 */
doca_error_t clip_initial_token(struct rte_mbuf *mbuf,
                                struct app_per_core_resources *apcr,
                                struct packet_headers *pkt_hdrs,
                                struct quic_pkt_info *info) {
    struct rte_ipv4_hdr *ip_hdr = pkt_hdrs->ip_hdr;
    struct rte_udp_hdr *udp_hdr = pkt_hdrs->udp_hdr;
    uint8_t *quic_hdr = pkt_hdrs->quic_hdr;
    uint8_t *dcid = info->init_dcid;
    uint8_t dcil = info->init_dcid_len;
    uint8_t quic_hp[16];
    uint8_t hp_mask[5];
    uint8_t *sample;
    uint8_t *pn;
    uint8_t *remain_length_ptr;
    uint8_t *decrypt_payload;
    uint8_t *encrypt_payload;
    uint8_t first_byte = quic_hdr[0];
    uint8_t pnl_bits = 0;
    uint8_t varint_bytes = 0;
    uint8_t packet_number_length = 0;
    uint16_t encrpyt_payload_len = 0;
    uint64_t packet_number = 0;
    size_t remain_length = 0;
    struct crypto_task_params *params = NULL;

    params = CALLOC_WITH_TYPE(struct crypto_task_params);
    if (params == NULL) {
        DOCA_LOG_ERR("Failed to allocate memory for crypto task params");
        return DOCA_ERROR_NO_MEMORY;
    }

    /* RFC 9000 17.2.2
     * +-----------------------------------------+
     * | QUIC INITIAL Packet Format {            |
     * |   Header Form (1) = 1,                  +------+
     * |   Fixed Bit (1) = 1,                    |      |
     * |   Long Packet Type (2) = 0,             |  1B  | 1
     * |   Reserved Bits (2),                    |      |
     * |   Packet Number Length (2), [protected] +------+
     * |   Version (32),                         |  4B  | 4
     * |   Destination Connection ID Length (8), |  1B  | 1
     * |   Destination Connection ID (0..160),   |  ?B  | 8
     * |   Source Connection ID Length (8),      |  1B  | 1
     * |   Source Connection ID (0..160),        |  ?B  | 8
     * |   Token Length (i),                     | 1~4B | 1
     * |   Token (..),                           |  ?B  | 30
     * |   Length (i),                           | 1~4B | 2
     * |   Packet Number (8..32),    [protected] | 1~4B |
     * |   Packet Payload (..),      [Skip]      | 0~3B |
     * |   Packet Payload (..),      [Sample]    | 16B  |
     * |   Packet Payload (..),      [Remainder] |  ?B  |
     * | }                                       |      |
     * +-----------------------------------------+------+
     */

    remain_length_ptr = info->init_token + info->init_token_len;
    remain_length = parse_varint(remain_length_ptr, &varint_bytes);
    DOCA_LOG_INFO("Token offset = %ld", info->init_token - pkt_hdrs->quic_hdr);
    DOCA_LOG_INFO("QUIC payload length = %ld, bytes = %d", remain_length,
                  varint_bytes);

    /* get the pointer to `Packet Number` field */
    pn = remain_length_ptr + varint_bytes;
    /* get the pointer to AES-ECB `sample` field */
    sample = pn + 4;

    /*
     * Generate the secrets used in head protection and payload encryption,
     * and setup params for decrypt doca task.
     */
    EXIT_ON_FAILURE(quic_derive_initial_secrets(
        dcid, dcil, sample, params->raw_key, params->iv, quic_hp, hp_mask));

    /* decrypt packet number length in the low 2 bit of the flag field */
    pnl_bits = (first_byte ^ (hp_mask[0] & 0x0f)) & 0x03;
    quic_hdr[0] = (first_byte & 0xf0) | pnl_bits;
    DOCA_LOG_INFO("Flags: 0x%02x", quic_hdr[0]);
    packet_number_length = pnl_bits + 1;
    if (packet_number_length < 1 || packet_number_length > 4) {
        DOCA_LOG_ERR("Parsed packet number length should be in the range of "
                     "[1, 4], but got %d",
                     packet_number_length);
        return DOCA_ERROR_INVALID_VALUE;
    }

    /* decrypt packet number */
    for (int i = 0; i < packet_number_length; i++) {
        pn[i] ^= hp_mask[1 + i];
        packet_number = (packet_number << 8) | pn[i];
    }
    DOCA_LOG_INFO("Packet Number Length: %d", packet_number_length);
    DOCA_LOG_INFO("Packet Number: %lu", packet_number);

    /* expand pn to 12B with zero padding in big endian format */
    uint8_t expanded_pn[RETRY_AEAD_NONCE_LEN] = {0};
    for (int i = 0; i < 8; i++) {
        expanded_pn[11 - i] = (packet_number >> (8 * i)) & 0xFF;
    }

    /* xor expanded pn with iv to get the nonce of aes gcm algorithm */
    for (int i = 0; i < RETRY_AEAD_NONCE_LEN; i++) {
        params->iv[i] ^= expanded_pn[i];
    }

    /* encrypted payload length */
    encrpyt_payload_len =
        remain_length - packet_number_length; // include 16B tag

    /* decrypt payload using AES-GCM-128 algorithm */
    uint16_t total_len = pn - quic_hdr + remain_length;
    DOCA_LOG_INFO("total length = %d", total_len);
    params->raw_key_type = RETRY_AEAD_KEY_TYPE;
    params->iv_length = RETRY_AEAD_NONCE_LEN;
    params->tag_size = RETRY_INTEGRITY_TAG_SIZE;
    params->aad_size = pn - quic_hdr + packet_number_length;
    print_hex("DCID", info->init_dcid, info->init_dcid_len);
    EXIT_ON_FAILURE(decrypt_quic_initial_payload(apcr, params, quic_hdr,
                                                 pn - quic_hdr + remain_length,
                                                 &decrypt_payload));

    /*
     * Clip token diagram for offset computing
     * +------------+-----+------+--+-------+--------+
     * |token length|token|length|PN|payload|auth tag|
     * +------------+-----+------+--+-------+--------+
     * |      1     |  tl | l(i) |  length  |  16B   |
     * +------------^-----^------+----------+--------+
     *              |     |
     *              p     p+tl
     *                 ↓
     * +------------+------+--+-------+-----+--------+
     * |token length|length|PN|payload|  0  |auth tag|
     * +------------+------+--+-------+-----+--------+
     * |      1     | l(i) |  length  |  tl |  16B   |
     * +------------^------+----------^-----+--------+
     *              |                 |
     *              p                 p+length+l(i)
     *
     * valid_part_len = length + l(i)
     * info->init_token_len = tl
     */
    params->aad_size -= info->init_token_len;
    rte_memcpy(info->init_token, remain_length_ptr,
               varint_bytes + packet_number_length);

    /* set token length to zero */
    switch (info->init_token_bytelen) {
    case 1:
        *(info->init_token_len_ptr) = 0;
        break;
    case 2:
        *((uint16_t *)info->init_token_len_ptr) = rte_cpu_to_be_16(0x4000);
        break;
    case 3:
        *((uint32_t *)info->init_token_len_ptr) = rte_cpu_to_be_32(0x80000000);
        break;
    case 4:
        *((uint64_t *)info->init_token_len_ptr) =
            rte_cpu_to_be_64(0xc000000000000000);
        break;
    default:
        DOCA_LOG_ERR("Token length bytes wrong! got %d",
                     info->init_token_bytelen);
        break;
    }

    /* update remaining length */
    remain_length += info->init_token_len;
    remain_length_ptr = info->init_token;
    switch (varint_bytes) {
    case 1:
        *(remain_length_ptr) = remain_length & 0xff;
        break;
    case 2:
        *((uint16_t *)remain_length_ptr) =
            rte_cpu_to_be_16(remain_length | 0x4000);
        break;
    case 3:
        *((uint32_t *)remain_length_ptr) =
            rte_cpu_to_be_32(0x80000000 | remain_length);
        break;
    case 4:
        *((uint64_t *)remain_length_ptr) =
            rte_cpu_to_be_64(0xc000000000000000 | remain_length);
        break;
    default:
        DOCA_LOG_ERR("Remaining length bytes wrong! got %d",
                     info->init_token_bytelen);
        return DOCA_ERROR_INVALID_VALUE;
    }

    EXIT_ON_FAILURE(encrypt_quic_initial_payload(
        apcr, params, quic_hdr,
        decrypt_payload + params->aad_size + info->init_token_len,
        encrpyt_payload_len - RETRY_INTEGRITY_TAG_SIZE, info->init_token_len,
        &encrypt_payload));

    /* encrypt payload using AES-GCM-128 algorithm */
    encrpyt_payload_len += info->init_token_len;
    rte_memcpy(quic_hdr + params->aad_size, encrypt_payload + params->aad_size,
               encrpyt_payload_len);

    /* protect pn with a new header protection bytes with a new encrypted sample
     * part */
    pn = remain_length_ptr + varint_bytes;
    doca_error_t result =
        generate_aes_ecb_mask(quic_hp, RETRY_AEAD_KEY_LEN, pn + 4, hp_mask);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR(
            "Failed to use AES ECB to generate header protection mask");
        return result;
    }
    DOCA_LOG_INFO("pn offset = %ld", pn - quic_hdr);
    // protect packet number
    for (int i = 0; i < packet_number_length; i++) {
        pn[i] ^= hp_mask[1 + i];
    }
    // protect packet number length
    quic_hdr[0] = (first_byte & 0xf0) | (pnl_bits ^ (hp_mask[0] & 0x0f));

    // char *dump_pkt = hex_dump(quic_hdr, total_len);
    // DOCA_LOG_INFO("QUIC PKT:\n%s", dump_pkt);
    // free(dump_pkt);

    /* if got ACK frame, offload rules */

    /* update udp checksum */
    udp_hdr->dgram_cksum = 0;
    udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hdr);

    return DOCA_SUCCESS;
}

/*
 * Process received packets.
 *
 * @param process_pkts_params [in]: an argument containing the mapping
 * between queues and cores/lcores
 * @return 0 on success and non-zero value on failure
 *
 * @note:
 *    This function is a thread safe
 */
int retry_fwd_process_pkts(void *process_pkts_params) {
    uint16_t j, nb_rx, queue_id, nb_tx, nb_real_tx;
    uint32_t port_id = 0, core_id = rte_lcore_id(), dst_port = 0;
    struct rte_mbuf *rx_bufs[APP_RX_BURST_SIZE], *tx_bufs[APP_RX_BURST_SIZE];
    struct app_per_core_params *params = &core_params_arr[core_id];
    struct app_resources *resources =
        (struct app_resources *)process_pkts_params;
    doca_error_t result = DOCA_SUCCESS;
#ifdef PROFILE
    struct timespec start = {0}, end = {0};
    long duration_ns = 0;
#endif

    // if (core_id == rte_get_main_lcore()) {
    //     DOCA_LOG_INFO("Core %u is the main core", core_id);
    // }
    // if (!params->used) {
    //     DOCA_LOG_INFO("Core %u nothing need to do", core_id);
    //     return 0;
    // }
    if (params->used) {
        DOCA_LOG_INFO("lcore %u is working on physical core %d", core_id,
                      rte_lcore_to_cpu_id(core_id));
    } else {
        DOCA_LOG_INFO("lcore 0 is the main thread, nothing to do.");
        return 0;
    }

    /* Main loop */
    while (!force_quit) {
        for (port_id = 0; port_id < NUM_OF_DPDK_PORTS; port_id++) {
            queue_id = params->queues[port_id];
            nb_tx = 0;
            nb_real_tx = 0;
            nb_rx =
                rte_eth_rx_burst(port_id, queue_id, rx_bufs, APP_RX_BURST_SIZE);
#ifdef DEBUG
            if (nb_rx > 0)
                DOCA_LOG_DBG("[core %u] %u packets received", core_id, nb_rx);
#endif

#ifdef PROFILE
            clock_gettime(CLOCK_MONOTONIC, &start);
#endif
            for (j = 0; j < nb_rx; j++) {
                DOCA_LOG_DBG("[core %u | Port %d] packet address = %p", port_id,
                             core_id, rx_bufs[j]);
                result = process_quic_packets(
                    rx_bufs[j], resources->apcrs[core_id], &dst_port);
                if (result == DOCA_SUCCESS) {
                    tx_bufs[nb_tx++] = rx_bufs[j];
                }
            }

            if (nb_tx > 0) {
#ifdef PROFILE
                clock_gettime(CLOCK_MONOTONIC, &end);
                duration_ns = (end.tv_sec - start.tv_sec) * 1e9 +
                              (end.tv_nsec - start.tv_nsec);
                stats[core_id].latency += duration_ns / 1e3;
                DOCA_LOG_DBG(
                    "[core=%02d] Retry process took %.3f us on average",
                    core_id, (duration_ns / 1e3) / nb_rx);
#endif
                stats[core_id].rx_pkts += nb_tx;
                nb_real_tx =
                    rte_eth_tx_burst(port_id, queue_id, tx_bufs, nb_tx);
                DOCA_LOG_DBG("[core=%02d | port=%d] packets sent (%u/%u)",
                             core_id, port_id, nb_tx, nb_rx);
                stats[core_id].tx_pkts += nb_real_tx;
            }
        }
    }

    return 0;
}

/*
 * Handle received traffic and check the pkt_meta value added by internal
 * pipe.
 *
 * @port_id [in]: proxy port id
 * @nb_queues [in]: number of queues the sample has
 */
int handle_rx_tx_pkts(void *process_pkts_params) {
    int rc;
    uint16_t i;
    uint16_t nb_rx;
    uint16_t nb_tx;
    uint16_t nb_real_tx;
    uint16_t queue_id;
    uint32_t port_id;
    uint32_t core_id;
    uint32_t dst_port;
    // uint32_t sw_packet_type;
    doca_error_t result;
    struct rte_mbuf *rx_bufs[APP_RX_BURST_SIZE];
    struct rte_mbuf *tx_bufs[APP_RX_BURST_SIZE];
    struct app_per_core_params *params;
    struct app_resources *resources;
#ifdef TOP_PROFILE
    struct timespec start = {0}, end = {0};
    long duration_ns = 0;
    long cur_duration_ns = 0;
#endif

    /* Initialize thread resources */
    core_id = rte_lcore_id();
    port_id = 0; // physical port `p0`
    params = &core_params_arr[core_id];
    queue_id = params->queues[port_id];
    resources = (struct app_resources *)process_pkts_params;

    /* Skip main thread */
    if (!params->used) {
        DOCA_LOG_INFO("Thread 0 is the main thread, nothing to do.");
        return 0;
    }
    DOCA_LOG_INFO("Thread %d manages queue [%d] on physical core %d", core_id,
                  queue_id, rte_lcore_to_cpu_id(core_id));

    /* Register metadata */
    rc = rte_flow_dynf_metadata_register();
    if (unlikely(rc)) {
        DOCA_LOG_ERR("Enable metadata failed");
        return -1;
    }

    /* Main process loop */
    while (!force_quit) {
        // sleep(1);
        nb_tx = 0;
        nb_rx = rte_eth_rx_burst(port_id, queue_id, rx_bufs, APP_RX_BURST_SIZE);

        for (i = 0; i < nb_rx; i++) {
            DOCA_LOG_DBG("[core %02d] packet address = %p", core_id,
                         rx_bufs[i]);
            dst_port = 1;
#ifdef TOP_PROFILE
            clock_gettime(CLOCK_MONOTONIC, &start);
#endif
            result = process_quic_packets(rx_bufs[i], resources->apcrs[core_id],
                                          &dst_port);
            if (result == DOCA_SUCCESS) {
                /* Set dst port in metadata field for hardware process */
                DOCA_LOG_INFO("Packet will be steered to port %d", dst_port);
                rte_flow_dynf_metadata_set(rx_bufs[i], dst_port);
                rx_bufs[i]->ol_flags |= RTE_MBUF_DYNFLAG_TX_METADATA;
                tx_bufs[nb_tx++] = rx_bufs[i];
            }
#ifdef TOP_PROFILE
            clock_gettime(CLOCK_MONOTONIC, &end);
            cur_duration_ns = (end.tv_sec - start.tv_sec) * 1e9 +
                              (end.tv_nsec - start.tv_nsec);
            duration_ns += cur_duration_ns;
            // stats[core_id].latency += duration_ns / 1e3;
            DOCA_LOG_WARN("[core=%02d] Retry process took %.3f us", core_id,
                          cur_duration_ns / 1e3);
#endif
        }
        if (nb_tx > 0) {
#ifdef TOP_PROFILE
            stats[core_id].latency += duration_ns / 1e3;
            DOCA_LOG_WARN(
                "[core=%02d] Retry process took %.3f us on average of %d "
                "packets",
                core_id, (duration_ns / 1e3) / nb_rx, nb_rx);
            duration_ns = 0;
#endif
            // stats[core_id].rx_pkts += nb_tx;
            nb_real_tx = rte_eth_tx_burst(port_id, queue_id, tx_bufs, nb_tx);
            DOCA_LOG_INFO("[core=%02d] packets sent (%u/%u)", core_id,
                          nb_real_tx, nb_rx);
            // stats[core_id].tx_pkts += nb_real_tx;
            // rte_pktmbuf_free_bulk(rx_bufs, nb_rx);
        }
    }

    return 0;
}

// sw_packet_type =
// rte_net_get_ptype(rx_bufs[i], NULL, RTE_PTYPE_ALL_MASK);
// if (mbufs[i]->ol_flags & RTE_MBUF_F_RX_FDIR_ID) {
// if (sw_packet_type & RTE_PTYPE_L4_UDP) {
//     DOCA_LOG_INFO("RSS packet is UDP");
// } else {
//     DOCA_LOG_INFO("RSS packet is others, %d", sw_packet_type);
// }
// dst_port = 1;
// DOCA_LOG_INFO("The pkt meta = 0x%x, dst_port = %d",
//               mbufs[i]->hash.fdir.hi, dst_port);
// rte_flow_dynf_metadata_set(mbufs[i], dst_port);
// mbufs[i]->ol_flags |= RTE_MBUF_DYNFLAG_TX_METADATA;
// } else {
// DOCA_LOG_INFO("Pkt without metadata");
// }