#ifndef RETRY_FWD_CORE_H_
#define RETRY_FWD_CORE_H_

#include "aes_gcm_common.h"
#include "common.h"
#include "quic.h"

#define NUM_OF_DPDK_PORTS 1

/* Statistics */
struct retry_fwd_statistics {
    uint64_t rx_pkts;
    uint64_t tx_pkts;
    double latency; /* latency unit: ms*/
};

/* Retry forward application configuration */
struct retry_fwd_config {
    uint32_t nb_lcores;
};

/* Retry forward parameters to be passed when starting processing packets */
struct retry_fwd_process_pkts_params {
    struct app_resources *resources;
};

/*
 * Print the statistics of the program.
 */
void retry_fwd_show_stats(uint32_t nb_cores);

/*
 * Parse quic packet and generate forward packet.
 *
 * @param mbuf [in]: dpdk packet buf
 * @param apcr [in]: program resources per core
 * @param dst_port [out]: port to send the packet
 * @return 0 on success and non-zero value on failure
 */
doca_error_t process_quic_packets(struct rte_mbuf *mbuf,
                                  struct app_per_core_resources *apcr,
                                  uint32_t *dst_port);

/*
 * Encode retry token.
 *
 * @retry_fwd_runtime [in]: pointer of application runtime resources
 * @quic_pkt_info [in]: client initial information
 * @quic_retry_pkt_info [out]: retry information (modify token related field)
 *
 * @return: 0 on success and non-zero value on failure
 */
doca_error_t encode_retry_token(struct app_per_core_resources *apcr,
                                struct quic_pkt_info *info);

/*
 * Decode retry token.
 *
 * @retry_fwd_runtime [in]: pointer of application runtime resources
 * @quic_pkt_info [in]: client initial information
 *
 * @return: 0 on success and non-zero value on failure
 */
doca_error_t decode_retry_token(struct app_per_core_resources *apcr,
                                struct quic_pkt_info *info);

/*
 * Compute retry integrity tag.
 *
 * @retry_fwd_runtime [in]: pointer of application runtime resources
 * @pseudo_retry_pkt [in]: the buffer of pseudo retry packet
 * @pseudo_retry_len [in]: the length of pseudo retry packet
 * @quic_retry_pkt_info [out]: retry information (modify tag field)
 *
 * @return: 0 on success and non-zero value on failure
 */
doca_error_t compute_integrity_tag(struct app_per_core_resources *apcr,
                                   size_t pseudo_retry_len,
                                   struct quic_pkt_info *info);

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
                                          uint8_t **encrypted_payload);

/*
 * Decrypt QUIC Initial Packet Payload.
 *
 * @retry_fwd_runtime [in]: pointer of application runtime resources
 * @quic_pkt_info [in]: client initial information
 *
 * @return: 0 on success and non-zero value on failure
 */
doca_error_t decrypt_quic_initial_payload(struct app_per_core_resources *apcr,
                                          struct crypto_task_params *params,
                                          uint8_t *quic_init_hdr,
                                          uint16_t total_len,
                                          uint8_t **decrypted_payload);

/*
 * Build real retry packet.
 *
 * @mbuf [inout]: rte buffer
 * @pkt_hdrs [in]: struct packet_headers parsed
 * @info [in]: struct quic_pkt_info parsed
 * @return: 0 on success and 1/-1 otherwise
 */
doca_error_t clip_initial_token(struct rte_mbuf *mbuf,
                                struct app_per_core_resources *apcr,
                                struct packet_headers *pkt_hdrs,
                                struct quic_pkt_info *info);

/*
 * Process received packets.
 *
 * @process_pkts_params [in]: an argument containing the mapping  between
 * queues and cores/lcores
 * @return: 0 on success and non-zero value on failure
 *
 * @NOTE: This function is a thread safe
 */
int retry_fwd_process_pkts(void *process_pkts_params);

/*
 * @brief map queues to port and logic cores.
 *
 * @param nb_queues the number of queues
 * @param nb_ports the number of ports
 */
void retry_fwd_map_queue(uint16_t nb_queues, int nb_ports);

int handle_rx_tx_pkts(void *process_pkts_params);

void app_quit(void);
void signal_handler(int signum);

#endif