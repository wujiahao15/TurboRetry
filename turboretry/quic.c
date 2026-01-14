#include <doca_log.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_memcpy.h>
#include <rte_udp.h>

#include "quic.h"
#include "utils.h"

DOCA_LOG_REGISTER(RETRY_BASELINE::QUIC);

/*
 * Retry AEAD related definitions
 *   AEAD_AES_GCM_128(
 *      NONCE (96 bit => 12 B) 0x461599d35d632bf2239825bb
 *       KEY (128 bit => 16 B) 0xbe0c690b9f66575a1d766b54e368c84e
 *   )
 * Above input parameters are fixed values according to RFC9001-5.8
 */
const uint8_t retry_aead_nonce[] = {0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63,
                                    0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};

const uint8_t retry_aead_key[] = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66,
                                  0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54,
                                  0xe3, 0x68, 0xc8, 0x4e};

/* Test version temporary constant values. */
uint8_t test_sid[] = {0xa0, 0xf7, 0x3b, 0xe6, 0xc8, 0x43, 0x3d, 0x8};
uint8_t retry_token[] = {0x0,  0x7d, 0xa9, 0x28, 0x94, 0x10, 0x98, 0x3c, 0xc3,
                         0x7c, 0xd0, 0xaa, 0x5b, 0x1f, 0x15, 0xd,  0x3c, 0x23,
                         0xba, 0x85, 0x66, 0x47, 0xfc, 0xae, 0xc,  0xd3, 0xbc,
                         0xe9, 0xba, 0x44, 0x81, 0x1d, 0x31, 0x9a, 0x82, 0x89,
                         0x81, 0x91, 0x2f, 0xf8, 0x9c, 0xd4, 0x73, 0xb8, 0x6,
                         0x50, 0xe4, 0x98, 0x3e, 0x1f, 0x25, 0x55};

/* Header protection related definitions */
#define INITIAL_SECRET_LEN 32
static const EVP_MD *hash_algo_md = NULL;
static const uint8_t initial_salt[] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                       0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                       0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
static const uint8_t token_initial_salt[] = {
    0x1d, 0x76, 0xcd, 0x55, 0x94, 0x68, 0x26, 0xb6, 0xdb, 0x10,
    0x67, 0xf9, 0x0d, 0xe5, 0x3e, 0x37, 0xb1, 0xbd, 0xc9, 0x8b};

void init_openssl() { hash_algo_md = EVP_sha256(); }

/* Print connection id of source and destination for debug. */
void print_connection_id(struct quic_pkt_info *info) {
    print_n_hex_bytes(info->init_dcid, info->init_dcid_len,
                      "Origin Destination Connection ID");
    print_n_hex_bytes(info->init_scid, info->init_scid_len,
                      "Origin Source Connection ID");
}

void print_hex(const char *label, const unsigned char *data, size_t len) {
    char buf[256] = {0};
    sprintf(buf, "0x");
    for (size_t i = 0; i < len; i++) {
        sprintf(buf + 2 + i * 2, "%02x", data[i]);
    }
    DOCA_LOG_INFO("%s: %s", label, buf);
}

/*
 * Parse packet headers of ethernet, ip, udp and quic header.
 *
 * @mbuf [inout]: rte buffer
 * @hdrs [out]: packet header information
 * @return: 0 on success and 1/-1 otherwise
 */
doca_error_t parse_packet_headers(struct rte_mbuf *mbuf,
                                  struct packet_headers *hdrs) {
    /* find ethernet header */
    hdrs->eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

    /*
      In current version, we only process udp packet.
      Thus, we will drop all other packets.
     */
    if (rte_be_to_cpu_16(hdrs->eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
        DOCA_LOG_DBG("Not a ipv4 packet, ignore");
        return DOCA_ERROR_INVALID_VALUE;
    }

    /* find ipv4 header */
    hdrs->ip_hdr = (struct rte_ipv4_hdr *)(hdrs->eth_hdr + 1);
    if (hdrs->ip_hdr->next_proto_id != IPPROTO_UDP) {
        DOCA_LOG_DBG("Not a udp packet, ignore");
        return DOCA_ERROR_INVALID_VALUE;
    }

    /* find udp hdr */
    hdrs->udp_hdr = (struct rte_udp_hdr *)(hdrs->ip_hdr + 1);
    hdrs->udp_payload_len =
        rte_be_to_cpu_16(hdrs->udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);

    /*
     * Check data length,
     * ensure it is longer than the minimum required value
     * of QUIC INITIAL packet.
     */
    if (hdrs->udp_payload_len < 2) {
        DOCA_LOG_ERR("Quic packet shorter than expected");
        return DOCA_ERROR_INVALID_VALUE;
    }

    /* find udp payload ==> QUIC header */
    hdrs->quic_hdr = (uint8_t *)(hdrs->udp_hdr + 1);

    return DOCA_SUCCESS;
}

/*
 * Parse quic initial packet header.
 *
 * @data [in]: udp payload start address
 * @len [in]: udp payload length
 * @info [out]: quic header information
 * @return: 0 on success and 1/-1 otherwise
 */
doca_error_t quic_parse_initial_pkt_hdr(uint8_t *data, uint16_t len,
                                        struct quic_pkt_info *info) {
    uint8_t flags = 0, varint_bytes = 0, dcil = 0, scil = 0;
    uint16_t offset = 0;
    uint32_t version = 0;
    size_t token_len = 0;

    /* parse first byte of quic */
    offset = 0;
    flags = *(data + offset);
    offset += 1;

    /*
     * parse quic header
     * we ignore short packet in current version
     */
    // switch (QUIC_PACKET_TYPE(flags)) {
    // case QUIC_SHORT_PACKET:
    //     // current, we ignore short packet
    //     DOCA_LOG_DBG("Currently, we ignore quic short packet");
    //     result = DOCA_ERROR_NOT_SUPPORTED;
    //     // return DOCA_ERROR_NOT_SUPPORTED;
    //     goto exit_with_code;
    //     // break;
    // case QUIC_LONG_PACKET:
    //     DOCA_LOG_DBG("Get a quic long packet");
    //     break;
    // default:
    //     DOCA_LOG_DBG("Not a quic packet");
    //     // return DOCA_ERROR_INVALID_VALUE;
    //     result = DOCA_ERROR_INVALID_VALUE;
    //     goto exit_with_code;
    // }
    /*
     * parse long packet type
     * we only process initial packet in current version
     */
    // switch (QUIC_LONG_PKT_TYPE(flags)) {
    // case QUIC_INITIAL:
    //     DOCA_LOG_DBG("Get a quic initial packet");
    //     break;
    // case QUIC_ZERORTT:
    // case QUIC_HANDSHAKE:
    // case QUIC_RETRY:
    //     DOCA_LOG_DBG("Get other long packet, ignore it currently");
    //     // return DOCA_ERROR_NOT_SUPPORTED;
    //     result = DOCA_ERROR_NOT_SUPPORTED;
    //     goto exit_with_code;
    // }
    /* Simplify process logic for QUIC INITIAL ONLY */
    if (!IS_QUIC_INITIAL_PACKET(flags)) {
        DOCA_LOG_DBG("Not QUIC INITIAL packet, ignore it");
        // uint8_t ptype = QUIC_PACKET_TYPE(flags);
        // uint8_t ltype = QUIC_LONG_PKT_TYPE(flags);
        // if (ptype == 1) {
        //     DOCA_LOG_ERR("1-RTT !");
        // } else if (ptype == 3) {
        //     switch (ltype) {
        //     case QUIC_ZERORTT:
        //         DOCA_LOG_ERR("0-RTT !");
        //         break;
        //     case QUIC_HANDSHAKE:
        //         DOCA_LOG_ERR("Handshake !");
        //         break;
        //     case QUIC_RETRY:
        //         DOCA_LOG_ERR("Retry !");
        //         break;
        //     }
        // } else {
        //     DOCA_LOG_ERR("Unknown packet type!");
        // }
        return DOCA_ERROR_IN_PROGRESS;
    }

    /* ensure the version is QUIC_VERSION */
    version = rte_be_to_cpu_32(*(uint32_t *)(data + offset));
    offset += 4;
    if (version != QUIC_VERSION) {
        DOCA_LOG_DBG("Quic version is not %08d, got %08d", QUIC_VERSION,
                     version);
        return DOCA_ERROR_INVALID_VALUE;
    }

    /*
     * Parse connection id information
     *   1. destination connection id length
     *   2. destination connection id
     *   3. source connection id length
     *   4. source connection id
     */
    // destination connection id length
#ifdef CHECK
    if (offset + CID_LENGTH_LEN > len) {
        DOCA_LOG_DBG("Dcidl > udp payload.");
        return DOCA_ERROR_INVALID_VALUE;
    }
#endif
    dcil = data[offset];
    info->init_dcid_len = dcil;
    offset += CID_LENGTH_LEN;

    // destination connection id
#ifdef CHECK
    if (offset + dcil > len) {
        DOCA_LOG_DBG("Dcid exceeds payload range.");
        return DOCA_ERROR_INVALID_VALUE;
    }
#endif
    info->init_dcid = data + offset;
    offset += dcil;

    // source connection id length
#ifdef CHECK
    if (offset + CID_LENGTH_LEN > len) {
        DOCA_LOG_DBG("Scidl > udp payload.");
        return DOCA_ERROR_INVALID_VALUE;
    }
#endif
    scil = data[offset];
    info->init_scid_len = scil;
    offset += 1;

    // source connection id
#ifdef CHECK
    if (offset + scil > len) {
        DOCA_LOG_DBG("Scid exceeds payload range.");
        return DOCA_ERROR_INVALID_VALUE;
    }
#endif
    info->init_scid = data + offset;
    offset += scil;

#ifdef DEBUG
    print_connection_id(info);
#endif

    /* Parse the token length and the token */
    info->init_token_len_ptr = data + offset;
    token_len = parse_varint(info->init_token_len_ptr, &varint_bytes);
    info->init_token_bytelen = varint_bytes;
    info->init_token_len = token_len;
    info->init_token = NULL;

    if (token_len == 0) {
        DOCA_LOG_DBG("Initial packet without token");
        return DOCA_SUCCESS;
    }

    // omit packet with invalid token size
    uint8_t odcidl = *(info->init_token_len_ptr + varint_bytes) & 0x7f;
    if (token_len != QUIC_RETRY_TOKEN_LEN(odcidl)) {
        DOCA_LOG_ERR("Token length is wrong, got %lu, expected %u", token_len,
                     QUIC_RETRY_TOKEN_LEN(odcidl));
        return DOCA_ERROR_INVALID_VALUE;
    }

    // check packet length
#ifdef CHECK
    if (offset + varint_bytes + token_len > len) {
        DOCA_LOG_ERR("Token exceeds payload range.");
        return DOCA_ERROR_INVALID_VALUE;
    }
#endif

    // get the token address within INITIAL PACKET
    offset += varint_bytes;
    info->init_token = data + offset;

#ifdef DEBUG
    print_n_hex_bytes(info->init_token, info->init_token_len,
                      "Initial packet with token");
#endif

    return DOCA_SUCCESS;
}

/*
 * Build retry pseudo packet.
 *
 * @info [in]: struct quic_initial_pkt_info parsed
 * @out_data [out]: pointer to pseudo retry packet
 * @out_len [out]: pseudo retry packet length
 * @return: 0 on success and 1/-1 otherwise
 */
doca_error_t quic_build_pseudo_retry_packet(struct quic_pkt_info *info,
                                            uint8_t *pseudo_rty_pkt,
                                            size_t *out_len) {
    uint8_t *out_buffer = pseudo_rty_pkt;

    /*
     * Build pseudo retry packet to get retry auth tag
     *
     * Retry Pseudo-Packet Format {
     *   ODCID Length (8),
     *   Original Destination Connection ID (0..160),
     *   Header Form (1) = 1,       |
     *   Fixed Bit (1) = 1,         | 1
     *   Long Packet Type (2) = 3,  | B
     *   Unused (4),                |
     *   Version (32),
     *   DCID Len (8),
     *   Destination Connection ID (0..160),
     *   SCID Len (8),
     *   Source Connection ID (0..160),
     *   Retry Token (..),
     * }
     */

#ifdef DEBUG
    print_connection_id(info);
#endif

    /*
     * Dynamically calculate pseudo packet length,
     * as connection id length is variable.
     */
    *out_len = RETRY_PSEUDO_PKT_LEN(info->init_dcid_len, info->init_scid_len);

    // Origin Destination Connection ID length
    *out_buffer = info->init_dcid_len;
    out_buffer += CID_LENGTH_LEN;

    // Origin Destination Connection ID
    memcpy(out_buffer, info->init_dcid, info->init_dcid_len);
    out_buffer += info->init_dcid_len;

    // Flags
    *out_buffer = QUIC_RETRY_PKT_FLAG;
    out_buffer += FLAG_LEN;

    // Version
    *((uint32_t *)(out_buffer)) = rte_cpu_to_be_32(QUIC_VERSION);
    out_buffer += QUIC_VERSION_LEN;

    // Destination Connection ID length <==> Origin source connection id length
    *out_buffer = info->init_scid_len;
    out_buffer += CID_LENGTH_LEN;

    // Destination Connection ID <==> Origin source connection id
    memcpy(out_buffer, info->init_scid, info->init_scid_len);
    out_buffer += info->init_scid_len;

    // Source Connection ID length
    *out_buffer = QUIC_CONNECTION_ID_LEN;
    out_buffer += CID_LENGTH_LEN;

    // Source Connection ID (now we set it random for fast development)
    // FIXME: maybe scid should generate using hmac to avoid duplication
    EXIT_ON_FAILURE(generate_random_bytes(out_buffer, QUIC_CONNECTION_ID_LEN));

    // rte_memcpy(out_buffer, info->init_dcid, info->init_dcid_len);
    // info->rty_scid_len = info->init_dcid_len;

    info->rty_scid_len = QUIC_CONNECTION_ID_LEN;
    info->rty_scid = out_buffer;

    // Setting token has been moved to function:
    //    `retry_fwd_core::encode_retry_token`.

    return DOCA_SUCCESS;
}

/*
 * Build real retry packet.
 *
 * @mbuf [inout]: rte buffer
 * @pkt_hdrs [in]: struct packet_headers parsed
 * @info [in]: struct quic_pkt_info parsed
 * @return: 0 on success and 1/-1 otherwise
 */
doca_error_t quic_build_real_retry_packet(struct rte_mbuf *mbuf,
                                          struct packet_headers *pkt_hdrs,
                                          struct quic_pkt_info *info) {
    uint16_t offset = 0, ip_total_len = 0, udp_len = 0, tmp_port = 0;
    uint32_t tmp_ip = 0;

    // header info from struct packet_headers
    uint8_t *quic_hdr = pkt_hdrs->quic_hdr;
    uint16_t payload_len = pkt_hdrs->udp_payload_len;
    struct rte_ether_addr tmp_ether_addr = {0};
    struct rte_ether_hdr *eth_hdr = pkt_hdrs->eth_hdr;
    struct rte_ipv4_hdr *ip_hdr = pkt_hdrs->ip_hdr;
    struct rte_udp_hdr *udp_hdr = pkt_hdrs->udp_hdr;

    /*
     * fill in quic retry packet first.
     *   +-----------------------------------------+
     *   | Retry Packet Format {                   |
     *   |   Header Form (1) = 1,                  |
     *   |   Fixed Bit (1) = 1,                    |
     *   |   Long Packet Type (2) = 3,             |
     *   |   Unused (4),                           |
     *   |   Version (32),                         |
     *   |   Destination Connection ID Length (8), |
     *   |   Destination Connection ID (0..160),   |
     *   |   Source Connection ID Length (8),      |
     *   |   Source Connection ID (0..160),        |
     *   |   Retry Token (..),                     |
     *   |   Retry Integrity Tag (128),            |
     *   | }                                       |
     *   +-----------------------------------------+
     */
    // flags
    *((uint8_t *)quic_hdr) = QUIC_RETRY_PKT_FLAG;
    offset += 1;

    // version
    *((uint32_t *)(quic_hdr + offset)) = rte_cpu_to_be_32(QUIC_VERSION);
    offset += 4;

    // destination connection id length (initial packet scid length)
    *((uint8_t *)(quic_hdr + offset)) = info->init_scid_len;
    offset += 1;

    // destination connection id (initial packet scid)
    rte_memcpy(quic_hdr + offset, info->init_scid, info->init_scid_len);
    offset += info->init_scid_len;

    // source connection id length
    *((uint8_t *)(quic_hdr + offset)) = info->rty_scid_len;
    offset += 1;

    // source connection id
    rte_memcpy(quic_hdr + offset, info->rty_scid, info->rty_scid_len);
    offset += info->rty_scid_len;

    // retry token
    rte_memcpy(quic_hdr + offset, info->rty_token, info->rty_token_len);
    offset += info->rty_token_len;

    // retry integrity tag (128 bit = 16 B)
    rte_memcpy(quic_hdr + offset, info->rty_auth_tag, RETRY_INTEGRITY_TAG_SIZE);
    offset += RETRY_INTEGRITY_TAG_SIZE;

    /* swap ethernet smac and dmac */
    tmp_ether_addr = eth_hdr->src_addr;
    rte_ether_addr_copy(&tmp_ether_addr, &eth_hdr->src_addr);
    rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
    rte_ether_addr_copy(&eth_hdr->dst_addr, &tmp_ether_addr);

    /* swap ipv4 sip and dip */
    tmp_ip = ip_hdr->src_addr;
    ip_hdr->src_addr = ip_hdr->dst_addr;
    ip_hdr->dst_addr = tmp_ip;
    ip_total_len =
        sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + offset;
    ip_hdr->total_length = rte_cpu_to_be_16(ip_total_len);
    /* update ipv4 checksum */
    ip_hdr->hdr_checksum = 0;
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

    /* update udp header part
     *  1. swap destination and source port
     *  2. udp length (udp header + payload)
     *  3. update udp checksum (pseudo ip hdr + udp hdr)
     */
    tmp_port = udp_hdr->src_port;
    udp_hdr->src_port = udp_hdr->dst_port;
    udp_hdr->dst_port = tmp_port;
    udp_len = sizeof(struct rte_udp_hdr) + offset;
    udp_hdr->dgram_len = rte_cpu_to_be_16(udp_len);
    udp_hdr->dgram_cksum = 0;
    udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hdr);

    /* update rte_mbuf information */
    mbuf->l4_len = udp_len;
    mbuf->pkt_len = mbuf->l2_len + mbuf->l3_len + mbuf->l4_len;
    rte_pktmbuf_trim(mbuf, payload_len - offset);

    return DOCA_SUCCESS;
}

doca_error_t hkdf_extract(const EVP_MD *md, const unsigned char *salt,
                          size_t salt_len, const unsigned char *ikm,
                          size_t ikm_len, unsigned char *prk) {
    if (!md) {
        return DOCA_ERROR_INVALID_VALUE;
    }

    unsigned int len = 0;
    if (HMAC(md, salt, salt_len, ikm, ikm_len, prk, &len) == NULL) {
        return DOCA_ERROR_INVALID_VALUE;
    }

    return DOCA_SUCCESS;
}

doca_error_t hkdf_expand_label(const EVP_MD *md, const unsigned char *secret,
                               size_t secret_len, const char *label,
                               const unsigned char *context, size_t context_len,
                               unsigned char *out, size_t out_len) {
    const char *tls13_prefix = "tls13 ";
    size_t label_len = strlen(label);
    size_t full_label_len = strlen(tls13_prefix) + label_len;

    if (full_label_len > 255 || context_len > 255 || out_len > 65535) {
        DOCA_LOG_ERR("Label, context, or length too long");
        return DOCA_ERROR_INVALID_VALUE;
    }

    // build HkdfLabel
    unsigned char info[512];
    size_t info_len = 0;

    // uint16 length (Big endian order)
    info[info_len++] = (out_len >> 8) & 0xff;
    info[info_len++] = out_len & 0xff;

    // opaque label<7..255> = "tls13 " + label
    info[info_len++] = (unsigned char)full_label_len;
    memcpy(info + info_len, tls13_prefix, strlen(tls13_prefix));
    info_len += strlen(tls13_prefix);
    memcpy(info + info_len, label, label_len);
    info_len += label_len;

    // opaque context<0..255>, context is set to null in RFC 9001
    info[info_len++] = (unsigned char)context_len;
    if (context_len > 0) {
        memcpy(info + info_len, context, context_len);
        info_len += context_len;
    }

#ifdef DEBUG
    // print label to debug
    printf("HkdfLabel: ");
    for (size_t i = 0; i < info_len; i++) {
        printf("%02x", info[i]);
    }
    printf("\n");
#endif

    unsigned char T[EVP_MAX_MD_SIZE] = {0};
    unsigned char *T_ptr = T;
    size_t T_len = 0;
    size_t remaining = out_len;
    unsigned char counter = 1;
    unsigned char hmac_input[512];
    size_t hmac_input_len = 0;
    unsigned int hmac_len = 0;
    size_t copy_len = 0;

    while (remaining > 0) {
        hmac_input_len = 0;

        // T(i) = HMAC(PRK, T(i-1) + info + counter)
        if (T_len > 0) {
            memcpy(hmac_input, T_ptr, T_len);
            hmac_input_len += T_len;
        }

        memcpy(hmac_input + hmac_input_len, info, info_len);
        hmac_input_len += info_len;

        hmac_input[hmac_input_len++] = counter;

        hmac_len = 0;
        if (!HMAC(md, secret, secret_len, hmac_input, hmac_input_len, T,
                  &hmac_len)) {
            DOCA_LOG_ERR("HMAC failed");
            return DOCA_ERROR_INVALID_VALUE;
        }

        copy_len = (remaining > hmac_len) ? hmac_len : remaining;
        memcpy(out + (out_len - remaining), T, copy_len);
        remaining -= copy_len;
        T_ptr = T;
        T_len = hmac_len;
        counter++;
    }

    return DOCA_SUCCESS;
}

doca_error_t generate_aes_ecb_mask(const unsigned char *key, size_t key_len,
                                   const unsigned char *plaintext,
                                   unsigned char *mask) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        DOCA_LOG_ERR("Failed to create openssl cipher context");
        return DOCA_ERROR_INITIALIZATION;
    }

    // Choose cipher according to key length
    const EVP_CIPHER *cipher = NULL;
    if (key_len == 16) {
        cipher = EVP_aes_128_ecb();
    } else if (key_len == 24) {
        cipher = EVP_aes_192_ecb();
    } else if (key_len == 32) {
        cipher = EVP_aes_256_ecb();
    } else {
        DOCA_LOG_ERR("Invalid AES key length: %zu (should be 16, 24, or 32)",
                     key_len);
        EVP_CIPHER_CTX_free(ctx);
        return DOCA_ERROR_INVALID_VALUE;
    }

    // initialize encrypt context
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        DOCA_LOG_ERR("Failed to initialize encrypt context");
        return DOCA_ERROR_INITIALIZATION;
    }

    // no padding (ECB need plaintext length to be divised by block size)
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    unsigned char ciphertext[QUIC_HP_SAMPLE_SIZE];
    int out_len = 0;

    // encrypt
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext,
                               QUIC_HP_SAMPLE_SIZE)) {
        EVP_CIPHER_CTX_free(ctx);
        DOCA_LOG_ERR("Failed to do encryption");
        return DOCA_ERROR_DRIVER;
    }

    // take the first 5 bytes as mask
    memcpy(mask, ciphertext, 5);

    EVP_CIPHER_CTX_free(ctx);
    return DOCA_SUCCESS;
}

doca_error_t quic_derive_initial_secrets(const unsigned char *dcid, size_t dcil,
                                         const unsigned char *sample,
                                         unsigned char *quic_key,
                                         unsigned char *quic_iv,
                                         unsigned char *quic_hp,
                                         unsigned char *hp_mask) {
    uint8_t initial_secret[EVP_MAX_MD_SIZE];
    uint8_t client_initial_secret[32];
    int initial_secret_len = INITIAL_SECRET_LEN;
    doca_error_t result = DOCA_SUCCESS;

#ifdef DEBUG
    print_hex("Salt", initial_salt, sizeof(initial_salt));
    print_hex("DCID", dcid, dcil);
    printf("initial secret length = %d", initial_secret_len);
#endif

    // Use hkdf-extract to derive initial secret
    result = hkdf_extract(hash_algo_md, initial_salt, sizeof(initial_salt),
                          dcid, dcil, initial_secret);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("HKDF-Extract failed");
        return result;
    }

#ifdef DEBUG
    DOCA_LOG_DBG("HKDF-Extract success");
    print_hex("Initial secret", initial_secret, initial_secret_len);
#endif

    /* Use hkdf-expand-label to derive `client initial secret`
     *  with context as null and label as "client in"
     */
    result = hkdf_expand_label(hash_algo_md, initial_secret, initial_secret_len,
                               "client in", NULL, 0, client_initial_secret,
                               sizeof(client_initial_secret));
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("HKDF-Expand-Label for client initial secret failed");
        return result;
    }
#ifdef DEBUG
    print_hex("Client initial secret", client_initial_secret,
              sizeof(client_initial_secret));
#endif

    /* Use hkdf-expand-label to derive `quic key`*/
    result = hkdf_expand_label(hash_algo_md, client_initial_secret,
                               initial_secret_len, "quic key", NULL, 0,
                               quic_key, RETRY_AEAD_KEY_LEN);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("HKDF-Expand-Label for quic key failed");
        return result;
    }
#ifdef DEBUG
    print_hex("QUIC key", quic_key, 16);
#endif

    /* Use hkdf-expand-label to derive `quic iv`*/
    result = hkdf_expand_label(hash_algo_md, client_initial_secret,
                               initial_secret_len, "quic iv", NULL, 0, quic_iv,
                               RETRY_AEAD_NONCE_LEN);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("HKDF-Expand-Label for quic iv failed");
        return result;
    }
#ifdef DEBUG
    print_hex("QUIC iv", quic_iv, 12);
#endif

    /* Use hkdf-expand-label to derive `quic hp`*/
    result = hkdf_expand_label(hash_algo_md, client_initial_secret,
                               initial_secret_len, "quic hp", NULL, 0, quic_hp,
                               RETRY_AEAD_KEY_LEN);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("HKDF-Expand-Label for quic hp failed");
        return result;
    }
#ifdef DEBUG
    print_hex("QUIC hp", quic_hp, 16);
    print_hex("Plaintext", sample, 16);
#endif

    // use aes ecb to generate header protection mask
    result =
        generate_aes_ecb_mask(quic_hp, RETRY_AEAD_KEY_LEN, sample, hp_mask);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR(
            "Failed to use AES ECB to generate header protection mask");
        return result;
    }
#ifdef DEBUG
    print_hex("Header protection mask", hp_mask, 5);
#endif

    return result;
}

doca_error_t quic_derive_token_secrets(const unsigned char *dcid, size_t dcil,
                                       unsigned char *quic_key,
                                       unsigned char *quic_iv) {
    uint8_t initial_secret[EVP_MAX_MD_SIZE];
    uint8_t client_initial_secret[32];
    int initial_secret_len = INITIAL_SECRET_LEN;
    doca_error_t result = DOCA_SUCCESS;

#ifdef DEBUG
    print_hex("Salt", initial_salt, sizeof(initial_salt));
    print_hex("DCID", dcid, dcil);
    printf("initial secret length = %d", initial_secret_len);
#endif

    // Use hkdf-extract to derive initial secret
    result =
        hkdf_extract(hash_algo_md, token_initial_salt,
                     sizeof(token_initial_salt), dcid, dcil, initial_secret);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("HKDF-Extract failed");
        return result;
    }

#ifdef DEBUG
    DOCA_LOG_DBG("HKDF-Extract success");
    print_hex("Initial secret", initial_secret, initial_secret_len);
#endif

    /* Use hkdf-expand-label to derive `client initial secret`
     *  with context as null and label as "client in"
     */
    result = hkdf_expand_label(hash_algo_md, initial_secret, initial_secret_len,
                               "retry token", NULL, 0, client_initial_secret,
                               sizeof(client_initial_secret));
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("HKDF-Expand-Label for client initial secret failed");
        return result;
    }
#ifdef DEBUG
    print_hex("Client initial secret", client_initial_secret,
              sizeof(client_initial_secret));
#endif

    /* Use hkdf-expand-label to derive `quic key`*/
    result = hkdf_expand_label(hash_algo_md, client_initial_secret,
                               initial_secret_len, "token key", NULL, 0,
                               quic_key, RETRY_AEAD_KEY_LEN);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("HKDF-Expand-Label for token key failed");
        return result;
    }
#ifdef DEBUG
    print_hex("QUIC key", quic_key, 16);
#endif

    /* Use hkdf-expand-label to derive `quic iv`*/
    result = hkdf_expand_label(hash_algo_md, client_initial_secret,
                               initial_secret_len, "token iv", NULL, 0, quic_iv,
                               RETRY_AEAD_NONCE_LEN);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("HKDF-Expand-Label for token iv failed");
        return result;
    }
#ifdef DEBUG
    print_hex("QUIC iv", quic_iv, 12);
#endif

    return result;
}