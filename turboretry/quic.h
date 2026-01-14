#ifndef QUIC_H_
#define QUIC_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * openssl library for implementing HKDF functions,
 *   e.g. HKDF-Extract and HKDF-Expand-Label
 */
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

/**
 * DPDK library
 */
#include <rte_mbuf.h>

/**
 * DOCA AES GCM library
 */
#include "aes_gcm_common.h"

/*
 * Retry packet related definitions
 *   AEAD_AES_GCM_128(
 *      NONCE (96 bit => 12 B) 0x461599d35d632bf2239825bb
 *       KEY (128 bit => 16 B) 0xbe0c690b9f66575a1d766b54e368c84e
 *   )
 * Above input parameters are fixed values according to RFC9001-5.8
 */
// QUIC Retry nonce (initial vector) length
#define RETRY_AEAD_NONCE_LEN MAX_AES_GCM_IV_LENGTH
// QUIC Retry nonce (iv) for AEAD-AES-GCM-128
extern const uint8_t retry_aead_nonce[];
// QUIC Retry key length (128 bit)
#define RETRY_AEAD_KEY_LEN AES_GCM_KEY_128_SIZE_IN_BYTES
// QUIC Retry key for AEAD-AES-GCM-128
extern const uint8_t retry_aead_key[];
// QUIC Retry key type (128 bit)
#define RETRY_AEAD_KEY_TYPE DOCA_AES_GCM_KEY_128
// QUIC Retry integrity tag length (128 bit <=> 16 B)
#define RETRY_INTEGRITY_TAG_SIZE AES_GCM_AUTH_TAG_128_SIZE_IN_BYTES
// QUIC Retry AEAD_AES_GCM_MODE => encryption
#define RETRY_AES_GCM_MODE AES_GCM_MODE_ENCRYPT
#define QUIC_HP_SAMPLE_SIZE AES_BLOCK_SIZE

/*
 * QUIC header parser helper
 */
enum quic_packet_type {
    QUIC_SHORT_PACKET = 1,
    QUIC_LONG_PACKET = 3,
};
enum quic_long_packet_type {
    QUIC_INITIAL = 0,
    QUIC_ZERORTT = 1,
    QUIC_HANDSHAKE = 2,
    QUIC_RETRY = 3,
};
#define QUIC_VERSION 0x00000001
/* the low 4 bit is arbitary, here we set it to 0x9 */
#define QUIC_RETRY_PKT_FLAG 0xf9
#define QUIC_PACKET_TYPE(x) ((x & 0xC0) >> 6)
#define QUIC_LONG_PKT_TYPE(x) ((x & 0x30) >> 4)
#define IS_QUIC_INITIAL_PACKET(x) ((x & 0xF0) == 0xC0)

/*
 * QUIC Retry settings in my system
 */
/* QUIC Retry connection id in my system. */
#define QUIC_CONNECTION_ID_LEN 8
#define BF_QUIC_CID_LEN QUIC_CONNECTION_ID_LEN
#define FLAG_LEN 1
#define CID_LENGTH_LEN 1
#define PORT_LEN 2
#define IPV4_ADDR_LEN 4
#define QUIC_VERSION_LEN 4
/*
 * QUIC Retry token encoded part length
 * encoded content = sip + sport + odcid
 */
#define RETRY_TOKEN_ENCODED_LEN(odcidl) (IPV4_ADDR_LEN + PORT_LEN + odcidl)
// QUIC Retry Token additional authentication data size
#define RETRY_TOKEN_AAD_SIZE (1 + 8) // ocidl + timestamp(64)
/* token = aad + encrypt(content) + authtag (16 B) */
#define QUIC_RETRY_TOKEN_LEN(odcidl)                                           \
    (RETRY_TOKEN_AAD_SIZE + odcidl + IPV4_ADDR_LEN + PORT_LEN +                \
     RETRY_INTEGRITY_TAG_SIZE)

// QUIC Retry packet max length
#define RETRY_PACKET_MAX_LEN 256

// QUIC Retry pseudo packet length
#define RETRY_PSEUDO_PKT_LEN(odcidl, scidl)                                    \
    (CID_LENGTH_LEN + odcidl + FLAG_LEN + QUIC_VERSION_LEN + CID_LENGTH_LEN +  \
     scidl + CID_LENGTH_LEN + QUIC_CONNECTION_ID_LEN +                         \
     QUIC_RETRY_TOKEN_LEN(odcidl))

#define RETRY_PSEUDO_PKT_FAKE_LEN                                              \
    ((CID_LENGTH_LEN + QUIC_CONNECTION_ID_LEN) * 3 + FLAG_LEN +                \
     QUIC_VERSION_LEN + QUIC_RETRY_TOKEN_LEN)
#define QUIC_INITIAL_MIN_LENGTH 1200

/**
 * QUIC PACKET INFORMATION
 * [SID, DID]
 * [CS1, CD1] - CLIENT INITIAL        (1)
 * [SS1, CS1] - SERVER RETRY          (2)
 * [CS1, SS1] - CLIENT INITIAL(TOKEN) (3)
 */
struct quic_pkt_info {
    /*
     * origin connection id information
     * it is parsed from QUIC INITIAL packet
     * we use pointers to decrease the frequency of memcpy
     * to improve the performance of the program
     * NOTE: in retry packet,
     *   - its destination cid is the origin scid
     *   - its source cid is new generated cid
     *   - its origin destination cid is the origin scid
     */
    uint8_t init_scid_len;
    uint8_t *init_scid;
    uint8_t init_dcid_len;
    uint8_t *init_dcid;
    uint8_t *init_token_len_ptr;
    uint8_t init_token_bytelen;
    uint8_t init_token_len;
    uint8_t *init_token;

    /*
     * connection id information used in retry packet
     */
    uint8_t rty_scid_len;
    uint8_t *rty_scid;
    /*
     * In our system, token will not
     * exceed 63 (version 0.1.1)
     * So we use uint8_t to define token length
     */
    uint8_t rty_token_len;
    uint8_t *rty_token;
    /* Retry integrity tag */
    uint8_t *rty_auth_tag;

    /* information to be encoded in token */
    uint16_t sport;
    uint32_t sip;
};

/* Packet header information */
struct packet_headers {
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_udp_hdr *udp_hdr;
    uint8_t *quic_hdr;
    uint16_t udp_payload_len;
};

/*
 * Parse packet headers of ethernet, ip, udp and quic header.
 *
 * @mbuf [inout]: rte buffer
 * @hdrs [out]: packet header information
 * @return: 0 on success and 1/-1 otherwise
 */
doca_error_t parse_packet_headers(struct rte_mbuf *mbuf,
                                  struct packet_headers *hdrs);

/*
 * Parse quic initial packet header.
 *
 * @data [in]: udp payload start address
 * @len [out]: udp payload length
 * @quic_pkt_info [out]: buffer length
 * @return: 0 on success and 1/-1 otherwise
 */
doca_error_t quic_parse_initial_pkt_hdr(uint8_t *data, uint16_t len,
                                        struct quic_pkt_info *info);

/*
 * Build retry pseudo packet.
 *
 * @info [in]: struct quic_pkt_info parsed
 * @pseudo_rty_pkt [out]: pointer to pseudo retry packet buffer
 * @out_len [out]: pseudo retry packet length
 * @return: 0 on success and 1/-1 otherwise
 */
doca_error_t quic_build_pseudo_retry_packet(struct quic_pkt_info *info,
                                            uint8_t *pseudo_rty_pkt,
                                            size_t *out_len);

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
                                          struct quic_pkt_info *info);

/**
 * HKDF-Extract function
 *
 * @param md The hash algorithm to use (e.g., EVP_sha256())
 * @param salt the salt value
 * @param salt_len length of the salt value
 * @param ikm input keying material
 * @param ikm_len input keying material length
 * @param prk peseudo random key (>= EVP_MD_size bytes)
 *
 * @return DOCA_SUCCESS on success, others on failure
 *
 */
doca_error_t hkdf_extract(const EVP_MD *md, const unsigned char *salt,
                          size_t salt_len, const unsigned char *ikm,
                          size_t ikm_len, unsigned char *prk);

/**
 * Performs HKDF-Expand-Label operation as defined in RFC 5869 and RFC 9001.
 *
 * @param md The hash algorithm to use (e.g., EVP_sha256())
 * @param secret The input pseudorandom key (PRK) from HKDF-Extract
 * @param secret_len Length of the secret in bytes
 * @param label The purpose-specific label for key derivation
 * @param context Optional context information (NULL for QUIC)
 * @param context_len Length of context in bytes (0 for QUIC)
 * @param out Output buffer for derived key material
 * @param out_len Desired length of output key material in bytes
 *
 * @return DOCA_SUCCESS on success, others on failure
 *
 * @note This implements the HKDF-Expand operation with TLS 1.3 labeling scheme:
 *       1. Constructs HkdfLabel structure as:
 *          - uint16 length (big-endian)
 *          - opaque label<7..255> ("tls13 " + custom_label)
 *          - opaque context<0..255>
 *       2. Performs iterative HMAC to expand the key material
 *       3. Follows QUIC-specific requirements from RFC 9001
 *
 * @warning Output length must not exceed 65535 bytes (uint16 max)
 * @warning Total label length (with "tls13 " prefix) must not exceed 255 bytes
 */
doca_error_t hkdf_expand_label(const EVP_MD *md, const unsigned char *secret,
                               size_t secret_len, const char *label,
                               const unsigned char *context, size_t context_len,
                               unsigned char *out, size_t out_len);

/**
 * Generates a 5-byte mask using AES-ECB encryption as specified in RFC 9001.
 *
 * @param key The encryption key (must be 16, 24, or 32 bytes for
 * AES-128/192/256)
 * @param key_len Length of the key in bytes (must be 16, 24, or 32)
 * @param plaintext 16-byte input block to encrypt (typically header sample)
 * @param mask Output buffer for the 5-byte mask
 *
 * @return DOCA_SUCCESS on success, others on failure
 *
 * @note This implements QUIC's header protection mask generation:
 *       1. Uses AES in ECB mode (no IV)
 *       2. Encrypts the given plaintext block
 *       3. Returns first 5 bytes of ciphertext as mask
 *       4. Follows RFC 9001 Section 5.4.1 requirements
 *
 * @warning Requires plaintext to be exactly AES_BLOCK_SIZE (16 bytes)
 * @warning Output buffer must have at least 5 bytes capacity
 *
 * @security ECB mode is generally insecure but acceptable here since:
 *           - Used only for header protection
 *           - Always encrypts unique samples (packet numbers)
 *           - Only exposes 5 bytes of ciphertext
 */
doca_error_t generate_aes_ecb_mask(const unsigned char *key, size_t key_len,
                                   const unsigned char *plaintext,
                                   unsigned char *mask);

doca_error_t quic_derive_initial_secrets(const unsigned char *dcid, size_t dcil,
                                         const unsigned char *sample,
                                         unsigned char *quic_key,
                                         unsigned char *quic_iv,
                                         unsigned char *quic_hp,
                                         unsigned char *hp_mask);
doca_error_t quic_derive_token_secrets(const unsigned char *dcid, size_t dcil,
                                       unsigned char *quic_key,
                                       unsigned char *quic_iv);

void print_hex(const char *label, const unsigned char *data, size_t len);
void init_openssl();

#endif