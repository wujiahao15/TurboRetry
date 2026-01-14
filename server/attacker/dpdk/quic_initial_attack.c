// Standard libraries
#include <arpa/inet.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

// DPDK libraries
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;
static volatile int force_quit = 0;

/**
 * DPDK buffer settings
 */
#define NUM_MBUFS 8191U
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32

/**
 * My packet settings
 */
#ifdef SHORT
#define QUIC_PART_LEN 86
#else
#define QUIC_PART_LEN 1200
#endif
#define MY_PACKET_ID 12306
#define CONNECTIONID_LEN 8
#define OFFSET_TO_QUIC                                                         \
    (sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +              \
     sizeof(struct rte_udp_hdr))
#define PACKET_LENGTH (QUIC_PART_LEN + OFFSET_TO_QUIC)

/**
 * Application configuration
 */
struct app_config {
    uint64_t pps;
    uint32_t duration;
    uint32_t send_interval_us;
} config;

/**
 * DPDK parameters
 */
static const struct rte_eth_conf port_conf_default = {
    .txmode =
        {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
};

struct rte_mempool *mbuf_pool = NULL;
struct rte_ether_addr port_eth_addr = {};
int count = 0;

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("Received signal %d, preparing to exit...\n", signum);
        force_quit = 1;
    }
}

uint32_t generate_random_uint32() {
    return ((uint32_t)rand() << 16) | (uint32_t)rand();
}

uint16_t generate_random_uint16() {
    return (uint16_t)rand();
}

/**
 * Pseudo quic packet payload
 */
unsigned char quic_initial_payload[] = {
    0xc6, 0x0,  0x0,  0x0,  0x1,  0x8,  0xb2, 0xfd, 0xe7, 0xe4, 0x69, 0x44,
    0x5,  0x89, 0x8,  0xc,  0xca, 0xac, 0xc6, 0xc1, 0xf,  0x6f, 0xff, 0x0,
    0x41, 0xf2, 0xfb, 0x89, 0x61, 0xcc, 0x75, 0xb1, 0xd9, 0xbe, 0x75, 0xa1,
    0x33, 0x9d, 0xbc, 0x1a, 0xb3, 0x24, 0xfa, 0xd6, 0xa4, 0xd7, 0x5f, 0x60,
    0x4f, 0xc7, 0xdd, 0x75, 0x43, 0xce, 0x3f, 0xda, 0x41, 0xaa, 0x41, 0xab,
    0x24, 0x8c, 0x85, 0xe1, 0xe2, 0xe5, 0x79, 0x8a, 0xc8, 0x70, 0x69, 0x3d,
    0x26, 0x88, 0x78, 0xcb, 0x9d, 0xd2, 0x89, 0x93, 0x71, 0xe8, 0x18, 0x14,
    0x4a, 0x10, 0xb0, 0x9f, 0x8d, 0x6e, 0x36, 0xa7, 0x47, 0xb5, 0x6f, 0x57,
    0x30, 0xfb, 0x98, 0xbe, 0x5b, 0x77, 0xae, 0xfc, 0xd,  0x9e, 0x12, 0xfa,
    0xe1, 0x24, 0x9b, 0x86, 0x45, 0x50, 0x72, 0x9e, 0x7c, 0x78, 0x67, 0x9,
    0x2f, 0x7,  0x12, 0x92, 0xbb, 0x65, 0xda, 0x1d, 0x55, 0x46, 0x87, 0x77,
    0x38, 0xee, 0x2a, 0x35, 0x9c, 0x1e, 0x57, 0x31, 0xef, 0x91, 0x46, 0x67,
    0x97, 0x31, 0xc1, 0xa3, 0x17, 0x96, 0x69, 0xbf, 0xb5, 0xb,  0xd1, 0x90,
    0x24, 0x5c, 0x57, 0x23, 0xe7, 0x9a, 0xb8, 0x12, 0x33, 0xb8, 0xa1, 0x99,
    0xb6, 0x22, 0x9f, 0x83, 0xa3, 0xa7, 0x8b, 0x2b, 0xf6, 0x86, 0x31, 0xfb,
    0xb,  0x55, 0xb1, 0x82, 0x79, 0xa4, 0x29, 0xd4, 0x6,  0x8e, 0x6c, 0xc1,
    0xeb, 0x17, 0x49, 0xc2, 0xd6, 0x1c, 0x66, 0xce, 0x75, 0xf9, 0xec, 0x32,
    0xee, 0x2f, 0x30, 0x7c, 0x47, 0xd2, 0x3,  0xe1, 0x59, 0xa4, 0x92, 0xee,
    0x8f, 0x81, 0x9f, 0xb6, 0x24, 0x9b, 0x90, 0x5d, 0x41, 0x55, 0x0,  0xbe,
    0x88, 0xbf, 0x5a, 0xcd, 0x44, 0x6d, 0x55, 0x64, 0xe1, 0x5,  0xe3, 0x2c,
    0x9d, 0x79, 0x9e, 0x43, 0x82, 0x6e, 0x70, 0x9a, 0xc8, 0x87, 0x67, 0x10,
    0x9e, 0x77, 0x12, 0xb6, 0x36, 0x1e, 0x2b, 0x2c, 0xf8, 0x82, 0xa7, 0x5c,
    0x3b, 0xb5, 0x72, 0xa2, 0x19, 0xa,  0x28, 0x6,  0x4a, 0x26, 0x4e, 0x30,
    0x5f, 0xf6, 0x97, 0x93, 0x29, 0x57, 0x95, 0xd1, 0xd7, 0x80, 0xbf, 0xe6,
    0xf,  0x2f, 0x1e, 0x13, 0xd4, 0x97, 0xb4, 0x59, 0xc6, 0xb3, 0x67, 0x4c,
    0x9,  0x96, 0x1d, 0xfc, 0x19, 0xcc, 0x6a, 0xe0, 0xd8, 0xc0, 0xf,  0x63,
    0x42, 0x55, 0xbf, 0xf3, 0x7a, 0x5,  0xf8, 0x9a, 0x4b, 0x4f, 0x97, 0xbe,
    0x49, 0xa2, 0xed, 0x77, 0xf6, 0x16, 0x74, 0xce, 0xab, 0x7c, 0xba, 0x47,
    0x29, 0xa0, 0xd0, 0x28, 0x9a, 0xd4, 0xf1, 0xdf, 0xaa, 0x66, 0xc4, 0xc7,
    0x48, 0x0,  0x62, 0x63, 0x54, 0x4,  0xff, 0x54, 0xc5, 0xc0, 0xe3, 0x4e,
    0x14, 0x2b, 0xc4, 0x92, 0x6e, 0x3f, 0x7d, 0x32, 0x2,  0x16, 0x52, 0xab,
    0x2e, 0x3,  0xd7, 0xf8, 0x2a, 0x24, 0xa9, 0x9a, 0x7,  0x34, 0x85, 0xf3,
    0x48, 0x92, 0x16, 0xba, 0x51, 0xad, 0x36, 0x79, 0x43, 0x56, 0xf9, 0x8a,
    0xfe, 0x22, 0x90, 0xd7, 0xbd, 0x7e, 0xa6, 0xc7, 0x5d, 0x4e, 0x39, 0x9c,
    0x87, 0x8d, 0xb,  0x12, 0x62, 0x29, 0x95, 0xd9, 0xc4, 0xc2, 0xa4, 0x28,
    0xa3, 0x5c, 0x87, 0x62, 0x5c, 0x48, 0xe7, 0x54, 0xe,  0xb,  0xf4, 0x1a,
    0x7f, 0xb5, 0x64, 0xb3, 0x7,  0xc7, 0xee, 0xa3, 0x70, 0x57, 0xf8, 0xb4,
    0x50, 0x9d, 0xea, 0x68, 0x22, 0x8e, 0x1f, 0xab, 0xd1, 0xce, 0x55, 0xba,
    0xe,  0x7d, 0x55, 0x87, 0x1f, 0x5,  0xee, 0x8c, 0x85, 0xaa, 0xc3, 0x6a,
    0xd4, 0x75, 0x8b, 0x49, 0xb3, 0x18, 0x9a, 0x36, 0x91, 0x2c, 0x3e, 0xb3,
    0x16, 0xe3, 0x42, 0xf5, 0xf6, 0x10, 0xc9, 0x50, 0xc1, 0xdb, 0x86, 0x2,
    0x30, 0x77, 0xb6, 0x1c, 0xcb, 0xa1, 0xb3, 0x27, 0xd9, 0x9a, 0xbe, 0xd8,
    0x59, 0x5e, 0x80, 0x25, 0xc5, 0xbd, 0x37, 0xf8, 0x53, 0x9f, 0xa7, 0xfa,
    0xa2, 0xe3, 0x37, 0xd4, 0x55, 0x70, 0x52, 0x37};

void setup_packet(struct rte_mbuf *mbuf) {
    int i = 0;
    uint8_t *quic_part = NULL;
    struct rte_ether_hdr *eth_hdr = NULL;
    struct rte_ipv4_hdr *ip_hdr = NULL;
    struct rte_udp_hdr *udp_hdr = NULL;

    // Set up Ethernet header
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    if (eth_hdr == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to point to ethernet header\n");
    }
    struct rte_ether_addr dst_eth_addr = {
        .addr_bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    rte_ether_addr_copy(&port_eth_addr, &eth_hdr->src_addr);
    rte_ether_addr_copy(&dst_eth_addr, &eth_hdr->dst_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    // Setup IPv4 header
    ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ip_hdr->version_ihl = 0x45;
    ip_hdr->type_of_service = 0;
    ip_hdr->packet_id = rte_cpu_to_be_16(MY_PACKET_ID);
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live = 64;
    ip_hdr->next_proto_id = IPPROTO_UDP;
    ip_hdr->total_length =
        rte_cpu_to_be_16(PACKET_LENGTH - sizeof(struct rte_ether_hdr));

#ifdef SHORT
    ip_hdr->src_addr = rte_cpu_to_be_32(RTE_IPV4(192, 168, 102, 25));
    ip_hdr->dst_addr = rte_cpu_to_be_32(RTE_IPV4(192, 168, 102, 30));
#else
    // ip_hdr->src_addr = rte_cpu_to_be_32(generate_random_uint32());
    ip_hdr->src_addr = rte_cpu_to_be_32(RTE_IPV4(192, 168, 102, 25));
    ip_hdr->dst_addr = rte_cpu_to_be_32(RTE_IPV4(192, 168, 102, 28));
#endif
    ip_hdr->hdr_checksum = 0; /* checksum is offloaded. */

    // Setup UDP header
    udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
    udp_hdr->src_port = rte_cpu_to_be_16(generate_random_uint16());
    udp_hdr->dst_port = rte_cpu_to_be_16(4433);
    udp_hdr->dgram_len = rte_cpu_to_be_16(QUIC_PART_LEN + 8);
    udp_hdr->dgram_cksum = 0; /* checksum is offloaded. */

    // Calculate checksum
    // udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hdr);
    // ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

    // QUIC Part
#ifndef SHORT
    quic_part = (uint8_t *)(udp_hdr + 1);
    memcpy(quic_part, quic_initial_payload, sizeof(quic_initial_payload));
    for (i = 0; i < CONNECTIONID_LEN; i++) {
        quic_part[6 + i] = rte_rand() % 256;         // DCID
        quic_part[6 + 8 + 1 + i] = rte_rand() % 256; // SCID
    }
#endif

#ifdef PROFILE
    // printf("sip %u, dip %u, ", ip_hdr->src_addr, ip_hdr->dst_addr);
    // printf("spt %u, dpt %u\n", udp_hdr->src_port, udp_hdr->dst_port);
#endif

    // set packet len
    mbuf->data_len = PACKET_LENGTH;
    mbuf->pkt_len = PACKET_LENGTH;

    mbuf->ol_flags |=
        RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_UDP_CKSUM;
    mbuf->l2_len = sizeof(struct rte_ether_hdr); // 以太网头部长度
    mbuf->l3_len = sizeof(struct rte_ipv4_hdr);  // IPv4头部长度
    mbuf->l4_len = sizeof(struct rte_udp_hdr);
}

static void send_loop(uint16_t port) {
    int i = 0;
    uint16_t nb_tx = -1;
    uint32_t nb_total_tx = 0, interval = 0, delta_us = 0;
    uint64_t start_tsc = rte_rdtsc();
    uint64_t tsc_hz = rte_get_tsc_hz();
    uint64_t interval_tsc = config.duration * tsc_hz;
    uint64_t fix_start_tsc = 0;
    struct rte_mbuf *mbuf = NULL;
    struct rte_mbuf *tx_bufs[BURST_SIZE] = {0};

    while (((rte_rdtsc() - start_tsc) < interval_tsc) && !force_quit) {
        // Set up a bulk of packets to send
        fix_start_tsc = rte_rdtsc();
        for (i = 0; i < BURST_SIZE; i++) {
            mbuf = rte_pktmbuf_alloc(mbuf_pool);
            if (!mbuf) {
                rte_exit(EXIT_FAILURE, "Failed to allocate mbuf\n");
            }
            setup_packet(mbuf);
            tx_bufs[i] = mbuf;
        }
        delta_us = ((rte_rdtsc() - fix_start_tsc) * 1000000ULL) / tsc_hz;

        // burst send
        nb_tx = rte_eth_tx_burst(port, 0, tx_bufs, BURST_SIZE);
        nb_total_tx += nb_tx;

#ifdef PROFILE
        if (nb_total_tx > 64) {
            break;
        }
#endif

        // Free any unsent packets.
        if (unlikely(nb_tx < BURST_SIZE)) {
            fprintf(stderr, "Packets sent %d of %d\n", nb_tx, BURST_SIZE);
            for (i = nb_tx; i < BURST_SIZE; i++)
                rte_pktmbuf_free(tx_bufs[i]);
        }

        // rate control
        interval = (delta_us > config.send_interval_us)
                       ? 0
                       : (config.send_interval_us - delta_us);
        // interval = (interval > 100) ? interval : 1;

#ifdef PROFILE
        // printf("delta_us = %u\n", delta_us);
        // printf("interval = %u\n", interval);
        rte_delay_us_block(1000 * 1);
#else
        rte_delay_us_block(interval);
#endif
    }

    double kpps = (double)nb_total_tx / config.duration / 1e3;
    double bps = (kpps * (PACKET_LENGTH << 3)) / 1e6;
    printf("\nFinished sending packets\n");
    printf("Duration: %u seconds\n", config.duration);
    printf("Total packets sent: %u\n", nb_total_tx);
    printf("Average rate: %.2f Kpps\n", kpps);
    printf("Average rate: %.2f Gbps\n", bps);
}

static int dpdk_init(int argc, char *argv[]) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }
    return ret;
}

static void port_init(uint16_t port_id) {
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf port_conf = port_conf_default;

    /* Get device info. */
    int ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        rte_exit(EXIT_FAILURE,
                 "Error during getting device (port %u) info: %s\n", port_id,
                 strerror(-ret));
    }
    printf("No error during getting device (port %u)\n", port_id);

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
        printf("%s\n", "IPV4 checksum offloaded");
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
        printf("%s\n", "UDP checksum offloaded");
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
    }

    /* Configure the Ethernet device. */
    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error during port configuration: %s\n",
                 rte_strerror(-ret));
    }
    printf("%s\n", "Configure dev success");

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE,
                 "Cannot adjust number of descriptors: err=%d, port=%u\n", ret,
                 port_id);
    }
    printf("%s\n", "Adjust rx tx desc success");

    /* init one RX queue */
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;
    /* RX queue setup. 8< */
    ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
                                 rte_eth_dev_socket_id(port_id), &rxq_conf,
                                 mbuf_pool);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret,
                 port_id);
    }
    /* >8 End of RX queue setup. */

    /* Set up 1 TX queue per Ethernet port. */
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
                                 rte_eth_dev_socket_id(port_id), &txq_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error during TX queue setup: %s\n",
                 rte_strerror(-ret));
    }
    printf("%s\n", "Configure TX queue success");

    /* Start the Ethernet port. */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error during starting port %u: %s\n", port_id,
                 rte_strerror(-ret));
    }
    printf("%s\n", "Start dev success");
}

static void get_port_mac_address(uint16_t port_id) {
    int ret = rte_eth_macaddr_get(port_id, &port_eth_addr);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%u\n", ret,
                 port_id);
    }
}

int main(int argc, char *argv[]) {
    int ret = -1;
    uint16_t port_id = 0, nb_ports = 0;

    /* Initialize EAL. */
    ret = dpdk_init(argc, argv);
    argc -= ret;
    argv += ret;
    if (argc != 3) {
        rte_exit(EXIT_FAILURE, "Usage: %s <kpps> <duration(s)>\n", argv[0]);
    }
    config.pps = atoi(argv[1]) * 1000;
    config.duration = atoi(argv[2]);
    config.send_interval_us = (1e6 / config.pps) * BURST_SIZE;
    printf("         rate: %lu pps\n", config.pps);
    printf("     duration: %u seconds\n", config.duration);
    printf("send interval: %u us\n", config.send_interval_us);

    /* Count avaliable devices. */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Ethernet ports found\n");
    }
    printf("# of ports: %d\n", nb_ports);

    /* Create mbuf pool. */
    mbuf_pool =
        rte_pktmbuf_pool_create("TXMBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                                RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
    }
    printf("%s\n", "Create mbuf pool success");

    /* Initialize port */
    char name[256] = {0};
    for (int i = 0; i < nb_ports; i++) {
        rte_eth_dev_get_name_by_port(i, name);
        printf("port id of %s = %d\n", name, i);
    }

    // ./build/dpdk_qia <kpps>  <duration>
    if (rte_eth_dev_get_port_by_name("0000:03:00.0_representor_vf4294967295",
                                     &port_id) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot find dev pf0hpf\n");
    }
    port_init(port_id);

    /* Get port MAC address */
    get_port_mac_address(port_id);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Packet length =  %lu bytes\n", PACKET_LENGTH);
    // printf("Press enter to continue.");
    // getchar();

    // start sending packets
    send_loop(port_id);

    struct rte_eth_stats rte_stats = {0};
    rte_eth_stats_get(port_id, &rte_stats);

    printf("\n************* Forward statistics *************\n");
    printf("                 # rx packets = %lu\n", rte_stats.ipackets);
    printf("                 # tx packets = %lu\n", rte_stats.opackets);
    printf("         # rx dropped packets = %lu\n", rte_stats.imissed);
    printf("      # errorneous rx packets = %lu\n", rte_stats.ierrors);
    printf("      # errorneous tx packets = %lu\n", rte_stats.oerrors);
    printf("# Rx mbuf allocation failures = %lu\n", rte_stats.rx_nombuf);
    printf("**********************************************\n");

    // close devices
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    printf("Done.\n");

    return 0;
}
