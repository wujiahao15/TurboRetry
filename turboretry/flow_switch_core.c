/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_net.h>

#include <doca_dev.h>
#include <doca_log.h>

#include "flow_switch_core.h"
#include "utils.h"

DOCA_LOG_REGISTER(FLOW_SWITCH_CORE);

/* number of pipe entries */
#define NB_VALID_ENTRIES 1
#define NB_N2H_ENTRIES 1
#define NB_H2N_ENTRIES 1
#define NB_ROOT_ENTRIES 2
#define NB_TOTAL_ENTRIES                                                       \
    (NB_VALID_ENTRIES + NB_N2H_ENTRIES + NB_ROOT_ENTRIES + NB_H2N_ENTRIES + 1)

/* app parameters */
#define MAX_PKTS 16
#define WAIT_SECS 15
#define NUM_OF_DOCA_PORTS 2

/* doca port resources */
static int nb_active_ports;
static struct doca_flow_port *active_ports[NUM_OF_DOCA_PORTS];

/* pipe definitions */
static struct doca_flow_pipe *n2h_pipe;
static struct doca_flow_pipe *root_pipe;
static struct doca_flow_pipe *pipe_valid;
static struct doca_flow_pipe *pipe_rss;
static struct doca_flow_pipe *h2n_pipe;

/* array for storing created network to host entries */
static struct doca_flow_pipe_entry *n2h_entries[NB_N2H_ENTRIES];

/* array for storing created egress entries */
static struct doca_flow_pipe_entry *valid_entries[NB_VALID_ENTRIES];

/* array for storing created root pipe entries */
static struct doca_flow_pipe_entry *root_entries[NB_ROOT_ENTRIES];

/* array for storing created host to network entries */
static struct doca_flow_pipe_entry *h2n_entries[NB_H2N_ENTRIES];

/* rss pipe entries */
static struct doca_flow_pipe_entry *rss_entry;

/*
 * Create DOCA Flow pipe with 5 tuple match, and forward RSS
 *
 * @port [in]: port of the pipe
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_rss_pipe(struct doca_flow_port *port,
                             struct doca_flow_pipe **pipe, int nb_queues) {
    struct doca_flow_match match;
    struct doca_flow_monitor monitor;
    struct doca_flow_fwd fwd;
    struct doca_flow_pipe_cfg *pipe_cfg;
    uint16_t rss_queues[nb_queues];
    doca_error_t result;

    memset(&match, 0, sizeof(match));
    memset(&fwd, 0, sizeof(fwd));
    memset(&monitor, 0, sizeof(monitor));

    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    /* L3 match */
    match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        return result;
    }

    result = set_flow_pipe_cfg(pipe_cfg, "RSS_META_PIPE", DOCA_FLOW_PIPE_BASIC,
                               true);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }

    /* RSS queue - send matched traffic to queue 0  */
    linear_array_init_u16(rss_queues, nb_queues);
    fwd.type = DOCA_FLOW_FWD_RSS;
    fwd.rss_queues = rss_queues;
    fwd.rss_outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP;
    fwd.num_of_queues = nb_queues;

    result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe);
    DOCA_LOG_INFO("# of RSS queues = %d", nb_queues);
destroy_pipe_cfg:
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    return result;
}

/*
 * Add DOCA Flow pipe entry with example 5 tuple
 *
 * @pipe [in]: pipe of the entry
 * @status [in]: user context for adding entry
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t add_rss_pipe_entry(struct doca_flow_pipe *pipe,
                                struct entries_status *status) {
    struct doca_flow_match match;
    struct doca_flow_actions actions;
    doca_error_t result;

    /**
     * RSS Pipe:
     *   Entry 0: IPv4 -> Rss queues
     */
    memset(&match, 0, sizeof(match));
    memset(&actions, 0, sizeof(actions));
    actions.action_idx = 0;

    result = doca_flow_pipe_add_entry(0, pipe, &match, &actions, NULL, NULL, 0,
                                      status, &rss_entry);
    if (result != DOCA_SUCCESS)
        return result;

    return DOCA_SUCCESS;
}

/*
 * Create DOCA Flow pipe with 5 tuple match on the switch port.
 * Matched traffic will be forwarded to the port defined per entry.
 * Unmatched traffic will be dropped.
 *
 * @sw_port [in]: switch port
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t create_switch_n2h_pipe(struct doca_flow_port *sw_port,
                                    struct doca_flow_pipe **pipe) {
    struct doca_flow_match match;
    struct doca_flow_monitor monitor;
    struct doca_flow_fwd fwd;
    struct doca_flow_pipe_cfg *pipe_cfg;
    // struct doca_flow_fwd fwd_miss;
    doca_error_t result;

    memset(&match, 0, sizeof(match));
    memset(&monitor, 0, sizeof(monitor));
    memset(&fwd, 0, sizeof(fwd));
    // memset(&fwd_miss, 0, sizeof(fwd_miss));

    /* Set relax match of IPv4 and UDP */
    match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_UDP;
    match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
    match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
    match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;

    /*
     * Destination ip address and port are defined per entry
     * Only desired flow are forwarded to next validation pipe
     * e.g. QUIC flow ==> dip = targeted host, dport = 4433
     */
    match.outer.ip4.dst_ip = UINT32_MAX;
    match.outer.udp.l4_port.dst_port = UINT16_MAX;

    /* Next pipe to forward to is defined per entry */
    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = NULL;

    /* Missed packets are steered to arm os kernel */
    // fwd_miss.type = DOCA_FLOW_FWD_PIPE;
    // fwd_miss.next_pipe = pipe_rss;

    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, sw_port);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        return result;
    }

    result =
        set_flow_pipe_cfg(pipe_cfg, "SWITCH_PIPE", DOCA_FLOW_PIPE_BASIC, false);
    // set_flow_pipe_cfg(pipe_cfg, "SWITCH_PIPE", DOCA_FLOW_PIPE_BASIC, true);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, NB_N2H_ENTRIES);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg nr_entries: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result =
        doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
    // doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg domain: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }

    // result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
    result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe);
destroy_pipe_cfg:
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    return result;
}

/*
 * Add DOCA Flow pipe entry to the pipe
 *
 * @pipe [in]: pipe of the entry
 * @status [in]: user context for adding entry
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t add_switch_n2h_pipe_entries(struct doca_flow_pipe *pipe,
                                         struct entries_status *status) {
    struct doca_flow_match match;
    struct doca_flow_fwd fwd;
    enum doca_flow_flags_type flags = DOCA_FLOW_NO_WAIT;
    doca_error_t result;

    doca_be32_t dst_ip_addr;
    doca_be16_t dst_port;

    memset(&fwd, 0, sizeof(fwd));
    memset(&match, 0, sizeof(match));

    /**
     * N2H Pipe:
     *   * Entry 0: IP dst 192.168.102.31 / UDP dst 4433 -> Valid Pipe
     */
    /* Only QUIC packets are forwared to next validation pipe */
    // dst_ip_addr = BE_IPV4_ADDR(10, 156, 169, 28);
    dst_ip_addr = BE_IPV4_ADDR(192, 168, 102, 31);
    dst_port = rte_cpu_to_be_16(4433);
    match.outer.ip4.dst_ip = dst_ip_addr;
    match.outer.tcp.l4_port.dst_port = dst_port;

    /* Forward to validation pipe */
    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = pipe_valid;

    /* Offload flow rules */
    result = doca_flow_pipe_add_entry(0, pipe, &match, NULL, NULL, &fwd, flags,
                                      status, &n2h_entries[0]);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add pipe entry: %s",
                     doca_error_get_descr(result));
        return result;
    }

    return DOCA_SUCCESS;
}

/*
 * Create DOCA Flow pipe with 5 tuple match on the switch port.
 * Matched traffic will be forwarded to the port defined per entry.
 * Unmatched traffic will be dropped.
 *
 * @sw_port [in]: switch port
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t create_switch_valid_pipe(struct doca_flow_port *sw_port,
                                      struct doca_flow_pipe **pipe) {
    struct doca_flow_match match;
    struct doca_flow_monitor monitor;
    struct doca_flow_fwd fwd;
    struct doca_flow_fwd fwd_miss;
    struct doca_flow_pipe_cfg *pipe_cfg;
    doca_error_t result;

    memset(&match, 0, sizeof(match));
    memset(&monitor, 0, sizeof(monitor));
    memset(&fwd, 0, sizeof(fwd));
    memset(&fwd_miss, 0, sizeof(fwd_miss));

    /* Match source ip address and port */
    match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_UDP;
    match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
    match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
    match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    /* Above parser meta and l3 l4 type are required
     * in matching l3 ip and l4 port */
    match.outer.ip4.src_ip = UINT32_MAX;
    match.outer.udp.l4_port.src_port = UINT16_MAX;

    /* Port ID to forward to is defined per entry */
    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = 0xffff;

    /* Unverified packets are steered to dpdk program */
    fwd_miss.type = DOCA_FLOW_FWD_PIPE;
    fwd_miss.next_pipe = pipe_rss;

    /* Set pipe counter */
    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
    result = doca_flow_pipe_cfg_create(&pipe_cfg, sw_port);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        return result;
    }

    /* Construct pipe config */
    result =
        set_flow_pipe_cfg(pipe_cfg, "SWITCH_PIPE", DOCA_FLOW_PIPE_BASIC, false);
    // set_flow_pipe_cfg(pipe_cfg, "SWITCH_PIPE", DOCA_FLOW_PIPE_BASIC, true);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, NB_VALID_ENTRIES);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg nr_entries: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result =
        doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
    // doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg domain: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }

    // result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe);
    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
destroy_pipe_cfg:
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    return result;
}

doca_error_t add_switch_valid_pipe_entries(struct doca_flow_pipe *pipe,
                                           struct entries_status *status) {
    struct doca_flow_match match;
    struct doca_flow_fwd fwd;
    doca_error_t result;
    int entry_index = 0;

    memset(&fwd, 0, sizeof(fwd));
    memset(&match, 0, sizeof(match));

    match.outer.ip4.src_ip = BE_IPV4_ADDR(10, 156, 169, 26);
    match.outer.tcp.l4_port.src_port = rte_cpu_to_be_16(32930);

    /* Verified flow is steered to host */
    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = 1;

    /* Offload flow rules */
    result =
        doca_flow_pipe_add_entry(0, pipe, &match, NULL, NULL, &fwd,
                                 DOCA_FLOW_NO_WAIT, status, &valid_entries[0]);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add valid pipe entry[%d]: %s", entry_index,
                     doca_error_get_descr(result));
        return result;
    }

    return DOCA_SUCCESS;
}

/*
 * Create DOCA Flow pipe with 5 tuple match on the switch port.
 * Matched traffic will be forwarded to the port defined per entry.
 * Unmatched traffic will be dropped.
 *
 * @sw_port [in]: switch port
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t create_switch_h2n_pipe(struct doca_flow_port *sw_port,
                                    struct doca_flow_pipe **pipe) {
    struct doca_flow_match match;
    struct doca_flow_monitor monitor;
    struct doca_flow_fwd fwd;
    struct doca_flow_pipe_cfg *pipe_cfg;
    doca_error_t result;

    memset(&match, 0, sizeof(match));
    memset(&monitor, 0, sizeof(monitor));
    memset(&fwd, 0, sizeof(fwd));
    memset(&pipe_cfg, 0, sizeof(pipe_cfg));

    // match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_TCP;
    // match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
    match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
    match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;

    /* Source IP addresses and source TCP ports are defined per entry */
    match.outer.ip4.src_ip = 0xffffffff;
    // match.outer.tcp.l4_port.src_port = 0xffff;

    /* Port ID to forward to is defined per entry */
    fwd.type = DOCA_FLOW_FWD_PORT;
    fwd.port_id = 0xffff;

    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, sw_port);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        return result;
    }

    result = set_flow_pipe_cfg(pipe_cfg, "SWITCH_VPORT_PIPE",
                               DOCA_FLOW_PIPE_BASIC, false);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, NB_H2N_ENTRIES);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg nr_entries: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result =
        doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg domain: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }

    result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe);
destroy_pipe_cfg:
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    return result;
}

/*
 * Add DOCA Flow pipe entry to the pipe
 *
 * @pipe [in]: pipe of the entry
 * @status [in]: user context for adding entry
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t add_switch_h2n_pipe_entries(struct doca_flow_pipe *pipe,
                                         struct entries_status *status) {
    struct doca_flow_match match;
    struct doca_flow_fwd fwd;
    enum doca_flow_flags_type flags = DOCA_FLOW_WAIT_FOR_BATCH;
    doca_error_t result;
    int entry_index = 0;

    memset(&fwd, 0, sizeof(fwd));
    memset(&match, 0, sizeof(match));

    /**
     * H2N Pipe:
     *   Entry 0: IP src 192.168.102.31 -> port 0 (p0)
     */
    for (entry_index = 0; entry_index < NB_H2N_ENTRIES; entry_index++) {
        /* Match source ip address (if coming from host then forward) */
        match.outer.ip4.src_ip = BE_IPV4_ADDR(192, 168, 102, 31 + entry_index);

        /* Forward to network */
        fwd.type = DOCA_FLOW_FWD_PORT;
        fwd.port_id = entry_index;

        /* Offload flow rules */
        result =
            doca_flow_pipe_add_entry(0, pipe, &match, NULL, NULL, &fwd, flags,
                                     status, &h2n_entries[entry_index]);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to add pipe entry: %s",
                         doca_error_get_descr(result));
            return result;
        }
    }

    return DOCA_SUCCESS;
}

/*
 * Create DOCA Flow pipe with 5 tuple match on the switch port.
 * Matched traffic will be forwarded to the port defined per entry.
 * Unmatched traffic will be dropped.
 *
 * @sw_port [in]: switch port
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t create_switch_root_pipe(struct doca_flow_port *sw_port,
                                     struct doca_flow_pipe **pipe) {
    struct doca_flow_match match;
    struct doca_flow_monitor monitor;
    struct doca_flow_fwd fwd;
    struct doca_flow_pipe_cfg *pipe_cfg;
    doca_error_t result;
    struct doca_flow_fwd fwd_miss;

    memset(&match, 0, sizeof(match));
    memset(&monitor, 0, sizeof(monitor));
    memset(&fwd, 0, sizeof(fwd));
    memset(&fwd_miss, 0, sizeof(fwd_miss));

    // set match field
    // match.parser_meta.port_meta = UINT32_MAX;

    // match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_TCP;
    // match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP;
    match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
    match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;

    /* Source, destination IP addresses and source, destination TCP ports are
     * defined per entry */
    match.outer.ip4.dst_ip = UINT32_MAX;
    // match.outer.ip4.src_ip = 0xffffffff;
    // match.outer.tcp.l4_port.src_port = 0xffff;
    // match.outer.tcp.l4_port.dst_port = 0xffff;

    // monitor.shared_mirror_id = mirror_id;

    /* Pipe to forward to is defined per entry */
    fwd.type = DOCA_FLOW_FWD_PIPE;
    fwd.next_pipe = NULL;

    /* Missed packets forward to os kernel */
    // fwd_miss.type = DOCA_FLOW_FWD_PIPE;
    // fwd_miss.next_pipe = pipe_rss;

    monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, sw_port);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        return result;
    }

    result =
        set_flow_pipe_cfg(pipe_cfg, "SWITCH_PIPE", DOCA_FLOW_PIPE_BASIC, true);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, NB_ROOT_ENTRIES);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg nr_entries: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result =
        doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_DEFAULT);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg domain: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s",
                     doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }

    // result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
    result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe);
destroy_pipe_cfg:
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    return result;
}

/*
 * Add DOCA Flow pipe entry to the pipe
 *
 * @pipe [in]: pipe of the entry
 * @status [in]: user context for adding entry
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t add_switch_root_pipe_entries(struct doca_flow_pipe *pipe,
                                          struct entries_status *status) {
    struct doca_flow_match match;
    struct doca_flow_fwd fwd;
    enum doca_flow_flags_type flags = DOCA_FLOW_WAIT_FOR_BATCH;
    doca_error_t result;
    int entry_index = 0;

    memset(&fwd, 0, sizeof(fwd));
    memset(&match, 0, sizeof(match));

    /**
     * Root Pipe:
     *   Entry 0: IP dst 192.168.102.31 -> N2H pipe
     *   Entry 1: IP dst 192.168.102.25 -> H2N pipe
     */

    // doca_be32_t n2h_dip = BE_IPV4_ADDR(10, 156, 169, 28);
    doca_be32_t n2h_dip = BE_IPV4_ADDR(192, 168, 102, 31);
    doca_be32_t h2n_dip = BE_IPV4_ADDR(192, 168, 102, 25);
    for (entry_index = 0; entry_index < NB_ROOT_ENTRIES; entry_index++) {
        /* Set match fields of different direction */
        match.outer.ip4.dst_ip = entry_index ? h2n_dip : n2h_dip;

        /* Forward to next pipe according to the packet direction */
        fwd.type = DOCA_FLOW_FWD_PIPE;
        fwd.next_pipe = entry_index ? h2n_pipe : n2h_pipe;

        /* Offload flow rules */
        result =
            doca_flow_pipe_add_entry(0, pipe, &match, NULL, NULL, &fwd, flags,
                                     status, &root_entries[entry_index]);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to add pipe entry: %s",
                         doca_error_get_descr(result));
            return result;
        }
    }

    return DOCA_SUCCESS;
}

doca_error_t flow_switch_report() {
    int entry_idx = 0;
    doca_error_t result = DOCA_SUCCESS;
    struct doca_flow_query query_stats = {0};

    /* dump validation pipe entries counters */
    for (entry_idx = 0; entry_idx < NB_VALID_ENTRIES; entry_idx++) {
        result = doca_flow_query_entry(valid_entries[entry_idx], &query_stats);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to query entry: %s",
                         doca_error_get_descr(result));
            flow_switch_cleanup();
            return result;
        }
        DOCA_LOG_INFO("Valid Entry in index: %d", entry_idx);
        DOCA_LOG_INFO("Total bytes: %ld", query_stats.total_bytes);
        DOCA_LOG_INFO("Total packets: %ld", query_stats.total_pkts);
    }

    /* dump network to host pipe entries counters */
    for (entry_idx = 0; entry_idx < NB_N2H_ENTRIES; entry_idx++) {
        result = doca_flow_query_entry(n2h_entries[entry_idx], &query_stats);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to query entry: %s",
                         doca_error_get_descr(result));
            flow_switch_cleanup();
            return result;
        }
        DOCA_LOG_INFO("N2H Entry in index: %d", entry_idx);
        DOCA_LOG_INFO("Total bytes: %ld", query_stats.total_bytes);
        DOCA_LOG_INFO("Total packets: %ld", query_stats.total_pkts);
    }

    /* dump host to network pipe entries counters */
    for (entry_idx = 0; entry_idx < NB_H2N_ENTRIES; entry_idx++) {
        result = doca_flow_query_entry(h2n_entries[entry_idx], &query_stats);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to query vport pipe entry: %s",
                         doca_error_get_descr(result));
            flow_switch_cleanup();
            return result;
        }
        DOCA_LOG_INFO("H2N Entry in index: %d", entry_idx);
        DOCA_LOG_INFO("Total bytes: %ld", query_stats.total_bytes);
        DOCA_LOG_INFO("Total packets: %ld", query_stats.total_pkts);
    }

    /* dump root pipe entries counters */
    char root_idx2str[2][10] = {"n2h", "h2n"};
    for (entry_idx = 0; entry_idx < NB_ROOT_ENTRIES; entry_idx++) {
        result = doca_flow_query_entry(root_entries[entry_idx], &query_stats);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to query entry: %s",
                         doca_error_get_descr(result));
            flow_switch_cleanup();
            return result;
        }
        DOCA_LOG_INFO("Root Entry of <%s>:", root_idx2str[entry_idx]);
        DOCA_LOG_INFO("Total bytes: %ld", query_stats.total_bytes);
        DOCA_LOG_INFO("Total packets: %ld", query_stats.total_pkts);
    }

    /* dump rss pipe entries counters */
    result = doca_flow_query_entry(rss_entry, &query_stats);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to query entry: %s", doca_error_get_descr(result));
        flow_switch_cleanup();
        return result;
    }
    DOCA_LOG_INFO("RSS Entry in index: 0");
    DOCA_LOG_INFO("Total bytes: %ld", query_stats.total_bytes);
    DOCA_LOG_INFO("Total packets: %ld", query_stats.total_pkts);

    return result;
}

/*
 * Initialize flow switch logic for pipe matching and rules offloading
 *
 * @nb_queues [in]: number of queues the sample will use
 * @nb_ports [in]: number of ports the sample will use
 * @ctx [in]: flow swith context the sample will use
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t flow_switch_init(int nb_queues, int nb_ports,
                              struct flow_switch_ctx *ctx) {
    struct flow_resources resource = {0};
    uint32_t nr_shared_resources[SHARED_RESOURCE_NUM_VALUES] = {0};
    struct doca_dev *dev_arr[nb_ports];
    struct entries_status status;
    doca_error_t result;
    struct doca_dev *doca_dev = ctx->doca_dev[0];
    const char *start_str;
    struct doca_flow_port *switch_port = NULL;
    bool is_expert = ctx->is_expert;

    /* Set global variable here */
    nb_active_ports = nb_ports;

    /* Initialize */
    memset(&status, 0, sizeof(status));
    nr_shared_resources[DOCA_FLOW_SHARED_RESOURCE_MIRROR] = 4;
    resource.nr_counters = 2 * NB_TOTAL_ENTRIES; /* counter per entry */
    /* Use isolated mode as we will create the RSS pipe later */
    if (is_expert) {
        // ,hairpinq_num=4
        start_str = "switch,hws,isolated,expert";
        DOCA_LOG_INFO("expert mode!");
    } else {
        start_str = "switch,hws,isolated";
        DOCA_LOG_INFO("None expert mode!");
    }
    result =
        init_doca_flow(nb_queues, start_str, &resource, nr_shared_resources);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init DOCA Flow: %s",
                     doca_error_get_descr(result));
        return result;
    }

    /* Doca_dev is opened for proxy_port only */
    memset(dev_arr, 0, sizeof(struct doca_dev *) * nb_ports);
    dev_arr[0] = doca_dev;
    result = init_doca_flow_ports(nb_ports, active_ports,
                                  false /* is_hairpin */, dev_arr);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init DOCA ports: %s",
                     doca_error_get_descr(result));
        doca_flow_destroy();
        return result;
    }
    switch_port = doca_flow_port_switch_get(active_ports[0]);

    /* Create rss pipe and entry */
    result = create_rss_pipe(switch_port, &pipe_rss, nb_queues);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create rss pipe: %s",
                     doca_error_get_descr(result));
        flow_switch_cleanup();
        return result;
    }
    result = add_rss_pipe_entry(pipe_rss, &status);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add entry: %s", doca_error_get_descr(result));
        flow_switch_cleanup();
        return result;
    }
    DOCA_LOG_INFO("Rss pipe and its entries added successfully");

    /* Create valid pipe and entries */
    result = create_switch_valid_pipe(switch_port, &pipe_valid);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create valid pipe: %s",
                     doca_error_get_descr(result));
        flow_switch_cleanup();
        return result;
    }
    result = add_switch_valid_pipe_entries(pipe_valid, &status);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add valid_entries to the pipe: %s",
                     doca_error_get_descr(result));
        flow_switch_cleanup();
        return result;
    }
    DOCA_LOG_INFO("Validation pipe and its entries added successfully");

    /* Create network to host pipe and entries */
    result = create_switch_n2h_pipe(switch_port, &n2h_pipe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create egress pipe: %s",
                     doca_error_get_descr(result));
        flow_switch_cleanup();
        return result;
    }
    result = add_switch_n2h_pipe_entries(n2h_pipe, &status);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add n2h_entries to the pipe: %s",
                     doca_error_get_descr(result));
        flow_switch_cleanup();
        return result;
    }
    DOCA_LOG_INFO("N2H pipe and its entries added successfully");

    /* Create host to network pipe and entries */
    result = create_switch_h2n_pipe(switch_port, &h2n_pipe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create vport pipe: %s",
                     doca_error_get_descr(result));
        flow_switch_cleanup();
        return result;
    }
    result = add_switch_h2n_pipe_entries(h2n_pipe, &status);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add h2n_entries to the pipe: %s",
                     doca_error_get_descr(result));
        flow_switch_cleanup();
        return result;
    }
    DOCA_LOG_INFO("H2N pipe and its entries added successfully");

    /* Create root pipe and entries */
    result = create_switch_root_pipe(switch_port, &root_pipe);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create ingress pipe: %s",
                     doca_error_get_descr(result));
        flow_switch_cleanup();
        return result;
    }
    result = add_switch_root_pipe_entries(root_pipe, &status);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to add root_entries to the pipe: %s",
                     doca_error_get_descr(result));
        flow_switch_cleanup();
        return result;
    }
    DOCA_LOG_INFO("Root pipe and its entries added successfully");

    /* Ensure all entries are offloaded */
    result = doca_flow_entries_process(switch_port, 0, DEFAULT_TIMEOUT_US,
                                       NB_TOTAL_ENTRIES);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to process n2h_entries: %s",
                     doca_error_get_descr(result));
        flow_switch_cleanup();
        return result;
    }
    if (status.nb_processed != NB_TOTAL_ENTRIES || status.failure) {
        DOCA_LOG_ERR("Failed to process all entries, process entries = %d "
                     "(expected %d), status = %d",
                     status.nb_processed, NB_TOTAL_ENTRIES, status.failure);
        flow_switch_cleanup();
        return DOCA_ERROR_BAD_STATE;
    }
    DOCA_LOG_INFO("Pipes and their entries are offloaded successfully.");

    return result;
}

doca_error_t flow_switch_cleanup() {
    doca_error_t result;
    result = stop_doca_flow_ports(nb_active_ports, active_ports);
    doca_flow_destroy();
    return result;
}
