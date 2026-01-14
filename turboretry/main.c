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
#include <stdlib.h>

#include <rte_ethdev.h>
#include <rte_lcore.h>

#include <doca_argp.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_flow.h>
#include <doca_log.h>

#include <dpdk_utils.h>

#include "flow_switch_core.h"
#include "retry_fwd_core.h"

DOCA_LOG_REGISTER(RETRY_BASELINE_MAIN);

#define NUM_SWITCH_PORTS 2

/*
 * App main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int main(int argc, char **argv) {
    uint16_t nr_ports = 0;
    int exit_status = EXIT_FAILURE;
    doca_error_t result = DOCA_SUCCESS;
    struct doca_log_backend *sdk_log = NULL;
    struct flow_switch_ctx ctx = {0};
    struct application_dpdk_config dpdk_config = {
        .port_config.nb_ports = NUM_SWITCH_PORTS,
        .port_config.nb_queues = 1,
        .port_config.isolated_mode = 1,
        .port_config.switch_mode = 1,
        .reserve_main_thread = true,
    };
    struct app_resources app_resources = {0};

    /* Register a logger backend */
    result = doca_log_backend_create_standard();
    if (result != DOCA_SUCCESS)
        goto app_exit;

    /* Register a logger backend for internal SDK errors and warnings */
    result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
    if (result != DOCA_SUCCESS)
        goto app_exit;
    result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
    if (result != DOCA_SUCCESS)
        goto app_exit;

    /* Initialize doca command line arguments */
    result = doca_argp_init("doca_retry_baseline", &ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init ARGP resources: %s",
                     doca_error_get_descr(result));
        goto app_exit;
    }
    result = register_doca_flow_switch_param();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register flow param: %s",
                     doca_error_get_descr(result));
        goto argp_cleanup;
    }
    doca_argp_set_dpdk_program(init_flow_switch_dpdk);
    result = doca_argp_start(argc, argv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to parse sample input: %s",
                     doca_error_get_descr(result));
        goto argp_cleanup;
    }

    /* Init doca flow switch resources */
    result = init_doca_flow_switch_common(&ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init flow switch common: %s",
                     doca_error_get_descr(result));
        goto dpdk_cleanup;
    }

    /* Check the number of available ports */
    nr_ports = rte_eth_dev_count_avail();
    if (nr_ports < NUM_SWITCH_PORTS) {
        DOCA_LOG_ERR("Failed to init - lack of ports, probed:%d, needed:%d",
                     nr_ports, NUM_SWITCH_PORTS);
        goto dpdk_cleanup;
    }

    /* update queues and ports */
    result = dpdk_queues_and_ports_init(&dpdk_config);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to update ports and queues");
        goto dpdk_cleanup;
    }

    /* Register signal handler for gracefully exiting */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* run sample */
    result = flow_switch_init(dpdk_config.port_config.nb_queues,
                              NUM_SWITCH_PORTS, &ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("flow_switch_init() encountered an error: %s",
                     doca_error_get_descr(result));
        goto dpdk_ports_queues_cleanup;
    }

    /* print information of queues and ports */
    DOCA_LOG_INFO("# of queues = %d", dpdk_config.port_config.nb_queues);
    DOCA_LOG_INFO("# of ports  = %d", dpdk_config.port_config.nb_ports);
    DOCA_LOG_INFO("# of cores  = %d", rte_lcore_count());

    /* initialize program resources */
    app_resources.nb_cores = rte_lcore_count();
    result = program_resources_init(&app_resources);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to update application ports and queues: %s",
                     doca_error_get_descr(result));
        goto resources_destroy;
    }

    /*
     * Below comment code will launch programs across all lcores
     * Note that only one port is initialized in DPDK
     * So the nb_ports is set 1 in function call of `retry_fwd_map_queue`
     */
    retry_fwd_map_queue(dpdk_config.port_config.nb_queues, NUM_OF_DPDK_PORTS);
    DOCA_LOG_INFO("Resources preparation is done!");
    // rte_eal_mp_remote_launch(retry_fwd_process_pkts, &app_resources,
    // CALL_MAIN);
    // rte_eal_mp_remote_launch(handle_rx_tx_pkts, &app_resources, SKIP_MAIN);
    rte_eal_mp_remote_launch(handle_rx_tx_pkts, &app_resources, CALL_MAIN);
    rte_eal_mp_wait_lcore();
    // handle_rx_tx_pkts(&app_resources);

    exit_status = EXIT_SUCCESS;

resources_destroy:
    program_resources_cleanup(&app_resources);
    flow_switch_cleanup();
dpdk_ports_queues_cleanup:
    dpdk_queues_and_ports_fini(&dpdk_config);
dpdk_cleanup:
    dpdk_fini();
argp_cleanup:
    doca_argp_destroy();
app_exit:
    destroy_doca_flow_switch_common(&ctx);
    if (exit_status == EXIT_SUCCESS)
        DOCA_LOG_INFO("Application finished successfully");
    else
        DOCA_LOG_INFO("Application finished with errors");
    return exit_status;
}
