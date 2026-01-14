/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
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

#ifndef FLOW_SWITCH_COMMON_H_
#define FLOW_SWITCH_COMMON_H_

#include <rte_byteorder.h>

#include <doca_flow.h>
#include <doca_dev.h>

#define FLOW_SWITCH_PORTS_MAX (2)

/* doca flow switch context */
struct flow_switch_ctx {
	bool is_expert;					  /* switch expert mode */
	uint16_t nb_ports;				  /* switch port number */
	uint16_t nb_reps;				  /* switch port number */
	const char *dev_arg[FLOW_SWITCH_PORTS_MAX];	  /* dpdk dev_arg */
	const char *rep_arg[FLOW_SWITCH_PORTS_MAX];	  /* dpdk rep_arg */
	struct doca_dev *doca_dev[FLOW_SWITCH_PORTS_MAX]; /* port doca_dev */
};

/*
 * Init DOCA Flow switch
 *
 * @argc [in]: dpdk argc
 * @dpdk_argv [in]: dpdk argv
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t init_flow_switch_dpdk(int argc, char **dpdk_argv);

/*
 * Register DOCA Flow switch parameter
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t register_doca_flow_switch_param(void);

/*
 * Init DOCA Flow switch
 *
 * @ctx [in]: flow switch context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t init_doca_flow_switch_common(struct flow_switch_ctx *ctx);

/*
 * Destroy dOCA Flow switch context
 *
 * @ctx [in]: flow switch context
 */
void destroy_doca_flow_switch_common(struct flow_switch_ctx *ctx);

#endif /* FLOW_SWITCH_COMMON_H_ */
