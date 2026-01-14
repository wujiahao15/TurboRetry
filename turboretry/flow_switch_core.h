#ifndef FLOW_SWITCH_CORE_H_
#define FLOW_SWITCH_CORE_H_

#include <doca_error.h>
#include <doca_flow.h>
#include <doca_flow_crypto.h>

#include "flow_common.h"
#include "flow_switch_common.h"

doca_error_t flow_switch_init(int nb_queues, int nb_ports,
                              struct flow_switch_ctx *ctx);
doca_error_t flow_switch_cleanup();
doca_error_t flow_switch_report();

doca_error_t create_rss_pipe(struct doca_flow_port *port,
                             struct doca_flow_pipe **pipe, int nb_queues);
doca_error_t add_rss_pipe_entry(struct doca_flow_pipe *pipe,
                                struct entries_status *status);

doca_error_t create_switch_valid_pipe(struct doca_flow_port *sw_port,
                                      struct doca_flow_pipe **pipe);
doca_error_t add_switch_valid_pipe_entries(struct doca_flow_pipe *pipe,
                                           struct entries_status *status);

doca_error_t create_switch_n2h_pipe(struct doca_flow_port *sw_port,
                                    struct doca_flow_pipe **pipe);
doca_error_t add_switch_n2h_pipe_entries(struct doca_flow_pipe *pipe,
                                         struct entries_status *status);

doca_error_t create_switch_h2n_pipe(struct doca_flow_port *sw_port,
                                    struct doca_flow_pipe **pipe);
doca_error_t add_switch_h2n_pipe_entries(struct doca_flow_pipe *pipe,
                                         struct entries_status *status);

doca_error_t create_switch_root_pipe(struct doca_flow_port *sw_port,
                                     struct doca_flow_pipe **pipe);
doca_error_t add_switch_root_pipe_entries(struct doca_flow_pipe *pipe,
                                          struct entries_status *status);

#endif