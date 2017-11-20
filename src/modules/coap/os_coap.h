/*
 *
 * Copyright 2017 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 */

#ifndef __OS_COAP_H__
#define __OS_COAP_H__

#include <artik_error.h>
#include <artik_coap.h>

artik_error os_coap_create_client(artik_coap_handle * client,
				artik_coap_config * config);
artik_error os_coap_destroy_client(artik_coap_handle client);
artik_error os_coap_connect(artik_coap_handle client);
artik_error os_coap_disconnect(artik_coap_handle client);
artik_error os_coap_create_server(artik_coap_handle *server,
				artik_coap_config *config);
artik_error os_coap_destroy_server(artik_coap_handle server);
artik_error os_coap_start_server(artik_coap_handle server);
artik_error os_coap_stop_server(artik_coap_handle server);
artik_error os_coap_send_message(artik_coap_handle handle,
				const char *path,
				artik_coap_msg *msg);
artik_error os_coap_observe(artik_coap_handle handle,
				const char *path,
				artik_coap_msg_type msg_type,
				artik_coap_option *options,
				int num_options,
				unsigned char *token,
				unsigned long token_len);
artik_error os_coap_cancel_observe(artik_coap_handle handle,
				const char *path,
				unsigned char *token,
				unsigned long token_len);
artik_error os_coap_init_resources(artik_coap_handle handle,
				artik_coap_resource *resources,
				int num_resources);
artik_error os_coap_notify_resource_changed(artik_coap_handle handle,
				const char *path);
artik_error os_coap_set_send_callback(artik_coap_handle handle,
				artik_coap_send_callback callback,
				void *user_data);
artik_error os_coap_set_observe_callback(artik_coap_handle handle,
				artik_coap_observe_callback callback,
				void *user_data);
artik_error os_coap_set_verify_psk_callback(artik_coap_handle handle,
				artik_coap_verify_psk_callback callback,
				void *user_data);
#endif /* __OS_COAP_H__ */
