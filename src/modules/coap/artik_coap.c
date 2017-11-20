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

#include <artik_module.h>
#include <artik_coap.h>

#include "os_coap.h"

static artik_error create_client(artik_coap_handle * client,
				artik_coap_config * config);
static artik_error destroy_client(artik_coap_handle client);
static artik_error connect(artik_coap_handle client);
static artik_error disconnect(artik_coap_handle client);
static artik_error create_server(artik_coap_handle *server,
				artik_coap_config *config);
static artik_error destroy_server(artik_coap_handle server);
static artik_error start_server(artik_coap_handle server);
static artik_error stop_server(artik_coap_handle server);
static artik_error send_message(artik_coap_handle handle,
				const char *path,
				artik_coap_msg *msg);
static artik_error observe(artik_coap_handle handle,
				const char *path,
				artik_coap_msg_type msg_type,
				artik_coap_option *options,
				int num_options,
				unsigned char *token,
				unsigned long token_len);
static artik_error cancel_observe(artik_coap_handle handle,
				const char *path,
				unsigned char *token,
				unsigned long token_len);
static artik_error init_resources(artik_coap_handle handle,
				artik_coap_resource *resources,
				int num_resources);
static artik_error notify_resource_changed(artik_coap_handle handle,
				const char *path);
static artik_error set_send_callback(artik_coap_handle handle,
				artik_coap_send_callback callback,
				void *user_data);
static artik_error set_observe_callback(artik_coap_handle handle,
				artik_coap_observe_callback callback,
				void *user_data);
static artik_error set_verify_psk_callback(artik_coap_handle handle,
				artik_coap_verify_psk_callback callback,
				void *user_data);

const artik_coap_module coap_module = {
	create_client,
	destroy_client,
	connect,
	disconnect,
	create_server,
	destroy_server,
	start_server,
	stop_server,
	send_message,
	observe,
	cancel_observe,
	init_resources,
	notify_resource_changed,
	set_send_callback,
	set_observe_callback,
	set_verify_psk_callback
};

artik_error create_client(artik_coap_handle *client,
			artik_coap_config *config)
{
	return os_coap_create_client(client, config);
}

artik_error destroy_client(artik_coap_handle client)
{
	return os_coap_destroy_client(client);
}

artik_error connect(artik_coap_handle client)
{
	return os_coap_connect(client);
}

artik_error disconnect(artik_coap_handle client)
{
	return os_coap_disconnect(client);
}

artik_error create_server(artik_coap_handle *server,
			artik_coap_config *config)
{
	return os_coap_create_server(server, config);
}

artik_error destroy_server(artik_coap_handle server)
{
	return os_coap_destroy_server(server);
}

artik_error start_server(artik_coap_handle server)
{
	return os_coap_start_server(server);
}

artik_error stop_server(artik_coap_handle server)
{
	return os_coap_stop_server(server);
}

artik_error send_message(artik_coap_handle handle,
			const char *path,
			artik_coap_msg *msg)
{
	return os_coap_send_message(handle, path, msg);
}

artik_error observe(artik_coap_handle handle,
			const char *path,
			artik_coap_msg_type msg_type,
			artik_coap_option *options,
			int num_options,
			unsigned char *token,
			unsigned long token_length)
{
	return os_coap_observe(handle, path, msg_type, options, num_options,
				token, token_length);
}

artik_error cancel_observe(artik_coap_handle handle,
			const char *path,
			unsigned char *token,
			unsigned long token_length)
{
	return os_coap_cancel_observe(handle, path, token, token_length);
}

artik_error init_resources(artik_coap_handle handle,
			artik_coap_resource *resources,
			int num_resources)
{
	return os_coap_init_resources(handle, resources, num_resources);
}

artik_error notify_resource_changed(artik_coap_handle handle,
			const char *path)
{
	return os_coap_notify_resource_changed(handle, path);
}

artik_error set_send_callback(artik_coap_handle handle,
			artik_coap_send_callback callback,
			void *user_data)
{
	return os_coap_set_send_callback(handle, callback, user_data);
}

artik_error set_observe_callback(artik_coap_handle handle,
			artik_coap_observe_callback callback,
			void *user_data)
{
	return os_coap_set_observe_callback(handle, callback, user_data);
}

artik_error set_verify_psk_callback(artik_coap_handle handle,
			artik_coap_verify_psk_callback callback,
			void *user_data)
{
	return os_coap_set_verify_psk_callback(handle, callback, user_data);
}
