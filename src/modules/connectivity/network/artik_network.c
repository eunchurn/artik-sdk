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

#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <artik_module.h>
#include <artik_http.h>
#include <artik_log.h>
#include <artik_network.h>

#include <unistd.h>

#include "common_network.h"
#include "os_network.h"

#define ARTIK_CURRENT_IP_URL	"http://www.checkip.org/"
#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))

static artik_error artik_set_network_config(
		artik_network_config * config,
		artik_network_interface_t interface);
static artik_error artik_get_network_config(
		artik_network_config * config,
		artik_network_interface_t interface);
static artik_error artik_dhcp_client_start(
		artik_network_dhcp_client_handle * handle,
		artik_network_interface_t interface);
static artik_error artik_dhcp_client_stop(
		artik_network_dhcp_client_handle handle);
static artik_error artik_dhcp_server_start(
		artik_network_dhcp_server_handle * handle,
		artik_network_dhcp_server_config *config);
static artik_error artik_dhcp_server_stop(
		artik_network_dhcp_server_handle handle);
static artik_error artik_get_online_status(
	const char *addr, int timeout, bool *online_status);
static artik_error artik_add_watch_online_status(
		artik_watch_online_status_handle * handle,
		const char *url,
		int delay,
		int timeout,
		artik_watch_online_status_callback app_callback,
		void *user_data);
static artik_error artik_remove_watch_online_status(
		artik_watch_online_status_handle handle);

const artik_network_module network_module = {
		artik_set_network_config,
		artik_get_network_config,
		artik_get_current_public_ip,
		artik_dhcp_client_start,
		artik_dhcp_client_stop,
		artik_dhcp_server_start,
		artik_dhcp_server_stop,
		artik_get_online_status,
		artik_add_watch_online_status,
		artik_remove_watch_online_status
};

artik_error artik_get_current_public_ip(artik_network_ip *ip)
{
	artik_http_module *http = (artik_http_module *)
					artik_request_api_module("http");
	artik_error ret = S_OK;
	int i = 0;
	char *response = NULL;
	char *point;
	char *token = NULL;
	char delimiter[] = "<>";
	unsigned int size = 0;
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"user-agent", "Artik browser"},
		{"Accept-Language", "en-US,en;q=0.8"},
	};

	log_dbg("");

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Perform the request */
	ret = http->get(ARTIK_CURRENT_IP_URL, &headers, &response, NULL, NULL);
	if (ret != S_OK)
		goto exit;

	point = strstr(response, "Your IP Address:");
	if (point != NULL) {
		token = strtok(point, delimiter);
		for (i = 0; token != NULL && i < 2; i++) {
			token = strtok(NULL, delimiter);
			size = strlen(token);
		}
		if (size > 0 && size < MAX_IP_ADDRESS_LEN) {
			strncpy(ip->address, token, size);
			ip->address[size] = '\0';
		}
	}

	free(response);

exit:
	artik_release_api_module(http);

	return ret;
}

artik_error artik_get_online_status(const char *addr, int timeout, bool *online_status)
{
	char buf[64];
	int sock;
	socklen_t fromlen;
	struct sockaddr_storage from;
	struct sockaddr_storage to;

	if (!online_status || !addr || !(timeout > 0))
		return E_BAD_ARGS;

	log_dbg("");

	*online_status = false;

	int err = resolve(addr, &to);

	if (err != 0)
		return E_NETWORK_ERROR;

	sock = create_icmp_socket(timeout);
	if (sock < 0)
		return E_NETWORK_ERROR;

	if (!os_send_echo(sock, (struct sockaddr *)&to, 0)) {
		close(sock);
		return E_NETWORK_ERROR;
	}

	size_t len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);

	if (len <= 0) {
		log_dbg("recvfrom: unable to receive data");
		close(sock);
		return E_NETWORK_ERROR;
	}
	close(sock);

	if (!os_check_echo_response(buf, len, 0))
		return E_NETWORK_ERROR;

	*online_status = true;
	return S_OK;
}

artik_error artik_dhcp_client_start(artik_network_dhcp_client_handle *handle,
		artik_network_interface_t interface)
{
	return os_dhcp_client_start(handle, interface);
}

artik_error artik_dhcp_client_stop(artik_network_dhcp_client_handle handle)
{
	return os_dhcp_client_stop(handle);
}

artik_error artik_dhcp_server_start(artik_network_dhcp_server_handle *handle,
		artik_network_dhcp_server_config *config)
{
	return os_dhcp_server_start(handle, config);
}

artik_error artik_dhcp_server_stop(artik_network_dhcp_server_handle handle)
{
	return os_dhcp_server_stop(handle);
}

artik_error artik_set_network_config(artik_network_config *config,
		artik_network_interface_t interface)
{
	return os_set_network_config(config, interface);
}

artik_error artik_get_network_config(artik_network_config *config,
		artik_network_interface_t interface)
{
	return os_get_network_config(config, interface);
}

artik_error artik_add_watch_online_status(artik_watch_online_status_handle *handle,
				const char *url,
				int delay,
				int timeout,
				artik_watch_online_status_callback app_callback,
				void *user_data)
{
	return os_network_add_watch_online_status(handle, url, delay, timeout, app_callback,
							user_data);
}

artik_error artik_remove_watch_online_status(artik_watch_online_status_handle handle)
{
	return os_network_remove_watch_online_status(handle);
}
