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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <artik_module.h>
#include <artik_http.h>
#include <artik_loop.h>
#include <artik_log.h>
#include <artik_network.h>

#include "os_network.h"

static const char geoipdb_root_ca[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\n"
	"MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n"
	"DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\n"
	"PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\n"
	"Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"
	"AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\n"
	"rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\n"
	"OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\n"
	"xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\n"
	"7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\n"
	"aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\n"
	"HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\n"
	"SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\n"
	"ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\n"
	"AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\n"
	"R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\n"
	"JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\n"
	"Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\n"
	"-----END CERTIFICATE-----\n";

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
static artik_error artik_add_watch_online_status(
		watch_online_status_handle * handle,
		watch_online_status_callback app_callback,
		void *user_data);
static artik_error artik_remove_watch_online_status(
		watch_online_status_handle handle);

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
	char delimiter[] = "\"";
	unsigned int size = 0;
	artik_ssl_config ssl;

	log_dbg("");

	memset(&ssl, 0, sizeof(artik_ssl_config));
	ssl.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;
	ssl.ca_cert.data = (char *)geoipdb_root_ca;
	ssl.ca_cert.len = sizeof(geoipdb_root_ca);

	/* Perform the request */
	ret = http->get("http://geoip.nekudo.com/api", NULL, &response, NULL, &ssl);
	if (ret != S_OK)
		goto exit;

	point = strstr(response, "\"ip\":");
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
exit:
	artik_release_api_module(http);

	return ret;
}

artik_error artik_get_online_status(bool *online_status)
{
	artik_network_ip current_ip;
	artik_error ret = artik_get_current_public_ip(&current_ip);

	if (ret == S_OK)
		*online_status = true;
	else if (ret == E_HTTP_ERROR) {
		*online_status = false;
		ret = S_OK;
	}

	return ret;
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

artik_error artik_add_watch_online_status(watch_online_status_handle *handle,
				watch_online_status_callback app_callback,
				void *user_data)
{
	return os_network_add_watch_online_status(handle, app_callback,
							user_data);
}

artik_error artik_remove_watch_online_status(watch_online_status_handle handle)
{
	return os_network_remove_watch_online_status(handle);
}
