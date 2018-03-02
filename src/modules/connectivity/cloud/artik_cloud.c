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

#include <artik_module.h>
#include <artik_http.h>
#include <artik_websocket.h>
#include <artik_cloud.h>
#include <artik_log.h>
#include <artik_list.h>
#include <artik_loop.h>
#include <artik_security.h>

#define ARTIK_CLOUD_URL_MAX			256
#define ARTIK_CLOUD_URL(x)			("https://api.artik.cloud"\
						"/v1.1/" x)
#define ARTIK_CLOUD_URL_MESSAGES		ARTIK_CLOUD_URL("messages")
#define ARTIK_CLOUD_URL_SELF_USER		ARTIK_CLOUD_URL("users/self")
#define ARTIK_CLOUD_URL_USER_DEVICES		ARTIK_CLOUD_URL("users/%s/"\
						"devices?count=%d&include"\
						"Properties=%s&offset=%d")
#define ARTIK_CLOUD_URL_USER_DEVICE_TYPES	ARTIK_CLOUD_URL("users/%s/"\
						"devicetypes?count=%d&include"\
						"Shared=%s&offset=%d")
#define ARTIK_CLOUD_URL_USER_APP_PROPS		ARTIK_CLOUD_URL("users/%s/"\
						"properties?aid=%s")
#define ARTIK_CLOUD_URL_GET_DEVICE		ARTIK_CLOUD_URL("devices/%s?"\
						"properties=%s")
#define ARTIK_CLOUD_URL_DELETE_DEVICE		ARTIK_CLOUD_URL("devices/%s")
#define ARTIK_CLOUD_URL_ADD_DEVICE		ARTIK_CLOUD_URL("devices")
#define ARTIK_CLOUD_ADD_DEVICE_BODY		"{\"uid\": \"%s\", \"dtid\":"\
						" \"%s\",\"name\": \"%s\", \""\
						"manifestVersionPolicy\": \""\
						"LATEST\"}"
#define ARTIK_CLOUD_URL_GET_DEVICE_TOKEN	ARTIK_CLOUD_URL("devices/%s/"\
						"tokens")
#define ARTIK_CLOUD_URL_UPDATE_DEVICE_TOKEN	ARTIK_CLOUD_URL("devices/%s/"\
						"tokens")
#define ARTIK_CLOUD_URL_DELETE_DEVICE_TOKEN	ARTIK_CLOUD_URL("devices/%s/"\
						"tokens")
#define ARTIK_CLOUD_URL_GET_DEVICE_PROPS	ARTIK_CLOUD_URL("devicemgmt/"\
						"devices/%s/properties?"\
						"includeTimestamp=%s")
#define ARTIK_CLOUD_URL_SET_DEVICE_SERV_PROPS	ARTIK_CLOUD_URL("devicemgmt/"\
						"devices/%s/serverproperties")

#define ARTIK_CLOUD_SECURE_URL(x)		("https://s-api.artik.cloud/"\
						"v1.1/" x)
#define ARTIK_CLOUD_SECURE_URL_REG_DEVICE	ARTIK_CLOUD_SECURE_URL("cert/"\
						"devices/registrations")
#define ARTIK_CLOUD_SECURE_URL_REG_ID		ARTIK_CLOUD_SECURE_URL("cert/"\
						"devices/registrations/%s")
#define ARTIK_CLOUD_SECURE_URL_REG_STATUS	ARTIK_CLOUD_SECURE_URL("cert/"\
						"devices/registrations/%s/"\
						"status")
#define ARTIK_CLOUD_MESSAGE_BODY		"{\"type\": \"message\",\""\
						"sdid\": \"%s\",\"data\": %s}"
#define ARTIK_CLOUD_ACTION_BODY			"{\"type\": \"action\",\""\
						"ddid\": \"%s\",\"data\": %s}"
#define ARTIK_CLOUD_SECURE_REG_DEVICE_BODY	"{\"deviceTypeId\":\"%s\",\""\
						"vendorDeviceId\":\"%s\"}"
#define ARTIK_CLOUD_SECURE_REG_COMPLETE_BODY	"{\"nonce\":\"%s\"}"

#define ARTIK_CLOUD_SECURE_URL_DELETE_DEVICE ARTIK_CLOUD_SECURE_URL("devices/%s")
#define ARTIK_CLOUD_SECURE_URL_ADD_DEVICE	ARTIK_CLOUD_SECURE_URL("devices")
#define ARTIK_CLOUD_SECURE_URL_MESSAGES		ARTIK_CLOUD_SECURE_URL("messages")
#define ARTIK_CLOUD_SECURE_URL_SELF_USER	ARTIK_CLOUD_SECURE_URL("users/self")
#define ARTIK_CLOUD_SECURE_URL_USER_DEVICES	ARTIK_CLOUD_SECURE_URL("users/%s/"\
						"devices?count=%d&include"\
						"Properties=%s&offset=%d")
#define ARTIK_CLOUD_SECURE_URL_USER_DEVICE_TYPES ARTIK_CLOUD_SECURE_URL("users"\
						"/%s/devicetypes?count=%d&includeShared=%s&offset=%d")
#define ARTIK_CLOUD_SECURE_URL_UPDATE_DEVICE_TOKEN ARTIK_CLOUD_SECURE_URL("dev"\
						"ices/%s/tokens")
#define ARTIK_CLOUD_SECURE_URL_DELETE_DEVICE_TOKEN ARTIK_CLOUD_SECURE_URL("dev"\
						"ices/%s/tokens")
#define ARTIK_CLOUD_SECURE_URL_GET_DEVICE_PROPS	ARTIK_CLOUD_SECURE_URL("devicemgmt/"\
						"devices/%s/properties?"\
						"includeTimestamp=%s")
#define ARTIK_CLOUD_SECURE_URL_SET_DEVICE_SERV_PROPS ARTIK_CLOUD_SECURE_URL("devicemgmt/"\
						"devices/%s/serverproperties")
#define ARTIK_CLOUD_TOKEN_MAX			128
#define ARTIK_CLOUD_DTID_MAX			64
#define ARTIK_CLOUD_VDID_MAX			64
#define ARTIK_CLOUD_RID_MAX			64
#define ARTIK_CLOUD_NONCE_MAX			64

#define ARTIK_CLOUD_WEBSOCKET_STR_MAX		1024
#define ARTIK_CLOUD_WEBSOCKET_HOST		"api.artik.cloud"
#define ARTIK_CLOUD_WEBSOCKET_PATH		"/v1.1/websocket?ack=true"
#define ARTIK_CLOUD_WEBSOCKET_MESSAGE_BODY	"{\"sdid\":\"%s\",\""\
						"Authorization\":\"bearer "\
						"%s\",\"type\":\"%s\"}"
#define ARTIK_CLOUD_WEBSOCKET_SEND_MESSAGE_BODY	"{\"sdid\":\"%s\",\"type"\
						"\":\"%s\",\"data\":%s}"
#define ARTIK_CLOUD_WEBSOCKET_PORT		443
#define ARTIK_CLOUD_SECURE_WEBSOCKET_HOST	"s-api.artik.cloud"

#define ARRAY_SIZE(a)				(sizeof(a) / sizeof((a)[0]))


typedef struct artik_cloud_reg_data_t {
	artik_websocket_handle handle;
	char registration_message[ARTIK_CLOUD_WEBSOCKET_STR_MAX];
	char *access_token;
	char *device_id;
	artik_websocket_callback callback;
	void *callback_data;
} artik_cloud_reg_data;

typedef struct {
	artik_list node;
	artik_cloud_reg_data data;
} cloud_node;

typedef struct {
	artik_cloud_callback callback;
	void *user_data;
	artik_http_module *http_module;
} artik_cloud_async;

typedef struct {
	char **response;
	artik_cloud_callback callback;
	void *user_data;
	artik_ssl_config *ssl_config;
} artik_cloud_http_request;

static artik_list *requested_node = NULL;

static artik_error send_message(const char *access_token, const char *device_id,
	const char *message, char **response,
	artik_ssl_config *ssl_config);
static artik_error send_message_async(const char *access_token,
	const char *device_id,
	const char *message,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error send_action(const char *access_token, const char *device_id,
	const char *action, char **response,
	artik_ssl_config *ssl_config);
static artik_error send_action_async(const char *access_token,
	const char *device_id,
	const char *action,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error get_current_user_profile(const char *access_token,
	char **response,
	artik_ssl_config *ssl_config);
static artik_error get_current_user_profile_async(const char
	*access_token,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error get_user_devices(const char *access_token, int count,
	bool properties, int offset,
	const char *user_id, char **response,
	artik_ssl_config *ssl_config);
static artik_error get_user_devices_async(const char *access_token,
	int count, bool properties,
	int offset,
	const char *user_id,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error get_user_device_types(const char *access_token, int count,
	bool shared, int offset,
	const char *user_id, char **response,
	artik_ssl_config *ssl_config);
static artik_error get_user_device_types_async(
	const char *access_token,
	int count, bool shared,
	int offset,
	const char *user_id,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error get_user_application_properties(const char *access_token,
	const char *user_id,
	const char *app_id,
	char **response,
	artik_ssl_config *ssl_config);
static artik_error get_user_application_properties_async(const char
	*access_token,
	const char
	*user_id,
	const char
	*app_id,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error get_device(const char *access_token, const char *device_id,
	bool properties, char **response,
	artik_ssl_config *ssl_config);
static artik_error get_device_async(const char *access_token,
	const char *device_id,
	bool properties,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error get_device_token(const char *access_token,
	const char *device_id, char **response,
	artik_ssl_config *ssl_config);
static artik_error get_device_token_async(const char *access_token,
	const char *device_id,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error add_device(const char *access_token,
	const char *user_id, const char *dt_id,
	const char *name, char **response,
	artik_ssl_config *ssl_config);
static artik_error add_device_async(
	const char *access_token,
	const char *user_id,
	const char *dt_id,
	const char *name,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error update_device_token(const char *access_token,
	const char *device_id, char **response,
	artik_ssl_config *ssl_config);
static artik_error update_device_token_async(
	const char *access_token,
	const char *device_id,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error delete_device_token(
	const char *access_token,
	const char *device_id, char **response,
	artik_ssl_config *ssl_config);
static artik_error delete_device_token_async(
	const char *access_token,
	const char *device_id,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error delete_device(const char *access_token,
	const char *device_id, char **response,
	artik_ssl_config *ssl_config);
static artik_error delete_device_async(
	const char *access_token,
	const char *device_id,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error get_device_properties(const char *access_token,
	const char *device_id,
	bool timestamp,
	char **response,
	artik_ssl_config *ssl_config);
static artik_error get_device_properties_async(
	const char *access_token,
	const char *device_id,
	bool timestamp,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error set_device_server_properties(const char *access_token,
	const char *device_id,
	const char *data,
	char **response,
	artik_ssl_config *ssl_config);
static artik_error set_device_server_properties_async(
	const char *access_token,
	const char *device_id,
	const char *data,
	artik_cloud_callback callback,
	void *user_data,
	artik_ssl_config *ssl);
static artik_error sdr_start_registration(
	const char *cert_name,
	const char *device_type_id,
	const char *vendor_id,
	char **response);
static artik_error sdr_start_registration_async(
	const char *cert_name,
	const char *device_type_id,
	const char *vendor_id,
	artik_cloud_callback callback,
	void *user_data);
static artik_error sdr_registration_status(
	const char *cert_name,
	const char *reg_id,
	char **response);
static artik_error sdr_registration_status_async(
	const char *cert_name,
	const char *reg_id,
	artik_cloud_callback callback,
	void *user_data);
static artik_error sdr_complete_registration(
	const char *cert_name,
	const char *reg_id,
	const char *reg_nonce,
	char **response);
static artik_error sdr_complete_registration_async(
	const char *cert_name,
	const char *reg_id,
	const char *reg_nonce,
	artik_cloud_callback callback,
	void *user_data);
static artik_error websocket_open_stream(artik_websocket_handle *handle,
	const char *access_token,
	const char *device_id,
	unsigned int ping_period,
	unsigned int pong_timeout,
	artik_ssl_config *ssl_config);
static artik_error websocket_send_message(artik_websocket_handle handle,
	char *message);
static artik_error websocket_set_receive_callback(artik_websocket_handle handle,
	artik_websocket_callback callback,
	void *user_data);
static artik_error websocket_set_connection_callback(
	artik_websocket_handle handle,
	artik_websocket_callback callback,
	void *user_data);
static artik_error websocket_close_stream(artik_websocket_handle handle);

const artik_cloud_module cloud_module = {
	send_message,
	send_message_async,
	send_action,
	send_action_async,
	get_current_user_profile,
	get_current_user_profile_async,
	get_user_devices,
	get_user_devices_async,
	get_user_device_types,
	get_user_device_types_async,
	get_user_application_properties,
	get_user_application_properties_async,
	get_device,
	get_device_async,
	get_device_token,
	get_device_token_async,
	add_device,
	add_device_async,
	update_device_token,
	update_device_token_async,
	delete_device_token,
	delete_device_token_async,
	delete_device,
	delete_device_async,
	get_device_properties,
	get_device_properties_async,
	set_device_server_properties,
	set_device_server_properties_async,
	sdr_start_registration,
	sdr_start_registration_async,
	sdr_registration_status,
	sdr_registration_status_async,
	sdr_complete_registration,
	sdr_complete_registration_async,
	websocket_open_stream,
	websocket_send_message,
	websocket_set_receive_callback,
	websocket_set_connection_callback,
	websocket_close_stream
};

static void http_response_callback(artik_error ret, int status, char *response, void *user_data)
{
	artik_cloud_async *cloud_async = (artik_cloud_async *)user_data;

	if (ret == S_OK) {
		if (status >= 300) {
			log_dbg("HTTP error %d", status);
			ret = E_HTTP_ERROR;
		}
	}

	cloud_async->callback(ret, response, cloud_async->user_data);

	artik_release_api_module(cloud_async->http_module);
	free(cloud_async);
}

static artik_error _artik_cloud_del(artik_cloud_http_request *akc_http_request,
	const char *url, artik_http_headers *headers)
{
	artik_error ret = S_OK;
	artik_http_module *http = (artik_http_module *)
		artik_request_api_module("http");
	if (akc_http_request->response) {
		int status;

		ret = http->del(url, headers, akc_http_request->response,
						&status, akc_http_request->ssl_config);
		if (ret != S_OK)
			goto exit;

		/* Check HTTP status code */
		if (status != 200) {
			log_err("HTTP error %d", status);
			ret = E_HTTP_ERROR;
			goto exit;
		}

		artik_release_api_module(http);
	} else {
		artik_cloud_async *akc_async = malloc(sizeof(artik_cloud_async));

		if (!akc_async) {
			ret = E_NO_MEM;
			goto exit;
		}

		akc_async->callback = akc_http_request->callback;
		akc_async->user_data = akc_http_request->user_data;
		akc_async->http_module = http;

		ret = http->del_async(url, headers,
							  http_response_callback,
							  akc_async,
							  akc_http_request->ssl_config);

		if (ret != S_OK) {
			free(akc_async);
			goto exit;
		}
	}

	return S_OK;

exit:
	artik_release_api_module(http);
	return ret;
}

static artik_error _artik_cloud_put(
	artik_cloud_http_request *akc_http_request,
	const char *url, artik_http_headers *headers, const char *body)
{
	artik_http_module *http = (artik_http_module *)
		artik_request_api_module("http");
	artik_error ret = S_OK;

	if (akc_http_request->response) {
		int status;

		ret = http->put(url, headers, body, akc_http_request->response,
						&status, akc_http_request->ssl_config);
		if (ret != S_OK)
			goto exit;

		/* Check HTTP status code */
		if (status != 200) {
			log_err("HTTP error %d", status);
			ret = E_HTTP_ERROR;
			goto exit;
		}

		artik_release_api_module(http);

	} else {
		artik_cloud_async *akc_async = malloc(sizeof(artik_cloud_async));

		if (!akc_async) {
			ret = E_NO_MEM;
			goto exit;
		}

		akc_async->callback = akc_http_request->callback;
		akc_async->user_data = akc_http_request->user_data;
		akc_async->http_module = http;

		ret = http->put_async(url, headers, body,
							  http_response_callback,
							  akc_async,
							  akc_http_request->ssl_config);

		if (ret != S_OK) {
			free(akc_async);
			goto exit;
		}
	}

	return S_OK;

exit:
	artik_release_api_module(http);

	return ret;
}

static artik_error _artik_cloud_post(
	artik_cloud_http_request *akc_http_request,
	const char *url, artik_http_headers *headers, const char *body)
{
	artik_http_module *http = (artik_http_module *)
		artik_request_api_module("http");
	artik_error ret = S_OK;

	if (akc_http_request->response) {
		int status;

		ret = http->post(url, headers, body, akc_http_request->response,
						 &status, akc_http_request->ssl_config);
		if (ret != S_OK)
			goto exit;

		/* Check HTTP status code */
		if (status != 200) {
			log_err("HTTP error %d", status);
			ret = E_HTTP_ERROR;
			goto exit;
		}

		artik_release_api_module(http);
	} else {
		artik_cloud_async *akc_async = malloc(sizeof(artik_cloud_async));

		if (!akc_async) {
			ret = E_NO_MEM;
			goto exit;
		}

		akc_async->callback = akc_http_request->callback;
		akc_async->user_data = akc_http_request->user_data;
		akc_async->http_module = http;

		ret = http->post_async(url, headers, body,
							   http_response_callback,
							   akc_async,
							   akc_http_request->ssl_config);

		if (ret != S_OK) {
			free(akc_async);
			goto exit;
		}
	}

	return S_OK;

exit:
	artik_release_api_module(http);

	return ret;
}

static artik_error _artik_cloud_get(
	artik_cloud_http_request *akc_http_request,
	const char *url, artik_http_headers *headers)
{
	artik_error ret = S_OK;
	artik_http_module *http = (artik_http_module *)
		artik_request_api_module("http");
	if (akc_http_request->response) {
		int status;

		ret = http->get(url, headers, akc_http_request->response,
						&status, akc_http_request->ssl_config);
		if (ret != S_OK)
			goto exit;

		/* Check HTTP status code */
		if (status != 200) {
			log_err("HTTP error %d", status);
			ret = E_HTTP_ERROR;
			goto exit;
		}

		artik_release_api_module(http);
	} else {
		artik_cloud_async *akc_async = malloc(sizeof(artik_cloud_async));

		if (!akc_async) {
			ret = E_NO_MEM;
			goto exit;
		}

		akc_async->callback = akc_http_request->callback;
		akc_async->user_data = akc_http_request->user_data;
		akc_async->http_module = http;

		ret = http->get_async(url, headers,
							  http_response_callback,
							  akc_async,
							  akc_http_request->ssl_config);

		if (ret != S_OK) {
			free(akc_async);
			goto exit;
		}
	}

	return S_OK;

exit:
	artik_release_api_module(http);

	return ret;
}

static artik_error _get_current_user_profile(
	artik_cloud_http_request *akc_http_request,
	const char *access_token)
{
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX,
			"Bearer %s", access_token);
	fields[0].data = bearer;

	return _artik_cloud_get(akc_http_request,
		akc_http_request->ssl_config->secure ?
		ARTIK_CLOUD_SECURE_URL_SELF_USER : ARTIK_CLOUD_URL_SELF_USER, &headers);
}

artik_error get_current_user_profile_async(const char *access_token,
	artik_cloud_callback callback, void *user_data, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	log_dbg("");

	if (!callback || !ssl)
		return E_BAD_ARGS;

	return _get_current_user_profile(&akc_http_request, access_token);
}
artik_error get_current_user_profile(const char *access_token,
	char **response, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	log_dbg("");

	if (!response || !ssl)
		return E_BAD_ARGS;

	return _get_current_user_profile(&akc_http_request, access_token);
}

static artik_error _get_user_devices(
	artik_cloud_http_request *akc_http_request, const char *access_token,
	int count, bool properties, int offset, const char *user_id)
{
	char url[ARTIK_CLOUD_URL_MAX];
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token || !user_id || count <= 0 || offset < 0)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX,
			"Bearer %s", access_token);
	fields[0].data = bearer;

	/* Build up url with parameters */
	snprintf(url, ARTIK_CLOUD_URL_MAX,
		akc_http_request->ssl_config->secure ?
		ARTIK_CLOUD_SECURE_URL_USER_DEVICES : ARTIK_CLOUD_URL_USER_DEVICES,
		 user_id, count, properties ? "true" : "false", offset);

	/* Perform the request */
	return _artik_cloud_get(akc_http_request, url, &headers);
}

artik_error get_user_devices_async(
	const char *access_token,
	int count, bool properties, int offset, const char *user_id,
	artik_cloud_callback callback, void *user_data, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	if (!callback || !ssl)
		return E_BAD_ARGS;

	return _get_user_devices(&akc_http_request, access_token, count, properties,
							 offset, user_id);
}

artik_error get_user_devices(
	const char *access_token, int count,
	bool properties, int offset, const char *user_id,
	char **response, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	if (!response || !ssl)
		return E_BAD_ARGS;

	return _get_user_devices(&akc_http_request, access_token, count,
							 properties, offset, user_id);
}

static artik_error _get_user_devices_types(
	artik_cloud_http_request *akc_http_request,
	const char *access_token, int count, bool shared, int offset,
	const char *user_id)
{
	char url[ARTIK_CLOUD_URL_MAX];
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token || !user_id || count <= 0 || offset < 0)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX, "Bearer %s", access_token);
	fields[0].data = bearer;

	/* Build up url with parameters */
	snprintf(url, ARTIK_CLOUD_URL_MAX,
		akc_http_request->ssl_config->secure ?
		ARTIK_CLOUD_SECURE_URL_USER_DEVICE_TYPES :
		ARTIK_CLOUD_URL_USER_DEVICE_TYPES,
		user_id, count, shared ? "true" : "false", offset);

	return _artik_cloud_get(akc_http_request, url, &headers);
}

artik_error get_user_device_types_async(
	const char *access_token, int count, bool shared,
	int offset, const char *user_id,
	artik_cloud_callback callback, void *user_data, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	if (!callback || !ssl)
		return E_BAD_ARGS;

	return _get_user_devices_types(&akc_http_request, access_token, count,
								   shared, offset, user_id);
}

artik_error get_user_device_types(
	const char *access_token, int count, bool shared,
	int offset, const char *user_id,
	char **response, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	if (!response || !ssl)
		return E_BAD_ARGS;

	return _get_user_devices_types(&akc_http_request, access_token, count,
								   shared, offset, user_id);
}

static artik_error _get_user_application_properties(
	artik_cloud_http_request *akc_http_request,
	const char *access_token, const char *user_id, const char *app_id)
{
	char url[ARTIK_CLOUD_URL_MAX];
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token || !user_id || !app_id)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX, "Bearer %s", access_token);
	fields[0].data = bearer;

	/* Build up url with parameters */
	snprintf(url, ARTIK_CLOUD_URL_MAX, ARTIK_CLOUD_URL_USER_APP_PROPS,
		 user_id, app_id);

	return _artik_cloud_get(akc_http_request, url, &headers);
}

artik_error get_user_application_properties_async(
	const char *access_token, const char *user_id,
	const char *app_id,
	artik_cloud_callback callback, void *user_data,
	artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	if (!callback)
		return E_BAD_ARGS;

	return _get_user_application_properties(&akc_http_request,
											access_token, user_id, app_id);
}
artik_error get_user_application_properties(
	const char *access_token, const char *user_id, const char *app_id,
	char **response, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	if (!response)
		return E_BAD_ARGS;

	return _get_user_application_properties(&akc_http_request,
											access_token, user_id, app_id);
}

artik_error _get_device(
	artik_cloud_http_request *akc_http_request,
	const char *access_token, const char *device_id, bool properties)
{
	char url[ARTIK_CLOUD_URL_MAX];
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token || !device_id)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX, "Bearer %s", access_token);
	fields[0].data = bearer;

	/* Build up url with parameters */
	snprintf(url, ARTIK_CLOUD_URL_MAX, ARTIK_CLOUD_URL_GET_DEVICE,
		 device_id, properties ? "true" : "false");

	return _artik_cloud_get(akc_http_request, url, &headers);
}

artik_error get_device_async(
	const char *access_token, const char *device_id, bool properties,
	artik_cloud_callback callback, void *user_data, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	if (!callback || !ssl)
		return E_BAD_ARGS;

	return _get_device(&akc_http_request, access_token, device_id, properties);
}
artik_error get_device(
	const char *access_token, const char *device_id,
	bool properties, char **response,
	artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	if (!response || !ssl)
		return E_BAD_ARGS;

	return _get_device(&akc_http_request, access_token, device_id, properties);
}

artik_error _get_device_token(
	artik_cloud_http_request *akc_http_request,
	const char *access_token, const char *device_id)
{
	char url[ARTIK_CLOUD_URL_MAX];
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token || !device_id)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX, "Bearer %s", access_token);
	fields[0].data = bearer;

	/* Build up url with parameters */
	snprintf(url, ARTIK_CLOUD_URL_MAX, ARTIK_CLOUD_URL_GET_DEVICE_TOKEN,
		 device_id);

	return _artik_cloud_get(akc_http_request, url, &headers);
}

artik_error get_device_token_async(
	const char *access_token, const char *device_id,
	artik_cloud_callback callback, void *user_data, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	if (!callback || !ssl)
		return E_BAD_ARGS;

	return _get_device_token(&akc_http_request, access_token, device_id);
}

artik_error get_device_token(
	const char *access_token, const char *device_id,
	char **response, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	if (!response || !ssl)
		return E_BAD_ARGS;

	return _get_device_token(&akc_http_request, access_token, device_id);
}

static artik_error _add_device(
	artik_cloud_http_request *akc_http_request,
	const char *access_token, const char *user_id, const char *dt_id, const char *name)
{
	char *body = NULL;
	artik_error ret;
	int body_len;
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token || !user_id || !dt_id || !name) {
		log_err("Bad arguments\n");
		return E_BAD_ARGS;
	}

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX, "Bearer %s", access_token);
	fields[0].data = bearer;

	/* Build up message body */
	body_len =
		strlen(ARTIK_CLOUD_ADD_DEVICE_BODY) + strlen(user_id) +
		strlen(dt_id) + strlen(name) + 1;

	body = (char *)malloc(body_len);
	if (!body) {
		log_err("Failed to allocate memory");
		return E_NO_MEM;
	}

	snprintf(body, body_len, ARTIK_CLOUD_ADD_DEVICE_BODY, user_id, dt_id,
		name);


	ret = _artik_cloud_post(akc_http_request,
		akc_http_request->ssl_config->secure ?
		ARTIK_CLOUD_SECURE_URL_ADD_DEVICE : ARTIK_CLOUD_URL_ADD_DEVICE,
		&headers, body);

	free(body);

	return ret;
}

artik_error add_device_async(
	const char *access_token, const char *user_id, const char *dt_id, const char *name,
	artik_cloud_callback callback, void *user_data, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	if (!callback || !ssl)
		return E_BAD_ARGS;

	return _add_device(&akc_http_request, access_token, user_id, dt_id, name);
}

artik_error add_device(
	const char *access_token, const char *user_id, const char *dt_id, const char *name,
	char **response, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	if (!response || !ssl)
		return E_BAD_ARGS;

	return _add_device(&akc_http_request, access_token, user_id, dt_id, name);
}

artik_error _send_message(
	artik_cloud_http_request *akc_http_request,
	const char *access_token, const char *device_id, const char *message)
{
	artik_error ret;
	char *body = NULL;
	int body_len;
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token || !device_id || !message) {
		log_err("Bad arguments\n");
		return E_BAD_ARGS;
	}

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX, "Bearer %s", access_token);
	fields[0].data = bearer;

	/* Build up message body */
	body_len =
		strlen(ARTIK_CLOUD_MESSAGE_BODY) + strlen(device_id) +
		strlen(message) + 1;

	body = (char *)malloc(body_len);
	if (!body) {
		log_err("Failed to allocate memory");
		return E_NO_MEM;
	}

	snprintf(body, body_len, ARTIK_CLOUD_MESSAGE_BODY, device_id, message);

	ret = _artik_cloud_post(akc_http_request,
		akc_http_request->ssl_config->secure ?
		ARTIK_CLOUD_SECURE_URL_MESSAGES : ARTIK_CLOUD_URL_MESSAGES,
		&headers, body);

	free(body);

	return ret;
}

artik_error send_message_async(
	const char *access_token, const char *device_id, const char *message,
	artik_cloud_callback callback, void *user_data, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	if (!callback || !ssl)
		return E_BAD_ARGS;

	return _send_message(&akc_http_request, access_token, device_id, message);
}

artik_error send_message(const char *access_token, const char *device_id,
			const char *message, char **response,
			artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	if (!response || !ssl)
		return E_BAD_ARGS;

	return _send_message(&akc_http_request, access_token, device_id, message);
}

static artik_error _send_action(
	artik_cloud_http_request *akc_http_request,
	const char *access_token, const char *device_id, const char *action)
{
	artik_error ret;
	char *body = NULL;
	int body_len;
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token || !device_id || !action)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX, "Bearer %s", access_token);
	fields[0].data = bearer;

	/* Build up message body */
	body_len =
		strlen(ARTIK_CLOUD_ACTION_BODY) + strlen(device_id) +
		strlen(action) + 1;
	body = (char *)malloc(body_len);
	if (!body)
		return E_NO_MEM;

	snprintf(body, body_len, ARTIK_CLOUD_ACTION_BODY, device_id, action);

	ret = _artik_cloud_post(akc_http_request,
		akc_http_request->ssl_config->secure ?
		ARTIK_CLOUD_SECURE_URL_MESSAGES : ARTIK_CLOUD_URL_MESSAGES,
		&headers, body);

	free(body);

	return ret;
}

artik_error send_action_async(
	const char *access_token, const char *device_id, const char *action,
	artik_cloud_callback callback, void *user_data, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	if (!callback || !ssl)
		return E_BAD_ARGS;

	return _send_action(&akc_http_request, access_token, device_id, action);
}

artik_error send_action(
	const char *access_token, const char *device_id, const char *action,
	char **response, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	if (!response || !ssl)
		return E_BAD_ARGS;

	return _send_action(&akc_http_request, access_token, device_id, action);
}

artik_error _update_device_token(
	artik_cloud_http_request *akc_http_request,
	const char *access_token, const char *device_id)
{
	char url[ARTIK_CLOUD_URL_MAX];
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	char body[] = "{}";
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token || !device_id)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX, "Bearer %s", access_token);
	fields[0].data = bearer;

	/* Build up url with parameters */
	snprintf(url, ARTIK_CLOUD_URL_MAX,
		akc_http_request->ssl_config->secure ?
		ARTIK_CLOUD_SECURE_URL_UPDATE_DEVICE_TOKEN :
		ARTIK_CLOUD_URL_UPDATE_DEVICE_TOKEN, device_id);

	/* Perform the request */
	return _artik_cloud_put(akc_http_request, url, &headers, body);

}

artik_error update_device_token_async(
	const char *access_token, const char *device_id,
	artik_cloud_callback callback, void *user_data, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	if (!callback || !ssl)
		return E_BAD_ARGS;

	return _update_device_token(&akc_http_request, access_token, device_id);
}

artik_error update_device_token(
	const char *access_token, const char *device_id,
	char **response, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	if (!response || !ssl)
		return E_BAD_ARGS;

	return _update_device_token(&akc_http_request, access_token, device_id);
}

static artik_error _delete_device_token(
	artik_cloud_http_request *akc_http_request,
	const char *access_token, const char *device_id)
{
	char url[ARTIK_CLOUD_URL_MAX];
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token || !device_id)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX, "Bearer %s", access_token);
	fields[0].data = bearer;

	/* Build up url with parameters */
	snprintf(url, ARTIK_CLOUD_URL_MAX,
		akc_http_request->ssl_config->secure ?
		ARTIK_CLOUD_SECURE_URL_DELETE_DEVICE_TOKEN :
		ARTIK_CLOUD_URL_DELETE_DEVICE_TOKEN,
		device_id);

	/* Perform the request */
	return _artik_cloud_del(akc_http_request, url, &headers);
}

artik_error delete_device_token_async(
	const char *access_token, const char *device_id,
	artik_cloud_callback callback, void *user_data, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	if (!callback || !ssl)
		return E_BAD_ARGS;

	return _delete_device_token(&akc_http_request, access_token, device_id);
}

artik_error delete_device_token(
	const char *access_token, const char *device_id,
	char **response, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	if (!response || !ssl)
		return E_BAD_ARGS;

	return _delete_device_token(&akc_http_request, access_token, device_id);
}

static artik_error _delete_device(
	artik_cloud_http_request *akc_http_request,
	const char *access_token, const char *device_id)
{
	char url[ARTIK_CLOUD_URL_MAX];
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token || !device_id)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX, "Bearer %s", access_token);
	fields[0].data = bearer;

	/* Build up url with parameters */
	snprintf(url, ARTIK_CLOUD_URL_MAX,
		akc_http_request->ssl_config->secure ?
		ARTIK_CLOUD_SECURE_URL_DELETE_DEVICE : ARTIK_CLOUD_URL_DELETE_DEVICE,
		 device_id);

	/* Perform the request */
	return _artik_cloud_del(akc_http_request, url, &headers);
}

artik_error delete_device_async(
	const char *access_token, const char *device_id,
	artik_cloud_callback callback, void *user_data, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	if (!callback || !ssl)
		return E_BAD_ARGS;

	return _delete_device(&akc_http_request, access_token, device_id);
}

static artik_error delete_device(
	const char *access_token, const char *device_id,
	char **response, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	if (!response || !ssl)
		return E_BAD_ARGS;

	return _delete_device(&akc_http_request, access_token, device_id);
}

static artik_error _get_device_properties(
	artik_cloud_http_request *akc_http_request,
	const char *access_token, const char *device_id, bool timestamp)
{
	char url[ARTIK_CLOUD_URL_MAX];
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token || !device_id)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX, "Bearer %s", access_token);
	fields[0].data = bearer;

	/* Build up url with parameters */
	snprintf(url, ARTIK_CLOUD_URL_MAX,
		akc_http_request->ssl_config->secure ?
		 ARTIK_CLOUD_SECURE_URL_GET_DEVICE_PROPS :
		 ARTIK_CLOUD_URL_GET_DEVICE_PROPS,
		device_id, timestamp ? "true" : "false");

	/* Perform the request */
	return _artik_cloud_get(akc_http_request, url, &headers);
}

static artik_error get_device_properties_async(
	const char *access_token, const char *device_id, bool timestamp,
	artik_cloud_callback callback, void *user_data, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	if (!callback || !ssl)
		return E_BAD_ARGS;

	return _get_device_properties(&akc_http_request, access_token, device_id, timestamp);
}

static artik_error get_device_properties(
	const char *access_token, const char *device_id, bool timestamp,
	char **response, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	if (!response || !ssl)
		return E_BAD_ARGS;

	return _get_device_properties(&akc_http_request, access_token, device_id, timestamp);
}

static artik_error _set_device_server_properties(
	artik_cloud_http_request *akc_http_request,
	const char *access_token, const char *device_id, const char *data)
{
	artik_error ret = S_OK;
	char *body = NULL;
	int body_len;
	char url[ARTIK_CLOUD_URL_MAX];
	char bearer[ARTIK_CLOUD_TOKEN_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Authorization", NULL},
		{"Content-Type", "application/json"},
	};

	log_dbg("");

	if (!access_token || !device_id || !data)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up authorization header */
	snprintf(bearer, ARTIK_CLOUD_TOKEN_MAX, "Bearer %s", access_token);
	fields[0].data = bearer;

	/* Build up url with parameters */
	snprintf(url, ARTIK_CLOUD_URL_MAX,
		akc_http_request->ssl_config->secure ?
		ARTIK_CLOUD_SECURE_URL_SET_DEVICE_SERV_PROPS :
		ARTIK_CLOUD_URL_SET_DEVICE_SERV_PROPS, device_id);

	/* Build up message body */
	body_len = strlen(data) + 1;

	body = (char *)malloc(body_len);
	if (!body) {
		log_err("Failed to allocate memory");
		return E_NO_MEM;
	}

	memcpy(body, data, body_len);

	/* Perform the request */
	ret = _artik_cloud_post(akc_http_request, url, &headers, body);
	free(body);

	return ret;
}

static artik_error set_device_server_properties_async(
	const char *access_token, const char *device_id, const char *data,
	artik_cloud_callback callback, void *user_data, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		ssl
	};

	if (!callback || !ssl)
		return E_BAD_ARGS;

	return _set_device_server_properties(&akc_http_request, access_token,
			device_id, data);
}

static artik_error set_device_server_properties(
	const char *access_token, const char *device_id, const char *data,
	char **response, artik_ssl_config *ssl)
{
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		ssl
	};

	if (!response || !ssl)
		return E_BAD_ARGS;

	return _set_device_server_properties(&akc_http_request, access_token,
			device_id, data);
}

static artik_error _sdr_start_registration(
	artik_cloud_http_request *akc_http_request,
	const char *device_type_id,
	const char *vendor_id)
{
	artik_error ret;
	char *body = NULL;
	int body_len = 0;
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Accept", "application/json"},
		{"Content-Type", "application/json"},
		{"charsets:", "utf-8"},
	};

	log_dbg("");

	if (!device_type_id || !vendor_id)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up message body */
	body_len =
		strlen(ARTIK_CLOUD_SECURE_REG_DEVICE_BODY) +
		strlen(device_type_id) + strlen(vendor_id) + 1;
	body = (char *)malloc(body_len);
	if (!body)
		return E_NO_MEM;

	snprintf(body, body_len, ARTIK_CLOUD_SECURE_REG_DEVICE_BODY,
		 device_type_id, vendor_id);

	/* Perform the request */
	ret = _artik_cloud_post(akc_http_request, ARTIK_CLOUD_SECURE_URL_REG_DEVICE,
			&headers, body);

	free(body);

	return ret;
}

static artik_error _sdr_fill_ssl_config(artik_ssl_config *ssl, const char *cert_name)
{
	artik_security_module *security = NULL;
	artik_security_handle sec_handle = NULL;
	artik_error ret = S_OK;

	memset(ssl, 0, sizeof(artik_ssl_config));
	ssl->verify_cert = ARTIK_SSL_VERIFY_NONE;
	ssl->secure = true;

	security = (artik_security_module *)artik_request_api_module("security");
	ret = security->request(&sec_handle);
	if (ret != S_OK) {
		log_err("Failed to request security module (%d)", ret);
		artik_release_api_module(security);
		return E_SECURITY_ERROR;
	}

	ret = security->get_certificate(sec_handle, cert_name,
			ARTIK_SECURITY_CERT_TYPE_PEM,
			(unsigned char **)&ssl->client_cert.data,
			&ssl->client_cert.len);
	if (ret != S_OK) {
		log_err("Failed to get certificate from the security module (%d)", ret);
		goto error;
	}

	ret = security->get_publickey(sec_handle, ECC_SEC_P256R1, cert_name,
			(unsigned char **)&ssl->client_key.data,
			&ssl->client_key.len);
	if (ret != S_OK) {
		log_err("Failed to get private key from the security module (%d)", ret);
		goto error;
	}

	security->release(&sec_handle);
	artik_release_api_module(security);
	return S_OK;

error:
	if (ssl->client_cert.data)
		free(ssl->client_cert.data);
	if (ssl->client_key.data)
		free(ssl->client_key.data);
	security->release(&sec_handle);
	artik_release_api_module(security);
	return E_SECURITY_ERROR;
}

static artik_error sdr_start_registration_async(
	const char *cert_name, const char *device_type_id, const char *vendor_id,
	artik_cloud_callback callback, void *user_data)
{
	artik_ssl_config ssl;
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		&ssl
	};

	if (!callback)
		return E_BAD_ARGS;

	_sdr_fill_ssl_config(&ssl, cert_name);
	return _sdr_start_registration(&akc_http_request,
									device_type_id,
									vendor_id);

}

static artik_error sdr_start_registration(
	const char *cert_name, const char *device_type_id, const char *vendor_id,
	char **response)
{
	artik_ssl_config ssl;
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		&ssl
	};

	if (!response)
		return E_BAD_ARGS;

	_sdr_fill_ssl_config(&ssl, cert_name);
	return _sdr_start_registration(&akc_http_request,
								   device_type_id,
								   vendor_id);
}

static artik_error _sdr_registration_status(
	artik_cloud_http_request *akc_http_request,
	const char *reg_id)
{
	char url[ARTIK_CLOUD_URL_MAX];
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Accept", "application/json"},
	};

	log_dbg("");

	if (!reg_id)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up url with parameters */
	snprintf(url, ARTIK_CLOUD_URL_MAX, ARTIK_CLOUD_SECURE_URL_REG_STATUS,
		 reg_id);

	/* Perform the request */
	return _artik_cloud_get(akc_http_request, url, &headers);
}

static artik_error sdr_registration_status_async(
	const char *cert_name, const char *reg_id,
	artik_cloud_callback callback, void *user_data)
{
	artik_ssl_config ssl;
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		&ssl
	};

	if (!callback)
		return E_BAD_ARGS;

	_sdr_fill_ssl_config(&ssl, cert_name);
	return _sdr_registration_status(&akc_http_request, reg_id);
}

static artik_error sdr_registration_status(
	const char *cert_name, const char *reg_id,
	char **response)
{
	artik_ssl_config ssl;
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		&ssl
	};

	if (!response)
		return E_BAD_ARGS;

	_sdr_fill_ssl_config(&ssl, cert_name);
	return _sdr_registration_status(&akc_http_request, reg_id);
}

static artik_error _sdr_complete_registration(
	artik_cloud_http_request *akc_http_request,
	const char *reg_id, const char *reg_nonce)
{
	artik_error ret;
	char url[ARTIK_CLOUD_URL_MAX];
	char *body = NULL;
	int body_len;
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"Accept", "application/json"},
		{"Content-Type", "application/json"},
		{"charsets:", "utf-8"}
	};

	log_dbg("");

	if (!reg_id || !reg_nonce)
		return E_BAD_ARGS;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	/* Build up url with parameters */
	snprintf(url, ARTIK_CLOUD_URL_MAX, ARTIK_CLOUD_SECURE_URL_REG_ID,
		 reg_id);

	/* Build up message body */
	body_len =
		strlen(ARTIK_CLOUD_SECURE_REG_COMPLETE_BODY) + strlen(reg_nonce) +
		1;
	body = (char *)malloc(body_len);
	if (!body)
		return E_NO_MEM;

	snprintf(body, body_len, ARTIK_CLOUD_SECURE_REG_COMPLETE_BODY, reg_nonce);

	/* Perform the request */
	ret = _artik_cloud_put(akc_http_request, url, &headers, body);
	free(body);

	return ret;
}

static artik_error sdr_complete_registration_async(
	const char *cert_name, const char *reg_id, const char *reg_nonce,
	artik_cloud_callback callback, void *user_data)
{
	artik_ssl_config ssl;
	artik_cloud_http_request akc_http_request = {
		NULL,
		callback,
		user_data,
		&ssl
	};

	if (!callback)
		return E_BAD_ARGS;

	_sdr_fill_ssl_config(&ssl, cert_name);
	return _sdr_complete_registration(&akc_http_request, reg_id, reg_nonce);
}

static artik_error sdr_complete_registration(
	const char *cert_name, const char *reg_id, const char *reg_nonce,
	char **response)
{
	artik_ssl_config ssl;
	artik_cloud_http_request akc_http_request = {
		response,
		NULL,
		NULL,
		&ssl
	};

	if (!response)
		return E_BAD_ARGS;

	_sdr_fill_ssl_config(&ssl, cert_name);
	return _sdr_complete_registration(&akc_http_request, reg_id, reg_nonce);
}

void websocket_connection_callback(void *user_data, void *result)
{
	artik_websocket_module *websocket = (artik_websocket_module *)
					artik_request_api_module("websocket");
	artik_cloud_reg_data *data = (artik_cloud_reg_data *)user_data;
	artik_websocket_handle handle = data->handle;

	log_dbg("");

	if (!websocket)
		return;

	switch ((intptr_t) result) {
	case ARTIK_WEBSOCKET_CONNECTED:
		websocket->websocket_write_stream(handle,
						data->registration_message);
		if (data->callback)
			data->callback(data->callback_data,
				(void *)ARTIK_WEBSOCKET_CONNECTED);
		break;
	case ARTIK_WEBSOCKET_CLOSED:
		log_dbg("Connection closed");
		if (data->callback)
			data->callback(data->callback_data,
				(void *)ARTIK_WEBSOCKET_CLOSED);
		break;
	case ARTIK_WEBSOCKET_HANDSHAKE_ERROR:
		log_dbg("Handshake error");
		if (data->callback)
			data->callback(data->callback_data,
				(void *)ARTIK_WEBSOCKET_HANDSHAKE_ERROR);
		break;
	default:
		break;
	}

	artik_release_api_module(websocket);
}

artik_error websocket_open_stream(artik_websocket_handle *handle,
				const char *access_token,
				const char *device_id,
				unsigned int ping_period,
				unsigned int pong_timeout,
				artik_ssl_config *ssl_config)
{
	artik_websocket_module *websocket;
	artik_error ret = S_OK;
	artik_websocket_config config;
	cloud_node *node;
	char port[4];
	char *host = (ssl_config != NULL && ssl_config->secure) ?
			ARTIK_CLOUD_SECURE_WEBSOCKET_HOST :	ARTIK_CLOUD_WEBSOCKET_HOST;
	char *path = ARTIK_CLOUD_WEBSOCKET_PATH;

	log_dbg("");

	if (!handle || !access_token || !ssl_config || !device_id)
		return E_BAD_ARGS;

	websocket = (artik_websocket_module *)
					artik_request_api_module("websocket");
	if (!websocket)
		return E_NOT_SUPPORTED;

	memset(&config, 0, sizeof(artik_websocket_config));

	snprintf(port, 4, "%d", ARTIK_CLOUD_WEBSOCKET_PORT);

	int len = 6 + strlen(host) + 1 + strlen(port) + strlen(path) + 1;

	config.uri = malloc(len);
	if (!config.uri) {
		artik_release_api_module(websocket);
		return E_NO_MEM;
	}

	snprintf(config.uri, len, "wss://%s:%s%s", host, port, path);

	if (ssl_config != NULL)
		config.ssl_config = *ssl_config;
	else {
		config.ssl_config.secure = false;
		config.ssl_config.verify_cert = ARTIK_SSL_VERIFY_NONE;
		config.ssl_config.client_cert.data = NULL;
		config.ssl_config.client_cert.len = 0;
		config.ssl_config.client_key.data = NULL;
		config.ssl_config.client_key.len = 0;
	}

	config.ping_period = ping_period;
	config.pong_timeout = pong_timeout;

	ret = websocket->websocket_request(handle, &config);
	if (ret != S_OK)
		goto exit;

	ret = websocket->websocket_open_stream(*handle);
	if (ret != S_OK)
		goto exit;

	node = (cloud_node *)artik_list_add(&requested_node,
				(ARTIK_LIST_HANDLE)*handle, sizeof(cloud_node));
	if (!node) {
		ret = E_NO_MEM;
		goto exit;
	}

	node->data.access_token = strndup(access_token, strlen(access_token));
	node->data.device_id = strndup(device_id, strlen(device_id));

	snprintf(node->data.registration_message, ARTIK_CLOUD_WEBSOCKET_STR_MAX,
		 ARTIK_CLOUD_WEBSOCKET_MESSAGE_BODY, device_id, access_token,
		 "register");

	node->data.handle = *handle;

	ret = websocket->websocket_set_connection_callback(*handle,
			websocket_connection_callback, (void *)&(node->data));
	if (ret != S_OK) {
		artik_list_delete_handle(&requested_node,
						(ARTIK_LIST_HANDLE)*handle);
		goto exit;
	}

exit:
	artik_release_api_module(websocket);

	if (ret != S_OK && *handle != NULL) {
		websocket->websocket_close_stream(*handle);
		websocket->websocket_release(*handle);
		*handle = NULL;
	}

	free(config.uri);

	return ret;
}


artik_error websocket_send_message(artik_websocket_handle handle, char *message)
{
	artik_websocket_module *websocket = (artik_websocket_module *)
					artik_request_api_module("websocket");
	artik_error ret = S_OK;
	cloud_node *node = (cloud_node *)artik_list_get_by_handle(
				requested_node, (ARTIK_LIST_HANDLE)handle);
	char message_buffer[ARTIK_CLOUD_WEBSOCKET_STR_MAX] = {0, };

	log_dbg("");

	if (!node || !message)
		return E_BAD_ARGS;

	if (!websocket)
		return E_NOT_SUPPORTED;

	snprintf(message_buffer, ARTIK_CLOUD_WEBSOCKET_STR_MAX,
		ARTIK_CLOUD_WEBSOCKET_SEND_MESSAGE_BODY, node->data.device_id,
		"message", message);

	ret = websocket->websocket_write_stream(handle, message_buffer);

	artik_release_api_module(websocket);

	return ret;
}

artik_error websocket_set_connection_callback(artik_websocket_handle handle,
			artik_websocket_callback callback, void *user_data)
{
	cloud_node *node = (cloud_node *)artik_list_get_by_handle(
				requested_node, (ARTIK_LIST_HANDLE)handle);

	log_dbg("");

	if (!node)
		return E_BAD_ARGS;

	node->data.callback = callback;
	node->data.callback_data = user_data;

	return S_OK;
}

artik_error websocket_set_receive_callback(artik_websocket_handle handle,
			artik_websocket_callback callback, void *user_data)
{
	artik_websocket_module *websocket = (artik_websocket_module *)
					artik_request_api_module("websocket");
	artik_error ret = S_OK;

	log_dbg("");

	if (!websocket)
		return E_NOT_SUPPORTED;

	ret = websocket->websocket_set_receive_callback(handle, callback,
							user_data);

	artik_release_api_module(websocket);

	return ret;
}

artik_error websocket_close_stream(artik_websocket_handle handle)
{
	artik_websocket_module *websocket = (artik_websocket_module *)
					artik_request_api_module("websocket");
	artik_error ret = S_OK;
	cloud_node *node = (cloud_node *)artik_list_get_by_handle(
				requested_node, (ARTIK_LIST_HANDLE)handle);

	log_dbg("");

	if (!websocket)
		return E_NOT_SUPPORTED;

	if (!node)
		return E_BAD_ARGS;

	if (node->data.access_token)
		free(node->data.access_token);

	if (node->data.device_id)
		free(node->data.device_id);

	ret = artik_list_delete_handle(&requested_node,
					(ARTIK_LIST_HANDLE)handle);
	if (ret != S_OK)
		goto exit;

	ret = websocket->websocket_close_stream(handle);
	if (ret != S_OK)
		goto exit;

	ret = websocket->websocket_release(handle);

exit:
	artik_release_api_module(websocket);

	return ret;
}
