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
#include <artik_platform.h>
#include <artik_loop.h>
#include <artik_log.h>
#include <artik_utils.h>

#include <openssl/ssl.h>
#include <openssl/engine.h>

#include <artik_lwm2m.h>
#include <artik_list.h>
#include "os_lwm2m.h"
#include "lwm2mclient.h"

typedef struct {
	artik_list node;

	object_container_t *container;
	client_handle_t *client;
	artik_lwm2m_callback callbacks[ARTIK_LWM2M_EVENT_COUNT];
	void *callbacks_params[ARTIK_LWM2M_EVENT_COUNT];
	int service_cbk_id;
	artik_loop_module *loop_module;
	bool connected;
} lwm2m_node;

typedef struct {
	lwm2m_node *node;
	artik_lwm2m_event_t event;
	void *extra;
	int id;
} lwm2m_idle_params;

static artik_list *nodes = NULL;

static int on_lwm2m_service_callback(void *user_data)
{
	lwm2m_node *node = (lwm2m_node *)user_data;
	int timeout;
	artik_error err;

	timeout = lwm2m_client_service(node->client, 1000);
	if (timeout < LWM2M_CLIENT_OK) {
		log_dbg("");
		switch (timeout) {
		case LWM2M_CLIENT_QUIT:
			if (node->callbacks[ARTIK_LWM2M_EVENT_ERROR]) {
				err = E_INTERRUPTED;
				node->callbacks[ARTIK_LWM2M_EVENT_ERROR]((void *)(intptr_t)err,
				node->callbacks_params[ARTIK_LWM2M_EVENT_ERROR]);
			}
			return 0;
		case LWM2M_CLIENT_ERROR:
			if (node->callbacks[ARTIK_LWM2M_EVENT_ERROR]) {
				err = E_LWM2M_ERROR;
				node->callbacks[ARTIK_LWM2M_EVENT_ERROR]((void *)(intptr_t)err,
				node->callbacks_params[ARTIK_LWM2M_EVENT_ERROR]);
			}
			return 0;
		case LWM2M_CLIENT_DISCONNECTED:
			if (node->callbacks[ARTIK_LWM2M_EVENT_DISCONNECT]) {
				err = E_LWM2M_DISCONNECTION_ERROR;
				node->callbacks[ARTIK_LWM2M_EVENT_DISCONNECT]((void *)(intptr_t)err,
				node->callbacks_params[ARTIK_LWM2M_EVENT_DISCONNECT]);
				node->connected = false;
			}
			return 1;
		default:
			break;
		}
	}

	if (node->callbacks[ARTIK_LWM2M_EVENT_CONNECT] &&
		(node->connected != true)) {
		err = S_OK;
		node->callbacks[ARTIK_LWM2M_EVENT_CONNECT]((void *)(intptr_t)err,
		node->callbacks_params[ARTIK_LWM2M_EVENT_CONNECT]);
		node->connected = true;
	}
	return 1;
}

static int on_idle_callback(void *user_data)
{
	lwm2m_idle_params *params = (lwm2m_idle_params *)user_data;

	if (params) {
		if (params->node->callbacks[params->event])
			params->node->callbacks[params->event](params->extra,
					params->node->callbacks_params[
							params->event]);
		params->node->loop_module->remove_idle_callback(params->id);
		free(params);
	}

	return 0;
}

static void on_exec_factory_reset(void *user_data, void *extra)
{
	lwm2m_node *node = (lwm2m_node *)user_data;

	log_dbg("");

	/* Call from the main loop in case we are called from Wakaama's rx
	 * thread. This avoid confusion to higher level callers
	 * (such as node.js addon) which rely on their callbacks being called
	 * from the same thread context
	 */
	if (node->callbacks[ARTIK_LWM2M_EVENT_RESOURCE_EXECUTE]) {
		artik_lwm2m_resource_t *res = malloc(sizeof(artik_lwm2m_resource_t));

		memset(res, 0, sizeof(artik_lwm2m_resource_t));
		lwm2m_idle_params *params = malloc(sizeof(lwm2m_idle_params));

		params->node = node;
		res->uri = (void *)strndup(LWM2M_URI_DEVICE_FACTORY_RESET,
				strlen(LWM2M_URI_DEVICE_FACTORY_RESET));
		params->extra = (void *)res;
		params->event = ARTIK_LWM2M_EVENT_RESOURCE_EXECUTE;
		node->loop_module->add_idle_callback(&params->id,
					on_idle_callback, (void *)params);
		free(extra);
	}
}

static void on_exec_device_reboot(void *user_data, void *extra)
{
	lwm2m_node *node = (lwm2m_node *)user_data;

	log_dbg("");

	/* Call from the main loop in case we are called from Wakaama's rx
	 * thread. This avoid confusion to higher level callers
	 * (such as node.js addon) which rely on their callbacks being called
	 * from the same thread context
	 */
	if (node->callbacks[ARTIK_LWM2M_EVENT_RESOURCE_EXECUTE]) {
		artik_lwm2m_resource_t *res = malloc(sizeof(artik_lwm2m_resource_t));

		memset(res, 0, sizeof(artik_lwm2m_resource_t));
		lwm2m_idle_params *params = malloc(sizeof(lwm2m_idle_params));

		params->node = node;
		res->uri = (void *)strndup(LWM2M_URI_DEVICE_REBOOT,
				strlen(LWM2M_URI_DEVICE_REBOOT));
		params->extra = (void *)res;
		params->event = ARTIK_LWM2M_EVENT_RESOURCE_EXECUTE;
		node->loop_module->add_idle_callback(&params->id,
					on_idle_callback, (void *)params);
	}
}

static void on_exec_firmware_update(void *user_data, void *extra)
{
	lwm2m_node *node = (lwm2m_node *)user_data;

	log_dbg("");

	/* Call from the main loop in case we are called from Wakaama's rx
	 * thread. This avoid confusion to higher level callers
	 * (such as node.js addon) which rely on their callbacks being called
	 * from the same thread context
	 */
	if (node->callbacks[ARTIK_LWM2M_EVENT_RESOURCE_EXECUTE]) {
		artik_lwm2m_resource_t *res = malloc(sizeof(artik_lwm2m_resource_t));

		memset(res, 0, sizeof(artik_lwm2m_resource_t));
		lwm2m_idle_params *params = malloc(sizeof(lwm2m_idle_params));

		params->node = node;
		res->uri = (void *)strndup(LWM2M_URI_FIRMWARE_UPDATE,
				strlen(LWM2M_URI_FIRMWARE_UPDATE));
		params->extra = (void *)res;
		params->event = ARTIK_LWM2M_EVENT_RESOURCE_EXECUTE;
		node->loop_module->add_idle_callback(&params->id,
					on_idle_callback, (void *)params);
	}
}

static void on_resource_changed(void *user_data, void *extra)
{
	lwm2m_node *node = (lwm2m_node *)user_data;
	lwm2m_resource_t *res = (lwm2m_resource_t *)extra;

	log_dbg("uri: %s", res->uri);

	/* Call from the main loop in case we are called from Wakaama's rx
	 * thread. This avoid confusion to higher level callers
	 * (such as node.js addon) which rely on their callbacks being called
	 * from the same thread context
	 */
	if (node->callbacks[ARTIK_LWM2M_EVENT_RESOURCE_CHANGED]) {
		artik_lwm2m_resource_t *resource = malloc(sizeof(artik_lwm2m_resource_t));

		memset(resource, 0, sizeof(artik_lwm2m_resource_t));
		lwm2m_idle_params *params = malloc(sizeof(lwm2m_idle_params));

		params->node = node;
		resource->uri = (void *)strndup(res->uri, strlen(res->uri));
		params->extra = (void *)resource;
		params->event = ARTIK_LWM2M_EVENT_RESOURCE_CHANGED;

		if (res->length) {
			resource->buffer = malloc(res->length);
			memcpy(resource->buffer, res->buffer, res->length);
			resource->length = res->length;
		}

		node->loop_module->add_idle_callback(&params->id,
					on_idle_callback, (void *)params);
	}
}

static bool check_lwm2m_uri(const char *uri)
{
	artik_utils_module *utils = (artik_utils_module *)
		artik_request_api_module("utils");
	artik_uri_info uri_info;
	bool ret = true;

	if (utils->get_uri_info(&uri_info, uri) != S_OK) {
		artik_release_api_module("utils");
		return false;
	}

	if (strcmp("coap", uri_info.scheme) != 0
		&& strcmp("coaps", uri_info.scheme) != 0
		&& strcmp("coap+tcp", uri_info.scheme) != 0
		&& strcmp("coaps+tcp", uri_info.scheme) != 0) {
		log_dbg("scheme is %s", uri_info.scheme);
		ret = false;
	}

	utils->free_uri_info(&uri_info);
	artik_release_api_module(utils);

	return ret;
}

static char *create_key_uri(artik_secure_element_config *se_config)
{
	const char *prefix;
	char *engine_key_uri;

	switch (se_config->key_algo) {
	case RSA_1024:
		prefix = "rsa1024://";
		break;
	case RSA_2048:
		prefix = "rsa2048://";
		break;
	case ECC_BRAINPOOL_P256R1:
		prefix = "bp256://";
		break;
	case ECC_SEC_P256R1:
		prefix = "ec256://";
		break;
	case ECC_SEC_P384R1:
		prefix = "ec384://";
		break;
	case ECC_SEC_P521R1:
		prefix = "ec521://";
		break;
	default:
		log_dbg("algo %d not supported", se_config->key_algo);
		return NULL;
	}

	engine_key_uri = malloc(strlen(prefix) + strlen(se_config->key_id) + 1);
	if (!engine_key_uri)
		return NULL;

	strcpy(engine_key_uri, prefix);
	strcat(engine_key_uri, se_config->key_id);

	return engine_key_uri;
}

static bool ssl_context_callback(void *ssl_ctx, void *user_data)
{
	X509 *cert = NULL;
	BIO *b64 = NULL;
	EVP_PKEY *pkey = NULL;
	artik_security_module *security = NULL;
	artik_ssl_config *ssl = user_data;
	SSL_CTX *ctx = (SSL_CTX *)ssl_ctx;
	bool ret = false;
	char *uri = NULL;

	security = (artik_security_module *)
		artik_request_api_module("security");
	if (!security) {
		log_dbg("Failed to request security module.");
		goto exit;
	}

	if (security->load_openssl_engine() != S_OK) {
		log_dbg("Failed to load openssl engine");
		goto exit;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	ENGINE *engine = ENGINE_get_default_ECDSA();
#else
	ENGINE *engine = ENGINE_get_default_EC();
#endif

	if (!engine) {
		log_dbg("Failed to get default engine");
		goto exit;
	}

	uri = create_key_uri(ssl->se_config);
	if (!uri) {
		log_dbg("Failed to create key uri");
		goto exit;
	}

	pkey = ENGINE_load_private_key(engine,
								   uri, NULL, NULL);
			free(uri);
	if (!pkey) {
		log_dbg("Failed to load private key from artiksee");
		goto exit;
	}

	b64 = BIO_new(BIO_s_mem());
	if (!b64) {
		log_dbg("Failed to allocate memory");
		goto exit;
	}

	BIO_write(b64, ssl->client_cert.data, ssl->client_cert.len);

	cert = PEM_read_bio_X509(b64, NULL, NULL, NULL);
	if (!cert) {
		log_dbg("Failed to parse client certificate");
		goto exit;

	}

	if (!SSL_CTX_use_certificate(ctx, cert)) {
		log_dbg("Failed to set client certificate");
		goto exit;
	}

	if (!SSL_CTX_use_PrivateKey(ctx, pkey)) {
		log_dbg("Failed to set client private key");
		goto exit;
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		log_dbg("Failed to check private key");
		goto exit;
	}

	ret = true;

exit:
	if (security)
		artik_release_api_module(security);

	if (pkey)
		EVP_PKEY_free(pkey);

	if (!cert)
		X509_free(cert);

	if (b64)
		BIO_free(b64);

	return ret;
}

artik_error os_lwm2m_client_request(artik_lwm2m_handle *handle,
				artik_lwm2m_config *config)
{
	lwm2m_node *node = NULL;
	object_container_t *objects;
	object_security_server_t *server;
	artik_error ret = S_OK;
	int i;

	log_dbg("");

	if (!config || !config->server_uri || !config->name)
		return E_BAD_ARGS;

	if (config->lifetime < 0 || config->server_id < 0)
		return E_BAD_ARGS;

	if (!check_lwm2m_uri(config->server_uri))
		return E_BAD_ARGS;

	if (!config->tls_psk_identity && !config->ssl_config)
		return E_BAD_ARGS;

	if (!config->tls_psk_key)
		return E_BAD_ARGS;

	node = (lwm2m_node *) artik_list_add(&nodes, 0, sizeof(lwm2m_node));
	if (!node)
		return E_NO_MEM;

	objects = malloc(sizeof(object_container_t));
	if (!objects) {
		artik_list_delete_node(&nodes, (artik_list *)node);
		return E_NO_MEM;
	}

	server = malloc(sizeof(object_security_server_t));
	if (!server) {
		artik_list_delete_node(&nodes, (artik_list *)node);
		free(objects);
		return E_NO_MEM;
	}

	node->loop_module =  (artik_loop_module *)
					artik_request_api_module("loop");

	/* Fill up server object based on passed config */
	memset(objects, 0, sizeof(object_container_t));
	memset(server, 0, sizeof(object_security_server_t));

	strncpy(server->serverUri, config->server_uri, LWM2M_MAX_STR_LEN - 1);
	strncpy(server->client_name, config->name, LWM2M_MAX_STR_LEN - 1);
	server->securityMode = LWM2M_SEC_MODE_PSK;

	log_dbg("config->ssl_config = %p", config->ssl_config);
	if (config->ssl_config) {
		if (!config->tls_psk_key) {
			ret = E_BAD_ARGS;
			goto exit;
		}

		server->verifyCert = config->ssl_config->verify_cert == ARTIK_SSL_VERIFY_REQUIRED;
		log_dbg("Check cert mode");
		if (config->ssl_config->client_cert.data && config->ssl_config->client_cert.len
			&& config->ssl_config->client_key.data && config->ssl_config->client_key.len) {
			server->clientCertificateOrPskId = strdup(config->ssl_config->client_cert.data);
			server->privateKey = strdup(config->ssl_config->client_key.data);
			server->securityMode = LWM2M_SEC_MODE_CERT;
			log_dbg("Cert Mode");
			log_dbg("server->clientCertif = %s", server->clientCertificateOrPskId);
		} else if (!config->ssl_config->client_cert.data && !config->ssl_config->client_cert.len
				   && !config->ssl_config->client_key.data && !config->ssl_config->client_key.len) {
			if (!config->tls_psk_identity) {
				ret = E_BAD_ARGS;
				goto exit;
			}

			server->clientCertificateOrPskId = strdup(config->tls_psk_identity);
			log_dbg("Copy PSK parameters (%s/%s)", config->tls_psk_identity,
					config->tls_psk_key);
		} else {
			ret = E_BAD_ARGS;
			goto exit;
		}

		strncpy(server->token, config->tls_psk_key, LWM2M_MAX_STR_LEN - 1);

		if (config->ssl_config->ca_cert.data)
			server->serverCertificate = strdup(config->ssl_config->ca_cert.data);

	} else if (config->tls_psk_identity && config->tls_psk_key) {
		server->clientCertificateOrPskId = strdup(config->tls_psk_identity);
		strncpy(server->token, config->tls_psk_key, LWM2M_MAX_STR_LEN - 1);
		log_dbg("Copy PSK parameters (%s/%s)", config->tls_psk_identity,
							config->tls_psk_key);
	}

	server->lifetime = config->lifetime;
	server->serverId = config->server_id;

	objects->server = server;

	/* Copy objects if they have been provided */
	for (i = 0; i < ARTIK_LWM2M_OBJECT_COUNT; i++) {
		if (!config->objects[i])
			continue;

		if (!config->objects[i]->content)
			continue;

		switch (config->objects[i]->type) {
		case ARTIK_LWM2M_OBJECT_DEVICE:
			objects->device = malloc(sizeof(object_device_t));
			if (!objects->device) {
				ret = E_NO_MEM;
				goto exit;
			}
			memcpy(objects->device, config->objects[i]->content, sizeof(object_device_t));
			break;
		case ARTIK_LWM2M_OBJECT_CONNECTIVITY_MONITORING:
			objects->monitoring = malloc(sizeof(object_conn_monitoring_t));
			if (!objects->monitoring) {
				ret = E_NO_MEM;
				goto exit;
			}
			memcpy(objects->monitoring, config->objects[i]->content, sizeof(object_conn_monitoring_t));
			break;
		case ARTIK_LWM2M_OBJECT_FIRMWARE:
			objects->firmware = malloc(sizeof(object_firmware_t));
			if (!objects->firmware) {
				ret = E_NO_MEM;
				goto exit;
			}
			memcpy(objects->firmware, config->objects[i]->content, sizeof(object_firmware_t));
			break;
		default:
			log_err("Unknown object");
			break;
		}
	}

	node->container = objects;

	/* Configure the client */
	if (config->ssl_config && config->ssl_config->se_config)
		node->client = lwm2m_client_start(node->container,
				node->container->server->serverCertificate,
				ssl_context_callback, config->ssl_config);
	else
		node->client = lwm2m_client_start(node->container,
				node->container->server->serverCertificate, NULL, NULL);
	if (!node->client) {
		log_dbg("lwm2m_client error");
		return E_BAD_ARGS;
	}

	*handle = (artik_lwm2m_handle)node;

	return S_OK;

exit:
	artik_list_delete_node(&nodes, (artik_list *)node);
	if (server) {
		if (server->serverCertificate)
			free(server->serverCertificate);

		if (server->clientCertificateOrPskId)
			free(server->clientCertificateOrPskId);

		if (server->privateKey)
			free(server->privateKey);

		free(server);
	}

	if (objects) {
		if (objects->device)
			free(objects->device);

		if (objects->firmware)
			free(objects->firmware);

		if (objects->monitoring)
			free(objects->monitoring);

		free(objects);
	}

	return ret;
}

artik_error os_lwm2m_client_release(artik_lwm2m_handle handle)
{
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes,
						(ARTIK_LIST_HANDLE) handle);

	log_dbg("");

	if (!node)
		return E_BAD_ARGS;

	if (node->container) {
		if (node->container->server) {
			if (node->container->server->serverCertificate)
				free(node->container->server->serverCertificate);

			if (node->container->server->clientCertificateOrPskId)
				free(node->container->server->clientCertificateOrPskId);

			if (node->container->server->privateKey)
				free(node->container->server->privateKey);

			free(node->container->server);
		}

		if (node->container->device)
			free(node->container->device);

		if (node->container->firmware)
			free(node->container->firmware);

		if (node->container->monitoring)
			free(node->container->monitoring);

		free(node->container);
	}

	artik_release_api_module(node->loop_module);
	artik_list_delete_node(&nodes, (artik_list *)node);
	return S_OK;
}

artik_error os_lwm2m_client_connect(artik_lwm2m_handle handle)
{
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes, (ARTIK_LIST_HANDLE) handle);
	artik_error ret = S_OK;

	log_dbg("");

	if (!node)
		return E_BAD_ARGS;

	node->connected = false;

	/* Start timeout callback to service the LWM2M library */
	ret = node->loop_module->add_idle_callback(&node->service_cbk_id,
							on_lwm2m_service_callback, (void *)node);
	if (ret != S_OK) {
		log_err("Failed to start timeout callback for LWM2M servicing");
		os_lwm2m_client_disconnect(node);
		return ret;
	}

	lwm2m_register_callback(node->client, LWM2M_EXE_FACTORY_RESET,
							on_exec_factory_reset,
							(void *)node);
	lwm2m_register_callback(node->client, LWM2M_EXE_DEVICE_REBOOT,
							on_exec_device_reboot,
							(void *)node);
	lwm2m_register_callback(node->client, LWM2M_EXE_FIRMWARE_UPDATE,
							on_exec_firmware_update,
							(void *)node);
	lwm2m_register_callback(node->client,
							LWM2M_NOTIFY_RESOURCE_CHANGED,
							on_resource_changed,
							(void *)node);

	return ret;
}

artik_error os_lwm2m_client_disconnect(artik_lwm2m_handle handle)
{
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes,
			(ARTIK_LIST_HANDLE) handle);

	log_dbg("");

	if (!node)
		return E_BAD_ARGS;

	if (!node->client)
		return E_NOT_CONNECTED;

	lwm2m_client_stop(node->client);
	node->loop_module->remove_timeout_callback(node->service_cbk_id);

	return S_OK;
}

artik_error os_lwm2m_client_write_resource(artik_lwm2m_handle handle,
		const char *uri, unsigned char *buffer, int length)
{
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes,
				(ARTIK_LIST_HANDLE) handle);
	lwm2m_resource_t res;
	artik_error ret = S_OK;

	log_dbg("");

	if (!node || !uri)
		return E_BAD_ARGS;

	if (!node->client)
		return E_NOT_CONNECTED;

	strncpy(res.uri, uri, LWM2M_MAX_URI_LEN - 1);
	res.length = length;
	res.buffer = buffer;

	if (lwm2m_write_resource(node->client, &res) != LWM2M_CLIENT_OK) {
		log_err("Failed to write resource %s", res.uri);
		ret = E_LWM2M_ERROR;
		goto exit;
	}

exit:
	return ret;
}

artik_error os_lwm2m_client_read_resource(artik_lwm2m_handle handle,
		const char *uri, unsigned char *buffer, int *length)
{
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes,
					(ARTIK_LIST_HANDLE) handle);
	lwm2m_resource_t res;
	artik_error ret = S_OK;

	log_dbg("");

	if (!node || !uri || !buffer || (*length == 0))
		return E_BAD_ARGS;

	if (!node->client)
		return E_NOT_CONNECTED;

	memset(&res, 0, sizeof(res));
	strncpy(res.uri, uri, LWM2M_MAX_URI_LEN - 1);

	if (lwm2m_read_resource(node->client, &res)) {
		log_err("Failed to read resource %s", res.uri);
		return E_LWM2M_ERROR;
	}

	if (res.length > *length) {
		log_err("Buffer is too small");
		ret = E_NO_MEM;
		goto exit;
	}

	*length = res.length;
	memcpy(buffer, res.buffer, res.length);

exit:
	if (res.buffer)
		free(res.buffer);

	return ret;
}

artik_error os_lwm2m_set_callback(artik_lwm2m_handle handle,
		artik_lwm2m_event_t event,
		artik_lwm2m_callback user_callback, void *user_data)
{
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes,
				(ARTIK_LIST_HANDLE) handle);

	log_dbg("");

	if (!node || !user_callback || (event >= ARTIK_LWM2M_EVENT_COUNT))
		return E_BAD_ARGS;

	node->callbacks[event] = user_callback;
	node->callbacks_params[event] = user_data;

	return S_OK;
}

artik_error os_lwm2m_unset_callback(artik_lwm2m_handle handle,
				artik_lwm2m_event_t event)
{
	lwm2m_node *node = (lwm2m_node *)artik_list_get_by_handle(nodes,
			(ARTIK_LIST_HANDLE) handle);

	log_dbg("");

	if (!node || (event >= ARTIK_LWM2M_EVENT_COUNT))
		return E_BAD_ARGS;

	node->callbacks[event] = NULL;
	node->callbacks_params[event] = NULL;

	return S_OK;
}

artik_lwm2m_object *os_lwm2m_create_device_object(const char *manufacturer,
		const char *model, const char *serial, const char *fw_version,
		const char *hw_version, const char *sw_version,
		const char *device_type, int power_source, int power_volt,
		int power_current, int battery_level, int memory_total,
		int memory_free, const char *time_zone, const char *utc_offset,
		const char *binding)
{
	artik_lwm2m_object *obj = NULL;
	object_device_t *content = NULL;

	log_dbg("");

	obj = malloc(sizeof(*obj));
	if (!obj) {
		log_err("Not enough memory to allocate LWM2M object");
		return NULL;
	}

	memset(obj, 0, sizeof(*obj));
	obj->type = ARTIK_LWM2M_OBJECT_DEVICE;

	content = malloc(sizeof(object_device_t));
	if (!content) {
		log_err("Not enough memory to allocate LWM2M object content");
		free(obj);
		return NULL;
	}

	memset(content, 0, sizeof(*content));

	if (manufacturer)
		strncpy(content->manufacturer, manufacturer, LWM2M_MAX_STR_LEN - 1);

	if (model)
		strncpy(content->model_number, model, LWM2M_MAX_STR_LEN - 1);

	if (serial)
		strncpy(content->serial_number, serial, LWM2M_MAX_STR_LEN - 1);

	if (fw_version)
		strncpy(content->firmware_version, fw_version,
			LWM2M_MAX_STR_LEN - 1);

	if (hw_version)
		strncpy(content->hardware_version, hw_version,
			LWM2M_MAX_STR_LEN - 1);

	if (sw_version)
		strncpy(content->software_version, sw_version,
			LWM2M_MAX_STR_LEN - 1);

	if (device_type)
		strncpy(content->device_type, device_type, LWM2M_MAX_STR_LEN - 1);

	content->power_source_1 = power_source;
	content->power_voltage_1 = power_volt;
	content->power_current_1 = power_current;
	content->battery_level = battery_level;
	content->memory_total = memory_total;
	content->memory_free = memory_free;

	if (time_zone)
		strncpy(content->time_zone, time_zone, LWM2M_MAX_STR_LEN - 1);

	if (utc_offset)
		strncpy(content->utc_offset, utc_offset, LWM2M_MAX_STR_LEN - 1);

	if (binding)
		strncpy(content->binding_mode, binding, LWM2M_MAX_STR_LEN - 1);

	obj->content = (void *)content;

	return obj;
}

artik_lwm2m_object *os_lwm2m_create_firmware_object(bool supported,
		char *pkg_name, char *pkg_version)
{
	artik_lwm2m_object *obj = NULL;
	object_firmware_t *content = NULL;

	log_dbg("");

	obj = malloc(sizeof(artik_lwm2m_object));
	if (!obj) {
		log_err("Not enough memory to allocate LWM2M object");
		return NULL;
	}
	memset(obj, 0, sizeof(artik_lwm2m_object));
	obj->type = ARTIK_LWM2M_OBJECT_FIRMWARE;

	content = malloc(sizeof(object_firmware_t));
	if (!content) {
		log_err("Not enough memory to allocale LWM2M object content");
		free(obj);
		return NULL;
	}

	memset(content, 0, sizeof(object_firmware_t));
	content->supported = supported;

	if (pkg_name)
		strncpy(content->pkg_name, pkg_name, LWM2M_MAX_STR_LEN - 1);

	if (pkg_version)
		strncpy(content->pkg_version, pkg_version, LWM2M_MAX_STR_LEN - 1);

	obj->content = (void *)content;
	return obj;
}

artik_lwm2m_object *os_lwm2m_create_connectivity_monitoring_object(
			int netbearer, int avlnetbearer,
			int signalstrength, int linkquality,
			int lenip, const char **ipaddr,
			int lenroute, const char **routeaddr,
			int linkutilization, const char *apn,
			int cellid, int smnc, int smcc)
{
	artik_lwm2m_object *obj = NULL;
	object_conn_monitoring_t *content = NULL;

	log_dbg("");

	obj = malloc(sizeof(*obj));
	if (!obj) {
		log_err("Not enough memory to allocate LWM2M object");
		return NULL;
	}

	memset(obj, 0, sizeof(*obj));
	obj->type = ARTIK_LWM2M_OBJECT_CONNECTIVITY_MONITORING;

	content = malloc(sizeof(object_device_t));
	if (!content) {
		log_err("Not enough memory to allocate LWM2M object content");
		free(obj);
		return NULL;
	}

	memset(content, 0, sizeof(*content));

	content->avl_network_bearer = netbearer;
	content->radio_signal_strength = avlnetbearer;
	content->link_quality = signalstrength;
	content->link_utilization = linkquality;
	content->cell_id = cellid;
	content->smnc = smnc;
	content->smcc = smcc;
	if (ipaddr && lenip >= 1 && ipaddr[0])
		strncpy(content->ip_addr2, ipaddr[0], LWM2M_MAX_STR_LEN - 1);
	if (ipaddr && lenip >= 2 && ipaddr[1])
		strncpy(content->ip_addr2, ipaddr[1], LWM2M_MAX_STR_LEN - 1);
	if (routeaddr && lenroute >= 1 && routeaddr[0])
		strncpy(content->router_ip_addr, routeaddr[0],
							LWM2M_MAX_STR_LEN - 1);
	if (routeaddr && lenroute >= 2 && routeaddr[1])
		strncpy(content->router_ip_addr2, routeaddr[1],
							LWM2M_MAX_STR_LEN - 1);
	if (apn)
		strncpy(content->apn, apn, LWM2M_MAX_STR_LEN - 1);

	obj->content = (void *)content;
	return obj;
}


void os_lwm2m_free_object(artik_lwm2m_object *object)
{
	log_dbg("");

	if (object) {
		if (object->content)
			free(object->content);
		free(object);
	}
}

artik_error os_serialize_tlv_int(int *data, int size,
				unsigned char **buffer, int *lenbuffer)
{
	lwm2m_resource_t	resource_serialized;

	if (size <= 0 || data == NULL)
		return E_BAD_ARGS;
	if (lwm2m_serialize_tlv_int(size, data, &resource_serialized) ==
							LWM2M_CLIENT_ERROR) {
		log_err("Can't serialize data of type 'array of integer',\n"
			"got an error from lwm2m.");
		return E_LWM2M_ERROR;
	}
	*lenbuffer = resource_serialized.length;
	if (resource_serialized.length < 1)
		return E_INVALID_VALUE;
	*buffer = resource_serialized.buffer;
	return S_OK;
}

artik_error os_serialize_tlv_string(char **data, int size,
					unsigned char **buffer, int *lenbuffer)
{
	lwm2m_resource_t	resource_serialized;

	if (size <= 0 || data == NULL)
		return E_BAD_ARGS;
	if (lwm2m_serialize_tlv_string(size, data, &resource_serialized) ==
							LWM2M_CLIENT_ERROR) {
		log_err("Can't serialize data of type 'array of string',\n"
			"got an error from lwm2m.");
		return E_LWM2M_ERROR;
	}
	*lenbuffer = resource_serialized.length;
	if (resource_serialized.length < 1)
		return E_INVALID_VALUE;
	*buffer = resource_serialized.buffer;
	return S_OK;
}
