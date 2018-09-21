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

#include <artik_log.h>
#include <artik_module.h>
#include <artik_coap.h>

#include <string.h>
#include <ctype.h>
#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#include <er-coap-13.h>

#include <pthread.h>
#include <sched.h>

#include <stdio.h>

#include "../os_coap.h"
#include "coap_resource.h"
#include "coap_address.h"
#include "coap_session.h"
#include "coap_uri.h"
#include "coap_dtls.h"
#include "coap_block.h"
#include "coap_socket.h"
#include "coap.h"
#include "coap_mem.h"

#define INTEGER		0x02
#define BIT_STRING	0x03
#define OCTET_STRING	0x04
#define OBJ_IDENTIFIER	0x06
#define SEQUENCE	0x30
#define OPT_PARAMS	0xA0
#define OPT_PUBKEY	0xA1

#define NI_MAXHOST	1025
#define NI_MAXSERV	32

#define MAX_IDLE_SESSIONS 5 // 0 for not limit
#define SESSION_TIMEOUT 30 // 0 for 300 s by default

/* ecPublicKey (Object Identifier) */
static unsigned char ec_public_key[] = {
	0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
};

/* prime256v1 (Object Identifier) */
static unsigned char prime_256v1[] = {
	0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

typedef struct {
	pthread_t thread_id;
	coap_context_t *ctx;
	coap_protocol_t proto;
	bool quit;
} os_coap_data;

typedef struct {
	coap_context_t *ctx;
	coap_session_t *session;
	artik_coap_config config;
	artik_coap_send_callback send_cb;
	artik_coap_observe_callback observe_cb;
	void *send_data;
	void *observe_data;
	bool enable_verify_psk;
	artik_list *requested_resource_node;
	bool client;
	bool connected;
	bool started;
	bool created;
	bool secure_connection;
	int method;
	int msg_type;
	char *uri_path;
	char *uri_query;
	char *location_path;
	char *location_query;
	bool use_uri_path;
	bool use_uri_query;
	bool use_location_path;
	bool use_location_query;
	artik_coap_option *coap_options;
	int num_coap_options;
	os_coap_data *coap_data;
} os_coap_interface;

typedef struct {
	coap_resource_t *res;
	artik_coap_resource_callback resource_cb[ARTIK_COAP_REQ_DELETE];
	void *resource_data[ARTIK_COAP_REQ_DELETE];
} os_coap_resource;

typedef struct {
	artik_list node;
	os_coap_interface interface;
} coap_node;

typedef struct {
	artik_list node;
	unsigned char *path;
	os_coap_resource resource;
} resource_node;

static int n = 1;

#define ARCH_LITTLE_ENDIAN (*(char *)&n == 1)

static void swap_bytes(unsigned int *val, int length)
{
	if (length == 1 || length == 0)
		return;
	else if (length == 2)
		*val = ((((*val >> 8) & 0x00FF) | ((*val << 8) & 0xFF00)));
	else if (length == 3)
		*val = (((*val >> 16) & 0x0000FF) | (*val & 0x00FF00) |
			(*val << 16 & 0xFF0000));
	else
		*val = ((((*val) >> 24) & 0x000000FF) | (((*val) >> 8) & 0x0000FF00) |
			(((*val) << 8) & 0x00FF0000) | (((*val) << 24) & 0xFF000000));
}

static artik_list *requested_node = NULL;

static void add_options(coap_packet_t *packet, artik_coap_option *options,
				int num_options, bool observe, coap_node *node)
{
	artik_coap_option *opt = options;
	artik_coap_option *end = opt + num_options;

	bool is_location_path = false;
	size_t location_path_len = 0;

	bool is_uri_path = false;
	size_t uri_path_len = 0;

	bool is_location_query = false;
	size_t location_query_len = 0;
	int location_query_index = 0;

	bool is_uri_query = false;
	size_t uri_query_len = 0;
	int uri_query_index = 0;

	for (; opt != end; opt++) {
		switch (opt->key) {
		case ARTIK_COAP_OPTION_LOCATION_PATH:
			if (!is_location_path)
				is_location_path = true;
			location_path_len += (opt->data_len + 1);
			break;
		case ARTIK_COAP_OPTION_URI_PATH:
			if (!is_uri_path)
				is_uri_path = true;
			uri_path_len += (opt->data_len + 1);
			break;
		case ARTIK_COAP_OPTION_LOCATION_QUERY:
			if (!is_location_query)
				is_location_query = true;
			location_query_len += (opt->data_len + 1);
			break;
		case ARTIK_COAP_OPTION_URI_QUERY:
			if (!is_uri_query)
				is_uri_query = true;
			uri_query_len += (opt->data_len + 1);
			break;
		default:
			break;
		}
	}

	if (is_location_path && node) {
		if (node->interface.location_path) {
			coap_free(node->interface.location_path);
			node->interface.location_path = NULL;
		}

		node->interface.location_path = coap_malloc(location_path_len + 1);

		if (!node->interface.location_path) {
			log_err("Memory problem");
			return;
		}

		memset(node->interface.location_path, 0, location_path_len + 1);
	}

	if (is_uri_path && node) {
		if (node->interface.uri_path) {
			coap_free(node->interface.uri_path);
			node->interface.uri_path = NULL;
		}

		node->interface.uri_path = coap_malloc(uri_path_len + 1);

		if (!node->interface.uri_path) {
			log_err("Memory problem");
			return;
		}

		memset(node->interface.uri_path, 0, uri_path_len + 1);
	}

	if (is_location_query && node) {
		if (node->interface.location_query) {
			coap_free(node->interface.location_query);
			node->interface.location_query = NULL;
		}

		node->interface.location_query = coap_malloc(location_query_len + 1);

		if (!node->interface.location_query) {
			log_err("Memory problem");
			return;
		}

		memset(node->interface.location_query, 0, location_query_len + 1);
	}

	if (is_uri_query && node) {
		if (node->interface.uri_query) {
			coap_free(node->interface.uri_query);
			node->interface.uri_query = NULL;
		}

		node->interface.uri_query = coap_malloc(uri_query_len + 1);

		if (!node->interface.uri_query) {
			log_err("Memory problem");
			return;
		}

		memset(node->interface.uri_query, 0, uri_query_len + 1);
	}

	opt = options;
	end = opt + num_options;

	for (; opt != end; opt++) {
		switch (opt->key) {
		case ARTIK_COAP_OPTION_IF_MATCH:
			coap_set_header_if_match((void *)packet,
				(uint8_t *)opt->data, opt->data_len);
			break;
		case ARTIK_COAP_OPTION_URI_HOST:
			coap_set_header_uri_host((void *)packet,
				(char *)opt->data);
			break;
		case ARTIK_COAP_OPTION_ETAG:
			coap_set_header_etag((void *)packet,
				(uint8_t *)opt->data, opt->data_len);
			break;
		case ARTIK_COAP_OPTION_URI_PATH:
			if (is_uri_path && node && node->interface.uri_path) {
				strncat(node->interface.uri_path, "/", 1);
				strncat(node->interface.uri_path, (char *)opt->data, opt->data_len);
			}
			break;
		case ARTIK_COAP_OPTION_URI_QUERY:
			if (is_uri_query && node && node->interface.uri_query) {
				if (uri_query_index == 0) {
					uri_query_index++;
					strncat(node->interface.uri_query, "?", 1);
				} else
					strncat(node->interface.uri_query, "&", 1);
				strncat(node->interface.uri_query, (char *)opt->data, opt->data_len);
			}
			break;
		case ARTIK_COAP_OPTION_LOCATION_PATH:
			if (is_location_path && node && node->interface.location_path) {
				strncat(node->interface.location_path, "/", 1);
				strncat(node->interface.location_path, (char *)opt->data, opt->data_len);
			}
			break;
		case ARTIK_COAP_OPTION_LOCATION_QUERY:
			if (is_location_query && node && node->interface.location_query) {
				if (location_query_index == 0) {
					location_query_index++;
					strncat(node->interface.location_query, "?", 1);
				} else
					strncat(node->interface.location_query, "&", 1);
				strncat(node->interface.location_query, (char *)opt->data, opt->data_len);
			}
			break;
		case ARTIK_COAP_OPTION_PROXY_URI:
			coap_set_header_proxy_uri((void *)packet,
				(char *)opt->data);
			break;
		case ARTIK_COAP_OPTION_PROXY_SCHEME:
			coap_set_header_proxy_scheme((void *)packet,
				(char *)opt->data);
			break;
		case ARTIK_COAP_OPTION_URI_PORT: {
			unsigned int uri_port = 0;

			memcpy(&uri_port, opt->data, opt->data_len);

			if (ARCH_LITTLE_ENDIAN)
				swap_bytes(&uri_port, opt->data_len);

			coap_set_header_uri_port((void *)packet,
				(uint16_t)uri_port);
			break;
		}
		case ARTIK_COAP_OPTION_ACCEPT: {
			unsigned int accept = 0;

			memcpy(&accept, opt->data, opt->data_len);

			if (ARCH_LITTLE_ENDIAN)
				swap_bytes(&accept, opt->data_len);

			coap_set_header_accept((void *)packet,
				(uint16_t)accept);
			break;
		}
		case ARTIK_COAP_OPTION_CONTENT_FORMAT: {
			unsigned int content_format = 0;

			memcpy(&content_format, opt->data, opt->data_len);

			if (ARCH_LITTLE_ENDIAN)
				swap_bytes(&content_format, opt->data_len);

			coap_set_header_content_type((void *)packet,
				content_format);
			break;
		}
		case ARTIK_COAP_OPTION_MAXAGE: {
			unsigned int max_age = 0;

			memcpy(&max_age, opt->data, opt->data_len);

			if (ARCH_LITTLE_ENDIAN)
				swap_bytes(&max_age, opt->data_len);

			coap_set_header_max_age((void *)packet,
				(uint32_t)max_age);
			break;
		}
		case ARTIK_COAP_OPTION_SIZE1: {
			unsigned int size1 = 0;

			memcpy(&size1, opt->data, opt->data_len);

			if (ARCH_LITTLE_ENDIAN)
				swap_bytes(&size1, opt->data_len);

			coap_set_header_size1((void *)packet,
				(uint32_t)size1);
			break;
		}
		case ARTIK_COAP_OPTION_OBSERVE: {
			if (observe) {
				unsigned int observeData = 0;

				memcpy(&observeData, opt->data, opt->data_len);

				if (ARCH_LITTLE_ENDIAN)
					swap_bytes(&observeData, opt->data_len);

				coap_set_header_observe((void *)packet,
					(uint32_t)observeData);
			}
			break;
		}
		case ARTIK_COAP_OPTION_IF_NONE_MATCH:
			coap_set_header_if_none_match((void *)packet);
			break;
		case ARTIK_COAP_OPTION_BLOCK2: {
			uint32_t block2 = 0;
			coap_block_t block;

			memcpy(&block2, opt->data, opt->data_len);

			if (ARCH_LITTLE_ENDIAN)
				swap_bytes(&block2, opt->data_len);

			coap_convert_to_block(block2, &block);

			coap_set_header_block2((void *)packet,
				block.num, block.m, block.szx);

			break;
		}
		default:
			break;
		}
	}

	if (is_location_path && node && node->interface.location_path) {
		coap_set_header_location_path((void *)packet, node->interface.location_path);
		node->interface.use_location_path = true;
	}

	if (is_uri_path && node && node->interface.uri_path) {
		coap_set_header_uri_path((void *)packet, node->interface.uri_path);
		node->interface.use_uri_path = true;
	}

	if (is_location_query && node && node->interface.location_query) {
		coap_set_header_location_query((void *)packet, node->interface.location_query);
		node->interface.use_location_query = true;
	}

	if (is_uri_query && node && node->interface.uri_query) {
		coap_set_header_uri_query((void *)packet, node->interface.uri_query);
		node->interface.use_uri_query = true;
	}
}

static int get_number_options(const coap_packet_t *packet)
{
	if (!packet)
		return 0;

	int number = 0;

	if (IS_OPTION(packet, COAP_OPTION_IF_MATCH))
		number++;
	if (IS_OPTION(packet, COAP_OPTION_URI_HOST))
		number++;
	if (IS_OPTION(packet, COAP_OPTION_ETAG))
		number++;
	if (IS_OPTION(packet, COAP_OPTION_IF_NONE_MATCH))
		number++;
	if (IS_OPTION(packet, COAP_OPTION_OBSERVE))
		number++;
	if (IS_OPTION(packet, COAP_OPTION_URI_PORT))
		number++;
	if (IS_OPTION(packet, COAP_OPTION_LOCATION_PATH)) {
		multi_option_t *optP;

		for (optP = packet->location_path; optP != NULL; optP = optP->next)
			number++;
	}
	if (IS_OPTION(packet, COAP_OPTION_URI_PATH)) {
		multi_option_t *optP;

		for (optP = packet->uri_path; optP != NULL; optP = optP->next)
			number++;
	}
	if (IS_OPTION(packet, COAP_OPTION_CONTENT_TYPE))
		number++;
	if (IS_OPTION(packet, COAP_OPTION_MAX_AGE))
		number++;
	if (IS_OPTION(packet, COAP_OPTION_URI_QUERY)) {
		multi_option_t *optP;

		for (optP = packet->uri_query; optP != NULL; optP = optP->next)
			number++;
	}
	if (IS_OPTION(packet, COAP_OPTION_ACCEPT))
		number++;
	if (IS_OPTION(packet, COAP_OPTION_LOCATION_QUERY)) {
		const char *query;
		const char sep[2] = "&";
		char *buf;
		int len;

		len = coap_get_header_location_query((void *)packet, &query);

		buf = (char *)coap_malloc(len + 1);

		if (!buf) {
			log_err("Memory problem");
		} else {

			buf[len] = 0;

			memcpy(buf, query, len);

			char *sub_query = strtok((char *)buf, sep);

			while (sub_query) {
				sub_query = strtok(NULL, sep);
				number++;
			}

			coap_free(buf);
		}
	}
	if (IS_OPTION(packet, COAP_OPTION_PROXY_URI))
		number++;
	if (IS_OPTION(packet, COAP_OPTION_PROXY_SCHEME))
		number++;
	if (IS_OPTION(packet, COAP_OPTION_SIZE1))
		number++;
	if (IS_OPTION(packet, COAP_OPTION_BLOCK2))
		number++;

	return number;
}

static void get_options(const coap_packet_t *packet, artik_coap_option **options,
			int *num_options, bool observe)
{
	artik_coap_option *opt;
	artik_coap_option *end;

	*num_options = get_number_options(packet);

	if (*num_options == 0)
		return;

	*options = (artik_coap_option *)coap_malloc(*num_options*sizeof(artik_coap_option));

	if (!*options) {
		log_err("Memory problem");
		return;
	}

	memset(*options, 0, *num_options*sizeof(artik_coap_option));

	opt = *options;
	end = opt + *num_options;

	if (opt != end && IS_OPTION(packet, COAP_OPTION_IF_MATCH)) {
		const uint8_t *etag;

		opt->key = ARTIK_COAP_OPTION_IF_MATCH;
		opt->data_len = coap_get_header_if_match((void *)packet,
					&etag);

		if (opt->data_len > 0) {
			opt->data = (unsigned char *)coap_malloc(opt->data_len);

			if (!opt->data) {
				log_err("Memory problem");
				return;
			}
			memcpy(opt->data, etag, opt->data_len);
		}

		opt++;
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_URI_HOST)) {
		const char *host;

		opt->key = ARTIK_COAP_OPTION_URI_HOST;
		opt->data_len = coap_get_header_uri_host((void *)packet,
					&host);

		if (opt->data_len > 0) {
			opt->data = (unsigned char *)coap_malloc(opt->data_len);

			if (!opt->data) {
				log_err("Memory problem");
				return;
			}

			strncpy((char *)opt->data, host, opt->data_len);
		}

		opt++;
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_ETAG)) {
		const uint8_t *etag;

		opt->key = ARTIK_COAP_OPTION_ETAG;
		opt->data_len = coap_get_header_etag((void *)packet,
					&etag);

		if (opt->data_len > 0) {
			opt->data = (unsigned char *)coap_malloc(opt->data_len);

			if (!opt->data) {
				log_err("Memory problem");
				return;
			}

			memcpy(opt->data, etag, opt->data_len);
		}

		opt++;
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_IF_NONE_MATCH)) {
		opt->key = ARTIK_COAP_OPTION_IF_NONE_MATCH;
		opt->data = NULL;
		opt->data_len = 0;
		opt++;
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_OBSERVE)) {
		if (observe) {
			uint32_t obs;

			opt->key = ARTIK_COAP_OPTION_OBSERVE;
			coap_get_header_observe((void *)packet,
					&obs);

			opt->data_len = 4;
			opt->data = (unsigned char *)coap_malloc(opt->data_len);

			if (!opt->data) {
				log_err("Memory problem");
				return;
			}

			memcpy(opt->data, &obs, opt->data_len);
		}
		opt++;
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_URI_PORT)) {
		uint16_t port;

		opt->key = ARTIK_COAP_OPTION_URI_PORT;
		coap_get_header_uri_port((void *)packet,
					&port);

		opt->data_len = 2;
		opt->data = (unsigned char *)coap_malloc(opt->data_len);

		if (!opt->data) {
			log_err("Memory problem");
			return;
		}

		memcpy(opt->data, &port, opt->data_len);
		opt++;
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_LOCATION_PATH)) {
		multi_option_t *optP;

		for (optP = packet->location_path; optP != NULL &&
			opt != end; optP = optP->next) {
			opt->key = ARTIK_COAP_OPTION_LOCATION_PATH;
			opt->data_len = optP->len;

			if (opt->data_len > 0) {
				opt->data = (unsigned char *)coap_malloc(opt->data_len + 1);

				if (!opt->data) {
					log_err("Memory problem");
					return;
				}

				opt->data[opt->data_len] = 0;
				memcpy(opt->data, optP->data, opt->data_len);
			}

			opt++;
		}
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_URI_PATH)) {
		multi_option_t *optP;

		for (optP = packet->uri_path; optP != NULL &&
			opt != end; optP = optP->next) {
			opt->key = ARTIK_COAP_OPTION_URI_PATH;
			opt->data_len = optP->len;

			if (opt->data_len > 0) {
				opt->data = (unsigned char *)coap_malloc(opt->data_len + 1);

				if (!opt->data) {
					log_err("Memory problem");
					return;
				}

				opt->data[opt->data_len] = 0;
				memcpy(opt->data, optP->data, opt->data_len);
			}

			opt++;
		}
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_CONTENT_TYPE)) {
		unsigned int content_type;

		opt->key = ARTIK_COAP_OPTION_CONTENT_TYPE;
		content_type = coap_get_header_content_type(
					(void *)packet);

		opt->data_len = 2;
		opt->data = (unsigned char *)coap_malloc(opt->data_len);

		if (!opt->data) {
			log_err("Memory problem");
			return;
		}

		memcpy(opt->data, &content_type, opt->data_len);
		opt++;
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_MAX_AGE)) {
		uint32_t age;

		opt->key = ARTIK_COAP_OPTION_MAXAGE;
		coap_get_header_max_age((void *)packet, &age);

		opt->data_len = 4;
		opt->data = (unsigned char *)coap_malloc(opt->data_len);

		if (!opt->data) {
			log_err("Memory problem");
			return;
		}

		memcpy(opt->data, &age, opt->data_len);
		opt++;
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_URI_QUERY)) {
		multi_option_t *optP;

		for (optP = packet->uri_query; optP != NULL &&
			opt != end; optP = optP->next) {
			opt->key = ARTIK_COAP_OPTION_URI_QUERY;
			opt->data_len = optP->len;

			if (opt->data_len > 0) {
				opt->data = (unsigned char *)coap_malloc(opt->data_len + 1);

				if (!opt->data) {
					log_err("Memory problem");
					return;
				}

				opt->data[opt->data_len] = 0;
				memcpy(opt->data, optP->data, opt->data_len);
			}

			opt++;
		}
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_ACCEPT)) {
		const uint16_t *accept;

		opt->key = ARTIK_COAP_OPTION_ACCEPT;
		coap_get_header_accept((void *)packet, &accept);

		opt->data_len = 2;
		opt->data = (unsigned char *)coap_malloc(opt->data_len);

		if (!opt->data) {
			log_err("Memory problem");
			return;
		}

		memcpy(opt->data, &accept, opt->data_len);
		opt++;
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_LOCATION_QUERY)) {
		const char *query;
		const char sep[2] = "&";
		char *buf = NULL;
		int buflen;

		buflen = coap_get_header_location_query(
					(void *)packet, &query);

		if (buflen > 0) {
			buf = (char *)coap_malloc(buflen + 1);

			if (!buf) {
				log_err("Memory problem");
				return;
			}

			buf[buflen] = 0;

			memcpy(buf, query, buflen);

			char *sub_query = strtok((char *)buf, sep);

			if (!sub_query) {
				opt->key = ARTIK_COAP_OPTION_LOCATION_QUERY;
				opt->data_len = buflen;
				opt->data = (unsigned char *)coap_malloc(opt->data_len + 1);

				if (!opt->data) {
					log_err("Memory problem");
					if (buf)
						coap_free(buf);
					return;
				}

				opt->data[opt->data_len] = 0;
				memcpy(opt->data, buf, opt->data_len + 1);
				opt++;
			}

			while (sub_query && opt != end) {
				int len = strlen(sub_query);

				if (len == 0) {
					log_err("Length null");
					if (buf)
						coap_free(buf);
					return;
				}

				opt->key = ARTIK_COAP_OPTION_LOCATION_QUERY;
				opt->data_len = len;
				opt->data = (unsigned char *)coap_malloc(opt->data_len + 1);

				if (!opt->data) {
					log_err("Memory problem");
					if (buf)
						coap_free(buf);
					return;
				}

				opt->data[opt->data_len] = 0;
				memcpy(opt->data, sub_query, opt->data_len + 1);
				sub_query = strtok(NULL, sep);
				opt++;
			}
		}

		if (buf)
			coap_free(buf);
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_PROXY_URI)) {
		const char *uri;

		opt->key = ARTIK_COAP_OPTION_PROXY_URI;
		opt->data_len = coap_get_header_proxy_uri(
					(void *)packet, &uri);

		if (opt->data_len > 0) {
			opt->data = (unsigned char *)coap_malloc(opt->data_len);

			if (!opt->data) {
				log_err("Memory problem");
				return;
			}

			strncpy((char *)opt->data, uri, opt->data_len);
		}

		opt++;
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_PROXY_SCHEME)) {
		const char *scheme;

		opt->key = ARTIK_COAP_OPTION_PROXY_SCHEME;
		opt->data_len = coap_get_header_proxy_scheme(
					(void *)packet, &scheme);

		if (opt->data_len > 0) {
			opt->data = (unsigned char *)coap_malloc(opt->data_len);

			if (!opt->data) {
				log_err("Memory problem");
				return;
			}

			strncpy((char *)opt->data, scheme, opt->data_len);
		}

		opt++;
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_SIZE1)) {
		uint32_t size;

		opt->key = ARTIK_COAP_OPTION_SIZE1;
		coap_get_header_size1((void *)packet, &size);

		opt->data_len = 4;
		opt->data = (unsigned char *)coap_malloc(opt->data_len);

		if (!opt->data) {
			log_err("Memory problem");
			return;
		}

		memcpy(opt->data, &size, opt->data_len);
		opt++;
	}
	if (opt != end && IS_OPTION(packet, COAP_OPTION_BLOCK2)) {
		uint32_t num = 0;
		uint8_t more = 0;
		uint16_t size = 0;
		uint32_t block2 = 0;
		uint16_t szx = 0;
		int count = 0;

		opt->key = ARTIK_COAP_OPTION_BLOCK2;
		coap_get_header_block2((void *)packet,
			&num, &more, &size, NULL);

		while (size != 1) {
			size >>= 1;
			count++;
		}

		szx = count - 4;

		opt->data_len = 3;
		opt->data = (unsigned char *)coap_malloc(opt->data_len);

		if (!opt->data) {
			log_err("Memory problem");
			return;
		}

		num <<= 4;

		more <<= 3;

		size = szx & 0x07;

		block2 = num | more | size;

		memcpy(opt->data, &block2, opt->data_len);
	}
}

static void free_options(artik_coap_option **options, int num_options)
{
	if (!*options || num_options < 0)
		return;

	int i;

	for (i = 0; i < num_options; i++) {
		if ((*options)[i].data)
			coap_free((*options)[i].data);
	}
	if (*options) {
		coap_free(*options);
		*options = NULL;
	}
}

static bool asn1_parse_pubkey(const unsigned char *data,
		int data_len, char **pub_key, int *pub_key_length)
{
	if (!data || !pub_key || *pub_key || !pub_key_length || data_len <= 0)
		return false;

	const unsigned char *p = data;
	const unsigned char *end = data + data_len;
	int i;

	if (*p == SEQUENCE && p+2 != end)
		p += 2;
	else
		return false;

	if (*p == SEQUENCE && p+2 != end)
		p += 2;
	else
		return false;

	if (*p == OBJ_IDENTIFIER && p+1 != end) {
		p++;

		int length = (int)*p;
		char buf[length];

		if (p+1 != end)
			p++;
		else
			return false;

		for (i = 0; i < length && p != end; i++, p++)
			buf[i] = (char)*p;

		if (p == end)
			return false;

		if (memcmp(buf, (char *)ec_public_key, length))
			return false;
	} else
		return false;

	if (*p == OBJ_IDENTIFIER && p+1 != end) {
		p++;

		int length = (int)*p;
		char buf[length];

		if (p+1 != end)
			p++;
		else
			return false;

		for (i = 0; i < length && p != end; i++, p++)
			buf[i] = (char)*p;

		if (p == end)
			return false;

		if (memcmp(buf, (char *)prime_256v1, length))
			return false;
	} else
		return false;

	if (*p == BIT_STRING && p+1 != end) {
		p++;

		int length = (int)*p;

		if (p+1 != end)
			p++;
		else
			return false;

		if (*p == 0x00) {
			length--;
			if (p+1 != end)
				p++;
			else
				return false;
		}

		(*pub_key) = (char *)coap_malloc((length)*sizeof(char));

		for (i = 0; i < length && p != end; i++, p++)
			(*pub_key)[i] = (char)*p;

		*pub_key_length = length;
	} else
		return false;

	return true;
}

static bool asn1_parse_key(const unsigned char *data, int data_len,
		const char *pub_key, char **key, int *key_length)
{
	if (!data || !key || *key || !key_length)
		return false;

	const unsigned char *p = data;
	const unsigned char *end = data + data_len;
	int i;

	if (*p == SEQUENCE)
		p += 2;
	else
		return false;

	if (*p == INTEGER && p+2 != end) {
		p += 2;

		if (*p != 0x01)
			return false;

		p++;
	} else
		return false;

	if (*p == OCTET_STRING && p+1 != end) {
		p++;

		int length = (int)*p;

		if (p+1 != end)
			p++;
		else
			return false;

		(*key) = (char *)coap_malloc((length)*sizeof(char));

		for (i = 0; i < length && p != end; i++, p++)
			(*key)[i] = (char)*p;

		*key_length = length;
	} else
		return false;

	if (p == end)
		return true;

	if (!pub_key) {
		log_err("Missing pub key");
		return false;
	}

	if (*p == OPT_PARAMS && p+2 != end)
		p += 2;
	else
		return false;

	if (*p == OBJ_IDENTIFIER && p+1 != end) {
		p++;

		int length = (int)*p;
		char buf[length];

		if (p+1 != end)
			p++;
		else
			return false;

		for (i = 0; i < length && p != end; i++, p++)
			buf[i] = (char)*p;

		if (p == end)
			return false;

		if (memcmp(buf, (char *)prime_256v1, length))
			return false;
	} else
		return false;

	if (*p == OPT_PUBKEY && p+2 != end)
		p += 2;
	else
		return false;

	if (*p == BIT_STRING && p+1 != end) {
		p++;

		int length = (int)*p;

		if (p+1 != end)
			p++;
		else
			return false;

		if (*p == 0x00) {
			length--;
			if (p+1 != end)
				p++;
			else
				return false;
		}

		char buf[length];

		for (i = 0; i < length && p != end; i++, p++)
			buf[i] = (char)*p;

		if (memcmp(buf, pub_key, length)) {
			log_err("The public key does not correspond to the"
				" private key.");
			return false;
		}
	} else
		return false;

	return true;
}

static int extract_pubkey_x_y(const char *pub_key, int pub_key_length,
			char **pub_key_x, char **pub_key_y)
{
	if (!pub_key || *pub_key_x || *pub_key_y) {
		log_err("Bad arguments in %s", __func__);
		return -1;
	}

	if (pub_key_length == 0 || (pub_key_length-1)%2 != 0) {
		log_err("Wrong size of pub_key");
		return -2;
	}

	size_t size = (pub_key_length-1)/2;

	*pub_key_x = (char *)coap_malloc(size);
	*pub_key_y = (char *)coap_malloc(size);

	if (!*pub_key_x && !*pub_key_y) {
		log_err("Memory problem");
		return -3;
	}

	int i = 1, j;

	for (j = 0; j < size && i < pub_key_length && *pub_key_x; j++)
		(*pub_key_x)[j] = pub_key[i++];

	for (j = 0; j < size && i < pub_key_length && *pub_key_y; j++)
		(*pub_key_y)[j] = pub_key[i++];

	return 0;
}

static int resolve_address(const coap_str *server, struct sockaddr *dst)
{
	struct addrinfo *res = NULL, *ainfo = NULL;
	struct addrinfo hints;
	static char addrstr[256];
	int error, len = -1;

	memset(addrstr, 0, sizeof(addrstr));

	if (server->length)
		memcpy(addrstr, server->s, server->length);
	else
		memcpy(addrstr, "localhost", 9);

	memset((char *)&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_family = AF_UNSPEC;

	error = getaddrinfo(addrstr, NULL, &hints, &res);

	if (error != 0) {
		log_err("getaddrinfo: %d", error);
		if (res)
			freeaddrinfo(res);
		return -1;
	}

	for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
		switch (ainfo->ai_family) {
		case AF_INET6:
		case AF_INET:
			len = ainfo->ai_addrlen;
			memcpy(dst, ainfo->ai_addr, len);
			goto finish;
		}
	}

finish:
	if (res)
		freeaddrinfo(res);
	return len;
}

static coap_session_t *get_session(coap_context_t *ctx,
				coap_protocol_t proto,
				coap_address_t *dst,
				artik_ssl_config *ssl,
				artik_coap_psk_param *psk)
{
	coap_session_t *session = NULL;
	artik_security_module *security = NULL;

	if (ssl && psk && proto == COAP_UDP_DTLS) {
		log_err("SSL and PSK cannot be defined together.");
		return NULL;
	} else if (ssl && !psk && proto == COAP_UDP_DTLS
			&& ssl->client_cert.data
			&& ssl->client_key.data) {
		char *pub_key_pem = NULL;
		char *ec_pub_key = NULL;
		char *ec_priv_key = NULL;
		char *ec_pub_key_x = NULL;
		char *ec_pub_key_y = NULL;
		unsigned char *pub_key_der = NULL;
		unsigned char *priv_key_der = NULL;
		int pub_key_der_len = 0;
		int priv_key_der_len = 0;
		int ec_pub_key_length = 0;
		int ec_priv_key_length = 0;
		coap_ecdsa_keys ecdsa_keys;
		artik_error ret;

		security = (artik_security_module *)
			artik_request_api_module("security");

		ret = security->get_ec_pubkey_from_cert(ssl->client_cert.data,
			&pub_key_pem);

		if (ret != S_OK) {
			log_err("Fail to get EC public key from certificate");
			artik_release_api_module(security);
			return NULL;
		}

		ret = security->convert_pem_to_der(pub_key_pem, &pub_key_der,
			(unsigned int *)&pub_key_der_len);

		if (ret != S_OK) {
			log_err("Fail to convert public key");
			artik_release_api_module(security);
			return NULL;
		}

		ret = security->convert_pem_to_der(ssl->client_key.data,
			&priv_key_der, (unsigned int *)&priv_key_der_len);

		if (ret != S_OK) {
			log_err("Fail to convert private key");
			artik_release_api_module(security);
			return NULL;
		}

		artik_release_api_module(security);

		if (!asn1_parse_pubkey(pub_key_der, pub_key_der_len,
				&ec_pub_key, &ec_pub_key_length)) {
			log_err("Fail to parse pubkey");
			return NULL;
		}

		if (!asn1_parse_key(priv_key_der, priv_key_der_len,
				ec_pub_key, &ec_priv_key, &ec_priv_key_length)) {
			log_err("Fail to parse priv_key");
			return NULL;
		}

		if (extract_pubkey_x_y(ec_pub_key, ec_pub_key_length,
			&ec_pub_key_x, &ec_pub_key_y) < 0) {
			log_err("Fail to extract pub key x and y");
			return NULL;
		}

		ecdsa_keys.priv_key = (unsigned char *)coap_malloc(ec_priv_key_length);
		memcpy(ecdsa_keys.priv_key, ec_priv_key,
					ec_priv_key_length);

		int size = (ec_pub_key_length - 1)/2;

		ecdsa_keys.pub_key_x = (unsigned char *)coap_malloc(size);
		memcpy(ecdsa_keys.pub_key_x, ec_pub_key_x,
					size);
		ecdsa_keys.pub_key_x_len = size;

		ecdsa_keys.pub_key_y = (unsigned char *)coap_malloc(size);
		memcpy(ecdsa_keys.pub_key_y, ec_pub_key_y,
					size);
		ecdsa_keys.pub_key_y_len = size;

		session = coap_new_client_session_ssl(
				ctx, NULL, dst,
				proto, &ecdsa_keys);

		if (pub_key_pem)
			coap_free(pub_key_pem);
		if (ec_pub_key)
			coap_free(ec_pub_key);
		if (ec_priv_key)
			coap_free(ec_priv_key);
		if (ec_pub_key_x)
			coap_free(ec_pub_key_x);
		if (ec_pub_key_y)
			coap_free(ec_pub_key_y);
		if (pub_key_der)
			coap_free(pub_key_der);
		if (priv_key_der)
			coap_free(priv_key_der);
		if (ecdsa_keys.priv_key)
			coap_free(ecdsa_keys.priv_key);
		if (ecdsa_keys.pub_key_x)
			coap_free(ecdsa_keys.pub_key_x);
		if (ecdsa_keys.pub_key_y)
			coap_free(ecdsa_keys.pub_key_y);

	} else if (!ssl && psk && proto == COAP_UDP_DTLS
			&& psk->identity
			&& psk->psk) {
		const char *identity = psk->identity;
		const uint8_t *key = (const uint8_t *)psk->psk;
		unsigned int key_len = (unsigned int)psk->psk_len;

		session = coap_new_client_session_psk(
				ctx, NULL, dst,
				proto, identity, key, key_len);
	} else
		session = coap_new_client_session(ctx, NULL, dst, proto);

	return session;
}

static bool create_endpoint(coap_context_t *ctx,
			coap_protocol_t proto,
			const char *node,
			const char *port)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp = NULL;
	int error;

	if (!ctx)
		return false;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
	hints.ai_protocol = IPPROTO_UDP;

	error = getaddrinfo(node, port, &hints, &result);

	if (error != 0) {
		log_err("getaddrinfo: %d", error);
		if (result)
			freeaddrinfo(result);
		return false;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		coap_address_t addr;
		coap_endpoint_t *endpoint;

		if (rp->ai_addrlen <= sizeof(addr.addr)) {
			coap_address_init(&addr);
			addr.size = rp->ai_addrlen;
			memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);

			endpoint = coap_new_endpoint(ctx, &addr, proto);

			if (!endpoint) {
				log_err("Cannot create endpoint");
				continue;
			}
		}
	}

	if (result)
		freeaddrinfo(result);

	return true;
}

static void message_handler(struct coap_context_t *ctx,
		coap_session_t *session, coap_packet_t *sent,
		coap_packet_t *received, const int id)
{
	const uint8_t *databuf = NULL;
	coap_packet_t *packet = NULL;
	size_t len;
	artik_coap_msg msg;
	artik_coap_error error = ARTIK_COAP_ERROR_NONE;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)ctx);

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		return;
	}

	if (!received) {
		log_err("received is NULL");
		return;
	}

	memset(&msg, 0, sizeof(artik_coap_msg));

	msg.msg_type = (artik_coap_msg_type)received->type;
	msg.msg_id = received->mid;
	msg.code = received->code;
	msg.token = received->token;
	msg.token_len = received->token_len;

	get_options(received, &msg.options, &msg.num_options, true);

	if (IS_OPTION(received, COAP_OPTION_BLOCK2)) {
		uint32_t num = 0;
		uint8_t more = 0;
		uint16_t size = 0;

		coap_get_header_block2((void *)received,
			&num, &more, &size, NULL);

		len = coap_get_payload(received, &databuf);

		msg.data = (unsigned char *)coap_malloc(len+1);

		if (!msg.data) {
			log_err("Memory problem");
			return;
		}

		memcpy(msg.data, databuf, len);
		msg.data_len = len;
		msg.data[len] = 0;

		if (more) {
			int method = node->interface.method;
			int msg_type = node->interface.msg_type;
			unsigned short msg_id = 0;

			packet = (coap_packet_t *)coap_malloc(sizeof(coap_packet_t));

			if (packet) {
				msg_id = coap_new_message_id(session);
				coap_init_message((void *)packet,
					(coap_protocol_t)(session->proto ?
					COAP_UDP_DTLS : COAP_UDP), msg_type,
					method, msg_id);

				if (node->interface.coap_options &&
					node->interface.num_coap_options > 0) {
					add_options(packet, node->interface.coap_options,
						node->interface.num_coap_options, false, node);
				}

				if (!node->interface.use_uri_path && node->interface.uri_path) {
					coap_set_header_uri_path((void *)packet,
						node->interface.uri_path);
				}
				if (!node->interface.use_uri_query && node->interface.uri_query) {
					coap_set_header_uri_query((void *)packet,
						node->interface.uri_query);
				}

				num += 1;

				coap_set_header_block2((void *)packet, num,
					0, size);

				coap_set_header_token((void *)packet, msg.token, msg.token_len);

				if (artik_coap_send(session, packet) == -1)
					log_err("Fail to send new request");
			}
		} else {
			if (node->interface.send_cb) {
				if (node->interface.coap_options &&
						node->interface.num_coap_options > 0)
					free_options(&node->interface.coap_options,
						node->interface.num_coap_options);
				if (node->interface.uri_path) {
					coap_free(node->interface.uri_path);
					node->interface.uri_path = NULL;
				}
				if (node->interface.uri_query) {
					coap_free(node->interface.uri_query);
					node->interface.uri_query = NULL;
				}
				if (node->interface.location_path) {
					coap_free(node->interface.location_path);
					node->interface.location_path = NULL;
				}
				if (node->interface.location_query) {
					coap_free(node->interface.location_query);
					node->interface.location_query = NULL;
				}
			}
		}
	} else {
		len = coap_get_payload(received, &databuf);

		msg.data = (unsigned char *)coap_malloc(len+1);
		memcpy(msg.data, databuf, len);
		msg.data_len = len;
		msg.data[len] = 0;
	}

	log_dbg("");

	if (node->interface.client &&
		node->interface.observe_cb && (IS_OPTION(received,
						COAP_OPTION_OBSERVE) ||
					IS_OPTION(received, COAP_OPTION_BLOCK2) ||
					msg.code >= ARTIK_COAP_RES_BAD_REQUEST))
		node->interface.observe_cb(&msg,
			error,
			node->interface.observe_data);

	if (node->interface.client &&
		node->interface.send_cb && (!IS_OPTION(received,
						COAP_OPTION_OBSERVE)))
		node->interface.send_cb(&msg,
			error,
			node->interface.send_data);


	if (msg.options && msg.num_options > 0)
		free_options(&msg.options, msg.num_options);

	if (node->interface.send_cb && !IS_OPTION(received, COAP_OPTION_BLOCK2)) {
		if (node->interface.coap_options &&
				node->interface.num_coap_options > 0) {
			free_options(&node->interface.coap_options,
				node->interface.num_coap_options);
		}
		if (node->interface.uri_path) {
			coap_free(node->interface.uri_path);
			node->interface.uri_path = NULL;
		}
		if (node->interface.uri_query) {
			coap_free(node->interface.uri_query);
			node->interface.uri_query = NULL;
		}
		if (node->interface.location_path) {
			coap_free(node->interface.location_path);
			node->interface.location_path = NULL;
		}
		if (node->interface.location_query) {
			coap_free(node->interface.location_query);
			node->interface.location_query = NULL;
		}
	}

	if (msg.data)
		coap_free(msg.data);
}

static void nack_handler(struct coap_context_t *ctx,
		coap_session_t *session, coap_packet_t *sent,
		coap_nack_reason_t reason, const int id)
{
	artik_coap_msg msg;
	artik_coap_error error = ARTIK_COAP_ERROR_NONE;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)ctx);
	os_coap_data *data = NULL;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		return;
	}

	memset(&msg, 0, sizeof(artik_coap_msg));

	switch (reason) {
	case COAP_NACK_TOO_MANY_RETRIES:
		log_dbg("Too many retries");
		error = ARTIK_COAP_ERROR_TOO_MANY_RETRIES;
		node->interface.connected = false;
		break;
	case COAP_NACK_NOT_DELIVERABLE:
		log_dbg("Not deliverable");
		error = ARTIK_COAP_ERROR_NOT_DELIVERABLE;
		node->interface.connected = false;
		break;
	case COAP_NACK_RST:
		log_dbg("Got RST");
		msg.msg_type = ARTIK_COAP_MSG_RST;
		msg.msg_id = id;
		error = ARTIK_COAP_ERROR_RST;
		break;
	case COAP_NACK_TLS_FAILED:
		log_dbg("TLS failed");
		error = ARTIK_COAP_ERROR_TLS_FAILED;
		node->interface.connected = false;
		break;
	default:
		break;
	}

	if (node->interface.client &&
		node->interface.observe_cb)
		node->interface.observe_cb(&msg,
			error,
			node->interface.observe_data);

	if (node->interface.client &&
		node->interface.send_cb)
		node->interface.send_cb(&msg,
			error,
			node->interface.send_data);

	if (node->interface.coap_options &&
			node->interface.num_coap_options > 0)
		free_options(&node->interface.coap_options,
			node->interface.num_coap_options);
	if (node->interface.uri_path) {
		coap_free(node->interface.uri_path);
		node->interface.uri_path = NULL;
	}
	if (node->interface.uri_query) {
		coap_free(node->interface.uri_query);
		node->interface.uri_query = NULL;
	}
	if (node->interface.location_path) {
		coap_free(node->interface.location_path);
		node->interface.location_path = NULL;
	}
	if (node->interface.location_query) {
		coap_free(node->interface.location_query);
		node->interface.location_query = NULL;
	}

	data = node->interface.coap_data;

	if (!data)
		return;

	if (!node->interface.connected && !data->quit) {
		data->quit = true;
		pthread_join(data->thread_id, NULL);

		if (node->interface.coap_data)
			coap_free(node->interface.coap_data);

		if (ctx)
			artik_coap_free_context(ctx);

		artik_list_delete_node(&requested_node, (artik_list *)node);
	}
}

static void get_resource_handler(coap_context_t *ctx,
				struct coap_resource_t *resource,
				coap_session_t *session,
				coap_packet_t *request,
				coap_str *token,
				coap_str *query,
				coap_packet_t *response)
{
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)ctx);
	size_t len;
	const uint8_t *databuf = NULL;
	artik_coap_msg msg;
	artik_coap_msg resp;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		return;
	}

	resource_node *res_node = (resource_node *)artik_list_get_by_handle(
		node->interface.requested_resource_node, (ARTIK_LIST_HANDLE)resource);

	if (!res_node) {
		log_err("No node exists for this resource");
		return;
	}

	log_dbg("");

	memset(&msg, 0, sizeof(artik_coap_msg));
	memset(&resp, 0, sizeof(artik_coap_msg));

	if (request) {
		msg.msg_type = (artik_coap_msg_type)request->type;
		msg.msg_id = request->mid;
		msg.code = request->code;
		msg.token = request->token;
		msg.token_len = request->token_len;

		log_dbg("");

		get_options(request, &msg.options, &msg.num_options, false);

		log_dbg("");

		len = coap_get_payload(request, &databuf);

		if (len != 0) {
			msg.data = (unsigned char *)coap_malloc(len + 1);
			if (!msg.data) {
				log_err("Fail to allocate msg.data");
				return;
			}
			memcpy(msg.data, databuf, len + 1);
			msg.data_len = len + 1;
		}
	}

	log_dbg("");

	if (res_node->resource.resource_cb[0])
		res_node->resource.resource_cb[0](&msg,
			&resp,
			res_node->resource.resource_data[0]);


	response->code = resp.code;

	log_dbg("");

	if (resource->observable && artik_coap_find_observer(resource, session, token))
		coap_set_header_observe((void *)response, ctx->observe);

	if (resp.options && resp.num_options > 0) {
		add_options(response, resp.options, resp.num_options, false, node);
		free_options(&resp.options, resp.num_options);
	}

	log_dbg("");

	if (resp.data && resp.data_len > 0)
		coap_set_payload(response, (void *)resp.data,
			(size_t)resp.data_len);

	if (msg.data)
		coap_free(msg.data);
	if (msg.options && msg.num_options > 0)
		free_options(&msg.options, msg.num_options);
}

static void post_resource_handler(coap_context_t *ctx,
				struct coap_resource_t *resource,
				coap_session_t *session,
				coap_packet_t *request,
				coap_str *token,
				coap_str *query,
				coap_packet_t *response)
{
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)ctx);
	size_t len;
	const uint8_t *databuf = NULL;
	artik_coap_msg msg;
	artik_coap_msg resp;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		return;
	}

	resource_node *res_node = (resource_node *)artik_list_get_by_handle(
		node->interface.requested_resource_node, (ARTIK_LIST_HANDLE)resource);

	if (!res_node) {
		log_err("No node exists for this resource");
		return;
	}

	log_dbg("");

	memset(&msg, 0, sizeof(artik_coap_msg));
	memset(&resp, 0, sizeof(artik_coap_msg));

	if (request) {
		msg.msg_type = (artik_coap_msg_type)request->type;
		msg.msg_id = request->mid;
		msg.code = request->code;
		msg.token = request->token;
		msg.token_len = request->token_len;

		log_dbg("");

		get_options(request, &msg.options, &msg.num_options, false);

		log_dbg("");

		len = coap_get_payload(request, &databuf);

		if (len != 0) {
			msg.data = (unsigned char *)coap_malloc(len + 1);
			if (!msg.data) {
				log_err("Fail to allocate msg.data");
				return;
			}
			memcpy(msg.data, databuf, len + 1);
			msg.data_len = len + 1;
		}
	}

	log_dbg("");

	if (res_node->resource.resource_cb[1])
		res_node->resource.resource_cb[1](&msg,
			&resp,
			res_node->resource.resource_data[1]);

	response->code = resp.code;

	log_dbg("");

	if (resource->observable && artik_coap_find_observer(resource, session, token))
		coap_set_header_observe((void *)response, ctx->observe);

	if (resp.options && resp.num_options > 0) {
		add_options(response, resp.options, resp.num_options, false, node);
		free_options(&resp.options, resp.num_options);
	}

	log_dbg("");

	if (resp.data && resp.data_len > 0)
		coap_set_payload(response, (void *)resp.data,
			(size_t)resp.data_len);

	if (msg.data)
		coap_free(msg.data);
	if (msg.options && msg.num_options > 0)
		free_options(&msg.options, msg.num_options);
}

static void put_resource_handler(coap_context_t *ctx,
				struct coap_resource_t *resource,
				coap_session_t *session,
				coap_packet_t *request,
				coap_str *token,
				coap_str *query,
				coap_packet_t *response)
{
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)ctx);
	size_t len;
	const uint8_t *databuf = NULL;
	artik_coap_msg msg;
	artik_coap_msg resp;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		return;
	}

	resource_node *res_node = (resource_node *)artik_list_get_by_handle(
		node->interface.requested_resource_node, (ARTIK_LIST_HANDLE)resource);

	if (!res_node) {
		log_err("No node exists for this resource");
		return;
	}

	log_dbg("");

	memset(&msg, 0, sizeof(artik_coap_msg));
	memset(&resp, 0, sizeof(artik_coap_msg));

	if (request) {
		msg.msg_type = (artik_coap_msg_type)request->type;
		msg.msg_id = request->mid;
		msg.code = request->code;
		msg.token = request->token;
		msg.token_len = request->token_len;

		log_dbg("");

		get_options(request, &msg.options, &msg.num_options, false);

		log_dbg("");

		len = coap_get_payload(request, &databuf);

		if (len != 0) {
			msg.data = (unsigned char *)coap_malloc(len + 1);
			if (!msg.data) {
				log_err("Fail to allocate msg.data");
				return;
			}
			memcpy(msg.data, databuf, len + 1);
			msg.data_len = len + 1;
		}
	}

	log_dbg("");

	if (res_node->resource.resource_cb[2])
		res_node->resource.resource_cb[2](&msg,
			&resp,
			res_node->resource.resource_data[2]);

	response->code = resp.code;

	log_dbg("");

	if (resource->observable && artik_coap_find_observer(resource, session, token))
		coap_set_header_observe((void *)response, ctx->observe);

	if (resp.options && resp.num_options > 0) {
		add_options(response, resp.options, resp.num_options, false, node);
		free_options(&resp.options, resp.num_options);
	}

	log_dbg("");

	if (resp.data && resp.data_len > 0)
		coap_set_payload(response, (void *)resp.data,
			(size_t)resp.data_len);

	if (msg.data)
		coap_free(msg.data);
	if (msg.options && msg.num_options > 0)
		free_options(&msg.options, msg.num_options);
}

static void delete_resource_handler(coap_context_t *ctx,
				struct coap_resource_t *resource,
				coap_session_t *session,
				coap_packet_t *request,
				coap_str *token,
				coap_str *query,
				coap_packet_t *response)
{
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)ctx);
	size_t len;
	const uint8_t *databuf = NULL;
	artik_coap_msg msg;
	artik_coap_msg resp;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		return;
	}

	resource_node *res_node = (resource_node *)artik_list_get_by_handle(
		node->interface.requested_resource_node, (ARTIK_LIST_HANDLE)resource);

	if (!res_node) {
		log_err("No node exists for this resource");
		return;
	}

	log_dbg("");

	memset(&msg, 0, sizeof(artik_coap_msg));
	memset(&resp, 0, sizeof(artik_coap_msg));

	if (request) {
		msg.msg_type = (artik_coap_msg_type)request->type;
		msg.msg_id = request->mid;
		msg.code = request->code;
		msg.token = request->token;
		msg.token_len = request->token_len;

		log_dbg("");

		get_options(request, &msg.options, &msg.num_options, false);

		log_dbg("");

		len = coap_get_payload(request, &databuf);

		if (len != 0) {
			msg.data = (unsigned char *)coap_malloc(len + 1);
			if (!msg.data) {
				log_err("Fail to allocate msg.data");
				return;
			}
			memcpy(msg.data, databuf, len + 1);
			msg.data_len = len + 1;
		}
	}

	log_dbg("");

	if (res_node->resource.resource_cb[3])
		res_node->resource.resource_cb[3](&msg,
			&resp,
			res_node->resource.resource_data[3]);

	response->code = resp.code;

	log_dbg("");

	if (resource->observable && artik_coap_find_observer(resource, session, token))
		coap_set_header_observe((void *)response, ctx->observe);

	if (resp.options && resp.num_options > 0) {
		add_options(response, resp.options, resp.num_options, false, node);
		free_options(&resp.options, resp.num_options);
	}

	log_dbg("");

	if (resp.data && resp.data_len > 0)
		coap_set_payload(response, (void *)resp.data,
			(size_t)resp.data_len);

	if (msg.data)
		coap_free(msg.data);
	if (msg.options && msg.num_options > 0)
		free_options(&msg.options, msg.num_options);
}

static bool init_resources(coap_context_t *ctx, artik_coap_resource *resources,
		int num_resources)
{
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)ctx);

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle.");
		return false;
	}

	artik_coap_resource *res = resources;
	artik_coap_resource *end_res = res + num_resources;

	for (; res != end_res; res++) {
		coap_resource_t *r = NULL;
		resource_node *res_node = NULL;

		r = artik_coap_resource_init((unsigned char *)res->path, res->path_len,
			res->default_notification_type);

		if (!r) {
			log_err("Fail to initialize resource");
			return false;
		}

		res_node = (resource_node *)artik_list_add(&node->interface.requested_resource_node,
					(ARTIK_LIST_HANDLE)r, sizeof(resource_node));

		if (!res_node) {
			log_err("No memory");
			return false;
		}

		res_node->resource.res = r;

		if (res->resource_cb[0]) {
			res_node->resource.resource_cb[0] =
			res->resource_cb[0];

			res_node->resource.resource_data[0] =
			res->resource_data[0];

			coap_register_handler(r, COAP_GET,
				get_resource_handler);
		}

		if (res->resource_cb[1]) {
			res_node->resource.resource_cb[1] =
			res->resource_cb[1];

			res_node->resource.resource_data[1] =
			res->resource_data[1];

			coap_register_handler(r, COAP_POST,
				post_resource_handler);
		}

		if (res->resource_cb[2]) {
			res_node->resource.resource_cb[2] =
			res->resource_cb[2];

			res_node->resource.resource_data[2] =
			res->resource_data[2];

			coap_register_handler(r, COAP_PUT,
				put_resource_handler);
		}

		if (res->resource_cb[3]) {
			res_node->resource.resource_cb[3] =
			res->resource_cb[3];

			res_node->resource.resource_data[3] =
			res->resource_data[3];

			coap_register_handler(r, COAP_DELETE,
				delete_resource_handler);
		}

		r->observable = res->observable;

		artik_coap_attr *att = res->attributes;
		artik_coap_attr *end_att = att + res->num_attributes;

		for (; att != end_att; att++) {
			artik_coap_add_attr(r, att->name, att->name_len, att->val,
				att->val_len, 0);
		}

		artik_coap_add_resource(ctx, r);
	}

	return true;
}

static void *client_service_thread(void *user_data)
{
	os_coap_data *data = (os_coap_data *)user_data;

	while (!data->quit)
		coap_run_once(data->ctx, 10);

	return 0;
}

static void *server_service_thread(void *user_data)
{
	os_coap_data *data = (os_coap_data *)user_data;

	while (!data->quit) {
		coap_run_once(data->ctx, 10);

		artik_coap_check_notify(data->ctx, data->proto);
	}

	return 0;
}

artik_error os_coap_create_client(artik_coap_handle *client,
				artik_coap_config *config)
{
	artik_error ret = S_OK;
	os_coap_interface *interface = NULL;
	coap_context_t *ctx = NULL;
	coap_node *node;

	log_dbg("");

	if (!client || !config) {
		ret = E_BAD_ARGS;
		goto exit;
	}

	if (!config->uri) {
		log_err("Missing CoAP URI");
		ret = E_COAP_ERROR;
		goto exit;
	}

	interface = (os_coap_interface *)coap_malloc(sizeof(os_coap_interface));

	if (interface == NULL) {
		log_err("Failed to allocate memory");
		ret = E_NO_MEM;
		goto exit;
	}

	memset(interface, 0, sizeof(os_coap_interface));

	ctx = artik_coap_new_context(config->ssl, config->psk);

	if (!ctx) {
		log_err("Cannot create CoAP client context");
		ret = E_COAP_ERROR;
		goto exit;
	}

	interface->ctx = ctx;
	*client = (artik_coap_handle)ctx;
	interface->client = true;

	node = (coap_node *)artik_list_add(&requested_node,
			(ARTIK_LIST_HANDLE)*client, sizeof(coap_node));

	if (!node) {
		ret = E_NO_MEM;
		goto exit;
	}

	memset(&node->interface, 0, sizeof(node->interface));

	memcpy(&interface->config, config, sizeof(interface->config));
	memcpy(&node->interface, interface, sizeof(node->interface));

exit:
	if (interface)
		coap_free(interface);

	return ret;
}

artik_error os_coap_destroy_client(artik_coap_handle client)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)client);

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (node->interface.connected) {
		log_err("The client is still connected");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (node->interface.ctx)
		artik_coap_free_context(node->interface.ctx);

	if (node->interface.uri_path)
		coap_free(node->interface.uri_path);

	if (node->interface.uri_query)
		coap_free(node->interface.uri_query);

	if (node->interface.location_path)
		coap_free(node->interface.location_path);

	if (node->interface.location_query)
		coap_free(node->interface.location_query);

	if (node->interface.coap_options &&
			node->interface.num_coap_options > 0)
		free_options(&node->interface.coap_options,
			node->interface.num_coap_options);

	artik_list_delete_node(&requested_node, (artik_list *)node);

exit:
	return ret;
}

artik_error os_coap_connect(artik_coap_handle client)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)client);
	artik_coap_config *config = NULL;
	coap_context_t *ctx = NULL;
	coap_session_t *session = NULL;
	coap_uri u;
	coap_address_t dst;
	static coap_str server;
	unsigned short port = COAP_DEFAULT_PORT;
	int res;
	pthread_attr_t thread_attr;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (node->interface.connected) {
		log_err("The client is already connected");
		ret = E_COAP_ERROR;
		goto exit;
	}

	ctx = node->interface.ctx;
	config = &node->interface.config;

	coap_startup();

	if (artik_coap_split_uri((unsigned char *)config->uri, strlen(config->uri),
		&u) < 0) {
		log_err("Failed to split CoAP URI");
		ret = E_COAP_ERROR;
		goto exit;
	}

	server = u.host;
	port = u.port;

	res = resolve_address(&server, &dst.addr.sa);

	if (res < 0) {
		log_err("Failed to resolve address");
		ret = E_COAP_ERROR;
		goto exit;
	}

	dst.size = res;
	dst.addr.sin.sin_port = htons(port);

	session = get_session(
				ctx,
				u.secure ? COAP_UDP_DTLS : COAP_UDP,
				&dst,
				config->ssl ? config->ssl : NULL,
				config->psk ? config->psk : NULL
				);

	if (!session) {
		log_err("Cannot create client session");
		ret = E_COAP_ERROR;
		goto exit;
	}

	node->interface.secure_connection = u.secure;
	node->interface.session = session;

	coap_register_response_handler(ctx, message_handler);
	coap_register_nack_handler(ctx, nack_handler);

	if (pthread_attr_init(&thread_attr) != 0) {
		log_err("Failed to initialize CoAP thread attribute");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (pthread_attr_setstacksize(&thread_attr, 16*1024) != 0) {
		log_err("Failed to set CoAP thread stack size");
		pthread_attr_destroy(&thread_attr);
		ret = E_COAP_ERROR;
		goto exit;
	}

	node->interface.coap_data = (os_coap_data *)coap_malloc(sizeof(os_coap_data));

	if (!node->interface.coap_data) {
		log_err("Memory problem");
		pthread_attr_destroy(&thread_attr);
		ret = E_COAP_ERROR;
		goto exit;
	}

	memset(node->interface.coap_data, 0, sizeof(os_coap_data));

	node->interface.coap_data->ctx = ctx;

	if (pthread_create(&node->interface.coap_data->thread_id, &thread_attr,
					client_service_thread,
					node->interface.coap_data) != 0) {
		log_err("Failed to create CoAP thread");
		pthread_attr_destroy(&thread_attr);
		ret = E_COAP_ERROR;
		goto exit;
	}

	pthread_attr_destroy(&thread_attr);
	pthread_setname_np(node->interface.coap_data->thread_id, "CoAP client daemon");

	node->interface.connected = true;

exit:
	return ret;
}

artik_error os_coap_disconnect(artik_coap_handle client)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)client);
	os_coap_data *data = NULL;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!node->interface.connected) {
		log_err("The client is not connected");
		ret = E_COAP_ERROR;
		goto exit;
	}

	data = node->interface.coap_data;

	if (!data) {
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!data->quit) {
		data->quit = true;
		pthread_join(data->thread_id, NULL);
	}

	if (node->interface.session)
		coap_session_release(node->interface.session);
	else {
		log_err("No session exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	node->interface.connected = false;

	if (node->interface.coap_data)
		coap_free(node->interface.coap_data);

exit:
	return ret;
}

artik_error os_coap_create_server(artik_coap_handle *server,
				artik_coap_config *config)
{
	artik_error ret = S_OK;
	os_coap_interface *interface = NULL;
	coap_context_t *ctx = NULL;
	coap_node *node;

	log_dbg("");

	if (!server || !config) {
		ret = E_BAD_ARGS;
		goto exit;
	}

	interface = (os_coap_interface *)coap_malloc(sizeof(os_coap_interface));

	if (interface == NULL) {
		log_err("Failed to allocate memory");
		ret = E_NO_MEM;
		goto exit;
	}

	memset(interface, 0, sizeof(os_coap_interface));

	if (config->ssl && (config->psk || config->enable_verify_psk)) {
		log_err("SSL and PSK cannot be defined together.");
		ret = E_COAP_ERROR;
		goto exit;
	}

	ctx = artik_coap_new_context(config->ssl, config->psk);

	if (!ctx) {
		log_err("Cannot create CoAP server context");
		ret = E_COAP_ERROR;
		goto exit;
	}

	ctx->max_idle_sessions = MAX_IDLE_SESSIONS;
	ctx->session_timeout = SESSION_TIMEOUT;

	if (config->psk && config->psk->identity && config->psk->psk) {
		size_t key_len = (size_t)config->psk->psk_len;
		uint8_t *key = (uint8_t *)coap_malloc(key_len*sizeof(uint8_t));

		if (!key) {
			log_err("Memory problem");
			ret = E_NO_MEM;
			if (ctx)
				artik_coap_free_context(ctx);
			goto exit;
		}

		memcpy(key, config->psk->psk, key_len);
		coap_context_set_psk(ctx, config->psk->identity,
			(uint8_t *)config->psk->psk, (size_t)config->psk->psk_len);

		if (key)
			coap_free(key);
	}

	if (config->ssl && config->ssl->client_cert.data
			&& config->ssl->client_key.data) {
		char *pub_key_pem = NULL;
		char *ec_pub_key = NULL;
		char *ec_priv_key = NULL;
		char *ec_pub_key_x = NULL;
		char *ec_pub_key_y = NULL;
		unsigned char *pub_key_der = NULL;
		unsigned char *priv_key_der = NULL;
		int pub_key_der_len = 0;
		int priv_key_der_len = 0;
		int ec_pub_key_length = 0;
		int ec_priv_key_length = 0;
		artik_security_module *security = NULL;

		security = (artik_security_module *)
			artik_request_api_module("security");

		if (security->get_ec_pubkey_from_cert(
			config->ssl->client_cert.data, &pub_key_pem) != S_OK) {
			log_err("Fail to get EC public key from certificate");
			artik_release_api_module(security);
			ret = E_COAP_ERROR;
			if (ctx)
				artik_coap_free_context(ctx);
			goto exit;
		}

		if (security->convert_pem_to_der(pub_key_pem,
			&pub_key_der, (unsigned int *)&pub_key_der_len) != S_OK) {
			log_err("Fail to convert public key");
			artik_release_api_module(security);
			ret = E_COAP_ERROR;
			if (ctx)
				artik_coap_free_context(ctx);
			goto exit;
		}

		if (security->convert_pem_to_der(
			config->ssl->client_key.data, &priv_key_der,
			(unsigned int *)&priv_key_der_len) != S_OK) {
			log_err("Fail to convert private key");
			artik_release_api_module(security);
			ret = E_COAP_ERROR;
			if (ctx)
				artik_coap_free_context(ctx);
			goto exit;
		}

		artik_release_api_module(security);

		if (!asn1_parse_pubkey(pub_key_der, pub_key_der_len, &ec_pub_key,
				&ec_pub_key_length)) {
			log_err("Fail to parse pubkey");
			ret = E_COAP_ERROR;
			if (ctx)
				artik_coap_free_context(ctx);
			goto exit;
		}

		if (!asn1_parse_key(priv_key_der, priv_key_der_len, ec_pub_key,
				&ec_priv_key, &ec_priv_key_length)) {
			log_err("Fail to parse priv_key");
			ret = E_COAP_ERROR;
			if (ctx)
				artik_coap_free_context(ctx);
			goto exit;
		}

		if (extract_pubkey_x_y(ec_pub_key, ec_pub_key_length,
				&ec_pub_key_x, &ec_pub_key_y) < 0) {
			log_err("Fail to extract pub key x and y");
			ret = E_COAP_ERROR;
			if (ctx)
				artik_coap_free_context(ctx);
			goto exit;
		}

		int size = (ec_pub_key_length - 1)/2;

		coap_context_set_ssl(ctx, (unsigned char *)ec_priv_key,
				ec_priv_key_length,
				(unsigned char *)ec_pub_key_x, size,
				(unsigned char *)ec_pub_key_y, size);

		if (pub_key_pem)
			coap_free(pub_key_pem);
		if (ec_pub_key)
			coap_free(ec_pub_key);
		if (ec_priv_key)
			coap_free(ec_priv_key);
		if (ec_pub_key_x)
			coap_free(ec_pub_key_x);
		if (ec_pub_key_y)
			coap_free(ec_pub_key_y);
		if (pub_key_der)
			coap_free(pub_key_der);
		if (priv_key_der)
			coap_free(priv_key_der);
	}

	interface->ctx = ctx;
	*server = (artik_coap_handle)ctx;
	interface->client = false;

	node = (coap_node *)artik_list_add(&requested_node,
			(ARTIK_LIST_HANDLE)*server, sizeof(coap_node));

	if (!node) {
		ret = E_NO_MEM;
		if (ctx)
			artik_coap_free_context(ctx);
		goto exit;
	}

	memset(&node->interface, 0, sizeof(node->interface));

	memcpy(&interface->config, config, sizeof(interface->config));

	interface->enable_verify_psk = config->enable_verify_psk;

	memcpy(&node->interface, interface, sizeof(node->interface));

exit:
	if (interface)
		coap_free(interface);

	return ret;
}

artik_error os_coap_destroy_server(artik_coap_handle server)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)server);

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (node->interface.started) {
		log_err("The server is still started");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (node->interface.ctx)
		artik_coap_free_context(node->interface.ctx);

	if (node->interface.uri_path)
		coap_free(node->interface.uri_path);

	if (node->interface.uri_query)
		coap_free(node->interface.uri_query);

	if (node->interface.location_path)
		coap_free(node->interface.location_path);

	if (node->interface.location_query)
		coap_free(node->interface.location_query);

	if (node->interface.coap_options &&
			node->interface.num_coap_options > 0)
		free_options(&node->interface.coap_options,
			node->interface.num_coap_options);

	artik_list_delete_all(&node->interface.requested_resource_node);

	artik_list_delete_node(&requested_node, (artik_list *)node);

exit:
	return ret;
}

artik_error os_coap_start_server(artik_coap_handle server)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)server);
	artik_coap_config *config = NULL;
	coap_context_t *ctx = NULL;
	bool enable_dtls;
	char addr_str[NI_MAXHOST] = "::";
	char port_str[NI_MAXSERV] = "5683";
	pthread_attr_t thread_attr;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (node->interface.started) {
		log_err("The server is already started");
		ret = E_COAP_ERROR;
		goto exit;
	}

	ctx = node->interface.ctx;
	config = &node->interface.config;

	coap_startup();

	enable_dtls = config->ssl || config->psk || config->enable_verify_psk ?
			true : false;

	if (config->port != 0) {
		snprintf(port_str, NI_MAXSERV - 1, "%d", config->port);
		port_str[NI_MAXSERV - 1] = '\0';
	} else {
		if (enable_dtls) {
			snprintf(port_str, NI_MAXSERV - 1, "5684");
			port_str[NI_MAXSERV - 1] = '\0';
		}
	}

	if (!create_endpoint(
			ctx,
			enable_dtls ? COAP_UDP_DTLS : COAP_UDP,
			addr_str,
			port_str)) {
		log_err("Fail to create endpoint");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (pthread_attr_init(&thread_attr) != 0) {
		log_err("Failed to initialize CoAP thread attribute");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (pthread_attr_setstacksize(&thread_attr, 16*1024) != 0) { // 16*1024 or 32*4096
		log_err("Failed to set CoAP thread stack size");
		ret = E_COAP_ERROR;
		goto exit;
	}

	node->interface.coap_data = (os_coap_data *)coap_malloc(sizeof(os_coap_data));

	if (!node->interface.coap_data) {
		log_err("Memory problem");
		ret = E_NO_MEM;
		goto exit;
	}

	memset(node->interface.coap_data, 0, sizeof(os_coap_data));

	node->interface.coap_data->ctx = ctx;
	node->interface.coap_data->proto = enable_dtls ? COAP_UDP_DTLS : COAP_UDP;

	if (pthread_create(&node->interface.coap_data->thread_id, &thread_attr,
					server_service_thread,
					node->interface.coap_data) != 0) {
		log_err("Failed to create CoAP thread");
		pthread_attr_destroy(&thread_attr);
		ret = E_COAP_ERROR;
		goto exit;
	}

	pthread_attr_destroy(&thread_attr);
	pthread_setname_np(node->interface.coap_data->thread_id, "CoAP server daemon");

	node->interface.started = true;

exit:
	return ret;
}

artik_error os_coap_stop_server(artik_coap_handle server)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)server);
	os_coap_data *data = NULL;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!node->interface.started) {
		log_err("The server is not started");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!node->interface.coap_data) {
		ret = E_COAP_ERROR;
		goto exit;
	}

	data = node->interface.coap_data;

	data->quit = true;
	pthread_join(data->thread_id, NULL);

	node->interface.started = false;

	if (node->interface.coap_data)
		coap_free(node->interface.coap_data);

exit:
	return ret;
}

artik_error os_coap_send_message(artik_coap_handle handle,
					const char *path,
					artik_coap_msg *msg)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)handle);
	coap_packet_t *packet = NULL;
	char *pathBuf = NULL;

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!node->interface.client) {
		log_err("This method is only for client handle");
		ret = E_NOT_SUPPORTED;
		goto exit;
	}

	if (!node->interface.connected) {
		log_err("The client is not connected");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!msg) {
		ret = E_BAD_ARGS;
		goto exit;
	}

	if (!msg->msg_id)
		msg->msg_id = coap_new_message_id(node->interface.session);

	packet = (coap_packet_t *)coap_malloc(sizeof(coap_packet_t));

	if (!packet) {
		log_err("Fail to create new CoAP request");
		ret = E_COAP_ERROR;
		goto exit;
	}

	coap_init_message((void *)packet, node->interface.secure_connection ?
		COAP_UDP_DTLS : COAP_UDP, (coap_message_type_t)msg->msg_type,
		(uint8_t)msg->code, (uint16_t)msg->msg_id);

	if (msg->options && msg->num_options > 0) {
		int i;

		add_options(packet, msg->options, msg->num_options, true, node);

		if (node->interface.coap_options && node->interface.num_coap_options > 0) {
			free_options(&node->interface.coap_options,
				node->interface.num_coap_options);
		}

		node->interface.num_coap_options = msg->num_options;

		node->interface.coap_options =
			(artik_coap_option *)
			coap_malloc(node->interface.num_coap_options*sizeof(artik_coap_option));

		if (!node->interface.coap_options) {
			log_err("Memory problem");
			ret = E_NO_MEM;
			goto exit;
		}

		memset(node->interface.coap_options, 0,
			node->interface.num_coap_options*sizeof(artik_coap_option));

		for (i = 0; i < node->interface.num_coap_options; i++) {
			node->interface.coap_options[i].key = msg->options[i].key;
			if (msg->options[i].data_len > 0) {
				node->interface.coap_options[i].data = coap_malloc(msg->options[i].data_len);

				if (!node->interface.coap_options[i].data) {
					log_err("Memory problem");
					ret = E_NO_MEM;
					free_options(&node->interface.coap_options,
						node->interface.num_coap_options);
					goto exit;
				}

				memcpy(node->interface.coap_options[i].data,
					msg->options[i].data, msg->options[i].data_len);

				node->interface.coap_options[i].data_len = msg->options[i].data_len;
			}
		}
	}

	if (!node->interface.use_uri_path && path) {
		pathBuf = coap_strdup(path);
		const char sep[2] = "?";
		char *onlyPath = strtok((char *)pathBuf, sep);

		if (onlyPath) {
			if (node->interface.uri_path)
				coap_free(node->interface.uri_path);
			node->interface.uri_path = coap_strdup(onlyPath);

			if (!node->interface.uri_path) {
				log_err("Memory problem");
				ret = E_NO_MEM;
				if (pathBuf)
					coap_free(pathBuf);
				goto exit;
			}

			coap_set_header_uri_path((void *)packet, node->interface.uri_path);
		} else {
			if (node->interface.uri_path)
				coap_free(node->interface.uri_path);
			node->interface.uri_path = coap_strdup(path);

			if (!node->interface.uri_path) {
				log_err("Memory problem");
				ret = E_NO_MEM;
				if (pathBuf)
					coap_free(pathBuf);
				goto exit;
			}

			coap_set_header_uri_path((void *)packet, node->interface.uri_path);
		}

		const char *query = strchr(path, '?');

		if (!node->interface.use_uri_query && query) {
			coap_set_header_uri_query((void *)packet, query);
			if (node->interface.uri_query)
				coap_free(node->interface.uri_query);
			node->interface.uri_query = coap_strdup(query);

			if (!node->interface.uri_query) {
				log_err("Memory problem");
				ret = E_NO_MEM;
				if (pathBuf)
					coap_free(pathBuf);
				goto exit;
			}
		}
	}

	if (msg->token && msg->token_len > 0)
		coap_set_header_token((void *)packet, (uint8_t *)msg->token,
			(size_t)msg->token_len);

	if (msg->data && msg->data_len > 0)
		coap_set_payload((void *)packet, (void *)msg->data,
			(size_t)msg->data_len);

	node->interface.method = msg->code;
	node->interface.msg_type = msg->msg_type;

	if (artik_coap_send(node->interface.session, packet) == -1) {
		log_err("Fail to send CoAP message");
		ret = E_COAP_ERROR;
	}

exit:
	if (pathBuf)
		coap_free(pathBuf);
	if (packet && (msg->msg_type == ARTIK_COAP_MSG_NON ||
		       msg->msg_type == ARTIK_COAP_MSG_RST)) {
		coap_free_header(packet);
		coap_free(packet);
	}
	return ret;
}

artik_error os_coap_observe(artik_coap_handle handle,
					const char *path,
					artik_coap_msg_type msg_type,
					artik_coap_option *options,
					int num_options,
					unsigned char *token,
					unsigned long token_len)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)handle);
	coap_packet_t *packet = NULL;
	unsigned short msg_id;
	char *pathBuf = NULL;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!node->interface.client) {
		log_err("This method is only for client handle");
		ret = E_NOT_SUPPORTED;
		goto exit;
	}

	if (!node->interface.connected) {
		log_err("The client is not connected");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!path) {
		ret = E_BAD_ARGS;
		goto exit;
	}

	msg_id = coap_new_message_id(node->interface.session);

	packet = (coap_packet_t *)coap_malloc(sizeof(coap_packet_t));

	if (!packet) {
		log_err("Fail to create new CoAP request");
		ret = E_COAP_ERROR;
		goto exit;
	}

	coap_init_message((void *)packet,
		node->interface.secure_connection ?
		COAP_UDP_DTLS : COAP_UDP, (coap_message_type_t)msg_type,
		(uint8_t)COAP_GET, (uint16_t)msg_id);

	node->interface.msg_type = msg_type;

	if (options && num_options > 0) {
		int i;

		add_options(packet, options, num_options, false, node);

		if (node->interface.coap_options && node->interface.num_coap_options > 0) {
			free_options(&node->interface.coap_options,
				node->interface.num_coap_options);
		}

		node->interface.num_coap_options = num_options;

		node->interface.coap_options =
			(artik_coap_option *)
			coap_malloc(node->interface.num_coap_options*sizeof(artik_coap_option));

		if (!node->interface.coap_options) {
			log_err("Memory problem");
			ret = E_NO_MEM;
			goto exit;
		}

		memset(node->interface.coap_options, 0,
			node->interface.num_coap_options*sizeof(artik_coap_option));

		for (i = 0; i < node->interface.num_coap_options; i++) {
			node->interface.coap_options[i].key = options[i].key;
			if (options[i].data_len > 0) {
				node->interface.coap_options[i].data = coap_malloc(options[i].data_len);

				if (!node->interface.coap_options[i].data) {
					log_err("Memory problem");
					ret = E_NO_MEM;
					free_options(&node->interface.coap_options,
						node->interface.num_coap_options);
					goto exit;
				}

				memcpy(node->interface.coap_options[i].data,
					options[i].data, options[i].data_len);

				node->interface.coap_options[i].data_len = options[i].data_len;
			}
		}
	}

	coap_set_header_observe((void *)packet, 0);

	if (!node->interface.use_uri_path && path) {
		pathBuf = coap_strdup(path);
		const char sep[2] = "?";
		char *onlyPath = strtok((char *)pathBuf, sep);

		if (onlyPath) {
			if (node->interface.uri_path)
				coap_free(node->interface.uri_path);
			node->interface.uri_path = coap_strdup(onlyPath);

			if (!node->interface.uri_path) {
				log_err("Memory problem");
				ret = E_NO_MEM;
				if (pathBuf)
					coap_free(pathBuf);
				goto exit;
			}

			coap_set_header_uri_path((void *)packet, node->interface.uri_path);
		} else {
			if (node->interface.uri_path)
				coap_free(node->interface.uri_path);
			node->interface.uri_path = coap_strdup(path);

			if (!node->interface.uri_path) {
				log_err("Memory problem");
				ret = E_NO_MEM;
				if (pathBuf)
					coap_free(pathBuf);
				goto exit;
			}

			coap_set_header_uri_path((void *)packet, node->interface.uri_path);
		}

		const char *query = strchr(path, '?');

		if (!node->interface.use_uri_query && query) {
			coap_set_header_uri_query((void *)packet, query);
			if (node->interface.uri_query)
				coap_free(node->interface.uri_query);
			node->interface.uri_query = coap_strdup(query);

			if (!node->interface.uri_query) {
				log_err("Memory problem");
				ret = E_NO_MEM;
				if (pathBuf)
					coap_free(pathBuf);
				goto exit;
			}
		}
	}

	if (token && token_len > 0)
		coap_set_header_token((void *)packet, (uint8_t *)token,
			(size_t)token_len);

	node->interface.method = COAP_GET;
	node->interface.msg_type = msg_type;

	if (artik_coap_send(node->interface.session, packet) == -1) {
		log_err("Fail to send CoAP message");
		ret = E_COAP_ERROR;
	}

exit:
	if (pathBuf)
		coap_free(pathBuf);
	if (packet && (msg_type == ARTIK_COAP_MSG_NON ||
		       msg_type == ARTIK_COAP_MSG_RST)) {
		coap_free_header(packet);
		coap_free(packet);
	}
	return ret;
}

artik_error os_coap_cancel_observe(artik_coap_handle handle,
					const char *path,
					unsigned char *token,
					unsigned long token_len)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)handle);
	coap_packet_t *packet = NULL;
	unsigned short msg_id;
	char *pathBuf = NULL;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!node->interface.client) {
		log_err("This method is only for client handle");
		ret = E_NOT_SUPPORTED;
		goto exit;
	}

	if (!node->interface.connected) {
		log_err("The client is not connected");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!path) {
		ret = E_BAD_ARGS;
		goto exit;
	}

	msg_id = coap_new_message_id(node->interface.session);

	packet = (coap_packet_t *)coap_malloc(sizeof(coap_packet_t));

	if (!packet) {
		log_err("Fail to create new CoAP request");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (node->interface.uri_path) {
		coap_free(node->interface.uri_path);
		node->interface.uri_path = NULL;
	}
	if (node->interface.uri_query) {
		coap_free(node->interface.uri_query);
		node->interface.uri_query = NULL;
	}
	if (node->interface.location_path) {
		coap_free(node->interface.location_path);
		node->interface.location_path = NULL;
	}

	coap_init_message((void *)packet, node->interface.secure_connection ?
		COAP_UDP_DTLS : COAP_UDP, (coap_message_type_t)node->interface.msg_type,
		(uint8_t)COAP_GET, (uint16_t)msg_id);

	coap_set_header_observe((void *)packet, COAP_OBSERVE_CANCEL);

	if (!node->interface.use_uri_path && path) {
		pathBuf = coap_strdup(path);
		const char sep[2] = "?";
		char *onlyPath = strtok((void *)pathBuf, sep);

		if (onlyPath) {
			if (node->interface.uri_path)
				coap_free(node->interface.uri_path);
			node->interface.uri_path = coap_strdup(onlyPath);

			if (!node->interface.uri_path) {
				log_err("Memory problem");
				ret = E_NO_MEM;
				if (pathBuf)
					coap_free(pathBuf);
				goto exit;
			}

			coap_set_header_uri_path((void *)packet, node->interface.uri_path);
		} else {
			if (node->interface.uri_path)
				coap_free(node->interface.uri_path);
			node->interface.uri_path = coap_strdup(path);

			if (!node->interface.uri_path) {
				log_err("Memory problem");
				ret = E_NO_MEM;
				if (pathBuf)
					coap_free(pathBuf);
				goto exit;
			}

			coap_set_header_uri_path((void *)packet, node->interface.uri_path);
		}

		const char *query = strchr(path, '?');

		if (query) {
			coap_set_header_uri_query((void *)packet, query);
			if (node->interface.uri_query)
				coap_free(node->interface.uri_query);
			node->interface.uri_query = coap_strdup(query);

			if (!node->interface.uri_query) {
				log_err("Memory problem");
				ret = E_NO_MEM;
				if (pathBuf)
					coap_free(pathBuf);
				goto exit;
			}
		}
	}

	if (token && token_len > 0)
		coap_set_header_token((void *)packet, (uint8_t *)token,
			(size_t)token_len);

	node->interface.method = COAP_GET;

	if (artik_coap_send(node->interface.session, packet) == -1) {
		log_err("Fail to send CoAP message");
		ret = E_COAP_ERROR;
	}

exit:
	if (pathBuf)
		coap_free(pathBuf);
	if (packet && (node->interface.msg_type == ARTIK_COAP_MSG_NON ||
		       node->interface.msg_type == ARTIK_COAP_MSG_RST)) {
		coap_free_header(packet);
		coap_free(packet);
	}
	return ret;
}

artik_error os_coap_init_resources(artik_coap_handle handle,
					artik_coap_resource *resources,
					int num_resources)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)handle);
	coap_context_t *ctx = NULL;

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (node->interface.client) {
		log_err("This method is only for server handle.");
		ret = E_NOT_SUPPORTED;
		goto exit;
	}

	if (!resources || num_resources <= 0) {
		log_err("Missing resources");
		ret = E_COAP_ERROR;
		goto exit;
	}

	ctx = node->interface.ctx;

	if (!init_resources(ctx, resources, num_resources)) {
		log_err("Fail to init resources");
		ret = E_COAP_ERROR;
		goto exit;
	}

exit:
	return ret;
}

artik_error os_coap_notify_resource_changed(artik_coap_handle handle,
					const char *path)
{

	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)handle);
	bool available_resource = false;
	int i;

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (node->interface.client) {
		log_err("This method is only for server handle");
		ret = E_NOT_SUPPORTED;
		goto exit;
	}

	if (!path) {
		log_err("Missing path for resource");
		ret = E_COAP_ERROR;
		goto exit;
	}

	artik_list *resources_list = node->interface.requested_resource_node;

	if (!resources_list) {
		log_err("No created resources");
		ret = E_COAP_ERROR;
		goto exit;
	}

	for (i = 0; i < artik_list_size(resources_list); i++) {
		if (artik_list_get_by_pos(resources_list, i)->handle) {
			ARTIK_LIST_HANDLE *list_handle =
				artik_list_get_by_pos(resources_list, i)->handle;
			resource_node *res_node = (resource_node *)artik_list_get_by_handle(
				resources_list, list_handle);

			if (res_node) {
				if (!strcmp((char *)res_node->resource.res->uri.s, path)) {
					coap_resource_set_dirty(res_node->resource.res, NULL);
					available_resource = true;
				}
			}
		}
	}

	if (!available_resource) {
		log_err("This resource does not exist");
		ret = E_COAP_ERROR;
	}

exit:
	return ret;
}

artik_error os_coap_set_send_callback(artik_coap_handle handle,
					artik_coap_send_callback callback,
					void *user_data)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)handle);

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	node->interface.send_cb = callback;
	node->interface.send_data = user_data;

exit:
	return ret;
}

artik_error os_coap_set_observe_callback(artik_coap_handle handle,
					artik_coap_observe_callback callback,
					void *user_data)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)handle);

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	node->interface.observe_cb = callback;
	node->interface.observe_data = user_data;

exit:
	return ret;
}

artik_error os_coap_set_verify_psk_callback(artik_coap_handle handle,
					artik_coap_verify_psk_callback callback,
					void *user_data)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)handle);

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (node->interface.client) {
		log_err("This method is only for server handle");
		ret = E_NOT_SUPPORTED;
		goto exit;
	}

	if (!node->interface.enable_verify_psk) {
		log_err("Verification of PSK is disabled");
		ret = E_COAP_ERROR;
		goto exit;
	}

	coap_context_t *ctx = node->interface.ctx;

	ctx->verify_psk_callback = callback;
	ctx->verify_data = user_data;

exit:
	return ret;
}
