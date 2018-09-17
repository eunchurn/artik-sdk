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
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <coap/coap.h>
#include <coap/coap_dtls.h>
#include <coap/libcoap.h>
#include <coap/address.h>
#include <coap/coap_session.h>
#include <coap/hashkey.h>
#include <coap/option.h>
#include <coap/uri.h>
#include <coap/utlist.h>
#include <coap/pdu.h>
#include <coap/subscribe.h>
#include <coap/net.h>
#include "coap_list.h"


#include <artik_log.h>
#include <artik_module.h>
#include <artik_loop.h>
#include <artik_coap.h>
#include <artik_security.h>

#include "os_coap.h"

#define BUFSIZE		128

#define INTEGER		0x02
#define BIT_STRING	0x03
#define OCTET_STRING	0x04
#define OBJ_IDENTIFIER	0x06
#define SEQUENCE	0x30
#define OPT_PARAMS	0xA0
#define OPT_PUBKEY	0xA1

/* ecPublicKey (Object Identifier) */
static unsigned char ec_public_key[] = {
	0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
};

/* prime256v1 (Object Identifier) */
static unsigned char prime_256v1[] = {
	0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

typedef struct {
	int loop_process_id;
	coap_context_t *ctx;
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
	coap_list_t *optlist;
	artik_list *requested_resource_node;
	int loop_process_id;
	bool client;
	bool connected;
	bool started;
	int method;
	int msg_type;
	os_coap_data *coap_data;
} os_coap_interface;

typedef struct {
	coap_resource_t *res;
	artik_coap_resource_callback resource_cb[ARTIK_COAP_REQ_DELETE];
	void *resource_data[ARTIK_COAP_REQ_DELETE];
} os_coap_resource;

typedef struct {
	unsigned char code;
	char *media_type;
} content_type_t;

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

static int order_opts(void *a, void *b)
{
	coap_option *o1, *o2;

	if (!a || !b)
		return a < b ? -1 : 1;

	o1 = (coap_option *)(((coap_list_t *)a)->data);
	o2 = (coap_option *)(((coap_list_t *)b)->data);

	return (COAP_OPTION_KEY(*o1) < COAP_OPTION_KEY(*o2))
			? -1 : (COAP_OPTION_KEY(*o1) != COAP_OPTION_KEY(*o2));
}


static coap_list_t *new_option_node(unsigned short key, size_t length,
				unsigned char *data)
{
	coap_list_t *node;

	node = coap_malloc(sizeof(coap_list_t) + sizeof(coap_option) + length);

	if (node) {
		coap_option *option;

		option = (coap_option *)(node->data);
		COAP_OPTION_KEY(*option) = key;
		COAP_OPTION_LENGTH(*option) = length;
		if (data)
			memcpy(COAP_OPTION_DATA(*option), data, length);
	} else
		log_dbg("new_option_node : malloc");

	return node;
}

static bool add_options(coap_list_t **optlist, artik_coap_option *options,
				int num_options, bool observe)
{
	artik_coap_option *opt = options;
	artik_coap_option *end = opt + num_options;

	for (; opt != end; opt++) {
		switch (opt->key) {
		case ARTIK_COAP_OPTION_IF_MATCH:
		case ARTIK_COAP_OPTION_URI_HOST:
		case ARTIK_COAP_OPTION_ETAG:
		case ARTIK_COAP_OPTION_URI_PATH:
		case ARTIK_COAP_OPTION_URI_QUERY:
		case ARTIK_COAP_OPTION_LOCATION_PATH:
		case ARTIK_COAP_OPTION_LOCATION_QUERY:
		case ARTIK_COAP_OPTION_PROXY_URI:
		case ARTIK_COAP_OPTION_PROXY_SCHEME:
		case ARTIK_COAP_OPTION_ACCEPT:
		case ARTIK_COAP_OPTION_CONTENT_FORMAT:
		case ARTIK_COAP_OPTION_BLOCK2:
			coap_insert(optlist,
				new_option_node(opt->key,
				opt->data_len,
				opt->data));
			break;
		case ARTIK_COAP_OPTION_OBSERVE:
			if (observe) {
				coap_insert(optlist,
				new_option_node(opt->key,
				0,
				NULL));
			}
			break;
		case ARTIK_COAP_OPTION_IF_NONE_MATCH:
			coap_insert(optlist,
				new_option_node(opt->key,
				0,
				NULL));
			break;
		case ARTIK_COAP_OPTION_URI_PORT:
			if (!opt->data) {
				log_err("URI port option not well defined");
				return false;
			}

			coap_insert(optlist,
				new_option_node(opt->key,
				opt->data_len,
				opt->data));
			break;
		case ARTIK_COAP_OPTION_MAXAGE: {
			unsigned long maxAge = 60;

			if (!opt->data) {
				opt->data = malloc(1);
				if (!opt->data) {
					log_err("Fail to allocate option");
					return false;
				}
				opt->data_len = 1;
				memcpy(opt->data, &maxAge, opt->data_len);
			}

			coap_insert(optlist,
				new_option_node(opt->key,
				opt->data_len,
				opt->data));
			break;
		}
		case ARTIK_COAP_OPTION_SIZE1:
			if (!opt->data) {
				log_err("Size1 option not well defined");
				return false;
			}

			coap_insert(optlist,
				new_option_node(opt->key,
				opt->data_len,
				opt->data));
			break;
		default:
			break;
		}
	}

	return true;
}


static bool check_option(const coap_pdu_t *pdu, unsigned short key)
{
	coap_opt_iterator_t opt_iter;
	coap_opt_t *option;

	coap_option_iterator_init((coap_pdu_t *)pdu, &opt_iter, COAP_OPT_ALL);

	while ((option = coap_option_next(&opt_iter))) {
		if (opt_iter.type == key)
			return true;
	}

	return false;
}

static void get_options(const coap_pdu_t *pdu, artik_coap_option **options,
				int *num_options, bool observe)
{
	artik_coap_option *opt;
	artik_coap_option *end;

	coap_opt_iterator_t opt_iter;
	coap_opt_t *option;

	if (*options) {
		log_err("options must be NULL");
		return;
	}

	*num_options = 0;

	coap_option_iterator_init((coap_pdu_t *)pdu, &opt_iter, COAP_OPT_ALL);

	while ((option = coap_option_next(&opt_iter))) {
		switch (opt_iter.type) {
		case COAP_OPTION_URI_HOST:
		case COAP_OPTION_URI_PATH:
		case COAP_OPTION_URI_QUERY:
		case COAP_OPTION_LOCATION_PATH:
		case COAP_OPTION_LOCATION_QUERY:
		case COAP_OPTION_PROXY_URI:
		case COAP_OPTION_PROXY_SCHEME:
		case COAP_OPTION_IF_MATCH:
		case COAP_OPTION_ETAG:
		case COAP_OPTION_URI_PORT:
		case COAP_OPTION_ACCEPT:
		case COAP_OPTION_CONTENT_FORMAT:
		case COAP_OPTION_MAXAGE:
		case COAP_OPTION_SIZE1:
		case COAP_OPTION_BLOCK2:
		case COAP_OPTION_OBSERVE:
		case COAP_OPTION_IF_NONE_MATCH:
			*num_options += 1;
			break;
		default:
			log_err("Option ID %d not supported", opt_iter.type);
			break;
		}
	}

	if (*num_options > 0)
		*options = malloc(*num_options*sizeof(artik_coap_option));
	else {
		log_dbg(" No options");
		return;
	}

	if (!*options) {
		log_err("Fail to allocate options");
		return;
	}

	memset(*options, 0, *num_options*sizeof(artik_coap_option));

	opt = *options;
	end = opt + *num_options;

	coap_option_iterator_init((coap_pdu_t *)pdu, &opt_iter, COAP_OPT_ALL);

	while ((option = coap_option_next(&opt_iter)) && opt != end) {
		if (opt->data) {
			free(opt->data);
			opt->data = NULL;
		}

		switch (opt_iter.type) {
		case COAP_OPTION_URI_HOST:
		case COAP_OPTION_URI_PATH:
		case COAP_OPTION_URI_QUERY:
		case COAP_OPTION_LOCATION_PATH:
		case COAP_OPTION_LOCATION_QUERY:
		case COAP_OPTION_PROXY_URI:
		case COAP_OPTION_PROXY_SCHEME:
			opt->key = opt_iter.type;
			opt->data = malloc(coap_opt_length(option) + 1);
			if (!opt->data) {
				log_err("Fail to allocate option");
				return;
			}
			memcpy(opt->data, coap_opt_value(option),
				coap_opt_length(option));
			opt->data_len = coap_opt_length(option) + 1;

			opt->data[opt->data_len - 1] = 0;
			opt++;
			break;
		case COAP_OPTION_IF_MATCH:
		case COAP_OPTION_ETAG:
			opt->key = opt_iter.type;
			opt->data = malloc(coap_opt_length(option));
			if (!opt->data) {
				log_err("Fail to allocate option");
				return;
			}
			memcpy(opt->data, coap_opt_value(option),
				coap_opt_length(option));
			opt->data_len = coap_opt_length(option);
			opt++;
			break;
		case COAP_OPTION_URI_PORT:
		case COAP_OPTION_ACCEPT:
		case COAP_OPTION_CONTENT_FORMAT:
		case COAP_OPTION_MAXAGE:
		case COAP_OPTION_SIZE1:
		case COAP_OPTION_BLOCK2: {
			unsigned int val = 0;

			if (coap_opt_length(option) > 0) {
				memcpy(&val, coap_opt_value(option),
					coap_opt_length(option));

				if (ARCH_LITTLE_ENDIAN)
					swap_bytes(&val, coap_opt_length(option));

				opt->key = opt_iter.type;
				opt->data = malloc(coap_opt_length(option));
				if (!opt->data) {
					log_err("Fail to allocate option");
					return;
				}
				memcpy(opt->data, &val, coap_opt_length(option));
				opt->data_len = coap_opt_length(option);
			} else
				opt->key = opt_iter.type;
			opt++;
			break;
		}
		case COAP_OPTION_OBSERVE:
			if (observe) {
				unsigned int val = 0;

				if (coap_opt_length(option) > 0) {
					memcpy(&val, coap_opt_value(option),
						coap_opt_length(option));

					if (ARCH_LITTLE_ENDIAN)
						swap_bytes(&val, coap_opt_length(option));

					opt->key = opt_iter.type;
					opt->data = malloc(coap_opt_length(option));
					if (!opt->data) {
						log_err("Fail to allocate option");
						return;
					}
					memcpy(opt->data, &val, coap_opt_length(option));
					opt->data_len = coap_opt_length(option);
				} else
					opt->key = opt_iter.type;
				opt++;
			}
			break;
		case COAP_OPTION_IF_NONE_MATCH:
			opt->key = opt_iter.type;
			opt->data = NULL;
			opt->data_len = 0;
			opt++;
			break;
		default:
			break;
		}
	}
}

static void free_options(artik_coap_option **options, int num_options)
{
	if (!*options || num_options < 0)
		return;

	int i;

	for (i = 0; i < num_options; i++) {
		if ((*options)[i].data)
			free((*options)[i].data);
	}
	if (*options) {
		free(*options);
		*options = NULL;
	}
}

static int parse_uri(const char *uri, coap_uri_t *u, coap_list_t **optlist)
{

	if (coap_split_uri((unsigned char *)uri, strlen(uri), u) < 0) {
		log_err("Invalid CoAP URI");
		return -1;
	}

	return 0;
}

static bool asn1_parse_pubkey(const unsigned char *data,
		int data_len, char **pub_key, int *pub_key_length)
{
	if (!data || !pub_key || *pub_key || !pub_key_length || data_len <= 0)
		return false;

	const unsigned char *p = data;
	const unsigned char *end = data + data_len;

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

		for (int i = 0; i < length && p != end; i++, p++)
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

		for (int i = 0; i < length && p != end; i++, p++)
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

		(*pub_key) = malloc((length)*sizeof(char));

		if (!*pub_key) {
			log_err("Fail to allocate pub_key");
			return false;
		}

		for (int i = 0; i < length && p != end; i++, p++)
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

		(*key) = malloc((length)*sizeof(char));

		if (!*key) {
			log_err("Fail to allocate key");
			return false;
		}

		for (int i = 0; i < length && p != end; i++, p++)
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

		for (int i = 0; i < length && p != end; i++, p++)
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

		for (int i = 0; i < length && p != end; i++, p++)
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

	*pub_key_x = malloc(size);
	*pub_key_y = malloc(size);

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

static int resolve_address(const str *server, struct sockaddr *dst)
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
		log_err("getaddrinfo: %s", gai_strerror(error));
		if (res)
			freeaddrinfo(res);
		return error;
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
				coap_proto_t proto,
				coap_address_t *dst,
				artik_ssl_config *ssl,
				artik_coap_psk_param *psk)
{
	coap_session_t *session = NULL;
	artik_security_module *security = NULL;

	if (ssl && psk && proto == COAP_PROTO_DTLS) {
		log_err("SSL and PSK cannot be defined"
			" together.");
		return NULL;
	} else if (ssl && !psk && proto == COAP_PROTO_DTLS
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
			log_err("Fail to get EC public key"
				" from certificate");
			artik_release_api_module(security);
			return NULL;
		}

		ret = security->convert_pem_to_der(pub_key_pem, &pub_key_der,
			(unsigned int *)&pub_key_der_len);

		if (ret != S_OK) {
			log_err("Fail to convert"
				" public key");
			artik_release_api_module(security);
			return NULL;
		}

		ret = security->convert_pem_to_der(ssl->client_key.data,
			&priv_key_der, (unsigned int *)&priv_key_der_len);

		if (ret != S_OK) {
			log_err("Fail to convert"
				" private key");
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
			log_err("Fail to extract pub key"
				" x and y");
			return NULL;
		}

		ecdsa_keys.priv_key = malloc(ec_priv_key_length);
		if (!ecdsa_keys.priv_key) {
			log_err("Fail to allocate priv_key");
			return NULL;
		}
		memcpy(ecdsa_keys.priv_key, ec_priv_key,
						ec_priv_key_length);
		ecdsa_keys.priv_key_len = ec_priv_key_length;

		int size = (ec_pub_key_length - 1)/2;

		ecdsa_keys.pub_key_x = malloc(size);
		if (!ecdsa_keys.pub_key_x) {
			log_err("Fail to allocate pub_key_x");
			if (ecdsa_keys.priv_key)
				free(ecdsa_keys.priv_key);
			return NULL;
		}
		memcpy(ecdsa_keys.pub_key_x, ec_pub_key_x,
						size);
		ecdsa_keys.pub_key_x_len = size;

		ecdsa_keys.pub_key_y = malloc(size);
		if (!ecdsa_keys.pub_key_y) {
			log_err("Fail to allocate pub_key_y");
			if (ecdsa_keys.priv_key)
				free(ecdsa_keys.priv_key);
			if (ecdsa_keys.pub_key_x)
				free(ecdsa_keys.pub_key_x);
			return NULL;
		}
		memcpy(ecdsa_keys.pub_key_y, ec_pub_key_y,
						size);
		ecdsa_keys.pub_key_y_len = size;

		session = coap_new_client_session_ssl(
				ctx, NULL, dst,
				proto, &ecdsa_keys);

		if (pub_key_pem)
			free(pub_key_pem);
		if (ec_pub_key)
			free(ec_pub_key);
		if (ec_priv_key)
			free(ec_priv_key);
		if (ec_pub_key_x)
			free(ec_pub_key_x);
		if (ec_pub_key_y)
			free(ec_pub_key_y);
		if (pub_key_der)
			free(pub_key_der);
		if (priv_key_der)
			free(priv_key_der);

	} else if (!ssl && psk && proto == COAP_PROTO_DTLS
			&& psk->identity
			&& psk->psk) {
		const char *identity = psk->identity;
		const uint8_t *key = (const uint8_t *)psk->psk;
		unsigned int key_len = (unsigned int)psk->psk_len;

		session = coap_new_client_session_psk(
				ctx, NULL, dst,
				proto, identity, key,
				key_len);
	} else
		session = coap_new_client_session(
				ctx, NULL, dst,
				proto);

	return session;
}

static bool create_endpoint(coap_context_t *ctx,
			coap_proto_t proto,
			const char *node,
			const char *port)
{
	int s;
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp = NULL;

	if (!ctx)
		return false;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

	s = getaddrinfo(node, port, &hints, &result);

	if (s != 0) {
		log_err("getaddrinfo: %s", gai_strerror(s));
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

static coap_pdu_t *coap_new_request(coap_context_t *ctx,
			coap_session_t *session,
			artik_coap_msg_type msg_type,
			artik_coap_code method,
			unsigned short *msg_id,
			coap_list_t **options,
			unsigned char *token,
			unsigned long token_len,
			unsigned char *data,
			size_t length)
{
	coap_pdu_t *pdu;
	coap_list_t *opt;
	(void)ctx;

	pdu = coap_new_pdu(session);

	if (!pdu)
		return NULL;

	pdu->hdr->type = msg_type;
	if (!*msg_id) {
		pdu->hdr->id = coap_new_message_id(session);
		*msg_id = pdu->hdr->id;
	} else
		pdu->hdr->id = htons(*msg_id);
	pdu->hdr->code = method;

	if (token && token_len > 0) {
		if (!coap_add_token(pdu, token_len, token))
			log_dbg("Cannot add token to request");
	}

	log_dbg("");

	if (options) {
		LL_SORT((*options), order_opts);

		LL_FOREACH((*options), opt) {
			coap_option *o = (coap_option *)(opt->data);

			coap_add_option(pdu,
					COAP_OPTION_KEY(*o),
					COAP_OPTION_LENGTH(*o),
					COAP_OPTION_DATA(*o));
		}
	}

	if (data && length > 0)
		coap_add_data(pdu, length, data);

	return pdu;

}

static void message_handler(struct coap_context_t *ctx,
		coap_session_t *session, coap_pdu_t *sent,
		coap_pdu_t *received, const coap_tid_t id)
{
	size_t len;
	unsigned char *databuf;
	unsigned char bufBlock[4];
	coap_pdu_t *pdu = NULL;
	artik_coap_msg msg;
	coap_opt_t *block_opt = NULL;
	coap_opt_iterator_t opt_iter;
	coap_list_t *option;
	artik_coap_error error = ARTIK_COAP_ERROR_NONE;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)ctx);

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		return;
	}

	memset(&msg, 0, sizeof(artik_coap_msg));

	msg.msg_type = received->hdr->type;
	msg.msg_id = ntohs(received->hdr->id);
	msg.code = received->hdr->code;
	msg.token = received->hdr->token;
	msg.token_len = received->hdr->token_length;

	get_options(received, &msg.options, &msg.num_options, true);

	block_opt = coap_check_option(received, COAP_OPTION_BLOCK2, &opt_iter);

	if (block_opt) {
		unsigned short blktype = opt_iter.type;

		if (coap_get_data(received, &len, &databuf)) {

			msg.data = malloc(len+1);
			if (!msg.data) {
				log_err("Fail to allocate msg.data");
				if (msg.options && msg.num_options > 0)
					free_options(&msg.options, msg.num_options);
				return;
			}
			memcpy(msg.data, databuf, len);
			msg.data_len = len;
			msg.data[len] = 0;
		}

		if (COAP_OPT_BLOCK_MORE(block_opt)) {

			int method = node->interface.method;
			int msg_type = node->interface.msg_type;
			unsigned short msg_id = 0;

			pdu = coap_new_request(ctx, session, msg_type,
				method, &msg_id, NULL, msg.token, msg.token_len, NULL, 0);

			if (pdu) {
				for (option = node->interface.optlist;
					option; option = option->next) {
					coap_option *o = (coap_option *)(option->data);

					switch (COAP_OPTION_KEY(*o)) {
					case COAP_OPTION_URI_HOST:
					case COAP_OPTION_URI_PATH:
					case COAP_OPTION_URI_QUERY:
					case COAP_OPTION_LOCATION_PATH:
					case COAP_OPTION_LOCATION_QUERY:
					case COAP_OPTION_PROXY_URI:
					case COAP_OPTION_PROXY_SCHEME:
					case COAP_OPTION_IF_MATCH:
					case COAP_OPTION_ETAG:
					case COAP_OPTION_URI_PORT:
					case COAP_OPTION_ACCEPT:
					case COAP_OPTION_CONTENT_FORMAT:
					case COAP_OPTION_MAXAGE:
					case COAP_OPTION_SIZE1:
					case COAP_OPTION_IF_NONE_MATCH:
						coap_add_option(
							pdu,
							COAP_OPTION_KEY(*o),
							COAP_OPTION_LENGTH(*o),
							COAP_OPTION_DATA(*o));
						break;
					default:
						break;
					}
				}

				coap_add_option(pdu, blktype,
					coap_encode_var_bytes(bufBlock,
						((coap_opt_block_num(block_opt) + 1) << 4) |
						COAP_OPT_BLOCK_SZX(block_opt)), bufBlock);

				if (coap_send(session, pdu) == COAP_INVALID_TID)
					log_err("Fail to send new request");
			}
		}
	} else {
		if (coap_get_data(received, &len, &databuf)) {

			msg.data = malloc(len+1);
			if (!msg.data) {
				log_err("Fail to allocate msg.data");
				if (msg.options && msg.num_options > 0)
					free_options(&msg.options, msg.num_options);
				return;
			}
			memcpy(msg.data, databuf, len);
			msg.data_len = len;
			msg.data[len] = 0;
		}
	}


	if (node->interface.client &&
		node->interface.observe_cb && (check_option(received,
						COAP_OPTION_OBSERVE) ||
					check_option(received, COAP_OPTION_BLOCK2) ||
					msg.code >= ARTIK_COAP_RES_BAD_REQUEST))
		node->interface.observe_cb(&msg,
			error,
			node->interface.observe_data);

	if (node->interface.client &&
		node->interface.send_cb && !check_option(received,
						COAP_OPTION_OBSERVE))
		node->interface.send_cb(&msg,
			error,
			node->interface.send_data);

	if (msg.options && msg.num_options > 0)
		free_options(&msg.options, msg.num_options);

	if (msg.data)
		free(msg.data);
}

static void nack_handler(struct coap_context_t *ctx,
		coap_session_t *session, coap_pdu_t *sent,
		coap_nack_reason_t reason, const coap_tid_t id)
{
	artik_coap_msg msg;
	artik_coap_error error = ARTIK_COAP_ERROR_NONE;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)ctx);
	artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");
	os_coap_data *data = NULL;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		return;
	}

	if (!node->interface.connected)
		return;

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

	data = node->interface.coap_data;

	if (!data)
		return;

	if (!node->interface.connected) {

		if (loop->remove_idle_callback(data->loop_process_id)
								!= S_OK)
			log_err("Fail to remove callback");

		free(data);
	}

	artik_release_api_module(loop);
}

static void get_resource_handler(coap_context_t *ctx,
				struct coap_resource_t *resource,
				coap_session_t *session,
				coap_pdu_t *request,
				str *token,
				str *query,
				coap_pdu_t *response)
{
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)ctx);
	size_t len;
	unsigned char *databuf;
	artik_coap_msg msg;
	artik_coap_msg resp;
	coap_list_t *opt;
	unsigned char obsBuf[40];

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

	memset(&msg, 0, sizeof(artik_coap_msg));
	memset(&resp, 0, sizeof(artik_coap_msg));

	if (request) {
		msg.msg_type = request->hdr->type;
		msg.msg_id = ntohs(request->hdr->id);
		msg.code = request->hdr->code;
		msg.token = request->hdr->token;
		msg.token_len = request->hdr->token_length;

		get_options(request, &msg.options, &msg.num_options, false);

		if (coap_get_data(request, &len, &databuf)) {
			msg.data = malloc(len + 1);
			if (!msg.data) {
				log_err("Fail to allocate msg.data");
				if (msg.options && msg.num_options > 0)
					free_options(&msg.options, msg.num_options);
				return;
			}
			memcpy(msg.data, databuf, len + 1);
			msg.data_len = len + 1;
		}
	}

	if (res_node->resource.resource_cb[0])
		res_node->resource.resource_cb[0](&msg,
			&resp,
			res_node->resource.resource_data[0]);

	response->hdr->code = resp.code;

	if (node->interface.optlist) {
		coap_delete_list(node->interface.optlist);
		node->interface.optlist = NULL;
	}

	if (resource->observable && coap_find_observer(resource, session, token))
		coap_add_option(response,
				COAP_OPTION_OBSERVE,
				coap_encode_var_bytes(obsBuf, ctx->observe), obsBuf);

	if (resp.options && resp.num_options > 0) {
		if (!add_options(&node->interface.optlist, resp.options,
				resp.num_options, false)) {
			log_err("Options not well defined");
			goto exit;
		}
		free_options(&resp.options, resp.num_options);
	}

	if (node->interface.optlist) {
		LL_SORT((node->interface.optlist), order_opts);

		LL_FOREACH((node->interface.optlist), opt) {
			coap_option *o = (coap_option *)(opt->data);

			coap_add_option(response,
					COAP_OPTION_KEY(*o),
					COAP_OPTION_LENGTH(*o),
					COAP_OPTION_DATA(*o));
		}
	}

	if (resp.data && resp.data_len > 0) {
		coap_add_data(response, resp.data_len, resp.data);
		free(resp.data);
	}

exit:
	if (msg.data)
		free(msg.data);
	if (msg.options && msg.num_options > 0)
		free_options(&msg.options, msg.num_options);
}

static void post_resource_handler(coap_context_t *ctx,
				struct coap_resource_t *resource,
				coap_session_t *session,
				coap_pdu_t *request,
				str *token,
				str *query,
				coap_pdu_t *response)
{
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)ctx);
	size_t len;
	unsigned char *databuf;
	artik_coap_msg msg;
	artik_coap_msg resp;
	coap_list_t *opt;
	unsigned char obsBuf[40];

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

	memset(&msg, 0, sizeof(artik_coap_msg));
	memset(&resp, 0, sizeof(artik_coap_msg));

	if (request) {
		msg.msg_type = request->hdr->type;
		msg.msg_id = ntohs(request->hdr->id);
		msg.code = request->hdr->code;
		msg.token = request->hdr->token;
		msg.token_len = request->hdr->token_length;

		get_options(request, &msg.options, &msg.num_options, false);

		if (coap_get_data(request, &len, &databuf)) {
			msg.data = malloc(len + 1);
			if (!msg.data) {
				log_err("Fail to allocate msg.data");
				return;
			}
			memcpy(msg.data, databuf, len + 1);
			msg.data_len = len + 1;
		}
	}

	if (res_node->resource.resource_cb[1])
		res_node->resource.resource_cb[1](&msg,
			&resp,
			res_node->resource.resource_data[1]);

	response->hdr->code = resp.code;

	if (node->interface.optlist) {
		coap_delete_list(node->interface.optlist);
		node->interface.optlist = NULL;
	}

	if (resource->observable && coap_find_observer(resource, session, token))
		coap_add_option(response,
				COAP_OPTION_OBSERVE,
				coap_encode_var_bytes(obsBuf, ctx->observe), obsBuf);

	if (resp.options && resp.num_options > 0) {
		if (!add_options(&node->interface.optlist, resp.options,
				resp.num_options, false)) {
			log_err("Options not well defined");
			goto exit;
		}
		free_options(&resp.options, resp.num_options);
	}

	if (node->interface.optlist) {
		LL_SORT((node->interface.optlist), order_opts);

		LL_FOREACH((node->interface.optlist), opt) {
			coap_option *o = (coap_option *)(opt->data);

			coap_add_option(response,
					COAP_OPTION_KEY(*o),
					COAP_OPTION_LENGTH(*o),
					COAP_OPTION_DATA(*o));
		}
	}

	if (resp.data && resp.data_len > 0) {
		coap_add_data(response, resp.data_len, resp.data);
		free(resp.data);
	}

exit:
	if (msg.data)
		free(msg.data);
	if (msg.options && msg.num_options > 0)
		free_options(&msg.options, msg.num_options);
}

static void put_resource_handler(coap_context_t *ctx,
				struct coap_resource_t *resource,
				coap_session_t *session,
				coap_pdu_t *request,
				str *token,
				str *query,
				coap_pdu_t *response)
{
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)ctx);
	size_t len;
	unsigned char *databuf;
	artik_coap_msg msg;
	artik_coap_msg resp;
	coap_list_t *opt;
	unsigned char obsBuf[40];

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

	memset(&msg, 0, sizeof(artik_coap_msg));
	memset(&resp, 0, sizeof(artik_coap_msg));

	if (request) {
		msg.msg_type = request->hdr->type;
		msg.msg_id = ntohs(request->hdr->id);
		msg.code = request->hdr->code;
		msg.token = request->hdr->token;
		msg.token_len = request->hdr->token_length;

		get_options(request, &msg.options, &msg.num_options, false);

		if (coap_get_data(request, &len, &databuf)) {
			msg.data = malloc(len + 1);
			if (!msg.data) {
				log_err("Fail to allocate msg.data");
				return;
			}
			memcpy(msg.data, databuf, len + 1);
			msg.data_len = len + 1;
		}
	}

	if (res_node->resource.resource_cb[2])
		res_node->resource.resource_cb[2](&msg,
			&resp,
			res_node->resource.resource_data[2]);

	response->hdr->code = resp.code;

	if (node->interface.optlist) {
		coap_delete_list(node->interface.optlist);
		node->interface.optlist = NULL;
	}

	if (resource->observable && coap_find_observer(resource, session, token))
		coap_add_option(response,
				COAP_OPTION_OBSERVE,
				coap_encode_var_bytes(obsBuf, ctx->observe), obsBuf);

	if (resp.options && resp.num_options > 0) {
		if (!add_options(&node->interface.optlist, resp.options,
				resp.num_options, false)) {
			log_err("Options not well defined");
			goto exit;
		}
		free_options(&resp.options, resp.num_options);
	}

	if (node->interface.optlist) {
		LL_SORT((node->interface.optlist), order_opts);

		LL_FOREACH((node->interface.optlist), opt) {
			coap_option *o = (coap_option *)(opt->data);

			coap_add_option(response,
					COAP_OPTION_KEY(*o),
					COAP_OPTION_LENGTH(*o),
					COAP_OPTION_DATA(*o));
		}
	}

	if (resp.data && resp.data_len > 0) {
		coap_add_data(response, resp.data_len, resp.data);
		free(resp.data);
	}

exit:
	if (msg.data)
		free(msg.data);
	if (msg.options && msg.num_options > 0)
		free_options(&msg.options, msg.num_options);
}

static void delete_resource_handler(coap_context_t *ctx,
				struct coap_resource_t *resource,
				coap_session_t *session,
				coap_pdu_t *request,
				str *token,
				str *query,
				coap_pdu_t *response)
{
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)ctx);
	size_t len;
	unsigned char *databuf;
	artik_coap_msg msg;
	artik_coap_msg resp;
	coap_list_t *opt;
	unsigned char obsBuf[40];

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

	memset(&msg, 0, sizeof(artik_coap_msg));
	memset(&resp, 0, sizeof(artik_coap_msg));

	if (request) {
		msg.msg_type = request->hdr->type;
		msg.msg_id = ntohs(request->hdr->id);
		msg.code = request->hdr->code;
		msg.token = request->hdr->token;
		msg.token_len = request->hdr->token_length;

		get_options(request, &msg.options, &msg.num_options, false);

		if (coap_get_data(request, &len, &databuf)) {
			msg.data = malloc(len + 1);
			if (!msg.data) {
				log_err("Fail to allocate msg.data");
				return;
			}
			memcpy(msg.data, databuf, len + 1);
			msg.data_len = len + 1;
		}
	}

	if (res_node->resource.resource_cb[3])
		res_node->resource.resource_cb[3](&msg,
			&resp,
			res_node->resource.resource_data[3]);

	response->hdr->code = resp.code;

	if (node->interface.optlist) {
		coap_delete_list(node->interface.optlist);
		node->interface.optlist = NULL;
	}

	if (resource->observable && coap_find_observer(resource, session, token))
		coap_add_option(response,
				COAP_OPTION_OBSERVE,
				coap_encode_var_bytes(obsBuf, ctx->observe), obsBuf);

	if (resp.options && resp.num_options > 0) {
		if (!add_options(&node->interface.optlist, resp.options,
				resp.num_options, false)) {
			log_err("Options not well defined");
			goto exit;
		}
		free_options(&resp.options, resp.num_options);
	}

	if (node->interface.optlist) {
		LL_SORT((node->interface.optlist), order_opts);

		LL_FOREACH((node->interface.optlist), opt) {
			coap_option *o = (coap_option *)(opt->data);

			coap_add_option(response,
					COAP_OPTION_KEY(*o),
					COAP_OPTION_LENGTH(*o),
					COAP_OPTION_DATA(*o));
		}
	}

	if (resp.data && resp.data_len > 0) {
		coap_add_data(response, resp.data_len, resp.data);
		free(resp.data);
	}

exit:
	if (msg.data)
		free(msg.data);
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
		log_err("No CoAP context exists for this handle");
		return false;
	}

	artik_coap_resource *res = resources;
	artik_coap_resource *end_res = res + num_resources;

	for (; res != end_res; res++) {
		coap_resource_t *r = NULL;
		resource_node *res_node = NULL;

		r = coap_resource_init((unsigned char *)res->path, res->path_len,
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

			coap_register_handler(r, COAP_REQUEST_GET,
				get_resource_handler);
		}

		if (res->resource_cb[1]) {
			res_node->resource.resource_cb[1] =
			res->resource_cb[1];

			res_node->resource.resource_data[1] =
			res->resource_data[1];

			coap_register_handler(r, COAP_REQUEST_POST,
				post_resource_handler);
		}

		if (res->resource_cb[2]) {
			res_node->resource.resource_cb[2] =
			res->resource_cb[2];

			res_node->resource.resource_data[2] =
			res->resource_data[2];

			coap_register_handler(r, COAP_REQUEST_PUT,
				put_resource_handler);
		}

		if (res->resource_cb[3]) {
			res_node->resource.resource_cb[3] =
			res->resource_cb[3];

			res_node->resource.resource_data[3] =
			res->resource_data[3];

			coap_register_handler(r, COAP_REQUEST_DELETE,
				delete_resource_handler);
		}

		r->observable = res->observable;

		artik_coap_attr *att = res->attributes;
		artik_coap_attr *end_att = att + res->num_attributes;

		for (; att != end_att; att++) {
			coap_add_attr(r, att->name, att->name_len, att->val,
				att->val_len, 0);
		}

		coap_add_resource(ctx, r);
	}

	return true;
}

static int client_loop_handler(void *arg)
{
	os_coap_data *data = (os_coap_data *)arg;

	coap_run_once(data->ctx, 10);

	return 1;
}

static int server_loop_handler(void *arg)
{
	os_coap_data *data = (os_coap_data *)arg;

	coap_run_once(data->ctx, 10);

	coap_check_notify(data->ctx);

	return 1;
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

	interface = malloc(sizeof(os_coap_interface));

	if (interface == NULL) {
		log_err("Failed to allocate memory");
		ret = E_NO_MEM;
		goto exit;
	}

	memset(interface, 0, sizeof(os_coap_interface));

	ctx = coap_new_context(NULL, config->ssl ? 1 : config->psk ? 2 : 0);

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
		free(interface);

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

	if (node->interface.session) {
		coap_session_release(node->interface.session);
		node->interface.session = NULL;
	}

	if (node->interface.ctx) {
		coap_free_context(node->interface.ctx);
		node->interface.ctx = NULL;
	}

	if (node->interface.optlist) {
		coap_delete_list(node->interface.optlist);
		node->interface.optlist = NULL;
	}

	artik_list_delete_node(&requested_node, (artik_list *)node);

exit:
	return ret;
}

artik_error os_coap_connect(artik_coap_handle client)
{
	artik_error ret = S_OK;
	artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)client);
	artik_coap_config *config = NULL;
	coap_context_t *ctx = NULL;
	coap_session_t *session = NULL;
	coap_uri_t u;
	coap_address_t dst;
	static str server;
	unsigned short port = COAP_DEFAULT_PORT;
	int res;

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

	if ((parse_uri(config->uri, &u, &node->interface.optlist) < 0)) {
		log_err("Fail to parse URI");
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
				coap_uri_scheme_is_secure(&u) ?
					COAP_PROTO_DTLS : COAP_PROTO_UDP,
				&dst,
				config->ssl ? config->ssl : NULL,
				config->psk ? config->psk : NULL
				);

	if (!session) {
		log_err("Cannot create client session");
		ret = E_COAP_ERROR;
		goto exit;
	}

	node->interface.session = session;

	coap_register_response_handler(ctx, message_handler);
	coap_register_nack_handler(ctx, nack_handler);

	node->interface.coap_data = (os_coap_data *)malloc(sizeof(os_coap_data));

	if (!node->interface.coap_data) {
		log_err("Memory problem");
		ret = E_COAP_ERROR;
		goto exit;
	}

	memset(node->interface.coap_data, 0, sizeof(os_coap_data));

	node->interface.coap_data->ctx = ctx;

	if (loop->add_idle_callback(&node->interface.coap_data->loop_process_id,
		client_loop_handler, node->interface.coap_data) != S_OK) {
		log_err("Fail to add idle callback");
		ret = E_COAP_ERROR;
		goto exit;
	}

	node->interface.connected = true;

exit:
	artik_release_api_module(loop);

	return ret;
}

artik_error os_coap_disconnect(artik_coap_handle client)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)client);
	artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");
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

	if (node->interface.session) {
		coap_session_release(node->interface.session);
		node->interface.session = NULL;
	} else {
		log_err("No session exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	data = node->interface.coap_data;

	if (!data) {
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (loop->remove_idle_callback(data->loop_process_id) != S_OK) {
		log_err("Fail to remove callback");
		ret = E_COAP_ERROR;
		goto exit;
	}

	node->interface.connected = false;

	if (node->interface.coap_data)
		free(node->interface.coap_data);

exit:
	artik_release_api_module(loop);

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

	interface = malloc(sizeof(os_coap_interface));

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

	ctx = coap_new_context(NULL, config->ssl ? 1 : config->psk ||
			config->enable_verify_psk ? 2 : 0);

	if (config->psk && config->psk->identity && config->psk->psk) {
		size_t key_len = (size_t)config->psk->psk_len;
		uint8_t *key = NULL;

		key = malloc(key_len*sizeof(uint8_t));

		if (!key) {
			log_err("Fail to allocate key");
			ret = E_NO_MEM;
			goto exit;
		}

		memcpy(key, config->psk->psk, key_len);
		coap_context_set_psk(ctx, config->psk->identity, key, key_len);

		if (key)
			free(key);
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
			log_err("Fail to get EC public key"
				" from certificate");
			artik_release_api_module(security);
			ret = E_COAP_ERROR;
			goto exit;
		}

		if (security->convert_pem_to_der(pub_key_pem,
			&pub_key_der, (unsigned int *)&pub_key_der_len) != S_OK) {
			log_err("Fail to convert"
				" public key");
			artik_release_api_module(security);
			ret = E_COAP_ERROR;
			goto exit;
		}

		if (security->convert_pem_to_der(
			config->ssl->client_key.data, &priv_key_der,
				(unsigned int *)&priv_key_der_len) != S_OK) {
			log_err("Fail to convert"
				" private key");
			artik_release_api_module(security);
			ret = E_COAP_ERROR;
			goto exit;
		}

		artik_release_api_module(security);

		if (!asn1_parse_pubkey(pub_key_der, pub_key_der_len, &ec_pub_key,
				&ec_pub_key_length)) {
			log_err("Fail to parse pubkey");
			ret = E_COAP_ERROR;
			goto exit;
		}

		if (!asn1_parse_key(priv_key_der, priv_key_der_len, ec_pub_key,
				&ec_priv_key, &ec_priv_key_length)) {
			log_err("Fail to parse priv_key");
			ret = E_COAP_ERROR;
			goto exit;
		}

		if (extract_pubkey_x_y(ec_pub_key, ec_pub_key_length,
				&ec_pub_key_x, &ec_pub_key_y) < 0) {
			log_err("Fail to extract pub key"
				" x and y");
			ret = E_COAP_ERROR;
			goto exit;
		}

		int size = (ec_pub_key_length - 1)/2;

		coap_context_set_ssl(ctx, (unsigned char *)ec_priv_key,
					ec_priv_key_length,
					(unsigned char *)ec_pub_key_x, size,
					(unsigned char *)ec_pub_key_y, size);

		if (pub_key_pem)
			free(pub_key_pem);
		if (ec_pub_key)
			free(ec_pub_key);
		if (ec_priv_key)
			free(ec_priv_key);
		if (ec_pub_key_x)
			free(ec_pub_key_x);
		if (ec_pub_key_y)
			free(ec_pub_key_y);
		if (pub_key_der)
			free(pub_key_der);
		if (priv_key_der)
			free(priv_key_der);
	}

	if (!ctx) {
		log_err("Cannot create CoAP server context");
		ret = E_COAP_ERROR;
		goto exit;
	}

	interface->ctx = ctx;
	*server = (artik_coap_handle)ctx;
	interface->client = false;

	node = (coap_node *)artik_list_add(&requested_node,
			(ARTIK_LIST_HANDLE)*server, sizeof(coap_node));

	if (!node) {
		ret = E_NO_MEM;
		goto exit;
	}

	memset(&node->interface, 0, sizeof(node->interface));

	memcpy(&interface->config, config, sizeof(interface->config));

	interface->enable_verify_psk = config->enable_verify_psk;

	memcpy(&node->interface, interface, sizeof(node->interface));

exit:
	if (interface)
		free(interface);

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

	if (node->interface.optlist)
		coap_delete_list(node->interface.optlist);

	if (node->interface.ctx)
		coap_free_context(node->interface.ctx);

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
	artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");
	artik_coap_config *config = NULL;
	coap_context_t *ctx = NULL;
	bool enable_dtls;
	char addr_str[NI_MAXHOST] = "::";
	char port_str[NI_MAXSERV] = "5683";

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
			enable_dtls ? COAP_PROTO_DTLS : COAP_PROTO_UDP,
			addr_str,
			port_str
		)) {
		log_err("Fail to create endpoint");
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

	if (loop->add_idle_callback(&node->interface.coap_data->loop_process_id,
		server_loop_handler, node->interface.coap_data) != S_OK) {
		log_err("Fail to add idle callback");
		ret = E_COAP_ERROR;
		goto exit;
	}

	node->interface.started = true;

exit:
	artik_release_api_module(loop);

	return ret;
}

artik_error os_coap_stop_server(artik_coap_handle server)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)server);
	artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");
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

	data = node->interface.coap_data;

	if (!data) {
		log_err("No available data");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (loop->remove_idle_callback(data->loop_process_id) != S_OK) {
		log_err("Fail to remove callback");
		ret = E_COAP_ERROR;
		goto exit;
	}

	node->interface.started = false;

	if (data)
		free(data);

exit:
	artik_release_api_module(loop);

	return ret;
}

artik_error os_coap_send_message(artik_coap_handle handle,
				const char *path,
				artik_coap_msg *msg)
{
	artik_error ret = S_OK;
	coap_node *node = (coap_node *)artik_list_get_by_handle(
		requested_node, (ARTIK_LIST_HANDLE)handle);
	coap_pdu_t  *pdu;
	unsigned char _buf[BUFSIZE];
	unsigned char *buf = _buf;
	size_t buflen;
	int res;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!node->interface.client) {
		log_err("This method is only for client handle.");
		ret = E_NOT_SUPPORTED;
		goto exit;
	}

	if (!node->interface.session) {
		log_err("No session exists.");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!msg) {
		ret = E_BAD_ARGS;
		goto exit;
	}

	if (node->interface.optlist) {
		coap_delete_list(node->interface.optlist);
		node->interface.optlist = NULL;
	}

	if (msg->options && msg->num_options > 0) {
		if (!add_options(&node->interface.optlist, msg->options,
				msg->num_options, true)) {
			log_err("Options not well defined");
			ret = E_COAP_ERROR;
			goto exit;
		}
	}

	if (path) {
		buflen = BUFSIZE;
		buf = _buf;
		res = coap_split_path((const unsigned char *)path, strlen(path),
				buf, &buflen);

		while (res--) {
			coap_insert(
				&node->interface.optlist,
				new_option_node(COAP_OPTION_URI_PATH,
					COAP_OPT_LENGTH(buf),
					COAP_OPT_VALUE(buf))
				);
			buf += COAP_OPT_SIZE(buf);
		}

		const char sep = '?';

		const char *query = strchr(path, sep);

		if (query) {
			query++;

			buflen = BUFSIZE;
			buf = _buf;
			res = coap_split_query((const unsigned char *)query,
				strlen(query), buf, &buflen);

			while (res--) {
				coap_insert(
					&node->interface.optlist,
					new_option_node(COAP_OPTION_URI_QUERY,
						COAP_OPT_LENGTH(buf),
						COAP_OPT_VALUE(buf))
					);
				buf += COAP_OPT_SIZE(buf);
			}
		}

	}

	pdu = coap_new_request(node->interface.ctx,
			node->interface.session, msg->msg_type, msg->code,
			&msg->msg_id, &node->interface.optlist, msg->token,
			msg->token_len, msg->data, msg->data_len);

	if (!pdu) {
		log_err("Fail to create new CoAP request");
		ret = E_COAP_ERROR;
		goto exit;
	}

	node->interface.method = msg->code;
	node->interface.msg_type = msg->msg_type;

	if (coap_send(node->interface.session, pdu) == COAP_INVALID_TID) {
		log_err("Fail to send CoAP message");
		ret = E_COAP_ERROR;
	}

exit:
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
	coap_pdu_t  *pdu;
	unsigned char _buf[BUFSIZE];
	unsigned char *buf = _buf;
	unsigned short msg_id;
	size_t buflen;
	int res;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!node->interface.client) {
		log_err("This method is only for client handle.");
		ret = E_NOT_SUPPORTED;
		goto exit;
	}

	if (!node->interface.session) {
		log_err("No session exists.");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!path) {
		ret = E_BAD_ARGS;
		goto exit;
	}

	if (node->interface.optlist) {
		coap_delete_list(node->interface.optlist);
		node->interface.optlist = NULL;
	}

	if (options && num_options > 0) {
		if (!add_options(&node->interface.optlist, options,
				num_options, false)) {
			log_err("Options not well defined");
			ret = E_COAP_ERROR;
			goto exit;
		}
	}

	coap_insert(&node->interface.optlist,
		new_option_node(COAP_OPTION_SUBSCRIPTION, 0, NULL));

	if (path) {
		buflen = BUFSIZE;
		buf = _buf;
		res = coap_split_path((const unsigned char *)path, strlen(path),
				buf, &buflen);

		while (res--) {
			coap_insert(
				&node->interface.optlist,
				new_option_node(COAP_OPTION_URI_PATH,
					COAP_OPT_LENGTH(buf),
					COAP_OPT_VALUE(buf))
				);
			buf += COAP_OPT_SIZE(buf);
		}

		const char sep = '?';

		const char *query = strchr(path, sep);

		if (query) {
			query++;

			buflen = BUFSIZE;
			buf = _buf;
			res = coap_split_query((const unsigned char *)query,
				strlen(query), buf, &buflen);

			while (res--) {
				coap_insert(
					&node->interface.optlist,
					new_option_node(COAP_OPTION_URI_QUERY,
						COAP_OPT_LENGTH(buf),
						COAP_OPT_VALUE(buf))
					);
				buf += COAP_OPT_SIZE(buf);
			}
		}
	}

	pdu = coap_new_request(node->interface.ctx,
			node->interface.session, msg_type, COAP_REQUEST_GET,
			&msg_id, &node->interface.optlist, token, token_len,
			NULL, 0);

	if (!pdu) {
		log_err("Fail to create new CoAP request");
		ret = E_COAP_ERROR;
		goto exit;
	}

	node->interface.method = COAP_REQUEST_GET;
	node->interface.msg_type = msg_type;

	if (coap_send(node->interface.session, pdu) == COAP_INVALID_TID) {
		log_err("Fail to send CoAP message");
		ret = E_COAP_ERROR;
	}

exit:
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
	coap_pdu_t  *pdu;
	unsigned char _buf[BUFSIZE];
	unsigned char *buf = _buf;
	unsigned short msg_id;
	size_t buflen;
	int res;

	log_dbg("");

	if (!node || !node->interface.ctx) {
		log_err("No CoAP context exists for this handle");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!node->interface.client) {
		log_err("This method is only for client handle.");
		ret = E_NOT_SUPPORTED;
		goto exit;
	}

	if (!node->interface.session) {
		log_err("No session exists.");
		ret = E_COAP_ERROR;
		goto exit;
	}

	if (!path) {
		ret = E_BAD_ARGS;
		goto exit;
	}

	if (node->interface.optlist) {
		coap_delete_list(node->interface.optlist);
		node->interface.optlist = NULL;
	}

	coap_insert(&node->interface.optlist, new_option_node(COAP_OPTION_OBSERVE,
		coap_encode_var_bytes(buf, COAP_OBSERVE_CANCEL),
		buf));

	log_dbg("");

	if (path) {
		buflen = BUFSIZE;
		buf = _buf;
		res = coap_split_path((const unsigned char *)path, strlen(path),
				buf, &buflen);

		while (res--) {
			coap_insert(
				&node->interface.optlist,
				new_option_node(COAP_OPTION_URI_PATH,
					COAP_OPT_LENGTH(buf),
					COAP_OPT_VALUE(buf))
				);
			buf += COAP_OPT_SIZE(buf);
		}

		const char sep = '?';

		const char *query = strchr(path, sep);

		if (query) {
			query++;

			buflen = BUFSIZE;
			buf = _buf;
			res = coap_split_query((const unsigned char *)query,
				strlen(query), buf, &buflen);

			while (res--) {
				coap_insert(
					&node->interface.optlist,
					new_option_node(COAP_OPTION_URI_QUERY,
						COAP_OPT_LENGTH(buf),
						COAP_OPT_VALUE(buf))
					);
				buf += COAP_OPT_SIZE(buf);
			}
		}
	}

	log_dbg("");

	pdu = coap_new_request(node->interface.ctx,
			node->interface.session, COAP_MESSAGE_CON, COAP_REQUEST_GET,
			&msg_id, &node->interface.optlist, token, token_len,
			NULL, 0);

	if (!pdu) {
		log_err("Fail to create new CoAP request");
		ret = E_COAP_ERROR;
		goto exit;
	}

	log_dbg("");

	node->interface.method = COAP_REQUEST_GET;
	node->interface.msg_type = COAP_MESSAGE_CON;

	if (coap_send(node->interface.session, pdu) == COAP_INVALID_TID) {
		log_err("Fail to send CoAP message");
		ret = E_COAP_ERROR;
	}

exit:
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

	if (!path) {
		log_err("Missing path for resource.");
		ret = E_COAP_ERROR;
		goto exit;
	}

	artik_list *resources_list = node->interface.requested_resource_node;

	if (!resources_list) {
		log_err("No created resources");
		ret = E_COAP_ERROR;
		goto exit;
	}

	for (int i = 0; i < artik_list_size(resources_list); i++) {
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
		log_err("This method is only for server handle.");
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
