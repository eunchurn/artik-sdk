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

#ifndef COAP_SESSION_H_
#define COAP_SESSION_H_

#include <stdlib.h>
#include <string.h>

#include <er-coap-13.h>

#include "coap_socket.h"
#include "coap_address.h"

#define COAP_DEFAULT_SESSION_TIMEOUT 300

#define COAP_SESSION_TYPE_CLIENT 1  /**< client-side */
#define COAP_SESSION_TYPE_SERVER 2  /**< server-side */
#define COAP_SESSION_TYPE_HELLO  3  /**< server-side ephemeral session for responding to a client hello */

#define COAP_SESSION_STATE_NONE		0
#define COAP_SESSION_STATE_CONNECTING	1
#define COAP_SESSION_STATE_HANDSHAKE	2
#define COAP_SESSION_STATE_ESTABLISHED	3

struct coap_context_t;
struct coap_endpoint_t;
struct coap_queue_t;

typedef struct {
	unsigned char *priv_key;
	size_t priv_key_len;
	unsigned char *pub_key_x;
	size_t pub_key_x_len;
	unsigned char *pub_key_y;
	size_t pub_key_y_len;
} coap_ecdsa_keys;

typedef struct coap_session_t {
	struct coap_session_t *next;
	coap_protocol_t proto;
	uint8_t state;
	struct coap_context_t *context;
	struct coap_endpoint_t *endpoint;
	void *tls;
	uint16_t tx_mid;
	struct coap_queue_t *sendqueue;
	uint32_t last_rx_tx;
	uint8_t type;
	uint8_t ref;
	uint16_t mtu;
	uint16_t tls_overhead;
	int ifindex;
	coap_address_t remote_addr;
	coap_address_t local_addr;
	coap_socket_t sock;
	uint8_t *psk_identity;
	size_t psk_identity_len;
	uint8_t *psk_key;
	size_t psk_key_len;
	coap_ecdsa_keys ecdsa_keys;
	uint8_t newly_created;
} coap_session_t;

typedef struct coap_endpoint_t {
	struct coap_endpoint_t *next;
	struct coap_context_t *context;
	coap_protocol_t proto;
	uint16_t default_mtu;
	coap_socket_t sock;
	coap_address_t bind_addr;
	coap_session_t *sessions;
	coap_session_t hello;
} coap_endpoint_t;

int coap_session_send(
		coap_session_t *session,
		const uint8_t *data,
		size_t datalen);

int coap_session_delay_packet(
		coap_session_t *session,
		coap_packet_t *packet,
		struct coap_queue_t *node);

void coap_session_connected(coap_session_t *session);

void coap_session_disconnected(coap_session_t *session,
		coap_nack_reason_t reason);

coap_session_t *coap_session_reference(coap_session_t *session);

void coap_session_release(coap_session_t *session);

coap_session_t *coap_make_session(
		coap_protocol_t proto,
		uint8_t type,
		const coap_address_t *local,
		const coap_address_t *remote,
		int ifindex,
		struct coap_context_t *context,
		struct coap_endpoint_t *endpoint);

coap_session_t *coap_endpoint_get_session(
		coap_endpoint_t *endpoint,
		const coap_data_t *packet,
		uint32_t now);

void coap_session_free(coap_session_t *session);

void coap_session_reset(coap_session_t *session);

coap_session_t *coap_endpoint_new_dtls_session(
		coap_endpoint_t *endpoint,
		coap_data_t *packet,
		uint32_t now);

coap_session_t *coap_session_create_client(
		struct coap_context_t *ctx,
		const coap_address_t *local_if,
		const coap_address_t *server,
		coap_protocol_t proto);

coap_session_t *coap_new_client_session(
		struct coap_context_t *ctx,
		const coap_address_t *local_if,
		const coap_address_t *server,
		coap_protocol_t proto);

coap_session_t *coap_new_client_session_psk(
		struct coap_context_t *ctx,
		const coap_address_t *local_if,
		const coap_address_t *server,
		coap_protocol_t proto,
		const char *identity,
		const uint8_t *key,
		unsigned int key_len);

coap_session_t *coap_new_client_session_ssl(
		struct coap_context_t *ctx,
		const coap_address_t *local_if,
		const coap_address_t *server,
		coap_protocol_t proto,
		const coap_ecdsa_keys *ecdsa_keys);

coap_endpoint_t *coap_new_endpoint(struct coap_context_t *context,
		const coap_address_t *listen_addr,
		coap_protocol_t proto);

void coap_free_endpoint(coap_endpoint_t *ep);

#endif /* COAP_SESSION_H_ */
