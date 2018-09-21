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

#ifndef COAP_H_
#define COAP_H_

#include <stdlib.h>
#include <string.h>

#include <er-coap-13.h>

#include <artik_ssl.h>
#include <artik_coap.h>

#include "coap_session.h"
#include "coap_resource.h"
#include "hashkey.h"

#define COAP_DEFAULT_PORT	5683
#define COAPS_DEFAULT_PORT	5684

#define COAP_DEFAULT_PDU_SIZE	1152

#define COAP_DEFAULT_VERSION	1

#define COAP_RESPONSE_CLASS(C) (((C) >> 5) & 0xFF)

#define COAP_RESPONSE_CODE(N) (((N)/100 << 5) | (N)%100)

#define COAP_DEFAULT_MAX_RETRANSMIT  4 /* see RFC 7252, Section 4.8 */

#define COAP_MESSAGE_RST 3

#define COAP_MESSAGE_IS_EMPTY(MSG)    ((MSG)->code == 0)
#define COAP_MESSAGE_IS_REQUEST(MSG)  (!COAP_MESSAGE_IS_EMPTY(MSG)  \
					&& ((MSG)->code < 32))
#define COAP_MESSAGE_IS_RESPONSE(MSG) ((MSG)->code >= 64)

#define COAP_DEFAULT_URI_WELLKNOWN ".well-known/core"

#define COAP_OPTION_NORESPONSE    258 /* N, uint, 0--1 B, 0 */

struct coap_session_t;
struct coap_context_t;
struct coap_queue_t;
struct coap_resource_t;

typedef struct coap_queue_t {
	struct coap_queue_t *next;
	uint32_t t;
	unsigned char retransmit_cnt;
	unsigned int timeout;
	struct coap_session_t *session;
	int id;
	coap_packet_t *packet;
} coap_queue_t;

typedef void (*coap_response_handler_t)(struct coap_context_t *ctx,
					coap_session_t *session,
					coap_packet_t *sent,
					coap_packet_t *received,
					const int id);

typedef void (*coap_nack_handler_t)(struct coap_context_t *ctx,
					coap_session_t *session,
					coap_packet_t *sent,
					coap_nack_reason_t reason,
					const int id);

typedef struct coap_context_t {
	struct coap_resource_t *resources;
	uint32_t sendqueue_basetime;
	coap_queue_t *sendqueue;
	coap_endpoint_t *endpoint;
	struct coap_session_t *sessions;
	unsigned int session_timeout;

	unsigned short message_id;
	unsigned int observe;

	coap_response_handler_t response_handler;
	coap_nack_handler_t nack_handler;

	int (*network_send)(coap_socket_t *sock, const coap_session_t *session,
					const uint8_t *data, size_t datalen);
	int (*network_read)(coap_socket_t *sock, coap_data_t *packet);

	size_t (*get_client_psk)(const coap_session_t *session,
					const uint8_t *hint,
					size_t hint_len, uint8_t *identity,
					size_t *identity_len,
					size_t max_identity_len,
					uint8_t *psk,
					size_t max_psk_len);
	size_t (*get_server_psk)(const coap_session_t *session,
					const uint8_t *identity,
					size_t identity_len,
					uint8_t *psk,
					size_t max_psk_len);
	size_t (*get_server_hint)(const coap_session_t *session,
					uint8_t *hint,
					size_t max_hint_len);

	size_t (*get_context_priv_key)(const coap_session_t *session,
					unsigned char **priv_key);
	size_t (*get_context_pub_key_x)(const coap_session_t *session,
					unsigned char **pub_key_x);
	size_t (*get_context_pub_key_y)(const coap_session_t *session,
					unsigned char **pub_key_y);

	void *dtls_context;
	uint8_t *psk_hint;
	size_t psk_hint_len;
	uint8_t *psk_key;
	size_t psk_key_len;

	unsigned char *priv_key;
	size_t priv_key_len;
	unsigned char *pub_key_x;
	size_t pub_key_x_len;
	unsigned char *pub_key_y;
	size_t pub_key_y_len;

	void *verify_data;
	int (*verify_psk_callback)(const unsigned char *identity,
				unsigned char **key,
				int key_len,
				void *user_data);

	unsigned int max_idle_sessions;
} coap_context_t;

void coap_startup(void);

int artik_coap_insert_node(coap_queue_t **queue, coap_queue_t *node);

int artik_coap_delete_node(coap_queue_t *node);

void artik_coap_delete_all(coap_queue_t *queue);

coap_queue_t *artik_coap_new_node(void);

int artik_coap_remove_from_queue(
		coap_queue_t **queue,
		struct coap_session_t *session,
		int id,
		coap_queue_t **node);

coap_context_t *artik_coap_new_context(artik_ssl_config *ssl, artik_coap_psk_param *psk);

void artik_coap_free_context(coap_context_t *context);

uint16_t coap_new_message_id(coap_session_t *session);

coap_queue_t *artik_coap_peek_next(coap_context_t *context);

coap_queue_t *artik_coap_pop_next(coap_context_t *context);

int is_wkc(coap_key_t k);

void coap_context_set_psk(coap_context_t *ctx,
		const char *hint, const uint8_t *key, size_t key_len);

void coap_context_set_ssl(coap_context_t *ctx,
		const unsigned char *priv_key, size_t priv_key_len,
		const unsigned char *pub_key_x, size_t pub_key_x_len,
		const unsigned char *pub_key_y, size_t pub_key_y_len);

coap_packet_t *artik_coap_new_error_response(coap_packet_t *request, unsigned char code);

unsigned int coap_write(coap_context_t *ctx,
		coap_socket_t *sockets[],
		unsigned int max_sockets,
		unsigned int *num_sockets,
		uint32_t now);

int artik_coap_send(coap_session_t *session, coap_packet_t *packet);

void artik_coap_read(coap_context_t *ctx, uint32_t now);

int artik_coap_retransmit(struct coap_context_t *context, struct coap_queue_t *node);

unsigned int calc_timeout(unsigned char r);

void artik_coap_dispatch(coap_context_t *context, coap_queue_t *rcvd, bool unknown_option);

void coap_cancel_session_messages(coap_context_t *context,
		coap_session_t *session,
		coap_nack_reason_t reason);

int coap_cancel(coap_context_t *context, const coap_queue_t *sent);

coap_packet_t *coap_wellknown_response(coap_context_t *context,
		coap_session_t *session, coap_packet_t *request);

void artik_handle_request(coap_context_t *context, coap_queue_t *node);

void handle_response(coap_context_t *context, coap_queue_t *sent,
		coap_queue_t *rcvd);

int artik_coap_send_ack(coap_session_t *session, coap_packet_t *request);

void artik_coap_cancel_all_messages(coap_context_t *context, coap_session_t *session,
		const unsigned char *token, size_t token_length);

int artik_coap_send_message_type(coap_session_t *session, coap_packet_t *request,
		unsigned char type);

void coap_register_response_handler(coap_context_t *context,
		coap_response_handler_t handler);

void coap_register_nack_handler(coap_context_t *context,
		coap_nack_handler_t handler);

int coap_handle_message(coap_context_t *ctx, coap_session_t *session,
		uint8_t *msg, size_t msg_len);

int coap_wait_ack(coap_context_t *context, coap_session_t *session,
		coap_queue_t *node);

#endif /* COAP_H_ */
