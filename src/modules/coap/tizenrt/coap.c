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

#include "coap.h"
#include "coap_uri.h"
#include "coap_time.h"
#include "coap_session.h"
#include "coap_dtls.h"
#include "coap_block.h"
#include "coap_resource.h"
#include "coap_mem.h"
#include "prng.h"
#include "hashkey.h"

#include "utlist.h"

#include <artik_log.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <limits.h>
#include <time.h>

#include <tls/easy_tls.h>

#define FRAC_BITS			6
#define MAX_BITS			8
#define COAP_DEFAULT_ACK_TIMEOUT	2
#define COAP_DEFAULT_ACK_RANDOM_FACTOR  1.5

#define NI_MAXHOST			1025
#define NI_MAXSERV			32

#define Q(frac, fval) ((unsigned short)(((1 << (frac)) * (fval))))

#define ACK_RANDOM_FACTOR Q(FRAC_BITS, COAP_DEFAULT_ACK_RANDOM_FACTOR)
#define ACK_TIMEOUT Q(FRAC_BITS, COAP_DEFAULT_ACK_TIMEOUT)

#define SZX_TO_BYTES(SZX) ((size_t)(1 << ((SZX) + 4)))

#define WANT_WKC(Packet, Key) \
	(((Packet)->code == COAP_GET) && is_wkc(Key))

static int coap_started = 0;

int flsll(long long mask)
{
	int bit;

	if (mask == 0)
		return 0;

	for (bit = 1; mask != 1; bit++)
		mask = (unsigned long long)mask >> 1;

	return bit;
}

void coap_startup(void)
{
	if (coap_started)
		return;
	coap_clock_init();
	prng_init(time(NULL));
}

static int coap_send_packet(coap_session_t *session, coap_packet_t *packet,
			coap_queue_t *node)
{
	int bytes_written;
	uint8_t *pktBuffer;
	size_t pktBufferLen, allocLen;
	multi_option_t *optP;
	char *uri_path = NULL, *uri_query = NULL, *location_path = NULL;
	int len = 0;
	int i = 0;

	if (packet->uri_path)
		uri_path = (char *)packet->uri_path->data;

	if (packet->location_path)
		location_path = (char *)packet->location_path->data;

	if (packet->uri_query)
		len++;

	for (optP = packet->uri_query; optP != NULL; optP = optP->next) {
		if (len > 1)
			len++;
		len += optP->len;
	}

	if (packet->uri_query) {

		if (len == 0) {
			log_err("Length null");
			return -1;
		}

		uri_query = (char *)coap_malloc(len + 1);

		if (!uri_query) {
			log_err("Memory problem");
			return -1;
		}

		memset(uri_query, 0, len + 1);

		uri_query[len] = 0;

		uri_query[i++] = '?';
	}


	for (optP = packet->uri_query; optP != NULL && i < len - 1; optP = optP->next) {
		int j;

		if (i > 1)
			uri_query[i++] = '&';

		for (j = 0; j < optP->len && i < len; j++, i++)
			uri_query[i] = optP->data[j];
	}

	allocLen = coap_serialize_get_size((void *)packet);

	pktBuffer = (uint8_t *)coap_malloc(allocLen*sizeof(uint8_t));

	pktBufferLen = coap_serialize_message((void *)packet, pktBuffer);

	if (uri_path)
		coap_set_header_uri_path((void *)packet, uri_path);

	if (uri_query)
		coap_set_header_uri_query((void *)packet, uri_query);

	if (location_path)
		coap_set_header_location_path((void *)packet, location_path);

	if (coap_is_mcast(&session->local_addr) &&
			COAP_RESPONSE_CLASS(packet->code) > 2)
		return -2;

	if (session->state == COAP_SESSION_STATE_NONE) {
		if (session->proto == COAP_UDP_DTLS && !session->tls) {
			log_dbg("");
			session->tls = coap_dtls_new_client_session(session);
			if (session->tls) {
				session->state = COAP_SESSION_STATE_ESTABLISHED;
				return coap_session_delay_packet(session,
						packet, node);
			}
		}
		return -1;
	}

	if (session->state != COAP_SESSION_STATE_ESTABLISHED)
		return coap_session_delay_packet(session, packet, node);

	log_dbg("");

	if (session->proto == COAP_UDP_DTLS)
		bytes_written = coap_dtls_send(session, pktBuffer, pktBufferLen);
	else
		bytes_written = coap_session_send(session, pktBuffer, pktBufferLen);

	if (pktBuffer)
		coap_free(pktBuffer);

	if (uri_query)
		coap_free(uri_query);

	return bytes_written;
}

int artik_coap_insert_node(coap_queue_t **queue, coap_queue_t *node)
{
	coap_queue_t *p, *q;

	if (!queue || !node)
		return 0;

	if (!*queue) {
		*queue = node;
		return 1;
	}

	q = *queue;

	if (node->t < q->t) {
		node->next = q;
		*queue = node;
		q->t -= node->t;
		return 1;
	}

	do {
		node->t -= q->t;
		p = q;
		q = q->next;
	} while (q && q->t <= node->t);

	/* insert new item */
	if (q)
		q->t -= node->t;

	node->next = q;
	p->next = node;

	return 1;
}

int artik_coap_delete_node(coap_queue_t *node)
{
	if (!node)
		return 0;

	if (node->packet) {
		coap_free_header(node->packet);
		coap_free(node->packet);
		node->packet = NULL;
	}

	if (node->session)
		coap_session_release(node->session);

	coap_free(node);
	node = NULL;

	return 1;
}

void artik_coap_delete_all(coap_queue_t *queue)
{
	if (!queue)
		return;

	artik_coap_delete_all(queue->next);
	artik_coap_delete_node(queue);
}

coap_queue_t *artik_coap_new_node(void)
{
	coap_queue_t *node;

	node = (coap_queue_t *)coap_malloc(sizeof(coap_queue_t));

	if (!node)
		return NULL;

	memset(node, 0, sizeof(*node));

	return node;
}

int artik_coap_remove_from_queue(
		coap_queue_t **queue,
		coap_session_t *session,
		int id,
		coap_queue_t **node)
{
	coap_queue_t *p, *q;

	if (!queue || !*queue)
		return 0;

	if (session == (*queue)->session && id == (*queue)->id) {
		*node = *queue;
		*queue = (*queue)->next;

		if (*queue)
			(*queue)->t += (*node)->t;

		(*node)->next = NULL;

		return 1;
	}

	q = *queue;

	do {
		p = q;
		q = q->next;
	} while (q && session != q->session && id != q->id);

	if (q) {
		p->next = q->next;

		if (p->next)
			p->next->t += q->t;

		q->next = NULL;
		*node = q;

		return 1;
	}

	return 0;
}

coap_context_t *artik_coap_new_context(artik_ssl_config *ssl, artik_coap_psk_param *psk)
{
	coap_context_t *c;

	coap_startup();

	c = (coap_context_t *)coap_malloc(sizeof(coap_context_t));

	if (!c)
		return NULL;

	memset(c, 0, sizeof(coap_context_t));

	if (ssl || psk) {
		c->dtls_context = (void *)coap_dtls_new_context(ssl, psk);

		if (!c->dtls_context) {
			log_dbg("coap_init: no DTLS context available");
			artik_coap_free_context(c);
			return NULL;
		}
	}

	prng((unsigned char *)&c->message_id, sizeof(unsigned short));

	c->network_send = coap_network_send;
	c->network_read = coap_network_read;

	return c;
}

void artik_coap_free_context(coap_context_t *context)
{
	coap_endpoint_t *ep, *tmp;

	if (!context)
		return;

	log_dbg("");

	artik_coap_delete_all(context->sendqueue);

	log_dbg("");

	coap_delete_all_resources(context);

	log_dbg("");

	if (context->dtls_context)
		coap_dtls_free_context(context->dtls_context);

	log_dbg("");

	LL_FOREACH_SAFE(context->endpoint, ep, tmp) {
		coap_free_endpoint(ep);
	}

	log_dbg("");

	if (context->psk_hint)
		coap_free(context->psk_hint);

	log_dbg("");

	if (context->psk_key)
		coap_free(context->psk_key);

	if (context->priv_key)
		coap_free(context->priv_key);

	if (context->pub_key_x)
		coap_free(context->pub_key_x);

	if (context->pub_key_y)
		coap_free(context->pub_key_y);

	log_dbg("");

	coap_free(context);

	context = NULL;
}

uint16_t coap_new_message_id(coap_session_t *session)
{
	session->tx_mid++;
	return htons(session->tx_mid);
}

coap_queue_t *artik_coap_peek_next(coap_context_t *context)
{
	if (!context || !context->sendqueue)
		return NULL;

	return context->sendqueue;
}

coap_queue_t *artik_coap_pop_next(coap_context_t *context)
{
	coap_queue_t *next;

	if (!context || !context->sendqueue)
		return NULL;

	next = context->sendqueue;
	context->sendqueue = context->sendqueue->next;

	if (context->sendqueue)
		context->sendqueue->t += next->t;

	next->next = NULL;

	return next;
}

int is_wkc(coap_key_t k)
{
	static coap_key_t wkc;
	static unsigned char _initialized = 0;

	if (!_initialized) {
		_initialized = artik_coap_hash_path((unsigned char *)
			COAP_DEFAULT_URI_WELLKNOWN,
			sizeof(COAP_DEFAULT_URI_WELLKNOWN) - 1, wkc);
	}
	return memcmp(k, wkc, sizeof(coap_key_t)) == 0;
}

void coap_context_set_psk(coap_context_t *ctx,
		const char *hint, const uint8_t *key, size_t key_len)
{
	if (ctx->psk_hint)
		coap_free(ctx->psk_hint);
	ctx->psk_hint = NULL;
	ctx->psk_hint_len = 0;

	if (hint) {
		size_t hint_len = strlen(hint);

		ctx->psk_hint = (uint8_t *)coap_malloc(hint_len);

		if (ctx->psk_hint) {
			memcpy(ctx->psk_hint, hint, hint_len);
			ctx->psk_hint_len = hint_len;
		} else
			log_err("No memory to store PSK hint");
	}

	if (ctx->psk_key)
		coap_free(ctx->psk_key);
	ctx->psk_key = NULL;
	ctx->psk_key_len = 0;

	if (key && key_len > 0) {
		ctx->psk_key = (uint8_t *)coap_malloc(key_len);
		if (ctx->psk_key) {
			memcpy(ctx->psk_key, key, key_len);
			ctx->psk_key_len = key_len;
		} else
			log_err("No memory to store PSK key");
	}
}

void coap_context_set_ssl(coap_context_t *ctx,
		const unsigned char *priv_key, size_t priv_key_len,
		const unsigned char *pub_key_x, size_t pub_key_x_len,
		const unsigned char *pub_key_y, size_t pub_key_y_len)
{
	if (ctx->priv_key)
		coap_free(ctx->priv_key);
	ctx->priv_key = NULL;
	ctx->priv_key_len = 0;

	if (priv_key && priv_key_len > 0) {
		ctx->priv_key = (unsigned char *)coap_malloc(priv_key_len);

		if (ctx->priv_key) {
			memcpy(ctx->priv_key, priv_key, priv_key_len);
			ctx->priv_key_len = priv_key_len;
		} else
			log_err("No memory to store EC private key");
	}

	if (pub_key_x && pub_key_x_len > 0) {
		ctx->pub_key_x = (unsigned char *)coap_malloc(pub_key_x_len);

		if (ctx->pub_key_x) {
			memcpy(ctx->pub_key_x, pub_key_x, pub_key_x_len);
			ctx->pub_key_x_len = pub_key_x_len;
		} else
			log_err("No memory to store EC X public key");
	}

	if (pub_key_y && pub_key_y_len > 0) {
		ctx->pub_key_y = (unsigned char *)coap_malloc(pub_key_y_len);

		if (ctx->pub_key_y) {
			memcpy(ctx->pub_key_y, pub_key_y, pub_key_y_len);
			ctx->pub_key_y_len = pub_key_y_len;
		} else
			log_err("No memory to store EC Y public key");
	}
}

typedef struct {
	unsigned char code;
	char *phrase;
} error_desc_t;

error_desc_t tizenrt_coap_error[] = {
	{ COAP_RESPONSE_CODE(201), "Created" },
	{ COAP_RESPONSE_CODE(202), "Deleted" },
	{ COAP_RESPONSE_CODE(203), "Valid" },
	{ COAP_RESPONSE_CODE(204), "Changed" },
	{ COAP_RESPONSE_CODE(205), "Content" },
	{ COAP_RESPONSE_CODE(231), "Continue" },
	{ COAP_RESPONSE_CODE(400), "Bad Request" },
	{ COAP_RESPONSE_CODE(401), "Unauthorized" },
	{ COAP_RESPONSE_CODE(402), "Bad Option" },
	{ COAP_RESPONSE_CODE(403), "Forbidden" },
	{ COAP_RESPONSE_CODE(404), "Not Found" },
	{ COAP_RESPONSE_CODE(405), "Method Not Allowed" },
	{ COAP_RESPONSE_CODE(406), "Not Acceptable" },
	{ COAP_RESPONSE_CODE(408), "Request Entity Incomplete" },
	{ COAP_RESPONSE_CODE(412), "Precondition Failed" },
	{ COAP_RESPONSE_CODE(413), "Request Entity Too Large" },
	{ COAP_RESPONSE_CODE(415), "Unsupported Content-Format" },
	{ COAP_RESPONSE_CODE(500), "Internal Server Error" },
	{ COAP_RESPONSE_CODE(501), "Not Implemented" },
	{ COAP_RESPONSE_CODE(502), "Bad Gateway" },
	{ COAP_RESPONSE_CODE(503), "Service Unavailable" },
	{ COAP_RESPONSE_CODE(504), "Gateway Timeout" },
	{ COAP_RESPONSE_CODE(505), "Proxying Not Supported" },
	{ 0, NULL }
};

char *artik_coap_response_phrase(unsigned char code)
{
	int i;

	for (i = 0; tizenrt_coap_error[i].code; ++i) {
		if (tizenrt_coap_error[i].code == code)
			return tizenrt_coap_error[i].phrase;
	}

	return NULL;
}

coap_packet_t *artik_coap_new_error_response(coap_packet_t *request, unsigned char code)
{
	coap_packet_t *response;
	coap_message_type_t type;

	const char *phrase = artik_coap_response_phrase(code);

	type = request->type == COAP_TYPE_CON ? COAP_TYPE_ACK : COAP_TYPE_NON;

	response = (coap_packet_t *)coap_malloc(sizeof(coap_packet_t));

	if (response) {
		coap_init_message((void *)response, request->protocol,
			type, code, request->mid);

		log_dbg("");

		if (request->token_len > 0)
			coap_set_header_token((void *)response,
				request->token,
				request->token_len);

		if (phrase)
			coap_set_payload((void *)response, (void *)phrase,
				(size_t)strlen(phrase));
	}

	return response;
}

static int coap_handle_message_for_proto(coap_context_t *ctx,
				coap_session_t *session, coap_data_t *packet)
{
	uint8_t *data;
	size_t data_len;
	int result = -1;

	coap_packet_get_memmapped(packet, &data, &data_len);

	result = coap_handle_message(ctx, session, data, data_len);

	return result;
}

static int coap_read_session(coap_context_t *ctx, coap_session_t *session,
				uint32_t now)
{
	int bytes_read = -1;
	int result = -1;

	log_dbg("");

	coap_data_t s_packet;
	coap_data_t *packet = &s_packet;

	if (packet) {
		coap_address_copy(&packet->src, &session->remote_addr);
		coap_address_copy(&packet->dst, &session->local_addr);
		if (session->proto == COAP_UDP_DTLS)
			bytes_read = coap_dtls_receive(session, packet->payload,
				COAP_RXBUFFER_SIZE);
		else
			bytes_read = ctx->network_read(&session->sock, packet);
	}

	if (bytes_read < 0) {
		if (bytes_read == -2)
			coap_session_reset(session);
		else
			log_err("read error");
	} else if (bytes_read > 0) {
		session->last_rx_tx = now;
		coap_data_set_addr(packet, &session->remote_addr,
				&session->local_addr);
		if (session->proto == COAP_UDP_DTLS)
			packet->length = bytes_read;
		result = coap_handle_message_for_proto(ctx, session, packet);
	}

	return result;
}

static int coap_read_endpoint(coap_context_t *ctx, coap_endpoint_t *endpoint,
				uint32_t now)
{
	int bytes_read = -1;
	int result = -1;

	coap_data_t s_packet;
	coap_data_t *packet = &s_packet;
	uint8_t family = 0;
	socklen_t n;
	int ret;

	coap_session_t *session = NULL;

	log_dbg("");

	if (packet) {
		coap_address_init(&packet->src);
		coap_address_copy(&packet->dst, &endpoint->bind_addr);

		if (endpoint->proto == COAP_UDP) {
			log_dbg("");
			bytes_read = ctx->network_read(&endpoint->sock, packet);
		} else if (endpoint->proto == COAP_UDP_DTLS) {
			unsigned char ip[16];
			unsigned int ip_len;
			int fd = endpoint->sock.fd;
			struct sockaddr_storage client_addr;

			n = (socklen_t)sizeof(client_addr);

			if ((endpoint->sock.flags & COAP_SOCKET_HAS_DATA) == 0)
				return -1;

			endpoint->sock.flags &= ~COAP_SOCKET_HAS_DATA;

			ret = (int)recvfrom(fd, NULL, 0, MSG_PEEK, (struct sockaddr *)&client_addr, &n);

			if (ret < 0) {
				log_err("recvfrom error: %s", strerror(errno));
				return ret;
			}

			if (client_addr.ss_family == AF_INET6) {
				struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&client_addr;

				ip_len = sizeof(addr6->sin6_addr.s6_addr);

				memcpy(ip, &addr6->sin6_addr.s6_addr, ip_len);

				memcpy(&packet->src.addr.sin6.sin6_addr.s6_addr, ip, ip_len);
				packet->src.addr.sa.sa_family = AF_INET6;
				packet->src.addr.sin6.sin6_family = addr6->sin6_family;
				packet->src.addr.sin6.sin6_port = addr6->sin6_port;
				packet->src.addr.sin6.sin6_scope_id = addr6->sin6_scope_id;
				packet->src.size = (socklen_t)sizeof(packet->src);

				family = AF_INET6;

			} else {
				struct sockaddr_in *addr4 = (struct sockaddr_in *)&client_addr;

				ip_len = sizeof(addr4->sin_addr.s_addr);
				memcpy(ip, &addr4->sin_addr.s_addr, ip_len);

				memcpy(&packet->src.addr.sin.sin_addr.s_addr, ip, ip_len);
				packet->src.addr.sa.sa_family = AF_INET;
				packet->src.addr.sin.sin_family = addr4->sin_family;
				packet->src.addr.sin.sin_port = addr4->sin_port;
				packet->src.size = (socklen_t)sizeof(packet->src);

				family = AF_INET;
			}

			session = coap_endpoint_get_session(endpoint, packet, now);

			if (session && session->tls) {
				bytes_read = coap_dtls_receive(session, packet->payload, COAP_RXBUFFER_SIZE);

				if (bytes_read > 0)
					packet->length = bytes_read;
			}
		}
	}

	if (bytes_read <= 0)
		log_err("read failed");
	else if (bytes_read > 0) {
		if (!session)
			session = coap_endpoint_get_session(endpoint,
						packet, now);
		if (session)
			result = coap_handle_message_for_proto(ctx, session, packet);
	}

	return result;
}

int coap_wait_ack(coap_context_t *context, coap_session_t *session,
		coap_queue_t *node)
{
	uint32_t now;

	log_dbg("");

	node->session = coap_session_reference(session);

	coap_ticks(&now);

	if (context->sendqueue == NULL) {
		node->t = node->timeout;
		context->sendqueue_basetime = now;
	} else
		node->t = (now - context->sendqueue_basetime) + node->timeout;

	artik_coap_insert_node(&context->sendqueue, node);

	return node->id;
}

int artik_coap_send(coap_session_t *session, coap_packet_t *packet)
{
	uint8_t r;
	int bytes_written = coap_send_packet(session, packet, NULL);

	if (bytes_written == -3)
		return ntohs(packet->mid);

	log_dbg("");

	if (bytes_written < 0) {
		log_dbg("");
		return bytes_written;
	}

	log_dbg("");

	if (packet->type != COAP_TYPE_CON)
		return ntohs(packet->mid);

	log_dbg("");

	coap_queue_t *node = artik_coap_new_node();

	if (!node) {
		log_err("insufficient memory");
		return -1;
	}

	node->id = ntohs(packet->mid);
	node->packet = packet;
	prng(&r, sizeof(r));

	node->timeout = calc_timeout(r);

	return coap_wait_ack(session->context, session, node);
}

void artik_coap_read(coap_context_t *ctx, uint32_t now)
{
	coap_endpoint_t *ep, *tmp;
	coap_session_t *s, *tmp_s;
	int ret = 0;

	LL_FOREACH_SAFE(ctx->endpoint, ep, tmp) {
		if ((ep->sock.flags & COAP_SOCKET_HAS_DATA) != 0) {
			ret = coap_read_endpoint(ctx, ep, now);
			if (ret < 0)
				return;
		}
	}

	LL_FOREACH_SAFE(ctx->sessions, s, tmp_s) {
		if ((s->sock.flags & COAP_SOCKET_HAS_DATA) != 0) {
			log_dbg("");
			coap_session_reference(s);
			coap_read_session(ctx, s, now);
			coap_session_release(s);
		}
	}
}

int coap_handle_message(coap_context_t *ctx, coap_session_t *session,
			uint8_t *msg, size_t msg_len)
{
	coap_queue_t *node;
	enum result_t { RESULT_OK, RESULT_ERR_EARLY, RESULT_ERR };
	int result = RESULT_ERR_EARLY;
	coap_status_t status;
	bool unknown_option = false;

	if (msg_len < COAP_HEADER_LEN) {
		log_err("coap_handle_message: discarded invalid frame");
		goto error_early;
	}

	if (((*msg >> 6) & 0x03) != COAP_DEFAULT_VERSION) {
		log_err("coap_handle_message: unknown protocol version %d",
			(*msg >> 6) & 0x03);
		goto error_early;
	}

	node = artik_coap_new_node();
	if (!node)
		goto error_early;

	result = RESULT_ERR;

	node->packet = (coap_packet_t *)coap_malloc(sizeof(coap_packet_t));

	if (!node->packet) {
		log_err("Memory problem");
		goto error_early;
	}

	coap_init_message((void *)node->packet, session->proto, 0, 0, 0);

	status = coap_parse_message((void *)node->packet, session->proto, msg,
		msg_len);

	if (status != NO_ERROR) {
		if (status == BAD_OPTION_4_02)
			unknown_option = true;
		else {
			log_err("discarded malformed packet");
			goto error;
		}
	}

	coap_ticks(&node->t);

	node->session = coap_session_reference(session);
	node->id = ntohs(node->packet->mid);

	artik_coap_dispatch(ctx, node, unknown_option);
	return -RESULT_OK;

error:
	artik_coap_delete_node(node);
	return -result;

error_early:
	return -result;
}

int artik_coap_retransmit(struct coap_context_t *context, struct coap_queue_t *node)
{
	if (!context || !node)
		return -1;

	log_dbg("");

	if (node->retransmit_cnt < COAP_DEFAULT_MAX_RETRANSMIT) {
		int bytes_written;
		uint32_t now;

		node->retransmit_cnt++;
		coap_ticks(&now);

		if (context->sendqueue == NULL) {
			node->t = node->timeout << node->retransmit_cnt;
			context->sendqueue_basetime = now;
		} else
			node->t = (now - context->sendqueue_basetime) +
				(node->timeout << node->retransmit_cnt);

		artik_coap_insert_node(&context->sendqueue, node);

		bytes_written = coap_send_packet(node->session, node->packet, node);

		if (bytes_written == -3)
			return node->id;

		if (bytes_written < 0)
			return (int)bytes_written;

		return node->id;
	}

	if (node->packet->code >= 64) {
		coap_str token = {0, NULL};

		token.length = node->packet->token_len;
		token.s = node->packet->token;

		artik_coap_handle_failed_notify(context, node->session, &token);
	}

	if (node->packet->type == COAP_TYPE_CON && context->nack_handler) {
		context->nack_handler(context, node->session, node->packet,
			COAP_NACK_TOO_MANY_RETRIES, node->id);
		coap_session_release(node->session);
	}

	artik_coap_delete_node(node);

	return -1;
}

unsigned int calc_timeout(unsigned char r)
{
	unsigned int result;

#define FP1 Q(FRAC_BITS, 1)

#define SHR_FP(val, frac) (((val) + (1 << ((frac) - 1))) >> (frac))

	result = SHR_FP((ACK_RANDOM_FACTOR - FP1) * r, MAX_BITS);

	result = SHR_FP(((result + FP1) * ACK_TIMEOUT), FRAC_BITS);

	return SHR_FP((COAP_TICKS_PER_SECOND * result), FRAC_BITS);

#undef FP1
#undef SHR_FP
}

void artik_coap_dispatch(coap_context_t *context, coap_queue_t *rcvd, bool unknown_option)
{
	coap_queue_t *sent = NULL;
	coap_packet_t *response;

	if (!context)
		return;

	switch (rcvd->packet->type) {
	case COAP_TYPE_ACK:
		log_dbg("%s: ACK", __func__);
		artik_coap_remove_from_queue(&context->sendqueue, rcvd->session,
					rcvd->id, &sent);

		if (rcvd->packet->code == 0)
			goto cleanup;

		if (sent && COAP_RESPONSE_CLASS(rcvd->packet->code) == 2) {
			const coap_str token = {
					sent->packet->token_len,
					sent->packet->token
				};

			artik_coap_touch_observer(context, sent->session, &token);
		}

		break;
	case COAP_TYPE_RST:
		log_dbg("%s: RST", __func__);
		artik_coap_remove_from_queue(&context->sendqueue, rcvd->session,
					rcvd->id, &sent);

		if (sent)
			coap_cancel(context, sent);

		if (sent && sent->packet->type == COAP_TYPE_CON &&
							context->nack_handler)
			context->nack_handler(context, sent->session,
						sent->packet, COAP_NACK_RST,
						rcvd->packet->mid);

		goto cleanup;
	case COAP_TYPE_NON:
		log_dbg("%s: NON", __func__);
		if (unknown_option)
			goto cleanup;
		break;
	case COAP_TYPE_CON:
		log_dbg("%s: CON", __func__);
		if (unknown_option) {
			log_dbg("");
			response = artik_coap_new_error_response(rcvd->packet,
					BAD_OPTION_4_02);

			if (!response)
				log_err("%s: cannot create error response", __func__);
			else {
				if (artik_coap_send(rcvd->session, response) == -1)
					log_err("%s: error sending response", __func__);
			}

			goto cleanup;
		}

	default:
		break;
	}

	if (COAP_MESSAGE_IS_REQUEST(rcvd->packet))
		artik_handle_request(context, rcvd);
	else if (COAP_MESSAGE_IS_RESPONSE(rcvd->packet))
		handle_response(context, sent, rcvd);
	else {
		log_err("dropped message with invalid code (%d.%02d)",
			COAP_RESPONSE_CLASS(rcvd->packet->code),
			rcvd->packet->code & 0x1f);
		if (!coap_is_mcast(&rcvd->session->local_addr)) {
			artik_coap_send_message_type(rcvd->session, rcvd->packet,
				COAP_MESSAGE_RST);
		}
	}

cleanup:
	log_dbg("cleanup");
	artik_coap_delete_node(sent);
	artik_coap_delete_node(rcvd);
}

void coap_cancel_session_messages(coap_context_t *context,
				coap_session_t *session,
				coap_nack_reason_t reason)
{
	coap_queue_t *p, *q;

	while (context->sendqueue && context->sendqueue->session == session) {

		q = context->sendqueue;
		context->sendqueue = q->next;

		if (q->packet->type == COAP_TYPE_CON && context->nack_handler)
			context->nack_handler(context, session, q->packet, reason,
				q->id);
		artik_coap_delete_node(q);
	}

	if (!context->sendqueue)
		return;

	p = context->sendqueue;
	q = p->next;

	while (q) {
		if (q->session && q->session == session) {
			p->next = q->next;

			if (q->packet &&
					q->packet->type == COAP_TYPE_CON &&
					context->nack_handler)
				context->nack_handler(context, session,
					q->packet, reason, q->id);
			artik_coap_delete_node(q);
			q = p->next;
		} else {
			p = q;
			q = q->next;
		}
	}
}

int coap_cancel(coap_context_t *context, const coap_queue_t *sent)
{
	coap_str token = {0, NULL};
	int num_cancelled = 0;

	COAP_SET_STR(&token, sent->packet->token_len, sent->packet->token);

	RESOURCES_ITER(context->resources, r) {
		num_cancelled += artik_coap_delete_observer(r, sent->session, &token);
		artik_coap_cancel_all_messages(context, sent->session, token.s,
				token.length);
	}

	return num_cancelled;
}

enum respond_t { RESPONSE_DEFAULT, RESPONSE_DROP, RESPONSE_SEND };

static size_t get_wkc_len(coap_context_t *context, multi_option_t *query_filter)
{
	unsigned char buf[1];
	size_t len = 0;

	if (coap_print_wellknown(context, buf, &len, UINT_MAX, query_filter) &
		COAP_PRINT_STATUS_ERROR) {
		log_err("cannot determine length of /.well-known/core");
		return 0;
	}

	log_dbg("%s: coap_print_wellknown() return %zu", __func__, len);

	return len;
}

coap_packet_t *coap_wellknown_response(coap_context_t *context,
	coap_session_t *session, coap_packet_t *request)
{
	coap_packet_t *resp;
	coap_message_type_t type;
	multi_option_t *query_filter;
	size_t len, wkc_len;
	int result = 0;
	size_t offset = 0;
	int need_block2 = 0;
	uint32_t num = 0;
	uint8_t more = 0;
	uint16_t size = 0;
	int szx;
	int count = 0;

	type = request->type == COAP_TYPE_CON ? COAP_TYPE_ACK : COAP_TYPE_NON;

	resp = (coap_packet_t *)coap_malloc(sizeof(coap_packet_t));

	if (resp) {
		coap_init_message((void *)resp, request->protocol, type,
			CONTENT_2_05, request->mid);
	} else {
		log_err("%s: cannot create packet", __func__);
		return NULL;
	}

	coap_set_header_token((void *)resp,
				(uint8_t *)request->token,
				(size_t)request->token_len);

	query_filter = request->uri_query;

	wkc_len = get_wkc_len(context, query_filter);

	if (wkc_len == 0) {
		log_err("%s: undefined resource", __func__);
		resp->code = BAD_REQUEST_4_00;
		return resp;
	} else if (wkc_len > REST_MAX_CHUNK_SIZE) {
		log_err("wellknown response too long");
		goto error;
	}

	if (IS_OPTION(request, COAP_OPTION_BLOCK2)) {

		coap_get_header_block2((void *)request, &num, &more, &size, NULL);

		while (size != 1) {
			size >>= 1;
			count++;
		}

		szx = count - 4;

		offset = num << (szx + 4);

		if (szx > COAP_MAX_BLOCK_SZX) {
			resp->code = BAD_REQUEST_4_00;
			return resp;
		}

		need_block2 = 1;
	}

	if (!need_block2 && (wkc_len > REST_MAX_CHUNK_SIZE)) {
		const size_t payloadlen = REST_MAX_CHUNK_SIZE;

		num = 0;
		more = 0;
		szx = COAP_MAX_BLOCK_SZX;

		while (payloadlen < SZX_TO_BYTES(szx)) {
			if (szx == 0) {
				log_err("message to small even for szx == 0");
				goto error;
			} else
				szx--;
		}

		need_block2 = 1;
	}

	if (need_block2) {
		size_t start, want, avail;

		start = num << (szx + 4);

		if (wkc_len <= start) {
			log_err("illegal block requested");
			goto error;
		}

		avail = REST_MAX_CHUNK_SIZE - 4;
		want = (size_t)1 << (szx + 4);

		if (want <= avail)
			more = want < wkc_len - start;
		else {
			if (wkc_len - start <= avail)
				more = 0;
			else {
				unsigned int _szx;
				int newBlockSize;

				newBlockSize = flsll((long long)avail) - 5;
				_szx = szx;
				szx = newBlockSize;
				more = 1;
				num <<= _szx - szx;
			}
		}

		size = SZX_TO_BYTES(szx);
		if (!coap_set_header_block2((void *)resp, num, more, size)) {
			log_err("cannot add block2 option");
			goto error;
		}
	}

	coap_set_header_content_type((void *)resp, APPLICATION_LINK_FORMAT);

	len = need_block2 ? wkc_len - (num << (szx + 4)) < SZX_TO_BYTES(szx) ?
		wkc_len - (num << (szx + 4)) : SZX_TO_BYTES(szx) : wkc_len;

	resp->payload = (uint8_t *)coap_malloc(len);

	if (!resp->payload) {
		log_err("Memory problem");
		goto error;
	}

	resp->payload_len = len;

	result = coap_print_wellknown(context, resp->payload, &len, offset,
			query_filter);

	if ((result & COAP_PRINT_STATUS_ERROR) != 0) {
		log_err("coap_print_wellknown failed");
		goto error;
	}

	return resp;

error:
	resp->code = SERVICE_UNAVAILABLE_5_03;
	return resp;
}

void artik_handle_request(coap_context_t *context, coap_queue_t *node)
{
	coap_method_handler_t h = NULL;
	coap_packet_t *response = NULL;
	bool allocated = false;
	coap_resource_t *resource;
	coap_key_t key;

	artik_coap_hash_request_uri(node->packet, key);
	resource = artik_coap_get_resource_from_key(context, key);

	if (!resource) {
		if (is_wkc(key)) {
			if (node->packet->code == COAP_GET) {
				response = coap_wellknown_response(context,
					node->session, node->packet);
				if (response && response->payload)
					allocated = true;

			} else {
				log_err("method not allowed for .well-known/core");
				response = artik_coap_new_error_response(node->packet,
					METHOD_NOT_ALLOWED_4_05);
			}
		} else {
			log_err("request for unknown resource 0x%02x%02x%02x%02x, return 4.04",
				key[0], key[1], key[2], key[3]);
				response = artik_coap_new_error_response(node->packet,
					NOT_FOUND_4_04);
		}

		if (response) {
			if (artik_coap_send(node->session, response) == -1)
				log_err("cannot send response for transaction %u", node->id);

			if (response->payload && allocated)
				coap_free(response->payload);
			coap_free_header(response);
			coap_free(response);
		}

		response = NULL;

		return;
	}

	if (node->packet && (size_t)node->packet->code - 1 <
		sizeof(resource->handler) / sizeof(coap_method_handler_t))
		h = resource->handler[node->packet->code - 1];

	if (h) {
		char *uri_query;

		if (node->packet)
			uri_query = coap_get_multi_option_as_string(node->packet->uri_query);

		coap_str *query = NULL;
		int owns_query = 1;

		query = (coap_str *)coap_malloc(sizeof(coap_str));

		if (!query) {
			log_err("Memory problem");
			return;
		}

		memset(query, 0, sizeof(coap_str));

		if (uri_query) {
			query->length = strlen(uri_query);
			query->s = (unsigned char *)coap_strdup(uri_query);

			if (!query->s) {
				log_err("Memory problem");
				if (query)
					coap_free(query);
				return;
			}
		}

		response = (coap_packet_t *)coap_malloc(sizeof(coap_packet_t));

		if (!response) {
			log_err("Memory problem");
			if (query->s)
				coap_free(query->s);
			if (query)
				coap_free(query);
			return;
		}

		log_dbg("call custom handler for resource 0x%02x%02x%02x%02x",
			key[0], key[1], key[2], key[3]);

		coap_init_message((void *)response,
			node->packet->protocol,
			node->packet->type == COAP_TYPE_CON ?
			COAP_TYPE_ACK : COAP_TYPE_NON, 0, node->packet->mid);

		if (node->packet && node->packet->token_len <= 8) {
			coap_set_header_token((void *)response, node->packet->token,
				node->packet->token_len);

			coap_str token = {node->packet->token_len, node->packet->token};
			uint32_t observe_action = COAP_OBSERVE_CANCEL;

			if (resource->observable) {
				if (IS_OPTION(node->packet, COAP_OPTION_OBSERVE)) {
					coap_get_header_observe((void *)node->packet,
						&observe_action);

					coap_subscription_t *subscription = NULL;

					if ((observe_action & COAP_OBSERVE_CANCEL) == 0) {

						subscription = artik_coap_add_observer(resource,
							node->session, &token, query);

						owns_query = 0;
					} else {
						artik_coap_delete_observer(resource,
							node->session,
							&token);
					}

					if (subscription)
						artik_coap_touch_observer(context,
							node->session,
							&token);
				}
			}

			log_dbg("");

			h(context, resource, node->session, node->packet,
				&token, query, response);

			if (uri_query) {
				coap_free(uri_query);
				uri_query = NULL;
			}

			if (query && owns_query) {
				if (query->s)
					coap_free(query->s);
				coap_free(query);
				query = NULL;
			}

			if (IS_OPTION(node->packet, COAP_OPTION_OBSERVE) &&
				(COAP_RESPONSE_CLASS(response->code) > 2)) {

				log_dbg("removed observer");
				artik_coap_delete_observer(resource, node->session, &token);

			}

			if ((response->type == COAP_TYPE_ACK) &&
				(response->code == 0))
				response->token_len = 0;

			if ((response->type != COAP_TYPE_NON) ||
				(response->code >= 64)) {
				if (artik_coap_send(node->session, response) == -1)
					log_err("cannot send response for message %d",
						node->packet->mid);
				if (response) {
					coap_free_header(response);
					if (response->payload)
						coap_free(response->payload);
					coap_free(response);
				}
			} else {
				if (response) {
					coap_free_header(response);
					if (response->payload)
						coap_free(response->payload);
					coap_free(response);
				}
			}

			response = NULL;

			if (query && query->s)
				coap_free(query->s);
			if (query)
				coap_free(query);

			query = NULL;

		}

		if (uri_query) {
			coap_free(uri_query);
			uri_query = NULL;
		}

	} else {
		bool error_response = false;

		if (node->packet && WANT_WKC(node->packet, key))
			response = coap_wellknown_response(context,
				node->session, node->packet);
		else {
			response = artik_coap_new_error_response(node->packet,
				METHOD_NOT_ALLOWED_4_05);
			error_response = true;
		}

		if (response) {
			if (artik_coap_send(node->session, response) == -1)
				log_err("cannot send response for transaction %d",
					node->id);
			coap_free_header(response);
			if (!error_response && response->payload)
				coap_free(response->payload);
			coap_free(response);
		}

		response = NULL;
	}
}

void handle_response(coap_context_t *context, coap_queue_t *sent,
			coap_queue_t *rcvd)
{
	artik_coap_send_ack(rcvd->session, rcvd->packet);

	artik_coap_cancel_all_messages(context, rcvd->session,
		rcvd->packet->token,
		rcvd->packet->token_len);

	if (context->response_handler)
		context->response_handler(context, rcvd->session,
			sent ? sent->packet : NULL, rcvd->packet, rcvd->id);
}

int artik_coap_send_ack(coap_session_t *session, coap_packet_t *request)
{
	coap_packet_t *response = NULL;
	int result = -1;

	log_dbg("");

	if (request && request->type == COAP_TYPE_CON) {
		response = (coap_packet_t *)coap_malloc(sizeof(coap_packet_t));

		if (!response) {
			log_err("Memory problem");
			return result;
		}

		coap_init_message((void *)response, session->proto, COAP_TYPE_ACK,
				0, request->mid);
		result = artik_coap_send(session, response);
	}

	if (response) {
		coap_free_header((void *)response);
		coap_free(response);
	}

	return result;
}

int token_match(const unsigned char *a, size_t alen,
		const unsigned char *b, size_t blen)
{
	return alen == blen && (alen == 0 || memcmp(a, b, alen) == 0);
}

void artik_coap_cancel_all_messages(coap_context_t *context, coap_session_t *session,
			const unsigned char *token, size_t token_length)
{
	coap_queue_t *p, *q;

	while (context->sendqueue && context->sendqueue->session == session &&
		token_match(token, token_length,
			context->sendqueue->packet->token,
			context->sendqueue->packet->token_len)) {
		q = context->sendqueue;
		context->sendqueue = q->next;
		artik_coap_delete_node(q);
	}

	if (!context->sendqueue)
		return;

	p = context->sendqueue;
	q = p->next;

	while (q) {
		if (q->session && q->session == session && q->packet &&
			token_match(token, token_length,
				q->packet->token, q->packet->token_len)) {
			p->next = q->next;
			artik_coap_delete_node(q);
			q = p->next;
		} else {
			p = q;
			q = q->next;
		}
	}

}

int artik_coap_send_message_type(coap_session_t *session, coap_packet_t *request,
			unsigned char type)
{
	coap_packet_t *response;
	int result = -1;

	if (request) {
		response = (coap_packet_t *)coap_malloc(sizeof(coap_packet_t));

		coap_init_message((void *)response, session->proto, type,
				0, request->mid);
		if (request)
			result = artik_coap_send(session, response);
	}

	return result;
}

void coap_register_response_handler(coap_context_t *context,
			coap_response_handler_t handler)
{
	context->response_handler = handler;
}

void coap_register_nack_handler(coap_context_t *context,
			coap_nack_handler_t handler)
{
	context->nack_handler = handler;
}
