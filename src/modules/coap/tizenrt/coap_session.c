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

#include "coap_session.h"
#include "coap_dtls.h"
#include "coap_time.h"
#include "coap_mem.h"
#include "coap.h"

#include "utlist.h"
#include "prng.h"

#include <artik_log.h>

#include <tls/easy_tls.h>
#include <unistd.h>

int coap_socket_send(
		coap_socket_t *sock,
		coap_session_t *session,
		const uint8_t *data,
		size_t data_len)
{
	return session->context->network_send(sock, session, data, data_len);
}

int coap_session_send(
		coap_session_t *session,
		const uint8_t *data,
		size_t datalen)
{
	int bytes_written;

	coap_socket_t *sock = &session->sock;

	log_dbg("");

	if (sock->flags == COAP_SOCKET_EMPTY)
		sock = &session->endpoint->sock;

	bytes_written = coap_socket_send(sock, session, data, datalen);

	if (bytes_written == (int)datalen)
		coap_ticks(&session->last_rx_tx);

	return bytes_written;
}

int coap_session_delay_packet(
		coap_session_t *session,
		coap_packet_t *packet,
		coap_queue_t *node)
{
	if (node) {
		coap_queue_t *removed;

		artik_coap_remove_from_queue(&session->context->sendqueue, session,
			node->id, &removed);
		coap_session_release(node->session);
		node->session = NULL;
		node->t = 0;
	} else {
		node = artik_coap_new_node();

		if (node == NULL)
			return -1;

		node->id = ntohs(packet->mid);
		node->packet = packet;

		if (packet->type == COAP_TYPE_CON) {
			uint8_t r;

			prng(&r, sizeof(r));
			node->timeout = calc_timeout(r);
		}
	}
	LL_APPEND(session->sendqueue, node);
	return -3;
}

void coap_session_connected(coap_session_t *session)
{
	session->state = COAP_SESSION_STATE_ESTABLISHED;

	if (session->proto == COAP_UDP_DTLS) {
		session->tls_overhead = (uint16_t)coap_dtls_get_overhead(session);
		if (session->tls_overhead >= session->mtu) {
			session->tls_overhead = session->mtu;
			log_err("DTLS overhead exceeds MTU");
		}
	}

	while (session->sendqueue && session->state == COAP_SESSION_STATE_ESTABLISHED) {
		int bytes_written;
		uint8_t *pktBuffer;
		size_t pktBufferLen, allocLen;
		coap_queue_t *q = session->sendqueue;

		if (q) {
			session->sendqueue = q->next;
			q->next = NULL;

			allocLen = coap_serialize_get_size((void *)q->packet);

			pktBuffer = (uint8_t *)coap_malloc(allocLen*sizeof(uint8_t));

			pktBufferLen = coap_serialize_message((void *)q->packet,
					pktBuffer);

			if (session->proto == COAP_UDP_DTLS)
				bytes_written = coap_dtls_send(session,
							pktBuffer, pktBufferLen);
			else
				bytes_written = coap_session_send(session,
							pktBuffer, pktBufferLen);

			if (q->packet->type == COAP_TYPE_CON) {
				if (coap_wait_ack(session->context, session, q) >= 0)
					q = NULL;
			}

			artik_coap_delete_node(q);

			if (bytes_written < 0)
				break;
		}

	}
}

void coap_session_disconnected(coap_session_t *session, coap_nack_reason_t reason)
{
	coap_queue_t *c, *tmp;

	if (reason == COAP_NACK_TLS_FAILED || reason == COAP_NACK_NOT_DELIVERABLE) {
		LL_FOREACH_SAFE(session->sendqueue, c, tmp) {
			if (c->packet->type == COAP_TYPE_CON &&
				session->context->nack_handler)
				session->context->nack_handler(session->context,
					session, c->packet,
					session->proto == COAP_UDP_DTLS ?
					COAP_NACK_TLS_FAILED : COAP_NACK_NOT_DELIVERABLE,
					c->id);
		}
	}

	if (session->proto == COAP_UDP_DTLS && session->tls) {
		coap_dtls_free_session(session);
		session->tls = NULL;
	}

	session->state = COAP_SESSION_STATE_NONE;
	while (session->sendqueue) {
		coap_queue_t *q = session->sendqueue;

		session->sendqueue = q->next;
		q->next = NULL;

		if (q->packet->type == COAP_TYPE_CON) {
			if (coap_wait_ack(session->context, session, q) >= 0)
				q = NULL;
		}

		if (q)
			artik_coap_delete_node(q);
	}
}

coap_session_t *coap_session_reference(coap_session_t *session)
{
	++session->ref;
	return session;
}

void coap_session_release(coap_session_t *session)
{
	if (session) {
		if (session->ref > 0) {
			log_dbg("");
			--session->ref;
		}
		if (session->ref == 0 && session->type == COAP_SESSION_TYPE_CLIENT) {
			log_dbg("");
			coap_session_free(session);
		}
	}
}

coap_session_t *coap_make_session(
		coap_protocol_t proto,
		uint8_t type,
		const coap_address_t *local,
		const coap_address_t *remote,
		int ifindex,
		struct coap_context_t *context,
		struct coap_endpoint_t *endpoint)
{
	coap_session_t *session = (coap_session_t *)coap_malloc(sizeof(coap_session_t));

	if (!session)
		return NULL;

	memset(session, 0, sizeof(*session));

	session->proto = proto;
	session->type = type;

	if (local)
		coap_address_copy(&session->local_addr, local);
	else
		coap_address_init(&session->local_addr);

	if (remote)
		coap_address_copy(&session->remote_addr, remote);
	else
		coap_address_init(&session->remote_addr);

	session->ifindex = ifindex;
	session->context = context;
	session->endpoint = endpoint;

	if (endpoint)
		session->mtu = endpoint->default_mtu;
	else
		session->mtu = COAP_DEFAULT_PDU_SIZE;

	prng((unsigned char *)&session->tx_mid, sizeof(session->tx_mid));

	return session;
}

void coap_session_free(coap_session_t *session)
{
	coap_queue_t *q, *tmp;

	log_dbg("");

	if (!session)
		return;
	if (session->ref)
		return;

	log_dbg("");

	if (session->proto == COAP_UDP_DTLS)
		coap_dtls_free_session(session);

	log_dbg("");

	if (session->psk_key)
		coap_free(session->psk_key);
	if (session->psk_identity)
		coap_free(session->psk_identity);
	if (session->sock.flags != COAP_SOCKET_EMPTY && session->sock.fd != -1) {
		close(session->sock.fd);
		session->sock.fd = -1;
		session->sock.flags = COAP_SOCKET_EMPTY;
	}
	if (session->endpoint) {
		if (session->endpoint->sessions)
			LL_DELETE(session->endpoint->sessions, session);
	} else if (session->context) {
		if (session->context->sessions)
			LL_DELETE(session->context->sessions, session);
	}

	LL_FOREACH_SAFE(session->sendqueue, q, tmp) {
		if (q->packet->type == COAP_TYPE_CON && session->context &&
				session->context->nack_handler)
			session->context->nack_handler(session->context, session,
				q->packet, session->proto == COAP_UDP_DTLS ?
					COAP_NACK_TLS_FAILED :
						COAP_NACK_NOT_DELIVERABLE, q->id);
		artik_coap_delete_node(q);
	}

	coap_free(session);

	session = NULL;
}

coap_session_t *coap_endpoint_new_dtls_session(
		coap_endpoint_t *endpoint,
		coap_data_t *packet,
		uint32_t now)
{
	coap_session_t *session = coap_make_session(COAP_UDP_DTLS,
				COAP_SESSION_TYPE_SERVER,
				&packet->dst, &packet->src, packet->ifindex,
				endpoint->context, endpoint);

	if (session) {
		mbedtls_ssl_context *ssl;
		unsigned char *ip;
		size_t ip_len = 0;

		session->last_rx_tx = now;
		session->state = COAP_SESSION_STATE_HANDSHAKE;
		session->sock.fd = endpoint->sock.fd;
		session->sock.flags = endpoint->sock.flags;
		session->tls = coap_dtls_new_server_session(session);

		ssl = (mbedtls_ssl_context *)session->tls;

		if (!ssl) {
			log_err("Memory problem");
			coap_session_free(session);
			return NULL;
		}

		ip_len = ssl->cli_id_len;

		ip = (unsigned char *)coap_malloc(ip_len);

		if (ip) {
			memcpy(ip, ssl->cli_id, ip_len);

			if (ip_len == sizeof(packet->src.addr.sin.sin_addr.s_addr)) {
				memcpy(&packet->src.addr.sin.sin_addr.s_addr, ip, ip_len);
				packet->src.size = (socklen_t)sizeof(packet->src);
				packet->src.addr.sin.sin_family = AF_INET;
			} else if (ip_len == sizeof(packet->src.addr.sin6.sin6_addr.s6_addr)) {
				memcpy(&packet->src.addr.sin6.sin6_addr.s6_addr, ip, ip_len);
				packet->src.size = (socklen_t)sizeof(packet->src);
				packet->src.addr.sin6.sin6_family = AF_INET6;
			} else {
				log_err("error ip");
				coap_session_free(session);
				coap_free(ip);
				return NULL;
			}
		} else {
			log_err("Memory problem");
			coap_session_free(session);
			return NULL;
		}

		if (session->tls) {
			session->state = COAP_SESSION_STATE_ESTABLISHED;
			log_dbg("Session DTLS created");
			LL_PREPEND(endpoint->sessions, session);
		} else {
			log_dbg("No session DTLS created");
			coap_session_free(session);
			session = NULL;
		}

		if (ip)
			coap_free(ip);
	}

	return session;
}

coap_session_t *coap_session_create_client(
		struct coap_context_t *ctx,
		const coap_address_t *local_if,
		const coap_address_t *server,
		coap_protocol_t proto)
{
	coap_session_t *session = NULL;

	session = coap_make_session(proto, COAP_SESSION_TYPE_CLIENT,
				local_if, server, 0, ctx, NULL);

	if (!session)
		goto error;

	if (!coap_socket_connect_udp(&session->sock, local_if, server,
		proto == COAP_UDP_DTLS ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT,
		&session->local_addr, &session->remote_addr))
		goto error;

	session->ref = 1;

	session->sock.flags = COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_CONNECTED |
				COAP_SOCKET_WANT_DATA;

	if (local_if)
		session->sock.flags |= COAP_SOCKET_BOUND;

	LL_PREPEND(ctx->sessions, session);

	return session;

error:
	coap_session_free(session);

	return NULL;
}

coap_session_t *coap_session_connect(coap_session_t *session)
{
	if (session->proto == COAP_UDP)
		session->state = COAP_SESSION_STATE_ESTABLISHED;
	else if (session->proto == COAP_UDP_DTLS) {
		log_dbg("");
		session->tls = (void *)coap_dtls_new_client_session(session);
		if (session->tls)
			session->state = COAP_SESSION_STATE_ESTABLISHED;
		else {
			session->ref = 0;
			coap_session_free(session);
			return NULL;
		}
	}

	coap_ticks(&session->last_rx_tx);

	return session;
}

coap_session_t *coap_new_client_session(
		struct coap_context_t *ctx,
		const coap_address_t *local_if,
		const coap_address_t *server,
		coap_protocol_t proto)
{
	coap_session_t *session = coap_session_create_client(ctx, local_if,
						server, proto);
	if (session)
		session = coap_session_connect(session);

	return session;
}

coap_session_t *coap_new_client_session_psk(
		struct coap_context_t *ctx,
		const coap_address_t *local_if,
		const coap_address_t *server,
		coap_protocol_t proto,
		const char *identity,
		const uint8_t *key,
		unsigned int key_len)
{
	coap_session_t *session = coap_session_create_client(ctx, local_if,
						server, proto);

	if (!session)
		return NULL;

	if (identity) {
		size_t identity_len = strlen(identity);

		session->psk_identity = (uint8_t *)coap_malloc(identity_len);

		if (session->psk_identity) {
			memcpy(session->psk_identity, identity, identity_len);
			session->psk_identity_len = identity_len;
		} else
			log_err("Cannot store session PSK identity");
	}

	if (key && key_len > 0) {
		session->psk_key = (uint8_t *)coap_malloc(key_len);

		if (session->psk_key) {
			memcpy(session->psk_key, key, key_len);
			session->psk_key_len = key_len;
		} else
			log_err("Cannot store session PSK key");
	}

	return coap_session_connect(session);
}

coap_session_t *coap_new_client_session_ssl(
		struct coap_context_t *ctx,
		const coap_address_t *local_if,
		const coap_address_t *server,
		coap_protocol_t proto,
		const coap_ecdsa_keys *ecdsa_keys)
{
	coap_session_t *session = coap_session_create_client(ctx, local_if,
						server, proto);

	if (!session)
		return NULL;

	if (ecdsa_keys) {
		memcpy(&session->ecdsa_keys, ecdsa_keys,
						sizeof(session->ecdsa_keys));
		coap_context_set_ssl(ctx, ecdsa_keys->priv_key,
					ecdsa_keys->priv_key_len,
					ecdsa_keys->pub_key_x,
					ecdsa_keys->pub_key_x_len,
					ecdsa_keys->pub_key_y,
					ecdsa_keys->pub_key_y_len);
	} else
		log_err("Cannot store session SSL keys");

	return coap_session_connect(session);
}

coap_endpoint_t *coap_new_endpoint(struct coap_context_t *context,
		const coap_address_t *listen_addr,
		coap_protocol_t proto)
{
	struct coap_endpoint_t *ep = NULL;

	ep = (coap_endpoint_t *)coap_malloc(sizeof(coap_endpoint_t));

	if (!ep) {
		log_err("coap_new_endpoint: coap_malloc");
		return NULL;
	}

	memset(ep, 0, sizeof(struct coap_endpoint_t));
	ep->context = context;
	ep->proto = proto;

	if (!coap_socket_bind_udp(&ep->sock, listen_addr, &ep->bind_addr)) {
		log_err("Fail to bind udp");
		goto error;
	}

	if (ep->sock.fd == -1)
		goto error;

	ep->sock.flags = COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_BOUND |
				COAP_SOCKET_WANT_DATA;

	if (proto == COAP_UDP_DTLS) {
		ep->hello.proto = proto;
		ep->hello.type = COAP_SESSION_TYPE_HELLO;
		ep->hello.mtu = ep->default_mtu;
		ep->hello.context = context;
		ep->hello.endpoint = ep;
	}

	ep->default_mtu = COAP_DEFAULT_PDU_SIZE;

	LL_PREPEND(context->endpoint, ep);
	return ep;

error:
	if (ep->sock.fd != -1)
		close(ep->sock.fd);
	coap_free(ep);
	return NULL;
}

void coap_free_endpoint(coap_endpoint_t *ep)
{
	if (ep) {
		coap_session_t *session;

		if (ep->sock.flags != COAP_SOCKET_EMPTY && ep->sock.fd != -1) {
			close(ep->sock.fd);
			ep->sock.fd = -1;
		}

		LL_FOREACH(ep->sessions, session) {
			if (session->ref == 0) {
				session->endpoint = NULL;
				session->context = NULL;
				coap_session_free(session);
			}
		}

		coap_free(ep);
		ep = NULL;
	}
}

void coap_session_reset(coap_session_t *session)
{
	coap_delete_observers(session->context, session);

	coap_cancel_session_messages(session->context, session,
				COAP_NACK_NOT_DELIVERABLE);

	if (session->proto == COAP_UDP_DTLS && session->tls) {
		coap_dtls_free_session(session);
		session->tls = NULL;
	}

	session->state = COAP_SESSION_STATE_NONE;

	while (session->sendqueue) {
		coap_queue_t *q = session->sendqueue;

		session->sendqueue = q->next;
		q->next = NULL;
		if (q->packet->type == COAP_TYPE_CON && session->context->nack_handler)
			session->context->nack_handler(session->context, session,
				q->packet, COAP_NACK_NOT_DELIVERABLE, q->id);
		artik_coap_delete_node(q);
	}
}

coap_session_t *coap_endpoint_get_session(coap_endpoint_t *endpoint,
			const coap_data_t *packet, uint32_t now)
{
	coap_session_t *session = NULL;
	unsigned int num_idle = 0;
	coap_session_t *oldest = NULL;

	endpoint->hello.ifindex = -1;

	LL_FOREACH(endpoint->sessions, session) {
		if (coap_address_equals(&session->local_addr, &packet->dst) &&
			coap_address_equals(&session->remote_addr, &packet->src)) {

			log_dbg("");
			session->last_rx_tx = now;
			session->newly_created = 0;
			return session;
		}
		if (session->ref == 0 && session->sendqueue == NULL &&
			session->type == COAP_SESSION_TYPE_SERVER) {
			++num_idle;

			if (oldest == NULL || session->last_rx_tx < oldest->last_rx_tx)
				oldest = session;
		}
	}

	log_dbg("");

	if (endpoint->context->max_idle_sessions > 0 &&
			num_idle >= endpoint->context->max_idle_sessions) {
		coap_session_release(oldest);
		coap_session_free(oldest);
	}

	if (endpoint->proto == COAP_UDP_DTLS) {

		session = coap_make_session(endpoint->proto,
			COAP_SESSION_TYPE_SERVER, &packet->dst, &packet->src,
			packet->ifindex, endpoint->context, endpoint);


		if (session) {
			session->last_rx_tx = now;
			session->state = COAP_SESSION_STATE_HANDSHAKE;

			coap_address_copy(&session->local_addr, &packet->dst);
			coap_address_copy(&session->remote_addr, &packet->src);

			session->tls = coap_dtls_new_server_session(session);

			if (session->tls) {
				session->state = COAP_SESSION_STATE_ESTABLISHED;
				session->newly_created = 1;
				log_dbg("session DTLS created");
				LL_PREPEND(endpoint->sessions, session);
			} else {
				log_dbg("No session DTLS created");
				coap_session_free(session);
				session = NULL;
			}
		}

	} else if (endpoint->proto == COAP_UDP) {
		session = coap_make_session(endpoint->proto, COAP_SESSION_TYPE_SERVER,
				&packet->dst, &packet->src, packet->ifindex,
				endpoint->context, endpoint);

		if (session) {
			session->last_rx_tx = now;

			session->state = COAP_SESSION_STATE_ESTABLISHED;

			LL_PREPEND(endpoint->sessions, session);
		}
	}


	return session;
}
