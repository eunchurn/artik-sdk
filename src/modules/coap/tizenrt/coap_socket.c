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

#include "coap_socket.h"
#include "coap_session.h"
#include "coap.h"
#include "coap_time.h"
#include "coap_dtls.h"

#include "utlist.h"

#include <sys/socket.h>
#include <sys/select.h>

#include <artik_log.h>

#include <unistd.h>

#include <errno.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define SOL_IP		0
#define IP_RECVDSTADDR	7
#define IP_PKTINFO	8
#define IPV6_PKTINFO	50

#define IN6_IS_ADDR_V4MAPPED(_Address) \
	(((_Address)->s6_addr[0] == 0) && \
	((_Address)->s6_addr[1] == 0) && \
	((_Address)->s6_addr[2] == 0) && \
	((_Address)->s6_addr[3] == 0) && \
	((_Address)->s6_addr[4] == 0) && \
	((_Address)->s6_addr[5] == 0) && \
	((_Address)->s6_addr[6] == 0) && \
	((_Address)->s6_addr[7] == 0) && \
	((_Address)->s6_addr[8] == 0) && \
	((_Address)->s6_addr[9] == 0) && \
	((_Address)->s6_addr[10] == 0) && \
	((_Address)->s6_addr[11] == 0) && \
	((_Address)->s6_addr[12] == 0) && \
	((_Address)->s6_addr[13] == 0) && \
	((_Address)->s6_addr[14] == 0xff) && \
	((_Address)->s6_addr[15] == 0xff))


struct in6_pktinfo {
	struct in6_addr ipi6_addr;	/* src/dst IPv6 address */
	unsigned int ipi6_ifindex;	/* send/recv interface index */
};

struct in_pktinfo {
	int ipi_ifindex;
	struct in_addr ipi_spec_dst;
	struct in_addr ipi_addr;
};

int coap_network_send(
	coap_socket_t *sock,
	const struct coap_session_t *session,
	const uint8_t *data,
	size_t datalen)
{
	int bytes_written = 0;

	if (sock->flags & COAP_SOCKET_CONNECTED)
		bytes_written = send(sock->fd, data, datalen, 0);
	else {

		if (session->remote_addr.addr.sa.sa_family == AF_INET) {
			struct sockaddr_in addr;
			socklen_t len;

			memset(&addr, 0, sizeof(struct sockaddr_in));
			memcpy(&addr.sin_addr, &session->remote_addr.addr.sin.sin_addr,
				sizeof(session->remote_addr.addr.sin.sin_addr));
			addr.sin_family = session->remote_addr.addr.sin.sin_family;
			addr.sin_port = session->remote_addr.addr.sin.sin_port;
			len = sizeof(addr);

			bytes_written = sendto(sock->fd, (void *)data, datalen,
				0, (struct sockaddr *)&addr, len);

		} else if (session->remote_addr.addr.sa.sa_family == AF_INET6) {
			struct sockaddr_in6 addr;
			socklen_t len;

			memset(&addr, 0, sizeof(struct sockaddr_in6));
			memcpy(&addr.sin6_addr, &session->remote_addr.addr.sin6.sin6_addr,
				sizeof(session->remote_addr.addr.sin6.sin6_addr));
			addr.sin6_family = session->remote_addr.addr.sin6.sin6_family;
			addr.sin6_port = session->remote_addr.addr.sin6.sin6_port;
			addr.sin6_scope_id = session->remote_addr.addr.sin6.sin6_scope_id;
			len = sizeof(addr);

			bytes_written = sendto(sock->fd, (void *)data, datalen,
				0, (struct sockaddr *)&addr, len);
		}

	}

	if (bytes_written < 0)
		log_err("error in sending: %s", strerror(errno));

	return bytes_written;
}

int coap_network_read(coap_socket_t *sock, coap_data_t *packet)
{
	int len = -1;

	log_dbg("");

	if ((sock->flags & COAP_SOCKET_HAS_DATA) == 0)
		return -1;

	sock->flags &= ~COAP_SOCKET_HAS_DATA;

	if (sock->flags & COAP_SOCKET_CONNECTED) {
		len = recv(sock->fd, packet->payload, COAP_RXBUFFER_SIZE, 0);
		if (len < 0) {
			if (errno == ECONNREFUSED) {
				log_err("%s: unreachable", __func__);
				return -2;
			}

			log_err("%s: %s", __func__, strerror(errno));

			goto error;
		} else if (len > 0)
			packet->length = (size_t)len;
	} else {
		unsigned char ip[16];
		unsigned int ip_len;
		int fd = sock->fd;
		struct sockaddr_storage client_addr;
		uint8_t family = 0;
		socklen_t n;

		n = (socklen_t)sizeof(client_addr);

		len = (int)recvfrom(fd, packet->payload, COAP_RXBUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &n);

		packet->length = len;

		if (len < 0) {
			log_err("recvfrom error: %s", strerror(errno));
			return len;
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
	}

	if (len >= 0) {
		log_dbg("");
		return len;
	}

error:
	log_dbg("");
	return -1;
}

int coap_socket_bind_udp(
	coap_socket_t *sock,
	const coap_address_t *listen_addr,
	coap_address_t *bound_addr)
{
	int on = 1;

	sock->fd = socket(listen_addr->addr.sa.sa_family, SOCK_DGRAM, 0);

	if (sock->fd == -1) {
		log_err("%s: socket: %s", __func__, strerror(errno));
		goto error;
	}

	if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, &on,
			sizeof(on)) == -1)
		log_err("%s: setsockopt SO_REUSEADDR: %s", __func__,
			strerror(errno));

	switch (listen_addr->addr.sa.sa_family) {
	case AF_INET:
		if (setsockopt(sock->fd, IPPROTO_IP, IP_PKTINFO, &on,
				sizeof(on)) == -1)
			log_err("%s: setsockopt IP_PKTINFO: %s", __func__,
				strerror(errno));
		break;
	case AF_INET6:
		break;
	default:
		log_err("%s: unsupported sa_family", __func__);
	}

	if (bind(sock->fd, &listen_addr->addr.sa, listen_addr->size) == -1) {
		log_err("%s: bind: %s", strerror(errno));
		goto error;
	}

	bound_addr->size = (socklen_t)sizeof(*bound_addr);

	if (getsockname(sock->fd, &bound_addr->addr.sa, &bound_addr->size) < 0) {
		log_err("%s: getsockname: %s", strerror(errno));
		goto error;
	}

	return 1;

error:
	if (sock->fd != -1)
		close(sock->fd);
	return 0;
}

int coap_socket_connect_udp(
	coap_socket_t *sock,
	const coap_address_t *local_if,
	const coap_address_t *server,
	int default_port,
	coap_address_t *local_addr,
	coap_address_t *remote_addr)
{
	int on = 1, off = 0;

	log_dbg("");

	coap_address_t connect_addr;

	coap_address_copy(&connect_addr, server);

	sock->fd = socket(connect_addr.addr.sa.sa_family, SOCK_DGRAM, 0);

	if (sock->fd == -1) {
		log_err("%s: socket: %s", __func__, strerror(errno));
		goto error;
	}

	switch (connect_addr.addr.sa.sa_family) {
	case AF_INET:
		if (connect_addr.addr.sin.sin_port == 0)
			connect_addr.addr.sin.sin_port = htons(default_port);
		break;
	case AF_INET6:
		if (connect_addr.addr.sin6.sin6_port == 0)
			connect_addr.addr.sin6.sin6_port = htons(default_port);
		if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY,
				(void *)&off, sizeof(off)) == -1)
			log_err("%s, setsockopt IPV6_V6ONLY: %s", __func__,
				strerror(errno));
		break;
	default:
		log_err("%s: unsupported sa_family", __func__);
	}

	if (local_if) {
		if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR,
			(void *)&on, sizeof(on)) == -1)
			log_err("%s: setsockopt SO_REUSEADDR: %s", __func__,
				strerror(errno));
		if (bind(sock->fd, &local_if->addr.sa, local_if->size) == -1) {
			log_err("%s: bind: %s", __func__, strerror(errno));
			goto error;
		}
	}

	if (connect(sock->fd, &connect_addr.addr.sa, connect_addr.size) == -1) {
		log_err("%s: connect: %s", __func__, strerror(errno));
		goto error;
	}

	if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == -1)
		log_err("%s: getsockname: %s", __func__, strerror(errno));

	if (getpeername(sock->fd, &remote_addr->addr.sa, &remote_addr->size) == -1)
		log_err("%s: getpeername: %s", __func__, strerror(errno));

	return 1;

error:
	if (sock->fd != -1)
		close(sock->fd);
	return 0;
}

unsigned int coap_write(coap_context_t *ctx,
			coap_socket_t *sockets[],
			unsigned int max_sockets,
			unsigned int *num_sockets,
			uint32_t now)
{
	coap_queue_t *nextpdu;
	coap_endpoint_t *ep;
	coap_session_t *s;
	uint32_t session_timeout;
	uint32_t timeout = 0;

	*num_sockets = 0;

	if (ctx->session_timeout > 0)
		session_timeout = ctx->session_timeout * COAP_TICKS_PER_SECOND;
	else
		session_timeout = COAP_DEFAULT_SESSION_TIMEOUT * COAP_TICKS_PER_SECOND;

	LL_FOREACH(ctx->endpoint, ep) {
		coap_session_t *tmp;

		if (ep->sock.flags & (COAP_SOCKET_WANT_DATA | COAP_SOCKET_WANT_WRITE)) {
			if (*num_sockets < max_sockets)
				sockets[(*num_sockets)++] = &ep->sock;
		}

		LL_FOREACH_SAFE(ctx->endpoint->sessions, s, tmp) {
			if (s && s->type == COAP_SESSION_TYPE_SERVER &&
				s->ref == 0 && s->sendqueue == NULL
				&& (s->last_rx_tx + session_timeout <= now ||
					s->state == COAP_SESSION_STATE_NONE))
				coap_session_free(s);
			else {
				if (s && s->type == COAP_SESSION_TYPE_SERVER &&
					s->ref == 0 && s->sendqueue == NULL) {
					uint32_t s_timeout = now - (s->last_rx_tx +
						session_timeout);
					if (timeout == 0 || s_timeout < timeout)
						timeout = s_timeout;
				}
				if (s && s->sock.flags & (COAP_SOCKET_WANT_DATA |
					COAP_SOCKET_WANT_WRITE)) {
					if (*num_sockets < max_sockets)
						sockets[(*num_sockets)++] = &s->sock;
				}
			}
		}
	}

	LL_FOREACH(ctx->sessions, s) {
		if (s && s->sock.flags & (COAP_SOCKET_WANT_DATA |
			COAP_SOCKET_WANT_WRITE)) {
			if (*num_sockets < max_sockets)
				sockets[(*num_sockets)++] = &s->sock;
		}
	}

	nextpdu = artik_coap_peek_next(ctx);

	while (nextpdu && now >= ctx->sendqueue_basetime && nextpdu->t <=
					now - ctx->sendqueue_basetime) {
		artik_coap_retransmit(ctx, artik_coap_pop_next(ctx));
		nextpdu = artik_coap_peek_next(ctx);
	}

	if (nextpdu && (timeout == 0 || nextpdu->t - (now - ctx->sendqueue_basetime) <
					timeout))
		timeout = nextpdu->t - (now - ctx->sendqueue_basetime);

	LL_FOREACH(ctx->endpoint, ep) {
		if (ep->proto == COAP_UDP_DTLS) {
			LL_FOREACH(ep->sessions, s) {
				if (ctx->dtls_context && s && s->proto == COAP_UDP_DTLS && s->tls) {
					uint32_t tls_timeout = coap_dtls_get_timeout(s);

					while (tls_timeout > 0 && tls_timeout <= now) {
						coap_dtls_handle_timeout(s);
						tls_timeout = coap_dtls_get_timeout(s);
					}
					if (tls_timeout > 0 &&
						(timeout == 0 || tls_timeout - now < timeout))
						timeout = tls_timeout - now;
				}
			}
		}
	}
	LL_FOREACH(ctx->sessions, s) {
		if (ctx->dtls_context && s && s->proto == COAP_UDP_DTLS && s->tls) {
			uint32_t tls_timeout = coap_dtls_get_timeout(s);

			while (tls_timeout > 0 && tls_timeout <= now) {
				coap_dtls_handle_timeout(s);
				tls_timeout = coap_dtls_get_timeout(s);
			}
			if (tls_timeout > 0 &&
				(timeout == 0 || tls_timeout - now < timeout))
				timeout = tls_timeout - now;
		}
	}

	return (unsigned int)((timeout * 1000 + COAP_TICKS_PER_SECOND - 1) / COAP_TICKS_PER_SECOND);
}

int coap_run_once(coap_context_t *ctx, unsigned int timeout_ms)
{
	fd_set readfds, writefds;
	int nfds = 0;
	struct timeval tv;
	uint32_t before, now;
	int result;
	coap_socket_t *sockets[64];
	unsigned int num_sockets = 0, i, timeout;

	coap_ticks(&before);

	timeout = coap_write(ctx, sockets,
			(unsigned int)(ARRAY_SIZE(sockets)),
			&num_sockets, before);

	if (timeout == 0 || timeout_ms < timeout)
		timeout = timeout_ms;

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);

	for (i = 0; i < num_sockets; i++) {
		if (sockets[i]->fd + 1 > nfds)
			nfds = sockets[i]->fd + 1;
		if (sockets[i]->flags & COAP_SOCKET_WANT_DATA)
			FD_SET(sockets[i]->fd, &readfds);
		if (sockets[i]->flags & COAP_SOCKET_WANT_WRITE)
			FD_SET(sockets[i]->fd, &writefds);
	}

	if (timeout > 0) {
		tv.tv_usec = (timeout % 1000) * 1000;
		tv.tv_sec = (long)(timeout/1000);
	}

	result = select(nfds, &readfds, &writefds, 0, timeout > 0 ? &tv : NULL);

	if (result < 0) {
		if (errno != EINTR) {
			log_err("select: %s", strerror(errno));
			return -1;
		}
	}

	if (result > 0) {
		for (i = 0; i < num_sockets; i++) {
			if ((sockets[i]->flags & COAP_SOCKET_WANT_DATA) &&
					FD_ISSET(sockets[i]->fd, &readfds))
				sockets[i]->flags |= COAP_SOCKET_HAS_DATA;
			if ((sockets[i]->flags & COAP_SOCKET_WANT_WRITE) &&
					FD_ISSET(sockets[i]->fd, &writefds))
				sockets[i]->flags |= COAP_SOCKET_CAN_WRITE;
		}
	}

	coap_ticks(&now);
	artik_coap_read(ctx, now);

	return (int)(((now - before) * 1000)/COAP_TICKS_PER_SECOND);
}

void coap_packet_get_memmapped(coap_data_t *packet, unsigned char **address,
				size_t *length)
{
	*address = packet->payload;
	*length = packet->length;
}

void coap_data_set_addr(coap_data_t *packet, const coap_address_t *src,
			const coap_address_t *dst)
{
	coap_address_copy(&packet->src, src);
	coap_address_copy(&packet->dst, dst);
}
