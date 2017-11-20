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

#ifndef COAP_SOCKET_H_
#define COAP_SOCKET_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "coap_address.h"

struct coap_session_t;
struct coap_context_t;
struct coap_queue_t;

#define COAP_RXBUFFER_SIZE 1472

typedef struct coap_socket_t {
	int fd;
	uint16_t flags;
} coap_socket_t;

typedef struct {
	coap_address_t src;
	coap_address_t dst;
	int ifindex;
	size_t length;
	unsigned char payload[COAP_RXBUFFER_SIZE];
} coap_data_t;

typedef enum {
	COAP_NACK_TOO_MANY_RETRIES,
	COAP_NACK_NOT_DELIVERABLE,
	COAP_NACK_RST,
	COAP_NACK_TLS_FAILED
} coap_nack_reason_t;

#define COAP_SOCKET_EMPTY       0x0000  /**< the socket is not used */
#define COAP_SOCKET_NOT_EMPTY   0x0001  /**< the socket is not empty */
#define COAP_SOCKET_BOUND       0x0002  /**< the socket is bound */
#define COAP_SOCKET_CONNECTED   0x0004  /**< the socket is connected */
#define COAP_SOCKET_WANT_DATA   0x0010  /**< non blocking socket is waiting for reading */
#define COAP_SOCKET_WANT_WRITE  0x0020  /**< non blocking socket is waiting for writing */
#define COAP_SOCKET_HAS_DATA    0x0100  /**< non blocking socket can now read without blocking */
#define COAP_SOCKET_CAN_WRITE   0x0200  /**< non blocking socket can now write without blocking */

int coap_network_send(
	coap_socket_t *sock,
	const struct coap_session_t *session,
	const uint8_t *data,
	size_t datalen);

int coap_network_read(coap_socket_t *sock, coap_data_t *packet);

int coap_socket_bind_udp(
	coap_socket_t *sock,
	const coap_address_t *listen_addr,
	coap_address_t *bound_addr);

int coap_socket_connect_udp(coap_socket_t *sock,
	const coap_address_t *local_if,
	const coap_address_t *server,
	int default_port,
	coap_address_t *local_addr,
	coap_address_t *remote_addr);

void coap_packet_get_memmapped(coap_data_t *paclet, unsigned char **address,
				size_t *length);

void coap_data_set_addr(coap_data_t *packet, const coap_address_t *src,
			const coap_address_t *dst);

int coap_run_once(struct coap_context_t *ctx, unsigned int timeout_ms);

#endif /* COAP_SOCKET_H_ */
