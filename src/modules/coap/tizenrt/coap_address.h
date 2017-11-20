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

#ifndef COAP_ADDRESS_H_
#define COAP_ADDRESS_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

typedef struct {
	socklen_t size;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} addr;
} coap_address_t;

void coap_address_init(coap_address_t *addr);

void coap_address_copy(coap_address_t *dst, const coap_address_t *src);

int coap_is_mcast(const coap_address_t *a);

int coap_address_isany(const coap_address_t *a);

int coap_address_equals(const coap_address_t *a, const coap_address_t *b);

#endif /* COAP_ADDRESS_H_ */
