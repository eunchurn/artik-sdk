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

#include "coap_address.h"

#include <artik_log.h>

#define IN6_IS_ADDR_MULTICAST(_Address) ((_Address)->s6_addr[0] == 0xFF)

void coap_address_init(coap_address_t *addr)
{
	memset(addr, 0, sizeof(coap_address_t));
}

void coap_address_copy(coap_address_t *dst, const coap_address_t *src)
{
	memset(dst, 0, sizeof(coap_address_t));
	dst->size = src->size;

	if (src->addr.sa.sa_family == AF_INET6) {
		dst->addr.sin6.sin6_family = src->addr.sin6.sin6_family;
		dst->addr.sin6.sin6_addr = src->addr.sin6.sin6_addr;
		dst->addr.sin6.sin6_port = src->addr.sin6.sin6_port;
		dst->addr.sin6.sin6_scope_id = src->addr.sin6.sin6_scope_id;
	} else if (src->addr.sa.sa_family == AF_INET)
		dst->addr.sin = src->addr.sin;
	else
		memcpy(&dst->addr, &src->addr, src->size);
}

int coap_is_mcast(const coap_address_t *a)
{
	if (!a)
		return 0;

	switch (a->addr.sa.sa_family) {
	case AF_INET:
		return IN_MULTICAST(ntohl(a->addr.sin.sin_addr.s_addr));
	case AF_INET6:
		return IN6_IS_ADDR_MULTICAST(&a->addr.sin6.sin6_addr);
	default:
		break;
	}

	return 0;
}

int coap_address_isany(const coap_address_t *a)
{
	switch (a->addr.sa.sa_family) {
	case AF_INET:
		return a->addr.sin.sin_addr.s_addr == INADDR_ANY;
	case AF_INET6:
		return memcmp(&in6addr_any,
			&a->addr.sin6.sin6_addr,
			sizeof(in6addr_any)) == 0;
	default:
		break;
	}

	return 0;
}

int coap_address_equals(const coap_address_t *a, const coap_address_t *b)
{
	if (a->size != b->size || a->addr.sa.sa_family != b->addr.sa.sa_family)
		return 0;

	switch (a->addr.sa.sa_family) {
	case AF_INET:
		return
			a->addr.sin.sin_port == b->addr.sin.sin_port &&
			memcmp(&a->addr.sin.sin_addr, &b->addr.sin.sin_addr,
				sizeof(struct in_addr)) == 0;
	case AF_INET6:
		return
			a->addr.sin6.sin6_port == b->addr.sin6.sin6_port &&
			memcmp(&a->addr.sin6.sin6_addr, &b->addr.sin6.sin6_addr,
				sizeof(struct in6_addr)) == 0;
	default:
		break;
	}

	return 0;
}
