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

#ifndef _COAP_RESOURCE_H
#define _COAP_RESOURCE_H

#include "coap.h"
#include "coap_uri.h"
#include "coap_subscribe.h"
#include "hashkey.h"

#include <er-coap-13.h>

struct coap_resource_t;
struct coap_context_t;

typedef void (*coap_method_handler_t)
	(struct coap_context_t *context,
	struct coap_resource_t *resource,
	coap_session_t *session,
	coap_packet_t *packet,
	coap_str *token,
	coap_str *query,
	coap_packet_t *response);

#define COAP_ATTR_FLAGS_RELEASE_NAME	0x1
#define COAP_ATTR_FLAGS_RELEASE_VALUE	0x2

typedef struct coap_attr_t {
	struct coap_attr_t *next;
	coap_str name;
	coap_str value;
	int flags;
} coap_attr_t;

#define COAP_RESOURCE_FLAGS_RELEASE_URI	0x1
#define COAP_RESOURCE_FLAGS_NOTIFY_NON	0x0
#define COAP_RESOURCE_FLAGS_NOTIFY_CON	0x2

typedef struct coap_resource_t {
	unsigned int dirty:1;
	unsigned int partiallydirty:1;

	unsigned int observable:1;
	unsigned int cacheable:1;

	coap_method_handler_t handler[7];

	coap_key_t key;

	struct coap_resource_t *next;

	coap_attr_t *link_attr;
	coap_subscription_t *subscribers;

	coap_str uri;
	int flags;
} coap_resource_t;

typedef unsigned int coap_print_status_t;

#define COAP_PRINT_STATUS_MASK  0xF0000000u
#define COAP_PRINT_OUTPUT_LENGTH(v) ((v) & ~COAP_PRINT_STATUS_MASK)
#define COAP_PRINT_STATUS_ERROR 0x80000000u
#define COAP_PRINT_STATUS_TRUNC 0x40000000u

void coap_register_handler(coap_resource_t *resource,
			unsigned char method,
			coap_method_handler_t handler);

coap_subscription_t *coap_find_observer(coap_resource_t *resource,
			coap_session_t *session,
			const coap_str *token);

void coap_delete_observers(struct coap_context_t *context,
			coap_session_t *session);

int coap_delete_observer(coap_resource_t *resource,
			coap_session_t *session,
			const coap_str *token);

void coap_touch_observer(struct coap_context_t *context,
			coap_session_t *session,
			const coap_str *token);

void coap_remove_failed_observers(struct coap_context_t *context,
			coap_resource_t *resource,
			coap_session_t *session,
			const coap_str *token);

void coap_handle_failed_notify(struct coap_context_t *context,
			coap_session_t *session,
			const coap_str *token);

void coap_check_notify(struct coap_context_t *context, coap_protocol_t proto);

coap_resource_t *coap_resource_init(const unsigned char *uri, size_t len, int flags);

coap_attr_t *coap_add_attr(
			coap_resource_t *resource,
			const unsigned char *name, size_t nlen,
			const unsigned char *val, size_t vlen,
			int flags);

void coap_hash_request_uri(const coap_packet_t *request, coap_key_t key);

void coap_add_resource(struct coap_context_t *context, coap_resource_t *resource);

coap_resource_t *coap_get_resource_from_key(struct coap_context_t *context, coap_key_t key);

coap_print_status_t coap_print_link(
			const coap_resource_t *resource,
			unsigned char *buf,
			size_t *len,
			size_t *offset);

coap_print_status_t coap_print_wellknown(
			struct coap_context_t *context,
			unsigned char *buf,
			size_t *buflen,
			size_t offset,
			multi_option_t *query_filter);

coap_subscription_t *coap_add_observer(
		coap_resource_t *resource,
		coap_session_t *session,
		const coap_str *token,
		coap_str *query);

int coap_resource_set_dirty(coap_resource_t *r, const coap_str *query);

void coap_delete_attr(coap_attr_t *attr);

void coap_free_resource(coap_resource_t *resource);

void coap_delete_all_resources(struct coap_context_t *context);

#define RESOURCES_ITER(r, tmp)		\
	struct coap_resource_t *tmp;	\
	LL_FOREACH((r), tmp)

#define RESOURCES_ADD(r, obj) \
	LL_PREPEND((r), (obj))

#define RESOURCES_FIND(r, k, res) {					\
	coap_resource_t *tmp;						\
	(res) = tmp = NULL;						\
	LL_FOREACH((r), tmp) {						\
		if (memcmp((k), tmp->key, sizeof(coap_key_t)) == 0) {	\
			(res) = tmp;					\
			break;						\
		}							\
	}								\
}

#endif
