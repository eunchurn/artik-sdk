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

#include "coap_resource.h"
#include "coap_subscribe.h"
#include "coap_uri.h"
#include "coap_mem.h"
#include "utlist.h"

#include <artik_log.h>

#include <er-coap-13.h>

#define MATCH_URI	0x01
#define MATCH_PREFIX	0x02
#define MATCH_SUBSTRING	0x04

#define min(a, b) ((a) < (b) ? (a) : (b))

#define COAP_PRINT_STATUS_MAX (~COAP_PRINT_STATUS_MASK)

#define PRINT_WITH_OFFSET(Buf, Offset, Char)	\
	do {					\
		if ((Offset) == 0) {		\
			(*(Buf)++) = (Char);	\
		} else {			\
			(Offset)--;		\
		}				\
	} while (0)

#define PRINT_COND_WITH_OFFSET(Buf, Bufend, Offset, Char, Result) {	\
	if ((Buf) < (Bufend)) {						\
		PRINT_WITH_OFFSET(Buf, Offset, Char);			\
	}								\
	(Result)++;							\
}

#define COPY_COND_WITH_OFFSET(Buf, Bufend, Offset, Str, Length, Result) {		\
	size_t i;									\
	for (i = 0; i < (Length); i++) {						\
		PRINT_COND_WITH_OFFSET((Buf), (Bufend), (Offset), (Str)[i], (Result));	\
	}										\
}

static int match(const coap_str *text, const coap_str *pattern, int match_prefix,
		int match_substring)
{
	if (text->length < pattern->length)
		return 0;

	if (match_substring) {
		unsigned char *next_token = text->s;
		size_t remaining_length = text->length;

		while (remaining_length) {
			size_t token_length;
			unsigned char *token = next_token;

			next_token = (unsigned char *)memchr(token, ' ', remaining_length);

			if (next_token) {
				token_length = next_token - token;
				remaining_length -= (token_length + 1);
				next_token++;
			} else {
				token_length = remaining_length;
				remaining_length = 0;
			}

			if ((match_prefix || pattern->length == token_length) &&
				memcmp(token, pattern->s, pattern->length) == 0)
				return 1;
		}
		return 0;
	}

	return (match_prefix || pattern->length == text->length) &&
		memcmp(text->s, pattern->s, pattern->length) == 0;
}

coap_subscription_t *coap_find_observer(coap_resource_t *resource,
			coap_session_t *session, const coap_str *token)
{
	coap_subscription_t *s;

	LL_FOREACH(resource->subscribers, s) {
		if (s->session == session &&
			(!token || (token->length == s->token_length
				&& memcmp(token->s, s->token, token->length) == 0)))
			return s;
	}

	return NULL;
}

int coap_delete_observer(coap_resource_t *resource, coap_session_t *session,
			const coap_str *token)
{
	coap_subscription_t *s;

	s = coap_find_observer(resource, session, token);

	if (resource->subscribers && s) {
		LL_DELETE(resource->subscribers, s);
		coap_session_release(session);
		coap_free(s);
	}

	return s != NULL;
}

void coap_delete_observers(struct coap_context_t *context, coap_session_t *session)
{
	RESOURCES_ITER(context->resources, resource) {
		coap_subscription_t *s, *tmp;

		LL_FOREACH_SAFE(resource->subscribers, s, tmp) {
			if (s->session == session) {
				LL_DELETE(resource->subscribers, s);
				coap_session_release(session);
				coap_free(s);
			}
		}
	}
}

void coap_touch_observer(struct coap_context_t *context, coap_session_t *session,
			const coap_str *token)
{
	coap_subscription_t *s;

	RESOURCES_ITER(context->resources, r) {
		s = coap_find_observer(r, session, token);
		if (s)
			s->fail_cnt = 0;
	}
}

void coap_remove_failed_observers(struct coap_context_t *context,
			coap_resource_t *resource,
			coap_session_t *session,
			const coap_str *token)
{
	coap_subscription_t *obs, *otmp;

	LL_FOREACH_SAFE(resource->subscribers, obs, otmp) {
		if (obs->session == session && token->length == obs->token_length &&
			memcmp(token->s, obs->token, token->length) == 0) {
			if (obs->fail_cnt < COAP_OBS_MAX_FAIL)
				obs->fail_cnt++;
			else {
				LL_DELETE(resource->subscribers, obs);
				obs->fail_cnt = 0;

				coap_cancel_all_messages(context,
					obs->session, obs->token,
					obs->token_length);
				coap_session_release(obs->session);
				coap_free(obs);
			}
			break;
		}
	}
}

void coap_handle_failed_notify(struct coap_context_t *context,
			coap_session_t *session,
			const coap_str *token)
{
	RESOURCES_ITER(context->resources, r) {
		coap_remove_failed_observers(context, r, session, token);
	}
}

static void coap_notify_observers(struct coap_context_t *context,
			coap_resource_t *r,
			coap_protocol_t proto)
{
	coap_method_handler_t h;
	coap_subscription_t *obs;
	coap_str token;
	coap_packet_t *response;


	if (r->observable && (r->dirty || r->partiallydirty)) {
		r->partiallydirty = 0;

		h = r->handler[COAP_GET - 1];

		LL_FOREACH(r->subscribers, obs) {
			if (r->dirty == 0 && obs->dirty == 0)
				continue;

			int tid = -1;

			obs->dirty = 0;

			response = (coap_packet_t *)coap_malloc(sizeof(coap_packet_t));

			if (!response) {
				obs->dirty = 1;
				r->partiallydirty = 1;
				log_err("Memory problem");
				return;
			}

			coap_init_message((void *)response, proto, COAP_TYPE_CON,
				0, 0);

			coap_set_header_token((void *)response,
				(uint8_t *)obs->token,
				(size_t)obs->token_length);

			token.length = obs->token_length;
			token.s = obs->token;

			response->mid = coap_new_message_id(obs->session);

			if ((r->flags & COAP_RESOURCE_FLAGS_NOTIFY_CON) == 0
				&& obs->non_cnt < COAP_OBS_MAX_NON)
				response->type = COAP_TYPE_NON;
			else
				response->type = COAP_TYPE_CON;

			coap_str *query = (coap_str *)obs->query;

			h(context, r, obs->session, NULL, &token, query,
				response);

			if (response->type == COAP_TYPE_CON)
				obs->non_cnt = 0;
			else
				obs->non_cnt++;

			tid = coap_send(obs->session, response);

			if (tid == -1) {
				log_err("%s: sending failed", __func__);
				obs->dirty = 1;
				r->partiallydirty = 1;
			}

			coap_free_header(response);
			coap_free(response->payload);

		}
		context->observe++;
	}
	r->dirty = 0;
}

void coap_check_notify(struct coap_context_t *context, coap_protocol_t proto)
{
	RESOURCES_ITER(context->resources, r) {
		coap_notify_observers(context, r, proto);
	}
}

coap_resource_t *coap_resource_init(const unsigned char *uri, size_t len, int flags)
{
	coap_resource_t *r;

	r = (coap_resource_t *)coap_malloc(sizeof(coap_resource_t));

	if (r) {
		memset(r, 0, sizeof(coap_resource_t));

		r->uri.s = (unsigned char *)uri;
		r->uri.length = len;

		coap_hash_path(r->uri.s, r->uri.length, r->key);

		r->flags = flags;
	} else
		log_err("%s: no memory left", __func__);

	return r;
}

coap_attr_t *coap_add_attr(
		coap_resource_t *resource,
		const unsigned char *name, size_t nlen,
		const unsigned char *val, size_t vlen,
		int flags)
{
	coap_attr_t *attr;

	if (!resource || !name)
		return NULL;

	attr = (coap_attr_t *)coap_malloc(sizeof(coap_attr_t));

	if (attr) {
		attr->name.length = nlen;
		attr->value.length = val ? vlen : 0;

		attr->name.s = (unsigned char *)name;
		attr->value.s = (unsigned char *)val;

		attr->flags = flags;

		LL_PREPEND(resource->link_attr, attr);
	} else
		log_err("coap_add_attr: no memory left");

	return attr;
}

coap_attr_t *coap_find_attr(coap_resource_t *resource,
	const unsigned char *name, size_t nlen)
{
	coap_attr_t *attr;

	if (!resource || !name)
		return NULL;

	LL_FOREACH(resource->link_attr, attr) {
		if (attr->name.length == nlen &&
			memcmp(attr->name.s, name, nlen) == 0)
			return attr;
	}

	return NULL;
}

void coap_hash_request_uri(const coap_packet_t *request, coap_key_t key)
{
	multi_option_t *p_uri = NULL;

	memset(key, 0, sizeof(coap_key_t));

	if (request) {
		for (p_uri = request->uri_path; p_uri != NULL; p_uri = p_uri->next)
			coap_hash(p_uri->data, p_uri->len, key);
	}
}

void coap_add_resource(struct coap_context_t *context, coap_resource_t *resource)
{
	RESOURCES_ADD(context->resources, resource);
}

coap_resource_t *coap_get_resource_from_key(struct coap_context_t *context, coap_key_t key)
{
	coap_resource_t *result;

	RESOURCES_FIND(context->resources, key, result);

	return result;
}

coap_print_status_t coap_print_link(
		const coap_resource_t *resource,
		unsigned char *buf,
		size_t *len,
		size_t *offset)
{
	unsigned char *p = buf;
	const unsigned char *bufend = buf + *len;
	coap_attr_t *attr;
	coap_print_status_t result = 0;
	size_t output_length = 0;
	const size_t old_offset = *offset;

	*len = 0;

	PRINT_COND_WITH_OFFSET(p, bufend, *offset, '<', *len);
	PRINT_COND_WITH_OFFSET(p, bufend, *offset, '/', *len);

	COPY_COND_WITH_OFFSET(p, bufend, *offset,
		resource->uri.s, resource->uri.length, *len);

	PRINT_COND_WITH_OFFSET(p, bufend, *offset, '>', *len);

	LL_FOREACH(resource->link_attr, attr) {

		PRINT_COND_WITH_OFFSET(p, bufend, *offset, ';', *len);

		COPY_COND_WITH_OFFSET(p, bufend, *offset,
			attr->name.s, attr->name.length, *len);

		if (attr->value.s) {
			PRINT_COND_WITH_OFFSET(p, bufend, *offset, '=', *len);

			COPY_COND_WITH_OFFSET(p, bufend, *offset,
				attr->value.s, attr->value.length, *len);
		}
	}

	if (resource->observable)
		COPY_COND_WITH_OFFSET(p, bufend, *offset, ";obs", 4, *len);

	output_length = p - buf;

	if (output_length > COAP_PRINT_STATUS_MAX)
		return COAP_PRINT_STATUS_ERROR;

	result = (coap_print_status_t)output_length;

	if (result + old_offset - *offset < *len)
		result |= COAP_PRINT_STATUS_TRUNC;

	return result;
}

coap_print_status_t coap_print_wellknown(
		struct coap_context_t *context,
		unsigned char *buf,
		size_t *buflen,
		size_t offset,
		multi_option_t *query_filter)
{
	size_t output_length = 0;
	unsigned char *p = buf;
	const unsigned char *bufend = buf + *buflen;
	size_t left, written = 0;
	coap_print_status_t result;
	const size_t old_offset = offset;
	int subsequent_resource = 0;
	coap_str resource_param = {0, NULL}, query_pattern = {0, NULL};
	int flags = 0;
	static const coap_str _rt_attributes[] = {
		{2, (unsigned char *)"rt"},
		{2, (unsigned char *)"if"},
		{2, (unsigned char *)"rel"},
		{0, NULL}
	};

	if (query_filter) {
		resource_param.s = query_filter->data;

		if (resource_param.s) {
			while (resource_param.length <
				query_filter->len
				&& resource_param.s[resource_param.length] != '=')
				resource_param.length++;

			if (resource_param.length < query_filter->len) {
				const coap_str *rt_attributes;

				if (resource_param.length == 4 &&
					memcmp(resource_param.s, "href", 4) == 0)
					flags |= MATCH_URI;

				for (rt_attributes = _rt_attributes; rt_attributes->s;
					rt_attributes++) {
					if (resource_param.length == rt_attributes->length &&
						memcmp(resource_param.s, rt_attributes->s,
							rt_attributes->length) == 0) {
						flags |= MATCH_SUBSTRING;
						break;
					}
				}

				query_pattern.s = query_filter->data +
					resource_param.length + 1;

				query_pattern.length =
					query_filter->len -
					(resource_param.length + 1);

				if ((query_pattern.s[0] == '/') &&
						((flags & MATCH_URI) == MATCH_URI)) {
					query_pattern.s++;
					query_pattern.length--;
				}

				if (query_pattern.length &&
					query_pattern.s[query_pattern.length-1] == '*') {
					query_pattern.length--;
					flags |= MATCH_PREFIX;
				}
			}
		}
	}

	RESOURCES_ITER(context->resources, r) {

		if (resource_param.length) {
			if (flags & MATCH_URI) {
				if (!match(&r->uri, &query_pattern,
					(flags & MATCH_PREFIX) != 0,
					(flags & MATCH_SUBSTRING) != 0))
					continue;
			} else {
				coap_attr_t *attr;
				coap_str unquoted_val;

				attr = coap_find_attr(r, resource_param.s, resource_param.length);

				if (!attr)
					continue;
				if (attr->value.s[0] == '"') {
					unquoted_val.length = attr->value.length - 2;
					unquoted_val.s = attr->value.s + 1;
				} else {
					unquoted_val = attr->value;
				}

				if (!(match(&unquoted_val, &query_pattern,
					(flags & MATCH_PREFIX) != 0,
					(flags & MATCH_SUBSTRING) != 0)))
					continue;
			}
		}

		if (!subsequent_resource)
			subsequent_resource = 1;
		else
			PRINT_COND_WITH_OFFSET(p, bufend, offset, ',', written);

		left = bufend - p;
		result = coap_print_link(r, p, &left, &offset);

		if (result & COAP_PRINT_STATUS_ERROR)
			break;

		p += COAP_PRINT_OUTPUT_LENGTH(result);
		written += left;
	}

	*buflen = written;
	output_length = p - buf;

	if (output_length > COAP_PRINT_STATUS_MAX)
		return COAP_PRINT_STATUS_ERROR;

	result = (coap_print_status_t)output_length;

	if (result + old_offset - offset < *buflen)
		result |= COAP_PRINT_STATUS_TRUNC;

	return result;
}

coap_subscription_t *coap_add_observer(
		coap_resource_t *resource,
		coap_session_t *session,
		const coap_str *token,
		coap_str *query)
{
	coap_subscription_t *s = NULL;

	s = coap_find_observer(resource, session, token);

	if (s) {
		if (s->query)
			coap_free(s->query);
		s->query = query;
		return s;
	}

	s = (coap_subscription_t *)coap_malloc(sizeof(coap_subscription_t));

	if (!s) {
		if (query)
			coap_free(query);
		return NULL;
	}

	coap_subscription_init(s);
	s->session = coap_session_reference(session);

	if (token && token->length) {
		s->token_length = token->length;
		memcpy(s->token, token->s, min(s->token_length, 8));
	}

	s->query = query;

	LL_PREPEND(resource->subscribers, s);

	return s;
}

int coap_resource_set_dirty(coap_resource_t *r, const coap_str *query)
{
	if (!r->observable)
		return 0;

	if (query) {
		coap_subscription_t *obs;
		int found = 0;

		LL_FOREACH(r->subscribers, obs) {
			if (obs->query && obs->query->length == query->length
					&& memcmp(obs->query->s, query->s, query->length) == 0) {
				found = 1;
				if (!r->dirty && !obs->dirty) {
					obs->dirty = 1;
					r->partiallydirty = 1;
				}
			}
		}

		if (!found)
			return 0;
	} else
		r->dirty = 1;

	return 1;
}

void coap_register_handler(coap_resource_t *resource,
			unsigned char method,
			coap_method_handler_t handler)
{
	resource->handler[method-1] = handler;
}

void coap_delete_attr(coap_attr_t *attr)
{
	if (!attr)
		return;
	if (attr->flags & COAP_ATTR_FLAGS_RELEASE_NAME)
		coap_free(attr->name.s);
	if (attr->flags & COAP_ATTR_FLAGS_RELEASE_VALUE)
		coap_free(attr->value.s);

	coap_free(attr);
}

void coap_free_resource(coap_resource_t *resource)
{
	coap_attr_t *attr, *tmp;
	coap_subscription_t *obs, *otmp;

	LL_FOREACH_SAFE(resource->link_attr, attr, tmp) {
		coap_delete_attr(attr);
	}

	if (resource->flags & COAP_RESOURCE_FLAGS_RELEASE_URI)
		coap_free(resource->uri.s);

	LL_FOREACH_SAFE(resource->subscribers, obs, otmp) {
		coap_session_release(obs->session);
		coap_free(obs);
	}

	coap_free(resource);
}

void coap_delete_all_resources(struct coap_context_t *context)
{
	coap_resource_t *res;
	coap_resource_t *rtmp;

	LL_FOREACH_SAFE(context->resources, res, rtmp) {
		coap_free_resource(res);
	}

	context->resources = NULL;
}
