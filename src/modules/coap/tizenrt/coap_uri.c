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

#include "coap_uri.h"
#include "coap.h"
#include "hashkey.h"

typedef void (*segment_handler_t)(unsigned char *, size_t, void *);

static unsigned char *strnchr(unsigned char *s, size_t len, unsigned char c)
{
	while (len && *s++ != c)
		--len;

	return len ? s : NULL;
}

int artik_coap_split_uri(const unsigned char *uri, size_t len, coap_uri *u)
{
	const unsigned char *p, *q;
	int res = 0;

	if (!uri || !u)
		return -1;

	memset(u, 0, sizeof(coap_uri));
	u->port = COAP_DEFAULT_PORT;

	p = uri;

	if (*p == '/') {
		q = p;
		goto path;
	}

	q = (unsigned char *)COAP_DEFAULT_SCHEME;

	while (len && *q && ISEQUAL_CI(*p, *q)) {
		++p; ++q; --len;
	}

	if (*q) {
		res = -1;
		goto error;
	}

	if (len && (*p == 's')) {
		++p; --len;
		u->secure = true;
		u->port = COAPS_DEFAULT_PORT;
	} else
		u->secure = false;

	q = (unsigned char *)"://";

	while (len && *q && *p == *q) {
		++p; ++q; --len;
	}

	if (*q) {
		res = -2;
		goto error;
	}

	q = p;

	if (len && *p == '[') {
		++p;

		while (len && *q != ']') {
			++q; --len;
		}

		if (!len || *q != ']' || p == q) {
			res = -3;
			goto error;
		}

		COAP_SET_STR(&u->host, q - p, (unsigned char *)p);

		++q; --len;
	} else {

		while (len && *q != ':' && *q != '/' && *q != '?') {
			++q;
			--len;
		}

		if (p == q) {
			res = -3;
			goto error;
		}

		COAP_SET_STR(&u->host, q - p, (unsigned char *)p);
	}

	if (len && *q == ':') {
		p = ++q;
		--len;

		while (len && isdigit(*q)) {
			++q;
			--len;
		}

		if (p < q) {
			int uri_port = 0;

			while (p < q)
				uri_port = uri_port * 10 + (*p++ - '0');

			if (uri_port > 65535) {
				res = -4;
				goto error;
			}

			u->port = (unsigned short)uri_port;
		}
	}

path:
	if (!len)
		goto end;

	if (*q == '/') {
		p = ++q;
		--len;

		while (len && *q != '?') {
			++q; --len;
		}

		if (p < q) {
			COAP_SET_STR(&u->path, q - p, (unsigned char *)p)
			p = q;
		}
	}

	if (len && *p == '?') {
		++p;
		--len;
		COAP_SET_STR(&u->query, len, (unsigned char *)p);
		len = 0;
	}

end:
	if (u->host.s && u->host.length > 0) {
		int u_len = 0;

		u_len = u->host.length;
		u->host.s[u_len] = '\0';
	}
	if (u->path.s && u->path.length > 0) {
		int u_len = 0;

		u_len = u->path.length;
		u->path.s[u_len] = '\0';
	}
	if (u->query.s && u->query.length > 0) {
		int u_len = 0;

		u_len = u->query.length;
		u->query.s[u_len] = '\0';
	}
	return len ? -1 : 0;

error:
	return res;
}

static int dots(unsigned char *s, size_t len)
{
	return *s == '.' && (len == 1 || (*(s+1) == '.' && len == 2));
}

static size_t coap_split_path_impl(const unsigned char *s, size_t length,
		segment_handler_t h, void *data)
{
	const unsigned char *p, *q;

	p = q = s;

	while (length > 0 && !strnchr((unsigned char *)"?#", 2, *q)) {

		if (*q == '/') {
			if (!dots((unsigned char *)p, q - p))
				h((unsigned char *)p, q - p, data);

			p = q + 1;
		}

		q++;
		length--;
	}


	if (!dots((unsigned char *)p, q - p))
		h((unsigned char *)p, q - p, data);

	return q - s;
}

void hash_segment(unsigned char *s, size_t len, void *data)
{
	coap_hash(s, (unsigned int)len, (unsigned char *)data);
}

int artik_coap_hash_path(const unsigned char *path, size_t len, coap_key_t key)
{
	if (!path)
		return 0;

	memset(key, 0, sizeof(coap_key_t));

	coap_split_path_impl(path, len, hash_segment, key);

	return 1;
}
