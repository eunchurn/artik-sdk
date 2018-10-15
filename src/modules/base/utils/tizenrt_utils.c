/*
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#include "os_utils.h"

#include <ctype.h>
#include <stddef.h>
#include <string.h>

#include <artik_log.h>

#define PORT_MIN 1
#define PORT_MAX 65535

typedef struct {
	const char *begin;
	const char *end;
} range_t;

typedef enum {
	URI_SCHEME_START,
	URI_SCHEME_LOOP,
	URI_HOST,
	URI_PORT,
	URI_PATH
} uri_state_e;

artik_error os_get_uri_info(artik_uri_info *uri_info, const char *uri)
{
	size_t len = strlen(uri);
	range_t scheme = { NULL, NULL };
	range_t host = { NULL, NULL };
	range_t port = { NULL, NULL };
	range_t path = { NULL, NULL };
	uri_state_e state = URI_SCHEME_START;
	int i;
	artik_error ret;

	for (i = 0; i < len; i++) {
		char c = uri[i];

		switch (state) {
		case URI_SCHEME_START:
			/* An URI scheme must start with a letter */
			if (!isalpha(c))
				return E_BAD_ARGS;

			state = URI_SCHEME_LOOP;
			scheme.begin = uri + i;
		case URI_SCHEME_LOOP:
			/*
			 * The first letter of an URI scheme is followed
			 * by any combination of letters, digits, plus ("+"),
			 * period (".") or hypen ("-")
			 */
			if (!isalnum(c) && c != '+' && c != '.' && c != '-')
				return E_BAD_ARGS;

			/* We match only URI with authority (with host and optional port but no userinfo) */
			if (uri[i+1] == ':' && uri[i+2] == '/' && uri[i+3] == '/') {
				scheme.end = uri + i;
				host.begin = scheme.end + 4;
				state = URI_HOST;
				i += 3;
			}
			break;

		case URI_HOST:
			/* Do not support IPv6 format */
			if (!isalnum(c) && c != '.' && c != '-')
				return E_BAD_ARGS;

			host.end = uri + i;
			if (uri[i + 1] == ':') {
				state = URI_PORT;
				port.begin = uri + i + 2;
				i += 1;
			}

			if (uri[i + 1] == '/') {
				state = URI_PATH;
				path.begin = uri + i + 1;
				path.end = uri + len + 1;
			}
			break;

		case URI_PORT:
			if (!isdigit(c))
				return E_BAD_ARGS;

			port.end = uri + i;
			if (uri[i + 1] == '/') {
				state = URI_PATH;
				path.begin = uri + i + 1;
				path.end = uri + len + 1;
			}
			break;

		case URI_PATH:
			if (!isalnum(c) && c != '-' && c != '.' && c != '_' && c != '~'
				&& c != '!' && c != '$' && c != '&' && c != '/' && c != '('
				&& c != ')' && c != '*' && c != '+' && c != ',' && c != ';'
				&& c != '=' && c != ':' && c != '@' && c != '?' ) {
				return E_BAD_ARGS;
			}
			break;
		}
	}

	if (state == URI_SCHEME_START || state == URI_SCHEME_LOOP)
		return E_BAD_ARGS;

	if (!host.begin || !host.end || !scheme.begin || !scheme.end)
		return E_BAD_ARGS;

	uri_info->scheme = strndup(scheme.begin, scheme.end - scheme.begin + 1);
	uri_info->hostname = strndup(host.begin, host.end - host.begin + 1);

	if (path.begin && path.end && (path.begin != path.end))
		uri_info->path = strndup(path.begin, path.end - path.begin);
	else
		uri_info->path = strdup("/");

	if (!uri_info->scheme || !uri_info->hostname || !uri_info->path) {
		ret = E_NO_MEM;
		goto error;
	}

	if (port.begin && port.end) {
		uri_info->port = strtol(port.begin, NULL, 10);

		if (uri_info->port <= PORT_MIN || uri_info->port >= PORT_MAX) {
			ret = E_BAD_ARGS;
			goto error;
		}
	} else {
		uri_info->port = -1;
	}

	log_dbg("For uri %s", uri);
	log_dbg("port = %d", uri_info->port);
	log_dbg("scheme = %s", uri_info->scheme);
	log_dbg("hostname = %s", uri_info->hostname);
	log_dbg("path = %s", uri_info->path);

	return S_OK;

error:
	if (uri_info->scheme)
		free(uri_info->scheme);

	if (uri_info->hostname)
		free(uri_info->hostname);

	if (uri_info->path)
		free(uri_info->path);

	return ret;
}

artik_error os_free_uri_info(artik_uri_info *uri_info)
{
	free(uri_info->scheme);
	free(uri_info->hostname);
	free(uri_info->path);

	return S_OK;
}
