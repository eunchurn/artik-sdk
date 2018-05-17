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

#define _GNU_SOURCE
#include "os_utils.h"

#include <pthread.h>
#include <regex.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "artik_list.h"
#include "artik_log.h"

#define NUMBER_NSUB 5
#define MAX_PORT UINT16_MAX

typedef struct {
	regex_t *preg;
	int nmatch;
	int count;
} artik_uri_t;

pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

artik_uri_t g_uri = { NULL, 0, 0 };

static artik_error init_uri_module(void)
{
	artik_error ret;
	int err;
	const char *regex =
		"([A-Za-z][A-Za-z0-9+.-]*)://([0-9A-Za-z.-]+)"
		"(:[0-9]+)?(/[0-9A-Za-z.-_~!$&'()*+,;=:@]*)?$";

	g_uri.preg = malloc(sizeof(regex_t));
	if (!g_uri.preg) {
		ret = E_NO_MEM;
		goto error;
	}

	err = regcomp(g_uri.preg, regex, REG_EXTENDED);
	if (err != 0) {
		log_dbg("regcomp failed with error code %d", err);
		ret = E_NOT_INITIALIZED;
		goto error;
	}

	g_uri.nmatch = g_uri.preg->re_nsub + 1;
	if (g_uri.nmatch != NUMBER_NSUB) {
		log_dbg("The number of parenthesized subexpressions must be equal to 5");
		ret = E_NOT_INITIALIZED;
		goto error;
	}

	return S_OK;

error:
	if (g_uri.preg)
		free(g_uri.preg);

	return ret;
}

static void clear_uri_module(void)
{
	regfree(g_uri.preg);
	g_uri.nmatch = 0;
	g_uri.preg = NULL;
}

static artik_error parse_uri(const char *uri, int default_port, artik_uri_info *uri_info)
{
	int err;
	artik_error ret;
	regmatch_t pmatch[NUMBER_NSUB];
	char port[6];
	char *p;

	memset(uri_info, 0, sizeof(artik_uri_info));

	err = regexec(g_uri.preg, uri, g_uri.nmatch, pmatch, 0);
	if (err != 0) {
		log_dbg("This '%s' is not a valid URI", uri);
		ret = E_BAD_ARGS;
		goto error;
	}

	uri_info->scheme = malloc(sizeof(char)*(pmatch[1].rm_eo - pmatch[1].rm_so + 1));
	if (!uri_info->scheme) {
		ret = E_NO_MEM;
		goto error;
	}

	uri_info->hostname = malloc(sizeof(char)*(pmatch[2].rm_eo - pmatch[2].rm_so + 1));
	if (!uri_info->hostname) {
		ret = E_NO_MEM;
		goto error;
	}

	if (pmatch[4].rm_eo - pmatch[4].rm_so > 0) {
		uri_info->path = malloc(sizeof(char)*(pmatch[4].rm_eo - pmatch[4].rm_so + 1));
		if (!uri_info->path) {
			return E_NO_MEM;
			goto error;
		}

		strncpy(uri_info->path, uri + pmatch[4].rm_so, pmatch[4].rm_eo - pmatch[4].rm_so);
		uri_info->path[pmatch[4].rm_eo - pmatch[4].rm_so] = '\0';
	} else {
		uri_info->path = strdup("/");
	}

	strncpy(uri_info->scheme, uri + pmatch[1].rm_so, pmatch[1].rm_eo - pmatch[1].rm_so);
	uri_info->scheme[pmatch[1].rm_eo - pmatch[1].rm_so] = '\0';
	strncpy(uri_info->hostname, uri + pmatch[2].rm_so, pmatch[2].rm_eo - pmatch[2].rm_so);
	uri_info->hostname[pmatch[2].rm_eo - pmatch[2].rm_so] = '\0';

	if (pmatch[3].rm_eo - pmatch[3].rm_so > 0) {
		if (pmatch[3].rm_eo - pmatch[3].rm_so >= sizeof(port)) {
			ret = E_BAD_ARGS;
			goto error;
		}

		strncpy(port, uri + pmatch[3].rm_so, pmatch[3].rm_eo - pmatch[3].rm_so);
		port[pmatch[3].rm_eo - pmatch[3].rm_so] = '\0';
		p = strtok(port, ":");
		if (!p) {
			ret = E_BAD_ARGS;
			goto error;
		}

		uri_info->port = atoi(p);

		if (uri_info->port > MAX_PORT) {
			ret = E_BAD_ARGS;
			goto error;
		}
	} else {
		uri_info->port = default_port;
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

artik_error os_get_uri_info(artik_uri_info *uri_info, const char *uri)
{
	artik_error ret;

	pthread_mutex_lock(&mutex);
	if (g_uri.count == 0) {
		log_dbg("initialized uri parser");
		ret = init_uri_module();
		g_uri.count++;
		if (ret != S_OK) {
			pthread_mutex_unlock(&mutex);
			return ret;
		}
	}
	pthread_mutex_unlock(&mutex);

	ret = parse_uri(uri, -1, uri_info);
	if (ret != S_OK)
		goto error;

	return S_OK;

error:
	pthread_mutex_lock(&mutex);
	g_uri.count--;
	if (g_uri.count == 0)
		clear_uri_module();
	pthread_mutex_unlock(&mutex);

	return ret;

}

artik_error os_free_uri_info(artik_uri_info *uri_info)
{
	free(uri_info->scheme);
	free(uri_info->hostname);
	free(uri_info->path);

	pthread_mutex_lock(&mutex);
	g_uri.count--;
	if (g_uri.count == 0)
		clear_uri_module();
	pthread_mutex_unlock(&mutex);

	return S_OK;
}
