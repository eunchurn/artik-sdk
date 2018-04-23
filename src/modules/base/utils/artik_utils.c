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

static artik_error get_uri_info(artik_uri_info *uri_info, const char *uri);
static artik_error free_uri_info(artik_uri_info *uri_info);

EXPORT_API const artik_utils_module utils_module = {
	get_uri_info,
	free_uri_info,
};

artik_error get_uri_info(artik_uri_info *uri_info, const char *uri)
{
	if (!uri || !uri_info)
		return E_BAD_ARGS;

	return os_get_uri_info(uri_info, uri);
}

artik_error free_uri_info(artik_uri_info *uri_info)
{
	if (!uri_info)
		return E_BAD_ARGS;

	return os_free_uri_info(uri_info);
}
