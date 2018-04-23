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

#ifndef __ARTIK_UTILS_H_
#define __ARTIK_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "artik_error.h"

/*!
 * \brief The \ref artik_uri_info represents an URI.
 *
 * This structure contains the elements that reperesents an URI of the
 * following format:
 * \verbatim scheme://hostname:[port]/path \endverbatim
 */
typedef struct {
	char *scheme; /**< The URI scheme */
	char *hostname; /**< The URI hostname */
	int port; /**< The optional URI port (-1 when this component is absent)*/
	char *path; /**< The URI path */
} artik_uri_info;

/*! \struct artik_utils_module
 *
 * \brief Utils module operation
 *
 * Structure containing all the exposed operations by the Utils module.
 */
typedef struct {
	/**
	 * Fill \a uri_info by parsing \a uri.
	 *
	 * The \a uri must be of the following format:
	 * \verbatim scheme://hostname:[port]/path \endverbatim
	 *
	 * \param[out] uri_info
	 * \param[in] uri The URI to be parse.
	 * \return S_OK on success, otherwise a negative error value.
	 */
	artik_error(*get_uri_info)(artik_uri_info * uri_info, const char *uri);
	/**
	 * Free the \a uri_info previously filled by \ref get_uri_info
	 *
	 * \param[in] uri_info Pointer of \ref artik_uri_info structure.
	 * \return S_OK on success, otherwise a negative error value.
	 */
	artik_error(*free_uri_info)(artik_uri_info * uri_info);
} artik_utils_module;

extern const artik_utils_module utils_module;

#ifdef __cplusplus
}
#endif
#endif /* __ARTIK_UTILS_H_ */
