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

#include <stdlib.h>

#ifndef COAP_MEMORY_TRACE

void *coap_calloc(size_t n, size_t s);

void *coap_malloc(size_t s);

void coap_free(void *p);

char *coap_strdup(const char *str);

#else

char *coap_trace_strdup(const char *str, const char *file, const char *function, int lineno);

void *coap_trace_malloc(size_t size, const char *file, const char *function, int lineno);

void *coap_trace_calloc(size_t num, size_t size, const char *file, const char *function, int lineno);

void coap_trace_free(void *mem, const char *file, const char *function, int lineno);

#define coap_strdup(S) coap_trace_strdup(S, __FILE__, __func__, __LINE__)

#define coap_malloc(S) coap_trace_malloc(S, __FILE__, __func__, __LINE__)

#define coap_calloc(N, S) coap_trace_calloc(N, S, __FILE__, __func__, __LINE__)

#define coap_free(M) coap_trace_free(M, __FILE__, __func__, __LINE__)

#endif
