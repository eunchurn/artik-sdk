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
#include <stdio.h>

#include "coap_mem.h"

#ifdef COAP_MEMORY_TRACE

#undef malloc
#undef free
#undef strdup

typedef struct MemoryEntry {
	struct MemoryEntry *next;
	const char *file;
	const char *function;
	int         lineno;
	size_t      size;
	int         count;
	uint32_t    data[1];
} memory_entry_t;

static memory_entry_t prv_memory_malloc_list = {
	.next = NULL,
	.file = "head",
	.function = "malloc",
	.lineno = 0,
	.size = 0,
	.count = 0
};

static memory_entry_t prv_memory_free_list = {
	.next = NULL,
	.file = "head",
	.function = "free",
	.lineno = 0,
	.size = 0,
	.count = 0
};

static memory_entry_t *prv_memory_find_previous(memory_entry_t *list, void *memory)
{
	while (list->next != NULL) {
		if (list->next->data == memory)
			return list;

		list = list->next;
	}

	return NULL;
}

static void prv_trace_add_free_list(memory_entry_t *remove, const char *file,
				    const char *function, int lineno)
{
	remove->next = prv_memory_free_list.next;
	prv_memory_free_list.next = remove;
	remove->file = file;
	remove->function = function;
	remove->lineno = lineno;

	if (prv_memory_free_list.count < 200)
		++prv_memory_free_list.count;
	else if (remove->next != NULL) {
		while (remove->next->next != NULL)
			remove = remove->next;

		free(remove->next);
		remove->next = NULL;
	}
}

char *coap_trace_strdup(const char *str, const char *file,
			const char *function, int lineno)
{
	size_t length = strlen(str);
	char *result = coap_trace_malloc(length + 1, file, function, lineno);

	memcpy(result, str, length);
	result[length] = 0;

	return result;
}

void *coap_trace_malloc(size_t size, const char *file,
			const char *function, int lineno)
{
	static int counter = 0;
	memory_entry_t *entry = malloc(size + sizeof(memory_entry_t));

	entry->next = prv_memory_malloc_list.next;
	prv_memory_malloc_list.next = entry;
	++prv_memory_malloc_list.count;
	prv_memory_malloc_list.size += size;
	prv_memory_malloc_list.lineno = 1;

	entry->file = file;
	entry->function = function;
	entry->lineno = lineno;
	entry->size = size;
	entry->count = ++counter;

	return &(entry->data);
}

void *coap_trace_calloc(size_t num, size_t size, const char *file,
			const char *function, int lineno)
{
	static int counter = 0;
	memory_entry_t *entry = calloc(num, size + sizeof(memory_entry_t));

	entry->next = prv_memory_malloc_list.next;
	prv_memory_malloc_list.next = entry;
	++prv_memory_malloc_list.count;
	prv_memory_malloc_list.size += num*size;
	prv_memory_malloc_list.lineno = 1;

	entry->file = file;
	entry->function = function;
	entry->lineno = lineno;
	entry->size = num*size;
	entry->count = ++counter;

	return &(entry->data);
}

void coap_trace_free(void *mem, const char *file,
		     const char *function, int lineno)
{
	if (mem != NULL) {
		memory_entry_t *entry =
			prv_memory_find_previous(&prv_memory_malloc_list, mem);

		if (entry != NULL) {
			memory_entry_t *remove = entry->next;

			entry->next = remove->next;
			--prv_memory_malloc_list.count;
			prv_memory_malloc_list.size -= remove->size;
			prv_memory_malloc_list.lineno = 1;
			prv_trace_add_free_list(remove, file, function, lineno);
		} else {
			fprintf(stderr, "memory: free error (no malloc) %s, %d, %s\n",
				file, lineno, function);
			entry = prv_memory_find_previous(&prv_memory_free_list, mem);

			if (entry != NULL) {
				entry = entry->next;
				fprintf(stderr, "memory: already frees at %s, %d, %s\n",
					entry->file, entry->lineno, entry->function);
			}
		}
	}
}

void trace_print(int loops, int level)
{
	static int counter = 0;

	if (loops == 0)
		counter = 0;
	else
		++counter;

	if (loops == 0 || (((counter % loops) == 0)
		&& prv_memory_malloc_list.lineno)) {
		prv_memory_malloc_list.lineno = 0;

		if (level == 1) {
			size_t total = 0;
			int entries = 0;
			memory_entry_t *entry = prv_memory_malloc_list.next;

			while (entry != NULL) {
				fprintf(stdout, "memory: #%d, %lu bytes, %s, %d, %s\n",
					entry->count, (unsigned long)entry->size,
					entry->file, entry->lineno, entry->function);
				++entries;
				total += entry->size;
				entry = entry->next;
			}

			if (entries != prv_memory_malloc_list.count)
				fprintf(stderr, "memory: error %d entries != %d\n",
					prv_memory_malloc_list.count, entries);

			if (total != prv_memory_malloc_list.size)
				fprintf(stderr, "memory: error %lu total bytes !=%lu\n",
					(unsigned long)prv_memory_malloc_list.size,
					(unsigned long)total);

			fprintf(stdout, "memory: %d entries, %lu total bytes\n",
				prv_memory_malloc_list.count,
				(unsigned long)prv_memory_malloc_list.size);
		}
	}
}

void trace_status(int *blocks, size_t *size)
{
	if (blocks != NULL)
		*blocks = prv_memory_malloc_list.count;

	if (size != NULL)
		*size = prv_memory_malloc_list.size;
}

#endif
