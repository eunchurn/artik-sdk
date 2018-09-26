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

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include <artik_module.h>
#include <artik_loop.h>

# define DEFAULT_MESSAGE "ARTIK SDK Loop example."

typedef void (*interactive_command_callback_t)(int argc, char **argv, artik_loop_module *loop);

typedef struct {
	const char *cmd;
	interactive_command_callback_t callback;
} interactive_command_t;

static unsigned int string_to_positive_integer(const char * const buff, int *dst, const char * const option_name)
{
	if (!buff) {
		fprintf(stdout, "Invalid buffer which is empty for '%s'.\n", option_name);
		return 0;
	}
	char *nbuff = NULL;

	*dst = strtol(buff, &nbuff, 10);
	if (nbuff[0] != 0 ||
		(errno != 0 && *dst == 0) ||
		(errno == ERANGE)) {
		fprintf(stdout, "Invalid '%s' base definition, it should be an integer of base 10.\n", option_name);
		return 0;
	}
	return 1;
}

static void usage(void)
{
	printf("Usage: loop-example [options]\n"
		   " Options:\n"
		   "  -m <message> Message to display to the terminal. (default \"ARTIK SDK Loop example\")\n"
		   "  -n <sec>     Number of seconds for each interval. (default 1)\n"
		   "  -h           Display this help and exit.\n");
}

static int on_signal_cb(void *user_data)
{
	artik_loop_module *loop = (artik_loop_module *)user_data;

	fprintf(stdout, "\rQuit loop example.\n");
	loop->quit();
	return 1;
}

static int on_periodic_cb(void *user_data)
{
	const char * const message = (const char * const)user_data;

	fprintf(stdout, "[>loop example<][> %s <]\n", message);
	return 1;
}

static artik_error init(int *periodicid, int *signalid, artik_loop_module *loop,
						int interval, const char * const message)
{
	artik_error res = S_OK;

	res = loop->add_periodic_callback(periodicid, interval * 1000, on_periodic_cb, (void *)message);
	if (res == S_OK)
		res = loop->add_signal_watch(SIGINT, on_signal_cb, (void *)loop, signalid);
	return res;
}

static int parse_arguments(int argc, char **argv,
						   char **message, int *interval)
{
	int c;

	while ((c = getopt(argc, argv, "m:n:h")) != -1) {
		switch (c) {
		case 'm':
			if (!optarg) {
				fprintf(stderr, "loop: Error, empty buffer.\n");
				goto exit;
			}

			if (*message)
				free(*message);

			(*message) = strdup(optarg);
			break;

		case 'n':
			if (!string_to_positive_integer(optarg, interval, "interval"))
				goto exit;
			break;
		case 'h':
			usage();
			goto exit;
		case '?':
			if (optopt == 'm' || optopt == 'n')
				fprintf(stderr, "Option '-%c' requires an argument.\n", optopt);
			else
				fprintf(stderr, "Unknow option '-%c'.\n", optopt);
			usage();
			goto exit;
		}
	}
	if (!(*message))
		(*message) = strdup(DEFAULT_MESSAGE);
	return true;
 exit:
	return false;
}


int main(int argc, char **argv)
{
	artik_loop_module *loop = NULL;
	char *message = NULL;
	int periodicid = -1, signalid = -1;
	int interval = 1;
	artik_error res = S_OK;

	if (!parse_arguments(argc, argv, &message, &interval))
		goto exit;
	loop = (artik_loop_module *)artik_request_api_module("loop");
	if (!loop)
		goto exit;
	res = init(&periodicid, &signalid, loop, interval, message);
	if (res != S_OK)
		goto exit;
	loop->run();
exit:
	if (message)
		free(message);
	if (loop && periodicid != -1)
		loop->remove_periodic_callback(periodicid);
	if (loop && signalid != -1)
		loop->remove_signal_watch(signalid);
	if (loop)
		artik_release_api_module(loop);
}
