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

#include <artik_module.h>
#include <artik_loop.h>
#include <artik_time.h>

# define DEFAULT_MESSAGE "ARTIK SDK Timer example."

static unsigned int string_to_positive_integer(const char * const buff, int *dst, const char * const option_name)
{
	char *nbuff = NULL;

	if (!buff) {
		fprintf(stdout, "Invalid buffer which is empty for '%s'.\n", option_name);
		return 0;
	}

	errno = 0;
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
	printf("Usage: time-example [OPTIONS]\n\n"
		   " Options:\n"
		   "  -m <message> Message to display to the terminal. (default \"ARTIK SDK Loop example\")\n"
		   "  -t <sec>    Number of seconds before the alarm callback. (default 10)\n"
		   "  -h          Display this help and exit.\n");
}

static int on_quit_cb(void *user_data)
{
	artik_loop_module *loop = (artik_loop_module *)user_data;

	fprintf(stdout, "\r\033[0;33;32mQuit Time example\n\033[0m");
	loop->quit();
	return 1;
}

static void on_alarm_cb(void *user_data)
{
	artik_loop_module *loop = (artik_loop_module *)((void **)user_data)[0];
	const char * const message = (const char * const)((void **)user_data)[1];

	fprintf(stdout, "\r\033[0;34;33m[>ALARM<][> %s <]\n\033[0m", message);
	loop->quit();
}

static int on_process_cb(void *user_data)
{
	artik_time_module *timem = (artik_time_module *)((void **)user_data)[0];
	artik_alarm_handle	alarm = ((void **)user_data)[1];
	char				date[32];
	artik_msecond		delay = 0;

	timem->get_delay_alarm(alarm, &delay);
	timem->get_time_str(date, 32, "%H:%M:%S", ARTIK_TIME_UTC);

	if (delay != 0) {
		fprintf(stdout, "\r\033[0;32;31m[>Timer example<][> %s <]"
				"[>Remain %lu secs for the alarm<]\n\033[0m", date, delay);
	}
	return 1;
}

static artik_error init(artik_loop_module **loop, artik_time_module **timem,
				 artik_alarm_handle *alarm, int *signalid, int *periodicid,
				 int timeout, const char * const message)
{
	static void *params_alarm[2] = {0, 0};
	static void *params_periodic[2] = {0, 0};
	artik_error res = S_OK;

	(*timem) = (artik_time_module *)artik_request_api_module("time");
	if (!(*timem))
		return E_BUSY;
	(*loop) = (artik_loop_module *)artik_request_api_module("loop");
	if (!(*loop))
		return E_BUSY;
	params_alarm[0] = (void *)(*loop);
	params_alarm[1] = (void *)message;
	res = (*timem)->create_alarm_second(ARTIK_TIME_UTC, timeout, alarm, on_alarm_cb, (void *)params_alarm);
	if (res == S_OK)
		res = (*loop)->add_signal_watch(SIGINT, on_quit_cb, (*loop), signalid);
	if (res == S_OK) {
		params_periodic[0] = (void *)(*timem);
		params_periodic[1] = (void *)(*alarm);
		res = (*loop)->add_periodic_callback(periodicid, 1000, on_process_cb, (void *)params_periodic);
	}
	return res;
}

static artik_error parse_arguments(int argc, char **argv, char **message, int *timeout)
{
	int c;

	while ((c = getopt(argc, argv, "m:t:h")) != -1) {
		switch (c) {
		case 'm':
			if (!optarg) {
				fprintf(stdout, "Invalid buffer which is empty for 'message'.\n");
				return -1;
			}

			if (*message)
				free(*message);

			(*message) = strdup(optarg);
			break;
		case 't':
			if (!string_to_positive_integer(optarg, timeout, "timeout"))
				return -1;
			break;
		case 'h':
			usage();
			return 1;

		case '?':
			if (optopt == 'm' || optopt == 't')
				fprintf(stderr, "Option '-%c' requires an argument.\n", optopt);
			else
				fprintf(stderr, "Unknow option '-%c'.\n", optopt);
			usage();
			return -1;
		}
	}
	if (!(*message))
		(*message) = strdup(DEFAULT_MESSAGE);
	return 0;
}

int main(int argc, char **argv)
{
	artik_loop_module *loop = NULL;
	artik_time_module *timem = NULL;
	artik_alarm_handle alarm = NULL;
	artik_error res = S_OK;
	char *message = NULL;
	int periodicid = -1, signalid = -1, timeout = 10;

	res = parse_arguments(argc, argv, &message, &timeout);
	if (res != S_OK)
		goto exit;
	res = init(&loop, &timem, &alarm, &signalid, &periodicid, timeout, message);
	if (res != S_OK)
		goto exit;
	loop->run();
 exit:
	if (message)
		free(message);
	if (timem)
		artik_release_api_module(timem);
	if (loop && periodicid != -1)
		loop->remove_periodic_callback(periodicid);
	if (loop && signalid != -1)
		loop->remove_signal_watch(signalid);
	if (loop)
		artik_release_api_module(loop);
	return 1;
}
