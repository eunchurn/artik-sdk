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
#include <artik_websocket.h>

#define MAX_PACKET_SIZE 1024

typedef void (*interactive_command_callback_t)
(int argc, char **argv, artik_websocket_module *ws, artik_websocket_handle *wsHandle);

typedef struct {
	const char *cmd;
	interactive_command_callback_t callback;
} interactive_command_t;

static void usage(void)
{
	fprintf(stdout, "Usage websocket-example [options]\n");
	fprintf(stdout, " Options:\n");
	fprintf(stdout, "  -h             Display this help and exit.\n");
}

static void interactive_shell_usage(void)
{
	fprintf(stdout, "  connect <address:port>\t Connect to a websocket server.\n");
	fprintf(stdout, "  disconnect\t\t\t\t Disconnect from the websocket server.\n");
	fprintf(stdout, "  send <message>\t\t\t Send a message to a server.\n");
	fprintf(stdout, "  exit\t\t\t\t Quit the program.\n");
	fprintf(stdout, "  help\t\t\t\t Display the shell command usage.\n");
}

static int on_quit_cb(void *user_data)
{
	artik_loop_module		*loop = (artik_loop_module *)user_data;

	fprintf(stdout, "\rQuit WEBSOCKET example\n");
	loop->quit();
	return 1;
}

static void on_receive_cb(void *user, void *result)
{
	char *buffer = (char *)result;

	if (buffer) {
		fprintf(stdout, "\nws-rcv: %s\n", buffer);
		write(1, ">", 1);
	}
}

static void on_connect_cb(void *user, void *result)
{
	intptr_t status = (intptr_t)result;

	if (status == ARTIK_WEBSOCKET_CONNECTED) {
		fprintf(stdout, "\nws-status: Connected.\n");
		write(1, ">", 1);
	} else if (status == ARTIK_WEBSOCKET_CLOSED) {
		fprintf(stdout, "\nws-status: Disconnected.\n");
		write(1, ">", 1);
	}
}

static void help_command(int argc, char **argv, artik_websocket_module *ws, artik_websocket_handle *wsHandle)
{
	interactive_shell_usage();
}

static void quit_command(int argc, char **argv, artik_websocket_module *ws, artik_websocket_handle *wsHandle)
{
	artik_loop_module *loop = (artik_loop_module *) artik_request_api_module("loop");

	printf("\rQuit WEBSOCKET example\n");
	loop->quit();
}

static void connect_command(int argc, char **argv, artik_websocket_module *ws, artik_websocket_handle *wsHandle)
{
	artik_error res = S_OK;
	int len = 0;
	artik_websocket_config *wsConfig = (artik_websocket_config *)argv[2];

	if (argc != 3 || !argv[1] || !argv[2]) {
		fprintf(stderr, "connect: Failed, invalid remote address.\n");
		return;
	}
	len = strlen(argv[1]) + 7;
	wsConfig->uri = malloc(sizeof(*wsConfig->uri) * len);
	if (!wsConfig->uri)
		goto exit;
	if (!strncmp(argv[1], "ws://", 5) || !strncmp(argv[1], "wss://", 6))
		snprintf(wsConfig->uri, len, "%s/", argv[1]);
	else
		snprintf(wsConfig->uri, len, "ws://%s/", argv[1]);
	res = ws->websocket_request(wsHandle, wsConfig);
	if (res != S_OK)
		goto exit;
	res = ws->websocket_open_stream(*wsHandle);
	if (res != S_OK)
		goto exit;
	res = ws->websocket_set_connection_callback(*wsHandle, on_connect_cb, NULL);
	if (res != S_OK)
		goto exit;
	res = ws->websocket_set_receive_callback(*wsHandle, on_receive_cb, NULL);
	if (res != S_OK)
		goto exit;
	fprintf(stdout, "connect: Success.\n");
	return;
 exit:
	if (res != S_OK)
		fprintf(stdout, "connect: Failed due to error(%d), %s.\n", res, error_msg(res));
	if (wsConfig->uri)
		free(wsConfig->uri);
}

static void disconnect_command(int argc, char **argv, artik_websocket_module *ws, artik_websocket_handle *wsHandle)
{
	if (!ws || !wsHandle) {
		fprintf(stderr, "disconnect: Failed, client is not connected\n");
		return;
	}
	ws->websocket_close_stream(*wsHandle);
	artik_release_api_module(ws);
	ws = NULL;
	wsHandle = NULL;
	fprintf(stdout, "disconnect: Success.\n");
}

static void send_command(int argc, char **argv, artik_websocket_module *ws, artik_websocket_handle *wsHandle)
{
	if (!ws) {
		fprintf(stderr, "send: Failed, not connected to a remote server.\n");
		return;
	} else if (argc != 2 || !argv[1]) {
		fprintf(stderr, "send: Failed, require an argument 'message'"
				"to send to the remote server.\n");
		return;
	}
	ws->websocket_write_stream(*wsHandle, argv[1]);
	fprintf(stdout, "send: Success.\n");
}

static int websocket_shell(int fd, enum watch_io io, void *user_data)
{
	interactive_command_t cmd[] = {
		{"help", help_command},
		{"connect", connect_command},
		{"disconnect", disconnect_command},
		{"send", send_command},
		{"exit", quit_command},
		{ NULL, NULL }
	};
	artik_websocket_module *ws = (artik_websocket_module *)user_data;
	artik_websocket_handle wsHandle = NULL;
	artik_websocket_config wsConfig = {0};
	char buffer[MAX_PACKET_SIZE];
	char **argv = NULL;
	int argc = 0;
	char *p = NULL;
	int i = 0;

	if (fgets(buffer, MAX_PACKET_SIZE, stdin) == NULL)
		return 1;
	p = strtok(buffer, " \t\n");
	while (p) {
		argv = realloc(argv, sizeof(char *) * ++argc);

		if (argv == NULL) {
			artik_loop_module *loop = (artik_loop_module *) artik_request_api_module("loop");

			fprintf(stderr, "Error: Not enough memory\n");
			loop->quit();
			return 0;
		}

		argv[argc - 1] = p;
		p = strtok(NULL, " \t\n");
	}

	if (argc < 1) {
		fprintf(stderr, "Error: Too few arguments\n");
		return 1;
	}

	while (cmd[i].cmd != NULL) {
		if (strcmp(cmd[i].cmd, argv[0]) == 0)
			break;
		++i;
	}
	if (cmd[i].cmd != NULL && i == 1) {
		++argc;
		argv = realloc(argv, sizeof(*argv) * argc);
		argv[argc-1] = (char *)&wsConfig;
		cmd[i].callback(argc, argv, ws, &wsHandle);
	} else if (cmd[i].cmd != NULL)
		cmd[i].callback(argc, argv, ws, &wsHandle);
	else
		fprintf(stderr, "Error: Unknow command '%s'\n", argv[0]);
	if (i != 4)
		write(1, ">", 1);
	return 1;
}

static int parse_arguments(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "h")) != -1) {
		switch (c) {
		case 'h':
			usage();
			goto exit;
		case '?':
			printf("Error: Unknow option '-%c'\n", optopt);
			goto exit;
		default:
			abort();
		}
	}
	return true;
 exit:
	return false;
}

int main(int argc, char **argv)
{
	artik_websocket_module	*ws = NULL;
	artik_loop_module		*loop = NULL;
	artik_error			ret = 0;
	int signalid = -1, watchid = -1;

	if (!parse_arguments(argc, argv))
		goto exit;
	loop = (artik_loop_module *) artik_request_api_module("loop");
	if (!loop) {
		fprintf(stderr, "Error: Failed to request Loop module\n");
		goto exit;
	}
	ws = (artik_websocket_module *) artik_request_api_module("websocket");
	if (!ws) {
		fprintf(stderr, "Error: Failed to request websocket module.\n");
		goto exit;
	}
	ret = loop->add_fd_watch(STDIN_FILENO, (WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP | WATCH_IO_NVAL),
							 websocket_shell, ws, &watchid);
	if (ret != S_OK)
		goto exit;
	ret = loop->add_signal_watch(SIGINT, on_quit_cb, loop, &signalid);
	if (ret != S_OK)
		goto exit;
	write(1, ">", 1);
	loop->run();
 exit:
	if (loop && watchid != -1)
		loop->remove_fd_watch(watchid);
	if (loop && signalid != -1)
		loop->remove_signal_watch(signalid);
	if (loop)
		artik_release_api_module(loop);
	if (ws)
		artik_release_api_module(ws);
	return 1;
}
