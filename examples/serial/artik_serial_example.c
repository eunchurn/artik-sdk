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
#include <artik_serial.h>
#include <artik_loop.h>
#include <artik_platform.h>

#define MAX_PACKET_SIZE 1024

typedef void (*interactive_command_callback_t)(int argc, char **argv, artik_serial_handle *handle_sp);

typedef struct {
	const char *cmd;
	interactive_command_callback_t callback;
} interactive_command_t;

static void interactive_shell_usage(void)
{
	printf("  send <message>\t Send a message to the serial port.\n"
		"  exit\t\t\t Quit the program.\n"
		"  help\t\t\t Display the shell command usage.\n");
}

static void usage(void)
{
	printf("Usage: serial-example [OPTIONS]\n\n"
			" Options:\n"
			"  -h\t Display this help and exit.\n");
}

static void help_command(int argc, char **argv, artik_serial_handle *handle_serial)
{
	interactive_shell_usage();
}

static void quit_command(int argc, char **argv, artik_serial_handle *handle_serial)
{
	artik_loop_module *loop = (artik_loop_module *) artik_request_api_module("loop");

	printf("\rQuit SERIAL example\n");
	loop->quit();
}

static void on_receive_cb(void *param, unsigned char *buff, int len)
{
	(void)param;

	if (buff && len > 0) {
		printf("\nsp-receive: %s\n", buff);
		write(1, ">", 1);
	}
}

static void send_command(int argc, char **argv, artik_serial_handle *handle_serial)
{
	artik_serial_module *serial = (artik_serial_module *) artik_request_api_module("serial");
	artik_error res = S_OK;
	int len = 0;

	if (!serial) {
		fprintf(stderr, "Error: Failed to request serial module.\n");
		return;
	}
	if (!argv || !argv[0]) {
		fprintf(stderr, "send: Failed, invalid parameter.\n");
		artik_release_api_module(serial);
		return;
	}
	len = strlen(argv[0]);
	res = serial->write(handle_serial, (unsigned char *)argv[0], &len);
	artik_release_api_module(serial);
	if (res != S_OK) {
		fprintf(stderr, "send: Failed, error(%d)\n", res);
		return;
	}
	printf("send: Success\n");
}

static int serial_shell(int fd, enum watch_io io, void *user_data)
{
	interactive_command_t cmd[] = {
		{"help", help_command},
		{"send", send_command},
		{"exit", quit_command},
		{ NULL, NULL }
	};
	artik_serial_handle *serial_handle = (artik_serial_handle *)user_data;
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

	if (cmd[i].cmd != NULL)
		cmd[i].callback(argc, argv, serial_handle);
	else
		fprintf(stderr, "Error: Unknow command '%s'\n", argv[0]);
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
	artik_serial_module	*serial = NULL;
	artik_serial_handle	handle_serial = NULL;
	artik_serial_config	config_serial = { 4,
										"UART3",
										ARTIK_SERIAL_BAUD_115200,
										ARTIK_SERIAL_PARITY_NONE,
										ARTIK_SERIAL_DATA_8BIT,
										ARTIK_SERIAL_STOP_1BIT,
										ARTIK_SERIAL_FLOWCTRL_NONE,
										NULL
	};
	artik_loop_module		*loop = NULL;
	artik_error			ret = 0;
	int					watchid = -1;

	if (!parse_arguments(argc, argv))
		goto exit;
	loop = (artik_loop_module *) artik_request_api_module("loop");
	if (!loop) {
		fprintf(stderr, "Error: Failed to request Loop module\n");
		goto exit;
	}
	serial = (artik_serial_module *) artik_request_api_module("serial");
	if (!serial) {
		fprintf(stderr, "Error: Failed to request serial module.\n");
		goto exit;
	}
	ret = serial->request(&handle_serial, &config_serial);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to initialize the wif adapter.\n");
		goto exit;
	}
	ret = serial->set_received_callback(handle_serial, on_receive_cb, NULL);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to initialize the wifi adapter.\n");
		goto exit;
	}
	ret = loop->add_fd_watch(STDIN_FILENO, (WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP | WATCH_IO_NVAL),
							 serial_shell, handle_serial, &watchid);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to create watcher for STDIN: %s\n", error_msg(ret));
		goto exit;
	}
	interactive_shell_usage();
	write(1, ">", 1);
	loop->run();

exit:
	if (loop && watchid != -1)
		loop->remove_fd_watch(watchid);
	if (loop)
		artik_release_api_module(loop);
	if (serial) {
		serial->release(handle_serial);
		artik_release_api_module(serial);
	}
}
