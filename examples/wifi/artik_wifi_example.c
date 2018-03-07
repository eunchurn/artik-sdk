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
#include <artik_wifi.h>

#define MAX_PACKET_SIZE 1024

typedef void (*interactive_command_callback_t)(int argc, char **argv, artik_wifi_module *wifi);

typedef struct {
	const char *cmd;
	interactive_command_callback_t callback;
} interactive_command_t;

static void usage(void)
{
	printf("Usage: wifi-example [OPTIONS]\n");
	printf(" Options:\n");
	printf("  -h             Display this help and exit.\n");
}

static void interactive_shell_usage(void)
{
	printf("Usage:\n");
	printf(" wifi-example shell command:\n\n");
	printf(" Command:\n");
	printf("  scan\t\t\t\t Launch a scan.\n");
	printf("  scan_list\t\t\t\t Display the list of SSID discovered.\n");
	printf("  info\t\t\t\t Display the wifi & network details.\n");
	printf("  connect <ssid> <pass>\t Connect to an access point.\n");
	printf("  disconnect\t\t\t Disconnect from the used access point.\n");
	printf("  exit\t\t\t\t Quit the program.\n");
	printf("  help\t\t\t\t Display the shell command usage.\n");
}

static void help_command(int argc, char **argv, artik_wifi_module *wifi)
{
	interactive_shell_usage();
}

static void quit_command(int argc, char **argv, artik_wifi_module *wifi)
{
	artik_loop_module *loop = (artik_loop_module *) artik_request_api_module("loop");

	printf("\rQuit WIFI example\n");
	loop->quit();
}

static void scan_command(int argc, char **argv, artik_wifi_module *wifi)
{
	wifi->scan_request();
}

static void scan_list_command(int argc, char **argv, artik_wifi_module *wifi)
{
	artik_wifi_ap	*list = NULL;
	int			len = 0, i = 0;

	if (wifi->get_scan_result(&list, &len) != S_OK) {
		printf("error get scan result ");
		return;
	}
	while (i < len) {
		printf("wifi: [%s]-[%s]\n", list[i].bssid, list[i].name);
		++i;
	}
	free(list);
}

static void info_command(int argc, char **argv, artik_wifi_module *wifi)
{
	artik_wifi_connection_info info;
	artik_wifi_ap ap;

	memset(&info, 0, sizeof(info));
	memset(&ap, 0, sizeof(ap));
	if (wifi->get_info(&info, &ap) != S_OK)
		return;
	printf("last_err: %d\nconnected: %s\n", info.error, (info.connected ? "true" : "false"));
	if (info.connected)
		printf("Access Point: %-20s\nName: %s\nFreq: %d - encrypt: 0x%X\n",
			ap.bssid, ap.name, ap.frequency, ap.encryption_flags);
}

static void connect_command(int argc, char **argv, artik_wifi_module *wifi)
{
	artik_error res = S_OK;

	if (!argv || !argv[0] || !argv[1]) {
		fprintf(stderr, "connect: Failed, invalid parameters\n");
		return;
	}
	res = wifi->connect(argv[0], argv[1], 0);
	if (res != S_OK)
		fprintf(stderr, "connect: Failed, wifi error (%d)\n", res);
	printf("connect: Success.\n");
}

static void disconnect_command(int argc, char **argv, artik_wifi_module *wifi)
{
	wifi->disconnect();
	printf("disconnect: Success.\n");
}
static int wifi_shell(int fd, enum watch_io io, void *user_data)
{
	interactive_command_t cmd[] = {
		{"help", help_command},
		{"scan", scan_command},
		{"scan_list", scan_list_command},
		{"info", info_command},
		{"connect", connect_command},
		{"disconnect", disconnect_command},
		{"exit", quit_command},
		{ NULL, NULL }
	};
	artik_wifi_module *wifi = (artik_wifi_module *)user_data;
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
		cmd[i].callback(argc, argv, wifi);
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
	artik_wifi_module		*wifi = NULL;
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
	wifi = (artik_wifi_module *) artik_request_api_module("wifi");
	if (!wifi) {
		fprintf(stderr, "Error: Failed to request wifi module.\n");
		goto exit;
	}
	ret = wifi->init(ARTIK_WIFI_MODE_STATION);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to initialize the wifi adapter.\n");
		goto exit;
	}
	ret = loop->add_fd_watch(STDIN_FILENO, (WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP | WATCH_IO_NVAL),
							 wifi_shell, wifi, &watchid);
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
	if (wifi) {
		wifi->deinit();
		artik_release_api_module(wifi);
	}
}
