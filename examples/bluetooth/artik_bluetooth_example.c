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
#include <artik_bluetooth.h>

#define MAX_PACKET_SIZE 1024

typedef void (*interactive_command_callback_t)(int argc, char **argv, artik_bluetooth_module *bluetooth);

typedef struct {
	const char *cmd;
	interactive_command_callback_t callback;
} interactive_command_t;

static unsigned int string_to_positive_integer(const char * const buff, int *dst, const char * const option_name)
{
	if (!buff) {
		fprintf(stderr,  "Invalid buffer which is empty for '%s'.\n", option_name);
		return 0;
	}
	char *nbuff = NULL;

	*dst = strtol(buff, &nbuff, 10);
	if (nbuff[0] != 0 ||
		(errno != 0 && *dst == 0) ||
		(errno == ERANGE)) {
		printf("Invalid '%s' base definition, it should be an integer of base 10.\n", option_name);
		return 0;
	}
	return 1;
}

static void usage(void)
{
	printf("Usage: bluetooth-example [OPTIONS]\n");
	printf(" Options:\n");
	printf("  -h             Display this help and exit.\n");
}

static void interactive_shell_usage(void)
{
	printf("  scan <timeout>\t\t\t Launch a scan.\n");
	printf("  devices\t\t\t\t Display the list of devices discovered.\n");
	printf("  services <mac>\t Discover the service of a device.\n");
	printf("  adapter\t Display the bluetooth adapter properties.\n");
	printf("  adapter set <discoverable|pairable|name>\t Modify the bluetooth adapter properties.\n");
	printf("  exit\t\t\t\t Quit the program.\n");
	printf("  help\t\t\t\t Display the shell command usage.\n");
}

static void help_command(int argc, char **argv, artik_bluetooth_module *bluetooth)
{
	interactive_shell_usage();
}

static void quit_command(int argc, char **argv, artik_bluetooth_module *bluetooth)
{
	artik_loop_module *loop = (artik_loop_module *) artik_request_api_module("loop");

	printf("\rQuit BLUETOOTH example\n");
	loop->quit();
}

static void scan_stop_command(void *user_data)
{
	artik_bluetooth_module *bluetooth = (artik_bluetooth_module *)user_data;

	bluetooth->stop_scan();
}

static void scan_command(int argc, char **argv, artik_bluetooth_module *bluetooth)
{
	artik_loop_module *loop = (artik_loop_module *) artik_request_api_module("loop");
	int32_t timeout = 0, timeoutid = -1;

	if (bluetooth->is_scanning()) {
		printf("scan: Failed, the device is already scanning.\n");
		return;
	}
	bluetooth->start_scan();
	if (argc == 2 && argv[1] &&
		!string_to_positive_integer(argv[1], &timeout, "")) {
		timeout = 100;
	}
	loop->add_timeout_callback(&timeoutid, timeout * 1000, scan_stop_command, bluetooth);
	printf("scan: Success.\n");
}

static void devices_command(int argc, char **argv, artik_bluetooth_module *bluetooth)
{
	artik_bt_device *devices = 0;
	int count = 0, i = 0;

	bluetooth->get_devices(BT_DEVICE_ALL, &devices, &count);
	if (count == 0) {
		printf("scan_list: Failed, not devices found.\n");
		return;
	}
	while (i < count) {
		printf("Name: %s\nAddress: %s\nRSSI: %d\nBonded: %s Connected: %s Authorized: %s\n"
			"Name Manufacturer: %s\nID Manufacturer: 0x%04x\n",
			devices[i].remote_name, devices[i].remote_address, devices[i].rssi,
			(devices[i].is_bonded ? "true" : "false"),
			(devices[i].is_connected ? "true" : "false"),
			(devices[i].is_authorized ? "true" : "false"),
			devices[i].manufacturer_name, devices[i].manufacturer_id);
		++i;
	}
}

static void services_command(int argc, char **argv, artik_bluetooth_module *bluetooth)
{
	artik_bt_device device;
	artik_error res = S_OK;
	int i = 0;

	memset(&device, 0, sizeof(device));
	if (!argv || !argv[0]) {
		printf("services: Failed, Invalid arguments.\n");
		return;
	}
	res = bluetooth->connect(argv[0]);
	if (res != S_OK) {
		printf("services: Failed, unable to connect due to error(%d).\n", res);
		return;
	}
	res = bluetooth->start_bond(argv[0]);
	if (res != S_OK) {
		bluetooth->disconnect(argv[0]);
		printf("services: Failed, unable to bond due to error(%d).\n", res);
		return;
	}
	res = bluetooth->get_device(argv[0], &device);
	if (res != S_OK) {
		bluetooth->stop_bond(argv[0]);
		bluetooth->disconnect(argv[0]);
		printf("services: Failed, unable to discover the service due to error(%d).\n", res);
		return;
	}
	while (i < device.uuid_length) {
		printf("\tService[%d]: [%s]-[%s]\n", i, device.uuid_list[i].uuid_name, device.uuid_list[i].uuid);
		++i;
	}
	bluetooth->stop_bond(argv[0]);
	bluetooth->disconnect(argv[0]);
}

static void adapter_command(int argc, char **argv, artik_bluetooth_module *bluetooth)
{
	artik_bt_adapter adapter;
	artik_error res = S_OK;
	int i = 0;

	res = bluetooth->get_adapter_info(&adapter);
	if (res != S_OK) {
		printf("info: Failed, error (%d)\n", res);
		return;
	}
	printf("Name: %s\n", adapter.name);
	printf("Alias: %s\n", adapter.alias);
	printf("Addr: %s\n", adapter.address);
	printf("Discoverable: %s\n", (adapter.discoverable ? "true" : "false"));
	printf("Pairable: %s\n", (adapter.pairable ? "true" : "false"));
	printf("Discovery: %s\n", (adapter.discovering ? "active" : "none"));
	printf("Services_list:");
	while (i < adapter.uuid_length) {
		printf("\tService[%d]: [%s]-[%s]\n",
			i, adapter.uuid_list[i].uuid_name, adapter.uuid_list[i].uuid);
		++i;
	}
}

static void discovered_command(int argc, char **argv, artik_bluetooth_module *bluetooth)
{
	artik_error res = S_OK;

	if (!argv || argc < 4 || !argv[3] || (strcmp(argv[3], "true") != 0 && strcmp(argv[3], "false") != 0)) {
		printf("discovered: Failed, invalid argument.\n");
		return;
	}
	res = bluetooth->set_discoverable((strcmp(argv[3], "true") == 0 ? 1 : 0));
	if (res != S_OK) {
		printf("name: Failed, error (%d).\n", res);
		return;
	}
	printf("discovered: Success.\n");
}

static void paired_command(int argc, char **argv, artik_bluetooth_module *bluetooth)
{
	artik_error res = S_OK;

	if (!argv || argc < 4 || !argv[3] || (strcmp(argv[3], "true") != 0 && strcmp(argv[3], "false") != 0)) {
		printf("discovered: Failed, invalid argument.\n");
		return;
	}
	res = bluetooth->set_pairable((strcmp(argv[3], "true") == 0 ? 1 : 0));
	if (res != S_OK) {
		printf("name: Failed, error (%d).\n", res);
		return;
	}
	printf("discovered: Success.\n");
}

static void name_command(int argc, char **argv, artik_bluetooth_module *bluetooth)
{
	artik_error res = S_OK;

	if (!argv || argc < 4 || !argv[3]) {
		printf("name: Failed, invalid argument.\n");
		return;
	}
	res = bluetooth->set_alias(argv[3]);
	if (res != S_OK) {
		printf("name: Failed, error (%d).\n", res);
		return;
	}
	printf("name: Success.\n");
}

static int bluetooth_shell(int fd, enum watch_io io, void *user_data)
{
	interactive_command_t cmd[] = {
		{"help", help_command},
		{"scan", scan_command},
		{"devices", devices_command},
		{"services", services_command},
		{"adapter set discoverable", discovered_command},
		{"adapter set pairable", paired_command},
		{"adapter set name", name_command},
		{"adapter", adapter_command},
		{"exit", quit_command},
		{ NULL, NULL }
	};
	artik_bluetooth_module *bluetooth = (artik_bluetooth_module *)user_data;
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
		if (argc < 4 && strcmp(cmd[i].cmd, argv[0]) == 0)
			break;
		if (argc >= 4) {
			int len = strlen(argv[0]) + strlen(argv[1]) + strlen(argv[2]) + 3;
			char *str = malloc(len);

			if (!str) {
				fprintf(stderr, "Error: Failed to allocate memory\n");
				break;
			}
			snprintf(str, len, "%s %s %s", argv[0], argv[1], argv[2]);
			if (strcmp(cmd[i].cmd, str) == 0) {
				free(str);
				break;
			}
			free(str);
		}
		++i;
	}

	if (cmd[i].cmd != NULL)
		cmd[i].callback(argc, argv, bluetooth);
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
	artik_bluetooth_module	*bluetooth = NULL;
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
	bluetooth = (artik_bluetooth_module *) artik_request_api_module("bluetooth");
	if (!bluetooth) {
		fprintf(stderr, "Error: Failed to request bluetooth module.\n");
		goto exit;
	}
	ret = bluetooth->init();
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to initialize the bluetooth adapter.\n");
		goto exit;
	}
	ret = loop->add_fd_watch(STDIN_FILENO, (WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP | WATCH_IO_NVAL),
							 bluetooth_shell, bluetooth, &watchid);
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
	if (bluetooth) {
		bluetooth->deinit();
		artik_release_api_module(bluetooth);
	}
}
