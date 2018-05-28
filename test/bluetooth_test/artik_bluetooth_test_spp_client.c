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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>

#include <artik_module.h>
#include <artik_loop.h>
#include <artik_bluetooth.h>

#define MAX_BDADDR_LEN 18
#define MAX_PACKET_SIZE 1024
#define BUFFER_SIZE 17

static artik_bluetooth_module *bt;
static artik_loop_module *loop;

static int input_watch_id;
static int spp_watch_id;
static int spp_fd = -1;
static char buffer[BUFFER_SIZE];
static char remote_address[MAX_BDADDR_LEN] = "";

static void ask(char *prompt)
{
	printf("<AGENT>: %s\n", prompt);
	if (fgets(buffer, BUFFER_SIZE, stdin)  == NULL)
		printf("<AGENT>:\ncmd fgets error\n");
}

void on_request_pincode(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_agent_request_property *request_property =
		(artik_bt_agent_request_property *)data;

	printf("<AGENT>: Request pincode (%s)\n", request_property->device);
	ask("Enter PIN Code: ");

	bt->agent_send_pincode(request_property->handle, buffer);
}

void on_request_passkey(artik_bt_event event, void *data, void *user_data)
{
	unsigned long passkey;
	artik_bt_agent_request_property *request_property =
		(artik_bt_agent_request_property *)data;

	printf("<AGENT>: Request passkey (%s)\n", request_property->device);
	ask("Enter passkey (1~999999): ");
	passkey = strtoul(buffer, NULL, 10);
	if ((passkey > 0) && (passkey < 999999))
		bt->agent_send_passkey(request_property->handle, (unsigned int)passkey);
	else
		printf("<AGENT>: get passkey error\n");
}

void on_confirmation(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_agent_confirmation_property *confirmation_property =
		(artik_bt_agent_confirmation_property *)data;

	printf("<AGENT>: Request confirmation (%s)\nPasskey: %06u\n",
		confirmation_property->device, confirmation_property->passkey);

	ask("Confirm passkey? (yes/no): ");
	if (!strncmp(buffer, "yes", 3))
		bt->agent_send_empty_response(confirmation_property->handle);
	else
		bt->agent_send_error(confirmation_property->handle,
			BT_AGENT_REQUEST_REJECTED, "rejected");
}

static int on_signal(void *user_data)
{
	printf("> %s\n", __func__);
	loop->quit();

	return 1;
}

static int on_socket(int fd, enum watch_io io, void *user_data)
{
	uint8_t buffer[MAX_PACKET_SIZE];
	int num_bytes = 0;

	if (io & WATCH_IO_IN) {
		num_bytes = recv(fd, buffer, MAX_PACKET_SIZE, 0);
		if (num_bytes == -1) {
			printf("> error in recvfrom()\n");
		} else {
			buffer[num_bytes] = '\0';
			printf("> received: %s", buffer);
			printf("> message: ");
			fflush(stdout);
		}
	} else if (io & WATCH_IO_HUP || io & WATCH_IO_ERR || io & WATCH_IO_NVAL) {
		printf("> socket hangs up\n");
		loop->quit();
	}

	return 1;
}

static int on_keyboard_received(int fd, enum watch_io id, void *user_data)
{
	char buffer[MAX_PACKET_SIZE];

	if (fgets(buffer, MAX_PACKET_SIZE, stdin) == NULL) {
		input_watch_id = 0;
		return 0;
	}

	if (send(spp_fd, buffer, strlen(buffer), 0) < 0) {
		input_watch_id = 0;
		return 0;
	}

	return 1;
}

void on_spp_connect(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_spp_connect_property *spp_property =
			(artik_bt_spp_connect_property *)data;

	printf("> connected to the SPP server\n");

	spp_fd = spp_property->fd;

	loop->add_fd_watch(STDIN_FILENO,
			(WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP | WATCH_IO_NVAL),
			on_keyboard_received, NULL, &input_watch_id);
	loop->add_fd_watch(spp_fd,
			WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP | WATCH_IO_NVAL,
			on_socket, NULL, &spp_watch_id);

	printf("> Message: ");
	fflush(stdout);
}

void on_spp_release(artik_bt_event event, void *data, void *user_data)
{
	printf("> %s\n", __func__);
}

void on_spp_disconnect(artik_bt_event event, void *data, void *user_data)
{
	printf("> %s\n", __func__);
}

void on_scan(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_device *devices = (artik_bt_device *) data;

	if (!strncmp(devices->remote_address, remote_address, 18)) {
		printf("> found: %s\n", devices->remote_address);
		bt->stop_scan();

		printf("> start bond\n");
		bt->start_bond(remote_address);
	}
}

void on_bond(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_device d = *(artik_bt_device *) data;

	if (d.is_bonded) {
		printf("> %s [%s] is paired\n", d.remote_name, d.remote_address);
		bt->connect_profile(remote_address,
				"00001101-0000-1000-8000-00805f9b34fb");
	} else {
		printf("> pairing is failed\n");
		loop->quit();
	}
}

void on_connect(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_device d = *(artik_bt_device *)data;

	if (d.is_connected)
		printf("> %s [%s] is connected\n", d.remote_name, d.remote_address);
	else {
		printf("> %s [%s] is disconnected\n", d.remote_name, d.remote_address);

		loop->quit();
	}
}

static artik_error set_callback(void)
{
	artik_bt_callback_property property[] = {
		{BT_EVENT_SCAN, on_scan, NULL},
		{BT_EVENT_BOND, on_bond, NULL},
		{BT_EVENT_CONNECT, on_connect, NULL},
		{BT_EVENT_SPP_CONNECT, on_spp_connect, NULL},
		{BT_EVENT_SPP_RELEASE, on_spp_release, NULL},
		{BT_EVENT_SPP_DISCONNECT, on_spp_disconnect, NULL},
		{BT_EVENT_AGENT_REQUEST_PINCODE, on_request_pincode, NULL},
		{BT_EVENT_AGENT_REQUEST_PASSKEY, on_request_passkey, NULL},
		{BT_EVENT_AGENT_CONFIRM, on_confirmation, NULL}
	};

	bt->set_callbacks(property, 9);

	return S_OK;
}

static void spp_profile_register(void)
{
	artik_bt_spp_profile_option profile_option;

	profile_option.name = "Artik SPP Loopback";
	profile_option.service = "SPP loopback";
	profile_option.role = "client";
	profile_option.channel = 1;
	profile_option.PSM = 3;
	profile_option.require_authentication = true;
	profile_option.require_authorization = true;
	profile_option.auto_connect = 1;
	profile_option.version = 10;
	profile_option.features = 20;

	bt->spp_register_profile(&profile_option);
}

int main(int argc, char *argv[])
{
	int opt, signal_id;

	bt = (artik_bluetooth_module *)artik_request_api_module("bluetooth");
	loop = (artik_loop_module *)artik_request_api_module("loop");

	while ((opt = getopt(argc, argv, "t:")) != -1) {
		switch (opt) {
		case 't':
			strncpy(remote_address, optarg, MAX_BDADDR_LEN);
			printf("> target address: %s\n", remote_address);
			break;
		default:
			printf("> usage: bluetooth-test-spp_client -t <target BDADDR>\n");
			return 0;
		}
	}

	bt->init();

	set_callback();
	spp_profile_register();

	bt->agent_register_capability(BT_CAPA_KEYBOARDDISPLAY);
	bt->agent_set_default();
	bt->start_scan();

	loop->add_signal_watch(SIGINT, on_signal, NULL, &signal_id);
	loop->run();
	loop->remove_signal_watch(signal_id);

	bt->agent_unregister();
	bt->spp_unregister_profile();
	bt->disconnect(remote_address);

	bt->deinit();

	if (spp_fd > 0)
		close(spp_fd);
	if (input_watch_id)
		loop->remove_fd_watch(input_watch_id);
	if (spp_watch_id)
		loop->remove_fd_watch(spp_watch_id);

	artik_release_api_module(bt);
	artik_release_api_module(loop);

	return 0;
}
