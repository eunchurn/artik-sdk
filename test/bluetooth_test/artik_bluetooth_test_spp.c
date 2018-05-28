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

#define MAX_PACKET_SIZE 1024

static artik_bluetooth_module *bt;
static artik_loop_module *loop;

static char buffer[MAX_PACKET_SIZE];
static int watch_id;
static int spp_fd = -1;

static void ask(char *prompt)
{
	printf("%s\n", prompt);
	if (fgets(buffer, MAX_PACKET_SIZE, stdin)  == NULL)
		printf("\ncmd fgets error\n");
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
			BT_AGENT_REQUEST_REJECTED, "Rejected");
}

void on_authorization(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_agent_request_property *request_property =
		(artik_bt_agent_request_property *)data;

	printf("<AGENT>: Request authorization (%s)\n", request_property->device);
	ask("Authorize? (yes/no): ");
	if (!strncmp(buffer, "yes", 3))
		bt->agent_send_empty_response(request_property->handle);
	else
		bt->agent_send_error(request_property->handle,
			BT_AGENT_REQUEST_REJECTED, "");
}

void on_authorize_service(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_agent_authorize_property *authorize_property =
		(artik_bt_agent_authorize_property *)data;

	printf("<AGENT>: Authorize Service (%s, %s)\n",
		authorize_property->device, authorize_property->uuid);
	ask("Authorize connection? (yes/no): ");
	if (!strncmp(buffer, "yes", 3))
		bt->agent_send_empty_response(authorize_property->handle);
	else
		bt->agent_send_error(authorize_property->handle,
			BT_AGENT_REQUEST_REJECTED, "");
}

void on_cancel(artik_bt_event event, void *data, void *user_data)
{
	printf("> %s\n", __func__);
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

		if (num_bytes == -1)
			printf("> error in recvfrom()\n");
		else {
			buffer[num_bytes] = '\0';
			printf("> received: %s", buffer);
			if (send(fd, buffer, num_bytes, 0) != num_bytes)
				printf("> failed to send data\n");
		}
	} else if (io & WATCH_IO_HUP || io & WATCH_IO_ERR || io & WATCH_IO_NVAL) {
		printf("> socket hangs up\n");

		bt->set_discoverable(true);

		close(spp_fd);
		watch_id = 0;

		return 0;
	}
	return 1;
}

static void on_spp_connect(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_spp_connect_property *spp_property =
			(artik_bt_spp_connect_property *)data;

	printf("> SPP client %s is connected\n", spp_property->device_addr);

	spp_fd = spp_property->fd;
	loop->add_fd_watch(spp_fd,
			WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP | WATCH_IO_NVAL,
			on_socket, NULL, &watch_id);
}

static void on_spp_release(artik_bt_event event, void *data, void *user_data)
{
	printf("> %s\n", __func__);
}

static void on_spp_disconnect(artik_bt_event event, void *data, void *user_data)
{
	printf("> %s\n", __func__);
}

void on_bond(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_device d = *(artik_bt_device *) data;

	if (d.is_bonded)
		printf("> %s [%s] is paired\n", d.remote_name, d.remote_address);
	else
		bt->set_discoverable(true);
}

void on_connect(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_device d = *(artik_bt_device *)data;

	if (d.is_connected)
		printf("> %s [%s] is connected\n", d.remote_name, d.remote_address);
	else {
		printf("> %s [%s] is disconnected\n", d.remote_name, d.remote_address);

		bt->set_discoverable(true);
	}
}

static void set_callback(void)
{
	artik_bt_callback_property callback_property[] = {
		{BT_EVENT_BOND, on_bond, NULL},
		{BT_EVENT_CONNECT, on_connect, NULL},
		{BT_EVENT_SPP_CONNECT, on_spp_connect, NULL},
		{BT_EVENT_SPP_RELEASE, on_spp_release, NULL},
		{BT_EVENT_SPP_DISCONNECT, on_spp_disconnect, NULL},
		{BT_EVENT_AGENT_REQUEST_PINCODE, on_request_pincode, NULL},
		{BT_EVENT_AGENT_REQUEST_PASSKEY, on_request_passkey, NULL},
		{BT_EVENT_AGENT_CONFIRM, on_confirmation, NULL},
		{BT_EVENT_AGENT_AUTHORIZE, on_authorization, NULL},
		{BT_EVENT_AGENT_AUTHORIZE_SERVICE, on_authorize_service, NULL},
		{BT_EVENT_AGENT_CANCEL, on_cancel, NULL}
	};

	bt->set_callbacks(callback_property, 11);
}

static void spp_profile_register(void)
{
	artik_bt_spp_profile_option profile_option;

	profile_option.name = "Artik SPP Loopback";
	profile_option.service = "SPP loopback";
	profile_option.role = "server";
	profile_option.channel = 1;
	profile_option.PSM = 3;
	profile_option.require_authentication = true;
	profile_option.require_authorization = true;
	profile_option.auto_connect = true;
	profile_option.version = 10;
	profile_option.features = 20;

	bt->spp_register_profile(&profile_option);
}

int main(int argc, char *argv[])
{
	int signal_id;

	bt = (artik_bluetooth_module *) artik_request_api_module("bluetooth");
	loop = (artik_loop_module *) artik_request_api_module("loop");

	bt->init();

	spp_profile_register();
	set_callback();

	bt->set_discoverable(true);
	bt->agent_register_capability(BT_CAPA_KEYBOARDDISPLAY);
	bt->agent_set_default();

	printf("> SPP server ready\n");

	loop->add_signal_watch(SIGINT, on_signal, NULL, &signal_id);
	loop->run();
	loop->remove_signal_watch(signal_id);

	bt->agent_unregister();
	bt->spp_unregister_profile();

	bt->deinit();

	if (spp_fd > 0)
		close(spp_fd);
	if (watch_id)
		loop->remove_fd_watch(watch_id);

	artik_release_api_module(bt);
	artik_release_api_module(loop);

	return 0;
}

