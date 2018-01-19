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

#define MAX_BDADDR_LEN         17
#define MAX_PACKET_SIZE        1024
#define SCAN_TIME_MILLISECONDS (20*1000)

static artik_bluetooth_module *bt;
static artik_loop_module *loop;
static int timeout_id;
static int input_watch_id;
static int spp_watch_id;
static int spp_fd;

static int uninit(void *user_data)
{
	fprintf(stdout, "<SPP>: Process cancel\n");
	close(spp_fd);
	if (input_watch_id)
		loop->remove_fd_watch(input_watch_id);
	if (spp_watch_id)
		loop->remove_fd_watch(spp_watch_id);
	loop->quit();
	return true;
}

static void scan_timeout_callback(void *user_data)
{
	fprintf(stdout, "<SPP>: %s - stop scan\n", __func__);
	bt->stop_scan();
	bt->unset_callback(BT_EVENT_SCAN);
	loop->quit();
	loop->remove_timeout_callback(timeout_id);
}

static int on_socket(int fd, enum watch_io io, void *user_data)
{
	if (io & WATCH_IO_IN) {
		uint8_t buffer[MAX_PACKET_SIZE];
		int num_bytes = 0;

		num_bytes = recv(fd, buffer, MAX_PACKET_SIZE, 0);
		if (num_bytes == -1) {
			printf("Error in recvfrom()\n");
		} else {
			printf("<SPP>: Received %d bytes\n", num_bytes);
			buffer[num_bytes] = '\0';
			printf("%s\n", buffer);
		}
	} else if (io & WATCH_IO_HUP || io & WATCH_IO_ERR || io & WATCH_IO_NVAL) {
		printf("Socket error occured.\n");
		close(fd);
		spp_watch_id = 0;
		return 0;
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
	fprintf(stdout, "<SPP>: Input: %s\n", buffer);

	if (send(spp_fd, buffer, strlen(buffer), 0) < 0) {
		input_watch_id = 0;
		return 0;
	}
	return 1;
}

void callback_on_spp_connect(artik_bt_event event,
	void *data, void *user_data)
{
	fprintf(stdout, "<SPP>: %s\n", __func__);

	artik_bt_spp_connect_property *spp_property =
		(artik_bt_spp_connect_property *)data;

	spp_fd = spp_property->fd;

	loop->add_fd_watch(STDIN_FILENO,
			(WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP
			| WATCH_IO_NVAL),
			on_keyboard_received, NULL, &input_watch_id);
	loop->add_fd_watch(spp_fd,
			WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP | WATCH_IO_NVAL,
			on_socket, NULL, &spp_watch_id);
	fprintf(stdout, "<SPP>: Please Input test message:\n");
}

void callback_on_spp_release(artik_bt_event event,
	void *data, void *user_data)
{
	fprintf(stdout, "<SPP>: %s\n", __func__);
}

void callback_on_spp_disconnect(artik_bt_event event,
	void *data, void *user_data)
{
	fprintf(stdout, "<SPP>: %s\n", __func__);
}

void callback_on_scan(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_device *devices = (artik_bt_device *) data;
	int i = 0, num = 1;

	for (i = 0; i < num; i++) {
		fprintf(stdout, "[Device]: %s  ",
			devices[i].remote_address ? devices[i].remote_address : "(null)");
		fprintf(stdout, "Name: %s\t",
			devices[i].remote_name ? devices[i].remote_name : "(null)");
		fprintf(stdout, "RSSI: %d\t", devices[i].rssi);
		fprintf(stdout, "Bonded: %s\t",
			devices[i].is_bonded ? "true" : "false");
		fprintf(stdout, "Connected: %s\t",
			devices[i].is_connected ? "true" : "false");
		fprintf(stdout, "Authorized: %s\t",
			devices[i].is_authorized ? "true" : "false");
		fprintf(stdout, "\n");
	}
}

static artik_error set_callback(void)
{
	artik_error ret = S_OK;

	artik_bt_callback_property callback_property[] = {
		{BT_EVENT_SCAN, callback_on_scan, NULL},
		{BT_EVENT_SPP_CONNECT, callback_on_spp_connect, NULL},
		{BT_EVENT_SPP_RELEASE, callback_on_spp_release, NULL},
		{BT_EVENT_SPP_DISCONNECT, callback_on_spp_disconnect, NULL},
	};

	ret = bt->set_callbacks(callback_property, 4);

	return ret;
}

artik_error bluetooth_scan(void)
{
	artik_error ret = S_OK;

	fprintf(stdout, "<SPP>: %s - starting\n", __func__);

	ret = bt->remove_devices();
	if (ret != S_OK)
		goto exit;

	ret = bt->start_scan();
	if (ret != S_OK)
		goto exit;

	loop->add_timeout_callback(&timeout_id,
			SCAN_TIME_MILLISECONDS, scan_timeout_callback,
			NULL);
	loop->run();

exit:
	fprintf(stdout, "<SPP>: %s - %s\n", __func__,
		(ret == S_OK) ? "succeeded" : "failed");

	return ret;
}

artik_error get_addr(char *remote_addr)
{
	artik_error ret = S_OK;

	fprintf(stdout, "\n<SPP>: Input SPP Server MAC address:\n");

	if (fgets(remote_addr, MAX_BDADDR_LEN + 1, stdin) == NULL) {
		fprintf(stdout, "<SPP>: get addr failed! fgets error\n");
		return E_BT_ERROR;
	}
	if (strlen(remote_addr) != MAX_BDADDR_LEN)
		ret =  E_BT_ERROR;

	return ret;
}

static artik_error spp_profile_register(void)
{
	artik_error ret = S_OK;
	artik_bt_spp_profile_option profile_option;

	profile_option.name = "Artik SPP Loopback";
	profile_option.service = "spp char loopback";
	profile_option.role = "client";
	profile_option.channel = 22;
	profile_option.PSM = 3;
	profile_option.require_authentication = 1;
	profile_option.require_authorization = 0;
	profile_option.auto_connect = 1;
	profile_option.version = 10;
	profile_option.features = 20;

	ret = bt->spp_register_profile(&profile_option);

	return ret;
}

int main(void)
{
	artik_error ret = S_OK;
	char remote_address[MAX_BDADDR_LEN + 1] = "";

	if (!artik_is_module_available(ARTIK_MODULE_BLUETOOTH)) {
		fprintf(stdout, "<SPP>: Bluetooth module not available!\n");
		goto loop_quit;
	}

	bt = (artik_bluetooth_module *)artik_request_api_module("bluetooth");
	loop = (artik_loop_module *)artik_request_api_module("loop");
	if (!bt || !loop)
		goto loop_quit;

	bt->init();

	ret = set_callback();
	if (ret != S_OK) {
		fprintf(stdout, "<SPP>: SPP set callback error!\n");
		goto spp_quit;
	}
	fprintf(stdout, "<SPP>: SPP set callback success!\n");

	ret = spp_profile_register();
	if (ret != S_OK) {
		fprintf(stdout, "<SPP>: SPP register error!\n");
		goto spp_quit;
	}
	fprintf(stdout, "<SPP>: SPP register profile success!\n");

	ret = bluetooth_scan();
	if (ret != S_OK) {
		fprintf(stdout, "<SPP>: SPP scan error!\n");
		goto spp_quit;
	}

	ret = get_addr(remote_address);
	if (ret != S_OK) {
		fprintf(stdout, "<SPP>: SPP get address error!\n");
		goto spp_quit;
	}
	fprintf(stdout, "<SPP>: get remote addr: %s\n", remote_address);

	ret = bt->start_bond(remote_address);
	if (ret != S_OK)
		goto spp_quit;
	fprintf(stdout, "<SPP>: SPP paired success!\n");

	ret = bt->connect(remote_address);
	if (ret != S_OK)
		goto spp_quit;

	loop->add_signal_watch(SIGINT, uninit, NULL, NULL);
	loop->run();

	bt->disconnect(remote_address);
spp_quit:
	bt->spp_unregister_profile();
	bt->unset_callback(BT_EVENT_SPP_CONNECT);
	bt->unset_callback(BT_EVENT_SPP_RELEASE);
	bt->unset_callback(BT_EVENT_SPP_DISCONNECT);

	fprintf(stdout, "<SPP>: SPP quit!\n");
	bt->deinit();

loop_quit:
	if (bt)
		artik_release_api_module(bt);

	if (loop)
		artik_release_api_module(loop);

	fprintf(stdout, "<SPP>: Loop quit!\n");
	return S_OK;
}
