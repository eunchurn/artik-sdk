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
#include <string.h>
#include <inttypes.h>

#include <artik_module.h>
#include <artik_platform.h>

artik_error test_api_version(void)
{
	artik_api_version version;
	artik_error ret = S_OK;

	fprintf(stdout, "TEST: %s\n", __func__);
	ret = artik_get_api_version(&version);
	if (ret == S_OK)
		fprintf(stdout, "ARTIK API version:%s\n", version.version);

	return ret;
}

artik_error test_platform_name(void)
{
	int platid = -1;
	char platname[MAX_PLATFORM_NAME];
	artik_error ret = S_OK;

	fprintf(stdout, "TEST: %s\n", __func__);
	platid = artik_get_platform();
	ret = artik_get_platform_name(platname);
	if (ret != S_OK)
		return ret;

	fprintf(stdout, "Platform ID:%d\n", platid);
	fprintf(stdout, "Platform name:%s\n", platname);

	return S_OK;
}

artik_error test_bt_address(void)
{
	char btaddr[MAX_BT_ADDR+1] = {0};
	artik_error ret = S_OK;

	fprintf(stdout, "TEST: %s\n", __func__);
	ret = artik_get_bt_mac_address(btaddr);
	if (ret != S_OK)
		return ret;

	fprintf(stdout, "Platform Bluetooth MAC address: %s\n", btaddr);

	return S_OK;
}

artik_error test_wifi_address(void)
{
	char wifiaddr[MAX_WIFI_ADDR+1] = {0};
	artik_error ret = S_OK;

	fprintf(stdout, "TEST: %s\n", __func__);
	ret = artik_get_wifi_mac_address(wifiaddr);
	if (ret != S_OK)
		return ret;

	fprintf(stdout, "Platform Wifi MAC address: %s\n", wifiaddr);

	return S_OK;
}

artik_error test_serial_number(void)
{
	char sn[MAX_PLATFORM_SN+1] = {0};
	artik_error ret = S_OK;

	fprintf(stdout, "TEST: %s\n", __func__);
	ret = artik_get_platform_serial_number(sn);
	if (ret != S_OK)
		return ret;

	fprintf(stdout, "Platform Serial Number: %s\n", sn);

	return S_OK;
}

artik_error test_platform_manufacturer(void)
{
	char manu[MAX_PLATFORM_MANUFACT+1] = {0};
	artik_error ret = S_OK;

	fprintf(stdout, "TEST: %s\n", __func__);
	ret = artik_get_platform_manufacturer(manu);
	if (ret != S_OK)
		return ret;

	fprintf(stdout, "Platform Manufacturer: %s\n", manu);

	return S_OK;
}

artik_error test_platform_uptime(void)
{
	int64_t uptime = 0;
	artik_error ret = S_OK;

	fprintf(stdout, "TEST: %s\n", __func__);
	ret = artik_get_platform_uptime(&uptime);
	if (ret != S_OK)
		return ret;

	fprintf(stdout, "Platform uptime time: %" PRId64 "\n", uptime);

	return S_OK;
}

artik_error test_platform_model_number(void)
{
	char modelnum[MAX_PLATFORM_MODELNUM+1] = {0};
	artik_error ret = S_OK;

	fprintf(stdout, "TEST: %s\n", __func__);
	ret = artik_get_platform_model_number(modelnum);
	if (ret != S_OK)
		return ret;

	fprintf(stdout, "Platform model number: %s\n", modelnum);

	return S_OK;
}

artik_error test_api_modules(void)
{
	artik_api_module *modules = NULL;
	int num_modules = 0;
	artik_error ret = S_OK;
	int i = 0;

	fprintf(stdout, "TEST: %s\n", __func__);
	fprintf(stdout, "Available Modules:\n");

	ret = artik_get_available_modules(&modules, &num_modules);

	for (i = 0; i < num_modules; i++)
		fprintf(stdout, "\t%d: %s\n", modules[i].id, modules[i].name);

	fprintf(stdout, "Is GPIO module available: %s\n",
		artik_is_module_available(ARTIK_MODULE_GPIO) ? "Yes" : "No");
	fprintf(stdout, "Is I2C module available: %s\n",
		artik_is_module_available(ARTIK_MODULE_I2C) ? "Yes" : "No");
	fprintf(stdout, "Is SERIAL module available: %s\n",
		artik_is_module_available(ARTIK_MODULE_SERIAL) ? "Yes" : "No");
	fprintf(stdout, "Is PWM module available: %s\n",
		artik_is_module_available(ARTIK_MODULE_PWM) ? "Yes" : "No");
	fprintf(stdout, "Is ADC module available: %s\n",
		artik_is_module_available(ARTIK_MODULE_ADC) ? "Yes" : "No");
	fprintf(stdout, "Is HTTP module available: %s\n",
		artik_is_module_available(ARTIK_MODULE_HTTP) ? "Yes" : "No");
	fprintf(stdout, "Is CLOUD module available: %s\n",
		artik_is_module_available(ARTIK_MODULE_CLOUD) ? "Yes" : "No");
	fprintf(stdout, "Is WIFI module available: %s\n",
		artik_is_module_available(ARTIK_MODULE_WIFI) ? "Yes" : "No");
	fprintf(stdout, "Is MEDIA module available: %s\n",
		artik_is_module_available(ARTIK_MODULE_MEDIA) ? "Yes" : "No");

	return ret;
}

artik_error test_device_information(void)
{
	char *info = NULL;

	fprintf(stdout, "TEST: %s\n", __func__);
	info = artik_get_device_info();
	fprintf(stdout, "Device Info:\n%s\n", info);
	free(info);

	return S_OK;
}

int main(void)
{
	artik_error ret = S_OK;

	fprintf(stdout, "artik_module_test:\n");

	ret = test_api_version();
	if (ret != S_OK)
		goto exit;

	ret = test_platform_name();
	if (ret != S_OK)
		goto exit;

	ret = test_api_modules();
	if (ret != S_OK)
		goto exit;

	ret = test_bt_address();
	if (ret != S_OK)
		goto exit;

	ret = test_wifi_address();
	if (ret != S_OK)
		goto exit;

	ret = test_serial_number();
	if (ret != S_OK)
		goto exit;

	ret = test_platform_manufacturer();
	if (ret != S_OK)
		goto exit;

	ret = test_platform_uptime();
	if (ret != S_OK)
		goto exit;

	ret = test_platform_model_number();
	if (ret != S_OK)
		goto exit;

	ret = test_device_information();
	if (ret != S_OK)
		goto exit;

exit:
	return (ret == S_OK) ? 0 : -1;
}
