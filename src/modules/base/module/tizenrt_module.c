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

#include <artik_types.h>
#include <artik_module.h>
#include <artik_network.h>
#include <artik_platform.h>

#include "os_module.h"

#include <net/if.h>
#include <netlib.h>
#include <tinyara/clock.h>
#include <cJSON.h>

typedef struct {

	int id;

	const artik_api_module *modules;

} tizenrt_platform;

static const tizenrt_platform artik_api_modules[] = {
	{ ARTIK05x, artik_api_a05x_modules },
	{ -1,		NULL}
};

artik_error os_get_api_version(artik_api_version *version)
{
	if (!version)
		return E_BAD_ARGS;

#ifdef LIB_VERSION_MAJOR
	version->major = LIB_VERSION_MAJOR;

#ifdef LIB_VERSION_MINOR
	version->minor = LIB_VERSION_MINOR;

#ifdef LIB_VERSION_PATCH
	version->patch = LIB_VERSION_PATCH;

	snprintf(version->version, MAX_VERSION_STRING, "%d.%d.%d",
		LIB_VERSION_MAJOR, LIB_VERSION_MINOR, LIB_VERSION_PATCH);
#endif
#endif
#endif

	return S_OK;
}

artik_module_ops os_request_api_module(const char *name)
{
	int i = 0, plat = 0;
	artik_module_ops ops = (artik_module_ops)NULL;

	if ((os_get_platform() == -1) || !name)
		return NULL;

	while (artik_api_modules[plat].modules) {
		if (artik_api_modules[plat].id == os_get_platform()) {
			artik_api_module *p_target = (artik_api_module *)
				artik_api_modules[plat].modules;

			for (; p_target->name; p_target++, i++) {
				if (strncmp(p_target->name, name,
					MAX_MODULE_NAME) == 0) {
					ops = (artik_module_ops)
					      p_target->object;
					break;
				}
			}
		}
		plat++;
	}

	return ops;
}

artik_error os_release_api_module(const artik_module_ops module)
{
	int i = 0, plat = 0;
	artik_error ret = E_BAD_ARGS;

	if (os_get_platform() == -1)
		return E_NOT_SUPPORTED;

	while (artik_api_modules[plat].modules) {
		if (artik_api_modules[plat].id == os_get_platform()) {
			artik_api_module *p_target = (artik_api_module *)
				artik_api_modules[plat].modules;

			for (; p_target->name; p_target++, i++) {
				if (p_target->object == module) {
					/*
					 * Nothing to do here, may need to
					 * do some cleanup later
					 */
					ret = S_OK;
					break;
				}
			}
		}
		plat++;
	}

	return ret;
}

int os_get_platform(void)
{
	/*
	 * For each platform ID that may be returned here,
	 * appropriate entry in "artik_api_modules" must
	 * be filled up.
	 *
	 */
#if defined(CONFIG_ARCH_BOARD_ARTIK05X_FAMILY)
	return ARTIK05x;
#else
	return -1;
#endif
}

artik_error os_get_platform_name(char *name)
{
	if (!name)
		return E_BAD_ARGS;

	if (os_get_platform() == -1)
		return E_NOT_SUPPORTED;

	strncpy(name, artik_platform_name[os_get_platform()], MAX_PLATFORM_NAME);

	return S_OK;
}

artik_error os_get_available_modules(artik_api_module **modules, int *num_modules)
{
	unsigned int i = 0;
	int plat = 0;

	if (!modules || !num_modules)
		return E_BAD_ARGS;

	if (os_get_platform() == -1)
		return E_NOT_SUPPORTED;

	while (artik_api_modules[plat].modules) {
		if (artik_api_modules[plat].id == os_get_platform()) {
			*modules = (artik_api_module *)
				artik_api_modules[plat].modules;

			/* Count number of entries in the modules array */
			while ((*modules)[i].name != NULL)
				i++;

			*num_modules = i;
		}
		plat++;
	}

	return S_OK;
}

bool os_is_module_available(artik_module_id_t id)
{
	int plat = 0;

	if (os_get_platform() == -1)
		return false;

	while (artik_api_modules[plat].modules) {
		if (artik_api_modules[plat].id == os_get_platform()) {
			artik_api_module *p_module = (artik_api_module *)
				artik_api_modules[plat].modules;

			for (; p_module->name; p_module++) {
				if (p_module->id == id)
					return true;
			}
		}
		plat++;
	}

	return false;
}

char *os_get_device_info(void)
{
	artik_api_module *modules = NULL;
	int num_modules = 0;
	int i = 0;
	char bt_mac_addr[MAX_BT_ADDR + 1] = {0};
	char wifi_mac_addr[MAX_WIFI_ADDR + 1] = {0};
	char platform_sn[MAX_PLATFORM_SN + 1] = {0};
	char platform_manu[MAX_PLATFORM_MANUFACT + 1] = {0};
	char platform_modelnum[MAX_PLATFORM_MODELNUM + 1] = {0};
	int64_t platform_uptime = 0;
	cJSON *resp = cJSON_CreateObject();
	cJSON *array = cJSON_CreateArray();
	int platid = os_get_platform();
	char *body = NULL;

	/* Copy platform info */
	if (platid == -1)
		return NULL;

	cJSON_AddStringToObject(resp, "name", artik_platform_name[platid]);

	/* Copy available modules */
	if (os_get_available_modules(&modules, &num_modules) == S_OK) {
		for (i = 0; i < num_modules; i++)
			cJSON_AddStringToObject(array, "", modules[i].name);

		cJSON_AddItemToObject(resp, "modules", array);
	}

	/* Copy available bt mac addr */
	if (os_get_bt_mac_address(bt_mac_addr) == S_OK)
		cJSON_AddStringToObject(resp, "bt_mac_addr", bt_mac_addr);

	/* Copy available wifi mac addr */
	if (os_get_wifi_mac_address(wifi_mac_addr) == S_OK)
		cJSON_AddStringToObject(resp, "wifi_mac_addr", wifi_mac_addr);

	/* Copy available platform serial number */
	if (os_get_platform_serial_number(platform_sn) == S_OK)
		cJSON_AddStringToObject(resp, "serial_number", platform_sn);

	/* Copy available platform manufacturer */
	if (os_get_platform_manufacturer(platform_manu) == S_OK)
		cJSON_AddStringToObject(resp, "manufacturer", platform_manu);

	/* Copy available platform uptime */
	if (os_get_platform_uptime(&platform_uptime) == S_OK)
		cJSON_AddNumberToObject(resp, "uptime", platform_uptime);

	/* Copy available platform modelnum */
	if (os_get_platform_model_number(platform_modelnum) == S_OK)
		cJSON_AddStringToObject(resp, "model_number", platform_modelnum);

	body = cJSON_Print(resp);

	cJSON_Delete(resp);

	return body;
}

artik_error os_get_bt_mac_address(char *addr)
{
	return E_NOT_SUPPORTED;
}

artik_error os_get_wifi_mac_address(char *addr)
{
	uint8_t macaddr[IFHWADDRLEN];

	if (netlib_getmacaddr("wl1", macaddr) != OK)
		return E_NETWORK_ERROR;

	snprintf(addr, MAX_WIFI_ADDR+1, "%02x:%02x:%02x:%02x:%02x:%02x",
	macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);

	return S_OK;
}

artik_error os_get_platform_manufacturer(char *manu)
{
	strncpy(manu, "SAMSUNG", strlen("SAMSUNG"));
	return S_OK;
}

artik_error os_get_platform_serial_number(char *addr)
{
	return E_NOT_SUPPORTED;
}

artik_error os_get_platform_model_number(char *modelnum)
{
#ifdef CONFIG_ARCH_BOARD_ARTIK053
	strncpy(modelnum, "ARTIK053", strlen("ARTIK053"));
#endif
#ifdef CONFIG_ARCH_BOARD_ARTIK053S
	strncpy(modelnum, "ARTIK053S", strlen("ARTIK053S"));
#endif
#ifdef CONFIG_ARCH_BOARD_ARTIK055S
	strncpy(modelnum, "ARTIK055S", strlen("ARTIK055S"));
#endif
	return S_OK;
}

artik_error os_get_platform_uptime(int64_t *uptime)
{
	systime_t ticktime;

	ticktime = clock_systimer();

	/* Convert the system up time to seconds */
	*uptime = (int64_t)(ticktime / CLOCKS_PER_SEC);

	return S_OK;
}