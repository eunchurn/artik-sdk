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
#include <stdint.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <pthread.h>

#include <artik_types.h>
#include <artik_log.h>
#include <artik_module.h>
#include <artik_platform.h>

#include "os_module.h"

#define MAX_STR_LEN 1024
#define PATH_STRING "libartik-sdk-%s.so.%d.%d.%d"
#define MODULE_STRING "%s_module"

static pthread_mutex_t lock;
static bool lock_initialized = false;

static void mutex_lock(void)
{
	if (!lock_initialized) {
		pthread_mutex_init(&lock, NULL);
		lock_initialized = true;
	}
	pthread_mutex_lock(&lock);
}

static void mutex_unlock(void)
{
	pthread_mutex_unlock(&lock);
}

static artik_list *requested_node = NULL;

typedef struct artik_module_info_t {
	char *module_name;
	void *dl_handle;
	void *dl_symbol;
} artik_module_info;

typedef struct artik_module_handle_t {
	artik_list node;
	artik_module_info info;
} artik_module_node;

static int artik_platform_id = -1;

/*
 * This table must follow exactly the same order as the
 * platform ID definition enum in artik_platform.h
 */
static const artik_api_module *artik_api_modules[] = {
	artik_api_generic_modules,
	artik_api_a520_modules,
	artik_api_a1020_modules,
	artik_api_a710_modules,
	artik_api_a530_modules,
	NULL,
	artik_api_a305_modules,
	artik_api_eagleye530_modules
};

artik_error os_get_api_version(artik_api_version *version)
{
	if (!version)
		return E_BAD_ARGS;

	version->major = LIB_VERSION_MAJOR;
	version->minor = LIB_VERSION_MINOR;
	version->patch = LIB_VERSION_PATCH;
	snprintf(version->version, MAX_VERSION_STRING, "%d.%d.%d",
		 LIB_VERSION_MAJOR, LIB_VERSION_MINOR, LIB_VERSION_PATCH);

	return S_OK;
}

static void *artik_compare_module_name(void *node, void *target)
{
	if (strncmp(((artik_module_node *)node)->info.module_name,
				(char *)target, strlen((char *)target)) == 0) {
		/* if the modules are same */
		return node;
	}
	/* if not */
	return NULL;
}

static void *artik_compare_module_ops(void *node, artik_module_ops target)
{
	if (memcmp(((artik_module_node *)node)->info.dl_symbol, target,
							sizeof(void *)) == 0) {
		/* if the modules are same */
		return node;
	}
	/* if not */
	return NULL;
}

artik_module_ops os_request_api_module(const char *name)
{
	artik_list *node = NULL;
	void *dl_handle = NULL;
	void *dl_symbol = NULL;
	char str_buf[MAX_STR_LEN] = {0, };
	char *module_name = NULL;
	char *error_msg;
	unsigned int i = 0, len = 0;
	int platid = os_get_platform();

	if (!name || (platid < 0))
		return INVALID_MODULE;

	while (artik_api_modules[platid][i].object != NULL) {
		if (!strncmp(artik_api_modules[platid][i].name, name,
							MAX_MODULE_NAME)) {

			mutex_lock();

			node = artik_list_get_by_check(requested_node,
				artik_compare_module_name, (void *)name);
			if (node) {
				module_name = ((artik_module_node *)
							node)->info.module_name;
				dl_symbol = ((artik_module_node *)
							node)->info.dl_symbol;
				dl_handle = ((artik_module_node *)
							node)->info.dl_handle;
			}

			node = artik_list_add(&requested_node, 0,
						sizeof(artik_module_node));
			if (node == NULL) {
				mutex_unlock();
				return INVALID_MODULE;
			} else if (dl_handle) {
				/* don't need to call DL again */
				goto exit;
			}

			memset(str_buf, 0, sizeof(str_buf));
			snprintf(str_buf, MAX_STR_LEN, PATH_STRING,
					artik_api_modules[platid][i].object,
					LIB_VERSION_MAJOR,
					LIB_VERSION_MINOR, LIB_VERSION_PATCH);
			dl_handle = (void *)dlopen(str_buf, RTLD_NOW|RTLD_GLOBAL);
			if (!dl_handle) {
				mutex_unlock();
				return INVALID_MODULE;
			}

			memset(str_buf, 0, sizeof(str_buf));
			snprintf(str_buf, MAX_STR_LEN, MODULE_STRING, name);
			dlerror();
			dl_symbol = dlsym(dl_handle, str_buf);
			error_msg = dlerror();
			if (error_msg != NULL) {
				dlclose(dl_handle);
				mutex_unlock();
				return INVALID_MODULE;
			}

exit:
			if (module_name == NULL) {
				len = strlen(name) + 1;
				module_name = malloc(len);
				if (module_name == NULL) {
					dlclose(dl_handle);
					mutex_unlock();
					return INVALID_MODULE;
				}
				memset(module_name, 0, len);
				strncpy(module_name, name, len);
			}

			((artik_module_node *)node)->info.module_name =
								module_name;
			((artik_module_node *)node)->info.dl_handle = dl_handle;
			((artik_module_node *)node)->info.dl_symbol = dl_symbol;

			mutex_unlock();

			break;
		}
		i++;
	}

	return (artik_module_ops)dl_symbol;
}

artik_error os_release_api_module(const artik_module_ops module)
{
	artik_list *node = NULL;
	artik_error ret = S_OK;
	void *dl_handle = NULL;
	char *module_name = NULL;

	mutex_lock();

	node = artik_list_get_by_check(requested_node, artik_compare_module_ops,
									module);
	if (node == NULL) {
		log_err("releasing invalid module");
		ret = E_BAD_ARGS;
		goto exit;
	}

	dl_handle = ((artik_module_node *)node)->info.dl_handle;
	module_name = ((artik_module_node *)node)->info.module_name;

	ret = artik_list_delete_check(&requested_node, artik_compare_module_ops,
									module);
	if (ret != S_OK) {
		log_err("failed to delete module");
		goto exit;
	}

	node = artik_list_get_by_check(requested_node, artik_compare_module_ops,
									module);
	if (node == NULL) {
		free(module_name);
		dlclose(dl_handle);
	}

exit:
	mutex_unlock();

	return ret;
}

int os_get_platform(void)
{
	FILE *f = NULL;
	char line[256];

	if (artik_platform_id >= GENERIC)
		goto exit;

	f = fopen("/proc/device-tree/model", "re");
	if (f == NULL)
		return -1;

	if (fgets(line, sizeof(line), f) != NULL) {
		if (strstr(line, "ARTIK5"))
			artik_platform_id = ARTIK520;
		else if (strstr(line, "ARTIK10"))
			artik_platform_id = ARTIK1020;
		else if (strstr(line, "artik710"))
			artik_platform_id = ARTIK710;
		else if (strstr(line, "compy"))
			artik_platform_id = EAGLEYE530;
		else if (strstr(line, "artik530"))
			artik_platform_id = ARTIK530;
		else if (strstr(line, "artik305"))
			artik_platform_id = ARTIK305;
		else
			artik_platform_id = GENERIC;
	}
	fclose(f);

exit:
	return artik_platform_id;
}

artik_error os_get_platform_name(char *name)
{
	int platid = artik_get_platform();

	if (platid < 0)
		return E_NOT_SUPPORTED;

	if (!name)
		return E_BAD_ARGS;

	strncpy(name, artik_platform_name[platid], MAX_PLATFORM_NAME);

	return S_OK;
}

artik_error os_get_available_modules(artik_api_module **modules, int
								*num_modules)
{
	unsigned int i = 0;
	int platid = artik_get_platform();

	if (platid < 0)
		return E_NOT_SUPPORTED;

	if (!modules || !num_modules)
		return E_BAD_ARGS;

	/* Count number of entries in the modules array */
	while (artik_api_modules[platid][i].object != NULL)
		i++;

	*modules = (artik_api_module *)artik_api_modules[platid];
	*num_modules = i;

	return S_OK;
}

bool os_is_module_available(artik_module_id_t id)
{
	unsigned int i = 0;
	bool found = false;
	int platid = artik_get_platform();

	if (platid < 0)
		return false;

	while (artik_api_modules[platid][i].object != NULL) {
		if (artik_api_modules[platid][i].id == id) {
			found = true;
			break;
		}
		i++;
	}

	return found;
}

char *os_get_device_info(void)
{
	char *entry = NULL;
	char *json = NULL;
	int max_plat_name_len = 0, max_module_len = 0, max_json_len = 0,
	max_bt_mac_addr_len = 0, max_wifi_mac_addr_len = 0,
	max_plat_sn_len = 0, max_plat_manu_len = 0,
	max_plat_uptime_len = 0, max_plat_modelnum_len = 0;

	artik_api_module *modules = NULL;
	int num_modules = 0;
	int i = 0;

	char header[] = "{\n";
	char tail[] = "\n}";

	char platform_info[] = "\t\"name\": \"%s\",\n";
	char modules_headher[] = "\t\"modules\":[\n";
	char modules_tail[] = "\t],\n";
	char modules_info[] = "\t\"%s\",\n";

	char bt_text_info[] = "\t\"bt_mac_addr\": \"%s\",\n";
	char bt_mac_addr[MAX_BT_ADDR+1] = {0};

	char wifi_text_info[] = "\t\"wifi_mac_addr\": \"%s\",\n";
	char wifi_mac_addr[MAX_WIFI_ADDR+1] = {0};

	char sn_text_info[] = "\t\"serial_number\": \"%s\",\n";
	char platform_sn[MAX_PLATFORM_SN+1] = {0};

	char manu_text_info[] = "\t\"manufacturer\": \"%s\",\n";
	char platform_manu[MAX_PLATFORM_MANUFACT+1] = {0};

	char uptime_text_info[] = "\t\"uptime\": \"%lld\",\n";
	int64_t platform_uptime = 0;

	char modelnum_text_info[] = "\t\"model_number\": \"%s\",\n";
	char platform_modelnum[MAX_PLATFORM_MODELNUM+1] = {0};

	int platid = artik_get_platform();

	artik_get_available_modules(&modules, &num_modules);

	max_plat_name_len = strlen(platform_info) + MAX_PLATFORM_NAME; /* Platform name */

	max_module_len = strlen(modules_info) + MAX_MODULE_NAME; /* module name */

	max_bt_mac_addr_len = strlen(bt_text_info) + MAX_BT_ADDR; /* Bluetooth MAC Addr */

	max_wifi_mac_addr_len = strlen(wifi_text_info) + MAX_WIFI_ADDR; /* Wifi MAC Addr */

	max_plat_sn_len =  strlen(sn_text_info) + MAX_PLATFORM_SN; /* Serial number */

	max_plat_manu_len =  strlen(manu_text_info) + MAX_PLATFORM_MANUFACT; /* Platform manufacturer */

	max_plat_uptime_len =  strlen(uptime_text_info) + sizeof(platform_uptime); /* Platform uptime */

	max_plat_modelnum_len =  strlen(modelnum_text_info) + MAX_PLATFORM_MODELNUM; /* Platform model number */

	max_json_len = max_plat_name_len + (max_module_len * num_modules) +
					max_bt_mac_addr_len + max_wifi_mac_addr_len +
					max_plat_sn_len + max_plat_manu_len +
					max_plat_uptime_len + max_plat_modelnum_len +
					strlen(header) + strlen(tail) +
					strlen(modules_headher) +
					strlen(modules_tail) + 1;
	json = (char *)malloc(max_json_len);
	if (!json)
		return json;

	/* Start building the JSON string */
	memset(json, 0, max_json_len);
	strncat(json, header, strlen(header));

	entry = (char *)malloc(max_plat_name_len);
	if (!entry) {
		free(json);
		return NULL;
	}

	if (platid == ARTIK520)
		snprintf(entry, max_plat_name_len, platform_info, "ARTIK520");
	else if (platid == ARTIK1020)
		snprintf(entry, max_plat_name_len, platform_info, "ARTIK1020");
	else if (platid == ARTIK710)
		snprintf(entry, max_plat_name_len, platform_info, "ARTIK710");
	else if (platid == ARTIK530)
		snprintf(entry, max_plat_name_len, platform_info, "ARTIK530");
	else if (platid == EAGLEYE530)
		snprintf(entry, max_plat_name_len, platform_info, "EAGLEYE530");
	else
		snprintf(entry, max_plat_name_len, platform_info, "GENERIC");

	/* Copy platform info */
	strncat(json, entry, max_plat_name_len);
	free(entry);

	/* Copy available modules */
	strncat(json, modules_headher, strlen(modules_headher));

	for (i = 0; i < num_modules; i++) {
		entry = (char *)malloc(max_module_len);
		if (!entry) {
			free(json);
			return NULL;
		}
		snprintf(entry, max_module_len, modules_info, modules[i].name);
		strncat(json, entry, max_module_len);
		free(entry);
	}

	/* Remove last comma */
	json[strlen(json) - 2] = '\n';
	json[strlen(json) - 1] = '\0';

	strncat(json, modules_tail, strlen(modules_tail));

	/* Copy available bt mac addr */
	entry = (char *)malloc(max_bt_mac_addr_len);
	if (!entry) {
		free(json);
		return NULL;
	}
	os_get_bt_mac_address(bt_mac_addr);

	snprintf(entry, max_bt_mac_addr_len, bt_text_info, bt_mac_addr);
	strncat(json, entry, max_bt_mac_addr_len);
	free(entry);

	/* Copy available wifi mac addr */
	entry = (char *)malloc(max_wifi_mac_addr_len);
	if (!entry) {
		free(json);
		return NULL;
	}
	os_get_wifi_mac_address(wifi_mac_addr);

	snprintf(entry, max_wifi_mac_addr_len, wifi_text_info, wifi_mac_addr);
	strncat(json, entry, max_wifi_mac_addr_len);
	free(entry);

	/* Copy available platform serial number */
	entry = (char *)malloc(max_plat_sn_len);
	if (!entry) {
		free(json);
		return NULL;
	}
	os_get_platform_serial_number(platform_sn);

	snprintf(entry, max_plat_sn_len, sn_text_info, platform_sn);
	strncat(json, entry, max_plat_sn_len);
	free(entry);

	/* Copy available platform manufacturer */
	entry = (char *)malloc(max_plat_manu_len);
	if (!entry) {
		free(json);
		return NULL;
	}
	os_get_platform_manufacturer(platform_manu);

	snprintf(entry, max_plat_manu_len, manu_text_info, platform_manu);
	strncat(json, entry, max_plat_manu_len);
	free(entry);


	/* Copy available platform uptime */
	entry = (char *)malloc(max_plat_uptime_len);
	if (!entry) {
		free(json);
		return NULL;
	}
	os_get_platform_uptime(&platform_uptime);

	snprintf(entry, max_plat_uptime_len, uptime_text_info, platform_uptime);
	strncat(json, entry, max_plat_uptime_len);
	free(entry);

	/* Copy available platform model number */
	entry = (char *)malloc(max_plat_modelnum_len);
	if (!entry) {
		free(json);
		return NULL;
	}
	os_get_platform_model_number(platform_modelnum);

	snprintf(entry, max_plat_modelnum_len, modelnum_text_info, platform_modelnum);
	strncat(json, entry, max_plat_modelnum_len);
	free(entry);

	/* Remove last comma */
	json[strlen(json) - 2] = '\n';
	json[strlen(json) - 1] = '\0';

	strncat(json, tail, strlen(tail));

	return json;
}

artik_error os_get_bt_mac_address(char *addr)
{
	FILE *f = NULL;

	f = fopen("/sys/class/bluetooth/hci0/address", "re");
	if (f == NULL)
		return E_ACCESS_DENIED;

	if (fgets(addr, MAX_BT_ADDR, f) == NULL) {
		fclose(f);
		return E_ACCESS_DENIED;
	}

	fclose(f);

	return S_OK;
}

artik_error os_get_wifi_mac_address(char *addr)
{
	FILE *f = NULL;

	f = fopen("/sys/class/net/wlan0/address", "re");
	if (f == NULL)
		return E_ACCESS_DENIED;

	if (fgets(addr, MAX_WIFI_ADDR, f) == NULL) {
		fclose(f);
		return E_ACCESS_DENIED;
	}

	fclose(f);

	return S_OK;
}

artik_error os_get_platform_serial_number(char *sn)
{
	FILE *f = NULL;

	f = fopen("/proc/device-tree/serial-number", "re");
	if (f == NULL)
		return E_ACCESS_DENIED;

	if (fgets(sn, MAX_PLATFORM_SN, f) == NULL) {
		fclose(f);
		return E_ACCESS_DENIED;
	}

	fclose(f);

	return S_OK;
}

artik_error os_get_platform_manufacturer(char *manu)
{
	strncpy(manu, "SAMSUNG", strlen("SAMSUNG"));
	return S_OK;
}

artik_error os_get_platform_uptime(int64_t *uptime)
{
	FILE *f = NULL;
	double uptime_seconds = 0;

	/* first get the uptime */
	f = fopen("/proc/uptime", "re");
	if (f == NULL)
		return E_ACCESS_DENIED;

	/* read uptime in second*/
	if (fscanf(f, "%lf", &uptime_seconds) < 1) {
		fclose(f);
		return E_ACCESS_DENIED;
	}

	*uptime = (int64_t)uptime_seconds;

	fclose(f);

	return S_OK;
}

artik_error os_get_platform_model_number(char *modelnum)
{
	FILE *f = NULL;
	char line[256];

	f = fopen("/etc/artik_release", "re");
	if (f == NULL)
		return E_ACCESS_DENIED;

	do {
		if (fgets(line, sizeof(line), f) == NULL) {
			fclose(f);
			return E_ACCESS_DENIED;
		}
	} while (strstr(line, "MODEL=") == NULL);

	/* In /etc/artik_release file... delete the "MODEL=" string */
	strncpy(modelnum, line+strlen("MODEL="), strlen(line)-strlen("MODEL=\n"));

	fclose(f);

	return S_OK;


}
