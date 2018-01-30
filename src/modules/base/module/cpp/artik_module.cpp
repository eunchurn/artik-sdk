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
#include "artik_module.hh"

artik::Module::Module() {
}

artik::Module::~Module() {
}

artik_error artik::Module::get_api_version(
  artik_api_version * version) {
  return artik_get_api_version(version);
}

int artik::Module::get_platform(void) {
  return artik_get_platform();
}

artik_error artik::Module::get_platform_name(char *name) {
  return artik_get_platform_name(name);
}

artik_error artik::Module::get_available_modules(
  artik_api_module **modules, int *num_modules) {
  return artik_get_available_modules(modules, num_modules);
}

bool artik::Module::is_module_available(artik_module_id_t id) {
  return artik_is_module_available(id);
}

char * artik::Module::get_device_info(void) {
  return artik_get_device_info();
}

artik_error artik::Module::get_bt_mac_address(char *addr) {
  return artik_get_bt_mac_address(addr);
}

artik_error artik::Module::get_wifi_mac_address(char *addr) {
  return artik_get_wifi_mac_address(addr);
}

artik_error artik::Module::get_platform_serial_number(char *sn) {
  return artik_get_platform_serial_number(sn);
}

artik_error artik::Module::get_platform_manufacturer(char *manu) {
  return artik_get_platform_manufacturer(manu);
}

artik_error artik::Module::get_platform_uptime(int64_t *uptime) {
  return artik_get_platform_uptime(uptime);
}

artik_error artik::Module::get_platform_model_number(char *modelnum) {
  return artik_get_platform_model_number(modelnum);
}
