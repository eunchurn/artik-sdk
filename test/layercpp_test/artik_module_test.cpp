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

#include <artik_module.hh>
#include <artik_platform.h>

#include <iostream>

static artik::Module *module = NULL;

artik_error test_api_version(void) {
  artik_api_version version;
  artik_error ret = S_OK;

  std::cout << "TEST: " << __func__ << std::endl;
  ret = module->get_api_version(&version);
  if (ret == S_OK)
    std::cout << "ARTIK API version: " << version.version << std::endl;

  return ret;
}

artik_error test_platform_name(void) {
  int platid = -1;
  char platname[MAX_PLATFORM_NAME];
  artik_error ret = S_OK;

  std::cout <<  "TEST: " << __func__ << std::endl;
  platid = module->get_platform();
  ret = module->get_platform_name(platname);
  if (ret != S_OK)
    return ret;

  std::cout << "Platform ID: " << platid << std::endl;
  std::cout << "Platform name: " << platname << std::endl;

  return S_OK;
}

artik_error test_bt_address(void) {
  char btaddr[MAX_BT_ADDR + 1] = {0};
  artik_error ret = S_OK;

  std::cout << "TEST: " << __func__ << std::endl;
  ret = module->get_bt_mac_address(btaddr);
  if (ret != S_OK)
    return ret;

  std::cout << "Platform Bluetooth MAC address: " << btaddr << std::endl;

  return S_OK;
}

artik_error test_wifi_address(void) {
  char wifiaddr[MAX_WIFI_ADDR + 1] = {0};
  artik_error ret = S_OK;

  std::cout << "TEST: " << __func__ << std::endl;
  ret = module->get_wifi_mac_address(wifiaddr);
  if (ret != S_OK)
    return ret;

  std::cout << "Platform Wifi MAC address: " << wifiaddr << std::endl;

  return S_OK;
}

artik_error test_serial_number(void) {
  char sn[MAX_PLATFORM_SN + 1] = {0};
  artik_error ret = S_OK;

  std::cout << "TEST: " << __func__ << std::endl;
  ret = module->get_platform_serial_number(sn);
  if (ret != S_OK)
    return ret;

  std::cout << "Platform Serial Number: " << sn << std::endl;

  return S_OK;
}

artik_error test_platform_manufacturer(void) {
  char manu[MAX_PLATFORM_MANUFACT + 1] = {0};
  artik_error ret = S_OK;

  std::cout << "TEST: " << __func__ << std::endl;
  ret = module->get_platform_manufacturer(manu);
  if (ret != S_OK)
    return ret;

  std::cout << "Platform Manufacturer: " << manu << std::endl;

  return S_OK;
}

artik_error test_platform_uptime(void) {
  int64_t uptime = 0;
  artik_error ret = S_OK;

  std::cout << "TEST: " << __func__ << std::endl;
  ret = module->get_platform_uptime(&uptime);
  if (ret != S_OK)
    return ret;

  std::cout << "Platform uptime: " << uptime << std::endl;

  return S_OK;
}

artik_error test_platform_model_number(void) {
  char modelnum[MAX_PLATFORM_MODELNUM + 1] = {0};
  artik_error ret = S_OK;

  std::cout << "TEST:" <<  __func__ << std::endl;
  ret = module->get_platform_model_number(modelnum);
  if (ret != S_OK)
    return ret;

  std::cout << "Platform model number: " << modelnum << std::endl;

  return S_OK;
}


artik_error test_api_modules(void) {
  artik_api_module *modules = NULL;
  int num_modules = 0;
  artik_error ret = S_OK;
  int i = 0;

  std::cout << "TEST:" <<  __func__ << std::endl;
  std::cout << "Available Modules:" << std::endl;

  ret = module->get_available_modules(&modules, &num_modules);
  if (ret != S_OK)
    return ret;

  for (i = 0; i < num_modules; i++)
    std::cout << "\t" << modules[i].id << modules[i].name << std::endl;

  std::cout << "Is GPIO module available: " <<
  (artik_is_module_available(ARTIK_MODULE_GPIO) ? "Yes" : "No") << std::endl;
  std::cout << "Is I2C module available: " <<
  (artik_is_module_available(ARTIK_MODULE_I2C) ? "Yes" : "No") << std::endl;
  std::cout << "Is SERIAL module available: " <<
  (artik_is_module_available(ARTIK_MODULE_SERIAL) ? "Yes" : "No") << std::endl;
  std::cout << "Is PWM module available: " <<
  (artik_is_module_available(ARTIK_MODULE_PWM) ? "Yes" : "No") << std::endl;
  std::cout << "Is ADC module available: " <<
  (artik_is_module_available(ARTIK_MODULE_ADC) ? "Yes" : "No") << std::endl;
  std::cout << "Is HTTP module available: " <<
  (artik_is_module_available(ARTIK_MODULE_HTTP) ? "Yes" : "No") << std::endl;
  std::cout << "Is CLOUD module available: " <<
  (artik_is_module_available(ARTIK_MODULE_CLOUD) ? "Yes" : "No") << std::endl;
  std::cout << "Is WIFI module available: " <<
  (artik_is_module_available(ARTIK_MODULE_WIFI) ? "Yes" : "No") << std::endl;
  std::cout << "Is MEDIA module available: " <<
  (artik_is_module_available(ARTIK_MODULE_MEDIA) ? "Yes" : "No") << std::endl;

  return ret;
}

artik_error test_device_information(void) {
  char *info = NULL;
  std::cout << "TEST:" <<  __func__ << std::endl;
  info = module->get_device_info();
  std::cout << "Device Info:" << info << std::endl;
  free(info);

  return S_OK;
}

int main(void) {
  artik_error ret = S_OK;
  std::cout << "artik_module_test:" << std::endl;

  // Create module object
  module = new artik::Module();
  if (module == NULL)
    goto exit;

  ret = test_api_version();
  if (ret != S_OK)
    goto exit;

  ret = test_platform_name();
  if (ret != S_OK)
    goto exit;

  ret = test_api_modules();
  if (ret != S_OK)
    goto exit;

  ret = test_device_information();
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

exit:
  // Delete module object
  if (module != NULL)
    delete module;

  std::cout << "ret = " << ret << std::endl;
  return (ret == S_OK) ? 0 : -1;
}
