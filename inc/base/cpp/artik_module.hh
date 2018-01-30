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

#ifndef BASE_CPP_ARTIK_MODULE_HH_
#define BASE_CPP_ARTIK_MODULE_HH_

#include <artik_module.h>
#include <artik_error.hh>

/*! \file artik_module.hh
 *
 *  \brief C++ Wrapper to the base module
 *
 *  This is a class encapsulation of the C
 *  base module API \ref artik_module.h
 */
namespace artik {
/*!
 * \brief module C++ class
 */
class Module {
 public:
  Module();
  ~Module();

  artik_error get_api_version(artik_api_version * version);
  int get_platform(void);
  artik_error get_platform_name(char *name);
  artik_error get_available_modules(artik_api_module **modules,
          int *num_modules);
  bool is_module_available(artik_module_id_t id);
  char *get_device_info(void);

  artik_error get_bt_mac_address(char *addr);
  artik_error get_wifi_mac_address(char *addr);
  artik_error get_platform_serial_number(char *sn);
  artik_error get_platform_manufacturer(char *manu);
  artik_error get_platform_uptime(int64_t *uptime);
  artik_error get_platform_model_number(char *modelnum);
};

}  // namespace artik

#endif  // BASE_CPP_ARTIK_MODULE_HH_
