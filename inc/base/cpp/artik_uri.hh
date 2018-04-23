/*
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#ifndef BASE_CPP_ARTIK_URI_HH_
#define BASE_CPP_ARTIK_URI_HH_

#include <artik_module.h>
#include <artik_utils.h>

/*! \file artik_utils.hh
 *
 *  \brief C++ Wrapper to the utils module
 *
 *  This is a class encapsulation of the C
 *  URI module API \ref artik_uri.h
 */

namespace artik {
/*!
 *  \brief URI module C++ Class
 */

class Uri {
 private:
  artik_utils_module *m_module;
  artik_uri_info m_info;

 public:
  explicit Uri(const char *uri);
  ~Uri();

  char *get_scheme();
  char *get_hostname();
  int get_port();
  char *get_path();

 private:
  Uri(const Uri& uri);
  Uri& operator=(const Uri& uri);
};

}  // namespace artik

#endif  // BASE_CPP_ARTIK_URI_HH_
