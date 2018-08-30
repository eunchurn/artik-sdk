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

#include "artik_uri.hh"
#include "artik_error.hh"

artik::Uri::Uri(const char *uri) {
  artik_error err;
  m_module =
    reinterpret_cast<artik_utils_module*>(artik_request_api_module("utils"));

  err = m_module->get_uri_info(&m_info, uri);
  if (err != S_OK) {
    artik_release_api_module(reinterpret_cast<void*>(m_module));
    artik_throw(artik::ArtikBadArgsException());
  }
}

artik::Uri::~Uri() {
  m_module->free_uri_info(&m_info);
  artik_release_api_module(reinterpret_cast<void*>(m_module));
}

char *artik::Uri::get_scheme() {
  return m_info.scheme;
}

char *artik::Uri::get_hostname() {
  return m_info.hostname;
}

int artik::Uri::get_port() {
  return m_info.port;
}

char *artik::Uri::get_path() {
  return m_info.path;
}
