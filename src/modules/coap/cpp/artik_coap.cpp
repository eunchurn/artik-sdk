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

#include "artik_coap.hh"

artik::Coap::Coap() {
  m_module = reinterpret_cast<artik_coap_module*>(
      artik_request_api_module("coap"));
  this->m_handle = NULL;
  memset(&this->m_config, 0, sizeof(artik_coap_config));
}

artik::Coap::Coap(artik_coap_config *config) {
  this->m_module = reinterpret_cast<artik_coap_module*>(
      artik_request_api_module("coap"));
  this->m_handle = NULL;
  memcpy(&this->m_config, config, sizeof(artik_coap_config));
}

artik::Coap::~Coap() {
  artik_release_api_module(reinterpret_cast<void*>(this->m_module));
}

artik_error artik::Coap::create_client() {
  return this->m_module->create_client(&this->m_handle, &this->m_config);
}

artik_error artik::Coap::destroy_client() {
  return this->m_module->destroy_client(this->m_handle);
}

artik_error artik::Coap::connect() {
  return this->m_module->connect(this->m_handle);
}

artik_error artik::Coap::disconnect() {
  return this->m_module->disconnect(this->m_handle);
}

artik_error artik::Coap::create_server() {
  return this->m_module->create_server(&this->m_handle, &this->m_config);
}

artik_error artik::Coap::destroy_server() {
  return this->m_module->destroy_server(this->m_handle);
}

artik_error artik::Coap::start_server() {
  return this->m_module->start_server(this->m_handle);
}

artik_error artik::Coap::stop_server() {
  return this->m_module->stop_server(this->m_handle);
}

artik_error artik::Coap::send_message(const char *path, artik_coap_msg *msg) {
  return this->m_module->send_message(this->m_handle, path, msg);
}

artik_error artik::Coap::observe(const char *path, artik_coap_msg_type msg_type,
                          artik_coap_option *options, int num_options,
                          unsigned char *token, uint32_t token_len) {
  return this->m_module->observe(this->m_handle, path, msg_type, options,
                          num_options, token, token_len);
}

artik_error artik::Coap::cancel_observe(const char *path, unsigned char *token,
                          uint32_t token_len) {
  return this->m_module->cancel_observe(this->m_handle, path, token, token_len);
}

artik_error artik::Coap::init_resources(artik_coap_resource * resources,
                          int num_resources) {
  return this->m_module->init_resources(this->m_handle, resources,
                                        num_resources);
}

artik_error artik::Coap::notify_resource_changed(const char *path) {
  return this->m_module->notify_resource_changed(this->m_handle, path);
}

artik_error artik::Coap::set_send_callback(artik_coap_send_callback callback,
                          void *user_data) {
  return this->m_module->set_send_callback(this->m_handle, callback, user_data);
}

artik_error artik::Coap::set_observe_callback(
                          artik_coap_observe_callback callback,
                          void *user_data) {
  return this->m_module->set_observe_callback(this->m_handle, callback,
                          user_data);
}

artik_error artik::Coap::set_verify_psk_callback(
                          artik_coap_verify_psk_callback callback,
                          void *user_data) {
  return this->m_module->set_verify_psk_callback(this->m_handle, callback,
                          user_data);
}
