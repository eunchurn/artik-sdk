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

#ifndef COAP_CPP_ARTIK_COAP_HH_
#define COAP_CPP_ARTIK_COAP_HH_

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <artik_module.h>
#include <artik_coap.h>

/*! \file artik_coap.hh
 *
 *  \brief C++ Wrapper to the CoAP module
 *
 *  This is a class encapsulation of the C
 *  CoAP module API \ref artik_coap.h
 */

namespace artik {
class Coap {
 private:
  artik_coap_module* m_module;
  artik_coap_config m_config;
  artik_coap_handle m_handle;

 public:
  Coap();
  explicit Coap(artik_coap_config *config);
  ~Coap();

  artik_error create_client();
  artik_error destroy_client();
  artik_error connect();
  artik_error disconnect();
  artik_error create_server();
  artik_error destroy_server();
  artik_error start_server();
  artik_error stop_server();
  artik_error send_message(const char *path, artik_coap_msg *msg);
  artik_error observe(const char *path, artik_coap_msg_type msg_type,
                      artik_coap_option *options, int num_options,
                      unsigned char *token, uint32_t token_len);
  artik_error cancel_observe(const char *path, unsigned char *token,
                      uint32_t token_len);
  artik_error init_resources(artik_coap_resource *resources, int num_resources);
  artik_error notify_resource_changed(const char *path);
  artik_error set_send_callback(artik_coap_send_callback callback,
                      void *user_data);
  artik_error set_observe_callback(artik_coap_observe_callback callback,
                      void *user_data);
  artik_error set_verify_psk_callback(artik_coap_verify_psk_callback callback,
                      void *user_data);
};
}  // namespace artik

#endif  // COAP_CPP_ARTIK_COAP_HH_
