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
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include <artik_module.h>
#include <artik_loop.h>
#include <artik_websocket.hh>

static const char *echo_websocket_root_ca =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\n"
  "MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n"
  "DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\n"
  "PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\n"
  "Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"
  "AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\n"
  "rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\n"
  "OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\n"
  "xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\n"
  "7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\n"
  "aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\n"
  "HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\n"
  "SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\n"
  "ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\n"
  "AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\n"
  "R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\n"
  "JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\n"
  "Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\n"
  "-----END CERTIFICATE-----\n";

static char *test_message = NULL;

static int quit_loop(void *user_data) {
  artik_loop_module *loop = reinterpret_cast<artik_loop_module*>(user_data);

  loop->quit();
  fprintf(stdout, "Loop quit!\n");

  return true;
}

void websocket_receive_callback(void *user_data, void *result) {
  char *buffer = reinterpret_cast<char*>(result);
  if (buffer == NULL) {
    fprintf(stdout, "Receive failed\n");
    return;
  }

  artik_loop_module *loop = reinterpret_cast<artik_loop_module*>(
      artik_request_api_module("loop"));

  printf("Received: %s\n", buffer);
  free(result);

  loop->quit();
  artik_release_api_module(loop);
}

void websocket_connection_callback(void *user_data, void *result) {
  artik::Websocket* websocket = (artik::Websocket*)user_data;
  intptr_t ret = reinterpret_cast<intptr_t>(result);

  if (ret == ARTIK_WEBSOCKET_CONNECTED) {
    fprintf(stdout, "Writing: %s\n", test_message);
    websocket->write_stream(test_message);
  } else if (ret == ARTIK_WEBSOCKET_CLOSED) {
    fprintf(stdout, "connection close\n");
    artik_loop_module *loop = reinterpret_cast<artik_loop_module*>(
        artik_request_api_module("loop"));
    loop->quit();
    artik_release_api_module(websocket);
    goto exit;
  } else if (ret == ARTIK_WEBSOCKET_CONNECTION_ERROR) {
    fprintf(stderr, "connection error\n");
    artik_loop_module *loop = reinterpret_cast<artik_loop_module*>(
        artik_request_api_module("loop"));
    loop->quit();
    artik_release_api_module(loop);
  } else {
    fprintf(stderr, "TEST failed, handshake error\n");
    artik_loop_module *loop = reinterpret_cast<artik_loop_module*>(
        artik_request_api_module("loop"));
    loop->quit();
    artik_release_api_module(loop);
  }

exit:
  return;
}

int main(int argc, char *argv[]) {
  int opt;
  bool verify = false;
  artik_error ret = S_OK;
  artik_loop_module *loop = reinterpret_cast<artik_loop_module*>(
      artik_request_api_module("loop"));
  char uri[26] = "ws://echo.websocket.org/";
  unsigned int ping_period = 10000;
  unsigned int pong_timeout = 5000;

  while ((opt = getopt(argc, argv, "m:vt")) != -1) {
    switch (opt) {
    case 'm':
      test_message = strndup(optarg, strlen(optarg)+1);
      break;
    case 'v':
      verify = true;
      break;
    case 't':
      snprintf(uri, sizeof(uri), "%s", "wss://echo.websocket.org/");
      break;
    default:
      printf("Usage: websocketcpp-test [-t for using TLS] [-m <message>]"
             " [-v for verifying CA certificate]\n");
      return 0;
    }
  }

  if (!test_message)
    test_message = strndup("ping", 5);

  artik_ssl_config ssl_config = { 0 };

  memset(&ssl_config, 0, sizeof(ssl_config));

  ssl_config.ca_cert.data = strdup(echo_websocket_root_ca);
  ssl_config.ca_cert.len = strlen(echo_websocket_root_ca);

  if (verify)
    ssl_config.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;
  else
    ssl_config.verify_cert = ARTIK_SSL_VERIFY_NONE;

  ssl_config.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;

  artik::Websocket* websocket = new artik::Websocket(uri, ping_period,
    pong_timeout, &ssl_config);

  ret = websocket->request();
  if (ret != S_OK) {
    fprintf(stderr, "request failed\n");
    goto exit;
  }
  ret = websocket->open_stream();
  if (ret != S_OK) {
    fprintf(stderr, "open_stream failed\n");
    goto exit;
  }

  ret = websocket->set_connection_callback(websocket_connection_callback,
      reinterpret_cast<void*>(websocket));
  if (ret != S_OK) {
    fprintf(stderr, "failed to set connection callback\n");
    goto exit;
  }

  ret = websocket->set_receive_callback(websocket_receive_callback,
      reinterpret_cast<void*>(websocket));
  if (ret != S_OK) {
    fprintf(stderr, "TEST failed, could not open Websocket\n");
    goto exit;
  }

  loop->add_signal_watch(SIGINT, quit_loop, reinterpret_cast<void *>(loop),
    NULL);
  loop->run();

exit:

  websocket->close_stream();
  websocket->release();

  printf("TEST FINISHED: WEBSOCKET_CPP_TEST\n");

  return (ret == S_OK) ? 0 : -1;
}
