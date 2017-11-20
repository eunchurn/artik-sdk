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

#ifndef INCLUDE_ARTIK_COAP_H_
#define INCLUDE_ARTIK_COAP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "artik_error.h"
#include "artik_types.h"
#include "artik_ssl.h"

/*! \file artik_coap.h
 *
 *  \brief CoAP module definition
 *
 *  Definitions and functions for accessing
 *  the CoAP module
 */

/*!
 *	\brief This enum defines predefined content formats for
 *             the option ARTIK_COAP_OPTION_CONTENT_FORMAT or
 *             ARTIK_COAP_OPTION_CONTENT_TYPE.
 */
typedef enum {
	/// plain
	ARTIK_OPTION_CONTENT_FORMAT_PLAIN		= 0,
	/// link-format
	ARTIK_OPTION_CONTENT_FORMAT_LINK_FORMAT		= 40,
	/// xml
	ARTIK_OPTION_CONTENT_FORMAT_XML			= 41,
	/// octet-stream
	ARTIK_OPTION_CONTENT_FORMAT_OCTET_STREAM	= 42,
	/// exi
	ARTIK_OPTION_CONTENT_FORMAT_EXI			= 47,
	/// json
	ARTIK_OPTION_CONTENT_FORMAT_JSON		= 50,
	/// cbor
	ARTIK_OPTION_CONTENT_FORMAT_CBOR		= 60
} artik_option_content_format;


/*!
 *	\brief This enum defines the supported CoAP options.
 */
typedef enum {
	/// C, opaque, 0-8 B, (none)
	ARTIK_COAP_OPTION_IF_MATCH		= 1,
	/// C, String, 1-255 B, destination address
	ARTIK_COAP_OPTION_URI_HOST		= 3,
	/// E, opaque, 1-8 B, (none)
	ARTIK_COAP_OPTION_ETAG			= 4,
	/// empty, 0 B, (none)
	ARTIK_COAP_OPTION_IF_NONE_MATCH		= 5,
	/// E, empty/uint, 0 B/0-3 B, (none)
	ARTIK_COAP_OPTION_OBSERVE		= 6,
	/// C, uint, 0-2 B, destination port
	ARTIK_COAP_OPTION_URI_PORT		= 7,
	/// E, String, 0-255 B, -
	ARTIK_COAP_OPTION_LOCATION_PATH		= 8,
	/// C, String, 0-255 B, (none)
	ARTIK_COAP_OPTION_URI_PATH		= 11,
	/// E, uint, 0-2 B, (none)
	ARTIK_COAP_OPTION_CONTENT_FORMAT	= 12,
	ARTIK_COAP_OPTION_CONTENT_TYPE		= ARTIK_COAP_OPTION_CONTENT_FORMAT,
	/// E, uint, 0--4 B, 60 Seconds
	ARTIK_COAP_OPTION_MAXAGE		= 14,
	/// C, String, 1-255 B, (none)
	ARTIK_COAP_OPTION_URI_QUERY		= 15,
	/// C, uint,   0-2 B, (none)
	ARTIK_COAP_OPTION_ACCEPT		= 17,
	/// E, String,   0-255 B, (none)
	ARTIK_COAP_OPTION_LOCATION_QUERY	= 20,
	/// C, uint, 0--3 B, (none)
	ARTIK_COAP_OPTION_BLOCK2		= 23,
	/// C, String, 1-1034 B, (none)
	ARTIK_COAP_OPTION_PROXY_URI		= 35,
	/// C, String, 1-255 B, (none)
	ARTIK_COAP_OPTION_PROXY_SCHEME		= 39,
	/// E, uint, 0-4 B, (none)
	ARTIK_COAP_OPTION_SIZE1			= 60
} artik_coap_option_key;

/*!
 *	\brief This enum defines the codes for
 *             request and response.
 */
typedef enum {
	/// Request Empty
	ARTIK_COAP_REQ_EMPTY				= 0,
	/// Request Get
	ARTIK_COAP_REQ_GET,
	/// Request Post
	ARTIK_COAP_REQ_POST,
	/// Request Put
	ARTIK_COAP_REQ_PUT,
	/// Request Delete
	ARTIK_COAP_REQ_DELETE,
	/// Reponse Created
	ARTIK_COAP_RES_CREATED				= 65,
	/// Response Deleted
	ARTIK_COAP_RES_DELETED,
	/// Response Valid
	ARTIK_COAP_RES_VALID,
	/// Response Changed
	ARTIK_COAP_RES_CHANGED,
	/// Response Content
	ARTIK_COAP_RES_CONTENT,
	/// Responnse Bad Request
	ARTIK_COAP_RES_BAD_REQUEST			= 128,
	/// Response Unauthorized
	ARTIK_COAP_RES_UNAUTHORIZED,
	/// Response Bad Option
	ARTIK_COAP_RES_BAD_OPTION,
	/// Response Forbidden
	ARTIK_COAP_RES_FORBIDDEN,
	/// Response Not Found
	ARTIK_COAP_RES_NOT_FOUND,
	/// Response Not Allowed
	ARTIK_COAP_RES_METHOD_NOT_ALLOWED,
	/// Response Not Acceptable
	ARTIK_COAP_RES_NOT_ACCEPTABLE,
	/// Response Precondition Failed
	ARTIK_COAP_RES_PRECONDITION_FAILED		= 140,
	/// Response Request Entity Too Large
	ARTIK_COAP_RES_REQ_ENTITY_TOO_LARGE,
	/// Response Request Unsupported Content Format
	ARTIK_COAP_RES_UNSUPPORTED_CONTENT_FORMAT	= 143,
	/// Response Internal Server Error
	ARTIK_COAP_RES_INTERNAL_SERVER_ERROR		= 160,
	/// Response Not Implemented
	ARTIK_COAP_RES_NOT_IMPLEMENTED,
	/// Response Bad Gateway
	ARTIK_COAP_RES_BAD_GATEWAY,
	/// Response Service Unavailable
	ARTIK_COAP_RES_SERVICE_UNAVAILABLE,
	/// Response Gateway Timeout
	ARTIK_COAP_RES_GATEWAY_TIMEOUT,
	/// Response Proxy Not Supported
	ARTIK_COAP_RES_PROXY_NOT_SUPPORTED
} artik_coap_code;

/*!
 *	\brief This enum defines the notification
 *             type for a resource.
 */
typedef enum {
	/// Notifications will be sent non-confirmable by default
	ARTIK_COAP_RESOURCE_NOTIFY_NON = 0x0,
	/// Notifications will be sent confirmable by default
	ARTIK_COAP_RESOURCE_NOTIFY_CON = 0x2,
} artik_coap_resource_notification_type;

/*!
 *	\brief This enum defines the CoAP message types
 */
typedef enum {
	/// Confirmable message (requires ACK/RST)
	ARTIK_COAP_MSG_CON = 0,
	/// Non-confirmable message (one-shot message)
	ARTIK_COAP_MSG_NON,
	/// Used to acknowledge confirmable messages
	ARTIK_COAP_MSG_ACK,
	/// Indicates error in received messages
	ARTIK_COAP_MSG_RST
} artik_coap_msg_type;

/*!
 *	\brief This enum defines errors when
 *             a confirmable message is dropped
 *             after several retries, a RST message
 *             is received, or a network or TLS level
 *             event was received that indicates the
 *             the message is not deliverable.
 */
typedef enum {
	/// No error
	ARTIK_COAP_ERROR_NONE = 0,
	/// Too many retries
	ARTIK_COAP_ERROR_TOO_MANY_RETRIES,
	/// Not deliverable
	ARTIK_COAP_ERROR_NOT_DELIVERABLE,
	/// Reset
	ARTIK_COAP_ERROR_RST,
	/// TLS error
	ARTIK_COAP_ERROR_TLS_FAILED
} artik_coap_error;

/*!
 *	\brief This structure defines the attribute
 *             for defining a resource.
 */
typedef struct {
	/// Name of the attribute
	const unsigned char *name;
	/// Length of the name
	int name_len;
	/// Value of the attribute
	const unsigned char *val;
	/// Length of the value
	int val_len;
} artik_coap_attr;

/*!
 *	\brief This structure defines a CoAP option.
 */
typedef struct {
	/// ID of the option
	artik_coap_option_key key;
	/// Data of the option
	unsigned char *data;
	/// Length of the data
	int data_len;
} artik_coap_option;

/*!
 *	\brief This structure defines the message that will
 *             be sent or received.
 */
typedef struct {
	/// Message type
	artik_coap_msg_type msg_type;
	/// Actual token, if any
	unsigned char *token;
	/// Length of the token
	unsigned long token_len;
	/// Message id
	unsigned short msg_id;
	/// Request method (value 1-10) or response code (value 40-255)
	artik_coap_code code;
	/// Payload: representation of a resource or result of the requested
	/// action
	unsigned char *data;
	/// Length of the payload
	int data_len;
	/// List of options, if any
	artik_coap_option *options;
	/// Length of the list of options
	int num_options;
} artik_coap_msg;

/*!
 *  \brief Send callback prototype
 *
 *  Response callback after sending a simple request (GET/POST/PUT/DELETE).
 *
 *  \param[in] msg Received message
 *  \param[in] error Error returned by the CoAP process, ARTIK_COAP_ERROR_NONE
 *             on success or else on failure
 *  \param[in] user_data The user data passed from the callback function
 */
typedef void (*artik_coap_send_callback)(const artik_coap_msg *msg,
					artik_coap_error error,
					void *user_data);

/*!
 *  \brief Observe callback prototype
 *
 *  Response callback after sending an observe request.
 *
 *  \param[in] msg Received message
 *  \param[in] error Error returned by the CoAP process, ARTIK_COAP_ERROR_NONE
 *             on success or else on failure
 *  \param[in] user_data The user data passed from the callback function
 */
typedef void (*artik_coap_observe_callback)(const artik_coap_msg *msg,
					artik_coap_error error,
					void *user_data);

/*!
 *  \brief Resource callback prototype
 *
 *  Callback called when a client sends a request on a resource.
 *
 *  \param[in] request Received message
 *  \param[out] response Message to fill and to be received by the client
 *  \param[in] user_data The user data passed from the callback function
 */
typedef void (*artik_coap_resource_callback)(const artik_coap_msg *request,
					artik_coap_msg *response,
					void *user_data);

/*!
 *  \brief Verify PSK callback prototype
 *
 *  Callback called during the TLS handshake (server-side) in order to verify the PSK
 *  parameters. Returns the length of the key which corresponds to identity,
 *  or 0.
 *
 *  \param[in] identity PSK identity
 *  \param[out] key Key corresponding to passed identity
 *  \param[in] key_len Max length of the key
 *  \param[in] user_data The user data passed from the callback function
 */
typedef int (*artik_coap_verify_psk_callback)(const unsigned char *identity,
					unsigned char **key,
					int key_len,
					void *user_data);

/*!
 *	\brief This structure defines a CoAP resource.
 */
typedef struct {
	/// Path of the resource
	const char *path;
	/// Length of the path
	int path_len;
	/// Default notification type (CON or NON)
	artik_coap_resource_notification_type default_notification_type;
	/// If the resource can be observed.
	bool observable;
	/// List of attributes
	artik_coap_attr *attributes;
	/// Length of the list of the attributes
	int num_attributes;
	/// List of the callback for each type of request (GET/POST/PUT/DELETE)
	artik_coap_resource_callback resource_cb[ARTIK_COAP_REQ_DELETE];
	/// List of resource data for callbacks
	void *resource_data[ARTIK_COAP_REQ_DELETE];
} artik_coap_resource;


/*!
 *	\brief This structure defines the PSK parameters.
 */
typedef struct {
	/// PSK identity
	const char *identity;
	/// PSK key
	char *psk;
	/// Length of PSK key
	int psk_len;
} artik_coap_psk_param;

/*!
 *	\brief This structure defines the CoAP configuration.
 */
typedef struct {
	/// Uri of the server (e.g: coap://californium.eclipse.org or
	/// coap://192.168.1.154:4577)
	const char *uri;
	/// Value of port for server-side
	int port;
	/// SSL configuration
	artik_ssl_config *ssl;
	/// PSK parameters
	artik_coap_psk_param *psk;
	/// Enable the verification of PSK parameters. If true, the verify PSK
	/// callback will be called. If false, the identity will be verified by
	/// default
	bool enable_verify_psk;
} artik_coap_config;

/*!
 *  \brief CoAP handle type
 *
 *  Handle type used to carry instance specific
 *  information for a CoAP object.
 */
typedef void *artik_coap_handle;

/*! \struct artik_coap_module
 *
 *  \brief CoAP module operations
 *
 *  Structure containing all the exposed operations exposed
 *  by CoAP module
 */
typedef struct {
	/*!
	 *  \brief Create client CoAP context
	 *
	 *  \param[in] handle Handle returned by the API
	 *             for later reference to the client
	 *  \param[in] config Pointer to a CoAP config structure
	 *                    for setting the communication.
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*create_client)(artik_coap_handle * client,
				artik_coap_config * config);
	/*!
	 *  \brief Destroy client CoAP context
	 *
	 *  \param[in] handle Handle to remove the reference
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*destroy_client)(artik_coap_handle client);
	/*!
	 *  \brief Establish the communication with the server
	 *
	 *  \param[in] handle Client handle
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*connect)(artik_coap_handle client);
	/*!
	 *  \brief Close the communication with the server
	 *
	 *  \param[in] handle Client handle
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*disconnect)(artik_coap_handle client);
	/*!
	 *  \brief Create server CoAP context
	 *
	 *  \param[in] handle Handle returned by the API
	 *             for later reference to the server
	 *  \param[in] config Pointer to a CoAP config structure
	 *                    for setting the server.
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*create_server)(artik_coap_handle * server,
				artik_coap_config * config);
	/*!
	 *  \brief Destroy server CoAP context
	 *
	 *  \param[in] handle Handle to remove the reference
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*destroy_server)(artik_coap_handle server);
	/*!
	 *  \brief Launch the server
	 *
	 *  \param[in] handle Server handle
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*start_server)(artik_coap_handle server);
	/*!
	 *  \brief Stop the server
	 *
	 *  \param[in] handle Server handle
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*stop_server)(artik_coap_handle server);
	/*!
	 *  \brief Send a request for a resource
	 *
	 *  \param[in] handle Client handle
	 *  \param[in] path Path of the resource
	 *  \param[in] msg Message to send
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*send_message)(artik_coap_handle handle,
				const char *path,
				artik_coap_msg *msg);
	/*!
	 *  \brief Observe a resource
	 *
	 *  \param[in] handle Client handle
	 *  \param[in] path Path of the resource
	 *  \param[in] msg_type Message type
	 *  \param[in] options List of options, if any
	 *  \param[in] num_options Length of the list of options
	 *  \param[in] token Actual token, if any
	 *  \param[in] token_len Length of the token
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*observe)(artik_coap_handle handle,
				const char *path,
				artik_coap_msg_type msg_type,
				artik_coap_option *options,
				int num_options,
				unsigned char *token,
				unsigned long token_len);
	/*!
	 *  \brief Stop observing a resource
	 *
	 *  \param[in] handle Client handle
	 *  \param[in] path Path of the resource
	 *  \param[in] token Actual token, if any
	 *  \param[in] token_len Length of the token
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*cancel_observe)(artik_coap_handle handle,
				const char *path,
				unsigned char *token,
				unsigned long token_len);
	/*!
	 *  \brief Initialize resources
	 *
	 *  \param[in] handle Server handle
	 *  \param[in] resources List of resources
	 *  \param[in] num_resources Length of the list of resources
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*init_resources)(artik_coap_handle handle,
				artik_coap_resource * resources,
				int num_resources);
	/*!
	 *  \brief Notify possible observers that the resource has
	 *         changed
	 *
	 *  \param[in] handle Server handle
	 *  \param[in] path Path of the resource
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*notify_resource_changed)(artik_coap_handle,
				const char *path);
	/*!
	 *  \brief Define send callback
	 *
	 *  \param[in] handle Client handle
	 *  \param[in] callback Callback function to set, can be unset by
	 *             setting NULL
	 *  \param[in] user_data The user data to be passed to the callback
	 *             function
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*set_send_callback)(artik_coap_handle,
				artik_coap_send_callback callback,
				void *user_data);
	/*!
	 *  \brief Define observe callback
	 *
	 *  \param[in] handle Client handle
	 *  \param[in] callback Callback function to set, can be unset by
	 *             setting NULL
	 *  \param[in] user_data The user data to be passed to the callback
	 *             function
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*set_observe_callback)(artik_coap_handle,
				artik_coap_observe_callback callback,
				void *user_data);
	/*!
	 *  \brief Define verify PSK callback
	 *
	 *  \param[in] handle Server handle
	 *  \param[in] callback Callback function to set, can be unset by
	 *             setting NULL
	 *  \param[in] user_data The user data to be passed to the callback
	 *             function
	 *
	 *  \return S_OK on success, error code otherwise
	 */
	artik_error(*set_verify_psk_callback)(artik_coap_handle,
				artik_coap_verify_psk_callback callback,
				void *user_data);
} artik_coap_module;

extern const artik_coap_module coap_module;

#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_ARTIK_COAP_H_ */

