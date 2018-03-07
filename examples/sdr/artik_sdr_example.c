#include <stdio.h>
#include <unistd.h>

#include <artik_cloud.h>
#include <artik_loop.h>
#include <artik_module.h>

typedef struct {
	char *id;
	char *nonce;
} registration_data_t;
bool registration_failed = true;

void usage(void)
{
	printf("Usage: sdr-example <dtid> <vendor_id>\n");
	printf("\n");
	printf("Options:\n");
	printf("  -h                   Display this help and exit\n");
}

static char *parse_json_object(const char *data, const char *obj)
{
	char *res = NULL;
	char prefix[256];
	char *substr = NULL;

	snprintf(prefix, 256, "\"%s\":\"", obj);

	substr = strstr(data, prefix);
	if (substr != NULL) {
		int idx = 0;

		/* Start after substring */
		substr += strlen(prefix);

		/* Count number of bytes to extract */
		while (substr[idx] != '\"')
			idx++;
		/* Copy the extracted string */
		res = strndup(substr, idx);
	}

	return res;
}

int wait_for_user_confirmation(void *user_data)
{
	artik_cloud_module *cloud = artik_request_api_module("cloud");
	artik_loop_module *loop = artik_request_api_module("loop");
	registration_data_t *reg = (registration_data_t *)user_data;
	artik_secure_element_config se_config;
	char *response = NULL;
	char *reg_status = NULL;
	char *device_id = NULL;
	char *device_token = NULL;
	artik_error ret;
	int cont = 0;

	se_config.key_id = "ARTIK/0";
	se_config.key_algo = ECC_SEC_P256R1;

	ret = cloud->sdr_registration_status(&se_config, reg->id, &response);
	if (ret != S_OK) {
		fprintf(stderr, "SDR 'status' failed: Failed to get status of SDR request %s", reg->id);
		goto exit;
	}

	reg_status = parse_json_object(response, "status");
	free(response);
	response = NULL;
	if (!reg_status) {
		fprintf(stderr, "SDR 'status' failed: Failed to parse JSON response.\n");
		goto exit;
	}

	if (strcmp(reg_status, "PENDING_USER_CONFIRMATION") == 0) {
		cont = 1;
	} else {
		ret = cloud->sdr_complete_registration(&se_config, reg->id, reg->nonce, &response);
		if (ret != S_OK) {
			fprintf(stderr, "SDR 'complete' failed: Failed to complete registration.");
			goto exit;
		}

		device_id = parse_json_object(response, "did");
		device_token = parse_json_object(response, "accessToken");

		if (!device_id || !device_token) {
			fprintf(stderr, "SDR 'complete' failed: Failed to parse JSON response");
			goto exit;
		}

		fprintf(stdout, "SDR: Device registered with ID %s, TOKEN %s\n",
				device_id, device_token);
		registration_failed = false;
		loop->quit();
	}

exit:
	if (reg_status)
		free(reg_status);

	if (device_id)
		free(device_id);

	if (device_token)
		free(device_token);

	if (!cont)
		loop->quit();

	artik_release_api_module(cloud);
	artik_release_api_module(loop);

	return cont;
}

int main(int argc, char **argv)
{
	artik_cloud_module *cloud = NULL;
	artik_loop_module *loop = NULL;
	registration_data_t reg = { NULL, NULL };
	artik_secure_element_config se_config;
	char *sdr_dtid = NULL;
	char *vendor_id = NULL;
	char *response = NULL;
	char *reg_pin = NULL;
	artik_error ret;
	int periodic_id;
	int c;

	while ((c = getopt(argc, argv, "h")) != -1) {
		switch (c) {
		case 'h':
			usage();
			return 0;
		case '?':
			fprintf(stderr, "Error: Unknow option '-%c'\n", optopt);
			return -1;
		default:
			abort();
		}
	}

	if (argc < 3) {
		fprintf(stderr, "Error: Too few arguments\n");
		usage();
		return -1;
	}
	sdr_dtid = argv[1];
	vendor_id = argv[2];

	cloud = (artik_cloud_module *) artik_request_api_module("cloud");
	if (!cloud) {
		fprintf(stderr, "Error: Failed to request Cloud module\n");
		return -1;
	}

	loop = (artik_loop_module *) artik_request_api_module("loop");
	if (!loop) {
		fprintf(stderr, "Error: Failed to request Loop module\n");
		artik_release_api_module(cloud);
		return -1;
	}

	se_config.key_id = "ARTIK/0";
	se_config.key_algo = ECC_SEC_P256R1;

	ret = cloud->sdr_start_registration(&se_config, sdr_dtid, vendor_id, &response);
	if (ret != S_OK) {
		if (response)
			fprintf(stderr, "SDR 'start' failed: %s", response);
		else
			fprintf(stderr, "SDR 'start' failed: %s", error_msg(ret));
		goto exit;
	}

	reg.id = parse_json_object(response, "rid");
	reg.nonce = parse_json_object(response, "nonce");
	reg_pin = parse_json_object(response, "pin");

	if (!reg.id || !reg.nonce || !reg_pin) {
		fprintf(stderr, "SDR 'start' failed: Failed to parse JSON response.\n");
		goto exit;
	}

	fprintf(stdout, "SDR: Your PIN is '%s'\n", reg_pin);
	loop->add_periodic_callback(&periodic_id, 1000, wait_for_user_confirmation, &reg);

	loop->run();

exit:
	if (response)
		free(response);

	artik_release_api_module(cloud);
	artik_release_api_module(loop);
	free(reg.id);
	free(reg.nonce);
	free(reg_pin);

	if (registration_failed)
		return -1;

	return 0;
}
