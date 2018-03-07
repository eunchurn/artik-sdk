#include <stdio.h>
#include <unistd.h>

#include <artik_module.h>
#include <artik_media.h>
#include <artik_loop.h>

static void usage(void)
{
	printf("Usage: media-example <filename>\n");
	printf("\n");
	printf("Options:\n");
	printf("  -h                   Display this help and exit\n");
}

static void on_finished(void *user_data)
{
	char *file = (char *)user_data;
	artik_loop_module *loop = (artik_loop_module *)artik_request_api_module("loop");

	fprintf(stdout, "Finish playing sound %s\n", file);
	loop->quit();
}

int main(int argc, char **argv)
{
	char *filename = NULL;
	artik_media_module *media = NULL;
	artik_loop_module *loop = NULL;
	artik_error ret = S_OK;
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

	if (argc < 2) {
		fprintf(stderr, "Error: Too few arguments\n");
		usage();
		return -1;
	}
	filename = argv[1];

	media = (artik_media_module *)artik_request_api_module("media");
	if (!media) {
		fprintf(stderr, "Error: Failed to request Media module\n");
		goto exit;
	}

	loop = (artik_loop_module *)artik_request_api_module("loop");
	if (!loop) {
		fprintf(stderr, "Error: Failed to request Loop module\n");
		goto exit;
	}

	ret = media->play_sound_file(filename);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed to play sound %s: %s\n", filename, error_msg(ret));
		goto exit;
	}

	ret = media->set_finished_callback(on_finished, (void *)filename);
	if (ret != S_OK) {
		fprintf(stderr, "Error: Failed configure media module: %s\n", error_msg(ret));
		goto exit;
	}

	loop->run();

	return 0;

exit:
	if (loop)
		artik_release_api_module(loop);

	if (media)
		artik_release_api_module(media);

	return -1;
}
