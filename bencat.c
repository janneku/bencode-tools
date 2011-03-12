#include <bencodetools/bencode.h>

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

static int teemode;

static int process(int fd)
{
	assert(0);
}

static int xclose(int fd)
{
	while (close(fd)) {
		if (errno == EINTR)
			continue;
		return 1;
	}
	return 0;
}

static int process_files(int i, int argc, char *argv[])
{
	int fd;
	int ret;
	for (; i < argc; i++) {
		fd = open(argv[i], O_RDONLY);
		if (fd < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "bencat: Unable to open %s\n", argv[i]);
			return 1;
		}
		ret = process(fd);
		xclose(fd);
		fd = -1;
		if (ret)
			return ret;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int i;

	for (i = 1; i < argc;) {
		if (argv[i][0] != '-')
			break;
		if (strcmp(argv[i], "--") == 0) {
			i++;
			break;
		}
		if (strcmp(argv[i], "-t") == 0 ||
		    strcmp(argv[i], "--tee") == 0) {
			teemode = 1;
			i++;
			continue;
		}
		fprintf(stderr, "bencat: Unknown option: %s\n", argv[i]);
		exit(1);
	}

	if (i < argc)
		return process_files(i, argc, argv);
	else
		return process(0);
}
