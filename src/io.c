// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "io.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int
OpenOrDie(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n",
			path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	return fd;
}

size_t
ReadOrDie(int fd, void *data, size_t size)
{
	ssize_t nbytes = read(fd, data, size);
	if (nbytes < 0) {
		fprintf(stderr, "Read failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return nbytes;
}

void
ReadFull(int fd, uint8_t *data, size_t size)
{
	while (size > 0) {
		const size_t nbytes = ReadOrDie(fd, data, size);
		if (nbytes == 0) {
			fprintf(stderr, "Premature end of file\n");
			exit(EXIT_FAILURE);
		}

		data += nbytes;
		size -= nbytes;
	}
}

void
ReadFileFd(const char *path, int fd, void *data, size_t size)
{
	struct stat st;
	if (fstat(fd, &st) < 0) {
		fprintf(stderr, "Failed to stat %s: %s\n",
			path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "Not a regular file: %s\n", path);
		exit(EXIT_FAILURE);
	}

	if (st.st_size != (off_t)size) {
		fprintf(stderr, "Wrong size: %s\n", path);
		exit(EXIT_FAILURE);
	}

	ssize_t nbytes = read(fd, data, size);
	if (nbytes < 0) {
		fprintf(stderr, "Failed to read %s: %s\n",
			path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((size_t)nbytes != size) {
		fprintf(stderr, "Short read from %s\n",
			path);
		exit(EXIT_FAILURE);
	}
}

void
ReadFile(const char *path, void *data, size_t size)
{
	const int fd = OpenOrDie(path);

	ReadFileFd(path, fd, data, size);

	close(fd);
}

size_t
WriteOrDie(int fd, const void *data, size_t size)
{
	ssize_t nbytes = write(fd, data, size);
	if (nbytes < 0) {
		fprintf(stderr, "Write failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return nbytes;
}

void
WriteFull(int fd, const uint8_t *data, size_t size)
{
	while (size > 0) {
		const size_t nbytes = WriteOrDie(fd, data, size);
		data += nbytes;
		size -= nbytes;
	}
}

void
WriteFile(const char *path, mode_t mode,
	  const void *data, size_t size)
{
	const int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, mode);
	if (fd < 0) {
		fprintf(stderr, "Failed to create %s: %s\n",
			path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	ssize_t nbytes = write(fd, data, size);
	if (nbytes < 0) {
		fprintf(stderr, "Failed to write %s: %s\n",
			path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((size_t)nbytes != size) {
		fprintf(stderr, "Short write to %s\n",
			path);
		exit(EXIT_FAILURE);
	}

	if (close(fd) < 0) {
		fprintf(stderr, "Failed to commit %s: %s\n",
			path, strerror(errno));
		exit(EXIT_FAILURE);
	}
}
