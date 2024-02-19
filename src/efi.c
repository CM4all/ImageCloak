// author: Max Kellermann <mk@cm4all.com>

#include "efi.h"
#include "hex.h"
#include "io.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void
WriteEfiHex(const char *path, mode_t mode,
	    const uint8_t *raw_data, size_t raw_size)
{
	char *buffer = alloca(4 + raw_size * 2 + 1), *p = buffer;
	*p++ = 0x07;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 0x00;
	p = HexFormat(p, raw_data, raw_size);
	*p++ = 0;

	WriteFile(path, mode, buffer, p - buffer);
}

static bool
ReadEfiStringFd(const char *path, int fd, char *dest, size_t length)
{
	struct stat st;
	if (fstat(fd, &st) < 0) {
		fprintf(stderr, "Failed to stat %s: %s\n",
			path, strerror(errno));
		return false;
	}

	uint8_t header[4];

	if (!S_ISREG(st.st_mode) || st.st_size != (off_t)(sizeof(header) + length + 1)) {
		fprintf(stderr, "File has wrong size: %s\n", path);
		return false;
	}

	if (ReadOrDie(fd, header, sizeof(header)) != sizeof(header) ||
	    ReadOrDie(fd, dest, length + 1) != length + 1) {
		fprintf(stderr, "Short read\n");
		return false;
	}

	if (header[0] != 0x07 || header[1] != 0x00 ||
	    header[2] != 0x00 || header[3] != 0x00 ||
	    dest[length] != 0) {
		fprintf(stderr, "Malformed EFI string in  %s\n", path);
		return false;
	}

	return true;
}

bool
ReadEfiString(const char *path, char *dest, size_t length)
{
	int fd = open(path, O_RDONLY|O_NOFOLLOW);
	if (fd < 0) {
		if (errno != ENOENT)
			fprintf(stderr, "Failed to open %s: %s\n",
				path, strerror(errno));
		return false;
	}

	bool success = ReadEfiStringFd(path, fd, dest, length);
	close(fd);
	return success;
}

bool
ReadEfiHex(const char *path, uint8_t *dest, size_t size)
{
	char *buffer = alloca(size * 2 + 1);
	if (!ReadEfiString(path, buffer, size * 2))
		return false;

	if (!ParseHexString(dest, buffer)) {
		fprintf(stderr, "Malformed file: %s\n", path);
		return false;
	}

	return true;
}
