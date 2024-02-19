// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h> // for mode_t

int
OpenOrDie(const char *path);

size_t
ReadOrDie(int fd, void *data, size_t size);

void
ReadFull(int fd, uint8_t *data, size_t size);

void
ReadFileFd(const char *path, int fd, void *data, size_t size);

void
ReadFile(const char *path, void *data, size_t size);

size_t
WriteOrDie(int fd, const void *data, size_t size);

void
WriteFull(int fd, const uint8_t *data, size_t size);

void
WriteFile(const char *path, mode_t mode,
	  const void *data, size_t size);
