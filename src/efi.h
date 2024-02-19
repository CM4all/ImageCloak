// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <stdbool.h>
#include <stddef.h> // for size_t
#include <stdint.h>
#include <sys/types.h> // for mode_t

/**
 * Mountpoint of the "efivarfs" filesystem.
 */
#define EFIVARS "/sys/firmware/efi/efivars"

/**
 * Write a hex dump of the specified buffer to the given EFI variable
 * file.
 *
 * Exits on error.
 *
 * @param path absolute path pointing inside #EFIVARS
 * @param mode the file mode to be passed to open()
 * @param raw_data the buffer containing binary data
 * @param raw_size the size of #raw_data
 */
void
WriteEfiHex(const char *path, mode_t mode,
	    const uint8_t *raw_data, size_t raw_size);

/**
 * Read a fixed-size (and null-terminated) ASCII string from an EFI
 * variable file.
 *
 * @param path absolute path pointing inside #EFIVARS
 * @param dest the destination buffer (must have room for #length
 * characters plus the null terminator)
 * @param length the expected length of the string excluding the null
 * terminator
 * @return true on success
 */
bool
ReadEfiString(const char *path, char *dest, size_t length);

/**
 * Read a fixed-size (and null-terminated) ASCII string and decode it
 * as a hex string.
 *
 * @return true on success
 */
bool
ReadEfiHex(const char *path, uint8_t *dest, size_t size);
