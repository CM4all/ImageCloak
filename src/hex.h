// author: Max Kellermann <mk@cm4all.com>

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/**
 * Formats a sequence of bytes to a hexadecimal ASCII string.
 *
 * @param output the output buffer; it must have enough space for
 * size*2 characters
 * @param src the input buffer
 * @param size the size of the input buffer
 * @return the byte after the last output digit (i.e. output + size *
 * 2)
 */
char *
HexFormat(char *output, const uint8_t *src, size_t size);

/**
 * Parse a number from a fixed-length (null-terminated) hexadecimal
 * string.
 *
 * @param output the output buffer; it must have enough space for
 * strlen(src)/2 bytes
 * @param src the null-terminate input string
 * @return true on success
 */
bool
ParseHexString(uint8_t *output, const char *src);
