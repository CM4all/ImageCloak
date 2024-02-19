// author: Max Kellermann <mk@cm4all.com>

#include "hex.h"

static char *
HexFormatUint8Fixed(char dest[2], uint8_t number)
{
	static const char hex_digits[] = "0123456789abcdef";
	dest[0] = hex_digits[(number >> 4) & 0xf];
	dest[1] = hex_digits[number & 0xf];
	return dest + 2;
}

char *
HexFormat(char *output, const uint8_t *src, size_t size)
{
	for (size_t i = 0; i < size; ++i)
		output = HexFormatUint8Fixed(output, src[i]);

	return output;
}

static int
ParseHexDigit(char ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	else if (ch >= 'a' && ch <= 'f')
		return 0xa + ch - 'a';
	else if (ch >= 'A' && ch <= 'F')
		return 0xa + ch - 'A';
	else
		return -1;
}

bool
ParseHexString(uint8_t *output, const char *src)
{
	while (*src != 0) {
		const int a = ParseHexDigit(*src++);
		if (a < 0)
			return false;

		const int b = ParseHexDigit(*src++);
		if (b < 0)
			return false;

		*output++ = (unsigned)a << 4 | (unsigned)b;
	}

	return true;
}
