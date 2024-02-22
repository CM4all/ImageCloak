// SPDX-License-Identifier: BSD-2-Clause
// Copyright CM4all GmbH
// author: Max Kellermann <mk@cm4all.com>

#include "efi.h"
#include "io.h"
#include "hex.h"

#include <sodium/crypto_box.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_secretstream_xchacha20poly1305.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/**
 * An EFI variable UUID for variables managed by this program.
 */
#define UUID "88a82a2a-c470-11ee-99ba-3fdf44f2815d"

/**
 * The chunk size for our ChaCha20Poly1305 stream.
 */
#define CHUNK_SIZE 65536

/**
 * The absolute path to the public key EFI variable.
 */
static const char PK_PATH[] = EFIVARS "/PK-" UUID;

/**
 * The absolute path to the secret key EFI variable.
 */
static const char SK_PATH[] = EFIVARS "/SK-" UUID;

static void
PrintUsage(FILE *file, const char *argv0)
{
	fprintf(file, "Usage: %s COMMAND ...\n", argv0);
	fprintf(file, "Commands:\n"
		"  keypair OUT_PUBKEY_FILE OUT_SECRETKEY_FILE\n"
		"  efi-keypair\n"
		"  auto-efi-keypair\n"
		"  print-efi-pkey\n"
		"  multi-seal IN_FILE OUT_DIRECTORY PUBKEY1...\n"
		"  encrypt-stream OUT_KEY_FILE <IN >OUT\n"
		"  decrypt-stream IN_KEY_FILE <IN >OUT\n"
		"  efi-decrypt-stream SEAL_DIRECTORY <IN >OUT\n"
		);
}

static bool
ReadEfiPublicKey(uint8_t key[crypto_box_PUBLICKEYBYTES])
{
	return ReadEfiHex(PK_PATH, key, crypto_box_PUBLICKEYBYTES);
}

static bool
ReadEfiSecretKey(uint8_t key[crypto_box_SECRETKEYBYTES])
{
	return ReadEfiHex(SK_PATH, key, crypto_box_SECRETKEYBYTES);
}

static bool
ValidateCryptoBoxKeypair(const uint8_t pk[crypto_box_PUBLICKEYBYTES],
			 const uint8_t sk[crypto_box_SECRETKEYBYTES])
{
	uint8_t expected[crypto_box_PUBLICKEYBYTES];
	crypto_scalarmult_curve25519_base(expected, sk);
	return memcmp(pk, expected, sizeof(expected)) == 0;
}


static void
GenerateKeyPair(const char *public_key_path,
		const char *secret_key_path)
{
	uint8_t pk[crypto_box_PUBLICKEYBYTES];
	uint8_t sk[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(pk, sk);

	WriteFile(public_key_path, 0666, pk, sizeof(pk));
	WriteFile(secret_key_path, 0600, sk, sizeof(sk));
}

static void
PrintPublicKey(const uint8_t pk[crypto_box_PUBLICKEYBYTES])
{
	char hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
	*HexFormat(hex, pk, crypto_box_PUBLICKEYBYTES) = 0;
	puts(hex);
}

static void
GenerateEfiKeyPair(void)
{
	uint8_t pk[crypto_box_PUBLICKEYBYTES];
	uint8_t sk[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(pk, sk);

	WriteEfiHex(PK_PATH, 0666, pk, sizeof(pk));
	WriteEfiHex(SK_PATH, 0600, sk, sizeof(sk));

	PrintPublicKey(pk);
}

static void
AutoGenerateEfiKeyPair(void)
{
	uint8_t pk[crypto_box_PUBLICKEYBYTES], sk[crypto_box_SECRETKEYBYTES];
	if (ReadEfiPublicKey(pk) && ReadEfiSecretKey(sk)) {
		if (ValidateCryptoBoxKeypair(pk, sk)) {
			fprintf(stderr, "EFI crypto_box keypair already exists\n");
			PrintPublicKey(pk);
			return;
		}

		fprintf(stderr, "Existing EFI crypto_box is invalid\n");
	}

	fprintf(stderr, "Generating new crypto_box keypair\n");
	GenerateEfiKeyPair();
}

static void
PrintEfiPublicKey(void)
{
	char buffer[2 * crypto_box_PUBLICKEYBYTES + 1];
	if (!ReadEfiString(PK_PATH, buffer, 2 * crypto_box_PUBLICKEYBYTES)) {
		fprintf(stderr, "No public key\n");
		exit(EXIT_FAILURE);
	}

	uint8_t key[crypto_box_PUBLICKEYBYTES];
	if (!ParseHexString(key, buffer)) {
		fprintf(stderr, "Malformed file: %s\n", PK_PATH);
		exit(EXIT_FAILURE);
	}

	puts(buffer);
}

static void
MultiSeal(const char *in_path, const char *out_directory,
	  const char *const* public_keys, size_t n_public_keys)
{
	/* open the input file and mmap it */
	const int in_fd = OpenOrDie(in_path);

	struct stat st;
	if (fstat(in_fd, &st) < 0) {
		fprintf(stderr, "Failed to stat %s: %s\n",
			in_path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "Not a regular file: %s\n", in_path);
		exit(EXIT_FAILURE);
	}

	const size_t in_size = st.st_size;

	void *in_data = mmap(NULL, in_size, PROT_READ, MAP_SHARED, in_fd, 0);
	if (in_data == MAP_FAILED) {
		fprintf(stderr, "Failed to map %s: %s\n",
			in_path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	close(in_fd);

	/* change to the output directory so all seal filenames can
	   simply be the hex public key */
	if (chdir(out_directory) < 0) {
		fprintf(stderr, "Failed to change to %s: %s\n",
			out_directory, strerror(errno));
		exit(EXIT_FAILURE);
	}

	const size_t out_size = crypto_box_SEALBYTES + in_size;
	uint8_t *const out_buffer = malloc(out_size);
	if (out_buffer == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}

	for (size_t i = 0; i < n_public_keys; ++i) {
		const char *key_hex = public_keys[i];
		if (strlen(key_hex) != crypto_box_PUBLICKEYBYTES * 2) {
			fprintf(stderr, "Bad hex key size: %s\n", key_hex);
			exit(EXIT_FAILURE);
		}

		uint8_t key[crypto_box_PUBLICKEYBYTES];
		if (!ParseHexString(key, key_hex)) {
			fprintf(stderr, "Malformed hex key: %s\n", key_hex);
			exit(EXIT_FAILURE);
		}

		crypto_box_seal(out_buffer, in_data, in_size, key);
		WriteFile(key_hex, 0666, out_buffer, out_size);
	}

	free(out_buffer);
	munmap((void *)in_data, in_size);
}

/**
 * Fill the given buffer with as much data as possible.  Repeatedly
 * calls read() until the stream gives us enough data (or until it
 * ends).  Dies on error.
 *
 * @return the number of bytes (may be less than #size if the stream
 * ends early)
 */
static size_t
FillBuffer(int fd, uint8_t *buffer, size_t size)
{
	size_t fill = 0;

	while (fill < size) {
		size_t nbytes = ReadOrDie(fd, buffer + fill, size - fill);
		if (nbytes == 0)
			break;

		fill += nbytes;
	}

	return fill;
}

static void
EncryptStream(const char *key_path, const int in_fd, const int out_fd)
{
	uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	crypto_secretstream_xchacha20poly1305_keygen(key);

	crypto_secretstream_xchacha20poly1305_state state;

	/* write the secretstream header */
	{
		uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
		crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
		WriteFull(out_fd, header, sizeof(header));
	}

	/* repeatedly read a chunk, encrypt it, write */
	while (true) {
		uint8_t input_buffer[CHUNK_SIZE];
		size_t input_fill = FillBuffer(in_fd, input_buffer, sizeof(input_buffer));
		uint8_t tag = input_fill < sizeof(input_buffer)
			? crypto_secretstream_xchacha20poly1305_TAG_FINAL
			: 0;

		uint8_t output_buffer[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
		unsigned long long output_fill;

		crypto_secretstream_xchacha20poly1305_push(&state,
							   output_buffer, &output_fill,
							   input_buffer, input_fill,
							   NULL, 0, tag);

		WriteFull(out_fd, output_buffer, output_fill);

		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
			break;
	}

	WriteFile(key_path, 0600, key, sizeof(key));
}

static void
_DecryptStream(uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES],
	       const int in_fd, const int out_fd)
{

	crypto_secretstream_xchacha20poly1305_state state;

	/* read and process the secretstream header */
	{
		uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
		ReadFull(in_fd, header, sizeof(header));
		if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0) {
			fprintf(stderr, "crypto_secretstream_xchacha20poly1305_init_pull() failed\n");
			exit(EXIT_FAILURE);
		}
	}

	/* repeatedly read a chunk, decrypt it, write */
	while (true) {
		uint8_t input_buffer[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
		size_t input_fill = FillBuffer(in_fd, input_buffer, sizeof(input_buffer));
		if (input_fill == 0) {
			fprintf(stderr, "Premature end of file\n");
			exit(EXIT_FAILURE);
		}

		uint8_t output_buffer[CHUNK_SIZE];
		unsigned long long output_fill;
		uint8_t tag;

		if (crypto_secretstream_xchacha20poly1305_pull(&state,
							       output_buffer, &output_fill,
							       &tag,
							       input_buffer, input_fill,
							       NULL, 0) != 0) {
			fprintf(stderr, "crypto_secretstream_xchacha20poly1305_pull() failed\n");
			exit(EXIT_FAILURE);
		}

		WriteFull(out_fd, output_buffer, output_fill);

		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
			break;
	}
}

static void
DecryptStream(const char *key_path, const int in_fd, const int out_fd)
{
	uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	ReadFile(key_path, key, sizeof(key));

	_DecryptStream(key, in_fd, out_fd);
}

static void
EfiUnsealStreamKey(const char *seal_directory,
		   uint8_t stream_key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
	if (chdir(seal_directory) < 0) {
		fprintf(stderr, "Failed to change to %s: %s\n",
			seal_directory, strerror(errno));
		exit(EXIT_FAILURE);
	}

	char pkey_hex[2 * crypto_box_PUBLICKEYBYTES + 1];
	if (!ReadEfiString(PK_PATH, pkey_hex, 2 * crypto_box_PUBLICKEYBYTES)) {
		fprintf(stderr, "No public key\n");
		exit(EXIT_FAILURE);
	}

	uint8_t pkey[crypto_box_SECRETKEYBYTES];
	if (!ParseHexString(pkey, pkey_hex)) {
		fprintf(stderr, "Malformed public key\n");
		exit(EXIT_FAILURE);
	}

	int seal_fd = open(pkey_hex, O_RDONLY);
	if (seal_fd < 0) {
		fprintf(stderr, "No sealed stream key for PK %s\n", pkey_hex);
		exit(EXIT_FAILURE);
	}

	uint8_t buffer[crypto_box_SEALBYTES + crypto_secretstream_xchacha20poly1305_KEYBYTES];
	ReadFileFd(pkey_hex, seal_fd, buffer, sizeof(buffer));

	uint8_t skey[crypto_box_SECRETKEYBYTES];
	if (!ReadEfiSecretKey(skey)) {
		fprintf(stderr, "No secret key\n");
		exit(EXIT_FAILURE);
	}

	if (crypto_box_seal_open(stream_key, buffer, sizeof(buffer),
				 pkey, skey) != 0) {
		fprintf(stderr, "Unsealing failed\n");
		exit(EXIT_FAILURE);
	}
}

static void
EfiDecryptStream(const char *seal_directory, const int in_fd, const int out_fd)
{
	uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	EfiUnsealStreamKey(seal_directory, key);

	_DecryptStream(key, in_fd, out_fd);
}

int
main(int argc, char **argv)
{
	if (argc < 2) {
		PrintUsage(stderr, argv[0]);
		return EXIT_FAILURE;
	}

	const char *const cmd = argv[1];
	if (strcmp(cmd, "keypair") == 0) {
		if (argc != 4) {
			PrintUsage(stderr, argv[0]);
			return EXIT_FAILURE;
		}

		GenerateKeyPair(argv[2], argv[3]);
	} else if (strcmp(cmd, "efi-keypair") == 0) {
		if (argc != 2) {
			PrintUsage(stderr, argv[0]);
			return EXIT_FAILURE;
		}

		GenerateEfiKeyPair();
	} else if (strcmp(cmd, "auto-efi-keypair") == 0) {
		if (argc != 2) {
			PrintUsage(stderr, argv[0]);
			return EXIT_FAILURE;
		}

		AutoGenerateEfiKeyPair();
	} else if (strcmp(cmd, "print-efi-pkey") == 0) {
		if (argc != 2) {
			PrintUsage(stderr, argv[0]);
			return EXIT_FAILURE;
		}

		PrintEfiPublicKey();
	} else if (strcmp(cmd, "multi-seal") == 0) {
		if (argc < 5) {
			PrintUsage(stderr, argv[0]);
			return EXIT_FAILURE;
		}

		MultiSeal(argv[2], argv[3], (const char *const*)argv + 4, argc - 4);
	} else if (strcmp(cmd, "encrypt-stream") == 0) {
		if (argc != 3) {
			PrintUsage(stderr, argv[0]);
			return EXIT_FAILURE;
		}

		EncryptStream(argv[2], STDIN_FILENO, STDOUT_FILENO);
	} else if (strcmp(cmd, "decrypt-stream") == 0) {
		if (argc != 3) {
			PrintUsage(stderr, argv[0]);
			return EXIT_FAILURE;
		}

		DecryptStream(argv[2], STDIN_FILENO, STDOUT_FILENO);
	} else if (strcmp(cmd, "efi-decrypt-stream") == 0) {
		if (argc != 3) {
			PrintUsage(stderr, argv[0]);
			return EXIT_FAILURE;
		}

		EfiDecryptStream(argv[2], STDIN_FILENO, STDOUT_FILENO);
	} else {
		PrintUsage(stderr, argv[0]);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
