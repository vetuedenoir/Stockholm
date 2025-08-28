#include "stockholm.h"

static const char b64_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length)
{
	size_t enc_len = 4 * ((input_length + 2) / 3);

	char *encoded_data = malloc(enc_len + 1);
	if (!encoded_data)
		return NULL;

	size_t i, j = 0;

	for (i = 0; i < input_length; i += 3)
	{
		uint32_t octet_a = i < input_length ? data[i] : 0;
		uint32_t octet_b = (i + 1) < input_length ? data[i + 1] : 0;
		uint32_t octet_c = (i + 2) < input_length ? data[i + 2] : 0;

		uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

		encoded_data[j++] = b64_table[(triple >> 18) & 0x3F];
		encoded_data[j++] = b64_table[(triple >> 12) & 0x3F];
		encoded_data[j++] = (i + 1 < input_length) ? b64_table[(triple >> 6) & 0x3F] : '=';
		encoded_data[j++] = (i + 2 < input_length) ? b64_table[triple & 0x3F] : '=';
	}

	encoded_data[enc_len] = '\0';
	if (output_length) *output_length = enc_len;
	return encoded_data;
}

static unsigned char b64_reverse_table[256];

void build_reverse_table() {
	static int built = 0;
	if (built) return;

	memset(b64_reverse_table, 0x80, 256);
	for (int i = 0; i < 64; i++)
		b64_reverse_table[(unsigned char)b64_table[i]] = i;
	b64_reverse_table['='] = 0;

	built = 1;
}

unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length)
{
	build_reverse_table();

	if (input_length % 4 != 0 || input_length == 0)
		return NULL;

	size_t dec_len = input_length / 4 * 3;

	if (data[input_length - 1] == '=')
		dec_len--;
	if (data[input_length - 2] == '=')
		dec_len--;

	unsigned char *decoded_data = malloc(dec_len);
	if (!decoded_data)
		return NULL;

	size_t i, j = 0;
	for (i = 0; i < input_length; i += 4)
	{
		uint32_t sextet_a = b64_reverse_table[(unsigned char)data[i]];
		uint32_t sextet_b = b64_reverse_table[(unsigned char)data[i + 1]];
		uint32_t sextet_c = b64_reverse_table[(unsigned char)data[i + 2]];
		uint32_t sextet_d = b64_reverse_table[(unsigned char)data[i + 3]];

		uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

		if (j < dec_len) decoded_data[j++] = (triple >> 16) & 0xFF;
		if (j < dec_len) decoded_data[j++] = (triple >> 8) & 0xFF;
		if (j < dec_len) decoded_data[j++] = triple & 0xFF;
	}

	if (output_length)
		*output_length = dec_len;
	return decoded_data;
}