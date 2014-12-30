#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "itmc.h"

double same_key_enc_square_sum_distribution(unsigned char byt_arr[], size_t byt_arr_len, size_t key_len, int strt_idx)
{
	unsigned int char_freq[UCHAR_MAX + 1];
	size_t same_key_txt_len;
	double sqr_sum;
	size_t offset;
	int i;

	/* count each alphabets that are encrpyted with the same key value */
	memset(char_freq, 0, sizeof(char_freq));
	same_key_txt_len = 0;
	offset = strt_idx;
	while (offset <= byt_arr_len) {
		unsigned char ch;

		ch = byt_arr[offset]; //get ciphered char from byte array
		char_freq[ch]++; //increment the frequency of deciphered char
		offset += key_len; //skip by key_len in byte array
		same_key_txt_len++;
	}

	/* calculate the square sum distribution */
	sqr_sum = 0.0;
	for (i = 0; i <= UCHAR_MAX; i++)
		sqr_sum += (double) (char_freq[i] * char_freq[i]) / (double) (same_key_txt_len * same_key_txt_len);

	return sqr_sum;
}

size_t collect_chars_same_enc_key(unsigned char *buf, unsigned char byt_arr[], size_t byt_arr_len, size_t key_len, int strt_idx)
{
	int offset;
	size_t len;

	offset = strt_idx;
	len = 0;
	while (offset <= byt_arr_len) {
		buf[len] = byt_arr[offset]; //get ciphered char from ciphered text and put it in buffer
		offset += key_len; //skip by key_len in ciphered text
		len++;
	}

	return len;
}

size_t convert_hexstr_to_bytestr(unsigned char *buf, unsigned char hexstr[], size_t hexstr_len)
{
	int i, j;

	j = 0;
	for (i = 0; i < hexstr_len; i += 2) {
		unsigned int val;

		sscanf((char *) hexstr + i, "%02X" , &val);
		buf[j++] = (unsigned char) val;
	}

	return (size_t) j;
}

void print_byte_sequence_hex(unsigned char arr[], size_t len)
{
	int i;

	for (i = 0; i < len; i++)
		printf("|0x%02X", arr[i]);
	printf("\n");
}

void print_byte_sequence_char(unsigned char arr[], size_t len)
{
	int i;

	for (i = 0; i < len; i++)
		printf("%c", arr[i]);
	printf("\n");
}
