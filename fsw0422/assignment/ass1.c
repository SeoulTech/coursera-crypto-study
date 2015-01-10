/*
 * ass1.c
 * 
 * decrypting the ciphertext of assignment1 in coursera
 * compiles on every platform
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "itmc.h"

#define MIN_KEY_LEN 1
#define MAX_KEY_LEN 13

void guess(unsigned char byt_arr[], size_t byt_arr_len);

int main(int argc, char *argv[])
{
	unsigned char *ctxt_buf, *byte_buf, *key, *dec_buf;
	size_t ctxt_len, byte_len, key_len;
	FILE *fp_in;
	int i;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <encrypted file name>\n", argv[0]);
		return -1;
	}

	/* read the text file */
	ctxt_buf = (unsigned char *) calloc(MAX_BUF_LEN, sizeof(unsigned char));
	ctxt_len = 0;
	fp_in = fopen(argv[1], "rb");
	while (!feof(fp_in)) {
		size_t bytes_read;

		bytes_read = fread(ctxt_buf, sizeof(unsigned char), MAX_BUF_LEN, fp_in);
		ctxt_len += bytes_read;
	}
	fclose(fp_in);

	/* convert read text to byte array */
	byte_buf = (unsigned char *) calloc(ctxt_len, sizeof(unsigned char));
	byte_len = convert_hexstr_to_bytestr(byte_buf, ctxt_buf, ctxt_len);
	free(ctxt_buf); //don't need anymore

	/* brute-force key length (done with this)*/
	for (key_len = MIN_KEY_LEN; key_len <= MAX_KEY_LEN; key_len++) {
		double sqr_sum;
	
		sqr_sum = same_key_enc_square_sum_distribution(byte_buf, byte_len, key_len, 0); //can try other offset values too
		printf("square sum distribution is %lf when key_len is %lu\n", sqr_sum, key_len);
	}
	
	/* guess every offset of plain text that is <ciphertext> mod(key_len) (done with this) */
	key_len = 7;
	for (i = 0; i < key_len; i++) {
		unsigned char buf[MAX_BUF_LEN];
		size_t buf_len;

		printf("--------starting from offset %d----------\n", i);
		buf_len = collect_chars_same_enc_key(buf, byte_buf, byte_len, key_len, i);
		guess(buf, buf_len);
	}

	/* decipher and print */
	key = (unsigned char *) calloc(key_len, sizeof(unsigned char));
	key[0] = 0xBA; key[1] = 0x1F; key[2] = 0x91; key[3] = 0xB2; key[4] = 0x53; key[5] = 0xCD; key[6] = 0x3E; //add keys
	dec_buf = (unsigned char *) calloc(byte_len, sizeof(unsigned char));
	for (i = 0; i < byte_len; i++)
		dec_buf[i] = byte_buf[i] ^ key[i % key_len];
	print_byte_sequence_char(dec_buf, byte_len);

	free(byte_buf);
	free(key);
	free(dec_buf);
	return 0;
}

void guess(unsigned char byt_arr[], size_t byt_arr_len)
{
	int i, j;

	/* go through all char brute force (key can be any char) */
	for (i = 0; i <= UCHAR_MAX; i++) {		
		int lwr_case, upr_case, punc, spc, nl, oth;

		/* go through all collected ciphered bytes */
		lwr_case = upr_case = punc = spc = nl = oth = 0;
		for (j = 0; j < byt_arr_len; j++) {
			unsigned char dec_char; //temp space to store decrypted char

			/* decrypt collected ciphered text with selected char */
			if (byt_arr[j] != '\n') //new line is not encrypted
				dec_char = byt_arr[j] ^ (unsigned char) i; //decrypt key
			else
				dec_char = byt_arr[j]; //just put it in

			/* check if the decrypted char meets the condition in assignment instructions */
			if (dec_char >= 'a' && dec_char <= 'z')
				lwr_case++;
			else if (dec_char >= 'A' && dec_char <= 'Z')
				upr_case++;
			else if (dec_char == ' ')
				spc++;
			else if (dec_char == ',' || dec_char == '.' || dec_char == '?' || dec_char == '!')
				punc++;
			else if (dec_char == '\n')
				nl++;
			else //everything other than the requirement
				oth++;
		}

		/* print the key candidates */
		if (oth == 0) //still don't get why offset 0 and 1 include oth chars
			printf("when key is 0x%02X: lwr_case: %d, upr_case: %d, spc: %d, punc: %d, nl: %d oth: %d\n", 
			       (unsigned char) i, lwr_case, upr_case, spc, punc, nl, oth); 
	}
}
