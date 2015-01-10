/*
 * ass2.c
 * 
 * decrypting the ciphertext of assignment2 in coursera
 * compiles on every platform
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "itmc.h"

#define NUM_OF_CTEXT 7

#define BYTE_LINE_LEN 31
#define KEY_LEN 31

void guess(unsigned char byt_arr[], size_t byt_arr_len);

/*
 * 1. all 7 texts have same last char except 4 -> guessing if it's a punctuation
 * 2.
 */
unsigned char key[KEY_LEN] = {
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
	0x30	
};

int main(int argc, char *argv[])
{
	unsigned char *ctxt_buf, *byte_buf;
	size_t ctxt_len, byte_len;
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
	//print_byte_sequence_hex(byte_buf, byte_len);

	/* guess keys based on row values */
	for (i = 0; i < BYTE_LINE_LEN; i++) {
		unsigned char buf[NUM_OF_CTEXT];

		printf("-------- index of %d chars' key candidates --------\n", i);
		collect_chars_same_enc_key(buf, byte_buf, byte_len, KEY_LEN, i);
		guess(buf, NUM_OF_CTEXT);
		//print_byte_sequence_hex(buf, NUM_OF_CTEXT);
	}

	/* seperate 7 texts from read file and convert to bytestr */
	
	free(byte_buf);
	return 0;
}

void guess(unsigned char byt_arr[], size_t byt_arr_len)
{
	int i, j;

	/* go through all char brute force (key can be any char) */
	for (i = 0; i <= UCHAR_MAX; i++) {		
		int lwr_case, upr_case, punc, spc, oth;

		/* go through all collected ciphered bytes */
		lwr_case = upr_case = punc = spc = oth = 0;
		for (j = 0; j < byt_arr_len; j++) {
			unsigned char dec_char; //temp space to store decrypted char

			dec_char = byt_arr[j] ^ (unsigned char) i; //decrypt key

			/* check if the decrypted char meets the condition in assignment instructions */
			if (dec_char >= 'a' && dec_char <= 'z')
				lwr_case++;
			else if (dec_char >= 'A' && dec_char <= 'Z')
				upr_case++;
			else if (dec_char == ' ')
				spc++;
			else if (dec_char == ',' || dec_char == '.' || dec_char == '?' || dec_char == '!')
				punc++;
			else //everything other than the requirement
				oth++;
		}

		/* print the key candidates */
		if (oth == 0)
			printf("when key is 0x%02X: lwr_case: %d, upr_case: %d, spc: %d, punc: %d, oth: %d\n", 
			       (unsigned char) i, lwr_case, upr_case, spc, punc, oth); 
	}
}
