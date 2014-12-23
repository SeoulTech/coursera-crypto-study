/*
 * decrypt.c
 * 
 * decrypting the ciphertext of assignment1 in coursera
 * compiles on every platform
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#define MAX_BUF_LEN 1024

#define MIN_KEY_LEN 1
#define MAX_KEY_LEN 13

double square_sum_distribution(unsigned char byt_arr[], size_t byt_arr_len, size_t key_len);
void guess(unsigned char byt_arr[], size_t byt_arr_len, size_t key_len, size_t offset);
unsigned char convert_hexstr_to_byte(char *hex_str);
void print_byte_sequence_hex(unsigned char arr[], size_t len);
void print_byte_sequence_char(unsigned char arr[], size_t len);

int main(int argc, char *argv[])
{
	unsigned char ctxt_buf[MAX_BUF_LEN], byte_buf[MAX_BUF_LEN], dec_buf[MAX_BUF_LEN], *key;
	size_t ctxt_len, byte_len, dec_len, key_len;
	FILE *fp_in;
	size_t bytes_read;
	int i, j;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <encrypted file name>\n", argv[0]);
		return -1;
	}

       	/* init */
	memset(ctxt_buf, 0, sizeof(ctxt_buf));
	memset(byte_buf, 0, sizeof(byte_buf));
	memset(dec_buf, 0, sizeof(dec_buf));
	bytes_read = ctxt_len = byte_len = dec_len = 0;

	/* read the text to buffer */
	fp_in = fopen(argv[1], "rb");
	/** read the ciphered text to buffer **/
	while (!feof(fp_in)) {
		bytes_read = fread(ctxt_buf, sizeof(unsigned char), MAX_BUF_LEN, fp_in);
		ctxt_len += bytes_read;
	}
	fclose(fp_in);

	/* convert the read text to byte array */
	j = 0;
	for (i = 0; i < ctxt_len; i += 2) {
		char hex_str_byt[2];
		unsigned char val;

		hex_str_byt[0] = ctxt_buf[i];
		hex_str_byt[1] = ctxt_buf[i + 1];

		val = convert_hexstr_to_byte(hex_str_byt);
		byte_buf[j++] = val;
		byte_len++;
	}
	//print_byte_sequence_hex(byte_buf, byte_len);

	/* brute-force key length (done with this)*/
	//for (key_len = MIN_KEY_LEN; key_len <= MAX_KEY_LEN; key_len++) {
	//	double sqr_sum;

	//	sqr_sum = square_sum_distribution(byte_buf, byte_len, key_len);
	//	printf("square sum distribution is %lf when key_len is %lu\n", sqr_sum, key_len);
	//}
	
	/* guess the bytes */
	key_len = 7;
	/** try every offset of plain text that is <ciphertext> mod(key_len) **/
	for (i = 0; i < key_len; i++) {
		//printf("--------starting from offset %d----------\n", i);
		guess(byte_buf, byte_len, key_len, i);
	}

	/* decipher and print */
	key = (unsigned char *) malloc(sizeof(unsigned char) * key_len);
	key[0] = 0xBA; key[1] = 0x1F; key[2] = 0x91; key[3] = 0xB2; key[4] = 0x53; key[5] = 0xCD; key[6] = 0x3E;
	for (i = 0; i < byte_len ; i++) {
		dec_buf[i] = byte_buf[i] ^ key[i % key_len];
		dec_len++;
	}
	print_byte_sequence_char(dec_buf, dec_len);
	free(key);
	key = NULL;
	return 0;
}

double square_sum_distribution(unsigned char byt_arr[], size_t byt_arr_len, size_t key_len)
{
	unsigned int char_freq[UCHAR_MAX + 1];
	unsigned int cand_txt_len;
	double sqr_sum;
	unsigned char ch;
	size_t offset;
	int i;

	/* init */
	memset(char_freq, 0, sizeof(char_freq));
	cand_txt_len = byt_arr_len / key_len; //get the total length of candidate letters of byte sequence chosen by the key_len
	sqr_sum = 0.0;
	offset = 0; //calculate only for <1st letter + key_len> mod(key_len) -> can try for other offsets as well

	/* count each alphabets that are encrpyted with the same key value */
	while (offset <= byt_arr_len) {
		ch = byt_arr[offset]; //get ciphered char from byte array
		char_freq[ch]++; //increment the frequency of deciphered char
		offset += key_len; //skip by key_len in byte array
	}

	/* calculate the square sum distribution */
	for (i = 0; i <= UCHAR_MAX; i++)
		sqr_sum += (double) (char_freq[i] * char_freq[i]) / (double) (cand_txt_len * cand_txt_len);

	return sqr_sum;
}

void guess(unsigned char byt_arr[], size_t byt_arr_len, size_t key_len, size_t offset)
{
	unsigned char enc_buf[MAX_BUF_LEN];
	size_t offst;
	size_t len;
	int i, j;

	/* init */
	memset(enc_buf, 0, sizeof(enc_buf));
	offst = offset;

	/* collect ciphered text that are encrpyted with the same key value based on a specific offset */
	len = 0;
	while (offst <= byt_arr_len) {
		enc_buf[len] = byt_arr[offst]; //get ciphered char from ciphered text and put it in buffer
		offst += key_len; //skip by key_len in ciphered text
		len++;
	}

	/* brute force key with all char */
	/** go through all char (key can be any char) **/
	for (i = 0; i <= UCHAR_MAX; i++) {		
		int lwr_case, upr_case, punc, spc, nl, oth;

		lwr_case = upr_case = punc = spc = nl = oth = 0;
		/* go through all collected ciphered bytes */
		for (j = 0; j < len; j++) {
			unsigned char dec_char; //temp space to store decrypted char

			/* decrypt collected ciphered text with selected char */
			if (enc_buf[j] != '\n') //new line is not encrypted
				dec_char = enc_buf[j] ^ (unsigned char) i; //decrypt key
			else
				dec_char = enc_buf[j]; //just put it in

			/* check if the decrypted char meets the condition in assignment instructions */
			if (dec_char >= 'a' && dec_char <= 'z')
				lwr_case++;
			else if (dec_char >= 'A' && dec_char <= 'Z')
				upr_case++;
			else if (dec_char == ' ')
				spc++;
			else if (dec_char == ',')
				punc++;
			else if (dec_char == '\n')
				nl++;
			else //everything other than the requirement
				oth++;
		}

		/* print the key candidates (still don't get why offset 0 and 1 include oth chars) */
		printf("when key is 0x%x: lwr_case: %d, upr_case: %d, spc: %d, punc: %d, nl: %d oth: %d\n", 
		       (unsigned char) i, lwr_case, upr_case, spc, punc, nl, oth); 
	}
}

unsigned char convert_hexstr_to_byte(char *hex_str)
{
	unsigned int val;
	int i;

	sscanf(hex_str, "%x" , &val);
	return (unsigned char) val;
}

void print_byte_sequence_hex(unsigned char arr[], size_t len)
{
	int i;

	for (i = 0; i < len; i++)
		printf("0x%X", arr[i]);
	printf("\n");
}

void print_byte_sequence_char(unsigned char arr[], size_t len)
{
	int i;

	for (i = 0; i < len; i++)
		printf("%c", arr[i]);
	printf("\n");
}
