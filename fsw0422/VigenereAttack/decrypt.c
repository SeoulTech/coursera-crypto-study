#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_BUF_LEN 1024

#define MIN_ASCII 0
#define MAX_ASCII 127

#define MIN_KEY_LEN 1
#define MAX_KEY_LEN 13

double square_sum_distribution(unsigned char ctxt[], size_t ctxt_len, size_t key_len);
void guess(unsigned char ctxt[], size_t ctxt_len, size_t key_len, int offset);
void check_space(unsigned char ctxt[], size_t ctxt_len, size_t key_len);
void print_byte_sequence(unsigned char arr[], size_t len);

int main(int argc, char *argv[])
{
	size_t ctxt_len;
	unsigned char ctxt_buf[MAX_BUF_LEN];
	unsigned char *key;
	FILE *fp_in;
	size_t bytes_read;
	size_t key_len;
	int i;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <encrypted file name>\n", argv[0]);
		return -1;
	}

       	/* init */
	memset(ctxt_buf, 0, sizeof(ctxt_buf));
	bytes_read = 0;
	ctxt_len = 0;

	/* read the ciphered text to buffer */
	fp_in = fopen(argv[1], "rb");
	/** read the ciphered text to buffer **/
	while (!feof(fp_in)) {
		bytes_read = fread(ctxt_buf, sizeof(unsigned char), MAX_BUF_LEN, fp_in);
		ctxt_len += bytes_read;
	}
	fclose(fp_in);
	print_byte_sequence(ctxt_buf, ctxt_len);

	/* brute-force key length (done with this)*/
	//for (key_len = MIN_KEY_LEN; key_len <= MAX_KEY_LEN; key_len++) {
	//	double sqr_sum;

	//	sqr_sum = square_sum_distribution(ctxt_buf, ctxt_len, key_len);
	//	printf("square sum distribution is %lf when key_len is %u\n", sqr_sum, key_len);
	//}
	
	/* guess the bytes */
	key_len = 7;
	key = (unsigned char *) malloc(sizeof(unsigned char) * key_len);
	/** try every offset of plain text that is <ciphertext> mod(key_len) **/
	for (i = 0; i < key_len; i++)
		guess(ctxt_buf, ctxt_len, key_len, i);

	/** try to look for spaces(ASCII #32) in two contiguous blocks of ciphered text with the chunk of key_len (which is 7) **/
	check_space(ctxt_buf, ctxt_len, key_len);	
	free(key);
	key = NULL;
	return 0;
}

double square_sum_distribution(unsigned char ctxt[], size_t ctxt_len, size_t key_len)
{
	unsigned int ascii_freq[MAX_ASCII + 1];
	unsigned int cand_txt_len;
	double sqr_sum;
	unsigned char ch;
	unsigned int offset;
	int i;

	/* init */
	memset(ascii_freq, 0, sizeof(ascii_freq));
	cand_txt_len = ctxt_len / key_len; //get the total length of candidate letters of ciphered text chosen by the key_len
	sqr_sum = 0.0;
	offset = 3; //calculate only for <1st letter + key_len> mod(key_len)

	/* count each alphabets that are encrpyted with the same key value */
	while (offset <= ctxt_len) {
		ch = ctxt[offset]; //get ciphered char from ciphered text
		ascii_freq[ch]++; //increment the frequency of deciphered char
		offset += key_len; //skip by key_len in ciphered text
	}

	/* calculate the square sum distribution */
	for (i = 0; i < MAX_ASCII; i++)
		sqr_sum += (double) (ascii_freq[i] * ascii_freq[i]) / (double) (cand_txt_len * cand_txt_len);

	return sqr_sum;
}

void guess(unsigned char ctxt[], size_t ctxt_len, size_t key_len, int offset)
{
	unsigned char enc_buf[MAX_BUF_LEN];
	unsigned char key_cand[MAX_BUF_LEN];
	int offst;
	size_t len;
	unsigned char c;
	int i, j;

	/* init */
	memset(enc_buf, 0, sizeof(enc_buf));
	memset(key_cand, 0, sizeof(key_cand));
	offst = offset;

	/* collect ciphered text that are encrpyted with the same key value based on a specific offset */
	len = 0;
	while (offst <= ctxt_len) {
		enc_buf[len] = ctxt[offst]; //get ciphered char from ciphered text and put it in buffer
		offst += key_len; //skip by key_len in ciphered text
		len++;
	}

	/* brute force key with all ascii code */
	j = 0;
	/** go through all ASCII (key can be any char in ASCII) **/
	for (c = MIN_ASCII; c <= MAX_ASCII; c++) {		
		int lwr_case, upr_case, punc, spc, nl;

		lwr_case = upr_case = punc = spc = nl = 0;
		/* go through all collected ciphered text */
		for (i = 0; i < len; i++) {
			unsigned char dec_char; //temp space to store decrypted char

			/* decrypt collected ciphered text with selected char */
			if (enc_buf[j] != '\n') //new line is not encrypted
				dec_char = enc_buf[j] ^ c; //decrypt key
			else
				dec_char = enc_buf[j]; //just put it in

			/* check if the decrypted char meets the condition range of ASCII code in assignment instruction */
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
				break;
		}
		/* filter out the candidate keys */
		if (i == len) {
			if (lwr_case != 0 && spc != 0) { //1st filter
				key_cand[j] = c;
				j++;
			}
		}
	}
	printf("key candidates of ciphertext with the starting offset of %d are\n", offset);
	print_byte_sequence(key_cand, j);
}

void check_space(unsigned char ctxt[], size_t ctxt_len, size_t key_len)
{
	unsigned char arr1[key_len];
	unsigned char arr2[key_len];
	int i, j;

	for (i = 0; i < key_len; i++)
		arr1[i] = ctxt[i];

	for (; i < 2 * key_len; i++) {
		j = i - key_len;
		arr2[j] = (ctxt[i] ^ arr1[j]) & ' ';

		if (arr2[i - key_len] == 0x00)
			printf("found space\n");	
	}
}

void print_byte_sequence(unsigned char arr[], size_t len)
{
	int i;

	for (i = 0; i < len; i++)
		printf("%c", arr[i]);

	printf("\n");
}
