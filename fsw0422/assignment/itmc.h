#ifndef __ITMC_H__
#define __ITMC_H__

#include <stdio.h>

#define MAX_BUF_LEN 1024

double same_key_enc_square_sum_distribution(unsigned char byt_arr[], size_t byt_arr_len, size_t key_len, int strt_idx);
size_t collect_chars_same_enc_key(unsigned char *buf, unsigned char byt_arr[], size_t byt_arr_len, size_t key_len, int strt_idx);
size_t convert_hexstr_to_bytestr(unsigned char *buf, unsigned char hexstr[], size_t hexstr_len);
void print_byte_sequence_hex(unsigned char arr[], size_t len);
void print_byte_sequence_char(unsigned char arr[], size_t len);

#endif
