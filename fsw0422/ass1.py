#!/usr/bin/env python

from itmc import *

# convert hexadecimal str to byte data
txt_str = 'F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D963FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794'
byt_lst = hex_str2byte_lst(txt_str)

# calculate square sum and find key val
MIN_KEY_LEN = 1
MAX_KEY_LEN = 13
sqr_sum_dic = {}
for key_len in range(MIN_KEY_LEN, MAX_KEY_LEN + 1):
    lst = coll_same_key_enc_bytes(byt_lst, key_len, 0)
    byt_freq_lst = cnt_byte_freq(lst)
    sqr_sum = sqr_sum_dist(byt_freq_lst.values())
    sqr_sum_dic[key_len] = sqr_sum
print('square sum values: ', sqr_sum_dic)

# key len determined
key_len = 7

# collect same key encrypted text based on key val
same_key_enc_lst_lst = []
for start_idx in range(key_len):
    lst = coll_same_key_enc_bytes(byt_lst, key_len, start_idx)
    same_key_enc_lst_lst.append(lst)

# brute force key value on collected list
i = 0
for enc_lst in same_key_enc_lst_lst:
    print('bytes encrypted with key startring index of ', i)
    key_cand_dic = brute_force_byte_lst(enc_lst)
    for key, val in key_cand_dic.items():
        if val['oth'] == 0:
            print('key:', hex(key), 'value:', val)
    i += 1

# key determined
key_val = [0xba, 0x1f, 0x91, 0xb2, 0x53, 0xcd, 0x3e]

# decipher text
dec_chr_lst = []
for i in range(len(byt_lst)):
    dec_chr_lst.append(chr(byt_lst[i] ^ key_val[i % key_len]))
print(''.join(dec_chr_lst))
