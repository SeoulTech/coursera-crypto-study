UCHAR_MIN = 0 
UCHAR_MAX = 255

import string

def hex_str2byte_lst(txt_str):
    byt_lst = []
    for i in range(0, len(txt_str), 2):
        hex_byt_str = txt_str[i : i + 2]
        byt_val = int(hex_byt_str, 16)
        byt_lst.append(byt_val)
    return byt_lst  

def coll_same_key_enc_bytes(byt_lst, key_len, start_idx):
    col_lst = []
    for i in range(start_idx, len(byt_lst), key_len):
        byt = byt_lst[i]
        col_lst.append(byt)
    return col_lst

def cnt_byte_freq(byt_lst):
    freq_lst = {}
    for byt in byt_lst: 
        for key in freq_lst.keys():
            if byt == key:
                freq_lst[key] += 1
                break;
        else: 
            freq_lst[byt] = 1
    return freq_lst

def sqr_sum_dist(lst):
    sqr_sum = 0.0
    for i in range(0, len(lst)):
        sqr_sum += pow(lst[i], 2) / len(lst)
    return sqr_sum

def brute_force_byte_lst(byt_lst):
    key_cand = {}
    cnt_dict = {'lwr': 0, 'upr': 0, 'spc': 0, 'pun': 0, 'oth': 0}
    for key in range(UCHAR_MIN, UCHAR_MAX + 1):
        cnt_dict['lwr'] = cnt_dict['upr'] = cnt_dict['spc'] = cnt_dict['pun'] = cnt_dict['oth'] = 0
        for byt in byt_lst:
            if chr(byt) == '\n':
                continue
            else:
                dec_ch = chr(byt ^ key)

            if dec_ch in string.lowercase:
                cnt_dict['lwr'] += 1
            elif dec_ch in string.uppercase:
                cnt_dict['upr'] += 1
            elif dec_ch == ' ':
                cnt_dict['spc'] += 1
            elif dec_ch in (',', '.', '?', '!', '-', '\'', '"', '(', ')'):
                cnt_dict['pun'] += 1
            else:
                cnt_dict['oth'] += 1
        key_cand[key] = cnt_dict.copy()
    return key_cand
