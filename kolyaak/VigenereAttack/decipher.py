#!/usr/bin/env python

from decimal import *

path = 'ciphertext'   
f=open(path, 'r')
encTxt = f.read()  
print('Ecnrypted text:\n' + encTxt)
print('Ecnrypted text length: ', len(encTxt))
f.close()

#######search key length##################
#in the loop for n key length check distribution of a letter appearance
sqSumDist = [] #square sum of distribution for each length of key
nMax = 1 #n with the biggest value of sqSumDist
sqSumDistMax = 0
for n in range(1, 256):
    encTxtN = [] #collect all entries with the step n
    encTxtDicN = {} #count n-th repeated entries
    total = 0
    for i in range(0, len(encTxt), n):
        total += 1        
        encTxtN.append(encTxt[i])
        if encTxt[i] in encTxtDicN:
            encTxtDicN[encTxt[i]] += 1
        else:
            encTxtDicN[encTxt[i]] = 1
    #print 'Entries for length {0}:'.format(n)    
    #print encTxtDicN    
    sqSum = 0
    for letter, count in encTxtDicN.iteritems():
        tempDist = Decimal(count) / Decimal(total)
        #print 'Count {0} / total {1} = {2} for letter {3}'.format(count, total, tempDist, letter)
        sqSum += tempDist * tempDist
    print ('{0}: square dist sum {1}'.format(n, sqSum))
    sqSumDist.append(sqSum)
    if sqSum > sqSumDistMax:
        sqSumDistMax = sqSum
        nMax = n
print ('The key length {0} maximizes the square distribution {1}.'.format(nMax, sqSumDistMax)) #n=182

#######search the key##################
#go through the entire key
key = []
for keyI in range(0, nMax):
    #go through all bytes B
    sqSumDistMax = 0
    sqSumDist = [] 
    bMax = 0
    #print 'Key step: {0}'.format(keyI)
    for b in range(0, 256):
        #go through the entire text
        encTxtDicN = {}
        total = 0
        for txtStepI in range(keyI, len(encTxt), nMax):
            total += 1
            #xor a letter at each step and calculate its rate
            origLet = b ^ ord(encTxt[txtStepI])
            origLetCh = chr(origLet)
            if origLetCh in encTxtDicN:
                encTxtDicN[origLetCh] += 1
            else:
                encTxtDicN[origLetCh] = 1
        sqSum = 0
        for letter, count in encTxtDicN.iteritems():
            tempDist = Decimal(count) / Decimal(total)
            #print 'Count {0} / total {1} = {2} for letter {3}'.format(count, total, tempDist, letter)
            sqSum += tempDist * tempDist
        #print ('Entries for b {0}'.format(b))
        #print (encTxtDicN)
        #print ('{0}: square dist sum {1}'.format(b, sqSum))
        #intest = input("Press key")        
        sqSumDist.append(sqSum)
        #print ('Current sqSum {0}, max sqSum {1}'.format(sqSum, sqSumDistMax))
        if sqSum > sqSumDistMax:
            sqSumDistMax = sqSum
            bMax = b
    #intest = input("Press key")
    #print ('Distribution at step {0}'.format(keyI))
    #print (sqSumDist)
    #intest = input("Press key")
    key.append(bMax)
print (key)    