#!/usr/bin/env python

def readStr(path):
    f=open(path, 'r')
    inStr = f.read()  
    f.close()
    return inStr

# returns array of integers
def parseHex(inStr):
    outStr = []
    for i in range(0, len(inStr) - 1, 2):
        tmpTxt = inStr[i] + inStr[i+1]
        outStr.append(int(tmpTxt, 16))
    return outStr

def readStrs():
    path = 'txt'
    outStrs = []
    for i in range(1, 8):   
        outStrs.append(parseHex(readStr(path + str(i))))
    return outStrs
 
# xor two strings and try to search valid their values        
def search(in1, in2):
    out = []
    mult = []
    range1 = list(range(32, 49))
    range2 = list(range(57, 128))
    rangeXY = range1 + range2
    for i in range(0, len(in1)):
        # get rid of the key
        mult.append(in1[i] ^ in2[i])
        # factorization in range
        # 32 : 48 and 57 : 127
        dic = {}
        for x in rangeXY:
            tmpY = []            
            for y in rangeXY:
                if ((x ^ y) == mult[i]):
                    tmpY.append(y)
            if (len(tmpY) > 0):
                dic[x] = tmpY
        if (len(dic) > 0):
            out.append(dic)
        else:
            out.append([])
    return out

#def printSolution(inArr):
#    maxCol = 0
#    colMaxLen = []
#    for col in range(0, len(inArr)):
#        if (len(col) > maxCol):
#            maxCol = len(col)
#        # search first the longest element
#        maxLen= 0
#        for x, y in col.iteritems():
#            if (len(y) > maxLen):
#                maxLen = len(y)
#        colMaxLen.append(maxLen)
#    
#    for i in range(0, maxCol):
       
strs = readStrs()
searchRes = search(strs[0], strs[1])
i = 1
#for i in range(0, 7):   
#    print('Encrypted hex text ' + str(i+1) + ":\n" + str(strs[i]))
#    print('Encrypted hex text length: ', len(strs[i]), '\n')
