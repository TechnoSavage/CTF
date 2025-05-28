# from secret import FLAG
# from random import randint

# def to_identity_map(a):
#     return ord(a) - 0x41    #convert character to ordinal character and subtract 65 ('A')

# def from_identity_map(a):
#     return chr(a % 26 + 0x41)

# def encrypt(m):
#     c = ''                   # initialize var 'c'
#     for i in range(len(m)):  # iterate over all letters in message 'm'
#         ch = m[i]            # ch = character at current index
#         if not ch.isalpha(): # if character 'ch' is not an alphabetic character assign to 'ech', all non-alpha characters remain intact
#             ech = ch
#         else:  
#             chi = to_identity_map(ch)  #if character is alpha then convert to ordinal, - 65, and assign to 'chi'
#             ech = from_identity_map(chi + i) # if character is alpha then take previous value 'chi' now (ordinal) add index position 'i' % 26 + 65 and convert to chr  
#         c += ech                             #append chr to string c
#     return c                                 # return ecrypted string c

# with open('output.txt', 'w') as f:
#     f.write('Make sure you wrap the decrypted text with the HTB flag format :-]\n')
#     f.write(encrypt(FLAG))


# valid A-Z values between 65 and 90

import re

# def findValue(ph, i):
#     v = chr(ord(ph) - 65 %26 - i + 65)
#     return v

def findValue(ph, i):
    acceptable = [n for n in range(65, 91)]
    num = 0
    v = ord(ph) % 26 - i + num
    while v not in acceptable:
        num += 1 
    return chr(v)

def decrypt(message):
    p = ''
    for i in range(len(message)):
        ph = message[i]
        if not ph.isalpha():
            eph = ph
        else:
            eph = findValue(ph, i)
        p += eph
    return p

ciphertext = "DJF_CTA_SWYH_NPDKK_MBZ_QPHTIGPMZY_KRZSQE?!_ZL_CN_PGLIMCU_YU_KJODME_RYGZXL"
plaintext = decrypt(ciphertext)
print(plaintext)
