# import string
# from secret import MSG

# def encryption(msg):
#     ct = []
#     for char in msg:
#         ct.append((123 * char + 18) % 256)
#     return bytes(ct)

# ct = encryption(MSG)
# f = open('./msg.enc','w')
# f.write(ct.hex())
# f.close()

import string

def decryption(hex):
    #convert from hex to bytes
    bytes = bytearray.fromhex(hex)
    #holder for plain text 
    pt = []
    #reversing match minus modulo function (modulo 256 wraps any integer above 256 resulting in difference between original value and 256)
    for char in bytes:
        value = ((char - 18) / 123) #Only two values will ever NOT have modulo applied: 1 and 2
        #accounting for modulo function
        if value >= 256:
            value = value - 256
        pt.append(value)
    #convert byte array to ascii/utf? string
    return ascii(pt)

#hex = "6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921"
hex = "8d0883fe79f46fea658d0883fe79f46fea658d0883fe79f46fea65" #known string: 123456789123456789123456789
print(decryption(hex))
