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

def findKey(cipher):
    key= []
    for char in cipher:
        k = 0
        while ((256 * k + char - 18) / 123) % 1 != 0:
            k += 1
        key.append(k)
    return(key)

def decryption(cipher):
    pt = []
    key = findKey(cipher)
    for k in range(len(key)):
        pt.append((256 * key[k] + cipher[k] - 18) / 123)
    return(pt)

# with open ('msg.enc', 'r') as f:
#     cipher = bytes.fromhex(f.read())
cipher = bytes.fromhex('6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921')
pt = decryption(cipher)
print(''.join([chr(int(char)) for char in pt]))