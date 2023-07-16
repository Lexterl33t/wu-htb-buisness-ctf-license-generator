from ctypes import c_uint8



xor_key = list(b"d!`\n;e!\n!=a!\nfa&,\n7 !\n,e \na\'f\n%\'f!!,\n69e&fo|")


for i in range(len(xor_key)):
    xor_key[i] = xor_key[i] ^ 0x55


a = open("aaa", "rb").read()


b = []

for i in range(len(a)):
    b.append((a[i] ^ xor_key[i % len(xor_key)]))


sub_key = list(b"\x1c\x00Y\x1b7\x1fY\x04\x047\x1b\x1d\x1a[\x04\x117\x03[[\x187\x1c\x00Y\x1b7\x18\x1aX\x1c[\x0b\x1c[\x0c")

for i in range(len(sub_key)):
    sub_key[i] = sub_key[i] ^ 0x68


for i in range(len(b)):

    b[i] = c_uint8(b[i] - sub_key[i % len(sub_key)]).value


second_xor_key = list(b"\x66\x40\xbf\x86\xc2\xd1\x73\x4f")


for i in range(len(b)):
    b[i] = b[i] ^ (second_xor_key[i % 8]);



f = open("lol.png", "wb")
f.write(bytes(b))
f.close()
