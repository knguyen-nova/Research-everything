import struct 

#Variable 
quak = "3c 00 51 00 6a 00 09 00 02 00 07 00 25 00 03 00 30 00 08 00 04 00 29 00 68 00 24 00 01 00 24 00 18 00 6b 00 77 00 0f 00 70 00 36 00 02 00 0e 00 0b 00 "
quak_b = bytes.fromhex(quak)
flare_b = bytes.fromhex("464c41524552414c46")
str1 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}_{=-"
str2 = "-={_}9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"
map_str = dict(zip(str2, str1))
#Handle byte
quak_short = struct.unpack("<25H", quak_b)

#Reverse quak
re_quak = quak_short[::-1]

# Short quak xor FLARE
xor_quak = []
for i in range(len(re_quak)):
    xor_quak.append( re_quak[i] ^ i + flare_b[i % len(flare_b)])
# Mapping str2 to str1
flag = ""
for i in xor_quak:
    flag += map_str[chr(i)]

print(f"Quak value {quak} \n ")
print(f"Short Quak {quak_short} \n ")
print(f"Reverse ushort Quak {re_quak} \n ")
print(f"Flare {flare_b} len = {len(flare_b)} \n")
print(f"Quak xor Flare {xor_quak}\n" )
print(f"Text Value =  {flag}")
