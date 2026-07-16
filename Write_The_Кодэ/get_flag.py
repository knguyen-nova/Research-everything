with open("constant_flag.txt", "r") as f:
    constant_en = f.readlines()
with open("mem.txt", "r") as f:
    mem = f.readlines()

constant_c0 = 0xc0dec0de
j = 3
flag_str = ""

for i in range(0, 51):
    constant_flag = int(constant_en[i], 16)
    mem_j_2 = int(mem[j + 2], 16)
    rot = mem_j_2 & 0x1f

    constant_origin = (constant_flag - (i * 0x45d9f3b ^ 0x9e3779b9)) & 0xffffffff
    constant_origin = (constant_origin >> rot | constant_origin << (0x20 - rot)) & 0xffffffff

    flag = (constant_origin ^ constant_c0) - int(mem[j + 1], 16)
    flag &= 0xff                    

    flag_str += chr(flag)

    constant_c0 = constant_flag
    j += 7

print(flag_str)