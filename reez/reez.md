#     Research how to solve - REVERSE - REEZ - CSCV 2025

**`According to source`** :heart: :heart: :heart: :heart:

https://bksec.vn/blog/writeup-cscv-2025

Reverse - REEZ: 

https://bksec.vn/blog/writeup-cscv-2025?fbclid=IwY2xjawNkTEZleHRuA2FlbQIxMABicmlkETFPWmlqTGg5SWtkUmF1VHdnAR7gRQoFp_KgUIk3yxCT1LAJvi4v7qfH2gBsHm1icn5w21mIV1qk64LlaQE7ig_aem_Zj3X20sq4GxUoXoE-AqdpA#ph%C3%A2n-t%C3%ADch-challenge-2

---
> Date: 21/10/2025 :beaver: 
> 
> Purpose : learn how to solve its :heart_eyes: 
> 
> Owner: Khoi nguyen - Nova :dragon_face: 

---
**`Step to solve`** :eagle: 
> *Solving by use IDA*

Step 1: dùng F5 trong IDA để decompile 

> F5 dùng để biên dịch ngược - decompile 1 hàm sang 1 mã giả C - pseudocode

Ta thu được code pseudocode:

~~~~
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdx
  __int64 v4; // r8
  __m128i si128; // xmm0
  const char *v6; // rcx
  _BYTE v8[32]; // [rsp+0h] [rbp-58h] BYREF
  char Str[16]; // [rsp+20h] [rbp-38h] BYREF
  __m128i v10; // [rsp+30h] [rbp-28h]
  __int64 v11; // [rsp+40h] [rbp-18h]
  __int64 v12; // [rsp+48h] [rbp-10h]

  v10 = 0;
  *(_OWORD *)Str = 0;
  v11 = 0;
  sub_1400010F0("Enter flag: ", argv, envp);
  sub_140001170("%32s", Str);
  if ( strlen(Str) != 32 )
  {
    puts("No");
    if ( ((unsigned __int64)v8 ^ v12) == _security_cookie )
      return 0;
LABEL_5:
    __debugbreak();
  }
  si128 = _mm_load_si128((const __m128i *)&xmmword_14001E030);
  *(__m128i *)Str = _mm_xor_si128(_mm_load_si128((const __m128i *)Str), si128);
  v10 = _mm_xor_si128(si128, v10);
  if ( _mm_movemask_epi8(
         _mm_and_si128(
           _mm_cmpeq_epi8(*(__m128i *)Str, (__m128i)xmmword_140029000),
           _mm_cmpeq_epi8(v10, (__m128i)xmmword_140029010))) == 0xFFFF )
    v6 = (const char *)&unk_140023E7C;
  else
    v6 = "No";
  sub_1400010F0(v6, v3, v4);
  if ( ((unsigned __int64)v8 ^ v12) != _security_cookie )
    goto LABEL_5;
  return 0;
}
~~~~

**Phân tích:**

 Lệnh SIMD (SSE): 
> SIMD - Single Instruction Multiple Date : 1 lệnh CPU xử lý nhiều tác vụ khác nhau cùng lúc 

ta thấy có 
```
sub_1400010F0("Enter flag: ", argv, envp);
sub_140001170("%32s", Str);
if ( strlen(Str) != 32 )
```
sub_1400010F0("Enter flag: ", argv, envp);
=> in ra Enter flag

sub_140001170("%32s", Str);
=> lấy 32 kí tự và nhập vào str

if ( strlen(Str) != 32 )
=> check xem có phải đúng 32 bit không 

* lấy 32 byte mà  char Str có 16 byte thế nên nó sẽ trản bit . Vây câu hỏi là nó sẽ tràn vào đâu?
* dựa trên mã giả mà chúng ta thu được bằng IDA thì ta có thể suy ra được vị trí mà nó sẽ tràn :+1: 
>   _BYTE v8[32]; // [rsp+0h] [rbp-58h] BYREF
>   char Str[16]; // [rsp+20h] [rbp-38h] BYREF
>   __m128i v10; // [rsp+30h] [rbp-28h]
>   __int64 v11; // [rsp+40h] [rbp-18h]
>   __int64 v12; // [rsp+48h] [rbp-10h]
>   
Dựa trên rsp (rengister stack pointer ) và rbp (register base pointer ) thì ta sắp xếp được theo thứ tự giảm dần từ high address đến lower address:

> v12

> v11

> v10

> str

> v8

dựa trên dữ liệu trên thì chúng ta có thể suy ra khi trản số thì sẽ đẩy vào v10 ( v10 có thể chứa 16 byte dựa trên --m128i nên suy ra v10 chứa 16 byte)


bỏ qua các trường hợp để check điều kiện nếu sai password thì ta thu được: 

**`1`**
```
si128 = _mm_load_si128((const __m128i *)&xmmword_14001E030); 
```
- Tương đương với trong assemply là :
```
movdqa  xmm0, cs:xmmword_14001E030
```
tại xmmword_14001E030 chứa:

**`xmmword_14001E030 xmmword 0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAh`**


=>dùng để lấy dữ liệu từ xmmword_14001E030 và chuyển vào si123 hay xmm0

**`2`**
```
*(__m128i *)Str = _mm_xor_si128(_mm_load_si128((const __m128i *)Str), si128);
```
- Tương đương với trong assemply là :

```
movdqa  xmm1, xmmword ptr [rsp+58h+Str]
pxor    xmm1, xmm0
movdqa  xmmword ptr [rsp+58h+Str], xmm1
```

=> dùng để gán lưu giá trị tại địa chỉ rsp+58h+Str có kích thước 16 byte - 128 bit vào xmm1

=> sau đó xmm1 xor với xmm 0 lưu tại xmm1

=> xmm0 là key để mã hóa flag => lưu ở **xmmword_14001E030**

=> có thể dùng key này để xor với flag đã mã hóa để ra flag

=> xmm1 hiện tại đang chứa phần đầu input vào được mã hóa 


**`3`**

v10 = _mm_xor_si128(si128, v10);

- Tương đương với trong assemply là :

```
pxor    xmm0, [rsp+58h+var_28]
movdqa  [rsp+58h+var_28], xmm0
```

=> xor xmm0 với [rsp+58h+var_28] - v10

=> kết quả lưu tại xmm0 và tại địa chỉ rsp+58h+var_28 - v10

=> xmm0 hiện tại đang chứa phần sau input vào được mã hóa

**`4`**
```
if ( _mm_movemask_epi8(
         _mm_and_si128(
           _mm_cmpeq_epi8(*(__m128i *)Str, (__m128i)xmmword_140029000),
           _mm_cmpeq_epi8(v10, (__m128i)xmmword_140029010))) == 0xFFFF )
```

-Tương đương với trong assemply là : 

```
pcmpeqb xmm0, cs:xmmword_140029010
pcmpeqb xmm1, cs:xmmword_140029000
pand    xmm1, xmm0
pmovmskb eax, xmm1
cmp     eax, 0FFFFh
jz      short loc_1400010CA
```
-Phân tích

`pcmpeqb xmm0, cs:xmmword_140029010 `

=> Dùng để so sánh từng byte trong xmm0 với từng byte trong xmmword_140029010 

> **nếu bằng nhau thì sẽ ra 0xFF**
> 
> **nếu không bằng nhau thì sẽ ra 0x00**

`pcmpeqb xmm1, cs:xmmword_140029000` tương tự như trên 

`pand xmm1, xmm0`

=> dùng để and xmm1 và xmm0 
> nếu khi mà 1 trong 2 là 0x00  thì sẽ and ra 0x00 
> 
> nếu cả 2 cùng là 0xFF thì sẽ ra 0xFF

```
pmovmskb eax, xmm1

cmp   eax, 0FFFFh

jz      short loc_1400010CA 
```

> pmovmskb eax, xmm1 - Packed Move Byte Mask dùng để nén dữ liệu từ 128 bit của thanh ghi xmm1 thành 16 bit lower của thanh ghi eax
> 
>nó sẽ trích 1 byte cao nhất của từng byte và gắn từ bit 0 đến bit 15 của thanh ghi eax 
>16 byte high còn lại eax sẽ là 0 

=> ta thây eax sẽ chứa 0x0000FFFF - 0x0FFFF sẽ == 0FFFFh và và sẽ nhảy tởi short loc_1400010CA và tại đó chứa yes 

=> đầy là đièu kiên để check cái mình nhập vào có đúng với flag mã hóa đã có không 

-Kết luận:

ta có

xmm1 chứa phần đầu input mã hóa và được check bởi cs:xmmword_140029000

=> xmmword_140029000 chứa flag đầu được mã hóa

xmm0 chứa phần sau input mã hóa và được check bởi cs:xmmword_140029010

=> xmmword_140029010 chừa flag sau được mã hóa

key 

0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAh

xmmword_140029000

0CBCCF5D9C3F5D9C3C2DEF5D3D8D8C5D9h 

=> af_si_siht_yrros => sorry_this_is_fa

xmmword_140029010

8B8B8B8B8B8B8B8B8BCDCBC6CCF5CFC1h

=> !!!!!!!!!galf_ek => ke_flag!!!!!!!!!

flag : sorry_this_is_fake_flag!!!!!!!!!
 
=> đó không phải flag đúng 

phần tích tĩnh thì ta thấy sub_140001210 cũng truy cập những hàm dùng xmmword_140029000 và xmmword_140029010 thì ta thấy 
![image](https://hackmd.io/_uploads/B1Ykh3oCex.png)


```
movaps  xmm0, cs:xmmword_14001E010
movaps  cs:xmmword_140029010, xmm0
movaps  xmm0, cs:xmmword_14001E000
movaps  cs:xmmword_140029000, xmm0
```

=> thì ta thấy xmmword_140029010 được mov giá trị tại xmmword_14001E010 và xmmword_140029000 được mov giá trị tại xmmword_14001E000

xmmword_14001E000 xmmword 939FCF9C9B9998C99DC8C9989ECFCB9Ah
=> part 1
xmmword_14001E010 xmmword 9F9D9D9DCB989A9B999A98CF9DCFCFCFh
=> part 2

flag :	0ae42cb7c2316e59eee7e203102a7775

> code xor:
```
import binascii
key = binascii.unhexlify("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
part1 = binascii.unhexlify("939FCF9C9B9998C99DC8C9989ECFCB9A")
part2  = binascii.unhexlify("9F9D9D9DCB989A9B999A98CF9DCFCFCF")

def decrypt(part , key):
    de = bytearray()
    for i in range(len(part)):
        de.append(part[i] ^ key[i])
    return de
depart1 = decrypt(part1, key)
depart2 = decrypt(part2, key)
print(f" part 1  : {depart1}")
print(f"  part 2 : {depart2}")
print("---------------------------------------------------")
flag1 = depart1[::-1].decode()
flag2 = depart2[::-1].decode()
print(f" part 1  : {flag1}")
print(f"  part 2  : {flag2}")
flag = flag1 + flag2
print("---------------------------------------------------")
print(f" flag : {flag}")
    
```