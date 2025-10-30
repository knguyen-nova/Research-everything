
Weird.png-HolaCTF 2025
--
> Date: Sep 18, 2025, 08:40 PM - 18/9/2025 :beaver: 
> 
> Purpose : writeup  :heart_eyes: 
> 
> Owner: Khoi nguyen - Nova :dragon_face: 

---
**`*Phân tích nhanh file Weird.png:`** :crossed_swords: 

-Kiểm tra bằng lệnh xxd (Công cụ dùng xem file dưới dạng hexdump) ta thấy:

` 00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR`

=> là một header chuẩn của 1 file ảnh PNG vì có PNG signature : PNG 89 50 4E 47 0D 0A 1A 0A

`000001f0: 0000 0000 0000 0000 0000 0000 0000 55aa  ..............U.`

=> có 2 byte cuối là 55aa => là một boot sector (sector khởi động đầu tiên của một phân vùng hoặc của ổ đĩa ) => có mã assembly


---

**`*Cách để tìm ra được flag:`** :lady_beetle: 

-Dùng lệnh ndisasm để dịch thành mã assembly 

>  ndisasm weird.png >> weird.asm
> 
-Tìm những đoạn mã assembly có nghĩa thì ta có :

```
00000032  89E5              mov bp,sp
```

=> sao chép địch chỉ thanh ghi sp vào bp để tạo stack frame nhằm để thiết lập mốc
( bp là thanh ghi basepoint ; sp là thanh ghi stackpoint)

---
```
00000034  C6460000          mov byte [bp+0x0],0x0
```

=> sao chép gía trị 0 vào bộ nhớ tại địa chỉ bp+0x0

---
```
00000038  B85F7D            mov ax,0x7d5f
0000003B  50                push ax
```

=> sao chép 0x7d5f vào ax (Accumulator Register có 16 bit)

=> ghi giá trị của thanh ghi ax vào stack
> Trong ax có 2 phân 1 là AH(8 bit high),2 là AL(8 bit low) và khi đẩy bằng push thì sẽ đẩy phần high trước low sau.

=> 0x7d5f chuyển thành mã ASCII ta được 0x7d = "}", 0x5f = "_", => ta được "}_ "và push sẽ đẩy "}" lên trước rồi sẽ đẩy "_"lên sau.

---
```
0000003C  B83237            mov ax,0x3732
0000003F  50                push ax
```

=> 0x3732 dịch được thành 72

---
```
00000040  B85F37            mov ax,0x375f
00000043  50                push ax
```
=> 0x375f dịch được thành 7_

---
```
00000044  B82140            mov ax,0x4021
00000047  351212            xor ax,0x1212
0000004A  50                push ax
```

=> xor 0x4021 với 0x1212 xong rồi dịch được thành R3

---
```
0000004B  B8BCCC            mov ax,0xccbc
0000004E  358888            xor ax,0x8888
00000051  50                push ax
```
=> làm tương tự ta dịch được thành D4

---
```
00000052  B8A8A9            mov ax,0xa9a8
00000055  359999            xor ax,0x9999
00000058  50                push ax
```

=> làm tương tự ta dịch được thành 01

---
```
00000059  B85B78            mov ax,0x785b
0000005C  350F27            xor ax,0x270f
0000005F  50                push ax
```

=> làm tương tự ta dịch được thành _T

---
```
00000060  B8075C            mov ax,0x5c07
00000063  353713            xor ax,0x1337
00000066  50                push ax
```

=> làm tương tự ta dịch được thành O0

---
```
00000067  B82815            mov ax,0x1528
0000006A  357777            xor ax,0x7777
0000006D  50                push ax
```

=> làm tương tự ta dịch được thành b_

---
```
0000006E  B85C30            mov ax,0x305c
00000071  356969            xor ax,0x6969
00000074  50                push ax
```

=> làm tương tự ta dịch được thành Y5

---
```
00000075  B85348            mov ax,0x4853
00000078  356009            xor ax,0x960
0000007B  50                push ax
```

=> làm tương tự ta dịch được thành A3

---
```
0000007C  B86459            mov ax,0x5964
0000007F  352222            xor ax,0x2222
00000082  50                push ax
```

=> làm tương tự ta dịch được thành {F

---
```
00000083  B85245            mov ax,0x4552
00000086  351111            xor ax,0x1111
00000089  50                push ax
```

=> làm tương tự ta dịch được thành TC

---
```
0000008A  B86D02            mov ax,0x26d
0000008D  352143            xor ax,0x4321
00000090  50                push ax
```

=> làm tương tự ta dịch được thành AL

---
```
00000091  B87C5D            mov ax,0x5d7c
00000094  353412            xor ax,0x1234
00000097  50                push ax
```

=> làm tương tự ta dịch được thành OH

---
```
00000098  89E5              mov bp,sp
```

=> sao chép giá trị hiện tại của sp vào bp

---
```
0000009A  8A4600            mov al,[bp+0x0]
0000009D  45                inc bp
```

=> tăng giá trị thanh ghi bp lên 1

---
```
0000009E  08C0              or al,al
```

=> kiểm tra có bằng 0 bằng or chính nó 

---
```
000000A0  740A              jz 0xac
```

=> nhảy tới 0xac nếu bằng 0

---
```
000000A2  B40E              mov ah,0xe
000000A4  B700              mov bh,0x0
000000A6  B307              mov bl,0x7
000000A8  CD10              int 0x10
```
=> dùng để phục vụ cho việc in ra bằng cách dùng interrupt  video của BIOS

---
```
000000AA  EBEE              jmp short 0x9a
```

=> Về lại inc bp

---
```
000000AC  EBFE              jmp short 
```

=> lặp vô hạn

---

=> Ghép từ dưới đi lên ta được flag: HOLACTF{3A5Y_b0OT_104D3R_727_}
Weird.png-HolaCTF 2025
