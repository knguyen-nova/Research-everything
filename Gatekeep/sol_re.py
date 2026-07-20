from z3 import *
import hashlib

s = Solver()

c1 = BitVec('c1', 8)
c2 = BitVec('c2', 8)
c3 = BitVec('c3', 8)
c4 = BitVec('c4', 8)
c5 = BitVec('c5', 8)
c6 = BitVec('c6', 8)
c7 = BitVec('c7', 8)
c8 = BitVec('c8', 8)
c9 = BitVec('c9', 8)
 
 
s.add(((c1 - c4 ) ^ (c1 + c4) ) == 0x60 )
s.add ( (( (c1 + c3 ) + c2) | ( ( c1 & c2 ) & (c1 + c4)) ) == 0x45 )
s.add ( (( (c9 ^ c6 ) - ( c8 &  c6) ) + (c9 - (~(c1 &c2) ) )) == 0xaf )
s.add (((c7 & ~c4) ^ (c1 + c5 ) ) == 0xbb )
s.add( (c9 + c5) == 0xa5  )
s.add (( c9 ^ c5 ) == 0x41  )
s.add((((c6 & c5 ) ^ (c9 | c5 ) ) ^ ( ~c5 & ~c6)) == 0xb2 )
s.add((( c1 + c5) -  c9 ) == 0x87  )
s.add(( ((c4 & c5 ) & c9 )  | ( ( (c1 & c8) & c2 ) ^ (c2 + c8) )) == 0xfd )

while s.check() == sat:
    m = s.model()
    vals = [m[v].as_long() for v in (c1,c2,c3,c4,c5,c6,c7,c8,c9)]
    h = hashlib.md5(bytes(vals)).hexdigest()
    if h == "47797f54b0f9f4b5b46463e7f86655d5":
        print(f"pass {bytes(vals).decode()}")
        break
   
    s.add(Or([v != m[v] for v in (c1,c2,c3,c4,c5,c6,c7,c8,c9)]))
