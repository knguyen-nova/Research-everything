import gdb

f_flag = open("constant_flag.txt", "w")
f_mem= open("mem.txt","w")

class BP_dump_mem(gdb.Breakpoint):
    def stop(seft):
        inferior = gdb.selected_inferior()
        data = bytes(inferior.read_memory(0x7ffff7ffa000, 0x200))
        print(data)
        for b in data:
            f_mem.write(f"{b:02x}\n")
            f_mem.flush()
        return True
class BP_dump_j(gdb.Breakpoint):
    def stop(self):
        rax = int(gdb.parse_and_eval("$rax"))
        print(f"j = {rax}")
        return False
class BP_dump_flag_en(gdb.Breakpoint):
    def stop(self):
        rcx = int(gdb.parse_and_eval("$rcx"))
        print(f"{hex(rcx)}")
        f_flag.write(f"{hex(rcx)}\n")
        f_flag.flush()
        gdb.execute(f"set $rax={hex(rcx)}")
        return False 
class BP_check_final(gdb.Breakpoint):
    def stop(self):
        return True 

class BP_debug(gdb.Breakpoint):
    def stop(self):
        print(f"hit 0x004025d1 : Check byte 51 is == 0")
        return True  
    
BP_dump_mem("*0x4023b0")
BP_dump_j("*0x40245e")
BP_dump_flag_en("*0x4025b1")
BP_debug("*0x004025d1")
BP_check_final("*0x401f33")
gdb.execute("run")
